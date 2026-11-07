// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! TLS 統合 (rustls の QUIC モード)
//!
//! rustls の quic::ClientConnection / quic::ServerConnection をラップし、
//! QUIC ハンドシェイクに必要な操作を提供する。
//!
//! このクレートは tobi_transport 等が rustls を直接 Cargo.toml に
//! 書かずに済むよう、`rustls` クレート全体を再エクスポートする。

pub use rustls;

use tobi_core::error::Error;

use std::sync::Arc;

/// TLS ハンドシェイクの出力
pub struct TlsOutput {
    /// 送信すべきハンドシェイクデータ (空の場合もある)
    pub handshake_data: Vec<u8>,
    /// 鍵変更イベント
    pub key_change: Option<KeyChange>,
}

/// 鍵変更イベント
///
/// rustls の鍵オブジェクトをそのまま保持する。
/// パケット保護の適用時にこれらのトレイトオブジェクトを直接使用する。
pub enum KeyChange {
    /// Handshake 鍵が利用可能
    Handshake { keys: RustlsKeys },
    /// 1-RTT 鍵が利用可能
    OneRtt {
        keys: RustlsKeys,
        next_secrets: rustls::quic::Secrets,
    },
}

/// 0-RTT 鍵 (RFC 9001 Section 4.6)
///
/// クライアント → サーバーの片方向のみ。
/// クライアントは送信鍵として、サーバーは受信鍵として使用する。
pub struct ZeroRttKeys {
    pub packet: Box<dyn rustls::quic::PacketKey>,
    pub header: Box<dyn rustls::quic::HeaderProtectionKey>,
}

/// rustls から取得した鍵ペア
pub struct RustlsKeys {
    pub local: RustlsDirectionalKeys,
    pub remote: RustlsDirectionalKeys,
}

/// rustls の片方向鍵セット
pub struct RustlsDirectionalKeys {
    pub packet: Box<dyn rustls::quic::PacketKey>,
    pub header: Box<dyn rustls::quic::HeaderProtectionKey>,
}

/// QUIC バージョン番号を rustls の QUIC バージョンへ変換する
///
/// rustls は v1 と v2 の Initial 鍵導出・ラベル選択を行う
/// (RFC 9369 Section 3.3)。未対応のバージョンはエラーにする。
fn quic_version_from_u32(version: u32) -> Result<rustls::quic::Version, Error> {
    match version {
        tobi_core::packet::QUIC_VERSION_1 => Ok(rustls::quic::Version::V1),
        tobi_core::packet::QUIC_VERSION_2 => Ok(rustls::quic::Version::V2),
        _ => Err(Error::InvalidData(format!(
            "unsupported QUIC version for TLS session: {version:#010x}"
        ))),
    }
}

/// QUIC クライアント TLS セッション
pub struct ClientTlsSession {
    inner: rustls::quic::ClientConnection,
}

impl ClientTlsSession {
    /// クライアント TLS セッションを作成する
    ///
    /// - `config`: rustls の ClientConfig (QUIC 用に設定済み)
    /// - `quic_version`: 接続で使用する QUIC バージョン (Initial 鍵とラベルの選択)
    /// - `server_name`: 接続先のサーバー名 (SNI)
    /// - `transport_params`: エンコード済みトランスポートパラメータ
    pub fn new(
        config: Arc<rustls::ClientConfig>,
        quic_version: u32,
        server_name: rustls::pki_types::ServerName<'static>,
        transport_params: Vec<u8>,
    ) -> Result<Self, Error> {
        let conn = rustls::quic::ClientConnection::new(
            config,
            quic_version_from_u32(quic_version)?,
            server_name,
            transport_params,
        )
        .map_err(|e| Error::InvalidData(format!("TLS client creation failed: {e}")))?;
        Ok(Self { inner: conn })
    }

    /// ハンドシェイクデータを処理する
    pub fn read_handshake(&mut self, data: &[u8]) -> Result<(), Error> {
        self.inner
            .read_hs(data)
            .map_err(|e| Error::InvalidData(format!("TLS read_hs failed: {e}")))?;
        Ok(())
    }

    /// ハンドシェイクデータを書き出す
    pub fn write_handshake(&mut self) -> TlsOutput {
        let mut data = Vec::new();
        let key_change = self.inner.write_hs(&mut data).map(convert_key_change);
        TlsOutput {
            handshake_data: data,
            key_change,
        }
    }

    /// ピアのトランスポートパラメータを取得する
    pub fn peer_transport_params(&self) -> Option<&[u8]> {
        self.inner.quic_transport_parameters()
    }

    /// ネゴシエートされた ALPN プロトコルを取得する
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.inner.alpn_protocol()
    }

    /// TLS アラートコードを取得する
    pub fn alert(&self) -> Option<rustls::AlertDescription> {
        self.inner.alert()
    }

    /// サーバーが 0-RTT を受理したかを返す (RFC 9001 Section 4.6.2)
    ///
    /// ハンドシェイク完了後に呼び出す。`false` の場合、0-RTT で送信したデータは
    /// サーバーに到達していないため、1-RTT で再送する必要がある。
    pub fn is_early_data_accepted(&self) -> bool {
        self.inner.is_early_data_accepted()
    }

    /// 0-RTT 鍵を取得する (RFC 9001 Section 4.6)
    ///
    /// セッション復元が設定されている場合のみ利用可能。
    /// `write_handshake()` の前に呼び出す。クライアントは送信鍵として使用する。
    pub fn zero_rtt_keys(&self) -> Option<ZeroRttKeys> {
        let dk = self.inner.zero_rtt_keys()?;
        Some(ZeroRttKeys {
            packet: dk.packet,
            header: dk.header,
        })
    }

    /// ネゴシエート済み TLS 1.3 cipher suite の AEAD nonce 長 (バイト数) を返す
    ///
    /// draft-ietf-quic-multipath-21 Section 2.1 の MUST 要件
    /// (nonce >= 12 バイトでない cipher suite は multipath で使用禁止) の
    /// 検証に使用する。
    ///
    /// 返り値:
    /// - `None`: cipher suite が未ネゴシエート、または未知の suite
    /// - `Some(len)`: 既知の TLS 1.3 suite の nonce 長 (標準 5 種はすべて 12)
    pub fn aead_nonce_len(&self) -> Option<usize> {
        aead_nonce_len_from_suite(self.inner.negotiated_cipher_suite()?)
    }
}

/// QUIC サーバー TLS セッション
pub struct ServerTlsSession {
    inner: rustls::quic::ServerConnection,
    /// ClientHello を解析するための受信バッファ
    ///
    /// TLS のハンドシェイクメッセージは複数の CRYPTO フレームに分割されて
    /// 届くことがあるため、ClientHello 全体が揃うまで保持する。
    client_hello_buffer: Vec<u8>,
    /// ClientHello の解析が完了したか
    client_hello_parsed: bool,
    /// ClientHello の PSK identity (セッションチケット) のハッシュ
    ///
    /// 0-RTT のリプレイ検出に使う。同じチケットを再利用した接続では同じ値に
    /// なるため、接続をまたいだリプレイを識別できる。
    zero_rtt_ticket_hash: Option<Vec<u8>>,
}

impl ServerTlsSession {
    /// サーバー TLS セッションを作成する
    ///
    /// `quic_version` はクライアントの Initial と同じ QUIC バージョンを渡す。
    pub fn new(
        config: Arc<rustls::ServerConfig>,
        quic_version: u32,
        transport_params: Vec<u8>,
    ) -> Result<Self, Error> {
        let conn = rustls::quic::ServerConnection::new(
            config,
            quic_version_from_u32(quic_version)?,
            transport_params,
        )
        .map_err(|e| Error::InvalidData(format!("TLS server creation failed: {e}")))?;
        Ok(Self {
            inner: conn,
            client_hello_buffer: Vec::new(),
            client_hello_parsed: false,
            zero_rtt_ticket_hash: None,
        })
    }

    /// ハンドシェイクデータを処理する
    pub fn read_handshake(&mut self, data: &[u8]) -> Result<(), Error> {
        // rustls は ClientHello の PSK identity (セッションチケット) を公開しない。
        // 0-RTT のリプレイ検出にはチケットに基づく識別子が必要なため、
        // ClientHello を自前で解析して PSK identity のハッシュを保持する。
        // 解析できなくてもハンドシェイク自体は rustls が処理する。
        if !self.client_hello_parsed {
            self.client_hello_buffer.extend_from_slice(data);
            match parse_client_hello_psk_identity(&self.client_hello_buffer) {
                ClientHelloParse::NeedMore => {}
                ClientHelloParse::NoPsk => {
                    self.client_hello_parsed = true;
                    self.client_hello_buffer.clear();
                }
                ClientHelloParse::Psk(identity) => {
                    self.client_hello_parsed = true;
                    self.client_hello_buffer.clear();
                    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &identity);
                    self.zero_rtt_ticket_hash = Some(digest.as_ref().to_vec());
                }
                ClientHelloParse::Invalid => {
                    self.client_hello_parsed = true;
                    self.client_hello_buffer.clear();
                }
            }
        }
        self.inner
            .read_hs(data)
            .map_err(|e| Error::InvalidData(format!("TLS read_hs failed: {e}")))?;
        Ok(())
    }

    /// サーバーが 0-RTT (early data) を受理したかを返す (RFC 9001 Section 4.6.2)
    ///
    /// rustls の QUIC サーバー実装は early_data 拡張の送信可否そのものを公開
    /// しないため、0-RTT 鍵が利用可能かどうかで判定する。rustls は early data
    /// を拒否した場合に 0-RTT 鍵を導出しないため、この判定は受理可否と一致する。
    pub fn is_early_data_accepted(&self) -> bool {
        self.zero_rtt_keys().is_some()
    }

    /// ClientHello の PSK identity (セッションチケット) の SHA-256 ハッシュを返す
    ///
    /// 同じセッションチケットを再利用した接続では同じ値を返すため、0-RTT の
    /// リプレイ検出の識別子として使える (RFC 9001 Section 9.2)。PSK を伴わない
    /// ハンドシェイクや、ClientHello がまだ揃っていない場合は `None` を返す。
    pub fn zero_rtt_ticket_hash(&self) -> Option<&[u8]> {
        self.zero_rtt_ticket_hash.as_deref()
    }

    /// ハンドシェイクデータを書き出す
    pub fn write_handshake(&mut self) -> TlsOutput {
        let mut data = Vec::new();
        let key_change = self.inner.write_hs(&mut data).map(convert_key_change);
        TlsOutput {
            handshake_data: data,
            key_change,
        }
    }

    /// ピアのトランスポートパラメータを取得する
    pub fn peer_transport_params(&self) -> Option<&[u8]> {
        self.inner.quic_transport_parameters()
    }

    /// ネゴシエートされた ALPN プロトコルを取得する
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.inner.alpn_protocol()
    }

    /// ハンドシェイクが進行中かどうかを返す
    ///
    /// サーバーの場合、クライアントの Handshake Finished を受信・検証するまで true を返す。
    /// RFC 9001 Section 4.1.2: サーバーのハンドシェイクはクライアントの Finished を
    /// 受信・検証した時点で完了する。
    pub fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    /// TLS アラートコードを取得する
    pub fn alert(&self) -> Option<rustls::AlertDescription> {
        self.inner.alert()
    }

    /// 0-RTT 鍵を取得する (RFC 9001 Section 4.6)
    ///
    /// クライアントから 0-RTT を受け入れ可能な場合のみ利用可能。
    /// `read_handshake()` でクライアントの ClientHello を処理した後に呼び出す。
    /// サーバーは受信鍵として使用する。
    pub fn zero_rtt_keys(&self) -> Option<ZeroRttKeys> {
        let dk = self.inner.zero_rtt_keys()?;
        Some(ZeroRttKeys {
            packet: dk.packet,
            header: dk.header,
        })
    }

    /// ネゴシエート済み TLS 1.3 cipher suite の AEAD nonce 長 (バイト数) を返す
    ///
    /// draft-ietf-quic-multipath-21 Section 2.1 の MUST 要件の検証に使用する。
    /// 詳細は `ClientTlsSession::aead_nonce_len` を参照。
    pub fn aead_nonce_len(&self) -> Option<usize> {
        aead_nonce_len_from_suite(self.inner.negotiated_cipher_suite()?)
    }
}

/// ネゴシエート済み TLS 1.3 cipher suite の nonce 長を判定する
///
/// RFC 8446 の標準 TLS 1.3 suite はすべて 12 バイト nonce を使用する。
/// 未知の suite (将来追加される可能性) は `None` を返し、呼び出し側が
/// 保守的に失敗として扱えるようにする。
fn aead_nonce_len_from_suite(suite: rustls::SupportedCipherSuite) -> Option<usize> {
    use rustls::CipherSuite;
    match suite.suite() {
        // RFC 8446 Appendix B.4 の TLS 1.3 cipher suites
        // (Section 9.1 mandatory/recommended は上位 3 つ)
        // すべて AEAD の nonce 長は 12 バイト
        CipherSuite::TLS13_AES_128_GCM_SHA256
        | CipherSuite::TLS13_AES_256_GCM_SHA384
        | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        | CipherSuite::TLS13_AES_128_CCM_SHA256
        | CipherSuite::TLS13_AES_128_CCM_8_SHA256 => Some(12),
        _ => None,
    }
}

/// ClientHello の PSK identity 解析結果
enum ClientHelloParse {
    /// ClientHello 全体がまだ揃っていない
    NeedMore,
    /// PSK (pre_shared_key) 拡張が無い
    NoPsk,
    /// PSK identity (セッションチケット) が見つかった
    Psk(Vec<u8>),
    /// ClientHello として解釈できない
    Invalid,
}

/// ClientHello から PSK identity (セッションチケット) を取り出す
///
/// TLS 1.3 の ClientHello (RFC 8446 Section 4.1.2) を最小限解析する。0-RTT の
/// リプレイ検出にだけ使うため、証明書や署名の検証は行わない。完全な
/// ClientHello が揃っていない場合は `NeedMore` を返し、呼び出し側が
/// バッファを継続する。
fn parse_client_hello_psk_identity(buf: &[u8]) -> ClientHelloParse {
    const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
    const EXTENSION_PRE_SHARED_KEY: u16 = 41;
    // CRYPTO バッファが異常に大きくなった場合は解析を諦める (上限は実装の防御)
    const MAX_CLIENT_HELLO_LEN: usize = 64 * 1024;

    if buf.len() < 4 {
        return ClientHelloParse::NeedMore;
    }
    if buf[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return ClientHelloParse::Invalid;
    }
    let body_len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
    if body_len > MAX_CLIENT_HELLO_LEN {
        return ClientHelloParse::Invalid;
    }
    if buf.len() < 4 + body_len {
        return ClientHelloParse::NeedMore;
    }
    let body = &buf[4..4 + body_len];

    // legacy_version (2) + random (32)
    let mut pos = 2 + 32;
    // legacy_session_id
    let Some(session_id_len) = read_u8(body, &mut pos) else {
        return ClientHelloParse::Invalid;
    };
    pos = pos.saturating_add(usize::from(session_id_len));
    // cipher_suites
    let Some(cipher_suites_len) = read_u16(body, &mut pos) else {
        return ClientHelloParse::Invalid;
    };
    pos = pos.saturating_add(usize::from(cipher_suites_len));
    // legacy_compression_methods
    let Some(compression_len) = read_u8(body, &mut pos) else {
        return ClientHelloParse::Invalid;
    };
    pos = pos.saturating_add(usize::from(compression_len));
    // extensions
    let Some(extensions_len) = read_u16(body, &mut pos) else {
        return ClientHelloParse::Invalid;
    };
    let extensions_end = pos.saturating_add(usize::from(extensions_len));
    if extensions_end > body.len() {
        return ClientHelloParse::Invalid;
    }
    while pos + 4 <= extensions_end {
        let Some(extension_type) = read_u16(body, &mut pos) else {
            return ClientHelloParse::Invalid;
        };
        let Some(extension_len) = read_u16(body, &mut pos) else {
            return ClientHelloParse::Invalid;
        };
        let extension_end = pos.saturating_add(usize::from(extension_len));
        if extension_end > extensions_end {
            return ClientHelloParse::Invalid;
        }
        if extension_type == EXTENSION_PRE_SHARED_KEY {
            // identities: vec<{ identity: opaque, obfuscated_ticket_age: u32 }>
            let Some(identities_len) = read_u16(body, &mut pos) else {
                return ClientHelloParse::Invalid;
            };
            let identities_end = pos.saturating_add(usize::from(identities_len));
            if identities_end > extension_end || identities_end == pos {
                return ClientHelloParse::Invalid;
            }
            let Some(identity_len) = read_u16(body, &mut pos) else {
                return ClientHelloParse::Invalid;
            };
            let identity_end = pos.saturating_add(usize::from(identity_len));
            if identity_end > identities_end || identity_end == pos {
                return ClientHelloParse::Invalid;
            }
            return ClientHelloParse::Psk(body[pos..identity_end].to_vec());
        }
        pos = extension_end;
    }
    ClientHelloParse::NoPsk
}

/// バッファから 1 バイト読み進める
fn read_u8(buf: &[u8], pos: &mut usize) -> Option<u8> {
    let value = *buf.get(*pos)?;
    *pos += 1;
    Some(value)
}

/// バッファから 2 バイトのビッグエンディアン値を読み進める
fn read_u16(buf: &[u8], pos: &mut usize) -> Option<u16> {
    let end = pos.checked_add(2)?;
    let bytes = buf.get(*pos..end)?;
    *pos = end;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// rustls の KeyChange を内部型に変換する
fn convert_key_change(kc: rustls::quic::KeyChange) -> KeyChange {
    match kc {
        rustls::quic::KeyChange::Handshake { keys } => KeyChange::Handshake {
            keys: RustlsKeys {
                local: RustlsDirectionalKeys {
                    packet: keys.local.packet,
                    header: keys.local.header,
                },
                remote: RustlsDirectionalKeys {
                    packet: keys.remote.packet,
                    header: keys.remote.header,
                },
            },
        },
        rustls::quic::KeyChange::OneRtt { keys, next } => KeyChange::OneRtt {
            keys: RustlsKeys {
                local: RustlsDirectionalKeys {
                    packet: keys.local.packet,
                    header: keys.local.header,
                },
                remote: RustlsDirectionalKeys {
                    packet: keys.remote.packet,
                    header: keys.remote.header,
                },
            },
            next_secrets: next,
        },
    }
}

#[cfg(test)]
mod tests;
