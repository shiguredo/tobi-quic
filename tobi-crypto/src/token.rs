// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! HMAC ベースのアドレス検証トークン (RFC 9000 Section 8.1.3)
//!
//! `tobi_core::token::TokenProvider` の aws-lc-rs 実装。
//! RFC 10069 Section 3.1.3 SHOULD: 複数の検証済みアドレスを
//! 含むトークンを発行できる。

use std::net::SocketAddr;

use tobi_core::token::TokenProvider;
use zeroize::Zeroizing;

/// HMAC ベースのトークンプロバイダ (デフォルト実装)
///
/// トークン形式:
///   HMAC-SHA256(key, payload) (32 bytes) || payload
///   payload = issued_at (8 bytes, big-endian unix seconds)
///             || version (4 bytes, big-endian QUIC バージョン)
///             || count (1 byte, アドレス個数 1..=MAX_ADDRS)
///             || addr1 || addr2 || ... || addrN
///
/// 各 `addrX` は encode_addr() によって以下の形式でエンコードされる:
///   - IPv4: マーカー(1) + IP(4) + port(2) = 7 バイト
///   - IPv6: マーカー(1) + IP(16) + port(2) = 19 バイト
///
/// 検証時にトークンの HMAC を再計算し、有効期限と発行バージョンを確認した後、
/// 格納されたいずれかのアドレスと呼び出し側の `client_addr` が一致するかを
/// チェックする (IP のみ比較、ポートは無視)。
///
/// RFC 9369 Section 5: トークンは発行した QUIC バージョンに固有であり、
/// サーバーは別バージョンのトークンを受け入れてはならない (MUST)。
pub struct HmacTokenProvider {
    /// HMAC 鍵
    key: aws_lc_rs::hmac::Key,
    /// HMAC 鍵の元バイト列
    ///
    /// `aws_lc_rs::hmac::Key` の内部コンテキストは aws-lc-rs の Drop で
    /// クリーンアップされるが、元バイト列も `Zeroizing` で保持して drop 時に
    /// ゼロ化する。読み出しは行わない。
    _key_bytes: Zeroizing<[u8; 32]>,
    /// トークンの有効期間 (秒)
    lifetime_secs: u64,
    /// ポート番号もトークンの検証対象にするか
    ///
    /// 既定は false。NAT リバインディングでポートが変わってもトークンを
    /// 再利用できるようにする。NAT 配下の複数クライアントでトークンが
    /// 共有される範囲を狭めたい場合は true にする。
    bind_port: bool,
}

impl std::fmt::Debug for HmacTokenProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 鍵をログや Debug 出力へ出さない
        f.debug_struct("HmacTokenProvider")
            .field("key", &"[REDACTED]")
            .field("lifetime_secs", &self.lifetime_secs)
            .field("bind_port", &self.bind_port)
            .finish()
    }
}

impl HmacTokenProvider {
    /// トークンに格納できるアドレス数の上限
    ///
    /// Initial パケットに載せる Retry トークンや NEW_TOKEN のサイズ影響を
    /// 抑えるため 8 個までとする。IPv6 × 8 の場合 HMAC(32) + timestamp(8) +
    /// count(1) + 19 × 8 = 197 バイトに収まる。
    pub const MAX_ADDRS: usize = 8;

    /// 新しい HmacTokenProvider を作成する
    ///
    /// `key_bytes` は 32 バイトの HMAC 鍵。
    /// `lifetime_secs` はトークンの有効期間 (秒)。
    ///
    /// 鍵をローテーションする場合は、新しいプロバイダを作成してサーバーを
    /// 再起動するか、旧プロバイダと新プロバイダを `lifetime_secs` 以上の期間
    /// 併用する。旧鍵で発行したトークンは有効期間を過ぎると検証に失敗する。
    pub fn new(key_bytes: &[u8; 32], lifetime_secs: u64) -> Self {
        Self {
            key: aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key_bytes),
            _key_bytes: Zeroizing::new(*key_bytes),
            lifetime_secs,
            bind_port: false,
        }
    }

    /// トークンの検証にポート番号も含める
    ///
    /// 既定では IP のみを比較する。NAT 配下の複数クライアントが同じ IP を
    /// 共有する場合、あるクライアントが取得したトークンを別のクライアントが
    /// 再利用できる。これを狭めたい場合に true を指定する。ただし NAT の
    /// ポートリバインディングでトークンが無効になる。
    pub fn with_port_binding(mut self, bind_port: bool) -> Self {
        self.bind_port = bind_port;
        self
    }

    fn encode_addr(addr: &SocketAddr) -> Vec<u8> {
        match addr {
            SocketAddr::V4(v4) => {
                let mut buf = vec![4u8]; // v4 マーカー
                buf.extend_from_slice(&v4.ip().octets());
                buf.extend_from_slice(&v4.port().to_be_bytes());
                buf
            }
            SocketAddr::V6(v6) => {
                let mut buf = vec![6u8]; // v6 マーカー
                buf.extend_from_slice(&v6.ip().octets());
                buf.extend_from_slice(&v6.port().to_be_bytes());
                buf
            }
        }
    }

    /// 検証対象とするアドレスをトークンに格納できる形に整形する
    ///
    /// `addrs` が `MAX_ADDRS` を超える場合は末尾 (より新しい) のアドレスを残す。
    fn trim_addrs(addrs: &[SocketAddr]) -> &[SocketAddr] {
        if addrs.len() > Self::MAX_ADDRS {
            &addrs[addrs.len() - Self::MAX_ADDRS..]
        } else {
            addrs
        }
    }

    fn encode_payload(issued_at: u64, version: u32, addrs: &[SocketAddr]) -> Vec<u8> {
        let trimmed = Self::trim_addrs(addrs);
        let mut payload = Vec::new();
        payload.extend_from_slice(&issued_at.to_be_bytes());
        payload.extend_from_slice(&version.to_be_bytes());
        payload.push(trimmed.len() as u8);
        for addr in trimmed {
            payload.extend_from_slice(&Self::encode_addr(addr));
        }
        payload
    }
}

impl TokenProvider for HmacTokenProvider {
    fn generate_token(&self, client_addr: &SocketAddr, version: u32) -> Vec<u8> {
        self.generate_token_multi(std::slice::from_ref(client_addr), version)
    }

    fn generate_token_multi(&self, client_addrs: &[SocketAddr], version: u32) -> Vec<u8> {
        if client_addrs.is_empty() {
            return Vec::new();
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let payload = Self::encode_payload(now, version, client_addrs);
        let tag = aws_lc_rs::hmac::sign(&self.key, &payload);
        let mut token = tag.as_ref().to_vec();
        token.extend_from_slice(&payload);
        token
    }

    fn validate_token(&self, token: &[u8], client_addr: &SocketAddr, version: u32) -> bool {
        // 最小サイズ: HMAC(32) + timestamp(8) + version(4) + count(1) + addr_min(7 for IPv4)
        const MIN_TOKEN_LEN: usize = 32 + 8 + 4 + 1 + 7;
        if token.len() < MIN_TOKEN_LEN {
            return false;
        }

        let (mac_bytes, payload) = token.split_at(32);

        // HMAC 検証
        if aws_lc_rs::hmac::verify(&self.key, payload, mac_bytes).is_err() {
            return false;
        }

        // 有効期限チェック
        let issued_at = u64::from_be_bytes(
            payload[..8]
                .try_into()
                .expect("payload length is at least 8 bytes"),
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // `lifetime_secs` が u64::MAX でも debug ビルドで overflow しないようにする。
        if now > issued_at.saturating_add(self.lifetime_secs) {
            return false;
        }

        // 発行バージョン (4 バイト)。別バージョン向けのトークンは受け入れない (MUST)。
        let token_version = u32::from_be_bytes(
            payload[8..12]
                .try_into()
                .expect("payload length is at least 12 bytes"),
        );
        if token_version != version {
            return false;
        }

        // count (1 バイト)
        let count = payload[12] as usize;
        if count == 0 || count > Self::MAX_ADDRS {
            return false;
        }

        let expected = Self::encode_addr(client_addr);
        if expected.is_empty() {
            return false;
        }
        let expected_marker = expected[0];
        let expected_ip_len: usize = match expected_marker {
            4 => 4,
            6 => 16,
            _ => return false,
        };

        // アドレス列を順に走査し、いずれかが一致すれば true
        let mut offset = 13usize;
        for _ in 0..count {
            if offset >= payload.len() {
                return false;
            }
            let marker = payload[offset];
            let addr_bytes = match marker {
                4 => 7,  // 1 + 4 + 2
                6 => 19, // 1 + 16 + 2
                _ => return false,
            };
            if offset + addr_bytes > payload.len() {
                return false;
            }
            if marker == expected_marker {
                if self.bind_port {
                    // ポート番号まで含めて一致することを要求する
                    if payload[offset..offset + addr_bytes] == expected[..] {
                        return true;
                    }
                } else {
                    // IP のみ比較 (ポートは無視、NAT 環境で変わるため)
                    let ip_start = offset + 1;
                    let ip_end = ip_start + expected_ip_len;
                    if payload[ip_start..ip_end] == expected[1..1 + expected_ip_len] {
                        return true;
                    }
                }
            }
            offset += addr_bytes;
        }
        false
    }
}

#[cfg(test)]
mod tests;
