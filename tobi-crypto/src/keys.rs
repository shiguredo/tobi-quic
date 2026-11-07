// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! QUIC パケット保護の暗号操作 (RFC 9001)
//!
//! aws-lc-rs を使用した AEAD 暗号化/復号と Header Protection を実装する。
//! Initial Keys の導出 (RFC 9001 Section 5.2) も含む。

use tobi_core::connection_id::ConnectionId;
use tobi_core::error::Error;
use tobi_core::role::Role;
use zeroize::{Zeroize, Zeroizing};

use aws_lc_rs::aead;
use aws_lc_rs::hkdf;

/// QUIC version 1 の Initial Salt (RFC 9001 Section 5.2)
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// QUIC version 2 の Initial Salt (RFC 9369 Section 3.3.1)
const INITIAL_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// AEAD 鍵と IV のペア
pub struct AeadKey {
    key: aead::LessSafeKey,
    iv: [u8; 12],
}

impl Drop for AeadKey {
    fn drop(&mut self) {
        // `LessSafeKey` の内部鍵は aws-lc-rs が管理するため、ここでは
        // 自前で保持する IV をゼロ化する。IV は秘密ではないが、鍵素材と
        // 同じ構造体に残さないことでメモリ上の残留を減らす。
        self.iv.zeroize();
    }
}

impl AeadKey {
    /// AEAD 暗号化 (in-place)
    ///
    /// payload の末尾に認証タグ (16 バイト) が追加される
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        payload: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let nonce = aead::Nonce::assume_unique_for_key(*nonce);
        let aad = aead::Aad::from(aad);
        self.key
            .seal_in_place_append_tag(nonce, aad, payload)
            .map_err(|_| Error::InvalidData("AEAD encryption failed".to_string()))?;
        Ok(())
    }

    /// AEAD 復号 (in-place)
    ///
    /// 復号後の平文の長さを返す (認証タグ分だけ短くなる)
    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        payload: &mut [u8],
    ) -> Result<usize, Error> {
        let nonce = aead::Nonce::assume_unique_for_key(*nonce);
        let aad = aead::Aad::from(aad);
        let plaintext = self
            .key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::InvalidData("AEAD decryption failed".to_string()))?;
        Ok(plaintext.len())
    }

    /// IV を返す
    pub fn iv(&self) -> &[u8; 12] {
        &self.iv
    }
}

/// Header Protection 鍵
pub struct HeaderProtectionKey {
    key: aead::quic::HeaderProtectionKey,
}

impl HeaderProtectionKey {
    /// Header Protection マスクを生成する
    ///
    /// sample は暗号化済みペイロードから取得した 16 バイト
    pub fn mask(&self, sample: &[u8]) -> Result<[u8; 5], Error> {
        let sample_arr: &[u8; 16] = sample
            .try_into()
            .map_err(|_| Error::InvalidData("HP sample must be 16 bytes".to_string()))?;
        let mask = self
            .key
            .new_mask(sample_arr)
            .map_err(|_| Error::InvalidData("HP mask generation failed".to_string()))?;
        Ok(mask)
    }
}

/// 暗号化レベル
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionLevel {
    Initial,
    Handshake,
    OneRtt,
}

/// パケット鍵のペア (送信用 + 受信用)
pub struct PacketKeys {
    pub local: DirectionalKeys,
    pub remote: DirectionalKeys,
}

/// 片方向の鍵セット (AEAD + Header Protection)
pub struct DirectionalKeys {
    pub aead: AeadKey,
    pub hp: HeaderProtectionKey,
}

/// Initial Salt を QUIC バージョンから返す
///
/// v1 は RFC 9001 Section 5.2、v2 は RFC 9369 Section 3.3.1 の値を使う。
fn initial_salt(version: u32) -> Result<&'static [u8; 20], Error> {
    match version {
        tobi_core::packet::QUIC_VERSION_1 => Ok(&INITIAL_SALT_V1),
        tobi_core::packet::QUIC_VERSION_2 => Ok(&INITIAL_SALT_V2),
        _ => Err(Error::InvalidData(format!(
            "unsupported QUIC version for initial keys: {version:#010x}"
        ))),
    }
}

/// バージョンに対応する HKDF-Expand-Label のラベルを返す
///
/// v2 は v1 の "quic " プレフィックスが "quicv2 " に変わる
/// (RFC 9369 Section 3.3.2)。
fn packet_key_label(version: u32, suffix: &'static [u8]) -> Result<Vec<u8>, Error> {
    match version {
        tobi_core::packet::QUIC_VERSION_1 => {
            let mut label = Vec::new();
            label.extend_from_slice(b"quic ");
            label.extend_from_slice(suffix);
            Ok(label)
        }
        tobi_core::packet::QUIC_VERSION_2 => {
            let mut label = Vec::new();
            label.extend_from_slice(b"quicv2 ");
            label.extend_from_slice(suffix);
            Ok(label)
        }
        _ => Err(Error::InvalidData(format!(
            "unsupported QUIC version for key labels: {version:#010x}"
        ))),
    }
}

/// Initial Keys を DCID から導出する (RFC 9001 Section 5.2 / RFC 9369 Section 3.3)
///
/// `version` に対応する Initial Salt とラベルを使う。導出するのは
/// client / server 両方向の鍵で、`role` に応じてどちらを `local` / `remote` に
/// 割り当てるかが決まる。role を引数で必須にすることで、呼び出し側が
/// 送受信鍵を取り違える余地を無くす。
pub fn derive_initial_keys(
    version: u32,
    dcid: &ConnectionId,
    role: Role,
) -> Result<PacketKeys, Error> {
    // initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
    let salt_bytes = initial_salt(version)?;
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt_bytes);
    let initial_secret = salt.extract(dcid.as_bytes());

    // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    let client_secret = hkdf_expand_label(&initial_secret, b"client in", 32)?;

    // server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
    let server_secret = hkdf_expand_label(&initial_secret, b"server in", 32)?;

    let client_keys = derive_packet_keys(version, &client_secret)?;
    let server_keys = derive_packet_keys(version, &server_secret)?;

    // RFC 9001 Section 5.2: "client in" はクライアントの送信 (サーバーの受信)、
    // "server in" はサーバーの送信 (クライアントの受信) に使う。
    Ok(match role {
        Role::Client => PacketKeys {
            local: client_keys,
            remote: server_keys,
        },
        Role::Server => PacketKeys {
            local: server_keys,
            remote: client_keys,
        },
    })
}

/// シークレットからパケット鍵を導出する
///
/// ラベルはバージョンごとに異なる (RFC 9369 Section 3.3.2)。
fn derive_packet_keys(version: u32, secret_bytes: &[u8]) -> Result<DirectionalKeys, Error> {
    let secret = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret_bytes);

    // key = HKDF-Expand-Label(secret, "quic key" / "quicv2 key", "", 16)
    let key_bytes = hkdf_expand_label_from_prk(&secret, &packet_key_label(version, b"key")?, 16)?;

    // iv = HKDF-Expand-Label(secret, "quic iv" / "quicv2 iv", "", 12)
    let iv_bytes = hkdf_expand_label_from_prk(&secret, &packet_key_label(version, b"iv")?, 12)?;

    // hp = HKDF-Expand-Label(secret, "quic hp" / "quicv2 hp", "", 16)
    let hp_bytes = hkdf_expand_label_from_prk(&secret, &packet_key_label(version, b"hp")?, 16)?;

    let unbound_key = aead::UnboundKey::new(&aead::AES_128_GCM, &key_bytes)
        .map_err(|_| Error::InvalidData("failed to create AEAD key".to_string()))?;

    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_bytes);

    let hp_key = aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &hp_bytes)
        .map_err(|_| Error::InvalidData("failed to create HP key".to_string()))?;

    Ok(DirectionalKeys {
        aead: AeadKey {
            key: aead::LessSafeKey::new(unbound_key),
            iv,
        },
        hp: HeaderProtectionKey { key: hp_key },
    })
}

/// HKDF-Expand-Label (TLS 1.3 式)
///
/// PRK から指定ラベルで鍵素材を導出する
fn hkdf_expand_label(
    prk: &hkdf::Prk,
    label: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let hkdf_label = build_hkdf_label(label, length);
    let info = [hkdf_label.as_slice()];
    let okm = prk
        .expand(&info, HkdfLen(length))
        .map_err(|_| Error::InvalidData("HKDF-Expand-Label failed".to_string()))?;
    // 導出した鍵素材はスコープ終了時にゼロ化する
    let mut out = Zeroizing::new(vec![0u8; length]);
    okm.fill(&mut out)
        .map_err(|_| Error::InvalidData("HKDF fill failed".to_string()))?;
    Ok(out)
}

/// Prk から HKDF-Expand-Label
fn hkdf_expand_label_from_prk(
    prk: &hkdf::Prk,
    label: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    hkdf_expand_label(prk, label, length)
}

/// TLS 1.3 の HkdfLabel 構造をビルドする
///
/// ```text
/// struct {
///    uint16 length;
///    opaque label<7..255>;  // "tls13 " + label
///    opaque context<0..255>;
/// } HkdfLabel;
/// ```
fn build_hkdf_label(label: &[u8], length: usize) -> Vec<u8> {
    let full_label_len = 6 + label.len(); // "tls13 " の 6 バイト + label
    let mut hkdf_label = Vec::with_capacity(2 + 1 + full_label_len + 1);

    // length (uint16)
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
    // label length (uint8)
    hkdf_label.push(full_label_len as u8);
    // "tls13 " + label
    hkdf_label.extend_from_slice(b"tls13 ");
    hkdf_label.extend_from_slice(label);
    // context length (uint8) + context (空)
    hkdf_label.push(0);

    hkdf_label
}

/// HKDF の出力長を指定するための型
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Retry Integrity Tag の固定キー (RFC 9001 Section 5.8)
const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

/// Retry Integrity Tag の固定ノンス (RFC 9001 Section 5.8)
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// Retry Integrity Tag の固定キー (QUIC v2, RFC 9369 Section 3.3.3)
const RETRY_INTEGRITY_KEY_V2: [u8; 16] = [
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
];

/// Retry Integrity Tag の固定ノンス (QUIC v2, RFC 9369 Section 3.3.3)
const RETRY_INTEGRITY_NONCE_V2: [u8; 12] = [
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
];

/// バージョンに対応する Retry Integrity Tag のキーとノンスを返す
fn retry_integrity_params(version: u32) -> Result<(&'static [u8; 16], &'static [u8; 12]), Error> {
    match version {
        tobi_core::packet::QUIC_VERSION_1 => {
            Ok((&RETRY_INTEGRITY_KEY_V1, &RETRY_INTEGRITY_NONCE_V1))
        }
        tobi_core::packet::QUIC_VERSION_2 => {
            Ok((&RETRY_INTEGRITY_KEY_V2, &RETRY_INTEGRITY_NONCE_V2))
        }
        _ => Err(Error::InvalidData(format!(
            "unsupported QUIC version for retry integrity tag: {version:#010x}"
        ))),
    }
}

/// Retry パケットの Integrity Tag を検証する (RFC 9001 Section 5.8 / RFC 9369 Section 3.3.3)
///
/// Retry Pseudo-Packet を構築し、AES-128-GCM で検証する。
/// - `version`: Retry パケットの QUIC バージョン (キーとノンスの選択に使う)
/// - `retry_packet`: Retry パケット全体 (末尾 16 バイトが Integrity Tag)
/// - `original_dcid`: クライアントが最初の Initial で使用した DCID
pub fn verify_retry_integrity_tag(
    version: u32,
    retry_packet: &[u8],
    original_dcid: &ConnectionId,
) -> Result<(), Error> {
    if retry_packet.len() < 16 {
        return Err(Error::InvalidData(
            "Retry packet too short for integrity tag".into(),
        ));
    }

    let tag_offset = retry_packet.len() - 16;
    let retry_without_tag = &retry_packet[..tag_offset];
    let expected_tag = &retry_packet[tag_offset..];

    // Retry Pseudo-Packet = ODCID Length (1 byte) || ODCID || Retry Packet (without tag)
    let mut pseudo_packet = Vec::with_capacity(1 + original_dcid.len() + retry_without_tag.len());
    pseudo_packet.push(original_dcid.len() as u8);
    pseudo_packet.extend_from_slice(original_dcid.as_bytes());
    pseudo_packet.extend_from_slice(retry_without_tag);

    // AES-128-GCM で空の平文を暗号化し、タグのみ生成して比較する
    let (integrity_key, integrity_nonce) = retry_integrity_params(version)?;
    let key = aead::UnboundKey::new(&aead::AES_128_GCM, integrity_key)
        .map_err(|_| Error::InvalidData("failed to create Retry integrity key".into()))?;
    let key = aead::LessSafeKey::new(key);
    let nonce = aead::Nonce::assume_unique_for_key(*integrity_nonce);
    let aad = aead::Aad::from(pseudo_packet.as_slice());

    // 空の平文で seal → 生成された 16 バイトのタグを比較する
    let mut empty = Vec::new();
    key.seal_in_place_append_tag(nonce, aad, &mut empty)
        .map_err(|_| Error::InvalidData("Retry integrity tag computation failed".into()))?;

    // 定数時間比較
    if empty.len() != 16 || !constant_time_eq(&empty, expected_tag) {
        return Err(Error::InvalidData(
            "Retry integrity tag verification failed".into(),
        ));
    }

    Ok(())
}

/// 定数時間のバイト列比較 (公開版)
///
/// Retry integrity tag の検証と Stateless Reset Token の照合で使う。
/// RFC 9000 Section 10.3 は Stateless Reset Token の比較を定数時間で行うことを
/// 要求する。
pub fn constant_time_eq_pub(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq(a, b)
}

/// 定数時間のバイト列比較 (内部用)
///
/// aws-lc-rs の `verify_slices_are_equal` (内部で C の `CRYPTO_memcmp`) に委ねる。
/// 自前の Rust ループは定数時間性が保証されず、LLVM の最適化で早期終了しうる。
/// 長さが異なる場合は `Err` が返るが、これは比較結果が偽であることと同じ意味で
/// あるため `false` に落とす。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// Retry Integrity Tag を生成する (RFC 9001 Section 5.8 / RFC 9369 Section 3.3.3)
///
/// `verify_retry_integrity_tag()` の逆操作。
/// Retry パケットの全バイト列 (Tag を除く) と元の DCID から 16 バイトの Tag を計算する。
fn generate_retry_integrity_tag(
    version: u32,
    retry_without_tag: &[u8],
    original_dcid: &ConnectionId,
) -> Result<[u8; 16], Error> {
    // Retry Pseudo-Packet = ODCID Length (1 byte) || ODCID || Retry Packet (without tag)
    let mut pseudo_packet = Vec::with_capacity(1 + original_dcid.len() + retry_without_tag.len());
    pseudo_packet.push(original_dcid.len() as u8);
    pseudo_packet.extend_from_slice(original_dcid.as_bytes());
    pseudo_packet.extend_from_slice(retry_without_tag);

    let (integrity_key, integrity_nonce) = retry_integrity_params(version)?;
    let key = aead::UnboundKey::new(&aead::AES_128_GCM, integrity_key)
        .map_err(|_| Error::InvalidData("failed to create Retry integrity key".into()))?;
    let key = aead::LessSafeKey::new(key);
    let nonce = aead::Nonce::assume_unique_for_key(*integrity_nonce);
    let aad = aead::Aad::from(pseudo_packet.as_slice());

    let mut empty = Vec::new();
    key.seal_in_place_append_tag(nonce, aad, &mut empty)
        .map_err(|_| Error::InvalidData("Retry integrity tag computation failed".into()))?;

    let mut tag = [0u8; 16];
    tag.copy_from_slice(&empty[..16]);
    Ok(tag)
}

/// Retry パケットを生成する (RFC 9000 Section 17.2.5 / RFC 9369 Section 3.2)
///
/// サーバーがアドレス検証のために送信する。Connection 確立前に呼び出す。
/// Retry はクライアントが最初に使ったバージョンで送らなければならない
/// (RFC 9369 Section 4.1)。
///
/// - `version`: クライアントの Initial と同じ QUIC バージョン
/// - `original_dcid`: クライアントが送信した Initial パケットの DCID
/// - `client_scid`: クライアントの SCID (Retry の DCID になる)
/// - `server_new_scid`: サーバーが生成する新しい CID (Retry の SCID)
/// - `retry_token`: クライアントに送るトークン (アドレス情報をエンコード)
///
/// RFC 9000 Section 17.2.5 準拠のレイアウト:
/// Long Header: First Byte || Version (4) || DCID Len (1) || DCID || SCID Len (1) || SCID
/// || Retry Token (variable) || Retry Integrity Tag (16)
pub fn generate_retry_packet(
    version: u32,
    original_dcid: &ConnectionId,
    client_scid: &ConnectionId,
    server_new_scid: &ConnectionId,
    retry_token: &[u8],
) -> Result<Vec<u8>, Error> {
    // 先頭バイト: Long Header (0x80) | Fixed Bit (0x40) | Retry Type | random 4 bits。
    // Retry の type bits はバージョンごとに異なる (RFC 9369 Section 3.2)。
    let type_bits = tobi_core::packet::LongPacketType::Retry.to_bits_for_version(version);
    let mut first_byte = [0u8; 1];
    aws_lc_rs::rand::fill(&mut first_byte)
        .map_err(|_| Error::InvalidData("failed to generate random bytes".into()))?;
    let first = 0xc0 | (type_bits << 4) | (first_byte[0] & 0x0f);

    let mut packet = Vec::new();
    packet.push(first);

    // Version (クライアントの Initial と同じバージョン)
    packet.extend_from_slice(&version.to_be_bytes());

    // DCID (= クライアントの SCID)
    packet.push(client_scid.len() as u8);
    packet.extend_from_slice(client_scid.as_bytes());

    // SCID (= サーバーの新しい CID)
    packet.push(server_new_scid.len() as u8);
    packet.extend_from_slice(server_new_scid.as_bytes());

    // Retry Token
    packet.extend_from_slice(retry_token);

    // Retry Integrity Tag を計算して付加する
    let tag = generate_retry_integrity_tag(version, &packet, original_dcid)?;
    packet.extend_from_slice(&tag);

    Ok(packet)
}

/// Retry Token を生成する (サーバー側)
///
/// クライアントのアドレス情報を暗号化してトークンに含める。
/// AEAD (AES-128-GCM) で保護する。
///
/// トークンの内容:
/// - Original DCID Length (1) || Original DCID
/// - Client IP (4 or 16 bytes, depending on addr type)
/// - Client Port (2)
/// - Timestamp (8, Unix epoch seconds)
///
/// - `original_dcid`: クライアントが送信した Original DCID
/// - `client_addr`: クライアントのソケットアドレス
/// - `token_key`: トークン暗号化用の 16 バイトキー
pub fn generate_retry_token(
    original_dcid: &ConnectionId,
    client_addr: std::net::SocketAddr,
    token_key: &[u8; 16],
    version: u32,
) -> Result<Vec<u8>, Error> {
    // 平文にはクライアントアドレスと時刻が入るため、スコープ終了時にゼロ化する
    let mut plaintext = Zeroizing::new(Vec::new());

    // Original DCID
    plaintext.push(original_dcid.len() as u8);
    plaintext.extend_from_slice(original_dcid.as_bytes());

    // Client address
    plaintext.extend_from_slice(&encode_retry_token_addr(client_addr));

    // Timestamp (秒単位)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    plaintext.extend_from_slice(&timestamp.to_be_bytes());
    // RFC 9369 Section 5: トークンは発行した QUIC バージョンに固有。
    plaintext.extend_from_slice(&version.to_be_bytes());

    encrypt_retry_token_plaintext(&plaintext, token_key)
}

/// Retry Token を生成する (Retry の SCID を含む拡張版)
///
/// RFC 9000 Section 7.3: サーバーは Retry を送った場合、
/// `retry_source_connection_id` transport parameter で Retry の SCID を
/// 通知しなければならない (MUST)。Retry ごとに SCID は変わるため、
/// 2 回目の Initial を受信したときにどの SCID を通知すべきかを知る必要がある。
/// ここでは token に Retry の SCID を埋め込んで再計算できるようにする。
///
/// ペイロード: Original DCID Length (1) || Original DCID
///             || Retry SCID Length (1) || Retry SCID
///             || Client Address || Timestamp
pub fn generate_retry_token_with_scid(
    original_dcid: &ConnectionId,
    retry_scid: &ConnectionId,
    client_addr: std::net::SocketAddr,
    token_key: &[u8; 16],
    version: u32,
) -> Result<Vec<u8>, Error> {
    // 平文にはクライアントアドレスと時刻が入るため、スコープ終了時にゼロ化する
    let mut plaintext = Zeroizing::new(Vec::new());
    plaintext.push(original_dcid.len() as u8);
    plaintext.extend_from_slice(original_dcid.as_bytes());
    plaintext.push(retry_scid.len() as u8);
    plaintext.extend_from_slice(retry_scid.as_bytes());
    plaintext.extend_from_slice(&encode_retry_token_addr(client_addr));

    // Timestamp (秒単位)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    plaintext.extend_from_slice(&timestamp.to_be_bytes());
    // RFC 9369 Section 5: トークンは発行した QUIC バージョンに固有。
    plaintext.extend_from_slice(&version.to_be_bytes());

    encrypt_retry_token_plaintext(&plaintext, token_key)
}

/// Retry Token を検証する (Retry の SCID を含む拡張版)
///
/// 成功時は `(original_dcid, retry_scid)` を返す。
/// `max_age_secs` が 0 の場合は有効期限を判定しない。
pub fn validate_retry_token_with_scid(
    token: &[u8],
    client_addr: std::net::SocketAddr,
    token_key: &[u8; 16],
    max_age_secs: u64,
    version: u32,
) -> Result<(ConnectionId, ConnectionId), Error> {
    let plaintext = decrypt_retry_token(token, token_key)?;
    let mut pos = 0;

    let original_dcid = take_retry_token_cid(&plaintext, &mut pos, "odcid")?;
    let retry_scid = take_retry_token_cid(&plaintext, &mut pos, "retry scid")?;
    verify_retry_token_addr(&plaintext, &mut pos, client_addr)?;
    verify_retry_token_timestamp(&plaintext, &mut pos, max_age_secs)?;
    verify_retry_token_version(&plaintext[..], &mut pos, version)?;

    Ok((original_dcid, retry_scid))
}

/// Retry token のアドレス部をエンコードする
fn encode_retry_token_addr(client_addr: std::net::SocketAddr) -> Vec<u8> {
    let mut buf = Vec::new();
    match client_addr.ip() {
        std::net::IpAddr::V4(ip) => {
            buf.push(4);
            buf.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            buf.push(6);
            buf.extend_from_slice(&ip.octets());
        }
    }
    buf.extend_from_slice(&client_addr.port().to_be_bytes());
    buf
}

/// Retry token の平文を AEAD で暗号化して token を組み立てる
fn encrypt_retry_token_plaintext(plaintext: &[u8], token_key: &[u8; 16]) -> Result<Vec<u8>, Error> {
    let key = aead::UnboundKey::new(&aead::AES_128_GCM, token_key)
        .map_err(|_| Error::InvalidData("failed to create token key".into()))?;
    let key = aead::LessSafeKey::new(key);
    let mut nonce_bytes = [0u8; 12];
    aws_lc_rs::rand::fill(&mut nonce_bytes)
        .map_err(|_| Error::InvalidData("failed to generate nonce".into()))?;
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut buf = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut buf)
        .map_err(|_| Error::InvalidData("token encryption failed".into()))?;

    let mut token = Vec::with_capacity(12 + buf.len());
    token.extend_from_slice(&nonce_bytes);
    token.extend_from_slice(&buf);
    Ok(token)
}

/// Retry token を復号して平文を返す
fn decrypt_retry_token(token: &[u8], token_key: &[u8; 16]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if token.len() < 12 {
        return Err(Error::InvalidData("retry token too short".into()));
    }
    let nonce_bytes: [u8; 12] = token[..12]
        .try_into()
        .map_err(|_| Error::InvalidData("invalid nonce".into()))?;
    // 復号後の平文はスコープ終了時にゼロ化する
    let mut ciphertext = Zeroizing::new(token[12..].to_vec());

    let key = aead::UnboundKey::new(&aead::AES_128_GCM, token_key)
        .map_err(|_| Error::InvalidData("failed to create token key".into()))?;
    let key = aead::LessSafeKey::new(key);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let plaintext = key
        .open_in_place(nonce, aead::Aad::empty(), &mut ciphertext)
        .map_err(|_| Error::InvalidData("retry token decryption failed".into()))?;
    Ok(Zeroizing::new(plaintext.to_vec()))
}

/// 平文から CID を取り出す
fn take_retry_token_cid(
    plaintext: &[u8],
    pos: &mut usize,
    name: &str,
) -> Result<ConnectionId, Error> {
    if *pos >= plaintext.len() {
        return Err(Error::InvalidData(format!("retry token truncated {name}")));
    }
    let len = plaintext[*pos] as usize;
    *pos += 1;
    if *pos + len > plaintext.len() {
        return Err(Error::InvalidData(format!("retry token invalid {name}")));
    }
    let cid = ConnectionId::from_slice(&plaintext[*pos..*pos + len])
        .map_err(|_| Error::InvalidData(format!("retry token invalid {name}")))?;
    *pos += len;
    Ok(cid)
}

/// 平文のアドレス部を検証する
fn verify_retry_token_addr(
    plaintext: &[u8],
    pos: &mut usize,
    client_addr: std::net::SocketAddr,
) -> Result<(), Error> {
    if *pos >= plaintext.len() {
        return Err(Error::InvalidData("retry token truncated".into()));
    }
    let addr_type = plaintext[*pos];
    *pos += 1;
    let expected_ip: std::net::IpAddr = match addr_type {
        4 => {
            if *pos + 4 > plaintext.len() {
                return Err(Error::InvalidData("retry token truncated ipv4".into()));
            }
            let octets: [u8; 4] = plaintext[*pos..*pos + 4]
                .try_into()
                .map_err(|_| Error::InvalidData("bad ipv4".into()))?;
            *pos += 4;
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets))
        }
        6 => {
            if *pos + 16 > plaintext.len() {
                return Err(Error::InvalidData("retry token truncated ipv6".into()));
            }
            let octets: [u8; 16] = plaintext[*pos..*pos + 16]
                .try_into()
                .map_err(|_| Error::InvalidData("bad ipv6".into()))?;
            *pos += 16;
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        _ => return Err(Error::InvalidData("retry token invalid addr type".into())),
    };
    if *pos + 2 > plaintext.len() {
        return Err(Error::InvalidData("retry token truncated port".into()));
    }
    let expected_port = u16::from_be_bytes([plaintext[*pos], plaintext[*pos + 1]]);
    *pos += 2;
    if client_addr.ip() != expected_ip || client_addr.port() != expected_port {
        return Err(Error::InvalidData("retry token address mismatch".into()));
    }
    Ok(())
}

/// 平文の timestamp を検証する
///
/// `max_age_secs` が 0 の場合は有効期限を判定しない。
fn verify_retry_token_timestamp(
    plaintext: &[u8],
    pos: &mut usize,
    max_age_secs: u64,
) -> Result<(), Error> {
    if *pos + 8 > plaintext.len() {
        return Err(Error::InvalidData("retry token truncated timestamp".into()));
    }
    let token_time = u64::from_be_bytes(
        plaintext[*pos..*pos + 8]
            .try_into()
            .map_err(|_| Error::InvalidData("bad timestamp".into()))?,
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if max_age_secs > 0 && now.saturating_sub(token_time) > max_age_secs {
        return Err(Error::InvalidData("retry token expired".into()));
    }
    *pos += 8;
    Ok(())
}

/// 平文の発行バージョンを検証する (RFC 9369 Section 5)
///
/// サーバーはトークンの発行バージョンと接続のバージョンが一致する場合のみ
/// 受理しなければならない (MUST)。
fn verify_retry_token_version(
    plaintext: &[u8],
    pos: &mut usize,
    version: u32,
) -> Result<(), Error> {
    if *pos + 4 > plaintext.len() {
        return Err(Error::InvalidData("retry token truncated version".into()));
    }
    let token_version = u32::from_be_bytes(
        plaintext[*pos..*pos + 4]
            .try_into()
            .map_err(|_| Error::InvalidData("bad version".into()))?,
    );
    *pos += 4;
    if token_version != version {
        return Err(Error::InvalidData("retry token version mismatch".into()));
    }
    Ok(())
}

/// Retry Token を検証する (サーバー側)
///
/// トークンを復号し、クライアントのアドレスと有効期限を検証する。
/// 成功時は Original DCID を返す。
///
/// - `token`: クライアントが送信してきた Token
/// - `client_addr`: 送信元のソケットアドレス
/// - `token_key`: トークン暗号化用の 16 バイトキー
/// - `max_age_secs`: トークンの最大有効期限 (秒)。0 は無期限
pub fn validate_retry_token(
    token: &[u8],
    client_addr: std::net::SocketAddr,
    token_key: &[u8; 16],
    max_age_secs: u64,
    version: u32,
) -> Result<ConnectionId, Error> {
    // `validate_retry_token_with_scid` と同じ復号・検証経路を使い、
    // `max_age_secs` の意味が 2 つの API で乖離しないようにする。
    let plaintext = decrypt_retry_token(token, token_key)?;
    let mut pos = 0;

    let original_dcid = take_retry_token_cid(&plaintext[..], &mut pos, "odcid")?;
    verify_retry_token_addr(&plaintext[..], &mut pos, client_addr)?;
    verify_retry_token_timestamp(&plaintext[..], &mut pos, max_age_secs)?;
    verify_retry_token_version(&plaintext[..], &mut pos, version)?;

    Ok(original_dcid)
}

/// CID と静的シークレットから Stateless Reset Token を生成する (RFC 9000 Section 10.3.2)
///
/// HMAC-SHA256(static_key, cid) の先頭 16 バイトを Token として使用する。
/// Token はサーバー再起動後も同じである必要があるため、static_key は永続的に保持する。
pub fn generate_stateless_reset_token(cid: &[u8], static_key: &[u8]) -> [u8; 16] {
    use aws_lc_rs::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, static_key);
    let tag = hmac::sign(&key, cid);
    let mut token = [0u8; 16];
    token.copy_from_slice(&tag.as_ref()[..16]);
    token
}

/// Stateless Reset パケットを生成する (RFC 9000 Section 10.3.1)
///
/// Connection 外から呼び出す。認識不能なパケットに対して返す。
///
/// - `token`: `generate_stateless_reset_token()` で生成した 16 バイトの Token
/// - `received_size`: 受信パケットのサイズ (受信パケットより厳密に小さいサイズにする)
///
/// RFC 9000 Section 10.3.1 準拠のレイアウト:
/// - 先頭バイト: 0x40 | random 6 bits (Short Header に見えるように)
/// - ランダムデータ (最低 4 バイト)
/// - 末尾 16 バイト: Stateless Reset Token
///
/// 最小 21 バイト (1 + 4 unpredictable + 16 token)。
pub fn generate_stateless_reset(token: &[u8; 16], received_size: usize) -> Option<Vec<u8>> {
    // 有効な Stateless Reset の最小 21 バイト (RFC 9000 Section 10.3 の
    // 「resulting minimum size of 21 bytes」)。1 + 4 unpredictable + 16 token
    let min_size = 21;
    // 21 バイト以下では 1 バイト短縮すると最小 21 バイトを下回り有効な Stateless Reset を作れない。
    // RFC 9000 Section 10.3.3 のループ防止はパケットが「too small to trigger a response」に
    // 収束することで成立するため、ここでは reset を返さない
    if received_size <= min_size {
        return None;
    }
    let size = if received_size > 43 {
        // 43 バイト超のパケットに対しては 43 バイトに固定する。根拠:
        // - RFC 9000 Section 10.3.3: triggered パケット (44 バイト以上) より厳密に小さい (ループ防止 MUST)
        // - RFC 9000 Section 10.3.3: 識別されにくさの目安である 41 バイト以上
        // - RFC 9000 Section 10.3: 3 倍未満で増幅攻撃を防ぐ (MUST NOT)
        43
    } else {
        // RFC 9000 Section 10.3: 43 バイト以下のパケットには 1 バイト短い Stateless Reset を返す (SHOULD)
        // RFC 9000 Section 10.3.3: triggered パケットより厳密に小さい (ループ防止 MUST)。
        // received_size >= 22 が保証されているため、計算結果は最小 21 バイト以上になる
        received_size - 1
    };
    let random_len = size - 1 - 16; // 先頭バイト + ランダム + Token

    let mut packet = Vec::with_capacity(size);

    // 先頭バイト: Fixed Bit (0x40) を設定し、残り 6 ビットをランダムにする
    let mut first = [0u8; 1];
    aws_lc_rs::rand::fill(&mut first).ok()?;
    // Fixed Bit を立てる (0x40)、Header Form bit は 0 (Short Header に見える)
    packet.push((first[0] & 0x3f) | 0x40);

    // ランダムデータ
    let mut random_data = vec![0u8; random_len];
    aws_lc_rs::rand::fill(&mut random_data).ok()?;
    packet.extend_from_slice(&random_data);

    // 末尾 16 バイト: Stateless Reset Token
    packet.extend_from_slice(token);

    Some(packet)
}

#[cfg(test)]
mod tests;
