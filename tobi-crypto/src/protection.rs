// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! パケット保護の適用と除去 (RFC 9001 Section 5.3, 5.4)
//!
//! パケットの暗号化/復号と Header Protection の適用/除去を行う。
//! 処理順序:
//! - 送信: AEAD 暗号化 → Header Protection 適用
//! - 受信: Header Protection 除去 → AEAD 復号

use crate::keys::{AeadKey, HeaderProtectionKey};
use tobi_core::error::Error;
use tobi_core::packet::header::is_long_header;

/// Header Protection を除去する
///
/// パケットバッファを変更して、first byte とパケット番号のマスクを除去する。
///
/// - `packet`: パケット全体のバッファ (変更される)
/// - `pn_offset`: パケット番号フィールドの開始オフセット
/// - `hp_key`: Header Protection 鍵
///
/// ヘッダ保護サンプルの開始オフセットを求める
///
/// サンプルはパケット番号フィールドの 4 バイト先から 16 バイトである
/// (RFC 9001 Section 5.4.2)。`pn_offset` は呼び出し元が渡す値なので、加算が
/// オーバーフローする可能性がある。`pn_offset` がどんな値でも panic / wrap せず、
/// サンプルが取れない場合は `Error::InvalidData` を返す
/// (RFC 9001 Section 5.4.2: 完全なサンプルを含まないパケットは破棄する MUST)。
fn hp_sample_offset(packet_len: usize, pn_offset: usize) -> Result<usize, Error> {
    pn_offset
        .checked_add(4)
        .and_then(|sample_offset| {
            sample_offset
                .checked_add(16)
                .map(|end| (sample_offset, end))
        })
        .filter(|(_, end)| *end <= packet_len)
        .map(|(sample_offset, _)| sample_offset)
        .ok_or_else(|| Error::InvalidData("packet too short for HP sample".to_string()))
}

/// 戻り値: パケット番号の長さ (1-4)
pub fn remove_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    hp_key: &HeaderProtectionKey,
) -> Result<u8, Error> {
    // サンプルはパケット番号フィールドの 4 バイト先から 16 バイト
    let sample_offset = hp_sample_offset(packet.len(), pn_offset)?;
    let sample: [u8; 16] = packet[sample_offset..sample_offset + 16]
        .try_into()
        .expect("slice is exactly 16 bytes, guaranteed by hp_sample_offset");
    let mask = hp_key.mask(&sample)?;

    // first byte のマスク除去
    if is_long_header(packet[0]) {
        packet[0] ^= mask[0] & 0x0f;
    } else {
        packet[0] ^= mask[0] & 0x1f;
    }

    // パケット番号の長さを取得 (マスク除去後の first byte から)
    let pn_len = (packet[0] & 0x03) + 1;

    // パケット番号フィールドのマスク除去
    for i in 0..pn_len as usize {
        packet[pn_offset + i] ^= mask[1 + i];
    }

    Ok(pn_len)
}

/// Header Protection を適用する
///
/// - `packet`: パケット全体のバッファ (変更される)
/// - `pn_offset`: パケット番号フィールドの開始オフセット
/// - `pn_len`: パケット番号の長さ (1-4)
/// - `hp_key`: Header Protection 鍵
pub fn apply_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    pn_len: u8,
    hp_key: &HeaderProtectionKey,
) -> Result<(), Error> {
    // パケット番号長は 1..=4 バイトである (RFC 9001 Section 5.4.1)。
    // 公開 API の利用者が範囲外の値を渡しても、mask の添字アクセスで
    // panic しないように事前に検証する。
    if !(1..=4).contains(&pn_len) {
        return Err(Error::InvalidData(
            "packet number length must be 1..=4".to_string(),
        ));
    }
    let sample_offset = hp_sample_offset(packet.len(), pn_offset)?;
    let sample: [u8; 16] = packet[sample_offset..sample_offset + 16]
        .try_into()
        .expect("slice is exactly 16 bytes, guaranteed by hp_sample_offset");
    let mask = hp_key.mask(&sample)?;

    // first byte のマスク適用
    if is_long_header(packet[0]) {
        packet[0] ^= mask[0] & 0x0f;
    } else {
        packet[0] ^= mask[0] & 0x1f;
    }

    // パケット番号フィールドのマスク適用
    for i in 0..pn_len as usize {
        packet[pn_offset + i] ^= mask[1 + i];
    }

    Ok(())
}

/// パケットペイロードを暗号化する
///
/// header はパケット番号を含むヘッダ全体 (AAD として使用)。
/// payload は暗号化するフレームデータ。
/// 暗号化後、payload の末尾に認証タグ (16 バイト) が追加される。
pub fn encrypt_payload(
    aead_key: &AeadKey,
    nonce: &[u8; 12],
    header: &[u8],
    payload: &mut Vec<u8>,
) -> Result<(), Error> {
    aead_key.encrypt_in_place(nonce, header, payload)
}

/// パケットペイロードを復号する
///
/// header はパケット番号を含むヘッダ全体 (AAD として使用)。
/// payload は認証タグを含む暗号文。
/// 復号後の平文の長さを返す。
pub fn decrypt_payload(
    aead_key: &AeadKey,
    nonce: &[u8; 12],
    header: &[u8],
    payload: &mut [u8],
) -> Result<usize, Error> {
    aead_key.decrypt_in_place(nonce, header, payload)
}
