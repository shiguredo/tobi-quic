// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! パケット番号のエンコード/デコード/復元 (RFC 9000 Section 17.1, Appendix A)
//!
//! パケット番号は 1-4 バイトでエンコードされる。
//! Header Protection が適用されているため、復号前にヘッダ保護を除去する必要がある。

use crate::error::Error;

/// パケット番号の最大値 (RFC 9000 Section 12.3: 0 から 2^62-1)
///
/// 送信側は送信に使用するパケット番号がこの値に達した時点で接続を閉じる
/// (RFC 9000 Section 12.3 MUST)。受信側は復元したパケット番号がこの値を
/// 超えるパケットを破棄する。
pub const MAX_PACKET_NUMBER: u64 = (1 << 62) - 1;

/// パケット番号をエンコードする際の最適な長さを決定する
///
/// RFC 9000 Appendix A.2
///
/// - `full_pn`: 送信するパケット番号 (2^62-1 以下)
/// - `largest_acked`: 相手が ACK した最大パケット番号。None の場合は初回送信
pub fn encode_length(full_pn: u64, largest_acked: Option<u64>) -> u8 {
    // RFC 9000 Section 12.3: パケット番号は 0 から 2^62-1。送信側は上限に達すると
    // パケットを送信せずに接続を閉じるため、ここには常に有効値が渡される。
    // 有効値では num_unacked * 2 が 2^63 を超えず、算術が overflow しない前提を明示する。
    debug_assert!(
        full_pn <= MAX_PACKET_NUMBER,
        "full packet number must not exceed 2^62-1"
    );

    // ACK されたパケットがない場合、全パケットが in-flight
    let num_unacked = match largest_acked {
        Some(acked) => full_pn.saturating_sub(acked),
        None => full_pn + 1,
    };

    // num_unacked * 2 以上の表現範囲が必要
    let min_bits = u64::BITS - (num_unacked * 2).leading_zeros();
    let min_bytes = min_bits.div_ceil(8).max(1) as u8;
    min_bytes.min(4)
}

/// パケット番号をトランケートしてエンコードする
///
/// - `full_pn`: 完全なパケット番号
/// - `pn_len`: エンコード長 (1-4)
/// - `buf`: 出力バッファ (pn_len バイト以上)
pub fn encode(full_pn: u64, pn_len: u8, buf: &mut [u8]) -> Result<(), Error> {
    let len = pn_len as usize;
    if buf.len() < len {
        return Err(Error::Incomplete {
            needed: len - buf.len(),
        });
    }

    // 下位 pn_len バイトだけをエンコード
    let pn_bytes = full_pn.to_be_bytes();
    buf[..len].copy_from_slice(&pn_bytes[8 - len..]);
    Ok(())
}

/// トランケートされたパケット番号をデコードする
///
/// - `buf`: 入力バッファ
/// - `pn_len`: パケット番号の長さ (1-4)
pub fn decode_truncated(buf: &[u8], pn_len: u8) -> Result<(u32, usize), Error> {
    let len = pn_len as usize;
    if buf.len() < len {
        return Err(Error::Incomplete {
            needed: len - buf.len(),
        });
    }

    let mut pn: u32 = 0;
    for &byte in &buf[..len] {
        pn = (pn << 8) | u32::from(byte);
    }

    Ok((pn, len))
}

/// トランケートされたパケット番号から完全なパケット番号を復元する
///
/// RFC 9000 Appendix A.3
///
/// - `largest_pn`: これまでに正常に処理した最大パケット番号 (2^62-1 以下)。None の場合は初回
/// - `truncated_pn`: トランケートされたパケット番号
/// - `pn_nbits`: パケット番号のビット数 (pn_len * 8)
pub fn decode_full(largest_pn: Option<u64>, truncated_pn: u64, pn_nbits: u32) -> u64 {
    // RFC 9000 Section 12.3: 有効なパケット番号は 2^62-1 以下。受信側は範囲外の
    // 番号を復元したパケットを破棄する契約なので、入口で前提を明示する。
    // 出力 (復元結果) は 2^62 になり得るため、出力に対する assert は置かない。
    debug_assert!(
        largest_pn.is_none_or(|pn| pn <= MAX_PACKET_NUMBER),
        "largest packet number must not exceed 2^62-1"
    );

    let expected_pn = largest_pn.map_or(0, |pn| pn + 1);
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;

    // 候補値: expected_pn の上位ビット + truncated_pn の下位ビット
    let candidate_pn = (expected_pn & !pn_mask) | truncated_pn;

    // 候補値の判定は RFC 9000 Appendix A.3 の擬似コードと等価。
    // RFC の `candidate_pn <= expected_pn - pn_hwin` は expected_pn < pn_hwin で
    // underflow するため、underflow しない `candidate_pn + pn_hwin <= expected_pn`
    // に移項した形を使う (RFC A.3 の "extra checks to prevent overflow and underflow"
    // の意図)。`candidate_pn + pn_win < (1u64 << 62)` も RFC のガードと同じで、
    // 復元結果が 2^62 以上になる前方ラップを防ぐ。
    if candidate_pn + pn_hwin <= expected_pn && candidate_pn + pn_win < (1u64 << 62) {
        candidate_pn + pn_win
    } else if candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win {
        candidate_pn - pn_win
    } else {
        candidate_pn
    }
}
