// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! ACK フレーム (RFC 9000 Section 19.3)

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

/// ACK レンジ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckRange {
    /// ギャップ (ACK されていないパケット数 - 1)
    pub gap: VarInt,
    /// ACK レンジ長
    pub ack_range: VarInt,
}

/// ECN カウント
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EcnCounts {
    pub ect0: VarInt,
    pub ect1: VarInt,
    pub ecn_ce: VarInt,
}

/// ACK フレーム
#[derive(Debug, Clone, PartialEq)]
pub struct Ack {
    /// 最大 ACK 済みパケット番号
    pub largest_acknowledged: VarInt,
    /// ACK 遅延 (マイクロ秒単位ではなく、エンコードされた値)
    pub ack_delay: VarInt,
    /// 最初の ACK レンジ
    pub first_ack_range: VarInt,
    /// 追加の ACK レンジ
    pub ack_ranges: Vec<AckRange>,
    /// ECN カウント (ACK_ECN の場合)
    pub ecn_counts: Option<EcnCounts>,
}

impl Ack {
    pub fn decode_payload(buf: &[u8], has_ecn: bool) -> Result<(Self, usize), Error> {
        Self::decode_fields(buf, has_ecn)
    }

    /// ACK のフィールド部分 (フレームタイプを除く) をデコードする
    ///
    /// ACK_RECEIVE_TIMESTAMPS / PATH_ACK_RECEIVE_TIMESTAMPS は ACK と同じ
    /// フィールド列の後ろに Receive Timestamps を続けるため、共通化する。
    pub(crate) fn decode_fields(buf: &[u8], has_ecn: bool) -> Result<(Self, usize), Error> {
        let mut offset = 0;

        let (largest_acknowledged, n) = VarInt::decode(&buf[offset..])?;
        offset += n;

        let (ack_delay, n) = VarInt::decode(&buf[offset..])?;
        offset += n;

        let (ack_range_count, n) = VarInt::decode(&buf[offset..])?;
        offset += n;

        let (first_ack_range, n) = VarInt::decode(&buf[offset..])?;
        offset += n;

        let range_count = usize::try_from(ack_range_count.as_u64()).unwrap_or(usize::MAX);
        // RFC 9000 Section 19.3: ACK Range Count は varint 最大値 (2^62-1) を取り得るため、
        // 信頼できないピア入力で直接 Vec::with_capacity を呼ぶとメモリ枯渇で abort する。
        // 各レンジは最低 2 バイト (Gap + ACK Range Length が各 1 バイト varint) 必要なので、
        // 残りバッファの半分で安全に上限する。
        let safe_cap = range_count.min(buf[offset..].len() / 2);
        let mut ack_ranges = Vec::with_capacity(safe_cap);
        for _ in 0..range_count {
            let (gap, n) = VarInt::decode(&buf[offset..])?;
            offset += n;
            let (ack_range, n) = VarInt::decode(&buf[offset..])?;
            offset += n;
            ack_ranges.push(AckRange { gap, ack_range });
        }

        let ecn_counts = if has_ecn {
            let (ect0, n) = VarInt::decode(&buf[offset..])?;
            offset += n;
            let (ect1, n) = VarInt::decode(&buf[offset..])?;
            offset += n;
            let (ecn_ce, n) = VarInt::decode(&buf[offset..])?;
            offset += n;
            Some(EcnCounts { ect0, ect1, ecn_ce })
        } else {
            None
        };

        Ok((
            Self {
                largest_acknowledged,
                ack_delay,
                first_ack_range,
                ack_ranges,
                ecn_counts,
            },
            offset,
        ))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        let ft = if self.ecn_counts.is_some() {
            super::frame_type::ACK_ECN
        } else {
            super::frame_type::ACK
        };
        VarInt::try_from(ft)
            .expect("ACK frame type fits in 62-bit varint")
            .encode_to_vec(buf);
        self.encode_fields(buf);
    }

    /// ACK のフィールド部分 (フレームタイプを除く) をエンコードする
    pub(crate) fn encode_fields(&self, buf: &mut Vec<u8>) {
        self.largest_acknowledged.encode_to_vec(buf);
        self.ack_delay.encode_to_vec(buf);
        VarInt::try_from(self.ack_ranges.len() as u64)
            .expect("length fits in 62-bit varint")
            .encode_to_vec(buf);
        self.first_ack_range.encode_to_vec(buf);
        for range in &self.ack_ranges {
            range.gap.encode_to_vec(buf);
            range.ack_range.encode_to_vec(buf);
        }
        if let Some(ecn) = &self.ecn_counts {
            ecn.ect0.encode_to_vec(buf);
            ecn.ect1.encode_to_vec(buf);
            ecn.ecn_ce.encode_to_vec(buf);
        }
    }

    /// ACK 範囲を明示的な区間へ展開する
    ///
    /// 戻り値は `(smallest, largest)` のタプル配列で、`largest_acknowledged` を
    /// 起点に降順に並ぶ (先頭要素が最も新しいレンジ)。
    ///
    /// 先頭レンジは RFC 9000 Section 19.3 の First ACK Range 定義に従い、
    ///   smallest = largest_acknowledged - first_ack_range
    /// で求める。追加レンジは RFC 9000 Section 19.3.1 の ACK Range デコード規則:
    ///   largest = previous_smallest - gap - 2
    ///   smallest = largest - ack_range
    /// を反復適用する。
    ///
    /// 不正な入力 (first_ack_range が largest を超える、gap で負値化する等) でも
    /// panic せず飽和減算で継続する。負値検出は受信側のフレーム処理が別途
    /// FRAME_ENCODING_ERROR として扱う。
    pub fn expand_ack_ranges(&self) -> Vec<(u64, u64)> {
        expand_ranges(
            self.largest_acknowledged.as_u64(),
            self.first_ack_range.as_u64(),
            &self.ack_ranges,
        )
    }
}

/// ACK 系フレームの確認応答範囲を展開する共通処理
///
/// PATH_ACK は ACK の拡張であり、同じレンジ復元規則を使う
/// (RFC 10069 Section 4.1)。復元規則は ACK と共通であり、
/// [`Ack::expand_ack_ranges`] と [`crate::frame::path_ack::PathAck::expand_ack_ranges`]
/// は同じ実装を使う。
pub(crate) fn expand_ranges(
    largest_acknowledged: u64,
    first_ack_range: u64,
    ack_ranges: &[AckRange],
) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    // current = 直前レンジの smallest。先頭レンジでは
    // smallest = largest_acknowledged - first_ack_range。
    let mut current = largest_acknowledged.saturating_sub(first_ack_range);
    ranges.push((current, largest_acknowledged));
    for gap_block in ack_ranges {
        // end = 新しいレンジの largest = 直前 smallest - gap - 2
        let end = current.saturating_sub(gap_block.gap.as_u64().saturating_add(2));
        // start = 新しいレンジの smallest = largest - ack_range
        let start = end.saturating_sub(gap_block.ack_range.as_u64());
        ranges.push((start, end));
        current = start;
    }
    ranges
}
