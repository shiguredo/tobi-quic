// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PATH_ACK フレーム (draft-ietf-quic-multipath-21 Section 4.1)
//!
//! ACK フレームに Path Identifier を追加したもの。

use alloc::vec::Vec;

use crate::error::Error;
use crate::frame::ack::{AckRange, EcnCounts};
use crate::varint::VarInt;

#[derive(Debug, Clone, PartialEq)]
pub struct PathAck {
    pub path_id: u32,
    pub largest_acknowledged: VarInt,
    pub ack_delay: VarInt,
    pub first_ack_range: VarInt,
    pub ack_ranges: Vec<AckRange>,
    pub ecn_counts: Option<EcnCounts>,
}

impl PathAck {
    pub fn decode_payload(buf: &[u8], has_ecn: bool) -> Result<(Self, usize), Error> {
        let mut pos = 0;

        let (path_id, n) = VarInt::decode(&buf[pos..])?;
        pos += n;

        // draft-ietf-quic-multipath-21 Section 2.4: path ID は nonce 計算で 32 ビットとして
        // 扱うため最大 2^32-1。超過は silent truncation せず PROTOCOL_VIOLATION とする。
        let path_id_u64 = path_id.as_u64();
        if path_id_u64 > u64::from(u32::MAX) {
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::PROTOCOL_VIOLATION,
                reason: format!("PATH_ACK path_id {path_id_u64} exceeds u32"),
            });
        }

        let (largest_acknowledged, n) = VarInt::decode(&buf[pos..])?;
        pos += n;

        let (ack_delay, n) = VarInt::decode(&buf[pos..])?;
        pos += n;

        let (ack_range_count, n) = VarInt::decode(&buf[pos..])?;
        pos += n;

        let (first_ack_range, n) = VarInt::decode(&buf[pos..])?;
        pos += n;

        let range_count = usize::try_from(ack_range_count.as_u64()).unwrap_or(usize::MAX);
        // RFC 9000 Section 19.3 / draft-ietf-quic-multipath-21 Section 4.1:
        // ACK Range Count は varint 最大値 (2^62-1) を取り得るため、
        // 信頼できないピア入力で直接 Vec::with_capacity を呼ぶとメモリ枯渇で abort する。
        // 各レンジは最低 2 バイト必要なので、残りバッファの半分で安全に上限する。
        let safe_cap = range_count.min(buf[pos..].len() / 2);
        let mut ack_ranges = Vec::with_capacity(safe_cap);
        for _ in 0..range_count {
            let (gap, n) = VarInt::decode(&buf[pos..])?;
            pos += n;
            let (ack_range, n) = VarInt::decode(&buf[pos..])?;
            pos += n;
            ack_ranges.push(AckRange { gap, ack_range });
        }

        let ecn_counts = if has_ecn {
            let (ect0, n) = VarInt::decode(&buf[pos..])?;
            pos += n;
            let (ect1, n) = VarInt::decode(&buf[pos..])?;
            pos += n;
            let (ecn_ce, n) = VarInt::decode(&buf[pos..])?;
            pos += n;
            Some(EcnCounts { ect0, ect1, ecn_ce })
        } else {
            None
        };

        Ok((
            Self {
                path_id: path_id.as_u64() as u32,
                largest_acknowledged,
                ack_delay,
                first_ack_range,
                ack_ranges,
                ecn_counts,
            },
            pos,
        ))
    }

    /// PATH_ACK 範囲を明示的な区間へ展開する
    ///
    /// 戻り値は `(smallest, largest)` のタプル配列で、`largest_acknowledged` を
    /// 起点に降順に並ぶ (先頭要素が最も新しいレンジ)。
    ///
    /// PATH_ACK は ACK の拡張であり、First ACK Range / Gap / ACK Range Length
    /// の復元規則は ACK と同じである
    /// (draft-ietf-quic-multipath-21 Section 4.1 / RFC 9000 Section 19.3)。
    /// 復元処理は [`crate::frame::ack::Ack::expand_ack_ranges`] と共通の
    /// 実装を使う。
    ///
    /// 不正な入力でも panic せず飽和減算で継続する。負値検出は受信側の
    /// フレーム処理が別途 FRAME_ENCODING_ERROR として扱う。
    pub fn expand_ack_ranges(&self) -> Vec<(u64, u64)> {
        crate::frame::ack::expand_ranges(
            self.largest_acknowledged.as_u64(),
            self.first_ack_range.as_u64(),
            &self.ack_ranges,
        )
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        let ft = if self.ecn_counts.is_some() {
            super::frame_type::PATH_ACK_ECN
        } else {
            super::frame_type::PATH_ACK
        };
        VarInt::try_from(ft)
            .expect("PATH_ACK frame type fits in 62-bit varint")
            .encode_to_vec(buf);
        VarInt::from(self.path_id).encode_to_vec(buf);
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
}
