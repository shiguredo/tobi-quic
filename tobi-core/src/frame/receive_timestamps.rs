// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Receive Timestamps 拡張 (draft-ietf-quic-receive-ts-03)
//!
//! 受信タイムスタンプを ACK / PATH_ACK で報告する拡張フレームを定義する。
//! フレームは 1-RTT でのみ送信し、トランスポートパラメータ
//! `max_receive_timestamps_per_ack` (0x4ac07) と
//! `receive_timestamps_exponent` (0x4ac26) でネゴシエーションする。

use alloc::vec::Vec;

use crate::error::Error;
use crate::error::TransportErrorCode;
use crate::frame::ack::Ack;
use crate::varint::VarInt;

/// タイムスタンプレンジ (draft-ietf-quic-receive-ts-03 Section 4.1)
///
/// 連続するパケット番号の受信タイムスタンプを降順に保持する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampRange {
    /// ACK の Largest Acknowledged からの差分 (0 は Largest Acknowledged 自身)
    pub delta_largest_acknowledged: VarInt,
    /// タイムスタンプ差分 (エンコードされた値。2^exponent を掛けるとマイクロ秒)
    pub deltas: Vec<VarInt>,
}

/// Receive Timestamps フィールド (draft-ietf-quic-receive-ts-03 Section 4)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveTimestamps {
    /// タイムスタンプレンジの一覧 (受信時刻の降順)
    pub timestamp_ranges: Vec<TimestampRange>,
}

impl ReceiveTimestamps {
    /// タイムスタンプレンジの合計数 (フレームの上限検査に使う)
    pub fn total_deltas(&self) -> u64 {
        self.timestamp_ranges
            .iter()
            .map(|range| range.deltas.len() as u64)
            .sum()
    }

    /// バッファからデコードする
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), Error> {
        let mut offset = 0;

        let (range_count, n) = VarInt::decode(&buf[offset..])?;
        offset += n;
        let range_count = usize::try_from(range_count.as_u64())
            .map_err(|_| Error::InvalidData("receive timestamps range count overflow".into()))?;

        // 各レンジは Delta Largest Acknowledged と Timestamp Delta Count で
        // 最低 2 バイト必要。信頼できない入力で巨大な容量を確保しないよう、
        // 残りバイト数で上限を抑える。
        let safe_cap = range_count.min(buf[offset..].len() / 2);
        let mut timestamp_ranges = Vec::with_capacity(safe_cap);
        for _ in 0..range_count {
            let (delta_largest_acknowledged, n) = VarInt::decode(&buf[offset..])?;
            offset += n;

            let (delta_count, n) = VarInt::decode(&buf[offset..])?;
            offset += n;
            let delta_count = usize::try_from(delta_count.as_u64())
                .map_err(|_| Error::InvalidData("timestamp delta count overflow".into()))?;

            // 各 delta は最低 1 バイト。同じく残りバイト数で上限を抑える。
            let delta_cap = delta_count.min(buf[offset..].len());
            let mut deltas = Vec::with_capacity(delta_cap);
            for _ in 0..delta_count {
                let (delta, n) = VarInt::decode(&buf[offset..])?;
                offset += n;
                deltas.push(delta);
            }

            timestamp_ranges.push(TimestampRange {
                delta_largest_acknowledged,
                deltas,
            });
        }

        Ok((Self { timestamp_ranges }, offset))
    }

    /// バッファへエンコードする
    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::try_from(self.timestamp_ranges.len() as u64)
            .expect("timestamp range count fits varint")
            .encode_to_vec(buf);
        for range in &self.timestamp_ranges {
            range.delta_largest_acknowledged.encode_to_vec(buf);
            VarInt::try_from(range.deltas.len() as u64)
                .expect("timestamp delta count fits varint")
                .encode_to_vec(buf);
            for delta in &range.deltas {
                delta.encode_to_vec(buf);
            }
        }
    }
}

/// ACK_RECEIVE_TIMESTAMPS フレーム (draft-ietf-quic-receive-ts-03 Section 4)
#[derive(Debug, Clone, PartialEq)]
pub struct AckReceiveTimestamps {
    /// ACK と同じフィールド
    pub ack: Ack,
    /// 受信タイムスタンプ
    pub timestamps: ReceiveTimestamps,
}

impl AckReceiveTimestamps {
    /// バッファからデコードする
    pub fn decode_payload(buf: &[u8], has_ecn: bool) -> Result<(Self, usize), Error> {
        let (ack, ack_size) = Ack::decode_fields(buf, has_ecn)?;
        let (timestamps, ts_size) = ReceiveTimestamps::decode(&buf[ack_size..])?;
        Ok((Self { ack, timestamps }, ack_size.saturating_add(ts_size)))
    }

    /// バッファへエンコードする
    pub fn encode(&self, buf: &mut Vec<u8>) {
        let ft = if self.ack.ecn_counts.is_some() {
            super::frame_type::ACK_RECEIVE_TIMESTAMPS_ECN
        } else {
            super::frame_type::ACK_RECEIVE_TIMESTAMPS
        };
        VarInt::try_from(ft)
            .expect("frame type fits varint")
            .encode_to_vec(buf);
        self.ack.encode_fields(buf);
        self.timestamps.encode(buf);
    }
}

/// PATH_ACK_RECEIVE_TIMESTAMPS フレーム (draft-ietf-quic-receive-ts-03 Section 5)
#[derive(Debug, Clone, PartialEq)]
pub struct PathAckReceiveTimestamps {
    /// パス ID
    pub path_id: u32,
    /// PATH_ACK と同じフィールド
    pub ack: Ack,
    /// 受信タイムスタンプ
    pub timestamps: ReceiveTimestamps,
}

impl PathAckReceiveTimestamps {
    /// バッファからデコードする
    pub fn decode_payload(buf: &[u8], has_ecn: bool) -> Result<(Self, usize), Error> {
        let mut offset = 0;

        let (path_id, n) = VarInt::decode(&buf[offset..])?;
        offset += n;
        // draft-ietf-quic-multipath-21 Section 2.4: path ID は PPN 計算で
        // 32 ビットとして扱うため、2^32-1 を超える値は PROTOCOL_VIOLATION。
        let path_id_u64 = path_id.as_u64();
        if path_id_u64 > u64::from(u32::MAX) {
            return Err(Error::Protocol {
                code: TransportErrorCode::PROTOCOL_VIOLATION,
                reason: format!("PATH_ACK_RECEIVE_TIMESTAMPS path_id {path_id_u64} exceeds u32"),
            });
        }

        let (ack, ack_size) = Ack::decode_fields(&buf[offset..], has_ecn)?;
        offset += ack_size;
        let (timestamps, ts_size) = ReceiveTimestamps::decode(&buf[offset..])?;
        offset += ts_size;

        Ok((
            Self {
                path_id: path_id_u64 as u32,
                ack,
                timestamps,
            },
            offset,
        ))
    }

    /// バッファへエンコードする
    pub fn encode(&self, buf: &mut Vec<u8>) {
        let ft = if self.ack.ecn_counts.is_some() {
            super::frame_type::PATH_ACK_RECEIVE_TIMESTAMPS_ECN
        } else {
            super::frame_type::PATH_ACK_RECEIVE_TIMESTAMPS
        };
        VarInt::try_from(ft)
            .expect("frame type fits varint")
            .encode_to_vec(buf);
        VarInt::from(self.path_id).encode_to_vec(buf);
        self.ack.encode_fields(buf);
        self.timestamps.encode(buf);
    }
}
