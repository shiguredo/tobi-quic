// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! ACK_FREQUENCY フレーム
//!
//! draft-ietf-quic-ack-frequency-14 Section 4
//! フレームタイプは 0xaf。Sequence Number / Ack-Eliciting Threshold /
//! Requested Max Ack Delay / Reordering Threshold の 4 つの可変長整数からなる。

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

/// ACK_FREQUENCY フレーム
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckFrequency {
    /// 送信側が付与する単調増加のシーケンス番号
    pub sequence_number: VarInt,
    /// ACK を送らずに受け取れる ack-eliciting パケットの最大数
    pub ack_eliciting_threshold: VarInt,
    /// ピアに要求する max_ack_delay (マイクロ秒)
    pub requested_max_ack_delay: VarInt,
    /// 即時 ACK を発火させるパケット再順序の閾値
    pub reordering_threshold: VarInt,
}

impl AckFrequency {
    /// ペイロードをデコードする
    pub fn decode_payload(buf: &[u8]) -> Result<(Self, usize), Error> {
        let mut offset = 0;
        let (sequence_number, n) = VarInt::decode(&buf[offset..])?;
        offset += n;
        let (ack_eliciting_threshold, n) = VarInt::decode(&buf[offset..])?;
        offset += n;
        let (requested_max_ack_delay, n) = VarInt::decode(&buf[offset..])?;
        offset += n;
        let (reordering_threshold, n) = VarInt::decode(&buf[offset..])?;
        offset += n;

        Ok((
            Self {
                sequence_number,
                ack_eliciting_threshold,
                requested_max_ack_delay,
                reordering_threshold,
            },
            offset,
        ))
    }

    /// フレームをエンコードする
    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::try_from(super::frame_type::ACK_FREQUENCY)
            .expect("ACK_FREQUENCY frame type is within VarInt range")
            .encode_to_vec(buf);
        self.sequence_number.encode_to_vec(buf);
        self.ack_eliciting_threshold.encode_to_vec(buf);
        self.requested_max_ack_delay.encode_to_vec(buf);
        self.reordering_threshold.encode_to_vec(buf);
    }
}
