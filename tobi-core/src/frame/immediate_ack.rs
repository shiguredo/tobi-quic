// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! IMMEDIATE_ACK フレーム
//!
//! draft-ietf-quic-ack-frequency-14 Section 5
//! フレームタイプは 0x1f。フィールドを持たない。

use alloc::vec::Vec;

use crate::varint::VarInt;

/// IMMEDIATE_ACK フレーム
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImmediateAck;

impl ImmediateAck {
    /// フレームをエンコードする
    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::try_from(super::frame_type::IMMEDIATE_ACK)
            .expect("IMMEDIATE_ACK frame type is within VarInt range")
            .encode_to_vec(buf);
    }
}
