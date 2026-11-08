// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PING フレーム (RFC 9000 Section 19.2)

use alloc::vec::Vec;

/// PING フレーム
///
/// ペイロードなし。ACK を誘発する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping;

impl Ping {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        crate::varint::VarInt::from(super::frame_type::PING as u8).encode_to_vec(buf);
    }
}
