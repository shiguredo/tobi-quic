// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! HANDSHAKE_DONE フレーム (RFC 9000 Section 19.20)

use alloc::vec::Vec;

use crate::varint::VarInt;

/// HANDSHAKE_DONE フレーム
///
/// ペイロードなし。サーバーのみが送信する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeDone;

impl HandshakeDone {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::from(super::frame_type::HANDSHAKE_DONE as u8).encode_to_vec(buf);
    }
}
