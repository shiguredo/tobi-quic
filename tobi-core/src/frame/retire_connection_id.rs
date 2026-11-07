// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! RETIRE_CONNECTION_ID フレーム (RFC 9000 Section 19.16)

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetireConnectionId {
    pub sequence_number: VarInt,
}

impl RetireConnectionId {
    pub fn decode_payload(buf: &[u8]) -> Result<(Self, usize), Error> {
        let (seq, n) = VarInt::decode(buf)?;
        Ok((
            Self {
                sequence_number: seq,
            },
            n,
        ))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::from(super::frame_type::RETIRE_CONNECTION_ID as u8).encode_to_vec(buf);
        self.sequence_number.encode_to_vec(buf);
    }
}
