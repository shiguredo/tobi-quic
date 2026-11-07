// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! DATA_BLOCKED フレーム (RFC 9000 Section 19.12)

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataBlocked {
    pub maximum_data: VarInt,
}

impl DataBlocked {
    pub fn decode_payload(buf: &[u8]) -> Result<(Self, usize), Error> {
        let (val, n) = VarInt::decode(buf)?;
        Ok((Self { maximum_data: val }, n))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::from(super::frame_type::DATA_BLOCKED as u8).encode_to_vec(buf);
        self.maximum_data.encode_to_vec(buf);
    }
}
