// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! MAX_STREAM_DATA フレーム (RFC 9000 Section 19.10)

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxStreamData {
    pub stream_id: VarInt,
    pub maximum_stream_data: VarInt,
}

impl MaxStreamData {
    pub fn decode_payload(buf: &[u8]) -> Result<(Self, usize), Error> {
        let mut pos = 0;
        let (stream_id, n) = VarInt::decode(&buf[pos..])?;
        pos += n;
        let (max_data, n) = VarInt::decode(&buf[pos..])?;
        pos += n;
        Ok((
            Self {
                stream_id,
                maximum_stream_data: max_data,
            },
            pos,
        ))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::from(super::frame_type::MAX_STREAM_DATA as u8).encode_to_vec(buf);
        self.stream_id.encode_to_vec(buf);
        self.maximum_stream_data.encode_to_vec(buf);
    }
}
