// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! RESET_STREAM フレーム (RFC 9000 Section 19.4)

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetStream {
    pub stream_id: VarInt,
    pub application_protocol_error_code: VarInt,
    pub final_size: VarInt,
}

impl ResetStream {
    pub fn decode_payload(buf: &[u8]) -> Result<(Self, usize), Error> {
        let mut offset = 0;
        let (stream_id, n) = VarInt::decode(&buf[offset..])?;
        offset += n;
        let (error_code, n) = VarInt::decode(&buf[offset..])?;
        offset += n;
        let (final_size, n) = VarInt::decode(&buf[offset..])?;
        offset += n;
        Ok((
            Self {
                stream_id,
                application_protocol_error_code: error_code,
                final_size,
            },
            offset,
        ))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::from(super::frame_type::RESET_STREAM as u8).encode_to_vec(buf);
        self.stream_id.encode_to_vec(buf);
        self.application_protocol_error_code.encode_to_vec(buf);
        self.final_size.encode_to_vec(buf);
    }
}
