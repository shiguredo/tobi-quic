// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! STOP_SENDING フレーム (RFC 9000 Section 19.5)

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopSending {
    pub stream_id: VarInt,
    pub application_protocol_error_code: VarInt,
}

impl StopSending {
    pub fn decode_payload(buf: &[u8]) -> Result<(Self, usize), Error> {
        let mut offset = 0;
        let (stream_id, n) = VarInt::decode(&buf[offset..])?;
        offset += n;
        let (error_code, n) = VarInt::decode(&buf[offset..])?;
        offset += n;
        Ok((
            Self {
                stream_id,
                application_protocol_error_code: error_code,
            },
            offset,
        ))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::from(super::frame_type::STOP_SENDING as u8).encode_to_vec(buf);
        self.stream_id.encode_to_vec(buf);
        self.application_protocol_error_code.encode_to_vec(buf);
    }
}
