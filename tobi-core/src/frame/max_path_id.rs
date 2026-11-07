// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! MAX_PATH_ID フレーム (draft-ietf-quic-multipath-21 Section 4.6)

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxPathId {
    pub maximum_path_id: u32,
}

impl MaxPathId {
    pub fn decode_payload(buf: &[u8]) -> Result<(Self, usize), Error> {
        let (val, n) = VarInt::decode(buf)?;
        let v = val.as_u64();
        if v > u64::from(u32::MAX) {
            // draft-ietf-quic-multipath-21 Section 4.6: 不正な Maximum Path Identifier の
            // 受信は PROTOCOL_VIOLATION として接続を閉じる (MUST)。
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::PROTOCOL_VIOLATION,
                reason: format!("MAX_PATH_ID value {v} exceeds 2^32-1"),
            });
        }
        Ok((
            Self {
                maximum_path_id: v as u32,
            },
            n,
        ))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::try_from(super::frame_type::MAX_PATH_ID)
            .expect("MAX_PATH_ID frame type fits in 62-bit varint")
            .encode_to_vec(buf);
        VarInt::from(self.maximum_path_id).encode_to_vec(buf);
    }
}
