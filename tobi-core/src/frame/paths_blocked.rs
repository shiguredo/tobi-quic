// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PATHS_BLOCKED フレーム (RFC 10069 Section 4.7)

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathsBlocked {
    pub maximum_path_id: u32,
}

impl PathsBlocked {
    pub fn decode_payload(buf: &[u8]) -> Result<(Self, usize), Error> {
        let (val, n) = VarInt::decode(buf)?;
        let v = val.as_u64();
        if v > u64::from(u32::MAX) {
            // RFC 10069 Section 4.7: 2^32-1 超の Maximum Path Identifier は
            // local maximum value を必ず超えるため PROTOCOL_VIOLATION として接続を閉じる。
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::PROTOCOL_VIOLATION,
                reason: format!("PATHS_BLOCKED maximum_path_id {v} exceeds 2^32-1"),
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
        VarInt::try_from(super::frame_type::PATHS_BLOCKED)
            .expect("PATHS_BLOCKED frame type fits in 62-bit varint")
            .encode_to_vec(buf);
        VarInt::from(self.maximum_path_id).encode_to_vec(buf);
    }
}
