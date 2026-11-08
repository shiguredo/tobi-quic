// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PATH_ABANDON フレーム (RFC 10069 Section 4.2)

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

/// PATH_ABANDON エラーコード
pub mod error_code {
    pub const NO_ERROR: u64 = 0x0;
    pub const APPLICATION_ABANDON_PATH: u64 = 0x3e;
    pub const PATH_RESOURCE_LIMIT_REACHED: u64 = 0x3e75;
    pub const PATH_UNSTABLE_OR_POOR: u64 = 0x3e76;
    pub const NO_CID_AVAILABLE_FOR_PATH: u64 = 0x3e77;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathAbandon {
    pub path_id: u32,
    pub error_code: VarInt,
}

impl PathAbandon {
    pub fn decode_payload(buf: &[u8]) -> Result<(Self, usize), Error> {
        let mut pos = 0;
        let (path_id, n) = VarInt::decode(&buf[pos..])?;
        pos += n;

        // RFC 10069 Section 2.4: path ID は nonce 計算で 32 ビットとして
        // 扱うため最大 2^32-1。超過は silent truncation せず PROTOCOL_VIOLATION とする。
        let path_id_u64 = path_id.as_u64();
        if path_id_u64 > u64::from(u32::MAX) {
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::PROTOCOL_VIOLATION,
                reason: format!("PATH_ABANDON path_id {path_id_u64} exceeds u32"),
            });
        }

        let (error_code, n) = VarInt::decode(&buf[pos..])?;
        pos += n;
        Ok((
            Self {
                path_id: path_id.as_u64() as u32,
                error_code,
            },
            pos,
        ))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::try_from(super::frame_type::PATH_ABANDON)
            .expect("PATH_ABANDON frame type fits in 62-bit varint")
            .encode_to_vec(buf);
        VarInt::from(self.path_id).encode_to_vec(buf);
        self.error_code.encode_to_vec(buf);
    }
}
