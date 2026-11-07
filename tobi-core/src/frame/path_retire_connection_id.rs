// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PATH_RETIRE_CONNECTION_ID フレーム (draft-ietf-quic-multipath-21 Section 4.5)

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathRetireConnectionId {
    pub path_id: u32,
    pub sequence_number: VarInt,
}

impl PathRetireConnectionId {
    pub fn decode_payload(buf: &[u8]) -> Result<(Self, usize), Error> {
        let mut pos = 0;
        let (path_id, n) = VarInt::decode(&buf[pos..])?;
        pos += n;

        // draft-ietf-quic-multipath-21 Section 2.4: path ID は nonce 計算で 32 ビットとして
        // 扱うため最大 2^32-1。超過は silent truncation せず PROTOCOL_VIOLATION とする。
        let path_id_u64 = path_id.as_u64();
        if path_id_u64 > u64::from(u32::MAX) {
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::PROTOCOL_VIOLATION,
                reason: format!("PATH_RETIRE_CONNECTION_ID path_id {path_id_u64} exceeds u32"),
            });
        }

        let (seq, n) = VarInt::decode(&buf[pos..])?;
        pos += n;
        Ok((
            Self {
                path_id: path_id_u64 as u32,
                sequence_number: seq,
            },
            pos,
        ))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::try_from(super::frame_type::PATH_RETIRE_CONNECTION_ID)
            .expect("PATH_RETIRE_CONNECTION_ID frame type fits in 62-bit varint")
            .encode_to_vec(buf);
        VarInt::from(self.path_id).encode_to_vec(buf);
        self.sequence_number.encode_to_vec(buf);
    }
}
