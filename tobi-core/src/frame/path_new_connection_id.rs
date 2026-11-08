// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PATH_NEW_CONNECTION_ID フレーム (RFC 10069 Section 4.4)

use alloc::vec::Vec;

use crate::connection_id::ConnectionId;
use crate::error::Error;
use crate::varint::VarInt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathNewConnectionId {
    pub path_id: u32,
    pub sequence_number: VarInt,
    pub retire_prior_to: VarInt,
    pub connection_id: ConnectionId,
    pub stateless_reset_token: [u8; 16],
}

impl PathNewConnectionId {
    pub fn decode_payload(buf: &[u8]) -> Result<(Self, usize), Error> {
        let mut pos = 0;

        let (path_id, n) = VarInt::decode(&buf[pos..])?;
        pos += n;

        // RFC 10069 Section 4.4: path_id は実運用上 u32 範囲で扱うため、
        // varint 最大値 (2^62-1) までの値を silent truncation しないこと。
        let path_id_u64 = path_id.as_u64();
        if path_id_u64 > u64::from(u32::MAX) {
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::PROTOCOL_VIOLATION,
                reason: format!("PATH_NEW_CONNECTION_ID path_id {path_id_u64} exceeds u32"),
            });
        }

        let (seq, n) = VarInt::decode(&buf[pos..])?;
        pos += n;

        let (retire, n) = VarInt::decode(&buf[pos..])?;
        pos += n;

        if pos >= buf.len() {
            return Err(Error::Incomplete { needed: 1 });
        }
        let cid_len = buf[pos] as usize;
        pos += 1;

        // RFC 9000 Section 19.15 の規定を PATH_NEW_CONNECTION_ID にも準用する
        // (RFC 10069 Section 4.4 が NEW_CONNECTION_ID の拡張)。
        if cid_len < 1 {
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::FRAME_ENCODING_ERROR,
                reason: "PATH_NEW_CONNECTION_ID length must be at least 1".into(),
            });
        }
        if cid_len > 20 {
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::FRAME_ENCODING_ERROR,
                reason: format!("PATH_NEW_CONNECTION_ID length {cid_len} exceeds 20"),
            });
        }

        if buf[pos..].len() < cid_len {
            return Err(Error::Incomplete {
                needed: cid_len - buf[pos..].len(),
            });
        }
        let connection_id = ConnectionId::from_slice(&buf[pos..pos + cid_len])?;
        pos += cid_len;

        if buf[pos..].len() < 16 {
            return Err(Error::Incomplete {
                needed: 16 - buf[pos..].len(),
            });
        }
        let mut token = [0u8; 16];
        token.copy_from_slice(&buf[pos..pos + 16]);
        pos += 16;

        Ok((
            Self {
                path_id: path_id_u64 as u32,
                sequence_number: seq,
                retire_prior_to: retire,
                connection_id,
                stateless_reset_token: token,
            },
            pos,
        ))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::try_from(super::frame_type::PATH_NEW_CONNECTION_ID)
            .expect("PATH_NEW_CONNECTION_ID frame type fits in 62-bit varint")
            .encode_to_vec(buf);
        VarInt::from(self.path_id).encode_to_vec(buf);
        self.sequence_number.encode_to_vec(buf);
        self.retire_prior_to.encode_to_vec(buf);
        buf.push(self.connection_id.len() as u8);
        buf.extend_from_slice(self.connection_id.as_bytes());
        buf.extend_from_slice(&self.stateless_reset_token);
    }
}
