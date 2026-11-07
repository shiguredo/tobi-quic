// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! NEW_CONNECTION_ID フレーム (RFC 9000 Section 19.15)

use alloc::vec::Vec;

use crate::connection_id::ConnectionId;
use crate::error::Error;
use crate::varint::VarInt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewConnectionId {
    pub sequence_number: VarInt,
    pub retire_prior_to: VarInt,
    pub connection_id: ConnectionId,
    pub stateless_reset_token: [u8; 16],
}

impl NewConnectionId {
    pub fn decode_payload(buf: &[u8]) -> Result<(Self, usize), Error> {
        let mut pos = 0;
        let (seq, n) = VarInt::decode(&buf[pos..])?;
        pos += n;
        let (retire, n) = VarInt::decode(&buf[pos..])?;
        pos += n;

        if pos >= buf.len() {
            return Err(Error::Incomplete { needed: 1 });
        }
        let cid_len = buf[pos] as usize;
        pos += 1;

        // RFC 9000 Section 19.15: "Values less than 1 and greater than 20 are invalid
        // and MUST be treated as a connection error of type FRAME_ENCODING_ERROR."
        // >20 は ConnectionId::from_slice で弾かれるが、<1 (= 0) は明示的に弾く必要がある。
        if cid_len < 1 {
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::FRAME_ENCODING_ERROR,
                reason: "NEW_CONNECTION_ID length must be at least 1".into(),
            });
        }
        if cid_len > 20 {
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::FRAME_ENCODING_ERROR,
                reason: format!("NEW_CONNECTION_ID length {cid_len} exceeds 20"),
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
                sequence_number: seq,
                retire_prior_to: retire,
                connection_id,
                stateless_reset_token: token,
            },
            pos,
        ))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::from(super::frame_type::NEW_CONNECTION_ID as u8).encode_to_vec(buf);
        self.sequence_number.encode_to_vec(buf);
        self.retire_prior_to.encode_to_vec(buf);
        buf.push(self.connection_id.len() as u8);
        buf.extend_from_slice(self.connection_id.as_bytes());
        buf.extend_from_slice(&self.stateless_reset_token);
    }
}
