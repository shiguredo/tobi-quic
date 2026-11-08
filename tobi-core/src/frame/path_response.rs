// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PATH_RESPONSE フレーム (RFC 9000 Section 19.18)

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathResponse {
    pub data: [u8; 8],
}

impl PathResponse {
    pub fn decode_payload(buf: &[u8]) -> Result<(Self, usize), Error> {
        if buf.len() < 8 {
            return Err(Error::Incomplete {
                needed: 8 - buf.len(),
            });
        }
        let mut data = [0u8; 8];
        data.copy_from_slice(&buf[..8]);
        Ok((Self { data }, 8))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::from(super::frame_type::PATH_RESPONSE as u8).encode_to_vec(buf);
        buf.extend_from_slice(&self.data);
    }
}
