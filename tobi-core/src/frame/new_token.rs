// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! NEW_TOKEN フレーム (RFC 9000 Section 19.7)

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewToken {
    pub token: Vec<u8>,
}

impl NewToken {
    pub fn decode_payload(buf: &[u8]) -> Result<(Self, usize), Error> {
        let mut pos = 0;
        let (length, n) = VarInt::decode(&buf[pos..])?;
        pos += n;
        let len = usize::try_from(length.as_u64()).unwrap_or(usize::MAX);
        if buf[pos..].len() < len {
            return Err(Error::Incomplete {
                needed: len - buf[pos..].len(),
            });
        }
        let token = buf[pos..pos + len].to_vec();
        pos += len;
        Ok((Self { token }, pos))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::from(super::frame_type::NEW_TOKEN as u8).encode_to_vec(buf);
        VarInt::try_from(self.token.len() as u64)
            .expect("length fits in 62-bit varint")
            .encode_to_vec(buf);
        buf.extend_from_slice(&self.token);
    }
}
