// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! CRYPTO フレーム (RFC 9000 Section 19.6)

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crypto {
    pub offset: VarInt,
    pub data: Vec<u8>,
}

impl Crypto {
    pub fn decode_payload(buf: &[u8]) -> Result<(Self, usize), Error> {
        let mut pos = 0;
        let (offset, n) = VarInt::decode(&buf[pos..])?;
        pos += n;
        let (length, n) = VarInt::decode(&buf[pos..])?;
        pos += n;
        let len = usize::try_from(length.as_u64()).unwrap_or(usize::MAX);
        if buf[pos..].len() < len {
            return Err(Error::Incomplete {
                needed: len - buf[pos..].len(),
            });
        }
        let data = buf[pos..pos + len].to_vec();
        pos += len;
        // RFC 9000 Section 19.6: offset と length の和は 2^62-1 を超えてはならない。
        // offset <= 2^62-1、data.len() はデータグラム長に制限されるため u64 加算は overflow しない。
        let end_offset = offset.as_u64() + data.len() as u64;
        if end_offset > crate::varint::MAX_VALUE {
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::FRAME_ENCODING_ERROR,
                reason: format!("CRYPTO offset + length = {end_offset} exceeds 2^62-1"),
            });
        }
        Ok((Self { offset, data }, pos))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::from(super::frame_type::CRYPTO as u8).encode_to_vec(buf);
        self.offset.encode_to_vec(buf);
        VarInt::try_from(self.data.len() as u64)
            .expect("length fits in 62-bit varint")
            .encode_to_vec(buf);
        buf.extend_from_slice(&self.data);
    }
}
