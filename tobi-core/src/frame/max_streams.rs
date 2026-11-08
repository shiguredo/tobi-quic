// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! MAX_STREAMS フレーム (RFC 9000 Section 19.11)

use alloc::vec::Vec;

use crate::error::{Error, TransportErrorCode};
use crate::varint::VarInt;

/// RFC 9000 Section 4.6: ストリーム数の上限 (2^60)
///
/// これを超えると、表現できないストリーム ID を許すことになる。
const MAX_STREAM_COUNT: u64 = 1 << 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxStreams {
    /// 双方向ストリームなら `true`
    pub bidirectional: bool,
    /// ピアが開設できる累積ストリーム数の上限 (2^60 以下)
    pub maximum_streams: VarInt,
}

impl MaxStreams {
    pub fn decode_payload(buf: &[u8], frame_type: u64) -> Result<(Self, usize), Error> {
        let (val, n) = VarInt::decode(buf)?;
        // RFC 9000 Section 19.11: 2^60 を超える値は FRAME_ENCODING_ERROR。
        if val.as_u64() > MAX_STREAM_COUNT {
            return Err(Error::Protocol {
                code: TransportErrorCode::FRAME_ENCODING_ERROR,
                reason: format!("MAX_STREAMS maximum_streams {} exceeds 2^60", val.as_u64()),
            });
        }
        Ok((
            Self {
                bidirectional: frame_type == super::frame_type::MAX_STREAMS_BIDI,
                maximum_streams: val,
            },
            n,
        ))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        let ft = if self.bidirectional {
            super::frame_type::MAX_STREAMS_BIDI
        } else {
            super::frame_type::MAX_STREAMS_UNI
        };
        VarInt::try_from(ft)
            .expect("MAX_STREAMS frame type fits in 62-bit varint")
            .encode_to_vec(buf);
        self.maximum_streams.encode_to_vec(buf);
    }
}
