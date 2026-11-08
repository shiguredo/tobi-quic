// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! STREAMS_BLOCKED フレーム (RFC 9000 Section 19.14)

use alloc::vec::Vec;

use crate::error::{Error, TransportErrorCode};
use crate::varint::VarInt;

/// RFC 9000 Section 4.6: ストリーム数の上限 (2^60)
///
/// これを超えると、表現できないストリーム ID を許すことになる。
const MAX_STREAM_COUNT: u64 = 1 << 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamsBlocked {
    /// 双方向ストリームなら `true`
    pub bidirectional: bool,
    /// 送信時点で許可されていた累積ストリーム数の上限 (2^60 以下)
    pub maximum_streams: VarInt,
}

impl StreamsBlocked {
    pub fn decode_payload(buf: &[u8], frame_type: u64) -> Result<(Self, usize), Error> {
        let (val, n) = VarInt::decode(buf)?;
        // RFC 9000 Section 19.14: 2^60 を超える値は STREAM_LIMIT_ERROR または
        // FRAME_ENCODING_ERROR。本実装は FRAME_ENCODING_ERROR に統一する。
        if val.as_u64() > MAX_STREAM_COUNT {
            return Err(Error::Protocol {
                code: TransportErrorCode::FRAME_ENCODING_ERROR,
                reason: format!(
                    "STREAMS_BLOCKED maximum_streams {} exceeds 2^60",
                    val.as_u64()
                ),
            });
        }
        Ok((
            Self {
                bidirectional: frame_type == super::frame_type::STREAMS_BLOCKED_BIDI,
                maximum_streams: val,
            },
            n,
        ))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        let ft = if self.bidirectional {
            super::frame_type::STREAMS_BLOCKED_BIDI
        } else {
            super::frame_type::STREAMS_BLOCKED_UNI
        };
        VarInt::try_from(ft)
            .expect("STREAMS_BLOCKED frame type fits in 62-bit varint")
            .encode_to_vec(buf);
        self.maximum_streams.encode_to_vec(buf);
    }
}
