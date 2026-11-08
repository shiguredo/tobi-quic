// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! RESET_STREAM_AT フレーム
//!
//! draft-ietf-quic-reliable-stream-reset-11 Section 4
//! フレームタイプ 0x24 は同 draft Section 8.2 が登録し、IANA の QUIC frame type
//! registry では 2026-09-28 に Permanent として登録済みである
//! (Specification: RFC-ietf-quic-reliable-stream-reset-11)。

use alloc::vec::Vec;

use crate::error::{Error, TransportErrorCode};
use crate::varint::VarInt;

/// RESET_STREAM_AT フレーム (draft-ietf-quic-reliable-stream-reset-11 Section 4)
///
/// ストリームをリセットしつつ、reliable_size までのデータ配信を保証する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetStreamAt {
    pub stream_id: VarInt,
    pub application_protocol_error_code: VarInt,
    pub final_size: VarInt,
    pub reliable_size: VarInt,
}

impl ResetStreamAt {
    pub fn decode_payload(buf: &[u8]) -> Result<(Self, usize), Error> {
        let mut offset = 0;
        let (stream_id, n) = VarInt::decode(&buf[offset..])?;
        offset += n;
        let (error_code, n) = VarInt::decode(&buf[offset..])?;
        offset += n;
        let (final_size, n) = VarInt::decode(&buf[offset..])?;
        offset += n;
        let (reliable_size, n) = VarInt::decode(&buf[offset..])?;
        offset += n;

        // draft-ietf-quic-reliable-stream-reset-11 Section 4:
        // reliable_size > final_size の場合は FRAME_ENCODING_ERROR
        if reliable_size.as_u64() > final_size.as_u64() {
            return Err(Error::Protocol {
                code: TransportErrorCode::FRAME_ENCODING_ERROR,
                reason: format!(
                    "RESET_STREAM_AT reliable_size {} exceeds final_size {}",
                    reliable_size.as_u64(),
                    final_size.as_u64()
                ),
            });
        }

        Ok((
            Self {
                stream_id,
                application_protocol_error_code: error_code,
                final_size,
                reliable_size,
            },
            offset,
        ))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::try_from(super::frame_type::RESET_STREAM_AT)
            .expect("RESET_STREAM_AT frame type fits in 62-bit varint")
            .encode_to_vec(buf);
        self.stream_id.encode_to_vec(buf);
        self.application_protocol_error_code.encode_to_vec(buf);
        self.final_size.encode_to_vec(buf);
        self.reliable_size.encode_to_vec(buf);
    }
}
