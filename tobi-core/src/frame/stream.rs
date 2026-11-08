// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! STREAM フレーム (RFC 9000 Section 19.8)

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stream {
    pub stream_id: VarInt,
    pub offset: VarInt,
    pub fin: bool,
    pub data: Vec<u8>,
}

impl Stream {
    /// フレームタイプからフラグをデコードする
    ///
    /// STREAM フレームタイプ (0x08-0x0f) のビットフィールド:
    /// - bit 0 (0x01): FIN
    /// - bit 1 (0x02): LEN (長さフィールドあり)
    /// - bit 2 (0x04): OFF (オフセットフィールドあり)
    pub fn decode_payload(buf: &[u8], frame_type: u64) -> Result<(Self, usize), Error> {
        let has_off = frame_type & 0x04 != 0;
        let has_len = frame_type & 0x02 != 0;
        let has_fin = frame_type & 0x01 != 0;

        let mut pos = 0;

        let (stream_id, n) = VarInt::decode(&buf[pos..])?;
        pos += n;

        let offset = if has_off {
            let (off, n) = VarInt::decode(&buf[pos..])?;
            pos += n;
            off
        } else {
            VarInt::from(0u8)
        };

        let data = if has_len {
            let (length, n) = VarInt::decode(&buf[pos..])?;
            pos += n;
            let len = usize::try_from(length.as_u64()).unwrap_or(usize::MAX);
            if buf[pos..].len() < len {
                return Err(Error::Incomplete {
                    needed: len - buf[pos..].len(),
                });
            }
            let d = buf[pos..pos + len].to_vec();
            pos += len;
            d
        } else {
            // 長さフィールドがない場合はパケットの残り全て
            let d = buf[pos..].to_vec();
            pos = buf.len();
            d
        };

        // RFC 9000 Section 19.8: offset と length の和は 2^62-1 を超えてはならない。
        // offset <= 2^62-1、data.len() はデータグラム長に制限されるため u64 加算は overflow しない。
        let end_offset = offset.as_u64() + data.len() as u64;
        if end_offset > crate::varint::MAX_VALUE {
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::FRAME_ENCODING_ERROR,
                reason: format!("STREAM offset + length = {end_offset} exceeds 2^62-1"),
            });
        }

        Ok((
            Self {
                stream_id,
                offset,
                fin: has_fin,
                data,
            },
            pos,
        ))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        let mut ft = super::frame_type::STREAM_START;
        if self.fin {
            ft |= 0x01;
        }
        // 常に長さフィールドを付ける (複数フレームをパケットに詰めるため)
        ft |= 0x02;
        if self.offset.as_u64() > 0 {
            ft |= 0x04;
        }
        VarInt::try_from(ft)
            .expect("STREAM frame type fits in 62-bit varint")
            .encode_to_vec(buf);
        self.stream_id.encode_to_vec(buf);
        if self.offset.as_u64() > 0 {
            self.offset.encode_to_vec(buf);
        }
        VarInt::try_from(self.data.len() as u64)
            .expect("length fits in 62-bit varint")
            .encode_to_vec(buf);
        buf.extend_from_slice(&self.data);
    }
}
