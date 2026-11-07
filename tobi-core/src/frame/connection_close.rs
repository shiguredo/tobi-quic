// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! CONNECTION_CLOSE フレーム (RFC 9000 Section 19.19)

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionClose {
    /// true: アプリケーションエラー (0x1d)、false: トランスポートエラー (0x1c)
    pub application: bool,
    pub error_code: VarInt,
    /// トランスポートエラーの場合のみ: エラーを引き起こしたフレームタイプ
    pub frame_type: Option<VarInt>,
    pub reason_phrase: Vec<u8>,
}

impl ConnectionClose {
    pub fn decode_payload(buf: &[u8], ft: u64) -> Result<(Self, usize), Error> {
        let application = ft == super::frame_type::APPLICATION_CLOSE;
        let mut pos = 0;

        let (error_code, n) = VarInt::decode(&buf[pos..])?;
        pos += n;

        let frame_type = if !application {
            let (ft_val, n) = VarInt::decode(&buf[pos..])?;
            pos += n;
            Some(ft_val)
        } else {
            None
        };

        let (reason_len, n) = VarInt::decode(&buf[pos..])?;
        pos += n;
        let len = usize::try_from(reason_len.as_u64()).unwrap_or(usize::MAX);
        if buf[pos..].len() < len {
            return Err(Error::Incomplete {
                needed: len - buf[pos..].len(),
            });
        }
        let reason_phrase = buf[pos..pos + len].to_vec();
        pos += len;

        Ok((
            Self {
                application,
                error_code,
                frame_type,
                reason_phrase,
            },
            pos,
        ))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        let ft = if self.application {
            super::frame_type::APPLICATION_CLOSE
        } else {
            super::frame_type::CONNECTION_CLOSE
        };
        VarInt::try_from(ft)
            .expect("CONNECTION_CLOSE frame type fits in 62-bit varint")
            .encode_to_vec(buf);
        self.error_code.encode_to_vec(buf);
        if let Some(frame_type) = self.frame_type {
            frame_type.encode_to_vec(buf);
        }
        VarInt::try_from(self.reason_phrase.len() as u64)
            .expect("length fits in 62-bit varint")
            .encode_to_vec(buf);
        buf.extend_from_slice(&self.reason_phrase);
    }
}
