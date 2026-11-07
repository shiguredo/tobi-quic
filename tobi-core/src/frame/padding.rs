// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PADDING フレーム (RFC 9000 Section 19.1)

use alloc::vec::Vec;

/// PADDING フレーム
///
/// 連続する 0x00 バイトの数を保持する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Padding {
    /// パディングバイト数
    pub length: usize,
}

impl Padding {
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), crate::error::Error> {
        let mut count = 0;
        while count < buf.len() && buf[count] == 0x00 {
            count += 1;
        }
        Ok((Self { length: count }, count))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(core::iter::repeat_n(0x00, self.length));
    }
}
