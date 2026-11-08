// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! QUIC 可変長整数のエンコード/デコード (RFC 9000 Section 16)
//!
//! 可変長整数は 1, 2, 4, 8 バイトのいずれかでエンコードされる。
//! 先頭 2 ビットがエンコード長を示す:
//! - 0b00: 1 バイト (6 ビット値、最大 63)
//! - 0b01: 2 バイト (14 ビット値、最大 16383)
//! - 0b10: 4 バイト (30 ビット値、最大 1073741823)
//! - 0b11: 8 バイト (62 ビット値、最大 4611686018427387903)

use alloc::vec::Vec;

use crate::error::Error;

/// QUIC 可変長整数の最大値 (2^62 - 1)
pub const MAX_VALUE: u64 = (1 << 62) - 1;

/// QUIC 可変長整数
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarInt(u64);

impl VarInt {
    /// 値から VarInt を生成する
    ///
    /// 値が 2^62 - 1 を超える場合は None を返す
    pub const fn new(value: u64) -> Option<Self> {
        if value > MAX_VALUE {
            None
        } else {
            Some(Self(value))
        }
    }

    /// 内部の u64 値を返す
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// エンコード後のバイト数を返す
    pub const fn encoded_size(self) -> usize {
        if self.0 <= 63 {
            1
        } else if self.0 <= 16383 {
            2
        } else if self.0 <= 1_073_741_823 {
            4
        } else {
            8
        }
    }

    /// バッファにエンコードする
    ///
    /// バッファの長さが不足している場合は Err を返す
    pub fn encode(self, buf: &mut [u8]) -> Result<usize, Error> {
        let size = self.encoded_size();
        if buf.len() < size {
            return Err(Error::Incomplete {
                needed: size - buf.len(),
            });
        }

        match size {
            1 => {
                buf[0] = self.0 as u8;
            }
            2 => {
                let val = (self.0 as u16) | 0x4000;
                buf[..2].copy_from_slice(&val.to_be_bytes());
            }
            4 => {
                let val = (self.0 as u32) | 0x8000_0000;
                buf[..4].copy_from_slice(&val.to_be_bytes());
            }
            8 => {
                let val = self.0 | 0xc000_0000_0000_0000;
                buf[..8].copy_from_slice(&val.to_be_bytes());
            }
            _ => unreachable!(),
        }

        Ok(size)
    }

    /// Vec にエンコードする
    pub fn encode_to_vec(self, buf: &mut Vec<u8>) {
        let size = self.encoded_size();
        let start = buf.len();
        buf.resize(start + size, 0);
        self.encode(&mut buf[start..])
            .expect("buffer length equals encoded size");
    }

    /// バッファからデコードする
    ///
    /// 成功時は (値, 消費バイト数) を返す
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), Error> {
        if buf.is_empty() {
            return Err(Error::Incomplete { needed: 1 });
        }

        let tag = buf[0] >> 6;
        let size = 1usize << tag;

        if buf.len() < size {
            return Err(Error::Incomplete {
                needed: size - buf.len(),
            });
        }

        let value = match size {
            1 => u64::from(buf[0] & 0x3f),
            2 => {
                let mut bytes = [0u8; 2];
                bytes.copy_from_slice(&buf[..2]);
                u64::from(u16::from_be_bytes(bytes) & 0x3fff)
            }
            4 => {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&buf[..4]);
                u64::from(u32::from_be_bytes(bytes) & 0x3fff_ffff)
            }
            8 => {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&buf[..8]);
                u64::from_be_bytes(bytes) & 0x3fff_ffff_ffff_ffff
            }
            _ => unreachable!(),
        };

        Ok((Self(value), size))
    }
}

impl core::fmt::Debug for VarInt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VarInt({})", self.0)
    }
}

impl core::fmt::Display for VarInt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for VarInt {
    /// 0 を返す
    ///
    /// 0 は varint の有効な値である。構造体の省略値として使う。
    fn default() -> Self {
        Self(0)
    }
}

impl From<u8> for VarInt {
    fn from(value: u8) -> Self {
        Self(u64::from(value))
    }
}

impl From<u16> for VarInt {
    fn from(value: u16) -> Self {
        Self(u64::from(value))
    }
}

impl From<u32> for VarInt {
    fn from(value: u32) -> Self {
        Self(u64::from(value))
    }
}

/// `VarInt` の値を u64 として返す
impl From<VarInt> for u64 {
    fn from(value: VarInt) -> Self {
        value.0
    }
}

/// 読み出し側の算術を簡潔に保つための演算実装
///
/// `VarInt` は常に 0..=2^62-1 の値を取る。加減算・比較の結果は u64 として
/// 扱い、新しい `VarInt` を作る場合は `VarInt::new` により再検証する。
/// 代入演算 (`+=` 等) は型の不変条件を壊せるため実装しない。
impl core::ops::Add<u64> for VarInt {
    type Output = u64;
    fn add(self, rhs: u64) -> u64 {
        self.0 + rhs
    }
}

impl core::ops::Add<VarInt> for VarInt {
    type Output = u64;
    fn add(self, rhs: VarInt) -> u64 {
        self.0 + rhs.0
    }
}

impl core::ops::Add<VarInt> for u64 {
    type Output = u64;
    fn add(self, rhs: VarInt) -> u64 {
        self + rhs.0
    }
}

impl core::ops::Sub<u64> for VarInt {
    type Output = u64;
    fn sub(self, rhs: u64) -> u64 {
        self.0 - rhs
    }
}

impl core::ops::Sub<VarInt> for VarInt {
    type Output = u64;
    fn sub(self, rhs: VarInt) -> u64 {
        self.0 - rhs.0
    }
}

impl core::ops::Sub<VarInt> for u64 {
    type Output = u64;
    fn sub(self, rhs: VarInt) -> u64 {
        self - rhs.0
    }
}

impl PartialEq<u64> for VarInt {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialEq<VarInt> for u64 {
    fn eq(&self, other: &VarInt) -> bool {
        *self == other.0
    }
}

impl PartialOrd<u64> for VarInt {
    fn partial_cmp(&self, other: &u64) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

impl PartialOrd<VarInt> for u64 {
    fn partial_cmp(&self, other: &VarInt) -> Option<core::cmp::Ordering> {
        self.partial_cmp(&other.0)
    }
}

impl VarInt {
    /// u64 を加算した結果を返す
    pub const fn saturating_add(self, rhs: u64) -> u64 {
        self.0.saturating_add(rhs)
    }

    /// u64 を減算した結果を返す
    pub const fn saturating_sub(self, rhs: u64) -> u64 {
        self.0.saturating_sub(rhs)
    }

    /// u64 を加算した結果を返す (オーバーフロー時は None)
    pub const fn checked_add(self, rhs: u64) -> Option<u64> {
        self.0.checked_add(rhs)
    }

    /// u64 を減算した結果を返す (アンダーフロー時は None)
    pub const fn checked_sub(self, rhs: u64) -> Option<u64> {
        self.0.checked_sub(rhs)
    }

    /// 2 つの値の大きい方を返す
    pub const fn max(self, rhs: u64) -> u64 {
        if self.0 > rhs { self.0 } else { rhs }
    }

    /// 2 つの値の小さい方を返す
    pub const fn min(self, rhs: u64) -> u64 {
        if self.0 < rhs { self.0 } else { rhs }
    }
}

impl TryFrom<u64> for VarInt {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value).ok_or_else(|| {
            Error::InvalidData(format!(
                "value {value} exceeds maximum varint value {MAX_VALUE}"
            ))
        })
    }
}
