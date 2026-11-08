// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! QUIC Connection ID (RFC 9000 Section 5.1)
//!
//! Connection ID は最大 20 バイトの可変長識別子。
//! Multipath では各 Connection ID が特定の Path ID に紐付く。

use crate::error::Error;

/// Connection ID の最大長 (RFC 9000 Section 17.2)
pub const MAX_CID_LENGTH: usize = 20;

/// QUIC Connection ID
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    len: u8,
    bytes: [u8; MAX_CID_LENGTH],
}

impl ConnectionId {
    /// 空の Connection ID を生成する
    pub const fn empty() -> Self {
        Self {
            len: 0,
            bytes: [0; MAX_CID_LENGTH],
        }
    }

    /// バイト列から Connection ID を生成する
    ///
    /// 長さが 20 バイトを超える場合はエラーを返す
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_CID_LENGTH {
            return Err(Error::InvalidData(format!(
                "connection ID length {} exceeds maximum {}",
                bytes.len(),
                MAX_CID_LENGTH
            )));
        }
        let mut cid = Self::empty();
        cid.len = bytes.len() as u8;
        cid.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(cid)
    }

    /// Connection ID のバイト列を返す
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Connection ID の長さを返す
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// 空かどうかを返す
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ConnectionId(")?;
        for byte in self.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

impl core::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
