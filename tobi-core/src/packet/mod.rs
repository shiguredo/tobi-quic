// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! QUIC パケットの定義とエンコード/デコード
//!
//! RFC 9000 Section 17 で定義されるパケットヘッダ形式を実装する。

pub mod header;
pub mod number;
pub mod version_negotiation;

/// QUIC version 1 (RFC 9000)
pub const QUIC_VERSION_1: u32 = 0x0000_0001;

/// QUIC version 2 (RFC 9369 Section 3.1)
pub const QUIC_VERSION_2: u32 = 0x6b33_43cf;

/// バージョンが本実装の対応範囲かを返す
pub const fn is_supported_version(version: u32) -> bool {
    matches!(version, QUIC_VERSION_1 | QUIC_VERSION_2)
}

/// バージョン番号の表示名を返す (ログ・qlog 用)
pub const fn version_name(version: u32) -> &'static str {
    match version {
        QUIC_VERSION_1 => "v1",
        QUIC_VERSION_2 => "v2",
        _ => "unknown",
    }
}

/// Long Header パケットタイプ (RFC 9000 Section 17.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

impl LongPacketType {
    /// QUIC v1 の 2 ビット値からパケットタイプを返す (RFC 9000 Section 17.2)
    pub const fn from_bits(bits: u8) -> Option<Self> {
        Self::from_bits_for_version(QUIC_VERSION_1, bits)
    }

    /// QUIC v1 の 2 ビット値を返す (RFC 9000 Section 17.2)
    pub const fn to_bits(self) -> u8 {
        self.to_bits_for_version(QUIC_VERSION_1)
    }

    /// バージョンに対応する 2 ビット値からパケットタイプを返す
    ///
    /// v2 は v1 とパケットタイプのビット割り当てが異なる
    /// (RFC 9369 Section 3.2)。未知のバージョンは v1 の割り当てで解釈する
    /// (Version Negotiation 応答の判定では Long Header の type bits を
    /// 参照しないため、この解釈は応答生成に影響しない)。
    pub const fn from_bits_for_version(version: u32, bits: u8) -> Option<Self> {
        match version {
            QUIC_VERSION_2 => match bits {
                0x01 => Some(Self::Initial),
                0x02 => Some(Self::ZeroRtt),
                0x03 => Some(Self::Handshake),
                0x00 => Some(Self::Retry),
                _ => None,
            },
            _ => match bits {
                0x00 => Some(Self::Initial),
                0x01 => Some(Self::ZeroRtt),
                0x02 => Some(Self::Handshake),
                0x03 => Some(Self::Retry),
                _ => None,
            },
        }
    }

    /// バージョンに対応する 2 ビット値を返す
    pub const fn to_bits_for_version(self, version: u32) -> u8 {
        match version {
            QUIC_VERSION_2 => match self {
                Self::Initial => 0x01,
                Self::ZeroRtt => 0x02,
                Self::Handshake => 0x03,
                Self::Retry => 0x00,
            },
            _ => match self {
                Self::Initial => 0x00,
                Self::ZeroRtt => 0x01,
                Self::Handshake => 0x02,
                Self::Retry => 0x03,
            },
        }
    }
}
