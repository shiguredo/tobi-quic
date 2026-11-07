// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! QUIC パケットヘッダのデコード/エンコード (RFC 9000 Section 17)
//!
//! ヘッダ保護適用前のデコードと、ヘッダ保護除去後のデコードを分離する。
//! Header Protection の適用 / 除去は tobi_crypto の protection モジュールで行う。

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::connection_id::ConnectionId;
use crate::error::{Error, TransportErrorCode};

use super::LongPacketType;

/// パケットの先頭バイトから Long Header か Short Header かを判定する
pub const fn is_long_header(first_byte: u8) -> bool {
    first_byte & 0x80 != 0
}

/// Long Header のデコード結果
///
/// Header Protection 除去前でもデコード可能なフィールドのみを含む。
/// パケット番号はヘッダ保護されているため、ここには含まない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongHeader {
    /// 先頭バイト (ヘッダ保護適用済み)
    pub first_byte: u8,
    /// パケットタイプ
    pub packet_type: LongPacketType,
    /// QUIC バージョン
    pub version: u32,
    /// 宛先 Connection ID
    pub dcid: ConnectionId,
    /// 送信元 Connection ID
    pub scid: ConnectionId,
    /// ヘッダの固定部分の長さ (先頭バイトから SCID の末尾まで)
    pub header_len: usize,
}

impl LongHeader {
    /// バッファから Long Header の固定部分をデコードする
    ///
    /// パケット番号やペイロードはデコードしない。
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        Self::decode_inner(buf, false)
    }

    /// QUIC Bit 0 のパケットを許容して Long Header をデコードする (RFC 9287)
    ///
    /// ピアが `grease_quic_bit` を広告した場合に使う。広告していない場合の
    /// 受信検証は [`Self::decode`] が行う。
    pub fn decode_allow_zero_quic_bit(buf: &[u8]) -> Result<Self, Error> {
        Self::decode_inner(buf, true)
    }

    /// Long Header をデコードする (QUIC Bit 0 を許容するか指定可能)
    fn decode_inner(buf: &[u8], allow_zero_quic_bit: bool) -> Result<Self, Error> {
        if buf.len() < 7 {
            return Err(Error::Incomplete {
                needed: 7 - buf.len(),
            });
        }

        let first_byte = buf[0];

        if !is_long_header(first_byte) {
            return Err(Error::InvalidData(
                "expected long header but got short header".to_string(),
            ));
        }

        let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);

        // Version Negotiation パケット (version == 0) は特殊
        // Retry パケットも固定ビットチェックをスキップ
        let packet_type = if version == 0 {
            // Version Negotiation は packet type を持たない
            // ここでは便宜的に Initial を返し、呼び出し側で version == 0 をチェックする
            LongPacketType::Initial
        } else {
            // Fixed Bit チェック (Version Negotiation 以外)。
            // RFC 9287 Section 3: 自分が grease_quic_bit を広告している場合は
            // QUIC Bit 0 を受け入れる。
            if !allow_zero_quic_bit && first_byte & 0x40 == 0 {
                return Err(Error::InvalidData(
                    "fixed bit is not set in long header".to_string(),
                ));
            }
            let type_bits = (first_byte & 0x30) >> 4;
            // パケットタイプのビット割り当てはバージョンごとに異なる
            // (RFC 9369 Section 3.2)。未知のバージョンは v1 の割り当てで
            // 解釈するが、呼び出し側は Version Negotiation 応答の判定を
            // この packet_type に依存させないこと。
            LongPacketType::from_bits_for_version(version, type_bits).ok_or_else(|| {
                Error::InvalidData(format!("invalid long packet type: {type_bits}"))
            })?
        };

        let dcid_len = buf[5] as usize;
        let dcid_start = 6;
        let dcid_end = dcid_start + dcid_len;

        if buf.len() < dcid_end + 1 {
            return Err(Error::Incomplete {
                needed: dcid_end + 1 - buf.len(),
            });
        }

        let dcid = ConnectionId::from_slice(&buf[dcid_start..dcid_end])?;

        let scid_len = buf[dcid_end] as usize;
        let scid_start = dcid_end + 1;
        let scid_end = scid_start + scid_len;

        if buf.len() < scid_end {
            return Err(Error::Incomplete {
                needed: scid_end - buf.len(),
            });
        }

        let scid = ConnectionId::from_slice(&buf[scid_start..scid_end])?;

        Ok(Self {
            first_byte,
            packet_type,
            version,
            dcid,
            scid,
            header_len: scid_end,
        })
    }

    /// Long Header の固定部分をエンコードする
    ///
    /// first_byte は呼び出し側で構築すること。
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.first_byte);
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.push(self.dcid.len() as u8);
        buf.extend_from_slice(self.dcid.as_bytes());
        buf.push(self.scid.len() as u8);
        buf.extend_from_slice(self.scid.as_bytes());
    }

    /// first_byte を構築する (ヘッダ保護前)
    ///
    /// パケットタイプのビット割り当てはバージョンごとに異なるため
    /// (RFC 9369 Section 3.2)、`version` に対応するビットを使う。
    ///
    /// - pn_len: パケット番号の長さ (1-4)
    pub fn build_first_byte(version: u32, packet_type: LongPacketType, pn_len: u8) -> u8 {
        Self::build_first_byte_with_quic_bit(version, packet_type, pn_len, false)
    }

    /// first_byte を構築する (QUIC Bit の値を指定可能)
    ///
    /// RFC 9287 Section 3: ピアが `grease_quic_bit` を広告した場合、
    /// `quic_bit_zero` を true にして QUIC Bit を 0 にできる。
    pub fn build_first_byte_with_quic_bit(
        version: u32,
        packet_type: LongPacketType,
        pn_len: u8,
        quic_bit_zero: bool,
    ) -> u8 {
        assert!((1..=4).contains(&pn_len));
        let mut byte = 0x80 | 0x40 | (packet_type.to_bits_for_version(version) << 4) | (pn_len - 1);
        if quic_bit_zero {
            byte &= !0x40;
        }
        byte
    }
}

/// Short Header (1-RTT) のデコード結果
///
/// Header Protection 除去前でもデコード可能なフィールドのみを含む。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortHeader {
    /// 先頭バイト (ヘッダ保護適用済み)
    pub first_byte: u8,
    /// 宛先 Connection ID
    pub dcid: ConnectionId,
    /// ヘッダの固定部分の長さ (先頭バイトから DCID の末尾まで)
    pub header_len: usize,
}

impl ShortHeader {
    /// バッファから Short Header をデコードする
    ///
    /// Short Header の DCID 長はコネクションのコンテキストから既知である必要がある。
    pub fn decode(buf: &[u8], dcid_len: usize) -> Result<Self, Error> {
        Self::decode_inner(buf, dcid_len, false)
    }

    /// QUIC Bit 0 のパケットを許容して Short Header をデコードする (RFC 9287)
    ///
    /// 自分が `grease_quic_bit` を広告している場合に使う。
    pub fn decode_allow_zero_quic_bit(buf: &[u8], dcid_len: usize) -> Result<Self, Error> {
        Self::decode_inner(buf, dcid_len, true)
    }

    /// Short Header をデコードする (QUIC Bit 0 を許容するか指定可能)
    fn decode_inner(buf: &[u8], dcid_len: usize, allow_zero_quic_bit: bool) -> Result<Self, Error> {
        let needed = 1 + dcid_len;
        if buf.len() < needed {
            return Err(Error::Incomplete {
                needed: needed - buf.len(),
            });
        }

        let first_byte = buf[0];

        if is_long_header(first_byte) {
            return Err(Error::InvalidData(
                "expected short header but got long header".to_string(),
            ));
        }

        // Fixed Bit チェック。RFC 9287 Section 3: 自分が grease_quic_bit を
        // 広告している場合は QUIC Bit 0 を受け入れる。
        if !allow_zero_quic_bit && first_byte & 0x40 == 0 {
            return Err(Error::InvalidData(
                "fixed bit is not set in short header".to_string(),
            ));
        }

        let dcid = ConnectionId::from_slice(&buf[1..1 + dcid_len])?;

        Ok(Self {
            first_byte,
            dcid,
            header_len: 1 + dcid_len,
        })
    }

    /// Short Header をエンコードする
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.first_byte);
        buf.extend_from_slice(self.dcid.as_bytes());
    }

    /// first_byte を構築する (ヘッダ保護前)
    ///
    /// - spin_bit: Latency Spin Bit
    /// - key_phase: Key Phase bit
    /// - pn_len: パケット番号の長さ (1-4)
    pub fn build_first_byte(spin_bit: bool, key_phase: bool, pn_len: u8) -> u8 {
        Self::build_first_byte_with_quic_bit(spin_bit, key_phase, pn_len, false)
    }

    /// first_byte を構築する (QUIC Bit の値を指定可能)
    ///
    /// RFC 9287 Section 3: ピアが `grease_quic_bit` を広告した場合、
    /// `quic_bit_zero` を true にして QUIC Bit を 0 にできる。
    pub fn build_first_byte_with_quic_bit(
        spin_bit: bool,
        key_phase: bool,
        pn_len: u8,
        quic_bit_zero: bool,
    ) -> u8 {
        assert!((1..=4).contains(&pn_len));
        let mut byte = 0x40; // Fixed Bit
        if spin_bit {
            byte |= 0x20;
        }
        // Reserved Bits (0x18) は 0
        if key_phase {
            byte |= 0x04;
        }
        if quic_bit_zero {
            byte &= !0x40;
        }
        byte | (pn_len - 1)
    }
}

/// ロングヘッダパケットの Reserved Bits を検査する (RFC 9000 Section 17.2)
///
/// パケット保護とヘッダ保護の両方を除去した後の先頭バイトを渡すこと。
/// マスク 0x0c の 2 ビットが非ゼロなら PROTOCOL_VIOLATION とする (MUST)。
///
/// ヘッダ保護を除去しただけの段階で判定すると、保護を外す前の値で
/// 攻撃者に接続を閉じさせられるため、AEAD 復号成功後に呼び出す
/// (RFC 9001 Section 9.5)。
pub fn check_long_header_reserved_bits(first_byte: u8) -> Result<(), Error> {
    if first_byte & 0x0c != 0 {
        return Err(Error::Protocol {
            code: TransportErrorCode::PROTOCOL_VIOLATION,
            reason: format!(
                "reserved bits 0x0c are non-zero after removing packet protection: 0x{first_byte:02x}"
            ),
        });
    }
    Ok(())
}

/// ショートヘッダパケットの Reserved Bits を検査する (RFC 9000 Section 17.3)
///
/// パケット保護とヘッダ保護の両方を除去した後の先頭バイトを渡すこと。
/// マスク 0x18 の 2 ビットが非ゼロなら PROTOCOL_VIOLATION とする (MUST)。
pub fn check_short_header_reserved_bits(first_byte: u8) -> Result<(), Error> {
    if first_byte & 0x18 != 0 {
        return Err(Error::Protocol {
            code: TransportErrorCode::PROTOCOL_VIOLATION,
            reason: format!(
                "reserved bits 0x18 are non-zero after removing packet protection: 0x{first_byte:02x}"
            ),
        });
    }
    Ok(())
}
