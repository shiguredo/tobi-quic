// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! OBSERVED_ADDRESS フレーム (draft-ietf-quic-address-discovery-01 Section 4.1)
//!
//! ピアから観測された自分のアドレスを通知する。
//! draft であり将来変更される可能性がある。

use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::Error;
use crate::varint::VarInt;

/// OBSERVED_ADDRESS フレーム
///
/// フレームタイプの最下位ビットでアドレスファミリを表す
/// (0: IPv4、1: IPv6)。[`ObservedAddress::encode`] は `addr` のファミリに応じて
/// フレームタイプを自動選択する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedAddress {
    /// シーケンス番号 (接続内で単調増加)
    pub sequence_number: VarInt,
    /// ピアから観測されたアドレス
    pub addr: SocketAddr,
}

impl ObservedAddress {
    /// ペイロードをデコードする
    ///
    /// `is_ipv6` はフレームタイプの最下位ビットが 1 の場合に true を渡す。
    pub fn decode_payload(buf: &[u8], is_ipv6: bool) -> Result<(Self, usize), Error> {
        let mut pos = 0;
        let (sequence_number, n) = VarInt::decode(&buf[pos..])?;
        pos += n;

        let ip = if is_ipv6 {
            if buf.len() < pos + 16 {
                return Err(Error::Incomplete {
                    needed: pos + 16 - buf.len(),
                });
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[pos..pos + 16]);
            pos += 16;
            IpAddr::V6(Ipv6Addr::from(octets))
        } else {
            if buf.len() < pos + 4 {
                return Err(Error::Incomplete {
                    needed: pos + 4 - buf.len(),
                });
            }
            let octets = [buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]];
            pos += 4;
            IpAddr::V4(Ipv4Addr::from(octets))
        };

        // Port (16) はネットワークバイトオーダー (Section 4.1)
        if buf.len() < pos + 2 {
            return Err(Error::Incomplete {
                needed: pos + 2 - buf.len(),
            });
        }
        let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        pos += 2;

        Ok((
            Self {
                sequence_number,
                addr: SocketAddr::new(ip, port),
            },
            pos,
        ))
    }

    /// フレームをエンコードする
    pub fn encode(&self, buf: &mut Vec<u8>) {
        let frame_type = if self.addr.is_ipv6() {
            super::frame_type::OBSERVED_ADDRESS_V6
        } else {
            super::frame_type::OBSERVED_ADDRESS_V4
        };
        VarInt::try_from(frame_type)
            .expect("OBSERVED_ADDRESS frame type is within VarInt range")
            .encode_to_vec(buf);
        self.sequence_number.encode_to_vec(buf);
        match self.addr.ip() {
            IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => buf.extend_from_slice(&v6.octets()),
        }
        buf.extend_from_slice(&self.addr.port().to_be_bytes());
    }
}
