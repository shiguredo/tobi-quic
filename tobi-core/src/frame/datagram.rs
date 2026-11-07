// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! DATAGRAM フレーム (RFC 9221 Section 4)
//!
//! フレームタイプ 0x30 (LEN ビットなし) と 0x31 (LEN ビットあり) の
//! エンコード/デコードを提供する。

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub data: Vec<u8>,
}

impl Datagram {
    /// LEN ビットなし (0x30) のデコード
    ///
    /// payload の残り全体を Datagram Data として読み取る。
    /// 呼び出し元はパケット末尾までのスライスを渡す必要がある。
    pub fn decode_payload_no_len(buf: &[u8]) -> (Self, usize) {
        let data = buf.to_vec();
        let len = data.len();
        (Self { data }, len)
    }

    /// LEN ビットあり (0x31) のデコード
    ///
    /// VarInt で Length をデコードし、その長さ分を Datagram Data として読み取る。
    pub fn decode_payload_with_len(buf: &[u8]) -> Result<(Self, usize), Error> {
        let (length, n) = VarInt::decode(buf)?;
        let length = usize::try_from(length.as_u64()).unwrap_or(usize::MAX);
        let payload = &buf[n..];
        if payload.len() < length {
            return Err(Error::Incomplete {
                needed: length - payload.len(),
            });
        }
        let data = payload[..length].to_vec();
        Ok((Self { data }, n + length))
    }

    /// LEN ビットあり (0x31) でエンコードする
    ///
    /// 複数フレームを 1 パケットに含められるよう、常に Length フィールドを付与する。
    pub fn encode(&self, buf: &mut Vec<u8>) {
        VarInt::from(super::frame_type::DATAGRAM_LEN as u8).encode_to_vec(buf);
        VarInt::try_from(self.data.len() as u64)
            .expect("length fits in 62-bit varint")
            .encode_to_vec(buf);
        buf.extend_from_slice(&self.data);
    }

    /// エンコード後のフレーム全体のサイズを返す (フレームタイプ + Length + Data)
    ///
    /// 送信側が LEN あり (0x31) で最短 Length を付けたときのサイズであり、
    /// 受信したフレームの wire 長と一致するのはその場合だけである。LEN なし
    /// (0x30) で受信したフレームは Length フィールドを持たないためその分だけ
    /// 過大になり、非最短 Length で受信したフレームは最短 Length との差分だけ
    /// 過小になる。受信側で `max_datagram_frame_size` と比較する場合は、
    /// `Frame::decode` が返す消費バイト数を wire 長として使うこと
    /// (RFC 9221 Section 3)。
    pub fn encoded_size(&self) -> usize {
        Self::encoded_size_for(self.data.len())
    }

    /// payload 長からエンコード後のフレーム全体のサイズを返す
    ///
    /// payload を複製せずにサイズだけを求める。`encoded_size` と同じ規則
    /// (フレームタイプ + Length + Data) で計算する。
    ///
    /// # パニック
    ///
    /// `data_len` が 62 ビット varint で表現できる上限
    /// ([`MAX_VALUE`](crate::varint::MAX_VALUE)) を超える場合はパニックする。
    /// DATAGRAM フレームの Length フィールドが 62 ビット varint であるため
    /// (RFC 9000 Section 16)。
    pub fn encoded_size_for(data_len: usize) -> usize {
        let type_size = VarInt::from(super::frame_type::DATAGRAM_LEN as u8).encoded_size();
        let length_size = VarInt::try_from(data_len as u64)
            .expect("length fits in 62-bit varint")
            .encoded_size();
        type_size + length_size + data_len
    }
}
