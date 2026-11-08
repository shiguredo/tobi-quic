// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Initial / Handshake パケットの AEAD nonce 計算 (RFC 9001 Section 5.3)
//!
//! パケット保護 IV に、復元済みパケット番号を IV のサイズまでゼロで左パディング
//! した値を XOR して nonce を作る。tobi-quic でこの関数を使うのは Initial / Handshake
//! パケットだけである。
//!
//! 1-RTT パケットの nonce は rustls が計算する。Multipath QUIC では Path ID を
//! 含む PPN (Path-and-Packet-Number) を組み立てて nonce を作る必要があるが、その
//! ビット配置の計算は rustls の `PacketKey::encrypt_in_place_for_path` /
//! `decrypt_in_place_for_path` が行う。tobi-transport はパス ID とパケット番号を
//! 渡すだけで、nonce の組み立てを自前で行わない
//! (RFC 10069 Section 2.4)。

/// 通常の QUIC AEAD nonce を計算する (RFC 9001 Section 5.3)
///
/// Initial / Handshake パケットの AEAD nonce を計算する。この関数が tobi-quic で
/// 本番に使われる唯一の nonce 計算経路である。1-RTT パケットの nonce は
/// rustls が Path ID を含めて計算するため、この関数は使わない。
///
/// - `iv`: パケット保護 IV (12 バイト)
/// - `packet_number`: 復元済みパケット番号
pub fn compute_nonce(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let pn_bytes = packet_number.to_be_bytes();
    // パケット番号 (8 バイト) を IV の下位 8 バイトに XOR する。
    // RFC 9001 Section 5.3 の「パケット番号を IV のサイズまでゼロで左パディング
    // して XOR する」計算に相当する。IV は 12 バイトなので上位 4 バイトは変化しない。
    for i in 0..8 {
        nonce[4 + i] ^= pn_bytes[i];
    }
    nonce
}
