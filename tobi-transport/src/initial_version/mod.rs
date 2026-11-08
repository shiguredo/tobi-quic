// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! サーバー向け: クライアントの最初の Initial から互換バージョンを選ぶ
//!
//! RFC 9368 Section 2.3 の互換バージョン交渉では、サーバーはクライアントの
//! 最初の flight を Chosen Version で復号し、ClientHello の
//! `version_information` トランスポートパラメータを読んでネゴシエートする
//! バージョンを決める。本モジュールは接続状態を持たずにそれを実行する
//! Sans I/O ヘルパーで、platform のルーターが接続を生成する前に使う。
//!
//! 本実装は rustls の QUIC セッションがバージョンに束縛されるため接続内で
//! バージョンを切り替えない。選択結果が Chosen Version と異なる場合は、
//! ルーターが選択されたバージョンで接続を生成し、サーバーは最初の flight を
//! Chosen Version のまま受信してネゴシエート済みバージョンで応答する。

use tobi_core::connection::select_server_negotiated_version;
use tobi_core::error::Error;
use tobi_core::frame::Frame;
use tobi_core::nonce;
use tobi_core::packet::header::LongHeader;
use tobi_core::packet::number;
use tobi_core::packet::{LongPacketType, version_negotiation::MIN_INITIAL_DATAGRAM_SIZE};
use tobi_core::role::Role;
use tobi_core::transport_params::TransportParams;
use tobi_core::varint::VarInt;
use tobi_crypto::keys as crypto;
use tobi_crypto::protection;

/// ClientHello として受け付ける最大バイト数
///
/// CRYPTO フレームのオフセットは可変長整数で任意に大きくできるため、
/// 受信データをそのまま確保するとメモリ枯渇攻撃になる。接続側の Initial
/// CRYPTO 受信バッファと同じ 16 KiB を上限にする。
const MAX_CLIENT_HELLO_BYTES: usize = 16 * 1024;

#[cfg(test)]
mod tests;

/// クライアントの最初の Initial から互換バージョンを選ぶ
///
/// 戻り値は Chosen Version と異なる、サーバーが選んだバージョン。
/// 次の場合は `None` を返し、呼び出し側は Chosen Version で接続する。
///
/// - Long Header が Initial でない、またはデータグラムが 1200 バイト未満
/// - Initial を復号できない
/// - ClientHello が最初の flight に収まっていない
/// - `version_information` が無い、または互換バージョンが選択されない
///
/// `server_versions` はサーバーが対応するバージョンの一覧で、優先順でもある。
pub fn select_compatible_version(datagram: &[u8], server_versions: &[u32]) -> Option<u32> {
    // RFC 9000 Section 14.1: サーバーは 1200 バイト未満の Initial を破棄する。
    // 破棄するパケットのために復号処理をしない。
    if datagram.len() < MIN_INITIAL_DATAGRAM_SIZE {
        return None;
    }
    let first = LongHeader::decode_allow_zero_quic_bit(datagram).ok()?;
    if first.packet_type != LongPacketType::Initial {
        return None;
    }
    let chosen_version = first.version;
    // 予約バージョンや未対応バージョンはサーバーが受理しないため対象外。
    if !tobi_core::packet::is_supported_version(chosen_version)
        || !server_versions.contains(&chosen_version)
    {
        return None;
    }

    // RFC 9001 Section 5.2: Initial 鍵はクライアントの最初の Initial の DCID から
    // 導出する。サーバーから見た remote がクライアントの送信鍵になる。
    let keys = crypto::derive_initial_keys(chosen_version, &first.dcid, Role::Server).ok()?;
    let mut crypto_data = CryptoData::default();
    let mut offset = 0;
    while offset < datagram.len() {
        let hdr = match LongHeader::decode_allow_zero_quic_bit(&datagram[offset..]) {
            Ok(hdr) => hdr,
            Err(_) => break,
        };
        // コアレスされたパケットは同じバージョンの Initial だけを読む。
        // Handshake 以降は Initial の復号対象ではない。
        if hdr.version != chosen_version || hdr.packet_type != LongPacketType::Initial {
            break;
        }
        let consumed =
            match decrypt_initial(&datagram[offset..], &hdr, &keys.remote, &mut crypto_data) {
                Ok(consumed) => consumed,
                // 1 通目を復号できない時点で互換バージョン交渉は諦める。
                Err(_) => return None,
            };
        if consumed == 0 {
            break;
        }
        offset += consumed;
        if let Some(params) = crypto_data.client_hello_transport_params() {
            let version_information = params.version_information.as_ref()?;
            let selected = select_server_negotiated_version(
                version_information,
                server_versions,
                server_versions,
            )?;
            if selected == chosen_version {
                return None;
            }
            return Some(selected);
        }
    }
    None
}

/// Initial パケットを復号し、CRYPTO フレームのデータを収集する
///
/// 戻り値は消費したバイト数 (パケットの末尾まで)。
fn decrypt_initial(
    packet: &[u8],
    hdr: &LongHeader,
    keys: &crypto::DirectionalKeys,
    crypto_data: &mut CryptoData,
) -> Result<usize, Error> {
    // Token Length と Length は Header Protection の対象外なので平文で読める
    // (RFC 9000 Section 17.2.2)。
    let mut pos = hdr.header_len;
    let (token_length, read) = VarInt::decode(&packet[pos..])?;
    pos += read;
    let token_len = usize::try_from(token_length.as_u64())
        .map_err(|_| Error::InvalidData("Initial token length exceeds usize".into()))?;
    if token_len > packet.len() - pos {
        return Err(Error::Incomplete {
            needed: token_len - (packet.len() - pos),
        });
    }
    pos += token_len;
    let (payload_length, read) = VarInt::decode(&packet[pos..])?;
    pos += read;
    let payload_len = usize::try_from(payload_length.as_u64())
        .map_err(|_| Error::InvalidData("Initial payload length exceeds usize".into()))?;
    let packet_end = pos
        .checked_add(payload_len)
        .ok_or_else(|| Error::InvalidData("initial packet length overflow".into()))?;
    if packet.len() < packet_end {
        return Err(Error::Incomplete {
            needed: packet_end - packet.len(),
        });
    }

    // Header Protection 除去とパケット番号復元
    let pn_offset = pos;
    let mut protected = packet[..packet_end].to_vec();
    let pn_len = protection::remove_header_protection(&mut protected, pn_offset, &keys.hp)?;
    let (truncated, _) = number::decode_truncated(&protected[pn_offset..], pn_len)?;
    let packet_number = number::decode_full(None, u64::from(truncated), u32::from(pn_len) * 8);
    let header_end = pn_offset + pn_len as usize;
    let aad = protected[..header_end].to_vec();

    // AEAD 復号
    let packet_nonce = nonce::compute_nonce(keys.aead.iv(), packet_number);
    let mut payload = protected[header_end..].to_vec();
    let plaintext_len = protection::decrypt_payload(&keys.aead, &packet_nonce, &aad, &mut payload)?;

    // CRYPTO フレームだけを集める。他のフレームは接続生成後に改めて処理される。
    let mut frame_pos = 0;
    while frame_pos < plaintext_len {
        let (frame, size) = Frame::decode(&payload[frame_pos..plaintext_len])?;
        if size == 0 {
            return Err(Error::InvalidData(
                "zero-length frame in initial packet".into(),
            ));
        }
        if let Frame::Crypto(crypto) = frame {
            crypto_data.push(crypto.offset.as_u64(), &crypto.data);
        }
        frame_pos += size;
    }
    Ok(packet_end)
}

/// 受信した CRYPTO データをオフセット付きで保持する
#[derive(Default)]
struct CryptoData {
    /// (オフセット, データ) の一覧
    chunks: Vec<(u64, Vec<u8>)>,
}

impl CryptoData {
    fn push(&mut self, offset: u64, data: &[u8]) {
        self.chunks.push((offset, data.to_vec()));
    }

    /// ClientHello が揃っていればトランスポートパラメータを返す
    ///
    /// 最初の TLS ハンドシェイクメッセージだけを対象にする。CRYPTO データに
    /// ギャップがある、または ClientHello が途中までの場合は `None`。
    fn client_hello_transport_params(&self) -> Option<TransportParams> {
        if self.chunks.is_empty() {
            return None;
        }
        let max_end = self
            .chunks
            .iter()
            .map(|(offset, data)| offset.saturating_add(data.len() as u64))
            .max()?;
        // 攻撃者が CRYPTO のオフセットを大きくして大量のメモリを確保させるのを防ぐ。
        if max_end > MAX_CLIENT_HELLO_BYTES as u64 {
            return None;
        }
        let mut buffer = vec![0u8; usize::try_from(max_end).ok()?];
        let mut received = vec![false; buffer.len()];
        for (offset, data) in &self.chunks {
            let start = usize::try_from(*offset).ok()?;
            let end = start.checked_add(data.len())?;
            if end > buffer.len() {
                return None;
            }
            buffer[start..end].copy_from_slice(data);
            received[start..end].fill(true);
        }

        // TLS ハンドシェイクメッセージ: type(1) + length(3) + body
        if buffer.len() < 4 || buffer[0] != 0x01 {
            return None;
        }
        let length = u32::from_be_bytes([0, buffer[1], buffer[2], buffer[3]]) as usize;
        let message_end = 4usize.checked_add(length)?;
        if buffer.len() < message_end || received[..message_end].iter().any(|ok| !ok) {
            return None;
        }
        let transport_params = client_hello_transport_parameters(&buffer[4..message_end])?;
        TransportParams::decode(transport_params).ok()
    }
}

/// ClientHello の body から quic_transport_parameters 拡張を取り出す
///
/// RFC 9001 Section 8.2: QUIC のトランスポートパラメータは TLS の
/// `quic_transport_parameters` 拡張 (type 0x0039) で運ばれる。
fn client_hello_transport_parameters(body: &[u8]) -> Option<&[u8]> {
    const QUIC_TRANSPORT_PARAMETERS_EXTENSION: u16 = 0x0039;

    // legacy_version(2) + random(32)
    let mut pos = 2 + 32;
    // session_id
    let session_id_len = usize::from(*body.get(pos)?);
    pos = pos.checked_add(1 + session_id_len)?;
    // cipher_suites
    let cipher_suites_len = usize::from(u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]));
    pos = pos.checked_add(2 + cipher_suites_len)?;
    // compression_methods
    let compression_methods_len = usize::from(*body.get(pos)?);
    pos = pos.checked_add(1 + compression_methods_len)?;
    // extensions
    let extensions_len = usize::from(u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]));
    pos = pos.checked_add(2)?;
    let extensions_end = pos.checked_add(extensions_len)?;
    if extensions_end > body.len() {
        return None;
    }

    while pos + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let extension_len = usize::from(u16::from_be_bytes([body[pos + 2], body[pos + 3]]));
        pos += 4;
        let extension_end = pos.checked_add(extension_len)?;
        if extension_end > extensions_end {
            return None;
        }
        if extension_type == QUIC_TRANSPORT_PARAMETERS_EXTENSION {
            return Some(&body[pos..extension_end]);
        }
        pos = extension_end;
    }
    None
}
