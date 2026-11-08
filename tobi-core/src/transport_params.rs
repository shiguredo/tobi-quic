// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! QUIC トランスポートパラメータ (RFC 9000 Section 18)
//!
//! RFC 10069 の initial_max_path_id パラメータを含む。

use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::connection_id::ConnectionId;
use crate::error::Error;
use crate::varint::VarInt;

/// 実装が扱う Path ID の実用上限
///
/// RFC 10069 の Path ID は u32 だが、実装が同時に保持する
/// パス数を制限するため、ローカルの `initial_max_path_id` と
/// `Connection::set_max_path_id` の値をこの値で検証する。ピアが広告する
/// `initial_max_path_id` / `MAX_PATH_ID` は u32 のまま受け入れる。
pub const MAX_PATH_ID: u32 = 64;

/// サーバーの preferred_address (RFC 9000 Section 18.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreferredAddress {
    /// IPv4 アドレス (4 バイト、ネットワークバイトオーダー)
    pub ipv4_address: [u8; 4],
    /// IPv4 ポート
    pub ipv4_port: u16,
    /// IPv6 アドレス (16 バイト、ネットワークバイトオーダー)
    pub ipv6_address: [u8; 16],
    /// IPv6 ポート
    pub ipv6_port: u16,
    /// コネクション ID (シーケンス番号 1)
    pub connection_id: ConnectionId,
    /// Stateless Reset Token (16 バイト)
    pub stateless_reset_token: [u8; 16],
}

/// トランスポートパラメータ ID (RFC 9000 Section 18.2)
pub mod param_id {
    pub const ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
    pub const MAX_IDLE_TIMEOUT: u64 = 0x01;
    pub const STATELESS_RESET_TOKEN: u64 = 0x02;
    pub const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
    pub const INITIAL_MAX_DATA: u64 = 0x04;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
    pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
    pub const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
    pub const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
    pub const ACK_DELAY_EXPONENT: u64 = 0x0a;
    pub const MAX_ACK_DELAY: u64 = 0x0b;
    pub const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
    pub const PREFERRED_ADDRESS: u64 = 0x0d;
    pub const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
    pub const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
    pub const RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;

    // version_information (RFC 9368 Section 3)
    // Chosen Version と Available Versions を保持する。
    pub const VERSION_INFORMATION: u64 = 0x11;

    // Reliable Stream Reset 拡張 (draft-ietf-quic-reliable-stream-reset-11 Section 3)
    // draft-11 Section 8.1 が値 0x1d を登録し、IANA の QUIC transport parameter
    // registry では 2026-09-28 に Permanent として登録済みである
    // (Specification: RFC-ietf-quic-reliable-stream-reset-11)。
    // -07 までの暫定値 0x17f7586d2cb571 は使わない。
    pub const RESET_STREAM_AT: u64 = 0x1d;

    // DATAGRAM 拡張 (RFC 9221 Section 3)
    pub const MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;

    // Multipath 拡張 (RFC 10069 Section 2.1)
    pub const INITIAL_MAX_PATH_ID: u64 = 0x3e;

    // Address Discovery 拡張 (draft-ietf-quic-address-discovery-01 Section 3)
    // draft であり将来変更される可能性がある。
    pub const ADDRESS_DISCOVERY: u64 = 0x9f81a176;

    // ACK Frequency 拡張 (draft-ietf-quic-ack-frequency-14 Section 3)
    // マイクロ秒単位の最小 ACK 遅延。
    pub const MIN_ACK_DELAY: u64 = 0xff04de1b;

    // Grease QUIC Bit 拡張 (RFC 9287 Section 3)
    // 空値で送信し、QUIC Bit を 0 にしたパケットの受信許容を通知する。
    pub const GREASE_QUIC_BIT: u64 = 0x2ab2;

    // Receive Timestamps 拡張 (draft-ietf-quic-receive-ts-03 Section 6)
    // draft の暫定値。RFC 化の際に恒久値へ置き換わる可能性がある。
    pub const MAX_RECEIVE_TIMESTAMPS_PER_ACK: u64 = 0x4ac07;
    pub const RECEIVE_TIMESTAMPS_EXPONENT: u64 = 0x4ac26;
}

/// バージョン情報 (RFC 9368 Section 3)
///
/// ハンドシェイク中に Chosen Version と Available Versions を交換し、
/// バージョンダウングレード攻撃の検出と互換バージョン交渉に使う。
/// フォーマットは Chosen Version (32) + Available Versions (32) ... であり、
/// Available Versions は 4 バイト単位で空でもよい (サーバー送信時)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInformation {
    /// 送信者がこの接続で選んだバージョン
    pub chosen_version: u32,
    /// 送信者が対応するバージョンの一覧
    ///
    /// クライアント送信時は最初のフライトが互換なバージョンを優先順で並べ、
    /// Chosen Version を必ず含める (RFC 9368 Section 3)。サーバー送信時は
    /// Fully Deployed Versions を並べ、空でもよい。
    pub available_versions: Vec<u32>,
}

impl VersionInformation {
    /// トランスポートパラメータ値をデコードする
    ///
    /// RFC 9368 Section 4: 長さが 4 未満、または 4 の倍数でない場合は
    /// 解析失敗とする。Chosen Version と Available Versions の 0 は
    /// 解析失敗とする。
    pub fn decode(value: &[u8]) -> Result<Self, Error> {
        if value.len() < 4 || !value.len().is_multiple_of(4) {
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                reason: format!(
                    "version_information length {} is not a non-zero multiple of 4",
                    value.len()
                ),
            });
        }
        let chosen_version = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
        if chosen_version == 0 {
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                reason: "version_information chosen version is zero".to_string(),
            });
        }
        let mut available_versions = Vec::new();
        for chunk in value[4..].chunks_exact(4) {
            let version = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            if version == 0 {
                return Err(Error::Protocol {
                    code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                    reason: "version_information available version is zero".to_string(),
                });
            }
            available_versions.push(version);
        }
        Ok(Self {
            chosen_version,
            available_versions,
        })
    }

    /// トランスポートパラメータ値をエンコードする
    pub fn encode(&self) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&self.chosen_version.to_be_bytes());
        for version in &self.available_versions {
            value.extend_from_slice(&version.to_be_bytes());
        }
        value
    }
}

/// デコード済みトランスポートパラメータ
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportParams {
    // RFC 9000
    pub original_destination_connection_id: Option<ConnectionId>,
    pub max_idle_timeout: u64,
    pub stateless_reset_token: Option<[u8; 16]>,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay: u64,
    pub disable_active_migration: bool,
    /// サーバーの preferred_address (RFC 9000 Section 18.2)
    /// サーバーのみ送信可能。クライアントは受信してパス作成の参考にする。
    pub preferred_address: Option<PreferredAddress>,
    pub active_connection_id_limit: u64,
    pub initial_source_connection_id: Option<ConnectionId>,
    pub retry_source_connection_id: Option<ConnectionId>,

    // DATAGRAM 拡張 (RFC 9221 Section 3)
    // None = パラメータ未送信 (DATAGRAM 非サポート)
    // Some(v) = DATAGRAM フレームの最大サイズ (フレームタイプ、長さ、ペイロード含む)
    pub max_datagram_frame_size: Option<u64>,

    // Reliable Stream Reset 拡張 (draft-ietf-quic-reliable-stream-reset-11)
    pub reset_stream_at: bool,

    // Multipath 拡張
    pub initial_max_path_id: Option<u32>,

    // Address Discovery 拡張 (draft-ietf-quic-address-discovery-01 Section 3)
    // None = パラメータ未送信 (Address Discovery 非サポート)
    // Some(0) = 観測アドレスの提供のみ (受信は希望しない)
    // Some(1) = 観測アドレスの受信のみ (提供はしない)
    // Some(2) = 提供と受信の両方
    pub address_discovery: Option<u64>,

    // ACK Frequency 拡張 (draft-ietf-quic-ack-frequency-14 Section 3)
    // None = パラメータ未送信 (拡張による ACK_FREQUENCY の受信を希望しない)
    // Some(v) = ACK を遅延できる最小時間 (マイクロ秒)
    pub min_ack_delay: Option<u64>,

    // Receive Timestamps 拡張 (draft-ietf-quic-receive-ts-03 Section 6)
    // None = パラメータ未送信 (ACK への受信タイムスタンプ提示を希望しない)。
    // Some(v) = ACK に載せてほしい受信タイムスタンプの最大数。0 は非サポートと同じ。
    pub max_receive_timestamps_per_ack: Option<u64>,
    // None = パラメータ未送信 (既定値 0 = マイクロ秒精度)。
    // Some(v) = ピアがフレームを送る際に使うタイムスタンプ差分の指数 (20 以下)。
    // max_receive_timestamps_per_ack が未送信または 0 の場合は無視される。
    pub receive_timestamps_exponent: Option<u64>,

    /// バージョン情報 (RFC 9368 Section 3)
    ///
    /// None = パラメータ未送信。v2 対応 endpoint は送信しなければならない
    /// (RFC 9369 Section 4)。
    pub version_information: Option<VersionInformation>,

    /// QUIC Bit の greasing に対応するか (RFC 9287 Section 3)
    ///
    /// 広告した場合、ピアから届く QUIC Bit 0 のパケットを受け入れる。
    /// 空値で送信する。
    pub grease_quic_bit: bool,
}

impl Default for TransportParams {
    fn default() -> Self {
        Self {
            original_destination_connection_id: None,
            max_idle_timeout: 0,
            stateless_reset_token: None,
            max_udp_payload_size: u64::from(crate::path::mtu::MAX_UDP_PAYLOAD),
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: false,
            preferred_address: None,
            active_connection_id_limit: 2,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
            max_datagram_frame_size: None,
            reset_stream_at: false,
            initial_max_path_id: None,
            address_discovery: None,
            min_ack_delay: None,
            max_receive_timestamps_per_ack: None,
            receive_timestamps_exponent: None,
            version_information: None,
            grease_quic_bit: false,
        }
    }
}

impl TransportParams {
    /// バッファからトランスポートパラメータをデコードする
    ///
    /// 不正な値や壊れたエンコーディングは、呼び出し側がそのまま接続クローズに
    /// 使えるよう `Error::Protocol` の `TRANSPORT_PARAMETER_ERROR` として返す
    /// (RFC 9000 Section 7.4)。
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        Self::decode_inner(buf).map_err(|e| match e {
            // すでに接続クローズ用のエラーへ変換済みのものはそのまま返す
            Error::Protocol { .. } => e,
            other => Error::Protocol {
                code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                reason: format!("invalid transport parameters: {other}"),
            },
        })
    }

    fn decode_inner(buf: &[u8]) -> Result<Self, Error> {
        let mut params = Self::default();
        let mut offset = 0;
        // 重複検出用の既読 ID 集合 (RFC 9000 Section 7.4)。
        // ID は varint 1 バイト以上、length も varint 1 バイト以上なので、
        // 集合の要素数は入力長の半分を超えず、入力サイズに比例する。
        let mut seen = BTreeSet::<u64>::new();

        while offset < buf.len() {
            let (id, n) = VarInt::decode(&buf[offset..])?;
            offset += n;

            // RFC 9000 Section 7.4: 同一のトランスポートパラメータを 2 回以上
            // 受信した場合は TRANSPORT_PARAMETER_ERROR で接続を閉じる。
            // length のデコードより前に判定するため、length が壊れた 2 度目の
            // 重複でもここで弾ける。
            let id_u64 = id.as_u64();
            if !seen.insert(id_u64) {
                return Err(Error::Protocol {
                    code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                    reason: format!("duplicate transport parameter {id_u64}"),
                });
            }

            let (length, n) = VarInt::decode(&buf[offset..])?;
            offset += n;

            // 32-bit ターゲットでも 62-bit varint の長さを切り捨てない。
            // usize に収まらない長さは、必ず残りバッファより大きいので
            // 下の Incomplete 判定で拒否される。
            let len = usize::try_from(length.as_u64()).unwrap_or(usize::MAX);
            if buf[offset..].len() < len {
                return Err(Error::Incomplete {
                    needed: len - buf[offset..].len(),
                });
            }

            let value = &buf[offset..offset + len];
            offset += len;

            match id.as_u64() {
                param_id::ORIGINAL_DESTINATION_CONNECTION_ID => {
                    params.original_destination_connection_id =
                        Some(ConnectionId::from_slice(value)?);
                }
                param_id::MAX_IDLE_TIMEOUT => {
                    params.max_idle_timeout = decode_varint_param(value)?;
                }
                param_id::STATELESS_RESET_TOKEN => {
                    if value.len() != 16 {
                        return Err(Error::InvalidData(format!(
                            "stateless_reset_token length {} != 16",
                            value.len()
                        )));
                    }
                    let mut token = [0u8; 16];
                    token.copy_from_slice(value);
                    params.stateless_reset_token = Some(token);
                }
                param_id::MAX_UDP_PAYLOAD_SIZE => {
                    let v = decode_varint_param(value)?;
                    // RFC 9000 Section 18.2: max_udp_payload_size の下限は 1200。
                    // 1200 未満は invalid として TRANSPORT_PARAMETER_ERROR で閉じる。
                    // 上限 65,527 を超える値は decode では拒否しない。上限はこの
                    // パラメータを受信した側が送信サイズへ反映する際
                    // (`apply_peer_max_udp_payload_size`) に clamp する。
                    if v < 1200 {
                        return Err(Error::Protocol {
                            code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                            reason: format!("max_udp_payload_size {v} is below 1200"),
                        });
                    }
                    params.max_udp_payload_size = v;
                }
                param_id::INITIAL_MAX_DATA => {
                    params.initial_max_data = decode_varint_param(value)?;
                }
                param_id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    params.initial_max_stream_data_bidi_local = decode_varint_param(value)?;
                }
                param_id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    params.initial_max_stream_data_bidi_remote = decode_varint_param(value)?;
                }
                param_id::INITIAL_MAX_STREAM_DATA_UNI => {
                    params.initial_max_stream_data_uni = decode_varint_param(value)?;
                }
                param_id::INITIAL_MAX_STREAMS_BIDI => {
                    let v = decode_varint_param(value)?;
                    // RFC 9000 Section 4.6: max_streams の値が 2^60 を超えると、
                    // 表現できないストリーム ID を許すことになるため
                    // TRANSPORT_PARAMETER_ERROR で接続を閉じる (MUST)。
                    if v > (1u64 << 60) {
                        return Err(Error::Protocol {
                            code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                            reason: format!("initial_max_streams_bidi {v} exceeds 2^60"),
                        });
                    }
                    params.initial_max_streams_bidi = v;
                }
                param_id::INITIAL_MAX_STREAMS_UNI => {
                    let v = decode_varint_param(value)?;
                    // RFC 9000 Section 4.6: initial_max_streams_bidi と同じく
                    // 2^60 を超える値は TRANSPORT_PARAMETER_ERROR (MUST)。
                    if v > (1u64 << 60) {
                        return Err(Error::Protocol {
                            code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                            reason: format!("initial_max_streams_uni {v} exceeds 2^60"),
                        });
                    }
                    params.initial_max_streams_uni = v;
                }
                param_id::ACK_DELAY_EXPONENT => {
                    let v = decode_varint_param(value)?;
                    // RFC 9000 Section 18.2: ack_delay_exponent の有効範囲は 0-20。
                    // 20 を超える値は invalid として TRANSPORT_PARAMETER_ERROR で閉じる。
                    if v > 20 {
                        return Err(Error::Protocol {
                            code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                            reason: format!("ack_delay_exponent {v} exceeds 20"),
                        });
                    }
                    params.ack_delay_exponent = v;
                }
                param_id::MAX_ACK_DELAY => {
                    let v = decode_varint_param(value)?;
                    // RFC 9000 Section 18.2: max_ack_delay の有効範囲は 2^14 未満。
                    // 2^14 以上の値は invalid として TRANSPORT_PARAMETER_ERROR で閉じる。
                    if v >= (1u64 << 14) {
                        return Err(Error::Protocol {
                            code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                            reason: format!("max_ack_delay {v} reaches 2^14"),
                        });
                    }
                    params.max_ack_delay = v;
                }
                param_id::DISABLE_ACTIVE_MIGRATION => {
                    if !value.is_empty() {
                        return Err(Error::InvalidData(
                            "disable_active_migration must have zero length".to_string(),
                        ));
                    }
                    params.disable_active_migration = true;
                }
                param_id::PREFERRED_ADDRESS => {
                    params.preferred_address = Some(decode_preferred_address(value)?);
                }
                param_id::ACTIVE_CONNECTION_ID_LIMIT => {
                    let v = decode_varint_param(value)?;
                    // RFC 9000 Section 18.2: active_connection_id_limit は 2 以上でなければならない (MUST)。
                    if v < 2 {
                        return Err(Error::Protocol {
                            code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                            reason: format!("active_connection_id_limit {v} is below 2"),
                        });
                    }
                    params.active_connection_id_limit = v;
                }
                param_id::INITIAL_SOURCE_CONNECTION_ID => {
                    params.initial_source_connection_id = Some(ConnectionId::from_slice(value)?);
                }
                param_id::RETRY_SOURCE_CONNECTION_ID => {
                    params.retry_source_connection_id = Some(ConnectionId::from_slice(value)?);
                }
                param_id::MAX_DATAGRAM_FRAME_SIZE => {
                    params.max_datagram_frame_size = Some(decode_varint_param(value)?);
                }
                param_id::RESET_STREAM_AT => {
                    // draft-ietf-quic-reliable-stream-reset-11 Section 3:
                    // reset_stream_at は空値で送信し、非空の値を受信した場合は
                    // TRANSPORT_PARAMETER_ERROR で接続を閉じる (MUST)
                    if !value.is_empty() {
                        return Err(Error::Protocol {
                            code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                            reason: "reset_stream_at must have zero length".to_string(),
                        });
                    }
                    params.reset_stream_at = true;
                }
                param_id::INITIAL_MAX_PATH_ID => {
                    let v = decode_varint_param(value)?;
                    if v > u64::from(u32::MAX) {
                        return Err(Error::Protocol {
                            code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                            reason: format!("initial_max_path_id value {v} exceeds 2^32-1"),
                        });
                    }
                    params.initial_max_path_id = Some(v as u32);
                }
                param_id::ADDRESS_DISCOVERY => {
                    let v = decode_varint_param(value)?;
                    // draft-ietf-quic-address-discovery-01 Section 3:
                    // 0 / 1 / 2 以外の値は TRANSPORT_PARAMETER_ERROR (MUST)
                    if v > 2 {
                        return Err(Error::Protocol {
                            code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                            reason: format!("address_discovery value {v} is not 0, 1, or 2"),
                        });
                    }
                    params.address_discovery = Some(v);
                }
                param_id::MIN_ACK_DELAY => {
                    // draft-ietf-quic-ack-frequency-14 Section 3:
                    // min_ack_delay はマイクロ秒単位の可変長整数。
                    params.min_ack_delay = Some(decode_varint_param(value)?);
                }
                param_id::GREASE_QUIC_BIT => {
                    // RFC 9287 Section 3: 空値で送信する。非空の値は
                    // TRANSPORT_PARAMETER_ERROR で接続を閉じる (MUST)。
                    if !value.is_empty() {
                        return Err(Error::Protocol {
                            code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                            reason: "grease_quic_bit must have zero length".to_string(),
                        });
                    }
                    params.grease_quic_bit = true;
                }
                param_id::MAX_RECEIVE_TIMESTAMPS_PER_ACK => {
                    // draft-ietf-quic-receive-ts-03 Section 6:
                    // 受信タイムスタンプの最大数を示す可変長整数。
                    params.max_receive_timestamps_per_ack = Some(decode_varint_param(value)?);
                }
                param_id::RECEIVE_TIMESTAMPS_EXPONENT => {
                    // draft-ietf-quic-receive-ts-03 Section 6:
                    // 形式の検証だけを行い、20 を超えるかどうかの範囲検査は
                    // 全パラメータの解析後に行う。max_receive_timestamps_per_ack が
                    // 未送信または 0 の場合は拡張が無効であり、指数は無視する。
                    params.receive_timestamps_exponent = Some(decode_varint_param(value)?);
                }
                param_id::VERSION_INFORMATION => {
                    // RFC 9368 Section 3: Chosen Version + Available Versions。
                    // 構造の不正はここで TRANSPORT_PARAMETER_ERROR として弾き、
                    // 接続バージョンとの整合検証は transport 層で行う。
                    params.version_information = Some(VersionInformation::decode(value)?);
                }
                _ => {
                    // 未知のパラメータは無視する (RFC 9000 Section 7.4.2)
                }
            }
        }

        // draft-ietf-quic-receive-ts-03 Section 6:
        // max_receive_timestamps_per_ack が未送信または 0 の場合、
        // receive_timestamps_exponent は無視する。同節は 20 を超える値を
        // invalid とするが、拡張が無効な場合は値を使用しないため範囲検査を
        // 省略する。範囲検査は拡張が有効な場合だけ行い、パラメータの出現順に
        // 依存させない。
        if params.max_receive_timestamps_per_ack.unwrap_or(0) == 0 {
            params.receive_timestamps_exponent = None;
        } else if let Some(exponent) = params.receive_timestamps_exponent
            && exponent > 20
        {
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                reason: format!("receive_timestamps_exponent {exponent} exceeds 20"),
            });
        }

        // draft-ietf-quic-ack-frequency-14 Section 3:
        // min_ack_delay はマイクロ秒、max_ack_delay はミリ秒で表現される。
        // min_ack_delay が max_ack_delay を超える場合は
        // TRANSPORT_PARAMETER_ERROR で接続を閉じる (MUST)。
        if let Some(min_ack_delay_us) = params.min_ack_delay
            && min_ack_delay_us > params.max_ack_delay.saturating_mul(1000)
        {
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                reason: format!(
                    "min_ack_delay {min_ack_delay_us}us exceeds max_ack_delay {}ms",
                    params.max_ack_delay
                ),
            });
        }

        Ok(params)
    }

    /// ローカル設定として送信するトランスポートパラメータを検証する
    ///
    /// ピアから受信する値の検証 (`decode`) とは異なり、こちらはアプリケーションが
    /// 設定した値を送信前に検証する。不正な値はエンコード時の panic や
    /// プロトコル違反の原因になるため、接続開始時にエラーとして返す。
    ///
    /// - RFC 9000 Section 18.2: `max_ack_delay` は 2^14 ミリ秒未満
    /// - RFC 9000 Section 18.2: `ack_delay_exponent` は 20 以下
    /// - RFC 9000 Section 18.2: `max_udp_payload_size` は 1200 以上
    /// - RFC 9000 Section 18.2: `active_connection_id_limit` は 2 以上
    /// - draft-ietf-quic-ack-frequency-14 Section 3:
    ///   `min_ack_delay` (マイクロ秒) は `max_ack_delay` (ミリ秒) 以下
    /// - すべての可変長整数パラメータが varint の範囲 (2^62-1) 以下
    pub fn validate_local(&self) -> Result<(), Error> {
        if self.max_ack_delay >= 16_384 {
            return Err(Error::InvalidData(format!(
                "max_ack_delay {}ms must be below 2^14 ms",
                self.max_ack_delay
            )));
        }
        if self.ack_delay_exponent > 20 {
            return Err(Error::InvalidData(format!(
                "ack_delay_exponent {} must be 20 or less",
                self.ack_delay_exponent
            )));
        }
        if self.max_udp_payload_size < 1200 {
            return Err(Error::InvalidData(format!(
                "max_udp_payload_size {} must be at least 1200",
                self.max_udp_payload_size
            )));
        }
        if self.active_connection_id_limit < 2 {
            return Err(Error::InvalidData(format!(
                "active_connection_id_limit {} must be at least 2",
                self.active_connection_id_limit
            )));
        }
        // draft-ietf-quic-receive-ts-03 Section 6:
        // receive_timestamps_exponent は 20 以下でなければならない。
        if let Some(receive_timestamps_exponent) = self.receive_timestamps_exponent
            && receive_timestamps_exponent > 20
        {
            return Err(Error::InvalidData(format!(
                "receive_timestamps_exponent {receive_timestamps_exponent} must be 20 or less"
            )));
        }
        // draft-ietf-quic-address-discovery-01 Section 3:
        // address_discovery は 0 / 1 / 2 のいずれかでなければならない。
        // decode では検証しているが、ローカル設定も送信前に検証する。
        if let Some(address_discovery) = self.address_discovery
            && address_discovery > 2
        {
            return Err(Error::InvalidData(format!(
                "address_discovery {address_discovery} must be 0, 1, or 2"
            )));
        }
        // 実用的な上限を設ける。varint の最大値 (2^62-1) をそのまま許可すると、
        // ウィンドウ前進の加算が varint 範囲を超えて panic したり、ピアが
        // 大量のストリーム・パス・CID を作成してメモリを枯渇させたりする。
        const MAX_CONFIG_DATA: u64 = 1 << 30;
        const MAX_CONFIG_STREAMS: u64 = 100_000;
        const MAX_CONFIG_CIDS: u64 = 64;
        // RFC 9000 Section 18.2 の最大 UDP ペイロード。MTU の上限と共有する。
        let max_udp_payload = u64::from(crate::path::mtu::MAX_UDP_PAYLOAD);
        for (name, value) in [
            ("initial_max_data", self.initial_max_data),
            (
                "initial_max_stream_data_bidi_local",
                self.initial_max_stream_data_bidi_local,
            ),
            (
                "initial_max_stream_data_bidi_remote",
                self.initial_max_stream_data_bidi_remote,
            ),
            (
                "initial_max_stream_data_uni",
                self.initial_max_stream_data_uni,
            ),
        ] {
            if value > MAX_CONFIG_DATA {
                return Err(Error::InvalidData(format!(
                    "{name} {value} exceeds the practical maximum {MAX_CONFIG_DATA}"
                )));
            }
        }
        for (name, value) in [
            ("initial_max_streams_bidi", self.initial_max_streams_bidi),
            ("initial_max_streams_uni", self.initial_max_streams_uni),
        ] {
            if value > MAX_CONFIG_STREAMS {
                return Err(Error::InvalidData(format!(
                    "{name} {value} exceeds the practical maximum {MAX_CONFIG_STREAMS}"
                )));
            }
        }
        if let Some(max_path_id) = self.initial_max_path_id
            && max_path_id > MAX_PATH_ID
        {
            return Err(Error::InvalidData(format!(
                "initial_max_path_id {max_path_id} exceeds the practical maximum {MAX_PATH_ID}"
            )));
        }
        if self.active_connection_id_limit > MAX_CONFIG_CIDS {
            return Err(Error::InvalidData(format!(
                "active_connection_id_limit {} exceeds the practical maximum {MAX_CONFIG_CIDS}",
                self.active_connection_id_limit
            )));
        }
        if self.max_udp_payload_size > max_udp_payload {
            return Err(Error::InvalidData(format!(
                "max_udp_payload_size {} exceeds the protocol maximum {max_udp_payload}",
                self.max_udp_payload_size
            )));
        }
        // draft-ietf-quic-ack-frequency-14 Section 3:
        // min_ack_delay はマイクロ秒、max_ack_delay はミリ秒。
        // min_ack_delay が max_ack_delay を超えてはならない (MUST NOT).
        if let Some(min_ack_delay_us) = self.min_ack_delay
            && min_ack_delay_us > self.max_ack_delay.saturating_mul(1000)
        {
            return Err(Error::InvalidData(format!(
                "min_ack_delay {min_ack_delay_us}us exceeds max_ack_delay {}ms",
                self.max_ack_delay
            )));
        }
        let varint_params = [
            ("max_idle_timeout", self.max_idle_timeout),
            ("max_udp_payload_size", self.max_udp_payload_size),
            ("initial_max_data", self.initial_max_data),
            (
                "initial_max_stream_data_bidi_local",
                self.initial_max_stream_data_bidi_local,
            ),
            (
                "initial_max_stream_data_bidi_remote",
                self.initial_max_stream_data_bidi_remote,
            ),
            (
                "initial_max_stream_data_uni",
                self.initial_max_stream_data_uni,
            ),
            ("initial_max_streams_bidi", self.initial_max_streams_bidi),
            ("initial_max_streams_uni", self.initial_max_streams_uni),
            ("ack_delay_exponent", self.ack_delay_exponent),
            ("max_ack_delay", self.max_ack_delay),
            (
                "active_connection_id_limit",
                self.active_connection_id_limit,
            ),
        ];
        for (name, value) in varint_params {
            if value > crate::varint::MAX_VALUE {
                return Err(Error::InvalidData(format!(
                    "{name} {value} exceeds the varint maximum {}",
                    crate::varint::MAX_VALUE
                )));
            }
        }
        // RFC 9368 Section 3 / Section 4: Chosen Version と Available Versions の
        // 0 は不正値。クライアントは Chosen Version を Available Versions に
        // 含めなければならないが、送信方向の種別 (クライアント / サーバー) を
        // TransportParams 単体では知らないため、ここでは最小限の検査に留め、
        // 方向別の検証は `ConnectionConfig::apply_version_information` で行う。
        if let Some(ref version_information) = self.version_information {
            if version_information.chosen_version == 0 {
                return Err(Error::InvalidData(
                    "version_information chosen version must not be zero".to_string(),
                ));
            }
            if version_information.available_versions.contains(&0) {
                return Err(Error::InvalidData(
                    "version_information available version must not be zero".to_string(),
                ));
            }
        }
        for (name, value) in [
            ("max_datagram_frame_size", self.max_datagram_frame_size),
            ("address_discovery", self.address_discovery),
            ("min_ack_delay", self.min_ack_delay),
            (
                "max_receive_timestamps_per_ack",
                self.max_receive_timestamps_per_ack,
            ),
            (
                "receive_timestamps_exponent",
                self.receive_timestamps_exponent,
            ),
        ] {
            if let Some(value) = value
                && value > crate::varint::MAX_VALUE
            {
                return Err(Error::InvalidData(format!(
                    "{name} {value} exceeds the varint maximum {}",
                    crate::varint::MAX_VALUE
                )));
            }
        }
        Ok(())
    }

    /// トランスポートパラメータをエンコードする
    pub fn encode(&self, buf: &mut Vec<u8>) {
        if let Some(ref cid) = self.original_destination_connection_id {
            encode_cid_param(buf, param_id::ORIGINAL_DESTINATION_CONNECTION_ID, cid);
        }
        if self.max_idle_timeout != 0 {
            encode_varint_param(buf, param_id::MAX_IDLE_TIMEOUT, self.max_idle_timeout);
        }
        if let Some(token) = &self.stateless_reset_token {
            encode_bytes_param(buf, param_id::STATELESS_RESET_TOKEN, token);
        }
        // 既定値 (最大 UDP ペイロード) と同じ場合は送信を省略する
        // (RFC 9000 Section 18.2 の既定値)。
        if self.max_udp_payload_size != u64::from(crate::path::mtu::MAX_UDP_PAYLOAD) {
            encode_varint_param(
                buf,
                param_id::MAX_UDP_PAYLOAD_SIZE,
                self.max_udp_payload_size,
            );
        }
        if self.initial_max_data != 0 {
            encode_varint_param(buf, param_id::INITIAL_MAX_DATA, self.initial_max_data);
        }
        if self.initial_max_stream_data_bidi_local != 0 {
            encode_varint_param(
                buf,
                param_id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                self.initial_max_stream_data_bidi_local,
            );
        }
        if self.initial_max_stream_data_bidi_remote != 0 {
            encode_varint_param(
                buf,
                param_id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                self.initial_max_stream_data_bidi_remote,
            );
        }
        if self.initial_max_stream_data_uni != 0 {
            encode_varint_param(
                buf,
                param_id::INITIAL_MAX_STREAM_DATA_UNI,
                self.initial_max_stream_data_uni,
            );
        }
        if self.initial_max_streams_bidi != 0 {
            encode_varint_param(
                buf,
                param_id::INITIAL_MAX_STREAMS_BIDI,
                self.initial_max_streams_bidi,
            );
        }
        if self.initial_max_streams_uni != 0 {
            encode_varint_param(
                buf,
                param_id::INITIAL_MAX_STREAMS_UNI,
                self.initial_max_streams_uni,
            );
        }
        if self.ack_delay_exponent != 3 {
            encode_varint_param(buf, param_id::ACK_DELAY_EXPONENT, self.ack_delay_exponent);
        }
        if self.max_ack_delay != 25 {
            encode_varint_param(buf, param_id::MAX_ACK_DELAY, self.max_ack_delay);
        }
        if self.disable_active_migration {
            encode_empty_param(buf, param_id::DISABLE_ACTIVE_MIGRATION);
        }
        if let Some(ref preferred) = self.preferred_address {
            encode_preferred_address(buf, preferred);
        }
        if self.active_connection_id_limit != 2 {
            encode_varint_param(
                buf,
                param_id::ACTIVE_CONNECTION_ID_LIMIT,
                self.active_connection_id_limit,
            );
        }
        if let Some(ref cid) = self.initial_source_connection_id {
            encode_cid_param(buf, param_id::INITIAL_SOURCE_CONNECTION_ID, cid);
        }
        if let Some(ref cid) = self.retry_source_connection_id {
            encode_cid_param(buf, param_id::RETRY_SOURCE_CONNECTION_ID, cid);
        }
        if let Some(max_datagram_frame_size) = self.max_datagram_frame_size {
            encode_varint_param(
                buf,
                param_id::MAX_DATAGRAM_FRAME_SIZE,
                max_datagram_frame_size,
            );
        }
        if self.reset_stream_at {
            encode_empty_param(buf, param_id::RESET_STREAM_AT);
        }
        if let Some(max_path_id) = self.initial_max_path_id {
            encode_varint_param(buf, param_id::INITIAL_MAX_PATH_ID, u64::from(max_path_id));
        }
        if let Some(address_discovery) = self.address_discovery {
            encode_varint_param(buf, param_id::ADDRESS_DISCOVERY, address_discovery);
        }
        if let Some(min_ack_delay) = self.min_ack_delay {
            encode_varint_param(buf, param_id::MIN_ACK_DELAY, min_ack_delay);
        }
        // draft-ietf-quic-receive-ts-03 Section 6: 0 は未送信と同じ意味だが、
        // エンコーダの往復一貫性のため明示的に指定された値はそのまま送る。
        if let Some(max_receive_timestamps_per_ack) = self.max_receive_timestamps_per_ack {
            encode_varint_param(
                buf,
                param_id::MAX_RECEIVE_TIMESTAMPS_PER_ACK,
                max_receive_timestamps_per_ack,
            );
        }
        // draft-ietf-quic-receive-ts-03 Section 6: exponent は
        // max_receive_timestamps_per_ack が有効な場合のみ意味を持つ。
        if self.max_receive_timestamps_per_ack.unwrap_or(0) > 0
            && let Some(receive_timestamps_exponent) = self.receive_timestamps_exponent
        {
            encode_varint_param(
                buf,
                param_id::RECEIVE_TIMESTAMPS_EXPONENT,
                receive_timestamps_exponent,
            );
        }
        if let Some(ref version_information) = self.version_information {
            encode_bytes_param(
                buf,
                param_id::VERSION_INFORMATION,
                &version_information.encode(),
            );
        }
        if self.grease_quic_bit {
            encode_empty_param(buf, param_id::GREASE_QUIC_BIT);
        }
    }
}

/// VarInt パラメータ値をデコードする
///
/// RFC 9000 Section 18: 整数値を取るトランスポートパラメータの値は
/// 可変長整数 1 個ちょうどでなければならない。空の値や、可変長整数の後に
/// 余剰バイトが続く値は不正値として拒否する。可変長整数の非最短エンコードは
/// 許容される (RFC 9000 Section 16)。
fn decode_varint_param(value: &[u8]) -> Result<u64, Error> {
    if value.is_empty() {
        return Err(Error::Protocol {
            code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            reason: "integer transport parameter has zero-length value".to_string(),
        });
    }
    let (v, consumed) = VarInt::decode(value)?;
    if consumed != value.len() {
        return Err(Error::Protocol {
            code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            reason: format!(
                "integer transport parameter has {} trailing bytes",
                value.len() - consumed
            ),
        });
    }
    Ok(v.as_u64())
}

/// VarInt パラメータをエンコードする
fn encode_varint_param(buf: &mut Vec<u8>, id: u64, value: u64) {
    // パラメータ ID と値は定数 / 検証済みのものだけが渡される想定。
    // `TransportParams::validate_local` を通さない直接利用でも panic しないよう、
    // varint の範囲外はエンコードしない (防御的)。
    let (Ok(id), Ok(value)) = (VarInt::try_from(id), VarInt::try_from(value)) else {
        return;
    };
    id.encode_to_vec(buf);
    let length = match VarInt::try_from(value.encoded_size() as u64) {
        Ok(length) => length,
        Err(_) => return,
    };
    length.encode_to_vec(buf);
    value.encode_to_vec(buf);
}

/// バイト列パラメータをエンコードする
fn encode_bytes_param(buf: &mut Vec<u8>, id: u64, value: &[u8]) {
    VarInt::try_from(id)
        .expect("transport parameter ID fits in 62-bit varint")
        .encode_to_vec(buf);
    VarInt::try_from(value.len() as u64)
        .expect("transport parameter value length fits in 62-bit varint")
        .encode_to_vec(buf);
    buf.extend_from_slice(value);
}

/// Connection ID パラメータをエンコードする
fn encode_cid_param(buf: &mut Vec<u8>, id: u64, cid: &ConnectionId) {
    encode_bytes_param(buf, id, cid.as_bytes());
}

/// 空パラメータをエンコードする
fn encode_empty_param(buf: &mut Vec<u8>, id: u64) {
    VarInt::try_from(id)
        .expect("transport parameter ID fits in 62-bit varint")
        .encode_to_vec(buf);
    VarInt::from(0u8).encode_to_vec(buf);
}

/// preferred_address をエンコードする (RFC 9000 Section 18.2)
///
/// フォーマット:
///   IPv4 Address (4) + IPv4 Port (2) + IPv6 Address (16) + IPv6 Port (2)
///   + CID Length (1) + CID (variable) + Stateless Reset Token (16)
fn encode_preferred_address(buf: &mut Vec<u8>, preferred: &PreferredAddress) {
    let mut value = Vec::new();
    value.extend_from_slice(&preferred.ipv4_address);
    value.extend_from_slice(&preferred.ipv4_port.to_be_bytes());
    value.extend_from_slice(&preferred.ipv6_address);
    value.extend_from_slice(&preferred.ipv6_port.to_be_bytes());
    value.push(preferred.connection_id.len() as u8);
    value.extend_from_slice(preferred.connection_id.as_bytes());
    value.extend_from_slice(&preferred.stateless_reset_token);
    encode_bytes_param(buf, param_id::PREFERRED_ADDRESS, &value);
}

/// preferred_address をデコードする (RFC 9000 Section 18.2)
///
/// フォーマット:
///   IPv4 Address (4) + IPv4 Port (2) + IPv6 Address (16) + IPv6 Port (2)
///   + CID Length (1) + CID (variable) + Stateless Reset Token (16)
fn decode_preferred_address(value: &[u8]) -> Result<PreferredAddress, Error> {
    // 最小サイズ: 4 + 2 + 16 + 2 + 1 + 0 + 16 = 41 バイト
    if value.len() < 41 {
        return Err(Error::InvalidData(format!(
            "preferred_address too short: {} bytes",
            value.len()
        )));
    }

    let mut pos = 0;

    let mut ipv4_address = [0u8; 4];
    ipv4_address.copy_from_slice(&value[pos..pos + 4]);
    pos += 4;

    let ipv4_port = u16::from_be_bytes([value[pos], value[pos + 1]]);
    pos += 2;
    // RFC 9000 Section 18.2: port 0 は未使用を意味する。非ゼロ port と
    // unspecified アドレスの組み合わせは、接続先として解釈できない不正値である。
    if ipv4_port != 0 && core::net::Ipv4Addr::from(ipv4_address).is_unspecified() {
        return Err(Error::Protocol {
            code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            reason: "preferred_address IPv4 port is non-zero but address is unspecified".into(),
        });
    }

    let mut ipv6_address = [0u8; 16];
    ipv6_address.copy_from_slice(&value[pos..pos + 16]);
    pos += 16;

    let ipv6_port = u16::from_be_bytes([value[pos], value[pos + 1]]);
    pos += 2;
    // IPv6 側も同じ規則で検証する。
    if ipv6_port != 0 && core::net::Ipv6Addr::from(ipv6_address).is_unspecified() {
        return Err(Error::Protocol {
            code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            reason: "preferred_address IPv6 port is non-zero but address is unspecified".into(),
        });
    }

    let cid_len = value[pos] as usize;
    pos += 1;

    // CID の長さは 0 であってはならない (RFC 9000 Section 18.2)
    if cid_len == 0 {
        return Err(Error::Protocol {
            code: crate::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            reason: "preferred_address connection ID must not be zero-length".into(),
        });
    }

    if value.len() < pos + cid_len + 16 {
        return Err(Error::InvalidData(format!(
            "preferred_address truncated: need {} more bytes",
            (pos + cid_len + 16) - value.len()
        )));
    }
    // RFC 9000 Section 18.2: preferred_address の値は図 22 のフィールドを
    // 過不足なく含まなければならない。末尾の余剰バイトは不正値として拒否する。
    if value.len() != pos + cid_len + 16 {
        return Err(Error::InvalidData(format!(
            "preferred_address has {} trailing bytes",
            value.len() - (pos + cid_len + 16)
        )));
    }

    let connection_id = ConnectionId::from_slice(&value[pos..pos + cid_len])?;
    pos += cid_len;

    let mut stateless_reset_token = [0u8; 16];
    stateless_reset_token.copy_from_slice(&value[pos..pos + 16]);

    Ok(PreferredAddress {
        ipv4_address,
        ipv4_port,
        ipv6_address,
        ipv6_port,
        connection_id,
        stateless_reset_token,
    })
}

#[cfg(test)]
mod tests;
