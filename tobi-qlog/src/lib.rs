// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! qlog 構造化ロギング (draft-ietf-quic-qlog-main-schema-14)
//!
//! QUIC パケットの送受信、接続状態遷移、ロス検出等のイベントを
//! JSON-SEQ (RFC 7464) 形式で出力するための構造化データ型と
//! `QlogWriter` トレイトを提供する。
//!
//! Sans I/O 原則を維持: `Connection` は `QlogWriter` トレイトを通じて
//! イベントを通知し、実際の I/O は外部の writer 実装が行う。
//! JSON-SEQ writer の参照実装は `tobi_quic::qlog::JsonSeqQlogWriter` を参照。

#![no_std]
// 自前コードに unsafe を入れない。
#![forbid(unsafe_code)]
// 本番コードでは panic しやすい unwrap を禁止する。テストコードは対象外。
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{self, Write as _};

use nojson::{DisplayJson, JsonFormatter};

use tobi_core::connection_id::ConnectionId;
use tobi_core::frame::Frame;

// --- qlog データ型 ---

/// パケットタイプの qlog 表現
#[derive(Debug, Clone, Copy)]
pub enum PacketType {
    Initial,
    Handshake,
    ZeroRtt,
    OneRtt,
    Retry,
    VersionNegotiation,
    Unknown,
}

impl PacketType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Handshake => "handshake",
            Self::ZeroRtt => "0RTT",
            Self::OneRtt => "1RTT",
            Self::Retry => "retry",
            Self::VersionNegotiation => "version_negotiation",
            Self::Unknown => "unknown",
        }
    }
}

impl DisplayJson for PacketType {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> fmt::Result {
        f.string(self.as_str())
    }
}

/// パケットヘッダの qlog 表現
#[derive(Debug, Clone)]
pub struct PacketHeader {
    pub packet_type: PacketType,
    pub packet_number: u64,
    pub dcid: String,
    pub scid: Option<String>,
    pub version: Option<String>,
    pub length: Option<usize>,
}

impl DisplayJson for PacketHeader {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> fmt::Result {
        f.object(|f| {
            f.member("packet_type", self.packet_type)?;
            f.member("packet_number", self.packet_number)?;
            f.member("dcid", &self.dcid)?;
            if let Some(ref scid) = self.scid {
                f.member("scid", scid)?;
            }
            if let Some(ref version) = self.version {
                f.member("version", version)?;
            }
            if let Some(length) = self.length {
                f.member("length", length)?;
            }
            Ok(())
        })
    }
}

/// フレームの qlog 表現
#[derive(Debug, Clone)]
pub enum QlogFrame {
    Padding {
        length: usize,
    },
    Ping,
    Ack {
        /// 確認応答したパケット番号の範囲 (最小, 最大)
        acked_ranges: Vec<(u64, u64)>,
        /// ACK Delay (ms)
        ///
        /// qlog-quic-events-13 Section 8.13.3 の `ack_delay` は ms 単位の
        /// float32 である。RFC 9000 Section 19.3 のエンコード値から
        /// [`ack_delay_ms`] で変換した値を保持する。
        ack_delay: f64,
    },
    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },
    ResetStreamAt {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
        reliable_size: u64,
    },
    StopSending {
        stream_id: u64,
        error_code: u64,
    },
    Crypto {
        offset: u64,
        length: usize,
    },
    NewToken {
        length: usize,
    },
    Stream {
        stream_id: u64,
        offset: u64,
        length: usize,
        fin: bool,
    },
    MaxData {
        maximum: u64,
    },
    MaxStreamData {
        stream_id: u64,
        maximum: u64,
    },
    MaxStreams {
        stream_type: &'static str,
        maximum: u64,
    },
    DataBlocked {
        limit: u64,
    },
    StreamDataBlocked {
        stream_id: u64,
        limit: u64,
    },
    StreamsBlocked {
        stream_type: &'static str,
        limit: u64,
    },
    NewConnectionId {
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: String,
    },
    RetireConnectionId {
        sequence_number: u64,
    },
    PathChallenge {
        data: String,
    },
    PathResponse {
        data: String,
    },
    ConnectionClose {
        error_code: u64,
        reason: String,
    },
    HandshakeDone,
    // DATAGRAM 拡張 (RFC 9221)
    Datagram {
        length: usize,
    },
    // Multipath 拡張
    PathAck {
        path_id: u32,
        /// 確認応答したパケット番号の範囲 (最小, 最大)
        acked_ranges: Vec<(u64, u64)>,
        /// ACK Delay (ms)
        ///
        /// qlog-quic-events-13 Section 8.13.3 の `ack_delay` は ms 単位の
        /// float32 である。RFC 9000 Section 19.3 のエンコード値から
        /// [`ack_delay_ms`] で変換した値を保持する。
        ack_delay: f64,
    },
    PathAbandon {
        path_id: u32,
        error_code: u64,
    },
    PathStatus {
        path_id: u32,
        status: &'static str,
    },
    PathNewConnectionId {
        path_id: u32,
        sequence_number: u64,
        connection_id: String,
    },
    PathRetireConnectionId {
        path_id: u32,
        sequence_number: u64,
    },
    MaxPathId {
        maximum: u32,
    },
    PathsBlocked {
        maximum: u32,
    },
    PathCidsBlocked {
        path_id: u32,
        sequence_number: u64,
    },
    Unknown {
        frame_type: u64,
    },
}

impl DisplayJson for QlogFrame {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> fmt::Result {
        f.object(|f| match self {
            Self::Padding { length } => {
                f.member("frame_type", "padding")?;
                f.member("length", *length)
            }
            Self::Ping => f.member("frame_type", "ping"),
            Self::Ack {
                acked_ranges,
                ack_delay,
            } => {
                f.member("frame_type", "ack")?;
                f.member("ack_delay", *ack_delay)?;
                // qlog-quic-events-13 Section 8.13.3 の acked_ranges は
                // [+ AckRange] であり空配列を許さない。受信した ACK と 1-RTT の
                // 送信 ACK はどちらもパケット payload のデコード結果から実レンジを
                // 得るため通常は必ず出力されるが、レンジを持たない ACK を
                // 渡された場合もスキーマに反する空配列を出さず、任意フィールド
                // として省略する。
                if !acked_ranges.is_empty() {
                    f.member("acked_ranges", AckedRanges(acked_ranges))?;
                }
                Ok(())
            }
            Self::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                f.member("frame_type", "reset_stream")?;
                f.member("stream_id", *stream_id)?;
                f.member("error_code", *error_code)?;
                f.member("final_size", *final_size)
            }
            Self::ResetStreamAt {
                stream_id,
                error_code,
                final_size,
                reliable_size,
            } => {
                f.member("frame_type", "reset_stream_at")?;
                f.member("stream_id", *stream_id)?;
                f.member("error_code", *error_code)?;
                f.member("final_size", *final_size)?;
                f.member("reliable_size", *reliable_size)
            }
            Self::StopSending {
                stream_id,
                error_code,
            } => {
                f.member("frame_type", "stop_sending")?;
                f.member("stream_id", *stream_id)?;
                f.member("error_code", *error_code)
            }
            Self::Crypto { offset, length } => {
                f.member("frame_type", "crypto")?;
                f.member("offset", *offset)?;
                f.member("length", *length)
            }
            Self::NewToken { length } => {
                f.member("frame_type", "new_token")?;
                f.member("length", *length)
            }
            Self::Stream {
                stream_id,
                offset,
                length,
                fin,
            } => {
                f.member("frame_type", "stream")?;
                f.member("stream_id", *stream_id)?;
                f.member("offset", *offset)?;
                f.member("length", *length)?;
                f.member("fin", *fin)
            }
            Self::MaxData { maximum } => {
                f.member("frame_type", "max_data")?;
                f.member("maximum", *maximum)
            }
            Self::MaxStreamData { stream_id, maximum } => {
                f.member("frame_type", "max_stream_data")?;
                f.member("stream_id", *stream_id)?;
                f.member("maximum", *maximum)
            }
            Self::MaxStreams {
                stream_type,
                maximum,
            } => {
                f.member("frame_type", "max_streams")?;
                f.member("stream_type", *stream_type)?;
                f.member("maximum", *maximum)
            }
            Self::DataBlocked { limit } => {
                f.member("frame_type", "data_blocked")?;
                f.member("limit", *limit)
            }
            Self::StreamDataBlocked { stream_id, limit } => {
                f.member("frame_type", "stream_data_blocked")?;
                f.member("stream_id", *stream_id)?;
                f.member("limit", *limit)
            }
            Self::StreamsBlocked { stream_type, limit } => {
                f.member("frame_type", "streams_blocked")?;
                f.member("stream_type", *stream_type)?;
                f.member("limit", *limit)
            }
            Self::NewConnectionId {
                sequence_number,
                retire_prior_to,
                connection_id,
            } => {
                f.member("frame_type", "new_connection_id")?;
                f.member("sequence_number", *sequence_number)?;
                f.member("retire_prior_to", *retire_prior_to)?;
                f.member("connection_id", connection_id)
            }
            Self::RetireConnectionId { sequence_number } => {
                f.member("frame_type", "retire_connection_id")?;
                f.member("sequence_number", *sequence_number)
            }
            Self::PathChallenge { data } => {
                f.member("frame_type", "path_challenge")?;
                f.member("data", data)
            }
            Self::PathResponse { data } => {
                f.member("frame_type", "path_response")?;
                f.member("data", data)
            }
            Self::ConnectionClose { error_code, reason } => {
                f.member("frame_type", "connection_close")?;
                f.member("error_code", *error_code)?;
                f.member("reason", reason)
            }
            Self::HandshakeDone => f.member("frame_type", "handshake_done"),
            // DATAGRAM 拡張
            Self::Datagram { length } => {
                f.member("frame_type", "datagram")?;
                f.member("length", length)
            }
            // Multipath
            Self::PathAck {
                path_id,
                acked_ranges,
                ack_delay,
            } => {
                f.member("frame_type", "path_ack")?;
                f.member("path_id", *path_id)?;
                f.member("ack_delay", *ack_delay)?;
                // ACK と同じく空の acked_ranges はスキーマ違反になるため省略する。
                if !acked_ranges.is_empty() {
                    f.member("acked_ranges", AckedRanges(acked_ranges))?;
                }
                Ok(())
            }
            Self::PathAbandon {
                path_id,
                error_code,
            } => {
                f.member("frame_type", "path_abandon")?;
                f.member("path_id", *path_id)?;
                f.member("error_code", *error_code)
            }
            Self::PathStatus { path_id, status } => {
                f.member("frame_type", "path_status")?;
                f.member("path_id", *path_id)?;
                f.member("status", *status)
            }
            Self::PathNewConnectionId {
                path_id,
                sequence_number,
                connection_id,
            } => {
                f.member("frame_type", "path_new_connection_id")?;
                f.member("path_id", *path_id)?;
                f.member("sequence_number", *sequence_number)?;
                f.member("connection_id", connection_id)
            }
            Self::PathRetireConnectionId {
                path_id,
                sequence_number,
            } => {
                f.member("frame_type", "path_retire_connection_id")?;
                f.member("path_id", *path_id)?;
                f.member("sequence_number", *sequence_number)
            }
            Self::MaxPathId { maximum } => {
                f.member("frame_type", "max_path_id")?;
                f.member("maximum", *maximum)
            }
            Self::PathsBlocked { maximum } => {
                f.member("frame_type", "paths_blocked")?;
                f.member("maximum", *maximum)
            }
            Self::PathCidsBlocked {
                path_id,
                sequence_number,
            } => {
                f.member("frame_type", "path_cids_blocked")?;
                f.member("path_id", *path_id)?;
                f.member("sequence_number", *sequence_number)
            }
            Self::Unknown { frame_type } => {
                f.member("frame_type", "unknown")?;
                f.member("raw_frame_type", *frame_type)
            }
        })
    }
}

/// ACK レンジの JSON 配列表現
struct AckedRanges<'a>(&'a [(u64, u64)]);

impl DisplayJson for AckedRanges<'_> {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> fmt::Result {
        f.array(|f| {
            for &(start, end) in self.0 {
                f.element(nojson::array(move |f| {
                    f.element(start)?;
                    f.element(end)
                }))?;
            }
            Ok(())
        })
    }
}

/// トランスポートパラメータの qlog 表現
#[derive(Debug, Clone)]
pub struct TransportParametersSet {
    pub max_idle_timeout: u64,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub active_connection_id_limit: u64,
    pub initial_max_path_id: Option<u32>,
}

impl DisplayJson for TransportParametersSet {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> fmt::Result {
        f.object(|f| write_transport_parameter_members(f, self))
    }
}

/// トランスポートパラメータの各フィールドを JSON オブジェクトのメンバーとして書く
///
/// `TransportParametersSet` 単体の出力と `quic:parameters_set` の data への
/// 展開で同じフィールド列を使うため、メンバー書き出しを一元化する。
fn write_transport_parameter_members(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    params: &TransportParametersSet,
) -> fmt::Result {
    f.member("max_idle_timeout", params.max_idle_timeout)?;
    f.member("max_udp_payload_size", params.max_udp_payload_size)?;
    f.member("initial_max_data", params.initial_max_data)?;
    f.member(
        "initial_max_stream_data_bidi_local",
        params.initial_max_stream_data_bidi_local,
    )?;
    f.member(
        "initial_max_stream_data_bidi_remote",
        params.initial_max_stream_data_bidi_remote,
    )?;
    f.member(
        "initial_max_stream_data_uni",
        params.initial_max_stream_data_uni,
    )?;
    f.member("initial_max_streams_bidi", params.initial_max_streams_bidi)?;
    f.member("initial_max_streams_uni", params.initial_max_streams_uni)?;
    f.member(
        "active_connection_id_limit",
        params.active_connection_id_limit,
    )?;
    if let Some(max_path_id) = params.initial_max_path_id {
        f.member("initial_max_path_id", max_path_id)?;
    }
    Ok(())
}

/// `quic:parameters_set` イベントの data 表現
///
/// qlog-quic-events-13 Section 5.3 の `QUICParametersSet` に対応する。
/// `initiator` とトランスポートパラメータを同じ階層に並べる。
/// `owner` / `parameters` のような入れ子は持たない。
#[derive(Debug, Clone)]
pub struct ParametersSet<'a> {
    /// パラメータの設定者
    ///
    /// `"local"` (ローカルが設定した値) または `"remote"` (ピアが設定した値)。
    /// 同じイベントに両側の設定を混在させてはならない
    /// (qlog-quic-events-13 Section 5.3)。
    pub initiator: &'a str,
    /// トランスポートパラメータ
    pub transport_parameters: &'a TransportParametersSet,
}

impl DisplayJson for ParametersSet<'_> {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> fmt::Result {
        f.object(|f| {
            f.member("initiator", self.initiator)?;
            // TransportParametersSet の各フィールドを data のトップレベルへ展開する。
            // フィールドの追加・削除は write_transport_parameter_members 側だけを
            // 変更すればよい。
            write_transport_parameter_members(f, self.transport_parameters)
        })
    }
}

// --- Frame → QlogFrame 変換 ---

/// ConnectionId を hex 文字列に変換する
pub fn cid_to_hex(cid: &ConnectionId) -> String {
    cid.as_bytes()
        .iter()
        .fold(String::with_capacity(cid.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// ACK Delay のエンコード値を ms に変換する
///
/// RFC 9000 Section 19.3 のとおり、ACK Delay フィールドの値は
/// ACK を送信した側の `ack_delay_exponent` で
/// `raw * 2^ack_delay_exponent` マイクロ秒に復元する。
/// qlog-quic-events-13 Section 8.13.3 の `ack_delay` は ms 単位の
/// float32 であるため、1000 で割って ms にする。
///
/// `ack_delay_exponent` の有効範囲は RFC 9000 Section 18.2 の 20 以下である。
/// qlog 出力は接続を失敗させない観測処理のため、範囲外の値は 20 として
/// 計算する (シフト量を制限し、過大な値でも panic しない)。
pub fn ack_delay_ms(raw: u64, ack_delay_exponent: u32) -> f64 {
    // 2^20 は u64 に収まる。no_std では f64::powi が使えないため整数シフトで
    // 2 のべき乗を作り、f64 へ変換する。
    let scale = 1u64 << ack_delay_exponent.min(20);
    (raw as f64) * (scale as f64) / 1000.0
}

impl QlogFrame {
    /// Frame を QlogFrame に変換する
    ///
    /// `ack_delay_exponent` は ACK / PATH_ACK の ACK Delay を ms に変換する
    /// ための指数である。受信したフレームにはピアの、送信したフレームには
    /// ローカルの `ack_delay_exponent` を渡す
    /// (RFC 9000 Section 19.3 / qlog-quic-events-13 Section 8.13.3)。
    /// ACK / PATH_ACK 以外のフレームでは使わない。
    pub fn from_frame(frame: &Frame, ack_delay_exponent: u32) -> Self {
        match frame {
            Frame::Padding(p) => QlogFrame::Padding { length: p.length },
            Frame::Ping(_) => QlogFrame::Ping,
            Frame::Ack(a) => QlogFrame::Ack {
                acked_ranges: a.expand_ack_ranges(),
                ack_delay: ack_delay_ms(a.ack_delay.as_u64(), ack_delay_exponent),
            },
            Frame::ResetStream(r) => QlogFrame::ResetStream {
                stream_id: r.stream_id.as_u64(),
                error_code: r.application_protocol_error_code.as_u64(),
                final_size: r.final_size.as_u64(),
            },
            Frame::ResetStreamAt(r) => QlogFrame::ResetStreamAt {
                stream_id: r.stream_id.as_u64(),
                error_code: r.application_protocol_error_code.as_u64(),
                final_size: r.final_size.as_u64(),
                reliable_size: r.reliable_size.as_u64(),
            },
            Frame::StopSending(s) => QlogFrame::StopSending {
                stream_id: s.stream_id.as_u64(),
                error_code: s.application_protocol_error_code.as_u64(),
            },
            Frame::Crypto(c) => QlogFrame::Crypto {
                offset: c.offset.as_u64(),
                length: c.data.len(),
            },
            Frame::NewToken(t) => QlogFrame::NewToken {
                length: t.token.len(),
            },
            Frame::Stream(s) => QlogFrame::Stream {
                stream_id: s.stream_id.as_u64(),
                offset: s.offset.as_u64(),
                length: s.data.len(),
                fin: s.fin,
            },
            Frame::MaxData(m) => QlogFrame::MaxData {
                maximum: m.maximum_data.as_u64(),
            },
            Frame::MaxStreamData(m) => QlogFrame::MaxStreamData {
                stream_id: m.stream_id.as_u64(),
                maximum: m.maximum_stream_data.as_u64(),
            },
            Frame::MaxStreams(m) => QlogFrame::MaxStreams {
                stream_type: if m.bidirectional {
                    "bidirectional"
                } else {
                    "unidirectional"
                },
                maximum: m.maximum_streams.as_u64(),
            },
            Frame::DataBlocked(d) => QlogFrame::DataBlocked {
                limit: d.maximum_data.as_u64(),
            },
            Frame::StreamDataBlocked(s) => QlogFrame::StreamDataBlocked {
                stream_id: s.stream_id.as_u64(),
                limit: s.maximum_stream_data.as_u64(),
            },
            Frame::StreamsBlocked(s) => QlogFrame::StreamsBlocked {
                stream_type: if s.bidirectional {
                    "bidirectional"
                } else {
                    "unidirectional"
                },
                limit: s.maximum_streams.as_u64(),
            },
            Frame::NewConnectionId(n) => QlogFrame::NewConnectionId {
                sequence_number: n.sequence_number.as_u64(),
                retire_prior_to: n.retire_prior_to.as_u64(),
                connection_id: cid_to_hex(&n.connection_id),
            },
            Frame::RetireConnectionId(r) => QlogFrame::RetireConnectionId {
                sequence_number: r.sequence_number.as_u64(),
            },
            Frame::PathChallenge(p) => QlogFrame::PathChallenge {
                data: hex::encode(&p.data),
            },
            Frame::PathResponse(p) => QlogFrame::PathResponse {
                data: hex::encode(&p.data),
            },
            Frame::ConnectionClose(c) => QlogFrame::ConnectionClose {
                error_code: c.error_code.as_u64(),
                reason: String::from_utf8_lossy(&c.reason_phrase).into_owned(),
            },
            Frame::HandshakeDone(_) => QlogFrame::HandshakeDone,
            // DATAGRAM 拡張
            Frame::Datagram(d) => QlogFrame::Datagram {
                length: d.data.len(),
            },
            // Multipath
            Frame::PathAck(a) => QlogFrame::PathAck {
                path_id: a.path_id,
                acked_ranges: a.expand_ack_ranges(),
                ack_delay: ack_delay_ms(a.ack_delay.as_u64(), ack_delay_exponent),
            },
            Frame::PathAbandon(a) => QlogFrame::PathAbandon {
                path_id: a.path_id,
                error_code: a.error_code.as_u64(),
            },
            Frame::PathStatusAvailable(s) => QlogFrame::PathStatus {
                path_id: s.path_id,
                status: "available",
            },
            Frame::PathStatusBackup(s) => QlogFrame::PathStatus {
                path_id: s.path_id,
                status: "backup",
            },
            Frame::PathNewConnectionId(n) => QlogFrame::PathNewConnectionId {
                path_id: n.path_id,
                sequence_number: n.sequence_number.as_u64(),
                connection_id: cid_to_hex(&n.connection_id),
            },
            Frame::PathRetireConnectionId(r) => QlogFrame::PathRetireConnectionId {
                path_id: r.path_id,
                sequence_number: r.sequence_number.as_u64(),
            },
            Frame::MaxPathId(m) => QlogFrame::MaxPathId {
                maximum: m.maximum_path_id,
            },
            Frame::PathsBlocked(p) => QlogFrame::PathsBlocked {
                maximum: p.maximum_path_id,
            },
            Frame::PathCidsBlocked(p) => QlogFrame::PathCidsBlocked {
                path_id: p.path_id,
                sequence_number: p.next_sequence_number.as_u64(),
            },
            // qlog スキーマに OBSERVED_ADDRESS の定義が無いため unknown として記録する
            Frame::ObservedAddress(oa) => QlogFrame::Unknown {
                frame_type: if oa.addr.is_ipv6() {
                    tobi_core::frame::frame_type::OBSERVED_ADDRESS_V6
                } else {
                    tobi_core::frame::frame_type::OBSERVED_ADDRESS_V4
                },
            },
            // ACK Frequency 拡張のフレームは qlog-quic-events-13 に対応する
            // イベントが定義されていないため、未知フレームとして記録する。
            Frame::AckFrequency(_) => QlogFrame::Unknown {
                frame_type: tobi_core::frame::frame_type::ACK_FREQUENCY,
            },
            Frame::ImmediateAck(_) => QlogFrame::Unknown {
                frame_type: tobi_core::frame::frame_type::IMMEDIATE_ACK,
            },
            // Receive Timestamps 拡張のフレームも qlog スキーマに対応する
            // イベントが定義されていないため、未知フレームとして記録する。
            Frame::AckReceiveTimestamps(_) => QlogFrame::Unknown {
                frame_type: tobi_core::frame::frame_type::ACK_RECEIVE_TIMESTAMPS,
            },
            Frame::PathAckReceiveTimestamps(_) => QlogFrame::Unknown {
                frame_type: tobi_core::frame::frame_type::PATH_ACK_RECEIVE_TIMESTAMPS,
            },
        }
    }
}

/// QlogFrame のスライスの JSON 配列表現
pub struct QlogFrames<'a>(pub &'a [QlogFrame]);

impl DisplayJson for QlogFrames<'_> {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> fmt::Result {
        f.array(|f| {
            for frame in self.0 {
                f.element(frame)?;
            }
            Ok(())
        })
    }
}

// --- QlogWriter トレイト ---

/// qlog イベントを受け取るトレイト
///
/// Connection はこのトレイトを通じてイベントを通知する。
/// 実際の I/O (ファイル書き込み等) は実装側が行う。
///
/// # 実装上の注意
///
/// tobi-quic の transport はこのトレイトのメソッドを接続処理と同じタスクから
/// 同期的に呼ぶ。実装がブロッキング I/O を行うと、パケット処理とタイマーが
/// 遅延し、PTO やアイドルタイムアウトの判定に影響する。ファイルやパイプへ
/// 書く場合は、バッファリングや別スレッドへの委譲を行うこと。
///
/// また、qlog の失敗で接続処理を失敗させないため、実装は panic してはならない。
/// メソッドは `Result` を返さないため、I/O エラーは実装側で無視する。
///
/// # データの取扱い
///
/// qlog は接続 ID、時刻、パケットサイズ、フレーム内容、トランスポート
/// パラメータなどを含む。draft-ietf-quic-qlog-main-schema-14 Section 14.1 の
/// "Data at risk" に挙げられるように、機密情報としてアクセス制御と保存期間を
/// 定めること。
pub trait QlogWriter: Send {
    /// パケット送信イベント (Core)
    fn on_packet_sent(
        &mut self,
        time_ms: f64,
        header: &PacketHeader,
        frames: &[QlogFrame],
        raw_length: usize,
    );

    /// パケット受信イベント (Core)
    fn on_packet_received(
        &mut self,
        time_ms: f64,
        header: &PacketHeader,
        frames: &[QlogFrame],
        raw_length: usize,
    );

    /// 接続状態遷移イベント (Base)
    fn on_connection_state_updated(&mut self, time_ms: f64, old: &str, new: &str);

    /// トランスポートパラメータ設定イベント (Core)
    ///
    /// qlog-quic-events-13 Section 5.3 の QUICParametersSet に対応する。
    /// `initiator` は `"local"` (ローカルが設定した値) または `"remote"`
    /// (ピアが設定した値)。data は `initiator` とパラメータを同じ階層に持つ。
    fn on_parameters_set(&mut self, time_ms: f64, initiator: &str, params: &TransportParametersSet);

    /// パケットロスイベント (Core)
    fn on_packet_lost(&mut self, time_ms: f64, header: &PacketHeader);

    /// リカバリメトリクス更新イベント (Core)
    fn on_recovery_metrics_updated(
        &mut self,
        time_ms: f64,
        min_rtt_ms: f64,
        smoothed_rtt_ms: f64,
        latest_rtt_ms: f64,
        congestion_window: u64,
    );

    /// 鍵更新イベント (Base)
    ///
    /// qlog-quic-events-13 Section 6.1 の QUICKeyUpdated に対応する。
    /// `key_type` は `"initial"` / `"handshake"` / `"0rtt"` / `"1rtt"` のいずれか。
    /// `trigger` は `"tls"` / `"remote_update"` / `"local_update"` のいずれか。
    fn on_key_updated(
        &mut self,
        time_ms: f64,
        key_type: &str,
        key_phase: Option<u64>,
        trigger: &str,
    );

    /// ECN 状態遷移イベント (Extra)
    ///
    /// qlog-quic-events-13 Section 7.6 の QUICECNStateUpdated に対応する。
    /// 状態は `"testing"` / `"unknown"` / `"failed"` / `"capable"` のいずれか。
    fn on_ecn_state_updated(&mut self, time_ms: f64, old: &str, new: &str);

    /// Path MTU 更新イベント (Extra)
    ///
    /// qlog-quic-events-13 Section 4.8 の QUICMTUUpdated に対応する。
    /// `done` は MTU 探索が完了したかどうか。
    fn on_mtu_updated(&mut self, time_ms: f64, old: u32, new: u32, done: bool);

    /// バージョン情報イベント (Core)
    ///
    /// qlog-quic-events-13 Section 5.1 の QUICVersionInformation に対応する。
    /// `chosen_version` が `None` の場合は重複するバージョンが無かったことを表す。
    fn on_version_information(
        &mut self,
        time_ms: f64,
        client_versions: &[u32],
        server_versions: &[u32],
        chosen_version: Option<u32>,
    );

    /// 接続クローズイベント (Base)
    ///
    /// qlog-quic-events-13 Section 4.3 の QUICConnectionClosed に対応する。
    /// `trigger` は `"idle_timeout"` / `"application"` / `"error"` /
    /// `"version_mismatch"` / `"stateless_reset"` / `"aborted"` /
    /// `"unspecified"` のいずれか。tobi-quic は application close を `"application"`、
    /// transport error によるクローズを `"error"` として使い分ける。
    /// `error_code` はクローズを引き起こしたエラーコード。transport error として
    /// 閉じた場合は QUIC の transport error code (RFC 9000 Section 20.1)、
    /// application close の場合はアプリケーションプロトコルが定義する
    /// application error code (RFC 9000 Section 20.2) を記録する。
    /// 本実装は同節の typed な `application_error` フィールドを出力せず、
    /// application close の error code も `error_code` に載せる簡略化を行っている
    /// (スキーマからの逸脱)。
    /// `reason` は実装が保持しているクローズ理由のテキスト。
    fn on_connection_closed(
        &mut self,
        time_ms: f64,
        error_code: Option<u64>,
        reason: Option<&str>,
        trigger: &str,
    );

    /// パケット破棄イベント (Base)
    ///
    /// qlog-quic-events-13 Section 5.7 の QUICPacketDropped に対応する。
    /// `trigger` は `"internal_error"` / `"rejected"` / `"unsupported"` /
    /// `"invalid"` / `"duplicate"` / `"connection_unknown"` /
    /// `"decryption_failure"` / `"key_unavailable"` / `"general"` のいずれか。
    /// `details` は実装固有の補足情報。
    fn on_packet_dropped(&mut self, time_ms: f64, trigger: &str, details: Option<&str>);
}

/// 接続ごとに qlog writer を生成するトレイト
///
/// `create` は接続確立の直前 (Connection 生成直後、Initial 処理や
/// `connect(now)` 呼び出しより前) に呼ばれる。`None` を返した接続では
/// qlog を有効化しない。生成に失敗した場合も `None` を返す。
///
/// draft-ietf-quic-qlog-main-schema-14 Section 14.2 の informative
/// recommendation「enabling qlog conspicuous」(明示的な操作なしに qlog を
/// 有効化しない) を踏まえ、`ServerBuilder` / `ClientBuilder` の
/// `with_qlog_writer_factory` で利用者が明示的に指定した場合のみ writer が
/// 装着される。
///
/// `create` は接続の主タスク (server の router、client の connect) 上で
/// 同期実行されるため、実装は重いブロッキング I/O を避けること。
/// ファイル open やヘッダー書き込み程度は許容されるが、大量の I/O や
/// ネットワーク I/O は writer 内部でバッファリングするか、別スレッドへ
/// 委譲すること。`create` は panic してはならず、失敗は `None` で返すこと。
pub trait QlogWriterFactory: Send + Sync {
    /// 接続識別用の DCID を受け取り、writer を返す
    ///
    /// `odcid` は writer 実装が出力ファイル名やログのメタデータに利用できる
    /// 接続識別子。値の由来は Server と Client で非対称:
    ///
    /// - Server: 受信した Initial パケットの DCID (クライアントが最初に選んだ
    ///   Destination Connection ID = RFC 9000 Section 7.3 の
    ///   `original_destination_connection_id`)。長さは可変 (1〜20 バイト)。
    /// - Client: 自身が Initial パケット送信時に使う Destination Connection ID
    ///   (クライアント視点での ODCID)。現行実装では 8 バイト固定。
    fn create(&self, odcid: &[u8]) -> Option<Box<dyn QlogWriter>>;
}

// --- hex エンコード (PathChallenge/PathResponse 用) ---

mod hex {
    use alloc::string::String;
    use core::fmt::Write;

    pub fn encode(data: &[u8]) -> String {
        data.iter()
            .fold(String::with_capacity(data.len() * 2), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
    }
}
