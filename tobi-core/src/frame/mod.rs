// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! QUIC フレームの定義とエンコード/デコード
//!
//! RFC 9000 Section 12.4 で定義される全フレームタイプと、
//! RFC 10069 Section 4 で定義される Multipath 拡張フレームを含む。

pub mod ack;
pub mod ack_frequency;
pub mod connection_close;
pub mod crypto;
pub mod data_blocked;
pub mod datagram;
pub mod handshake_done;
pub mod immediate_ack;
pub mod max_data;
pub mod max_path_id;
pub mod max_stream_data;
pub mod max_streams;
pub mod new_connection_id;
pub mod new_token;
pub mod observed_address;
pub mod padding;
pub mod path_abandon;
pub mod path_ack;
pub mod path_challenge;
pub mod path_cids_blocked;
pub mod path_new_connection_id;
pub mod path_response;
pub mod path_retire_connection_id;
pub mod path_status;
pub mod paths_blocked;
pub mod ping;
pub mod receive_timestamps;
pub mod reset_stream;
pub mod reset_stream_at;
pub mod retire_connection_id;
pub mod stop_sending;
pub mod stream;
pub mod stream_data_blocked;
pub mod streams_blocked;

use alloc::vec::Vec;

use crate::error::Error;
use crate::varint::VarInt;

/// フレームタイプ定数 (RFC 9000 Section 12.4)
pub mod frame_type {
    // RFC 9000 標準フレーム
    pub const PADDING: u64 = 0x00;
    pub const PING: u64 = 0x01;
    pub const ACK: u64 = 0x02;
    pub const ACK_ECN: u64 = 0x03;
    pub const RESET_STREAM: u64 = 0x04;
    pub const STOP_SENDING: u64 = 0x05;
    pub const CRYPTO: u64 = 0x06;
    pub const NEW_TOKEN: u64 = 0x07;
    pub const STREAM_START: u64 = 0x08;
    pub const STREAM_END: u64 = 0x0f;
    pub const MAX_DATA: u64 = 0x10;
    pub const MAX_STREAM_DATA: u64 = 0x11;
    pub const MAX_STREAMS_BIDI: u64 = 0x12;
    pub const MAX_STREAMS_UNI: u64 = 0x13;
    pub const DATA_BLOCKED: u64 = 0x14;
    pub const STREAM_DATA_BLOCKED: u64 = 0x15;
    pub const STREAMS_BLOCKED_BIDI: u64 = 0x16;
    pub const STREAMS_BLOCKED_UNI: u64 = 0x17;
    pub const NEW_CONNECTION_ID: u64 = 0x18;
    pub const RETIRE_CONNECTION_ID: u64 = 0x19;
    pub const PATH_CHALLENGE: u64 = 0x1a;
    pub const PATH_RESPONSE: u64 = 0x1b;
    pub const CONNECTION_CLOSE: u64 = 0x1c;
    pub const APPLICATION_CLOSE: u64 = 0x1d;
    pub const HANDSHAKE_DONE: u64 = 0x1e;

    // ACK Frequency 拡張 (draft-ietf-quic-ack-frequency-14 Section 4 / Section 5)
    // フレームタイプは同 draft の IANA Considerations で登録されている。
    pub const ACK_FREQUENCY: u64 = 0xaf;
    pub const IMMEDIATE_ACK: u64 = 0x1f;

    // DATAGRAM 拡張 (RFC 9221 Section 4)
    pub const DATAGRAM: u64 = 0x30;
    pub const DATAGRAM_LEN: u64 = 0x31;

    // Reliable Stream Reset 拡張 (draft-ietf-quic-reliable-stream-reset-11)
    // フレームタイプ 0x24 は同 draft Section 8.2 が登録し、IANA の QUIC frame type
    // registry では 2026-09-28 に Permanent として登録済みである
    // (Specification: RFC-ietf-quic-reliable-stream-reset-11)。
    pub const RESET_STREAM_AT: u64 = 0x24;

    // Multipath 拡張フレーム (RFC 10069 Section 4)
    pub const PATH_ACK: u64 = 0x3e;
    pub const PATH_ACK_ECN: u64 = 0x3f;
    pub const PATH_ABANDON: u64 = 0x3e75;
    pub const PATH_STATUS_BACKUP: u64 = 0x3e76;
    pub const PATH_STATUS_AVAILABLE: u64 = 0x3e77;
    pub const PATH_NEW_CONNECTION_ID: u64 = 0x3e78;
    pub const PATH_RETIRE_CONNECTION_ID: u64 = 0x3e79;
    pub const MAX_PATH_ID: u64 = 0x3e7a;
    pub const PATHS_BLOCKED: u64 = 0x3e7b;
    pub const PATH_CIDS_BLOCKED: u64 = 0x3e7c;

    // Receive Timestamps 拡張 (draft-ietf-quic-receive-ts-03 Section 10)
    // ACK / PATH_ACK の拡張で、ECN の有無を下位 1 bit で表す。
    pub const ACK_RECEIVE_TIMESTAMPS: u64 = 0x03178307;
    pub const ACK_RECEIVE_TIMESTAMPS_ECN: u64 = 0x03178308;
    pub const PATH_ACK_RECEIVE_TIMESTAMPS: u64 = 0x03178309;
    pub const PATH_ACK_RECEIVE_TIMESTAMPS_ECN: u64 = 0x0317830a;

    // Address Discovery 拡張 (draft-ietf-quic-address-discovery-01 Section 4.1)
    // 最下位ビット 0 が IPv4、1 が IPv6 を表す。
    pub const OBSERVED_ADDRESS_V4: u64 = 0x9f81a6;
    pub const OBSERVED_ADDRESS_V6: u64 = 0x9f81a7;
}

/// デコードされたフレーム
#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    Padding(padding::Padding),
    Ping(ping::Ping),
    Ack(ack::Ack),
    ResetStream(reset_stream::ResetStream),
    ResetStreamAt(reset_stream_at::ResetStreamAt),
    StopSending(stop_sending::StopSending),
    Crypto(crypto::Crypto),
    NewToken(new_token::NewToken),
    Stream(stream::Stream),
    MaxData(max_data::MaxData),
    MaxStreamData(max_stream_data::MaxStreamData),
    MaxStreams(max_streams::MaxStreams),
    DataBlocked(data_blocked::DataBlocked),
    StreamDataBlocked(stream_data_blocked::StreamDataBlocked),
    StreamsBlocked(streams_blocked::StreamsBlocked),
    NewConnectionId(new_connection_id::NewConnectionId),
    RetireConnectionId(retire_connection_id::RetireConnectionId),
    PathChallenge(path_challenge::PathChallenge),
    PathResponse(path_response::PathResponse),
    ConnectionClose(connection_close::ConnectionClose),
    HandshakeDone(handshake_done::HandshakeDone),
    // ACK Frequency 拡張 (draft-ietf-quic-ack-frequency-14 Section 4 / Section 5)
    AckFrequency(ack_frequency::AckFrequency),
    ImmediateAck(immediate_ack::ImmediateAck),
    // Receive Timestamps 拡張 (draft-ietf-quic-receive-ts-03 Section 4 / Section 5)
    AckReceiveTimestamps(receive_timestamps::AckReceiveTimestamps),
    PathAckReceiveTimestamps(receive_timestamps::PathAckReceiveTimestamps),
    // DATAGRAM 拡張 (RFC 9221)
    Datagram(datagram::Datagram),
    // Multipath 拡張
    PathAck(path_ack::PathAck),
    PathAbandon(path_abandon::PathAbandon),
    PathStatusAvailable(path_status::PathStatusAvailable),
    PathStatusBackup(path_status::PathStatusBackup),
    PathNewConnectionId(path_new_connection_id::PathNewConnectionId),
    PathRetireConnectionId(path_retire_connection_id::PathRetireConnectionId),
    MaxPathId(max_path_id::MaxPathId),
    PathsBlocked(paths_blocked::PathsBlocked),
    PathCidsBlocked(path_cids_blocked::PathCidsBlocked),
    // Address Discovery 拡張 (draft-ietf-quic-address-discovery-01)
    ObservedAddress(observed_address::ObservedAddress),
}

impl Frame {
    /// バッファからフレームをデコードする
    ///
    /// 成功時は (フレーム, 消費バイト数) を返す。消費バイト数はフレームタイプを
    /// 含むフレーム全体の wire 上のバイト数であり、LEN なし DATAGRAM (0x30) では
    /// 渡したスライス (パケット payload) の末尾までを消費する。
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), Error> {
        if buf.is_empty() {
            return Err(Error::Incomplete { needed: 1 });
        }

        // PADDING フレームは特殊: タイプバイトが 0x00
        if buf[0] == 0x00 {
            let (frame, size) = padding::Padding::decode(buf)?;
            return Ok((Frame::Padding(frame), size));
        }

        let (frame_type, type_size) = VarInt::decode(buf)?;
        let ft = frame_type.as_u64();

        // RFC 9000 Section 12.4: Frame Type は最短エンコードを使用しなければならない (MUST)。
        // 非最短形の受信を PROTOCOL_VIOLATION として拒否するのは MAY だが、
        // デコードの正準性 (同一フレームが一意のバイト列に対応) と
        // フレーム型ガードの一貫性を保つため、本実装ではこの MAY を採用する。
        // RFC 9000 Section 16: 最短エンコードが要求されるのは Frame Type フィールドのみで、
        // payload 内の varint には適用しない。
        // VarInt::decode が返す消費バイト数 type_size は tag バイト由来、encoded_size() は
        // 値に対する一意の最短長であり、両者の不一致が非最短形の判定になる。
        // 未知 Frame Type でも意味解釈 (match ft) より前に構文レベルの違反として弾く。
        if type_size != frame_type.encoded_size() {
            return Err(Error::Protocol {
                code: crate::error::TransportErrorCode::PROTOCOL_VIOLATION,
                reason: format!(
                    "frame type 0x{ft:x} uses non-minimal varint encoding ({type_size} bytes)"
                ),
            });
        }

        let payload = &buf[type_size..];

        match ft {
            frame_type::PING => Ok((Frame::Ping(ping::Ping), type_size)),
            frame_type::ACK | frame_type::ACK_ECN => {
                let (frame, size) = ack::Ack::decode_payload(payload, ft == frame_type::ACK_ECN)?;
                Ok((Frame::Ack(frame), type_size + size))
            }
            frame_type::ACK_RECEIVE_TIMESTAMPS | frame_type::ACK_RECEIVE_TIMESTAMPS_ECN => {
                let (frame, size) = receive_timestamps::AckReceiveTimestamps::decode_payload(
                    payload,
                    ft == frame_type::ACK_RECEIVE_TIMESTAMPS_ECN,
                )?;
                Ok((Frame::AckReceiveTimestamps(frame), type_size + size))
            }
            frame_type::PATH_ACK_RECEIVE_TIMESTAMPS
            | frame_type::PATH_ACK_RECEIVE_TIMESTAMPS_ECN => {
                let (frame, size) = receive_timestamps::PathAckReceiveTimestamps::decode_payload(
                    payload,
                    ft == frame_type::PATH_ACK_RECEIVE_TIMESTAMPS_ECN,
                )?;
                Ok((Frame::PathAckReceiveTimestamps(frame), type_size + size))
            }
            frame_type::RESET_STREAM => {
                let (frame, size) = reset_stream::ResetStream::decode_payload(payload)?;
                Ok((Frame::ResetStream(frame), type_size + size))
            }
            frame_type::RESET_STREAM_AT => {
                let (frame, size) = reset_stream_at::ResetStreamAt::decode_payload(payload)?;
                Ok((Frame::ResetStreamAt(frame), type_size + size))
            }
            frame_type::STOP_SENDING => {
                let (frame, size) = stop_sending::StopSending::decode_payload(payload)?;
                Ok((Frame::StopSending(frame), type_size + size))
            }
            frame_type::CRYPTO => {
                let (frame, size) = crypto::Crypto::decode_payload(payload)?;
                Ok((Frame::Crypto(frame), type_size + size))
            }
            frame_type::NEW_TOKEN => {
                let (frame, size) = new_token::NewToken::decode_payload(payload)?;
                Ok((Frame::NewToken(frame), type_size + size))
            }
            frame_type::STREAM_START..=frame_type::STREAM_END => {
                let (frame, size) = stream::Stream::decode_payload(payload, ft)?;
                Ok((Frame::Stream(frame), type_size + size))
            }
            frame_type::MAX_DATA => {
                let (frame, size) = max_data::MaxData::decode_payload(payload)?;
                Ok((Frame::MaxData(frame), type_size + size))
            }
            frame_type::MAX_STREAM_DATA => {
                let (frame, size) = max_stream_data::MaxStreamData::decode_payload(payload)?;
                Ok((Frame::MaxStreamData(frame), type_size + size))
            }
            frame_type::MAX_STREAMS_BIDI | frame_type::MAX_STREAMS_UNI => {
                let (frame, size) = max_streams::MaxStreams::decode_payload(payload, ft)?;
                Ok((Frame::MaxStreams(frame), type_size + size))
            }
            frame_type::DATA_BLOCKED => {
                let (frame, size) = data_blocked::DataBlocked::decode_payload(payload)?;
                Ok((Frame::DataBlocked(frame), type_size + size))
            }
            frame_type::STREAM_DATA_BLOCKED => {
                let (frame, size) =
                    stream_data_blocked::StreamDataBlocked::decode_payload(payload)?;
                Ok((Frame::StreamDataBlocked(frame), type_size + size))
            }
            frame_type::STREAMS_BLOCKED_BIDI | frame_type::STREAMS_BLOCKED_UNI => {
                let (frame, size) = streams_blocked::StreamsBlocked::decode_payload(payload, ft)?;
                Ok((Frame::StreamsBlocked(frame), type_size + size))
            }
            frame_type::NEW_CONNECTION_ID => {
                let (frame, size) = new_connection_id::NewConnectionId::decode_payload(payload)?;
                Ok((Frame::NewConnectionId(frame), type_size + size))
            }
            frame_type::RETIRE_CONNECTION_ID => {
                let (frame, size) =
                    retire_connection_id::RetireConnectionId::decode_payload(payload)?;
                Ok((Frame::RetireConnectionId(frame), type_size + size))
            }
            frame_type::PATH_CHALLENGE => {
                let (frame, size) = path_challenge::PathChallenge::decode_payload(payload)?;
                Ok((Frame::PathChallenge(frame), type_size + size))
            }
            frame_type::PATH_RESPONSE => {
                let (frame, size) = path_response::PathResponse::decode_payload(payload)?;
                Ok((Frame::PathResponse(frame), type_size + size))
            }
            frame_type::CONNECTION_CLOSE | frame_type::APPLICATION_CLOSE => {
                let (frame, size) = connection_close::ConnectionClose::decode_payload(payload, ft)?;
                Ok((Frame::ConnectionClose(frame), type_size + size))
            }
            frame_type::HANDSHAKE_DONE => Ok((
                Frame::HandshakeDone(handshake_done::HandshakeDone),
                type_size,
            )),
            // DATAGRAM 拡張 (RFC 9221 Section 4)
            frame_type::DATAGRAM => {
                let (frame, size) = datagram::Datagram::decode_payload_no_len(payload);
                Ok((Frame::Datagram(frame), type_size + size))
            }
            frame_type::DATAGRAM_LEN => {
                let (frame, size) = datagram::Datagram::decode_payload_with_len(payload)?;
                Ok((Frame::Datagram(frame), type_size + size))
            }
            // Multipath 拡張
            frame_type::PATH_ACK | frame_type::PATH_ACK_ECN => {
                let (frame, size) =
                    path_ack::PathAck::decode_payload(payload, ft == frame_type::PATH_ACK_ECN)?;
                Ok((Frame::PathAck(frame), type_size + size))
            }
            frame_type::PATH_ABANDON => {
                let (frame, size) = path_abandon::PathAbandon::decode_payload(payload)?;
                Ok((Frame::PathAbandon(frame), type_size + size))
            }
            frame_type::PATH_STATUS_AVAILABLE => {
                let (frame, size) = path_status::PathStatusAvailable::decode_payload(payload)?;
                Ok((Frame::PathStatusAvailable(frame), type_size + size))
            }
            frame_type::PATH_STATUS_BACKUP => {
                let (frame, size) = path_status::PathStatusBackup::decode_payload(payload)?;
                Ok((Frame::PathStatusBackup(frame), type_size + size))
            }
            frame_type::PATH_NEW_CONNECTION_ID => {
                let (frame, size) =
                    path_new_connection_id::PathNewConnectionId::decode_payload(payload)?;
                Ok((Frame::PathNewConnectionId(frame), type_size + size))
            }
            frame_type::PATH_RETIRE_CONNECTION_ID => {
                let (frame, size) =
                    path_retire_connection_id::PathRetireConnectionId::decode_payload(payload)?;
                Ok((Frame::PathRetireConnectionId(frame), type_size + size))
            }
            frame_type::MAX_PATH_ID => {
                let (frame, size) = max_path_id::MaxPathId::decode_payload(payload)?;
                Ok((Frame::MaxPathId(frame), type_size + size))
            }
            frame_type::PATHS_BLOCKED => {
                let (frame, size) = paths_blocked::PathsBlocked::decode_payload(payload)?;
                Ok((Frame::PathsBlocked(frame), type_size + size))
            }
            frame_type::PATH_CIDS_BLOCKED => {
                let (frame, size) = path_cids_blocked::PathCidsBlocked::decode_payload(payload)?;
                Ok((Frame::PathCidsBlocked(frame), type_size + size))
            }
            frame_type::OBSERVED_ADDRESS_V4 | frame_type::OBSERVED_ADDRESS_V6 => {
                let (frame, size) = observed_address::ObservedAddress::decode_payload(
                    payload,
                    ft == frame_type::OBSERVED_ADDRESS_V6,
                )?;
                Ok((Frame::ObservedAddress(frame), type_size + size))
            }
            frame_type::ACK_FREQUENCY => {
                let (frame, size) = ack_frequency::AckFrequency::decode_payload(payload)?;
                Ok((Frame::AckFrequency(frame), type_size + size))
            }
            frame_type::IMMEDIATE_ACK => {
                Ok((Frame::ImmediateAck(immediate_ack::ImmediateAck), type_size))
            }
            _ => Err(Error::InvalidData(format!("unknown frame type: 0x{ft:x}"))),
        }
    }

    /// バッファにフレームをエンコードする
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Frame::Padding(f) => f.encode(buf),
            Frame::Ping(f) => f.encode(buf),
            Frame::Ack(f) => f.encode(buf),
            Frame::AckReceiveTimestamps(f) => f.encode(buf),
            Frame::PathAckReceiveTimestamps(f) => f.encode(buf),
            Frame::ResetStream(f) => f.encode(buf),
            Frame::ResetStreamAt(f) => f.encode(buf),
            Frame::StopSending(f) => f.encode(buf),
            Frame::Crypto(f) => f.encode(buf),
            Frame::NewToken(f) => f.encode(buf),
            Frame::Stream(f) => f.encode(buf),
            Frame::MaxData(f) => f.encode(buf),
            Frame::MaxStreamData(f) => f.encode(buf),
            Frame::MaxStreams(f) => f.encode(buf),
            Frame::DataBlocked(f) => f.encode(buf),
            Frame::StreamDataBlocked(f) => f.encode(buf),
            Frame::StreamsBlocked(f) => f.encode(buf),
            Frame::NewConnectionId(f) => f.encode(buf),
            Frame::RetireConnectionId(f) => f.encode(buf),
            Frame::PathChallenge(f) => f.encode(buf),
            Frame::PathResponse(f) => f.encode(buf),
            Frame::ConnectionClose(f) => f.encode(buf),
            Frame::HandshakeDone(f) => f.encode(buf),
            Frame::AckFrequency(f) => f.encode(buf),
            Frame::ImmediateAck(f) => f.encode(buf),
            Frame::Datagram(f) => f.encode(buf),
            Frame::PathAck(f) => f.encode(buf),
            Frame::PathAbandon(f) => f.encode(buf),
            Frame::PathStatusAvailable(f) => f.encode(buf),
            Frame::PathStatusBackup(f) => f.encode(buf),
            Frame::PathNewConnectionId(f) => f.encode(buf),
            Frame::PathRetireConnectionId(f) => f.encode(buf),
            Frame::MaxPathId(f) => f.encode(buf),
            Frame::PathsBlocked(f) => f.encode(buf),
            Frame::PathCidsBlocked(f) => f.encode(buf),
            Frame::ObservedAddress(f) => f.encode(buf),
        }
    }
}
