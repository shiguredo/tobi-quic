// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! WebTransport クライアントのエラー型

use std::fmt;

use shiguredo_http3::webtransport::connect::DraftVersion;

/// WebTransport クライアントのエラー
#[derive(Debug)]
pub enum Error {
    /// QUIC 層のエラー
    Quic(tobi_quic::Error),
    /// HTTP/3 層のエラー
    Http3(shiguredo_http3::Error),
    /// WebTransport ストリームヘッダーのデコードエラー
    StreamHeader(shiguredo_http3::webtransport::StreamHeaderDecodeError),
    /// CONNECT ヘッダーの構築エラー
    Header(shiguredo_http3::HeaderError),
    /// ネゴシエートされた ALPN が h3 ではない
    AlpnMismatch {
        /// 実際にネゴシエートされた ALPN (未確定の場合は `None`)
        actual: Option<Vec<u8>>,
    },
    /// QUIC DATAGRAM を使えない
    DatagramNotSupported,
    /// ピアの transport parameter を取得できない
    TransportParametersUnavailable,
    /// ピアが `reset_stream_at` transport parameter を広告していない
    ResetStreamAtNotSupported,
    /// クライアントとサーバーの WebTransport draft が両立しない
    DraftMismatch {
        /// クライアントが指定した draft
        requested: DraftVersion,
        /// サーバーの SETTINGS から判定した draft
        server: DraftVersion,
    },
    /// サーバーが WebTransport を有効にしていない
    WebTransportNotEnabled,
    /// サーバーが選択したアプリケーションプロトコルが指定と一致しない
    ///
    /// `wt-available-protocols` を指定したのに、応答の `wt-protocol` が無いか
    /// 指定した一覧に含まれていない。
    /// (draft-ietf-webtrans-http3-15 Section 3.3)
    ProtocolMismatch {
        /// クライアントが提示したプロトコル
        requested: Vec<String>,
        /// サーバーが返したプロトコル (未指定の場合は `None`)
        selected: Option<String>,
    },
    /// サーバーの SETTINGS に必須の設定がない
    MissingSetting {
        /// 欠けている SETTINGS の名前
        name: &'static str,
    },
    /// CONNECT が 2xx 以外の最終レスポンスの `:status` で応答された
    ConnectRejected {
        /// サーバーが返した `:status`
        status: u16,
    },
    /// セッションが終了している
    ///
    /// 受信系を分離した [`Session`](crate::session::Session) で
    /// [`accept_bidirectional_stream`](crate::session::Session::accept_bidirectional_stream) /
    /// [`accept_unidirectional_stream`](crate::session::Session::accept_unidirectional_stream) /
    /// [`receive`](crate::session::Session::receive) /
    /// [`receive_datagram`](crate::session::Session::receive_datagram)
    /// を呼んだ場合もこのエラーになる。
    SessionClosed,
    /// セッションが異常終了した
    ///
    /// CONNECT ストリームの RESET_STREAM や、`WT_ALPN_ERROR` /
    /// `WT_FLOW_CONTROL_ERROR` などのセッションエラーで終了した。
    /// (draft-ietf-webtrans-http3-15 Section 6)
    SessionAborted {
        /// セッション終了時に通知されたトランスポート側のエラーコード
        transport_error_code: u64,
        /// CONNECT ストリームの RESET_STREAM で通知されたエラーコード
        connect_stream_error_code: Option<u64>,
    },
    /// ピアがセッションの終了準備 (WT_DRAIN_SESSION) を通知している
    ///
    /// ピアは新しいストリームの開設とデータグラムの送信を利用しないことが
    /// 期待されるため、この実装は新規ストリームの開設とデータグラムの送信を
    /// 拒否する (draft-ietf-webtrans-http3-15 Section 4.7)。
    SessionDraining,
    /// セッションがドライバーの失敗で終了した
    DriverFailed(String),
    /// ドライバータスクが停止している
    DriverStopped,
    /// ピアがストリームをリセットした
    ///
    /// `error_code` は WebTransport のアプリケーションエラーコードである。
    /// ピアが `WT_APPLICATION_ERROR` の範囲外のコードでリセットした場合は
    /// アプリケーションエラーコードとして解釈できないため `None` になる
    /// (draft-ietf-webtrans-http3-15 Section 4.4)。
    StreamReset {
        /// QUIC ストリーム ID
        stream_id: u64,
        /// ピアが通知したアプリケーションエラーコード
        error_code: Option<u32>,
    },
    /// ピアがストリームの送信停止 (STOP_SENDING) を要求した
    ///
    /// `error_code` は WebTransport のアプリケーションエラーコードである。
    /// ピアが `WT_APPLICATION_ERROR` の範囲外のコードで送信停止した場合は
    /// アプリケーションエラーコードとして解釈できないため `None` になる
    /// (draft-ietf-webtrans-http3-15 Section 4.4)。
    StreamStopped {
        /// QUIC ストリーム ID
        stream_id: u64,
        /// ピアが通知したアプリケーションエラーコード
        error_code: Option<u32>,
    },
    /// ストリームが終了している
    StreamClosed {
        /// QUIC ストリーム ID
        stream_id: u64,
    },
    /// ストリームの受信側で回復不能なエラーが発生した
    StreamFailed {
        /// QUIC ストリーム ID
        stream_id: u64,
        /// エラーメッセージ
        message: String,
    },
    /// ピアが通知した WT_MAX_STREAMS の上限に達している
    ///
    /// ピアが WT_MAX_STREAMS で上限を増やすと開設できるようになる。
    /// (draft-ietf-webtrans-http3-15 Section 5.3)
    StreamsBlocked {
        /// 双方向ストリームの上限に達したか
        bidirectional: bool,
    },
    /// データグラムが QUIC の送信上限を超えている
    DatagramTooLarge {
        /// HTTP Datagram にエンコードした後のサイズ
        size: usize,
        /// `Connection::max_datagram_size` が返した上限
        maximum: usize,
    },
    /// 接続のストリーム ID が想定と異なる
    ///
    /// WebTransport の結線は、接続で最初に開く双方向ストリーム (ID 0) を
    /// CONNECT ストリームとして使い、制御ストリームに単方向ストリーム ID の
    /// 2 / 6 / 10 を要求する。同じ接続で別の目的のストリームを開いていたり、
    /// 利用側が接続を再利用している場合はこのエラーになる。
    StreamIdMismatch {
        /// 期待したストリーム ID
        expected: u64,
        /// 実際に割り当てられたストリーム ID
        actual: u64,
    },
    /// セッション確立がタイムアウトした
    HandshakeTimeout,
    /// SETTINGS に設定する値が VarInt の範囲外
    InvalidLimit {
        /// 範囲外だった設定値の名前
        name: &'static str,
    },
    /// 設定値が不正
    InvalidConfig {
        /// 不正だった設定の名前
        name: &'static str,
    },
    /// セッションのクローズ理由が長すぎる
    CloseReasonTooLong {
        /// 指定された理由のバイト数
        length: usize,
    },
    /// TLS 設定が指定されていない
    MissingTlsConfig,
    /// I/O 設定が指定されていない
    MissingIoConfig,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quic(e) => write!(f, "QUIC error: {e}"),
            Self::Http3(e) => write!(f, "HTTP/3 error: {e}"),
            Self::StreamHeader(e) => write!(f, "WebTransport stream header error: {e:?}"),
            Self::Header(e) => write!(f, "CONNECT header error: {e}"),
            Self::AlpnMismatch { actual } => match actual {
                Some(actual) => write!(
                    f,
                    "negotiated ALPN is not h3: {}",
                    String::from_utf8_lossy(actual)
                ),
                None => write!(f, "ALPN was not negotiated (expected h3)"),
            },
            Self::DatagramNotSupported => {
                write!(f, "peer did not advertise max_datagram_frame_size")
            }
            Self::TransportParametersUnavailable => {
                write!(f, "peer transport parameters are not available")
            }
            Self::ResetStreamAtNotSupported => {
                write!(
                    f,
                    "peer did not advertise the reset_stream_at transport parameter"
                )
            }
            Self::DraftMismatch { requested, server } => {
                write!(
                    f,
                    "WebTransport draft mismatch: requested {requested:?}, server {server:?}"
                )
            }
            Self::WebTransportNotEnabled => {
                write!(f, "server did not enable WebTransport")
            }
            Self::ProtocolMismatch {
                requested,
                selected,
            } => match selected {
                Some(selected) => write!(
                    f,
                    "server selected WebTransport protocol {selected:?}, which is not in the requested list {requested:?}"
                ),
                None => write!(
                    f,
                    "server did not select a WebTransport protocol (requested {requested:?})"
                ),
            },
            Self::MissingSetting { name } => {
                write!(f, "server SETTINGS is missing {name}")
            }
            Self::ConnectRejected { status } => {
                write!(f, "WebTransport CONNECT was rejected with status {status}")
            }
            Self::SessionClosed => write!(f, "WebTransport session is closed"),
            Self::SessionAborted {
                transport_error_code,
                connect_stream_error_code,
            } => match connect_stream_error_code {
                Some(connect_stream_error_code) => write!(
                    f,
                    "WebTransport session was aborted: CONNECT stream reset with \
                     error_code={connect_stream_error_code:#x}, \
                     transport error_code={transport_error_code:#x}"
                ),
                None => write!(
                    f,
                    "WebTransport session was aborted: transport error_code={transport_error_code:#x}"
                ),
            },
            Self::SessionDraining => {
                write!(f, "WebTransport session is draining")
            }
            Self::DriverFailed(message) => {
                write!(f, "WebTransport session failed: {message}")
            }
            Self::DriverStopped => write!(f, "WebTransport session driver stopped"),
            Self::StreamReset {
                stream_id,
                error_code,
            } => match error_code {
                Some(error_code) => write!(
                    f,
                    "stream {stream_id} was reset by the peer: application error_code={error_code:#x}"
                ),
                None => write!(
                    f,
                    "stream {stream_id} was reset by the peer: no application error code"
                ),
            },
            Self::StreamStopped {
                stream_id,
                error_code,
            } => match error_code {
                Some(error_code) => write!(
                    f,
                    "stream {stream_id} was stopped by the peer: application error_code={error_code:#x}"
                ),
                None => write!(
                    f,
                    "stream {stream_id} was stopped by the peer: no application error code"
                ),
            },
            Self::StreamClosed { stream_id } => {
                write!(f, "stream {stream_id} is closed")
            }
            Self::StreamFailed { stream_id, message } => {
                write!(f, "stream {stream_id} failed: {message}")
            }
            Self::StreamsBlocked { bidirectional } => {
                let kind = if *bidirectional {
                    "bidirectional"
                } else {
                    "unidirectional"
                };
                write!(
                    f,
                    "cannot open a {kind} stream: the WT_MAX_STREAMS limit set by the peer is reached"
                )
            }
            Self::DatagramTooLarge { size, maximum } => {
                write!(
                    f,
                    "datagram is too large: encoded size {size} exceeds maximum {maximum}"
                )
            }
            Self::StreamIdMismatch { expected, actual } => {
                write!(
                    f,
                    "stream id mismatch: expected {expected}, actual {actual} (reuse the connection for one session only)"
                )
            }
            Self::HandshakeTimeout => write!(f, "WebTransport session establishment timed out"),
            Self::InvalidLimit { name } => {
                write!(f, "configuration value {name} is out of the VarInt range")
            }
            Self::InvalidConfig { name } => {
                write!(f, "configuration value {name} is invalid")
            }
            Self::CloseReasonTooLong { length } => {
                write!(f, "close reason is too long: {length} bytes (maximum 1024)")
            }
            Self::MissingTlsConfig => write!(f, "TLS configuration is not set"),
            Self::MissingIoConfig => write!(f, "I/O configuration is not set"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Quic(e) => Some(e),
            Self::Http3(e) => Some(e),
            Self::Header(e) => Some(e),
            _ => None,
        }
    }
}

impl From<tobi_quic::Error> for Error {
    fn from(e: tobi_quic::Error) -> Self {
        Self::Quic(e)
    }
}

impl From<shiguredo_http3::Error> for Error {
    fn from(e: shiguredo_http3::Error) -> Self {
        Self::Http3(e)
    }
}

impl From<tobi_http3::Error> for Error {
    fn from(error: tobi_http3::Error) -> Self {
        match error {
            tobi_http3::Error::Quic(error) => Self::Quic(error),
            tobi_http3::Error::Http3(error) => Self::Http3(error),
            other => Self::DriverFailed(other.to_string()),
        }
    }
}

impl From<shiguredo_http3::webtransport::StreamHeaderDecodeError> for Error {
    fn from(e: shiguredo_http3::webtransport::StreamHeaderDecodeError) -> Self {
        Self::StreamHeader(e)
    }
}

impl From<shiguredo_http3::HeaderError> for Error {
    fn from(e: shiguredo_http3::HeaderError) -> Self {
        Self::Header(e)
    }
}
