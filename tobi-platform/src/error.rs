// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! エラー型

use std::fmt;

/// 接続エラー
///
/// 接続が閉じた原因を表す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionError {
    /// 正常クローズ
    Closed,
    /// トランスポートエラー (RFC 9000 Section 20)
    Transport { code: u64, reason: String },
    /// アプリケーションエラー
    ///
    /// RFC 9000 Section 19.19 の application error (type 0x1d) を表す。
    Application { code: u64, reason: Vec<u8> },
    /// アイドルタイムアウト
    TimedOut,
    /// 内部エラー
    Internal(String),
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionError::Closed => write!(f, "connection closed"),
            ConnectionError::Transport { code, reason } => {
                write!(f, "transport error: code={code:#x}, reason={reason}")
            }
            ConnectionError::Application { code, reason } => {
                let reason_str = String::from_utf8_lossy(reason);
                write!(f, "application error: code={code:#x}, reason={reason_str}")
            }
            ConnectionError::TimedOut => write!(f, "connection timed out"),
            ConnectionError::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl ConnectionError {
    /// 受信した CONNECTION_CLOSE の内容から接続エラーを組み立てる
    ///
    /// RFC 9000 Section 19.19: CONNECTION_CLOSE にはトランスポートエラー
    /// (type 0x1c) とアプリケーションエラー (type 0x1d) があり、種別は
    /// [`ConnectionCloseKind`] で区別される。
    ///
    /// transport-level (type 0x1c) の error code は RFC 9000 Section 20.1 が定義し、
    /// 0 は NO_ERROR を表す。application-level (type 0x1d) の error code は
    /// RFC 9000 Section 20.2 の application code space の値であり、0 が NO_ERROR で
    /// あるとは限らない。本実装では application close の 0 も正常クローズとして扱う
    /// (本実装の規約)。
    pub(crate) fn from_close_event(
        error_code: u64,
        reason: Vec<u8>,
        kind: tobi_core::connection::ConnectionCloseKind,
    ) -> Self {
        use tobi_core::connection::ConnectionCloseKind;
        match kind {
            ConnectionCloseKind::IdleTimeout => Self::TimedOut,
            ConnectionCloseKind::Internal => {
                Self::Internal(String::from_utf8_lossy(&reason).into_owned())
            }
            ConnectionCloseKind::Local => Self::Closed,
            ConnectionCloseKind::Transport => {
                if error_code == 0 {
                    Self::Closed
                } else {
                    Self::Transport {
                        code: error_code,
                        reason: String::from_utf8_lossy(&reason).into_owned(),
                    }
                }
            }
            ConnectionCloseKind::Application => {
                if error_code == 0 {
                    Self::Closed
                } else {
                    Self::Application {
                        code: error_code,
                        reason,
                    }
                }
            }
        }
    }

    /// ローカルで接続を閉じたときの接続エラーを組み立てる
    ///
    /// transport の `Connection::close` は transport-level の CONNECTION_CLOSE
    /// (type 0x1c) を送るため、ピアから見た種別に合わせて `Transport` とする。
    /// transport error code は RFC 9000 Section 20.1 が定義し、0 は NO_ERROR を
    /// 表すため正常クローズとして扱う。
    pub(crate) fn from_local_close(error_code: u64, reason: &[u8]) -> Self {
        if error_code == 0 {
            Self::Closed
        } else {
            Self::Transport {
                code: error_code,
                reason: String::from_utf8_lossy(reason).into_owned(),
            }
        }
    }

    /// アプリケーションエラーでローカルから接続を閉じたときの接続エラーを組み立てる
    ///
    /// transport の `Connection::close_application` は application-level の
    /// CONNECTION_CLOSE (type 0x1d) を送る。RFC 9000 Section 19.19 は 0x1d の
    /// Error Code をアプリケーションプロトコルが定義する code space
    /// (RFC 9000 Section 20.2) の値と定めているため、ピアから見た種別に合わせて
    /// `Application` とする。reason はアプリケーション由来のバイト列をそのまま
    /// 保持する。
    ///
    /// application code space はアプリケーションプロトコルが定義するものであり、
    /// transport の NO_ERROR (RFC 9000 Section 20.1 の 0) と同じ意味を持つとは
    /// 限らない。本実装では error code 0 を正常クローズとして扱う規約とする。
    pub(crate) fn from_local_application_close(error_code: u64, reason: &[u8]) -> Self {
        if error_code == 0 {
            Self::Closed
        } else {
            Self::Application {
                code: error_code,
                reason: reason.to_vec(),
            }
        }
    }
}

impl std::error::Error for ConnectionError {}

/// ストリームエラー
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    /// ピアがストリームをリセットした (RESET_STREAM / RESET_STREAM_AT)
    ///
    /// `final_size` はリセットが通知したストリームの最終サイズ
    /// (RFC 9000 Section 4.5)。リセット前に受信してバッファ済みのデータを
    /// 読み切った後、このエラーで最終サイズを報告する。
    ///
    /// `reliable_size` は draft-ietf-quic-reliable-stream-reset-11 Section 4 の
    /// Reliable Size である。`Some(n)` は RESET_STREAM_AT が `n` バイトまでの
    /// 配信を保証していることを表し、`None` は RESET_STREAM によるリセットを
    /// 表す。`Some(0)` はデータ配信上は `None` と等価である (同 Section 5)。
    Reset {
        error_code: u64,
        final_size: u64,
        reliable_size: Option<u64>,
    },
    /// ピアが送信停止を要求した (STOP_SENDING)
    Stopped { error_code: u64 },
    /// 接続が切断された
    ConnectionLost(ConnectionError),
    /// 送信側がそれ以上データを受け付けない状態への書き込み
    ///
    /// FIN / RESET_STREAM を送信済み、またはストリームが GC 済みの場合に返す。
    FinishedSending,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamError::Reset {
                error_code,
                final_size,
                reliable_size,
            } => {
                write!(
                    f,
                    "stream reset by peer: error_code={error_code:#x}, final_size={final_size}, reliable_size={reliable_size:?}"
                )
            }
            StreamError::Stopped { error_code } => {
                write!(f, "stream stopped by peer: error_code={error_code:#x}")
            }
            StreamError::ConnectionLost(e) => write!(f, "connection lost: {e}"),
            StreamError::FinishedSending => write!(f, "stream already finished sending"),
        }
    }
}

impl std::error::Error for StreamError {}

/// エンドポイント起動エラー
#[derive(Debug)]
pub enum StartError {
    /// I/O エラー
    Io(std::io::Error),
    /// 設定エラー
    Config(String),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartError::Io(e) => write!(f, "I/O error: {e}"),
            StartError::Config(msg) => write!(f, "config error: {msg}"),
        }
    }
}

impl std::error::Error for StartError {}

impl From<std::io::Error> for StartError {
    fn from(e: std::io::Error) -> Self {
        StartError::Io(e)
    }
}

/// tobi_platform のエラー型
#[derive(Debug)]
pub enum Error {
    /// I/O エラー
    Io(std::io::Error),
    /// プロトコルエラー
    Protocol(String),
    /// 内部エラー
    Internal(String),
    /// 接続エラー
    Connection(ConnectionError),
    /// ピアが許可したストリーム数の上限に達した
    ///
    /// ローカル起動のストリームを開こうとした時点で、ピアが許可した累積上限
    /// (`initial_max_streams_*` と MAX_STREAMS で通知された値) に達していたこと
    /// を表す。RFC 9000 Section 4.6 / Section 19.11 が定める上限を超えないための
    /// 正常な停止状態であり、接続は閉じていない。ピアからより大きい上限を通知
    /// する MAX_STREAMS を受信した後に、同じ open を再試行できる。
    StreamLimitReached {
        /// 双方向ストリームの上限到達なら `true`
        bidirectional: bool,
        /// 到達したピアの累積上限
        maximum_streams: u64,
    },
    /// ストリームエラー
    Stream(StreamError),
    /// Version Negotiation により接続試行を中止した
    ///
    /// `offered` はサーバーが提示したバージョン一覧。呼び出し側はこの一覧から
    /// 未試行の対応バージョンを選んで新しい接続試行を開始できる
    /// (RFC 9000 Section 6.2)。
    VersionNegotiation { offered: Vec<u32> },
    /// 互換バージョン交渉でサーバーが別のバージョンを選んだ
    ///
    /// RFC 9368 Section 2.3: サーバーがクライアントの Chosen Version と
    /// 異なる互換バージョンで応答した。rustls の QUIC セッションが
    /// バージョンに束縛されるため接続内では切り替えられず、呼び出し側は
    /// このバージョンで新しい接続試行を開始する。
    CompatibleVersionNegotiation { version: u32 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Error::Internal(msg) => write!(f, "internal error: {msg}"),
            Error::Connection(e) => write!(f, "connection error: {e}"),
            Error::StreamLimitReached {
                bidirectional,
                maximum_streams,
            } => {
                // 表示文言はコア層と揃える。両層で同じ文字列を二重管理しない。
                let error = tobi_core::error::Error::StreamLimitReached {
                    bidirectional: *bidirectional,
                    maximum_streams: *maximum_streams,
                };
                write!(f, "{error}")
            }
            Error::Stream(e) => write!(f, "stream error: {e}"),
            Error::VersionNegotiation { offered } => {
                write!(
                    f,
                    "version negotiation required: server supports {offered:?}"
                )
            }
            Error::CompatibleVersionNegotiation { version } => {
                write!(
                    f,
                    "compatible version negotiation required: server selected {version:#010x}"
                )
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<ConnectionError> for Error {
    fn from(e: ConnectionError) -> Self {
        Error::Connection(e)
    }
}

impl From<StreamError> for Error {
    fn from(e: StreamError) -> Self {
        Error::Stream(e)
    }
}

impl From<StartError> for Error {
    fn from(e: StartError) -> Self {
        match e {
            StartError::Io(e) => Error::Io(e),
            StartError::Config(msg) => Error::Internal(msg),
        }
    }
}

/// transport 層のエラーを公開 API のエラーへ変換する
///
/// ストリーム上限到達は接続終了ではないため、文字列化せずに専用の種別のまま
/// 伝え、利用側が再試行可能か型で判別できるようにする。それ以外のエラーは、
/// どの操作で発生したか分かるよう操作の文脈を付けて文字列化する。
pub(crate) fn map_transport_error(error: tobi_core::error::Error, context: &str) -> Error {
    match error {
        tobi_core::error::Error::StreamLimitReached {
            bidirectional,
            maximum_streams,
        } => Error::StreamLimitReached {
            bidirectional,
            maximum_streams,
        },
        error => Error::Protocol(format!("{context}: {error}")),
    }
}

/// ログ出力用に reason phrase を整形する
///
/// ピアが送る reason phrase は任意のバイト列であり、改行や制御文字を含み得る。
/// そのままログへ出すとログ行が分裂し、ログ注入や過大なログ行の原因になる。
/// UTF-8 として不正なバイトは置換し、制御文字は空白または `.` に置き換え、
/// 長さを 256 文字に制限する。
pub(crate) fn sanitize_reason_for_log(reason: &[u8]) -> String {
    /// ログに載せる reason phrase の最大文字数
    const MAX_LOG_REASON_LEN: usize = 256;
    let mut out = String::new();
    for (count, c) in String::from_utf8_lossy(reason).chars().enumerate() {
        if count >= MAX_LOG_REASON_LEN {
            out.push_str("...");
            break;
        }
        let c = if c == '\n' || c == '\r' || c == '\t' {
            ' '
        } else if c.is_control() {
            '.'
        } else {
            c
        };
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests;
