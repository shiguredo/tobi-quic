// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 接続終了ログのレベル判定
//!
//! `ConnectionClosed` イベントを、`ConnectionError::Closed` は `debug`、
//! `ConnectionError::Application` は `info`、それ以外は `warn` で出すための
//! 判定をまとめる。application-level の正常終了 (`H3_NO_ERROR` の 0x100 など、
//! RFC 9114 Section 8.1) は `tobi-platform` では判別しない。`tobi-platform` は
//! `tobi-http3` / `tobi-webtransport` に依存できず、プロトコル固有の正常終了
//! コードをこの層に置くのは責務を超えるためである。そのため
//! `ConnectionError::Application` は `info` のまま残す。

use crate::error::ConnectionError;

/// `ConnectionClosed` を出すログレベル
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseLogLevel {
    /// 正常終了
    Debug,
    /// アプリケーションクローズ
    Info,
    /// トランスポートエラー / アイドルタイムアウト / 内部エラー
    Warn,
}

/// 接続終了理由に対応するログレベルを返す
///
/// `ConnectionError::Closed` はローカルクローズ、transport の error_code 0、
/// application の error_code 0 を正規化したものである。application の
/// error_code 0 は `from_close_event` で `Closed` になるため、ここへは
/// `Closed` として渡る。
pub(crate) fn close_log_level(error: &ConnectionError) -> CloseLogLevel {
    match error {
        ConnectionError::Closed => CloseLogLevel::Debug,
        ConnectionError::Application { .. } => CloseLogLevel::Info,
        ConnectionError::Transport { .. }
        | ConnectionError::TimedOut
        | ConnectionError::Internal(_) => CloseLogLevel::Warn,
    }
}

#[cfg(test)]
mod tests;
