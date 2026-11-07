// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Sans I/O QUIC トランスポートの状態マシン
//!
//! 接続状態、ストリーム管理、Initial パケット処理、タイマー処理を提供する。
//! I/O は呼び出し側が担い、パケットの送受信は `Connection::receive` /
//! `Connection::poll_output` を介して行う。

// unsafe コードを禁止する。Sans I/O の状態マシンには unsafe は不要であり、
// 将来の追加で安全性レビューが漏れるのを防ぐ。
#![forbid(unsafe_code)]
// 本番コードでは unwrap を禁止する。unwrap は失敗理由を伝えず、ピア入力や
// 設定値の変化で容易に panic の原因になる。テストコードは除外する。
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

pub mod connection;
pub mod initial_version;
pub mod stream;

// rustls / TLS セッションラッパは tobi_rustls クレートに移設された。
// 後方互換のため当該クレートを `tls` として再エクスポートする。
pub use tobi_rustls as tls;
