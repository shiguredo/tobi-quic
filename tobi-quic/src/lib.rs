// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! tobi_quic — Multipath QUIC ライブラリ
//!
//! 接続とストリームを非同期に操作する高水準 API を提供する。
//! 内部は tobi_core (型・アルゴリズム) +
//! tobi_transport (Sans I/O ステートマシン) +
//! tobi_platform (Tokio I/O ドライバー) の 3 層で構成。

// --- API 層のモジュール ---
pub mod config;
pub mod connection;
pub mod endpoint;
pub mod error {
    //! エラー型
    pub use tobi_platform::error::*;
}
pub mod path {
    //! パス管理型
    pub use tobi_platform::path::*;
}
pub mod qlog;
pub mod session;
pub mod stream;
pub mod token;

// --- API 層の re-export ---
pub use config::{
    AddressToken, ClientTlsConfig, CongestionControlAlgorithm, Connect, ConnectionCloseFormatter,
    DatagramConfig, EndpointLimits, InterfaceFilter, IoConfig, MtuConfig, MultipathConfig,
    MultipathMode, ServerTlsConfig, SilentConnectionCloseFormatter, UdpBatchConfig,
};
pub use connection::{ApplicationEvent, Connection, ConnectionEvent, PeerStream, StreamAcceptor};
pub use endpoint::{
    Client, ClientBuilder, ConnectionIdGenerator, DefaultConnectionIdGenerator,
    DefaultStatelessResetTokenGenerator, Server, ServerBuilder, StatelessResetTokenGenerator,
};
pub use error::{ConnectionError, Error, StartError, StreamError};
pub use path::{NetworkEvent, NewPath, PathEvent, PathHandle, PathSnapshot};
pub use stream::{BidirectionalStream, ReceiveStream, SendStream, StreamChunk, StreamRead};

// core の型を再エクスポート
pub use tobi_core::path::PathStatus;
pub use tobi_core::path::state::PathState;
pub use tobi_core::scheduler::{
    AckPathPolicyKind, DataSchedulerKind, RetransmissionPolicyKind, SchedulerConfig,
};
pub use tobi_core::stats::{ConnectionStats, PathStats};

// qlog クレートから factory トレイトを再エクスポート
pub use tobi_qlog::{QlogWriter, QlogWriterFactory};

// --- 内部クレートの re-export (Sans I/O 層の直接利用向け) ---
pub use tobi_core as core;
pub use tobi_transport as transport;
