// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! tobi-quic の platform クレート
//!
//! Tokio ベースの I/O ドライバーを提供する。
//! Sans I/O の Connection を tokio の UdpSocket で駆動する。

pub mod batch;
pub(crate) mod client;
pub mod clock;
pub mod config;
pub mod error;
pub mod network_monitor;
pub mod path;
pub(crate) mod server;
pub mod socket;

pub use client::QuicConnection;
pub use config::{BindOptions, ConnectOptions, DEFAULT_HANDSHAKE_TIMEOUT, UdpBatchConfig};
pub use server::{
    ConnectionShutdown, DEFAULT_ACCEPT_QUEUE_CAPACITY, QuicServer, QuicServerConnection,
};

pub(crate) mod close_log;
pub(crate) mod stop_sending;

/// Retry によるアドレス検証の設定 (RFC 9000 Section 8.1.2)
///
/// サーバーが未検証のクライアントに Retry を返し、token 付きの Initial で
/// 再接続させるための設定。
///
/// 鍵のローテーションは、新しい `RetryConfig` を作ってサーバーを再起動するか、
/// 新しい鍵で発行したトークンと旧鍵の検証を一定期間併用する運用で行う。
/// 旧鍵で発行したトークンは `max_age_secs` を過ぎると検証に失敗するため、
/// 併用期間は `max_age_secs` 以上にする。
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct RetryConfig {
    /// Retry token の AEAD 鍵 (16 バイト)
    pub token_key: [u8; 16],
    /// Retry token の有効期間 (秒)
    pub max_age_secs: u64,
}

impl RetryConfig {
    /// 新しい Retry 設定を作成する
    pub fn new(token_key: [u8; 16], max_age_secs: u64) -> Self {
        Self {
            token_key,
            max_age_secs,
        }
    }

    /// 鍵がすべてゼロでないことを検証する
    ///
    /// 長さは型で 16 バイトに固定されている。全ゼロ鍵は推測可能であり、
    /// Retry トークンを偽造できるため起動時に拒否する。
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.token_key.iter().all(|byte| *byte == 0) {
            return Err("retry token key must not be all zeros");
        }
        Ok(())
    }
}

impl std::fmt::Debug for RetryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 鍵をログや Debug 出力へ出さない
        f.debug_struct("RetryConfig")
            .field("token_key", &"[REDACTED]")
            .field("max_age_secs", &self.max_age_secs)
            .finish()
    }
}

/// CID 生成器が未設定のときに使う Connection ID 長 (後方互換)
pub(crate) const DEFAULT_CID_LEN: usize = 8;

/// Connection ID 長の上限 (RFC 9000 Section 17.2)
pub(crate) const MAX_CID_LEN: usize = 20;

/// CID 生成器の設定を検証する
///
/// RFC 9000 Section 17.2: Connection ID の長さは 0-20 バイト。0 バイトは
/// Short Header の DCID 抽出と両立しないため 1..=20 に制限する。
/// `generate()` の戻り値長が `cid_len()` と一致しない生成器も設定ミスとして拒否する。
pub(crate) fn validate_cid_generator(
    generator: &dyn tobi_core::connection::ConnectionIdGenerator,
) -> Result<(), error::Error> {
    let len = generator.cid_len();
    if !(1..=MAX_CID_LEN).contains(&len) {
        return Err(error::Error::Protocol(format!(
            "connection ID length {len} is out of range (1..={MAX_CID_LEN})"
        )));
    }
    let generated = generator.generate();
    if generated.len() != len {
        return Err(error::Error::Protocol(format!(
            "connection ID generator returned {} bytes but declares cid_len {}",
            generated.len(),
            len
        )));
    }
    Ok(())
}
