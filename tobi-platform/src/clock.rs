// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Timestamp <-> tokio::time::Instant 変換
//!
//! tobi_core::time::Timestamp (マイクロ秒 u64) と
//! std::time::Instant / tokio::time::Instant の変換を提供する。

use tobi_core::time::Timestamp;

/// Sans I/O の Timestamp と実時刻の変換を行うクロック
pub struct Clock {
    /// 基準時刻 (接続作成時の Instant)
    base: std::time::Instant,
}

impl Clock {
    /// 新しいクロックを作成する
    pub fn new() -> Self {
        Self {
            base: std::time::Instant::now(),
        }
    }

    /// 現在時刻を Timestamp として返す
    pub fn now(&self) -> Timestamp {
        let elapsed = self.base.elapsed();
        Timestamp::from_micros(elapsed.as_micros() as u64)
    }

    /// Timestamp を tokio::time::Instant に変換する
    pub fn to_tokio_instant(&self, ts: Timestamp) -> tokio::time::Instant {
        let duration = std::time::Duration::from_micros(ts.as_micros());
        tokio::time::Instant::from_std(self.base + duration)
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}
