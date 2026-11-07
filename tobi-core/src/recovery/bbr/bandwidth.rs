// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 帯域幅型 (BBRv2/BBRv3 共通)
//!
//! draft-ietf-ccwg-bbr-06 で使用される帯域幅 (bytes/sec) を型安全に扱う。

use crate::time::Duration;

/// 帯域幅 (bytes/sec)
///
/// BBR の帯域推定で使用する。ゼロ除算や単位混同を防ぐための型ラッパー。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bandwidth(u64);

impl Bandwidth {
    /// ゼロ帯域幅
    pub const ZERO: Self = Self(0);

    /// 無限大帯域幅 (初期値などに使用)
    pub const INFINITE: Self = Self(u64::MAX);

    /// bytes/sec から生成する
    pub const fn from_bytes_per_second(bps: u64) -> Self {
        Self(bps)
    }

    /// bytes と Duration から帯域幅を計算する
    ///
    /// interval がゼロの場合は INFINITE を返す。
    pub fn from_bytes_and_interval(bytes: u64, interval: Duration) -> Self {
        let micros = interval.as_micros();
        if micros == 0 {
            return Self::INFINITE;
        }
        // bytes / interval (秒) = bytes * 1_000_000 / interval (マイクロ秒)
        // オーバーフロー対策: u128 を経由する
        let bps = (bytes as u128 * 1_000_000) / micros as u128;
        Self(bps.min(u64::MAX as u128) as u64)
    }

    /// bytes/sec を返す
    pub const fn as_bytes_per_second(self) -> u64 {
        self.0
    }

    /// 帯域幅にゲイン (分子/分母) を乗じる
    ///
    /// BBR の pacing_gain や cwnd_gain の適用に使う。
    pub fn mul_ratio(self, numerator: u64, denominator: u64) -> Self {
        debug_assert!(denominator > 0, "denominator must be non-zero");
        let result = (self.0 as u128 * numerator as u128) / denominator as u128;
        Self(result.min(u64::MAX as u128) as u64)
    }

    /// 帯域幅と Duration の積でバイト数を計算する
    ///
    /// target_cwnd = bw * min_rtt のような計算に使う。
    pub fn bytes_for_duration(self, duration: Duration) -> u64 {
        let micros = duration.as_micros();
        // bw (bytes/sec) * duration (sec) = bw * duration_us / 1_000_000
        let result = (self.0 as u128 * micros as u128) / 1_000_000;
        result.min(u64::MAX as u128) as u64
    }

    /// 2 つの帯域幅の小さい方を返す
    pub fn min(self, other: Self) -> Self {
        if self.0 <= other.0 { self } else { other }
    }

    /// 2 つの帯域幅の大きい方を返す
    pub fn max(self, other: Self) -> Self {
        if self.0 >= other.0 { self } else { other }
    }
}

impl Default for Bandwidth {
    fn default() -> Self {
        Self::ZERO
    }
}

impl core::fmt::Display for Bandwidth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.0 >= 1_000_000_000 {
            write!(f, "{:.2} Gbps", self.0 as f64 * 8.0 / 1_000_000_000.0)
        } else if self.0 >= 1_000_000 {
            write!(f, "{:.2} Mbps", self.0 as f64 * 8.0 / 1_000_000.0)
        } else if self.0 >= 1_000 {
            write!(f, "{:.2} Kbps", self.0 as f64 * 8.0 / 1_000.0)
        } else {
            write!(f, "{} bps", self.0 * 8)
        }
    }
}
