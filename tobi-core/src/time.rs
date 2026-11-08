// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! タイムスタンプとデュレーション型
//!
//! Sans I/O のため std::time::Instant に依存しない。
//! アプリケーションから渡されるマイクロ秒単位の単調増加値を使用する。

/// マイクロ秒単位の単調増加タイムスタンプ
///
/// アプリケーションが提供する時刻値を保持する。
/// 具体的なエポックはアプリケーション依存。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    /// マイクロ秒値からタイムスタンプを生成する
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    /// マイクロ秒値を返す
    pub const fn as_micros(self) -> u64 {
        self.0
    }

    /// Duration を加算する
    ///
    /// overflow 時は `u64::MAX` に飽和する。RFC 9002 の PTO backoff など、
    /// 連続する指数的増加で理論上は u64 範囲を超え得る経路があるため、
    /// panic せず飽和挙動にする。
    pub const fn add(self, duration: Duration) -> Self {
        Self(self.0.saturating_add(duration.0))
    }

    /// 2 つのタイムスタンプの差を Duration として返す
    ///
    /// self が other より前の場合は Duration(0) を返す
    pub const fn saturating_duration_since(self, other: Self) -> Duration {
        Duration(self.0.saturating_sub(other.0))
    }

    /// other 以降かどうかを返す
    pub const fn has_elapsed(self, other: Self) -> bool {
        self.0 >= other.0
    }
}

/// マイクロ秒単位のデュレーション
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration(u64);

impl Duration {
    pub const ZERO: Self = Self(0);

    /// マイクロ秒値からデュレーションを生成する
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    /// ミリ秒値からデュレーションを生成する
    ///
    /// overflow 時は `u64::MAX` マイクロ秒に飽和する。ピアが RFC 9000 の MUST 範囲を
    /// 逸脱した値 (例: `max_ack_delay = 2^62`) を送ってきた場合でも panic させない。
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis.saturating_mul(1000))
    }

    /// 秒値からデュレーションを生成する
    ///
    /// overflow 時は `u64::MAX` マイクロ秒に飽和する。
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs.saturating_mul(1_000_000))
    }

    /// マイクロ秒値を返す
    pub const fn as_micros(self) -> u64 {
        self.0
    }

    /// ミリ秒値を返す (端数切り捨て)
    pub const fn as_millis(self) -> u64 {
        self.0 / 1000
    }

    /// 定数倍する
    ///
    /// overflow 時は `u64::MAX` に飽和する。
    pub const fn mul(self, factor: u32) -> Self {
        Self(self.0.saturating_mul(factor as u64))
    }

    /// 飽和加算
    pub const fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// 飽和減算
    pub const fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

impl core::ops::Add<Duration> for Timestamp {
    type Output = Timestamp;

    fn add(self, rhs: Duration) -> Timestamp {
        self.add(rhs)
    }
}

impl core::ops::Add for Duration {
    type Output = Duration;

    fn add(self, rhs: Duration) -> Duration {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl core::ops::Sub for Timestamp {
    type Output = Duration;

    fn sub(self, rhs: Timestamp) -> Duration {
        self.saturating_duration_since(rhs)
    }
}
