// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Startup フェーズ定数 (draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.1)
//!
//! 帯域の上限を指数的に探索する初期フェーズ。
//! pacing gain = 2.77 (4*ln(2)) で帯域を毎ラウンド 2 倍にする。

/// Startup pacing gain (2.77 ≈ 4*ln(2))
///
/// 帯域を毎ラウンド 2 倍にする最小ゲイン。
pub const PACING_GAIN_NUM: u64 = 277;
pub const PACING_GAIN_DEN: u64 = 100;

/// Startup cwnd gain (2.0)
pub const CWND_GAIN_NUM: u64 = 2;
pub const CWND_GAIN_DEN: u64 = 1;
