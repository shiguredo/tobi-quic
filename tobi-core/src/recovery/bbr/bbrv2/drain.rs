// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Drain フェーズ定数 (draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.2)
//!
//! Startup で蓄積したキューを排出するフェーズ。
//! pacing gain = 0.5 (1/StartupCwndGain) で 1 ラウンドでキューを排出する。

/// Drain pacing gain (1/StartupCwndGain = 0.5)
///
/// Startup で溜まったキューを 1 ラウンドで排出する。
pub const PACING_GAIN_NUM: u64 = 1;
pub const PACING_GAIN_DEN: u64 = 2;

/// Drain cwnd gain (Startup と同じ 2.0)
///
/// cwnd は維持し、pacing rate で排出を制御する。
pub const CWND_GAIN_NUM: u64 = 2;
pub const CWND_GAIN_DEN: u64 = 1;
