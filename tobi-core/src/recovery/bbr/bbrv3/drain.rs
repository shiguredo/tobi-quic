// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Drain フェーズ定数 (draft-ietf-ccwg-bbr-06 Section 5.3.2)

/// Drain pacing gain (1/StartupCwndGain = 0.5)
pub const PACING_GAIN_NUM: u64 = 1;
pub const PACING_GAIN_DEN: u64 = 2;

/// Drain cwnd gain (2.0)
pub const CWND_GAIN_NUM: u64 = 2;
pub const CWND_GAIN_DEN: u64 = 1;
