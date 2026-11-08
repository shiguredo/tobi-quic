// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Startup フェーズ定数 (draft-ietf-ccwg-bbr-06 Section 5.3.1)

/// Startup pacing gain (2.77 ≈ 4*ln(2))
pub const PACING_GAIN_NUM: u64 = 277;
pub const PACING_GAIN_DEN: u64 = 100;

/// Startup cwnd gain (2.0)
pub const CWND_GAIN_NUM: u64 = 2;
pub const CWND_GAIN_DEN: u64 = 1;
