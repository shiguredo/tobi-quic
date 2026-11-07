// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! BBR 輻輳制御 共通基盤
//!
//! BBRv2 (draft-cardwell-iccrg-bbr-congestion-control-02) と
//! BBRv3 (draft-ietf-ccwg-bbr-06) で共有する型とモジュール。

use crate::time::Duration;

pub mod bandwidth;
pub mod bbrv2;
pub mod bbrv3;
pub mod delivery_rate;
pub(crate) mod rng;

pub use bandwidth::Bandwidth;
pub use bbrv2::{BbrV2, BbrV2Factory};
pub use bbrv3::{BbrV3, BbrV3Factory};
pub use delivery_rate::{DeliveryRateEstimator, PacketDeliveryState, RateSample};

/// 初期の平滑化 RTT (RFC 9002 Section 5.3)
///
/// BBR の InitPacingRate は OnInit の時点でこの値を使って初期 pacing rate を
/// 設定する (draft-ietf-ccwg-bbr-06 Section 5.1)。
pub(crate) const INITIAL_SRTT: Duration = Duration::from_millis(333);
