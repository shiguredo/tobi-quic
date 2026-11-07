// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 損失検出と回復 (RFC 9002)
//!
//! Multipath First: 全コンポーネントはパスごとに独立したインスタンスを持つ。

pub mod ack_tracker;
pub mod bbr;
pub mod congestion;
pub mod cubic;
pub mod loss_detection;
pub mod pacing;
pub mod rtt;
pub mod sent_packets;
pub mod windowed_filter;

pub use ack_tracker::AckTracker;
pub use bbr::{BbrV2, BbrV2Factory, BbrV3, BbrV3Factory};
pub use congestion::{
    AckedPacketInfo, CongestionControl, CongestionControlAlgorithm, CongestionControlFactory,
    CongestionControlFactoryImpl, CongestionControlImpl, CongestionState, CongestionStateKind,
    IdleReason, LostPacketInfo, NewReno, NewRenoFactory,
};
pub use cubic::{Cubic, CubicFactory, CubicState};
pub use loss_detection::{LossDetector, LossDetectors, PacketNumberSpace};
pub use pacing::Pacer;
pub use rtt::RttEstimator;
pub use sent_packets::SentPackets;

/// 初期ウィンドウを計算する (RFC 9002 Section 7.2)
///
/// initial_window = min(10 * max_datagram_size, max(14720, 2 * max_datagram_size))
pub fn initial_window(max_datagram_size: u64) -> u64 {
    let a = 10 * max_datagram_size;
    let b = (14720u64).max(2 * max_datagram_size);
    a.min(b)
}

/// 最小ウィンドウを計算する (RFC 9002 Section 7.2)
pub fn minimum_window(max_datagram_size: u64) -> u64 {
    2 * max_datagram_size
}
