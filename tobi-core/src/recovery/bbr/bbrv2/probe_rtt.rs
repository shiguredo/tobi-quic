// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! ProbeRTT 状態マシン (draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.4)
//!
//! min_rtt 測定のためにパス帯域を一時的に低下させる。
//! Multipath QUIC ではパスごとに独立した ProbeRTT サイクルを持つ。

use crate::time::{Duration, Timestamp};

/// ProbeRTT 最小継続時間 (200ms)
pub const DURATION: Duration = Duration::from_millis(200);

/// ProbeRTT cwnd gain (0.5)
pub const CWND_GAIN_NUM: u64 = 1;
pub const CWND_GAIN_DEN: u64 = 2;

/// ProbeRTT の状態
///
/// ProbeRTT 中の done_stamp と round_done を追跡する。
#[derive(Debug)]
pub struct State {
    /// ProbeRTT 完了予定時刻 (now + DURATION)
    done_stamp: Option<Timestamp>,

    /// 1 ラウンド経過したか
    round_done: bool,
}

impl State {
    /// 新しい ProbeRTT 状態を作成する
    pub fn new() -> Self {
        Self {
            done_stamp: None,
            round_done: false,
        }
    }

    /// ProbeRTT に入る
    pub fn enter(&mut self) {
        self.done_stamp = None;
        self.round_done = false;
    }

    /// ProbeRTT 中の処理を行う
    ///
    /// inflight が probe_rtt_cwnd 以下になったら done_stamp を設定し、
    /// 1 ラウンド + DURATION 経過で完了とする。
    pub fn handle(
        &mut self,
        bytes_in_flight: u64,
        probe_rtt_cwnd: u64,
        now: Timestamp,
        round_start: bool,
    ) {
        if self.done_stamp.is_none() && bytes_in_flight <= probe_rtt_cwnd {
            self.done_stamp = Some(now + DURATION);
            self.round_done = false;
        } else if self.done_stamp.is_some() && round_start {
            self.round_done = true;
        }
    }

    /// ProbeRTT が完了したかを返す
    ///
    /// done_stamp が設定され、時刻が経過し、かつ 1 ラウンド経過した場合に true。
    pub fn is_done(&self, now: Timestamp) -> bool {
        if let Some(done_stamp) = self.done_stamp {
            self.round_done && now >= done_stamp
        } else {
            false
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
