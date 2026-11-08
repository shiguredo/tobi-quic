// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! BBRv3 ProbeBW 状態マシン (draft-ietf-ccwg-bbr-06 Section 5.3.3)
//!
//! BBRv2 との差分:
//! - ProbeBW_UP cwnd_gain: 2.0 → 2.25

use crate::recovery::bbr::rng::Rng;
use crate::time::{Duration, Timestamp};

/// ProbeBW_DOWN pacing gain (0.9)
const DOWN_PACING_GAIN_NUM: u64 = 9;
const DOWN_PACING_GAIN_DEN: u64 = 10;

/// ProbeBW_UP pacing gain (1.25)
const UP_PACING_GAIN_NUM: u64 = 5;
const UP_PACING_GAIN_DEN: u64 = 4;

/// ProbeBW cwnd gain (2.0)
const CWND_GAIN_NUM: u64 = 2;
const CWND_GAIN_DEN: u64 = 1;

/// ProbeBW_UP cwnd gain (2.25)
/// BBRv3 差分: BBRv2 の 2.0 から 2.25 に変更
const UP_CWND_GAIN_NUM: u64 = 9;
const UP_CWND_GAIN_DEN: u64 = 4;

const MAX_BW_PROBE_ROUNDS: u64 = 63;
const MAX_BW_PROBE_UP_ROUNDS: u8 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CyclePhase {
    Down,
    Cruise,
    Refill,
    Up,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckPhase {
    /// 帯域プローブを行っておらず、プローブのフィードバックも受けていない
    ///
    /// draft-ietf-ccwg-bbr-06 Section 2.14: ACKS_INIT
    AcksInit,
    /// 推定帯域でパイプを満たしている (ACKS_REFILLING)
    Refilling,
    /// inflight を増やして帯域をプローブし始めた (ACKS_PROBE_STARTING)
    ProbeStarting,
    /// 帯域プローブのフィードバックを受け取っている (ACKS_PROBE_FEEDBACK)
    ProbeFeedback,
    /// 帯域プローブを止めたが、まだフィードバックを受け取っている
    /// (ACKS_PROBE_STOPPING)
    ProbesStopping,
}

#[derive(Debug)]
pub struct State {
    phase: CyclePhase,
    ack_phase: AckPhase,
    bw_probe_wait: Duration,
    rounds_since_bw_probe: u64,
    bw_probe_up_rounds: u8,
    bw_probe_up_acked: u64,
    /// inflight_longterm を 1 SMSS 増やすために必要な ACK バイト数
    ///
    /// None = UP フェーズ未開始
    probe_up_acked_per_inc: Option<u64>,
    cycle_stamp: Option<Timestamp>,
    bw_probe_samples: bool,
    /// 直前の帯域プローブで過剰ロストが発生したか (Section 2.14)
    prev_probe_too_high: bool,
    /// 直前の ProbeBW_UP を inflight_longterm 到達で切り上げたか (Section 2.14)
    prev_probe_precautionary: bool,
}

impl State {
    pub fn new() -> Self {
        Self {
            phase: CyclePhase::Down,
            // draft-ietf-ccwg-bbr-06 Section 5.2.1 OnInit: ack_phase = ACKS_INIT
            ack_phase: AckPhase::AcksInit,
            bw_probe_wait: Duration::ZERO,
            rounds_since_bw_probe: 0,
            bw_probe_up_rounds: 0,
            bw_probe_up_acked: 0,
            probe_up_acked_per_inc: None,
            cycle_stamp: None,
            bw_probe_samples: false,
            prev_probe_too_high: false,
            prev_probe_precautionary: false,
        }
    }

    pub fn phase(&self) -> CyclePhase {
        self.phase
    }

    pub fn ack_phase(&self) -> AckPhase {
        self.ack_phase
    }

    pub fn bw_probe_samples(&self) -> bool {
        self.bw_probe_samples
    }

    /// 直前の帯域プローブで過剰ロストが発生したか (Section 2.14)
    pub fn prev_probe_too_high(&self) -> bool {
        self.prev_probe_too_high
    }

    /// 直前の ProbeBW_UP を inflight_longterm 到達で切り上げたか (Section 2.14)
    pub fn prev_probe_precautionary(&self) -> bool {
        self.prev_probe_precautionary
    }

    /// 過剰ロストの発生を記録する (Section 5.3.3 の HandleInflightTooHigh)
    pub fn set_prev_probe_too_high(&mut self, value: bool) {
        self.prev_probe_too_high = value;
    }

    /// 慎重なプローブの実施を記録する (Section 5.3.3.6 の減速)
    pub fn set_prev_probe_precautionary(&mut self, value: bool) {
        self.prev_probe_precautionary = value;
    }

    pub fn pacing_gain(&self) -> (u64, u64) {
        match self.phase {
            CyclePhase::Down => (DOWN_PACING_GAIN_NUM, DOWN_PACING_GAIN_DEN),
            CyclePhase::Cruise | CyclePhase::Refill => (1, 1),
            CyclePhase::Up => (UP_PACING_GAIN_NUM, UP_PACING_GAIN_DEN),
        }
    }

    /// cwnd gain を返す
    ///
    /// BBRv3 差分: UP フェーズでは 2.25 を使用する
    pub fn cwnd_gain(&self) -> (u64, u64) {
        match self.phase {
            CyclePhase::Up => (UP_CWND_GAIN_NUM, UP_CWND_GAIN_DEN),
            _ => (CWND_GAIN_NUM, CWND_GAIN_DEN),
        }
    }

    /// Down フェーズに遷移する。cycle_stamp は呼び出し側が設定する
    pub fn start_down(&mut self, rng: &mut Rng) {
        self.probe_up_acked_per_inc = None;
        self.pick_probe_wait(rng);
        self.cycle_stamp = None;
        self.ack_phase = AckPhase::ProbesStopping;
        self.phase = CyclePhase::Down;
    }

    pub fn start_cruise(&mut self) {
        self.phase = CyclePhase::Cruise;
    }

    pub fn start_refill(&mut self) {
        self.bw_probe_up_rounds = 0;
        self.bw_probe_up_acked = 0;
        // 慎重なプローブ (precautionary) はここで完了する (Section 5.3.3.6 の加速)
        self.prev_probe_precautionary = false;
        self.ack_phase = AckPhase::Refilling;
        self.phase = CyclePhase::Refill;
    }

    pub fn start_up(&mut self, now: Timestamp, cwnd: u64, max_datagram_size: u64) {
        self.ack_phase = AckPhase::ProbeStarting;
        self.cycle_stamp = Some(now);
        self.phase = CyclePhase::Up;
        self.raise_inflight_longterm_slope(cwnd, max_datagram_size);
    }

    pub fn has_elapsed_in_phase(&self, interval: Duration, now: Timestamp) -> bool {
        match self.cycle_stamp {
            Some(stamp) => now >= stamp + interval,
            None => true,
        }
    }

    pub fn is_time_to_probe_bw(
        &self,
        now: Timestamp,
        target_inflight: u64,
        max_datagram_size: u64,
    ) -> bool {
        self.has_elapsed_in_phase(self.bw_probe_wait, now)
            || self.is_reno_coexistence_probe_time(target_inflight, max_datagram_size)
    }

    fn is_reno_coexistence_probe_time(&self, target_inflight: u64, max_datagram_size: u64) -> bool {
        if max_datagram_size == 0 {
            return false;
        }
        let reno_rounds = target_inflight / max_datagram_size;
        let rounds = reno_rounds.min(MAX_BW_PROBE_ROUNDS);
        self.rounds_since_bw_probe >= rounds
    }

    pub fn check_time_to_cruise(
        &self,
        bytes_in_flight: u64,
        inflight_with_headroom: u64,
        inflight_1x: u64,
    ) -> bool {
        if bytes_in_flight > inflight_with_headroom {
            return false;
        }
        bytes_in_flight <= inflight_1x
    }

    fn pick_probe_wait(&mut self, rng: &mut Rng) {
        self.rounds_since_bw_probe = rng.gen_range(2);
        let extra_ms = rng.gen_range(1001);
        self.bw_probe_wait = Duration::from_secs(2) + Duration::from_millis(extra_ms);
    }

    pub fn set_cycle_stamp(&mut self, now: Timestamp) {
        self.cycle_stamp = Some(now);
    }

    pub fn on_round_start(&mut self) {
        self.rounds_since_bw_probe += 1;
    }

    /// ACK フェーズをラウンド開始時に更新する
    ///
    /// draft-ietf-ccwg-bbr-06 Section 5.3.3.9 の AdaptLongTermModel の前半:
    /// - ACKS_PROBE_STARTING → ACKS_PROBE_FEEDBACK
    /// - ACKS_PROBE_STOPPING → ACKS_INIT (
    ///   このとき is_bw_probe_sample を false に戻す)
    ///
    /// 戻り値は max_bw フィルタを進めるべきかどうか。
    /// ACKS_PROBE_STOPPING から ACKS_INIT へ遷移したラウンドでのみ true を返す。
    /// これにより cycle_count は ProbeBW サイクルごとに 1 回だけ進み、
    /// max_bw フィルタの窓が 2 ProbeBW サイクル分になる
    /// (Section 5.5.3, Section 5.5.6)。
    pub fn update_ack_phase_on_round_start(&mut self) -> bool {
        match self.ack_phase {
            AckPhase::ProbeStarting => {
                self.ack_phase = AckPhase::ProbeFeedback;
                false
            }
            AckPhase::ProbesStopping => {
                // プローブフェーズのサンプル受信が終わった
                self.bw_probe_samples = false;
                self.ack_phase = AckPhase::AcksInit;
                true
            }
            AckPhase::AcksInit | AckPhase::Refilling | AckPhase::ProbeFeedback => false,
        }
    }

    /// inflight_longterm を上方向にプローブする (Section 5.3.3 の ProbeInflightLongtermUpward)
    ///
    /// 戻り値は inflight_longterm の増加量 (バイト)。1 増分あたり
    /// `probe_up_acked_per_inc` バイトの ACK で 1 SMSS 増加する。
    pub fn probe_inflight_longterm_upward(
        &mut self,
        newly_acked: u64,
        cwnd: u64,
        cwnd_limited_in_round: bool,
        inflight_longterm: u64,
        max_datagram_size: u64,
        round_start: bool,
    ) -> u64 {
        if !cwnd_limited_in_round || cwnd < inflight_longterm {
            return 0;
        }
        self.bw_probe_up_acked += newly_acked;
        let mut delta_bytes = 0u64;
        if let Some(per_inc) = self.probe_up_acked_per_inc
            && per_inc > 0
            && self.bw_probe_up_acked >= per_inc
        {
            let delta = self.bw_probe_up_acked / per_inc;
            self.bw_probe_up_acked -= delta * per_inc;
            delta_bytes = delta * max_datagram_size;
        }
        // 傾きの更新はラウンド開始時のみ行う (Section 5.3.3)
        if round_start {
            self.raise_inflight_longterm_slope(cwnd, max_datagram_size);
        }
        delta_bytes
    }

    /// 次ラウンドで inflight_longterm を増やす傾きを設定する
    ///
    /// `growth_this_round` は SMSS 単位の増加量 (1, 2, 4, 8, ...) であり、
    /// 1 増分あたりに ACK される必要のあるバイト数は
    /// `max(cwnd / growth_this_round, SMSS)` になる (Section 5.3.3)。
    fn raise_inflight_longterm_slope(&mut self, cwnd: u64, max_datagram_size: u64) {
        let growth_this_round = 1u64 << (self.bw_probe_up_rounds as u32).min(30);
        self.bw_probe_up_rounds = self
            .bw_probe_up_rounds
            .saturating_add(1)
            .min(MAX_BW_PROBE_UP_ROUNDS);
        let per_inc = cwnd
            .checked_div(growth_this_round)
            .unwrap_or(0)
            .max(max_datagram_size);
        self.probe_up_acked_per_inc = Some(per_inc);
    }

    pub fn set_bw_probe_samples(&mut self, value: bool) {
        self.bw_probe_samples = value;
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
