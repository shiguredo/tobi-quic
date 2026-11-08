// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! ProbeBW 状態マシン (draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.3)
//!
//! BBR の定常状態。4 フェーズサイクル (Down → Cruise → Refill → Up) で
//! 帯域を継続的にプローブする。
//! Multipath QUIC ではパスごとに独立した ProbeBW サイクルを実行する。

use crate::recovery::bbr::rng::Rng;
use crate::time::{Duration, Timestamp};

// ---------------------------------------------------------------------------
// ProbeBW ゲイン定数
// ---------------------------------------------------------------------------

/// ProbeBW_DOWN pacing gain (0.9)
const DOWN_PACING_GAIN_NUM: u64 = 9;
const DOWN_PACING_GAIN_DEN: u64 = 10;

/// ProbeBW_UP pacing gain (1.25)
const UP_PACING_GAIN_NUM: u64 = 5;
const UP_PACING_GAIN_DEN: u64 = 4;

/// ProbeBW cwnd gain (2.0)
const CWND_GAIN_NUM: u64 = 2;
const CWND_GAIN_DEN: u64 = 1;

/// Reno 共存の最大ラウンド数
const MAX_BW_PROBE_ROUNDS: u64 = 63;

/// inflight_hi の指数増加の最大ラウンド数
const MAX_BW_PROBE_UP_ROUNDS: u8 = 30;

// ---------------------------------------------------------------------------
// 列挙型
// ---------------------------------------------------------------------------

/// ProbeBW のサイクルフェーズ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CyclePhase {
    /// キュー排出 (pacing_gain = 0.9)
    Down,
    /// 帯域一致 (pacing_gain = 1.0)
    Cruise,
    /// パイプ再充填 (pacing_gain = 1.0)
    Refill,
    /// 帯域プローブ (pacing_gain = 1.25)
    Up,
}

/// ACK の到着がプローブとどう関連するか
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckPhase {
    /// プローブ停止中 (DOWN/CRUISE)
    ProbesStopping,
    /// パイプ再充填中 (REFILL)
    Refilling,
    /// プローブ開始 (UP の最初のラウンド)
    ProbeStarting,
    /// プローブフィードバック受信中 (UP の 2 ラウンド目以降)
    ProbeFeedback,
}

// ---------------------------------------------------------------------------
// ProbeBW 状態
// ---------------------------------------------------------------------------

/// ProbeBW の状態
#[derive(Debug)]
pub struct State {
    /// 現在のサイクルフェーズ
    phase: CyclePhase,

    /// ACK フェーズ
    ack_phase: AckPhase,

    /// bw プローブの待機時間
    bw_probe_wait: Duration,

    /// bw プローブからのラウンド数
    rounds_since_bw_probe: u64,

    /// inflight_hi の指数増加のラウンド数
    bw_probe_up_rounds: u8,

    /// 増加プローブ中の ACK バイト数の累積 (newly_acked の合計)
    bw_probe_up_acks: u64,

    /// inflight_hi の増加しきい値 (無次元カウント)
    ///
    /// `cwnd / (MSS << bw_probe_up_rounds)` で計算する無次元のカウントであり、
    /// バイト数ではない。draft は ACK バイト数の累積である `bw_probe_up_acks`
    /// とこのカウントをそのまま比較するため、実装も同じ単位で比較し、その商
    /// (バイト数) だけ inflight_hi を増やす。
    /// None = UP フェーズ未開始
    probe_up_cnt: Option<u64>,

    /// サイクル開始のタイムスタンプ
    cycle_stamp: Option<Timestamp>,

    /// プローブサンプルが有効か
    bw_probe_samples: bool,
}

impl State {
    /// 新しい ProbeBW 状態を作成する (Down フェーズで初期化)
    pub fn new() -> Self {
        Self {
            phase: CyclePhase::Down,
            ack_phase: AckPhase::ProbesStopping,
            bw_probe_wait: Duration::ZERO,
            rounds_since_bw_probe: 0,
            bw_probe_up_rounds: 0,
            bw_probe_up_acks: 0,
            probe_up_cnt: None,
            cycle_stamp: None,
            bw_probe_samples: false,
        }
    }

    // --- アクセサ ---

    /// 現在のサイクルフェーズを返す
    pub fn phase(&self) -> CyclePhase {
        self.phase
    }

    /// ACK フェーズを返す
    pub fn ack_phase(&self) -> AckPhase {
        self.ack_phase
    }

    /// プローブサンプルが有効かを返す
    pub fn bw_probe_samples(&self) -> bool {
        self.bw_probe_samples
    }

    /// pacing gain を返す (分子, 分母)
    pub fn pacing_gain(&self) -> (u64, u64) {
        match self.phase {
            CyclePhase::Down => (DOWN_PACING_GAIN_NUM, DOWN_PACING_GAIN_DEN),
            CyclePhase::Cruise | CyclePhase::Refill => (1, 1),
            CyclePhase::Up => (UP_PACING_GAIN_NUM, UP_PACING_GAIN_DEN),
        }
    }

    /// cwnd gain を返す (分子, 分母)
    pub fn cwnd_gain(&self) -> (u64, u64) {
        (CWND_GAIN_NUM, CWND_GAIN_DEN)
    }

    // --- フェーズ遷移 ---

    /// Down フェーズに遷移する。cycle_stamp は呼び出し側が設定する
    pub fn start_down(&mut self, rng: &mut Rng) {
        self.probe_up_cnt = None;
        self.rounds_since_bw_probe = 0;
        self.pick_probe_wait(rng);
        self.cycle_stamp = None;
        self.ack_phase = AckPhase::ProbesStopping;
        self.phase = CyclePhase::Down;
    }

    /// Cruise フェーズに遷移する
    pub fn start_cruise(&mut self) {
        self.phase = CyclePhase::Cruise;
    }

    /// Refill フェーズに遷移する
    pub fn start_refill(&mut self) {
        self.bw_probe_up_rounds = 0;
        self.bw_probe_up_acks = 0;
        self.ack_phase = AckPhase::Refilling;
        self.phase = CyclePhase::Refill;
    }

    /// Up フェーズに遷移する
    pub fn start_up(&mut self, now: Timestamp, cwnd: u64, max_datagram_size: u64) {
        self.ack_phase = AckPhase::ProbeStarting;
        self.cycle_stamp = Some(now);
        self.phase = CyclePhase::Up;
        self.raise_inflight_hi_slope(cwnd, max_datagram_size);
    }

    // --- タイミング ---

    /// フェーズ内で指定の時間が経過したかを返す
    pub fn has_elapsed_in_phase(&self, interval: Duration, now: Timestamp) -> bool {
        match self.cycle_stamp {
            Some(stamp) => now >= stamp + interval,
            None => true,
        }
    }

    /// bw プローブの時期かを判定する
    pub fn is_time_to_probe_bw(
        &self,
        now: Timestamp,
        target_inflight: u64,
        max_datagram_size: u64,
    ) -> bool {
        self.has_elapsed_in_phase(self.bw_probe_wait, now)
            || self.is_reno_coexistence_probe_time(target_inflight, max_datagram_size)
    }

    /// Reno 共存のプローブタイミングかを判定する
    fn is_reno_coexistence_probe_time(&self, target_inflight: u64, max_datagram_size: u64) -> bool {
        if max_datagram_size == 0 {
            return false;
        }
        let reno_rounds = target_inflight / max_datagram_size;
        let rounds = reno_rounds.min(MAX_BW_PROBE_ROUNDS);
        self.rounds_since_bw_probe >= rounds
    }

    /// Cruise に遷移する時期かを判定する
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

    /// プローブ待ち時間をランダムに選択する
    ///
    /// draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.3.5:
    /// bw_probe_wait = 2s + random(0..1s)
    fn pick_probe_wait(&mut self, rng: &mut Rng) {
        self.rounds_since_bw_probe = rng.gen_range(2); // 0 or 1
        let extra_ms = rng.gen_range(1001); // 0..1000 ms
        self.bw_probe_wait = Duration::from_secs(2) + Duration::from_millis(extra_ms);
    }

    /// サイクル開始タイムスタンプを設定する
    pub fn set_cycle_stamp(&mut self, now: Timestamp) {
        self.cycle_stamp = Some(now);
    }

    // --- ラウンドイベント ---

    /// ラウンド開始時にカウンタを更新する
    pub fn on_round_start(&mut self) {
        self.rounds_since_bw_probe += 1;
    }

    /// ACK フェーズを更新する (ラウンド開始時)
    pub fn update_ack_phase_on_round_start(&mut self) {
        if self.ack_phase == AckPhase::ProbeStarting {
            self.ack_phase = AckPhase::ProbeFeedback;
        }
    }

    /// ProbesStopping の ACK フェーズ更新 (ラウンド開始時)
    /// MaxBwFilter を advance すべきかを返す
    pub fn should_advance_max_bw_filter(&self, is_app_limited: bool) -> bool {
        self.ack_phase == AckPhase::ProbesStopping && !is_app_limited
    }

    // --- inflight_hi プローブ ---

    /// inflight_hi を段階的に引き上げる
    ///
    /// draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.3.6 の
    /// BBRProbeInflightHiUpward()。cwnd 律速で cwnd が inflight_hi 以上の
    /// ときだけ、この ACK で新たに ACK されたバイト数 (`newly_acked`) を
    /// `bw_probe_up_acks` に積む。`bw_probe_up_acks` が `probe_up_cnt` に
    /// 達するごとに、その商 (バイト数) だけ inflight_hi を増やし、傾き
    /// (`probe_up_cnt`) の更新はラウンド開始時だけ行う。
    ///
    /// 戻り値は inflight_hi の増加量 (バイト)。
    pub(crate) fn probe_inflight_hi_upward(
        &mut self,
        newly_acked: u64,
        cwnd: u64,
        cwnd_limited_in_round: bool,
        inflight_hi: u64,
        max_datagram_size: u64,
        round_start: bool,
    ) -> u64 {
        if !cwnd_limited_in_round || cwnd < inflight_hi {
            return 0;
        }
        self.bw_probe_up_acks += newly_acked;
        let mut delta_bytes = 0u64;
        if let Some(cnt) = self.probe_up_cnt
            && cnt > 0
            && self.bw_probe_up_acks >= cnt
        {
            // draft のとおり、増分は ACK バイト数をしきい値で割った商 (バイト数)。
            // ここで MSS を掛けると増分が過大になる。
            let delta = self.bw_probe_up_acks / cnt;
            self.bw_probe_up_acks -= delta * cnt;
            delta_bytes = delta;
        }
        // draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.3.6:
        // BBRRaiseInflightHiSlope() は BBR.round_start のときだけ呼ぶ。
        if round_start {
            self.raise_inflight_hi_slope(cwnd, max_datagram_size);
        }
        delta_bytes
    }

    /// inflight_hi の増加スロープを設定する
    ///
    /// draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.3.6 の
    /// BBRRaiseInflightHiSlope():
    ///   growth_this_round = 1MSS << bw_probe_up_rounds
    ///   bw_probe_up_rounds = min(bw_probe_up_rounds + 1, 30)
    ///   probe_up_cnt = max(cwnd / growth_this_round, 1)
    /// `probe_up_cnt` は `cwnd / growth_this_round` で求める無次元カウントで
    /// あり、バイト数ではない。`bw_probe_up_acks` (ACK バイト数の累積) と
    /// そのまま比較する。
    fn raise_inflight_hi_slope(&mut self, cwnd: u64, max_datagram_size: u64) {
        let growth_this_round = max_datagram_size
            .checked_shl((self.bw_probe_up_rounds as u32).min(30))
            .unwrap_or(0);
        self.bw_probe_up_rounds = self
            .bw_probe_up_rounds
            .saturating_add(1)
            .min(MAX_BW_PROBE_UP_ROUNDS);
        if let Some(cnt) = cwnd.checked_div(growth_this_round) {
            self.probe_up_cnt = Some(cnt.max(1));
        }
    }

    /// bw_probe_samples フラグを設定する
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
