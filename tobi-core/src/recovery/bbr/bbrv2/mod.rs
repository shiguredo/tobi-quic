// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! BBRv2 輻輳制御 (draft-cardwell-iccrg-bbr-congestion-control-02)
//!
//! モデルベースの輻輳制御アルゴリズム。帯域推定と pacing により
//! bufferbloat 耐性が高く、Multipath QUIC で有効。

pub mod congestion;
pub mod data_rate;
pub mod data_volume;
pub mod drain;
pub mod full_pipe;
pub mod probe_bw;
pub mod probe_rtt;
pub mod recovery;
pub mod round;
pub mod startup;

use hashbrown::HashMap;

use crate::recovery::bbr::INITIAL_SRTT;
use crate::recovery::bbr::bandwidth::Bandwidth;
use crate::recovery::bbr::delivery_rate::{DeliveryRateEstimator, PacketDeliveryState, RateSample};
use crate::recovery::bbr::rng::Rng;
use crate::recovery::congestion::{
    AckedPacketInfo, CongestionControl, CongestionControlFactory, LostPacketInfo,
};
use crate::recovery::loss_detection::PacketNumberSpace;
use crate::recovery::pacing::Pacer;
use crate::time::{Duration, Timestamp};

// ---------------------------------------------------------------------------
// 定数 (draft-cardwell-iccrg-bbr-congestion-control-02 Section 2.8)
// ---------------------------------------------------------------------------

// --- 輻輳モデル ---

/// ロスト率閾値 (2%)
const LOSS_THRESH_NUM: u64 = 1;
const LOSS_THRESH_DEN: u64 = 50;

/// 損失時の乗算減少係数 (0.7)
const BETA_NUM: u64 = 7;
const BETA_DEN: u64 = 10;

/// ヘッドルーム係数 (0.85)
const HEADROOM_NUM: u64 = 85;
const HEADROOM_DEN: u64 = 100;

/// 最小パイプ cwnd (パケット数)
const MIN_PIPE_CWND_PACKETS: u64 = 4;

// ---------------------------------------------------------------------------
// 状態定義 (draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.1.1)
// ---------------------------------------------------------------------------

/// BBRv2 の状態マシン
///
/// 帯域探索の各フェーズを表す。
/// Multipath QUIC ではパスごとに独立した状態を持つ。
///
/// ```text
/// Startup → Drain → ProbeBW ←→ ProbeRTT
///                    (Down → Cruise → Refill → Up → Down → ...)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbrState {
    /// 帯域の上限を指数的に探索する初期フェーズ
    Startup,
    /// Startup で蓄積したキューを排出するフェーズ
    Drain,
    /// 定常状態: 4 フェーズサイクルで帯域をプローブする
    /// サイクルフェーズは probe_bw::State で管理する
    ProbeBw,
    /// 最小 RTT を計測するために inflight を最小化するフェーズ
    ProbeRtt,
}

// ---------------------------------------------------------------------------
// BbrV2 本体
// ---------------------------------------------------------------------------

/// BBRv2 輻輳制御
/// draft-cardwell-iccrg-bbr-congestion-control-02
#[derive(Debug)]
pub struct BbrV2 {
    // --- 状態マシン ---
    state: BbrState,
    probe_bw: probe_bw::State,
    full_pipe: full_pipe::Estimator,

    // --- 制御パラメータ ---
    cwnd: u64,
    prior_cwnd: u64,
    pacer: Pacer,

    // --- 帯域モデル ---
    data_rate: data_rate::Model,

    // --- inflight モデル ---
    data_volume: data_volume::Model,

    // --- ProbeRTT ---
    probe_rtt_state: probe_rtt::State,

    // --- ラウンド追跡 ---
    round: round::Counter,

    // --- 輻輳信号 ---
    congestion: congestion::State,

    // --- ロスト追跡 ---
    /// 空間ごとの最後にロストしたパケット番号 (loss burst 検出用)
    ///
    /// パケット番号は空間ごとに独立して採番されるため、空間をまたいで
    /// 連続性を判定してはならない (RFC 9000 Section 12.3)。空間ごとに
    /// 直前のロスト PN を持つことで、Initial / Handshake / Application Data
    /// のロストが交互に発生しても burst を過小カウントしない。
    last_lost_pn: [Option<u64>; PacketNumberSpace::ALL.len()],

    // --- 乱数生成 ---
    rng: Rng,

    // --- アイドル ---
    idle_restart: bool,

    // --- Delivery Rate ---
    delivery_rate: DeliveryRateEstimator,
    /// per-packet delivery state
    ///
    /// パケット番号は空間ごとに独立して採番されるため、(空間, パケット番号) の
    /// 組で管理する (RFC 9000 Section 12.3)。
    packet_states: HashMap<(PacketNumberSpace, u64), PacketDeliveryState>,

    // --- 基本パラメータ ---
    max_datagram_size: u64,
    bytes_in_flight: u64,
    initial_cwnd: u64,

    // --- Recovery ---
    recovery: recovery::State,

    cwnd_limited_in_round: bool,
}

impl BbrV2 {
    /// 新しい BBRv2 インスタンスを作成する
    pub fn new(max_datagram_size: u64) -> Self {
        let initial_cwnd = initial_window(max_datagram_size);
        let min_pipe_cwnd = MIN_PIPE_CWND_PACKETS * max_datagram_size;

        let mut s = Self {
            state: BbrState::Startup,
            probe_bw: probe_bw::State::new(),
            full_pipe: full_pipe::Estimator::new(full_pipe::STARTUP_LOSS_BURST_THRESH_BBRV2),

            cwnd: initial_cwnd,
            prior_cwnd: 0,
            pacer: Pacer::new(max_datagram_size),

            data_rate: data_rate::Model::new(),

            data_volume: data_volume::Model::new(),

            probe_rtt_state: probe_rtt::State::new(),

            round: round::Counter::new(),

            congestion: congestion::State::new(),

            last_lost_pn: [None; PacketNumberSpace::ALL.len()],

            // max_datagram_size をシードにする (パスごとに異なる作成タイミングで異なる値になる)
            rng: Rng::new(
                max_datagram_size
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1),
            ),

            idle_restart: false,

            delivery_rate: DeliveryRateEstimator::new(),
            packet_states: HashMap::new(),

            max_datagram_size,
            bytes_in_flight: 0,
            initial_cwnd,

            recovery: recovery::State::new(),

            cwnd_limited_in_round: false,
        };
        // 初期パイプ cwnd を保証する
        s.cwnd = s.cwnd.max(min_pipe_cwnd);
        // draft-ietf-ccwg-bbr-06 Section 5.1 の OnCreate / OnInit: 初期 pacing rate を
        // 初期 cwnd と初期 srtt (333ms) から設定する。
        s.init_pacing_rate(INITIAL_SRTT);
        s
    }

    // --- 状態アクセサ ---

    /// 現在の BBR 状態を返す
    pub fn state(&self) -> BbrState {
        self.state
    }

    /// 現在の状態に基づく pacing gain を返す (分子, 分母)
    fn pacing_gain(&self) -> (u64, u64) {
        match self.state {
            BbrState::Startup => (startup::PACING_GAIN_NUM, startup::PACING_GAIN_DEN),
            BbrState::Drain => (drain::PACING_GAIN_NUM, drain::PACING_GAIN_DEN),
            BbrState::ProbeBw => self.probe_bw.pacing_gain(),
            BbrState::ProbeRtt => (1, 1),
        }
    }

    /// 現在の状態に基づく cwnd gain を返す (分子, 分母)
    fn cwnd_gain(&self) -> (u64, u64) {
        match self.state {
            BbrState::Startup | BbrState::Drain => (startup::CWND_GAIN_NUM, startup::CWND_GAIN_DEN),
            BbrState::ProbeBw => self.probe_bw.cwnd_gain(),
            BbrState::ProbeRtt => (probe_rtt::CWND_GAIN_NUM, probe_rtt::CWND_GAIN_DEN),
        }
    }

    /// 最小パイプ cwnd
    fn min_pipe_cwnd(&self) -> u64 {
        MIN_PIPE_CWND_PACKETS * self.max_datagram_size
    }

    // =======================================================================
    // ラウンド追跡 (Section 4.5.1)
    // =======================================================================

    fn update_round(&mut self, rs: &RateSample) {
        let prev_count = self.round.round_count();
        self.round
            .on_ack(rs.prior_delivered, self.delivery_rate.delivered());
        if self.round.round_count() > prev_count {
            self.probe_bw.on_round_start();
        }
    }

    // =======================================================================
    // max_bw 推定 (Section 4.5.2)
    // =======================================================================

    fn update_max_bw(&mut self, rs: &RateSample) {
        self.update_round(rs);
        self.data_rate.update_max_bw(rs);
    }

    /// モデルが推定した帯域 (bytes/sec) を返す
    ///
    /// BBR の配送レート推定から得た操作帯域。公開 API やスケジューラーが
    /// パスごとの推定帯域として参照する。
    pub fn model_bandwidth(&self) -> Bandwidth {
        self.data_rate.bw()
    }

    fn max_bw(&self) -> Bandwidth {
        self.data_rate.max_bw()
    }

    // =======================================================================
    // BDP と inflight 計算 (Section 4.6.4.2)
    // =======================================================================

    /// BDP * gain を計算する
    fn bdp_multiple(&self, gain_num: u64, gain_den: u64) -> u64 {
        match self.data_volume.min_rtt() {
            None => self.initial_cwnd,
            Some(min_rtt) => {
                let bdp = self.data_rate.bw().bytes_for_duration(min_rtt);
                bdp * gain_num / gain_den
            }
        }
    }

    /// 量子化バジェットを適用する
    fn quantization_budget(&self, mut inflight: u64) -> u64 {
        // offload_budget = 3 * send_quantum
        let offload_budget = 3 * self.pacer.send_quantum();
        inflight = inflight.max(offload_budget);
        inflight = inflight.max(self.min_pipe_cwnd());
        if self.state == BbrState::ProbeBw && self.probe_bw.phase() == probe_bw::CyclePhase::Up {
            inflight += 2 * self.max_datagram_size;
        }
        inflight
    }

    /// BBRInflight(gain): BDP * gain + 量子化
    fn inflight_for_gain(&self, gain_num: u64, gain_den: u64) -> u64 {
        let inflight = self.bdp_multiple(gain_num, gain_den);
        self.quantization_budget(inflight)
    }

    /// BBRTargetInflight: min(bdp, cwnd)
    fn target_inflight(&self) -> u64 {
        let bdp = self.bdp_multiple(1, 1);
        bdp.min(self.cwnd)
    }

    /// max_inflight を更新する
    fn update_max_inflight(&self) -> u64 {
        let (cg_num, cg_den) = self.cwnd_gain();
        let mut inflight = self.bdp_multiple(cg_num, cg_den);
        inflight += self.data_volume.extra_acked();
        self.quantization_budget(inflight)
    }

    /// headroom 付き inflight
    fn inflight_with_headroom(&self) -> u64 {
        if !self.data_volume.has_inflight_hi() {
            return u64::MAX;
        }
        let hi = self.data_volume.inflight_hi();
        let headroom = (hi * (HEADROOM_DEN - HEADROOM_NUM) / HEADROOM_DEN).max(1);
        hi.saturating_sub(headroom).max(self.min_pipe_cwnd())
    }

    // =======================================================================
    // 状態遷移 (Section 4.3)
    // =======================================================================

    // --- Startup ---

    fn enter_startup(&mut self) {
        self.state = BbrState::Startup;
    }

    fn check_startup_done(&mut self) {
        if self.state != BbrState::Startup {
            return;
        }

        // 帯域プラトー検出 (ラウンド開始時)
        // draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.1.2:
        // BBR.max_bw のプラトーで full pipe を判定する。
        if self.round.round_start() {
            let rs = self.delivery_rate.rate_sample();
            self.full_pipe
                .on_round_start(self.max_bw(), rs.is_app_limited);
        }

        // 過剰ロストチェック (ロスラウンド開始時)
        if self.congestion.loss_round_start() {
            let rs = *self.delivery_rate.rate_sample();
            self.full_pipe
                .on_loss_round_start(self.congestion.loss_bursts_in_round(), &rs);
        }

        if self.full_pipe.filled_pipe() {
            self.enter_drain();
        }
    }

    // --- Drain ---

    fn enter_drain(&mut self) {
        self.state = BbrState::Drain;
    }

    fn check_drain(&mut self, now: Timestamp) {
        if self.state == BbrState::Drain && self.bytes_in_flight <= self.inflight_for_gain(1, 1) {
            self.enter_probe_bw(now);
        }
    }

    // --- ProbeBW ---

    /// Drain 完了 (CheckDrainDone) として ProbeBW を開始する
    fn enter_probe_bw(&mut self, now: Timestamp) {
        self.start_probe_bw_down(now);
    }

    fn start_probe_bw_down(&mut self, now: Timestamp) {
        self.reset_congestion_signals();
        self.probe_bw.start_down(&mut self.rng);
        // draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.3.6:
        // BBRStartProbeBW_DOWN() は BBR.cycle_stamp = Now() を設定する。
        // start_down は cycle_stamp を未設定にするため、DOWN へ入る全経路
        // (Drain 完了 / ProbeRTT 終了 / 過剰ロスト / UP からの遷移) で
        // ここで開始時刻を設定する。設定しないと has_elapsed_in_phase が
        // 常に true になり、DOWN を待たずに REFILL へ遷移してしまう。
        self.probe_bw.set_cycle_stamp(now);
        self.round.set_round_end(self.delivery_rate.delivered());
        self.state = BbrState::ProbeBw;
    }

    fn start_probe_bw_cruise(&mut self) {
        self.probe_bw.start_cruise();
    }

    fn start_probe_bw_refill(&mut self) {
        self.reset_lower_bounds();
        self.probe_bw.start_refill();
        self.round.set_round_end(self.delivery_rate.delivered());
    }

    fn start_probe_bw_up(&mut self, now: Timestamp) {
        self.probe_bw
            .start_up(now, self.cwnd, self.max_datagram_size);
        self.round.set_round_end(self.delivery_rate.delivered());
    }

    fn update_probe_bw_cycle_phase(&mut self, newly_acked: u64, now: Timestamp) {
        if !self.full_pipe.filled_pipe() {
            return;
        }
        self.adapt_upper_bounds(newly_acked, now);
        if self.state != BbrState::ProbeBw {
            return;
        }

        match self.probe_bw.phase() {
            probe_bw::CyclePhase::Down => {
                if self.check_time_to_probe_bw(now) {
                    return;
                }
                if self.check_time_to_cruise() {
                    self.start_probe_bw_cruise();
                }
            }
            probe_bw::CyclePhase::Cruise => {
                let _ = self.check_time_to_probe_bw(now);
            }
            probe_bw::CyclePhase::Refill => {
                if self.round.round_start() {
                    self.probe_bw.set_bw_probe_samples(true);
                    self.start_probe_bw_up(now);
                }
            }
            probe_bw::CyclePhase::Up => {
                let (up_gain_num, up_gain_den) = self.probe_bw.pacing_gain();
                if let Some(min_rtt) = self.data_volume.min_rtt()
                    && self.probe_bw.has_elapsed_in_phase(min_rtt, now)
                    && self.bytes_in_flight > self.inflight_for_gain(up_gain_num, up_gain_den)
                {
                    self.start_probe_bw_down(now);
                }
            }
        }
    }

    fn is_in_probe_bw_state(&self) -> bool {
        self.state == BbrState::ProbeBw
    }

    fn check_time_to_probe_bw(&mut self, now: Timestamp) -> bool {
        if self
            .probe_bw
            .is_time_to_probe_bw(now, self.target_inflight(), self.max_datagram_size)
        {
            self.start_probe_bw_refill();
            return true;
        }
        false
    }

    fn check_time_to_cruise(&self) -> bool {
        self.probe_bw.check_time_to_cruise(
            self.bytes_in_flight,
            self.inflight_with_headroom(),
            self.inflight_for_gain(1, 1),
        )
    }

    /// inflight_hi を `newly_acked` に応じて引き上げる
    ///
    /// 判定と増分計算は ProbeBW 状態側に委譲する。`newly_acked` はこの ACK で
    /// 新たに ACK されたバイト数であり、`RateSample.delivered` (サンプリング
    /// 間隔中の配送バイト数) とは異なる。
    fn probe_inflight_hi_upward(&mut self, newly_acked: u64, round_start: bool) {
        let delta = self.probe_bw.probe_inflight_hi_upward(
            newly_acked,
            self.cwnd,
            self.cwnd_limited_in_round,
            self.data_volume.inflight_hi(),
            self.max_datagram_size,
            round_start,
        );
        if delta > 0 {
            self.data_volume.raise_inflight_hi(delta);
        }
    }

    // --- ProbeRTT ---

    fn enter_probe_rtt(&mut self) {
        self.state = BbrState::ProbeRtt;
        self.probe_rtt_state.enter();
    }

    fn probe_rtt_cwnd(&self) -> u64 {
        let probe_cwnd = self.bdp_multiple(probe_rtt::CWND_GAIN_NUM, probe_rtt::CWND_GAIN_DEN);
        probe_cwnd.max(self.min_pipe_cwnd())
    }

    fn update_min_rtt(&mut self, rtt_sample: Duration, now: Timestamp) {
        self.data_volume.update_min_rtt(rtt_sample, now);
    }

    fn check_probe_rtt(&mut self, now: Timestamp) {
        if self.state != BbrState::ProbeRtt
            && self.data_volume.probe_rtt_expired()
            && !self.idle_restart
        {
            self.enter_probe_rtt();
            self.save_cwnd();
            self.round.set_round_end(self.delivery_rate.delivered());
        }

        if self.state == BbrState::ProbeRtt {
            self.handle_probe_rtt(now);
        }

        if self.delivery_rate.delivered() > 0 {
            self.idle_restart = false;
        }
    }

    fn handle_probe_rtt(&mut self, now: Timestamp) {
        // ProbeRTT 中は app_limited としてマークする
        self.delivery_rate.mark_app_limited(self.bytes_in_flight);

        let probe_cwnd = self.probe_rtt_cwnd();
        self.probe_rtt_state.handle(
            self.bytes_in_flight,
            probe_cwnd,
            now,
            self.round.round_start(),
        );

        if self.probe_rtt_state.is_done(now) {
            self.data_volume.schedule_next_probe_rtt(now);
            self.restore_cwnd();
            self.exit_probe_rtt(now);
        }
    }

    fn exit_probe_rtt(&mut self, now: Timestamp) {
        self.reset_lower_bounds();
        if self.full_pipe.filled_pipe() {
            // Down フェーズから開始し、update_probe_bw_cycle_phase で
            // 通常の Down → Cruise 遷移を行う
            self.start_probe_bw_down(now);
        } else {
            self.enter_startup();
        }
    }

    // =======================================================================
    // 輻輳信号 (Section 4.5.6)
    // =======================================================================

    fn update_latest_delivery_signals(&mut self) {
        let rs = *self.delivery_rate.rate_sample();
        let delivered = self.delivery_rate.delivered();
        self.congestion.update_latest(&rs, delivered);
    }

    fn advance_latest_delivery_signals(&mut self) {
        let rs = *self.delivery_rate.rate_sample();
        self.congestion.advance(&rs);
    }

    fn update_congestion_signals(&mut self, rs: &RateSample) {
        self.update_max_bw(rs);
        // ロスト信号は on_packets_lost_cc で congestion.on_packet_lost() 経由で設定済み
        if !self.congestion.loss_round_start() {
            return;
        }
        self.adapt_lower_bounds_from_congestion();
        // draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.5.6.3:
        // BBRUpdateCongestionSignals() がリセットするのは loss_in_round だけ。
        // loss burst 数は直後の check_startup_done が CheckStartupHighLoss の
        // 入力として読むため、ここでは消さない。
        self.congestion.reset_round_signals_except_bursts();
    }

    fn adapt_lower_bounds_from_congestion(&mut self) {
        if self.is_probing_bw() {
            return;
        }
        if self.congestion.loss_in_round() {
            self.init_lower_bounds();
            self.loss_lower_bounds();
        }
    }

    fn is_probing_bw(&self) -> bool {
        self.state == BbrState::ProbeBw
            && matches!(
                self.probe_bw.phase(),
                probe_bw::CyclePhase::Refill | probe_bw::CyclePhase::Up
            )
    }

    fn init_lower_bounds(&mut self) {
        self.data_rate.init_lower_bounds();
        self.data_volume.init_inflight_lo(self.cwnd);
    }

    fn loss_lower_bounds(&mut self) {
        self.data_rate
            .update_lower_bound(self.congestion.bw_latest());
        self.data_volume
            .update_inflight_lo(self.congestion.inflight_latest());
    }

    fn reset_congestion_signals(&mut self) {
        self.congestion.reset();
    }

    fn reset_lower_bounds(&mut self) {
        self.data_rate.reset_lower_bound();
        self.data_volume.reset_inflight_lo();
    }

    fn bound_bw_for_model(&mut self) {
        self.data_rate.bound_bw_for_model();
    }

    // --- upper bounds ---

    /// 安全な ACK で inflight_hi / bw_hi を引き上げる
    ///
    /// draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.3.6 の
    /// BBRAdaptUpperBounds()。`newly_acked` はこの ACK で新たに ACK された
    /// バイト数で、BBRProbeInflightHiUpward() の `rs.newly_acked` に対応する。
    /// `RateSample.delivered` はサンプリング間隔中の配送バイト数であり、
    /// この ACK の ACK 済みバイト数ではないため使わない。
    fn adapt_upper_bounds(&mut self, newly_acked: u64, now: Timestamp) {
        let round_start = self.round.round_start();
        if round_start {
            self.probe_bw.update_ack_phase_on_round_start();
            let rs = self.delivery_rate.rate_sample();
            if self.is_in_probe_bw_state()
                && self
                    .probe_bw
                    .should_advance_max_bw_filter(rs.is_app_limited)
            {
                self.data_rate.advance_max_bw_filter();
            }
        }

        let rs = *self.delivery_rate.rate_sample();
        if !self.check_inflight_too_high(&rs, now) {
            // ロスト率は安全で上限を引き上げ可能。
            // inflight_hi が未設定なら引き上げる対象が無いため戻る。
            // inflight_hi が有限なら bw_hi が Infinity のままでも
            // 引き上げと probe_inflight_hi_upward は実行する。
            if !self.data_volume.has_inflight_hi() {
                return;
            }
            if rs.prior_inflight > self.data_volume.inflight_hi() {
                self.data_volume.set_inflight_hi(rs.prior_inflight);
            }
            // draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.3.6 の
            // BBRAdaptUpperBounds() は inflight_hi と bw_hi の両方が有限でないと
            // 早期 return する。しかし draft の擬似コードには bw_hi を Infinity から
            // 有限値へ下げる経路が無く、そのままでは bw_hi が永久に上限として
            // 機能しない。実装では bw_hi == Infinity を「上限未設定」とみなし、
            // inflight_hi が有限になった後の安全なサンプルで有限化する。
            //
            // 有限化と引き上げの条件から app-limited を一律に除外するのは
            // draft に無い実装上の判断である。同じ推定器の update_max_bw は
            // max_bw を上回る app-limited サンプルを採用するが、bw_hi は
            // 引き上げでしか更新しない。未設定時に低い app-limited サンプルを
            // 一度焼き付けると、bound_bw_for_model の min を通じて pacing rate と
            // BDP 由来の cwnd が恒久的に崩落するため、bw_hi では app-limited
            // サンプルを一律に除外する。draft 改訂でこの扱いが変わる可能性がある。
            if !rs.is_app_limited
                && rs.delivery_rate > Bandwidth::ZERO
                && (self.data_rate.bw_hi() == Bandwidth::INFINITE
                    || rs.delivery_rate > self.data_rate.bw_hi())
            {
                self.data_rate.update_upper_bound(rs.delivery_rate);
            }
            if self.state == BbrState::ProbeBw && self.probe_bw.phase() == probe_bw::CyclePhase::Up
            {
                self.probe_inflight_hi_upward(newly_acked, round_start);
            }
        }
    }

    fn check_inflight_too_high(&mut self, rs: &RateSample, now: Timestamp) -> bool {
        if Self::is_inflight_too_high(rs) {
            if self.probe_bw.bw_probe_samples() {
                let prior_inflight = rs.prior_inflight;
                let is_app_limited = rs.is_app_limited;
                self.handle_inflight_too_high(prior_inflight, is_app_limited, now);
            }
            return true;
        }
        false
    }

    fn is_inflight_too_high(rs: &RateSample) -> bool {
        if rs.prior_inflight == 0 {
            return false;
        }
        rs.lost * LOSS_THRESH_DEN > rs.prior_inflight * LOSS_THRESH_NUM
    }

    fn handle_inflight_too_high(
        &mut self,
        prior_inflight: u64,
        is_app_limited: bool,
        now: Timestamp,
    ) {
        self.probe_bw.set_bw_probe_samples(false);
        if !is_app_limited {
            let target = self.target_inflight() * BETA_NUM / BETA_DEN;
            self.data_volume.set_inflight_hi(prior_inflight.max(target));
        }
        if self.state == BbrState::ProbeBw && self.probe_bw.phase() == probe_bw::CyclePhase::Up {
            self.start_probe_bw_down(now);
        }
    }

    // =======================================================================
    // Extra ACKed (Section 4.5.5)
    // =======================================================================

    fn update_ack_aggregation(&mut self, newly_acked: u64, now: Timestamp) {
        self.data_volume.update_ack_aggregation(
            self.data_rate.bw(),
            newly_acked,
            self.cwnd,
            self.round.round_count(),
            data_volume::EXTRA_ACKED_FILTER_LEN,
            now,
        );
    }

    // =======================================================================
    // 制御パラメータ更新 (Section 4.6)
    // =======================================================================

    fn set_pacing_rate(&mut self) {
        let (pg_num, pg_den) = self.pacing_gain();
        self.set_pacing_rate_with_gain(pg_num, pg_den);
    }

    fn set_pacing_rate_with_gain(&mut self, gain_num: u64, gain_den: u64) {
        self.pacer.set_pacing_rate(
            self.data_rate.bw(),
            gain_num,
            gain_den,
            self.full_pipe.filled_pipe(),
        );
    }

    fn init_pacing_rate(&mut self, srtt: Duration) {
        self.pacer.initialize_pacing_rate(
            self.initial_cwnd,
            srtt,
            startup::PACING_GAIN_NUM,
            startup::PACING_GAIN_DEN,
        );
    }

    fn set_send_quantum(&mut self) {
        self.pacer.set_send_quantum(self.max_datagram_size);
    }

    fn set_cwnd(&mut self, newly_acked: u64) {
        let max_inflight = self.update_max_inflight();
        self.modulate_cwnd_for_recovery(newly_acked);

        if !self.recovery.in_recovery() {
            if self.full_pipe.filled_pipe() {
                self.cwnd = (self.cwnd + newly_acked).min(max_inflight);
            } else if self.cwnd < max_inflight || self.delivery_rate.delivered() < self.initial_cwnd
            {
                self.cwnd += newly_acked;
            }
            self.cwnd = self.cwnd.max(self.min_pipe_cwnd());
        }

        self.bound_cwnd_for_probe_rtt();
        self.bound_cwnd_for_model();
    }

    fn modulate_cwnd_for_recovery(&mut self, newly_acked: u64) {
        // Recovery 中はパケット保存モードで cwnd を制限する
        if self.recovery.in_recovery() {
            self.cwnd = self.cwnd.max(self.bytes_in_flight + newly_acked);
        }
    }

    fn bound_cwnd_for_probe_rtt(&mut self) {
        if self.state == BbrState::ProbeRtt {
            self.cwnd = self.cwnd.min(self.probe_rtt_cwnd());
        }
    }

    fn bound_cwnd_for_model(&mut self) {
        let mut cap = u64::MAX;
        let is_cruise = self.state == BbrState::ProbeBw
            && self.probe_bw.phase() == probe_bw::CyclePhase::Cruise;
        if self.is_in_probe_bw_state() && !is_cruise {
            cap = self.data_volume.inflight_hi();
        } else if self.state == BbrState::ProbeRtt || is_cruise {
            cap = self.inflight_with_headroom();
        }
        cap = cap.min(self.data_volume.inflight_lo());
        cap = cap.max(self.min_pipe_cwnd());
        self.cwnd = self.cwnd.min(cap);
    }

    fn save_cwnd(&mut self) {
        if !self.recovery.in_recovery() && self.state != BbrState::ProbeRtt {
            self.prior_cwnd = self.cwnd;
        } else {
            self.prior_cwnd = self.prior_cwnd.max(self.cwnd);
        }
    }

    fn restore_cwnd(&mut self) {
        self.cwnd = self.cwnd.max(self.prior_cwnd);
    }

    // =======================================================================
    // アイドル復帰 (Section 4.4)
    // =======================================================================

    /// 送信前の in-flight を復元する
    ///
    /// 呼び出し契約: `on_packet_sent` が同一 `sent_bytes` で先に呼ばれ、
    /// `sent_bytes` が `bytes_in_flight` に加算済みであること。アイドル復帰
    /// (draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.4.3) と
    /// Delivery Rate Sampling は「送信前」と「送信直後」の in-flight を
    /// 必要とするため、加算済みの値から送信前の値を復元する。契約違反は
    /// `debug_assert` で検出する。
    fn inflight_before_send(&self, sent_bytes: u64) -> u64 {
        debug_assert!(
            self.bytes_in_flight >= sent_bytes,
            "on_packet_sent must be called before on_packet_sent_cc"
        );
        self.bytes_in_flight.saturating_sub(sent_bytes)
    }

    fn handle_restart_from_idle(&mut self, inflight_before_send: u64) {
        // draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.4.3:
        // BBRHandleRestartFromIdle() は「送信前」の packets_in_flight == 0 と
        // C.app_limited を条件にする。
        if inflight_before_send == 0 && self.delivery_rate.is_app_limited() {
            self.idle_restart = true;
            self.data_volume.reset_ack_aggregation_interval();
            if self.is_in_probe_bw_state() {
                self.set_pacing_rate_with_gain(1, 1);
            }
        }
    }

    // =======================================================================
    // ロスト処理 (Section 4.5.6.2)
    // =======================================================================

    fn handle_lost_packet(
        &mut self,
        pkt_state: &PacketDeliveryState,
        pkt_size: u64,
        now: Timestamp,
    ) {
        if !self.probe_bw.bw_probe_samples() {
            return;
        }
        let lost_since_send = self
            .delivery_rate
            .lost_bytes()
            .saturating_sub(pkt_state.lost_bytes);

        // IsInflightTooHigh チェック
        if pkt_state.tx_in_flight > 0
            && lost_since_send * LOSS_THRESH_DEN > pkt_state.tx_in_flight * LOSS_THRESH_NUM
        {
            // inflight_hi を推定する
            let inflight_prev = pkt_state.tx_in_flight.saturating_sub(pkt_size);
            let lost_prev = lost_since_send.saturating_sub(pkt_size);
            // lost_prefix = (LOSS_THRESH * inflight_prev - lost_prev) / (1 - LOSS_THRESH)
            // 整数展開: (NUM * inflight_prev - lost_prev * DEN) / (DEN - NUM)
            let numerator =
                (LOSS_THRESH_NUM * inflight_prev).saturating_sub(lost_prev * LOSS_THRESH_DEN);
            let denominator = LOSS_THRESH_DEN - LOSS_THRESH_NUM;
            let lost_prefix = numerator.checked_div(denominator).unwrap_or(0);
            let estimated_inflight = inflight_prev + lost_prefix;

            self.handle_inflight_too_high(estimated_inflight, pkt_state.is_app_limited, now);
        }
    }

    // =======================================================================
    // Per-ACK メインループ (Section 4.2.3)
    // =======================================================================

    /// Per-ACK メイン処理 (draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.2.3)
    ///
    /// `rtt_sample`: 最新の ACK されたパケットから計算した RTT サンプル。
    /// None の場合は min_rtt を更新しない。
    fn update_on_ack(&mut self, newly_acked: u64, rtt_sample: Option<Duration>, now: Timestamp) {
        // RateSample を生成
        self.delivery_rate
            .generate_rate_sample(self.data_volume.min_rtt());

        let rs = *self.delivery_rate.rate_sample();

        // BBRUpdateModelAndState
        self.update_latest_delivery_signals();
        self.update_congestion_signals(&rs);
        self.update_ack_aggregation(newly_acked, now);
        self.check_startup_done();
        // Startup の損失終了判定がこのロスラウンドの loss burst 数を読んだので、
        // 次のロスラウンドへ持ち越さないようにここでリセットする。
        // (update_congestion_signals は burst 数を残している)
        if self.congestion.loss_round_start() {
            self.congestion.reset_loss_bursts();
        }
        self.check_drain(now);
        self.update_probe_bw_cycle_phase(newly_acked, now);

        if let Some(rtt) = rtt_sample {
            self.update_min_rtt(rtt, now);
        }

        self.check_probe_rtt(now);
        self.advance_latest_delivery_signals();
        self.bound_bw_for_model();

        // BBRUpdateControlParameters
        self.set_pacing_rate();
        self.set_send_quantum();
        self.set_cwnd(newly_acked);
    }
}

use crate::recovery::initial_window;

// ===========================================================================
// CongestionControl trait 実装
// ===========================================================================

impl CongestionControl for BbrV2 {
    fn on_packet_sent(&mut self, sent_bytes: u64) {
        if sent_bytes > 0 {
            self.recovery.on_packet_sent();
        }
        self.bytes_in_flight += sent_bytes;
        // cwnd_limited 追跡
        if self.bytes_in_flight + self.max_datagram_size > self.cwnd {
            self.cwnd_limited_in_round = true;
        }
    }

    fn on_packet_acked_bytes(&mut self, acked_bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);
    }

    /// 鍵破棄に伴い破棄したパケットのバイト数を bytes_in_flight から除去する
    /// (RFC 9002 Section 6.4)
    fn on_packet_discarded_bytes(&mut self, discarded_bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(discarded_bytes);
        if discarded_bytes > 0 {
            self.recovery.on_packet_discarded();
        }
    }

    /// 鍵破棄された空間の per-packet delivery state を削除する
    ///
    /// 削除しないと、別空間で同じパケット番号を送ったときに古い状態を
    /// 誤って参照し、また鍵破棄後もメモリが残る (RFC 9002 Section 6.4)。
    fn on_packets_discarded_cc(&mut self, space: PacketNumberSpace, packet_numbers: &[u64]) {
        for pn in packet_numbers {
            self.packet_states.remove(&(space, *pn));
        }
    }

    fn on_ack_received(
        &mut self,
        _bytes_acknowledged: u64,
        _newest_acked_time_sent: Timestamp,
        _now: Timestamp,
    ) {
        // BBR は on_packets_acked_cc で処理する
    }

    fn on_packets_lost(&mut self, lost_bytes: u64, now: Timestamp) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        self.delivery_rate.on_packets_lost(lost_bytes);
        if lost_bytes == 0 {
            return;
        }

        // draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.6.4.4:
        // 回復前の cwnd を保存し、最初の RTT は送信中の量に合わせる。
        // draft 改訂で回復中の制御方法が変わる可能性がある。
        if !self.recovery.in_recovery() {
            self.save_cwnd();
            self.recovery.on_congestion_event(now);
            self.cwnd = self.bytes_in_flight.saturating_add(self.max_datagram_size);
        } else {
            self.cwnd = self.cwnd.saturating_sub(lost_bytes);
        }
        // 回復中は 1 パケットまで縮める。通常時の MinPipeCwnd を適用すると、
        // 全パケットを失った直後に複数パケットを送れてしまう。
        self.cwnd = self.cwnd.max(self.max_datagram_size);
    }

    fn on_spurious_loss_detection(&mut self, _now: Timestamp) {
        // 損失回復が後から spurious と判明した場合、損失回復開始前の
        // cwnd (last known good) へ戻す (draft-cardwell-iccrg-bbr-congestion-control-02
        // Section 4.6.4.4)。prior_cwnd は save_cwnd で記録済みの値を使う。
        self.recovery = recovery::State::new();
        self.restore_cwnd();
    }

    fn on_persistent_congestion(&mut self) {
        self.cwnd = self.min_pipe_cwnd();
    }

    fn bandwidth_estimate(&self) -> Option<u64> {
        let bandwidth = self.model_bandwidth();
        let bps = bandwidth.as_bytes_per_second();
        if bps == 0 || bps == u64::MAX {
            None
        } else {
            Some(bps)
        }
    }

    fn congestion_window(&self) -> u64 {
        self.cwnd
    }

    fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    fn available_window(&self) -> u64 {
        let available = self.cwnd.saturating_sub(self.bytes_in_flight);
        // RFC 9002 Section 7.3.2: 回復開始時は cwnd の制限を超えて
        // 1 パケットを送れる。実際の送信時にこの追加の送信権を消費する。
        if self.recovery.requires_fast_retransmission() {
            available.max(self.max_datagram_size)
        } else {
            available
        }
    }

    fn is_congestion_limited(&self) -> bool {
        self.available_window() < self.max_datagram_size
    }

    fn on_rtt_update(&mut self, smoothed_rtt: Duration, min_rtt: Duration, latest_rtt: Duration) {
        // 初期 pacing rate は OnInit (new) で 333ms の srtt を使って設定済み。
        // 何らかの理由で未設定のまま最初の RTT サンプルが来た場合はここで初期化する。
        if self.pacer.pacing_rate() == 0 && smoothed_rtt.as_micros() > 0 {
            self.init_pacing_rate(smoothed_rtt);
        }
        // BBR では min_rtt は on_packets_acked_cc 内で新鮮な RTT サンプルから直接更新する。
        // on_rtt_update の Timestamp (now) が利用できないため、ここでは smoothed_rtt のみ使用する。
        let _ = (min_rtt, latest_rtt);
    }

    fn on_packet_sent_cc(
        &mut self,
        space: PacketNumberSpace,
        pn: u64,
        sent_bytes: u64,
        now: Timestamp,
    ) {
        let inflight_before_send = self.inflight_before_send(sent_bytes);
        self.handle_restart_from_idle(inflight_before_send);
        // pacing の departure time を P.send_time として使う。
        let send_time = self.pacer.on_packet_sent(now, sent_bytes);
        // P.tx_in_flight は送信直後の C.inflight (このパケットを含む)。
        // 送信前の inflight は Delivery Rate Sampling とアイドル復帰判定に使う。
        let pkt_state = self.delivery_rate.on_packet_sent(
            inflight_before_send,
            self.bytes_in_flight,
            send_time,
        );
        self.packet_states.insert((space, pn), pkt_state);
    }

    fn on_packet_sent_cc_unpaced(
        &mut self,
        space: PacketNumberSpace,
        pn: u64,
        sent_bytes: u64,
        now: Timestamp,
    ) {
        let inflight_before_send = self.inflight_before_send(sent_bytes);
        self.handle_restart_from_idle(inflight_before_send);
        // pacing の対象外の経路では P.send_time に実際の送信時刻を使う。
        self.pacer.on_packet_sent(now, sent_bytes);
        let pkt_state =
            self.delivery_rate
                .on_packet_sent(inflight_before_send, self.bytes_in_flight, now);
        self.packet_states.insert((space, pn), pkt_state);
    }

    fn on_packets_acked_cc(&mut self, packets: &[AckedPacketInfo], now: Timestamp) {
        if packets.is_empty() {
            return;
        }

        let mut newly_acked: u64 = 0;

        // Delivery Rate Sampling: 各パケットの RateSample を更新する
        self.delivery_rate.init_rate_sample();
        for pkt in packets {
            if let Some(pkt_state) = self.packet_states.remove(&(pkt.space, pkt.pn)) {
                self.delivery_rate
                    .update_rate_sample(pkt.pn, pkt.sent_bytes, &pkt_state, now);
            }
            newly_acked += pkt.sent_bytes;
        }

        // RTT サンプルは ACK された中で最も新しく送信されたパケットから計算する。
        // draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.5.3.1:
        // 「the data packet with the latest transmission time」を使う。
        let newest_acked_time_sent = packets
            .iter()
            .map(|pkt| pkt.time_sent)
            .max()
            .expect("non-empty acknowledged packet list");
        let rtt_sample = Some(now - newest_acked_time_sent);

        // 回復開始後に送信されたパケットの ACK で回復を終了する
        // (RFC 9002 Section 7.3.2)。モデルによる上限制御より先に cwnd を戻す。
        if self.recovery.on_ack(newest_acked_time_sent) {
            self.restore_cwnd();
        }

        // Per-ACK 処理 (RTT サンプルを渡して update_min_rtt を一箇所で呼ぶ)
        self.update_on_ack(newly_acked, rtt_sample, now);

        // ラウンド開始時に cwnd_limited をリセット
        if self.round.round_start() {
            self.cwnd_limited_in_round = false;
        }
    }

    fn on_packets_lost_cc(&mut self, lost_packets: &[LostPacketInfo], now: Timestamp) {
        for pkt_info in lost_packets {
            // loss burst 検出: 同じ空間で直前にロストしたパケットと連続して
            // いなければ新しい burst。空間ごとに独立して比較するため、別空間の
            // ロストが間に入っても同じ空間の連続したロストは 1 burst のまま数える。
            // 各空間で最初のロストは直前の PN が無いので必ず新しい burst になる。
            let space_index = pkt_info.space.index();
            let is_new_burst = match self.last_lost_pn[space_index] {
                Some(last_pn) => pkt_info.pn > last_pn.saturating_add(1),
                None => true,
            };
            self.last_lost_pn[space_index] = Some(pkt_info.pn);

            // congestion に通知する
            self.congestion.on_packet_lost(is_new_burst);

            // per-packet delivery state を取得して handle_lost_packet を呼ぶ
            if let Some(pkt_state) = self.packet_states.remove(&(pkt_info.space, pkt_info.pn)) {
                self.handle_lost_packet(&pkt_state, pkt_info.sent_bytes, now);
            }
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u64) {
        let old_mtu = self.max_datagram_size;
        if old_mtu == 0 || new_mtu == 0 || old_mtu == new_mtu {
            return;
        }
        self.max_datagram_size = new_mtu;

        // RFC 8899 Section 3: PLPMTU の更新で輻輳ウィンドウをバイト単位で
        // 増やしてはならない (MUST NOT)。MTU 比のスケーリングも行わず、
        // cwnd のバイト数を据え置く。初期ウィンドウは再計算して保持する
        // (RFC 9002 Section 7.2) が、既存の cwnd は引き上げない。
        self.initial_cwnd = initial_window(new_mtu);

        // send_quantum を再計算する
        self.pacer.set_send_quantum(new_mtu);
    }

    fn on_ecn_ce_count(&mut self, ce_count: u64, now: Timestamp) {
        if ce_count == 0 {
            return;
        }
        // ECN CE をラウンド内の輻輳信号として記録する
        self.delivery_rate.on_ecn_ce(ce_count);
        self.congestion.on_explicit_congestion();

        // ECT(0) / ECT(1) をマークした接続は CE マークを輻輳として扱う。
        // draft-cardwell-iccrg-bbr-congestion-control-02 には ECN 応答の
        // 規定が無いため、draft-ietf-ccwg-bbr-06 Section 3.7 を採用する。
        // CE マーク時点の in-flight を上限推定に使い、inflight_hi を
        // 引き下げる。ProbeBW_UP 中であればロスと同じく ProbeBW_DOWN へ
        // 遷移して増加を止める。
        let prior_inflight = self.bytes_in_flight.max(self.min_pipe_cwnd());
        self.handle_inflight_too_high(prior_inflight, false, now);
    }

    fn on_app_limited(&mut self) {
        // draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.5.2.3 /
        // Section 4.5.2.4:
        // app-limited なサンプルは max_bw から除外するが、現在の max_bw を
        // 上回る場合のみ採用する。app-limited の判定自体は共通の
        // DeliveryRateEstimator (CheckIfApplicationLimited) に任せ、
        // BBRv3 と同じ条件 (inflight < cwnd) を使う。
        self.delivery_rate
            .check_if_application_limited(self.bytes_in_flight, self.cwnd);
    }

    fn pacing_rate(&self) -> Option<u64> {
        if self.pacer.pacing_rate() > 0 {
            Some(self.pacer.pacing_rate())
        } else {
            None
        }
    }

    fn earliest_departure_time(&self) -> Option<Timestamp> {
        self.pacer.earliest_departure_time()
    }
}

// ===========================================================================
// ファクトリ
// ===========================================================================

/// BBRv2 ファクトリ
#[derive(Debug, Clone)]
pub struct BbrV2Factory;

impl CongestionControlFactory for BbrV2Factory {
    type Controller = BbrV2;

    fn create(&self, max_datagram_size: u64) -> BbrV2 {
        BbrV2::new(max_datagram_size)
    }
}

// ===========================================================================
// テスト
// ===========================================================================

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_recovery;
