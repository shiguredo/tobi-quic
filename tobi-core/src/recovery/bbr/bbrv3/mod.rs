// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! BBRv3 輻輳制御 (draft-ietf-ccwg-bbr-06)
//!
//! モデルベースの輻輳制御アルゴリズム。帯域推定と pacing により
//! bufferbloat 耐性が高く、Multipath QUIC で有効。
//!
//! BBRv2 からの主な変更点:
//! - bw_hi を廃止し bw = min(max_bw, bw_shortterm) のみで操作帯域を決定する
//! - inflight_hi / inflight_lo を inflight_longterm / inflight_shortterm にリネームする

// BBRv2 と共通のモジュールを re-export
pub use crate::recovery::bbr::bbrv2::congestion;
pub use crate::recovery::bbr::bbrv2::full_pipe;
pub use crate::recovery::bbr::bbrv2::probe_rtt;
pub use crate::recovery::bbr::bbrv2::recovery;
pub use crate::recovery::bbr::bbrv2::round;

// BBRv3 固有のモジュール
pub mod data_rate;
pub mod data_volume;
pub mod drain;
pub mod probe_bw;
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
// 定数 (draft-ietf-ccwg-bbr-06 Section 2.8)
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
// 状態定義 (draft-ietf-ccwg-bbr-06 Section 5.1.1)
// ---------------------------------------------------------------------------

/// BBRv3 の状態マシン
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

/// 損失回復開始時に保存する遷移元の状態 (draft-ietf-ccwg-bbr-06 Section 2.15)
///
/// 損失回復が後から spurious と判明したとき、ここに記録した状態へ戻す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UndoState {
    /// Startup を損失で抜けた場合の取り消し用
    Startup,
    /// ProbeBW_UP を損失で抜けた場合の取り消し用
    ProbeBwUp,
}

// ---------------------------------------------------------------------------
// BbrV3 本体
// ---------------------------------------------------------------------------

/// BBRv3 輻輳制御
/// draft-ietf-ccwg-bbr-06
#[derive(Debug)]
pub struct BbrV3 {
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

    // --- Spurious loss undo (draft-ietf-ccwg-bbr-06 Section 2.15) ---
    /// 損失回復開始時に記録した遷移元の状態
    undo_state: Option<UndoState>,
    /// 損失回復開始時の bw_shortterm
    undo_bw_shortterm: Bandwidth,
    /// 損失回復開始時の inflight_shortterm
    undo_inflight_shortterm: u64,
    /// 損失回復開始時の inflight_longterm
    undo_inflight_longterm: u64,
    /// 損失回復開始時に状態を保存済みか
    ///
    /// undo_state は損失起因の状態遷移が起きたときだけ設定されるため、
    /// 「保存済みだが遷移はしていない」場合と「未保存」を区別する。
    loss_state_saved: bool,

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

    // --- 最適化 ---
    /// fast path 最適化フラグ
    ///
    /// ProbeBW の安定フェーズ (Down/Cruise) でロスト/ECN 信号がない場合、
    /// 次回の update_on_ack で状態遷移チェックをスキップして制御パラメータの
    /// 更新のみ実行できる。
    try_fast_path: bool,
    cwnd_limited_in_round: bool,
}

impl BbrV3 {
    /// 新しい BBRv3 インスタンスを作成する
    pub fn new(max_datagram_size: u64) -> Self {
        let initial_cwnd = initial_window(max_datagram_size);
        let min_pipe_cwnd = MIN_PIPE_CWND_PACKETS * max_datagram_size;

        let mut s = Self {
            state: BbrState::Startup,
            probe_bw: probe_bw::State::new(),
            full_pipe: full_pipe::Estimator::new(full_pipe::STARTUP_LOSS_BURST_THRESH_BBRV3),

            cwnd: initial_cwnd,
            prior_cwnd: 0,
            pacer: Pacer::new(max_datagram_size),

            data_rate: data_rate::Model::new(),

            data_volume: data_volume::Model::new(),

            probe_rtt_state: probe_rtt::State::new(),

            round: round::Counter::new(),

            congestion: congestion::State::new(),

            undo_state: None,
            undo_bw_shortterm: Bandwidth::INFINITE,
            undo_inflight_shortterm: u64::MAX,
            undo_inflight_longterm: u64::MAX,
            loss_state_saved: false,

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

            try_fast_path: false,
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

    /// モデルが推定した帯域 (bytes/sec) を返す
    ///
    /// BBR の配送レート推定から得た操作帯域。公開 API やスケジューラーが
    /// パスごとの推定帯域として参照する。
    pub fn model_bandwidth(&self) -> Bandwidth {
        self.data_rate.bw()
    }

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
    // ラウンド追跡 (draft-ietf-ccwg-bbr-06 Section 5.5.1)
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
    // BDP と inflight 計算 (draft-ietf-ccwg-bbr-06 Section 5.6.4.2)
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

    /// Inflight(gain): BDP * gain + 量子化
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
    /// BBRv3 では inflight_longterm (BBRv2 の inflight_hi 相当) を使用する
    fn inflight_with_headroom(&self) -> u64 {
        if !self.data_volume.has_inflight_longterm() {
            return u64::MAX;
        }
        let longterm = self.data_volume.inflight_longterm();
        let headroom = (longterm * (HEADROOM_DEN - HEADROOM_NUM) / HEADROOM_DEN).max(1);
        longterm.saturating_sub(headroom).max(self.min_pipe_cwnd())
    }

    // =======================================================================
    // 状態遷移 (draft-ietf-ccwg-bbr-06 Section 5.3)
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
        // draft-ietf-ccwg-bbr-06 Section 5.3.1.2:
        // BBRv3 は BBR.max_bw ではなく現在の RS.delivery_rate のプラトーで
        // full pipe を判定する。
        if self.round.round_start() {
            let rs = self.delivery_rate.rate_sample();
            self.full_pipe
                .on_round_start(rs.delivery_rate, rs.is_app_limited);
        }

        // 過剰ロストチェック (ロスラウンド開始時)
        if self.congestion.loss_round_start() {
            let rs = *self.delivery_rate.rate_sample();
            let was_filled = self.full_pipe.filled_pipe();
            self.full_pipe
                .on_loss_round_start(self.congestion.loss_bursts_in_round(), &rs);
            // 損失を契機に Startup を抜けた場合、spurious loss に備えて
            // 遷移元の状態を記録する (Section 5.3.1.3, Section 5.5.11.1)。
            if !was_filled && self.full_pipe.filled_pipe() {
                self.undo_state = Some(UndoState::Startup);
                // draft-ietf-ccwg-bbr-06 Section 5.3.1.3:
                // inflight_longterm = max(BBR.bdp, BBR.inflight_latest) とし、
                // 損失が示す安全な inflight とする。
                let bdp = self.bdp_multiple(1, 1);
                let inflight_latest = self.congestion.inflight_latest();
                self.data_volume
                    .set_inflight_longterm(bdp.max(inflight_latest));
            }
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
        // draft-ietf-ccwg-bbr-06 Section 5.3.3.9:
        // StartProbeBW_DOWN() は BBR.cycle_stamp = Now() を設定する。
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
        if self.adapt_upper_bounds(newly_acked, now) {
            // 予防的プロービングの加速で状態遷移した
            return;
        }
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
                if self.is_time_to_go_down(now) {
                    // UP を抜けるときは次のプローブのためにフラグを戻す (Section 5.3.3)
                    self.probe_bw.set_prev_probe_too_high(false);
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

    /// ProbeBW_UP から ProbeBW_DOWN へ移るかどうかを返す
    ///
    /// IsTimeToGoDown (Section 5.3.3) に相当する。直前のプローブが過剰ロスト
    /// だった場合は inflight_longterm に達した時点で切り上げる
    /// (Section 5.3.3.6 の減速)。
    fn is_time_to_go_down(&mut self, now: Timestamp) -> bool {
        if self.probe_bw.prev_probe_too_high()
            && self.bytes_in_flight >= self.data_volume.inflight_longterm()
        {
            self.probe_bw.set_prev_probe_precautionary(true);
            return true;
        }

        let (up_gain_num, up_gain_den) = self.probe_bw.pacing_gain();
        if let Some(min_rtt) = self.data_volume.min_rtt()
            && self.probe_bw.has_elapsed_in_phase(min_rtt, now)
            && self.bytes_in_flight > self.inflight_for_gain(up_gain_num, up_gain_den)
        {
            return true;
        }
        false
    }

    /// inflight_longterm を上方向にプローブする
    ///
    /// `newly_acked` はこの ACK の新規確認バイト数であり、サンプリング期間の
    /// 配送量 (`RateSample::delivered`) ではない
    /// (draft-ietf-ccwg-bbr-06 Section 2.3 / Section 5.3.3.9)。
    fn probe_inflight_longterm_upward(&mut self, newly_acked: u64) {
        let round_start = self.round.round_start();
        let delta = self.probe_bw.probe_inflight_longterm_upward(
            newly_acked,
            self.cwnd,
            self.cwnd_limited_in_round,
            self.data_volume.inflight_longterm(),
            self.max_datagram_size,
            round_start,
        );
        if delta > 0 {
            self.data_volume.raise_inflight_longterm(delta);
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
    // 輻輳信号 (draft-ietf-ccwg-bbr-06 Section 5.5.10)
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

    fn update_congestion_signals(&mut self, rs: &RateSample, round_already_updated: bool) {
        // fast path で update_round 済みの場合、round_start を保持したまま
        // max_bw だけを更新し、ラウンドを二重に進めない。
        if !round_already_updated {
            self.update_round(rs);
        }
        self.data_rate.update_max_bw(rs);
        // ロスト信号は on_packets_lost_cc で congestion.on_packet_lost() 経由で設定済み
        if !self.congestion.loss_round_start() {
            return;
        }
        self.adapt_lower_bounds_from_congestion();
        // draft-ietf-ccwg-bbr-06 Section 5.5.10.3:
        // UpdateCongestionSignals() がリセットするのは is_loss_in_round だけ。
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

    /// 下限を初期化する
    /// BBRv3 では bw_hi がないため data_rate.init_lower_bounds() のみ
    fn init_lower_bounds(&mut self) {
        self.data_rate.init_lower_bounds();
        self.data_volume.init_inflight_shortterm(self.cwnd);
    }

    fn loss_lower_bounds(&mut self) {
        self.data_rate
            .update_lower_bound(self.congestion.bw_latest());
        self.data_volume
            .update_inflight_shortterm(self.congestion.inflight_latest());
    }

    fn reset_congestion_signals(&mut self) {
        self.congestion.reset();
    }

    fn reset_lower_bounds(&mut self) {
        self.data_rate.reset_lower_bound();
        self.data_volume.reset_inflight_shortterm();
    }

    fn bound_bw_for_model(&mut self) {
        self.data_rate.bound_bw_for_model();
    }

    // --- upper bounds ---

    /// 上限を適応させる
    /// BBRv3 では bw_hi がないため、inflight_longterm のみ更新する
    ///
    /// AdaptLongTermModel (Section 5.3.3) に相当する。状態遷移した場合は
    /// true を返す。
    fn adapt_upper_bounds(&mut self, newly_acked: u64, now: Timestamp) -> bool {
        if self.round.round_start() {
            // draft-ietf-ccwg-bbr-06 Section 5.3.3.9 AdaptLongTermModel:
            // ACKS_PROBE_STOPPING → ACKS_INIT の遷移でのみ max_bw フィルタの
            // 仮想時間 (cycle_count) を進める。これによりフィルタ窓は
            // 2 ProbeBW サイクル分になる (Section 5.5.3, Section 5.5.6)。
            let advanced = self.probe_bw.update_ack_phase_on_round_start();
            let is_app_limited = self.delivery_rate.rate_sample().is_app_limited;
            if advanced && self.is_in_probe_bw_state() && !is_app_limited {
                self.data_rate.advance_max_bw_filter();
            }
            // 予防的プロービングの加速: 慎重なプローブが過剰ロストなく終わったら
            // REFILL に戻して再プローブする (Section 5.3.3.6)
            if self.is_in_probe_bw_state()
                && self.probe_bw.prev_probe_precautionary()
                && !self.probe_bw.prev_probe_too_high()
            {
                self.start_probe_bw_refill();
                return true;
            }
        }

        let rs = *self.delivery_rate.rate_sample();
        if !self.check_inflight_too_high(&rs, now) {
            // ロスト率は安全、上限を引き上げ可能
            // BBRv3 では bw_hi がないため inflight_longterm のみチェックする
            if !self.data_volume.has_inflight_longterm() {
                return false;
            }
            if rs.prior_inflight > self.data_volume.inflight_longterm() {
                self.data_volume.set_inflight_longterm(rs.prior_inflight);
            }
            if self.state == BbrState::ProbeBw && self.probe_bw.phase() == probe_bw::CyclePhase::Up
            {
                // draft-ietf-ccwg-bbr-06 Section 2.3: RS.delivered はサンプリング
                // 期間の配送量であり、今回の ACK の新規確認量ではない。Section
                // 5.3.3.9 の ProbeInflightLongtermUpward は `bw_probe_up_acked +=
                // RS.newly_acked` とするため、ここでは newly_acked を渡す。
                self.probe_inflight_longterm_upward(newly_acked);
            }
        }
        false
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
        // 次のプローブを慎重に実施するための記録 (Section 5.3.3.6)
        self.probe_bw.set_prev_probe_too_high(true);
        self.probe_bw.set_bw_probe_samples(false);
        if !is_app_limited {
            let target = self.target_inflight() * BETA_NUM / BETA_DEN;
            self.data_volume
                .set_inflight_longterm(prior_inflight.max(target));
        }
        if self.state == BbrState::ProbeBw && self.probe_bw.phase() == probe_bw::CyclePhase::Up {
            // ProbeBW_UP から損失で ProbeBW_DOWN へ移る場合、spurious loss に
            // 備えて遷移元の状態を記録する (Section 5.5.11.1)。
            self.undo_state = Some(UndoState::ProbeBwUp);
            self.start_probe_bw_down(now);
        }
    }

    // =======================================================================
    // Spurious loss recovery (draft-ietf-ccwg-bbr-06 Section 5.5.11)
    // =======================================================================

    /// 損失回復開始時に状態を保存する (SaveStateUponLoss)
    ///
    /// draft-ietf-ccwg-bbr-06 Section 5.5.11.1:
    /// cwnd と短期・長期のモデルパラメータを保存し、undo_state を初期化する。
    fn save_state_upon_loss(&mut self) {
        self.save_cwnd();
        self.loss_state_saved = true;
        self.undo_state = None;
        self.undo_bw_shortterm = self.data_rate.bw_shortterm();
        self.undo_inflight_shortterm = self.data_volume.inflight_shortterm();
        self.undo_inflight_longterm = self.data_volume.inflight_longterm();
    }

    /// 損失回復が spurious だったと判明したときの処理 (HandleSpuriousLossDetection)
    ///
    /// draft-ietf-ccwg-bbr-06 Section 5.5.11.2:
    /// cwnd・モデルパラメータを保存時の値へ戻し、損失起因で Startup または
    /// ProbeBW_UP を抜けていた場合は元の状態へ戻す。
    fn handle_spurious_loss_detection(&mut self) {
        // 損失回復開始時の状態を保存していない (spurious を宣言できる損失回復が
        // 無い) 場合は何も復元しない。未保存のまま復元すると、初期値
        // u64::MAX (Infinity) を保存値として扱ってしまい、未設定だった
        // inflight_longterm / inflight_shortterm が設定済みに変わってしまう。
        if self.undo_state.is_none() && !self.loss_state_saved {
            return;
        }
        self.loss_state_saved = false;
        self.restore_cwnd();
        self.congestion.reset_round_signals();
        self.full_pipe.reset();
        self.data_rate.restore_bw_shortterm(self.undo_bw_shortterm);
        self.data_volume
            .restore_inflight_shortterm(self.undo_inflight_shortterm);
        self.data_volume
            .restore_inflight_longterm(self.undo_inflight_longterm);

        match self.undo_state {
            Some(UndoState::Startup) if self.state != BbrState::Startup => {
                self.full_pipe.clear_filled_pipe();
                if self.state != BbrState::ProbeRtt {
                    self.enter_startup();
                }
            }
            Some(UndoState::ProbeBwUp)
                if !(self.state == BbrState::ProbeBw
                    && self.probe_bw.phase() == probe_bw::CyclePhase::Up)
                    && self.state != BbrState::ProbeRtt =>
            {
                self.start_probe_bw_refill();
            }
            _ => {}
        }
        self.undo_state = None;
    }

    // =======================================================================
    // Extra ACKed (draft-ietf-ccwg-bbr-06 Section 5.5.9)
    // =======================================================================

    fn update_ack_aggregation(&mut self, newly_acked: u64, now: Timestamp) {
        // draft-ietf-ccwg-bbr-06 Section 5.5.9:
        // Startup 中は 1 ラウンド、full_bw_reached 後は 10 ラウンドの窓を使う。
        let filter_len = if self.full_pipe.filled_pipe() {
            data_volume::STEADY_EXTRA_ACKED_FILTER_LEN
        } else {
            data_volume::STARTUP_EXTRA_ACKED_FILTER_LEN
        };
        self.data_volume.update_ack_aggregation(
            self.data_rate.bw(),
            newly_acked,
            self.cwnd,
            self.round.round_count(),
            filter_len,
            now,
        );
    }

    // =======================================================================
    // 制御パラメータ更新 (draft-ietf-ccwg-bbr-06 Section 5.6)
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
        // draft-ietf-ccwg-bbr-06 Section 5.6.4.4 / 5.6.4.6:
        // 回復中もモデルに従って cwnd を更新する。BBRv2 の最初の RTT の
        // パケット保存モードは適用しない。draft 改訂で変わる可能性がある。
        if self.full_pipe.filled_pipe() {
            self.cwnd = (self.cwnd + newly_acked).min(max_inflight);
        } else if self.cwnd < max_inflight || self.delivery_rate.delivered() < self.initial_cwnd {
            self.cwnd += newly_acked;
        }
        self.cwnd = self.cwnd.max(self.min_pipe_cwnd());

        self.bound_cwnd_for_probe_rtt();
        self.bound_cwnd_for_model();
    }

    fn bound_cwnd_for_probe_rtt(&mut self) {
        if self.state == BbrState::ProbeRtt {
            self.cwnd = self.cwnd.min(self.probe_rtt_cwnd());
        }
    }

    /// cwnd をモデルで制限する
    /// BBRv3 では inflight_longterm / inflight_shortterm を使用する
    fn bound_cwnd_for_model(&mut self) {
        let mut cap = u64::MAX;
        let is_cruise = self.state == BbrState::ProbeBw
            && self.probe_bw.phase() == probe_bw::CyclePhase::Cruise;
        if self.is_in_probe_bw_state() && !is_cruise {
            cap = self.data_volume.inflight_longterm();
        } else if self.state == BbrState::ProbeRtt || is_cruise {
            cap = self.inflight_with_headroom();
        }
        cap = cap.min(self.data_volume.inflight_shortterm());
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
    // アイドル復帰 (draft-ietf-ccwg-bbr-06 Section 5.4)
    // =======================================================================

    /// 送信前の in-flight を復元する
    ///
    /// 呼び出し契約: `on_packet_sent` が同一 `sent_bytes` で先に呼ばれ、
    /// `sent_bytes` が `bytes_in_flight` に加算済みであること。アイドル復帰
    /// (draft-ietf-ccwg-bbr-06 Section 5.4.1) と Delivery Rate Sampling は
    /// 「送信前」と「送信直後」の in-flight を必要とするため、加算済みの値から
    /// 送信前の値を復元する。契約違反は `debug_assert` で検出する。
    fn inflight_before_send(&self, sent_bytes: u64) -> u64 {
        debug_assert!(
            self.bytes_in_flight >= sent_bytes,
            "on_packet_sent must be called before on_packet_sent_cc"
        );
        self.bytes_in_flight.saturating_sub(sent_bytes)
    }

    fn handle_restart_from_idle(&mut self, inflight_before_send: u64) {
        // draft-ietf-ccwg-bbr-06 Section 5.4.1:
        // HandleRestartFromIdle() は「送信前」の C.inflight == 0 と C.app_limited を
        // 条件にする。
        if inflight_before_send == 0 && self.delivery_rate.is_app_limited() {
            self.idle_restart = true;
            self.data_volume.reset_ack_aggregation_interval();
            if self.is_in_probe_bw_state() {
                self.set_pacing_rate_with_gain(1, 1);
            }
        }
    }

    // =======================================================================
    // ロスト処理 (draft-ietf-ccwg-bbr-06 Section 5.5.10.2)
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
            // inflight_longterm を推定する
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
    // Per-ACK メインループ (draft-ietf-ccwg-bbr-06 Section 5.2.3)
    // =======================================================================

    /// Per-ACK メイン処理 (draft-ietf-ccwg-bbr-06 Section 5.2.3)
    ///
    /// `rtt_sample`: 最新の ACK されたパケットから計算した RTT サンプル。
    /// None の場合は min_rtt を更新しない。
    ///
    /// fast path 最適化: ProbeBW の安定フェーズ (Down/Cruise) で
    /// ロスト/ECN 信号がなく新しいラウンドも開始されない場合、
    /// 状態遷移チェックをスキップして制御パラメータの更新のみ実行する。
    fn update_on_ack(&mut self, newly_acked: u64, rtt_sample: Option<Duration>, now: Timestamp) {
        // RateSample を生成する
        self.delivery_rate
            .generate_rate_sample(self.data_volume.min_rtt());

        let rs = *self.delivery_rate.rate_sample();

        // fast path 判定: 前回 full path 完了時に安定状態と判定されており、
        // かつロスト/ECN 信号が発生していない場合
        let use_fast_path = self.try_fast_path
            && !self.congestion.loss_in_round()
            && !self.congestion.ecn_in_round();

        // fast path で update_round を実行したかを記録する。
        // 1 ACK につき update_round は 1 回だけ実行する契約とし、
        // full path の update_congestion_signals では再実行しない。
        let mut round_already_updated = false;
        if use_fast_path {
            // ラウンドカウンタだけを進める。max_bw の更新は下の分岐で行う。
            self.update_round(&rs);
            round_already_updated = true;
            // ラウンドが進んだ場合は full path にフォールバックする。
            // ここで round_start を保持したまま full path へ渡すことで、
            // adapt_upper_bounds がラウンド開始を 1 回だけ観測できる。
            if !self.round.round_start() {
                self.data_rate.update_max_bw(&rs);
                if let Some(rtt) = rtt_sample {
                    self.update_min_rtt(rtt, now);
                }
                // BBRUpdateControlParameters のみ実行する
                self.set_pacing_rate();
                self.set_send_quantum();
                self.set_cwnd(newly_acked);
                return;
            }
        }

        // full path: BBRUpdateModelAndState
        self.try_fast_path = false;
        self.update_latest_delivery_signals();
        self.update_congestion_signals(&rs, round_already_updated);
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

        // 次回の fast path 判定フラグを更新する
        // ProbeBW の安定フェーズ (Down/Cruise) で、アイドル復帰でなく、
        // ProbeRTT への遷移も不要な場合に有効化する
        self.try_fast_path = self.state == BbrState::ProbeBw
            && matches!(
                self.probe_bw.phase(),
                probe_bw::CyclePhase::Down | probe_bw::CyclePhase::Cruise
            )
            && !self.idle_restart
            && !self.data_volume.probe_rtt_expired();
    }
}

use crate::recovery::initial_window;

// ===========================================================================
// CongestionControl trait 実装
// ===========================================================================

impl CongestionControl for BbrV3 {
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
        if lost_bytes > 0 && !self.recovery.in_recovery() {
            // draft-ietf-ccwg-bbr-06 Section 5.6.4.4: 回復開始前に cwnd と
            // モデルを保存する。draft 改訂で保存対象が変わる可能性がある。
            self.save_state_upon_loss();
            self.recovery.on_congestion_event(now);
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        self.delivery_rate.on_packets_lost(lost_bytes);
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
        // RFC 9002 Section 7.3.2 の回復開始直後の 1 パケット送信を許可する。
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
        // draft-ietf-ccwg-bbr-06 Section 5.5.7.1:
        // 「the data packet with the latest transmission time」を使う。
        let newest_acked_time_sent = packets
            .iter()
            .map(|pkt| pkt.time_sent)
            .max()
            .expect("non-empty acknowledged packet list");
        let rtt_sample = Some(now - newest_acked_time_sent);

        // 回復終了時の復元をモデルの上限制御より先に行う
        // (draft-ietf-ccwg-bbr-06 Section 5.6.4.4 / RFC 9002 Section 7.3.2)。
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
            // このラウンド最初の損失なら、spurious loss に備えて状態を保存する
            // (draft-ietf-ccwg-bbr-06 Section 5.5.10.2 NoteLoss / Section 5.5.11.1)。
            if !self.congestion.loss_in_round() {
                self.save_state_upon_loss();
            }

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

        // ECT(0) / ECT(1) をマークした接続は CE マークを輻輳として扱う
        // (draft-ietf-ccwg-bbr-06 Section 3.7)。CE マーク時点の in-flight を
        // 上限推定に使い、inflight_longterm を引き下げる。ProbeBW_UP 中で
        // あればロスと同じく ProbeBW_DOWN へ遷移して増加を止める。
        let prior_inflight = self.bytes_in_flight.max(self.min_pipe_cwnd());
        self.handle_inflight_too_high(prior_inflight, false, now);
    }

    fn on_app_limited(&mut self) {
        // draft-ietf-ccwg-bbr-06 Section 4.1.2.4 CheckIfApplicationLimited:
        // 送信可能なデータが尽きた時点で inflight < cwnd なら
        // アプリケーション制限状態としてマークする。
        self.delivery_rate
            .check_if_application_limited(self.bytes_in_flight, self.cwnd);
    }

    fn on_spurious_loss_detection(&mut self, _now: Timestamp) {
        self.recovery = recovery::State::new();
        self.handle_spurious_loss_detection();
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

/// BBRv3 ファクトリ
#[derive(Debug, Clone)]
pub struct BbrV3Factory;

impl CongestionControlFactory for BbrV3Factory {
    type Controller = BbrV3;

    fn create(&self, max_datagram_size: u64) -> BbrV3 {
        BbrV3::new(max_datagram_size)
    }
}

// ===========================================================================
// テスト
// ===========================================================================

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_recovery;
