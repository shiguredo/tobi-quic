// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! CUBIC 輻輳制御 (RFC 9438) + HyStart++ (RFC 9406)
//!
//! パスごとに独立したインスタンスを持つ (RFC 10069 Section 5.3)。
//!
//! ## 参照
//!
//! - RFC 9438: CUBIC for Fast and Long-Distance Networks
//! - RFC 9406: HyStart++: Modified Slow Start for TCP
//! - draft-ietf-ccwg-ratelimited-increase-03: Rate-Limited Increase

use crate::recovery::congestion::{
    CongestionControl, CongestionControlFactory, CongestionStateKind, IdleReason,
};
use crate::recovery::pacing::Pacer;
use crate::recovery::{initial_window, minimum_window};
use crate::time::{Duration, Timestamp};

// ---------------------------------------------------------------------------
// CUBIC 定数 (RFC 9438 Section 5)
// ---------------------------------------------------------------------------

/// CUBIC の積極性パラメータ
const C: f64 = 0.4;

/// CUBIC の乗法的減少係数
const BETA_CUBIC: f64 = 0.7;

/// Reno-フレンドリー領域での加法的増加係数
/// α_cubic = 3 × (1 - β_cubic) / (1 + β_cubic)
const ALPHA_CUBIC: f64 = 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC);

/// pacing rate のゲイン (RFC 9002 Section 7.7 の N = 1.25)
const PACING_GAIN_NUM: u64 = 5;

/// pacing rate のゲインの分母
const PACING_GAIN_DEN: u64 = 4;

// ---------------------------------------------------------------------------
// HyStart++ 定数 (RFC 9406 Section 4)
// ---------------------------------------------------------------------------

/// 最小 RTT 閾値 (4 ms)
const HYSTART_MIN_RTT_THRESH: Duration = Duration::from_millis(4);

/// 最大 RTT 閾値 (16 ms)
const HYSTART_MAX_RTT_THRESH: Duration = Duration::from_millis(16);

/// RTT 分割因子
const HYSTART_MIN_RTT_DIVISOR: u64 = 8;

/// ラウンドあたりの最小 RTT サンプル数
const HYSTART_N_RTT_SAMPLE: usize = 8;

/// CSS 成長除数
const HYSTART_CSS_GROWTH_DIVISOR: u64 = 4;

/// CSS 最大ラウンド数
const HYSTART_CSS_ROUNDS: usize = 5;

// ---------------------------------------------------------------------------
// 共通定数
// ---------------------------------------------------------------------------

/// デフォルトの最大データグラムサイズ (QUIC 最小値)
const DEFAULT_MAX_DATAGRAM_SIZE: u64 = 1200;

// ---------------------------------------------------------------------------
// HyStart++ (RFC 9406)
// ---------------------------------------------------------------------------

/// HyStart++ の状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HyStartPhase {
    /// 標準スロースタート
    SlowStart,
    /// 保守的スロースタート (CSS)
    Css { rounds: usize },
}

/// HyStart++ (RFC 9406)
///
/// スロースタートの出口判定を RTT 増加検知で改善する。
#[derive(Debug)]
struct HyStartPlusPlus {
    /// 現在のフェーズ
    phase: HyStartPhase,
    /// 前ラウンドの最小 RTT
    last_round_min_rtt: Option<Duration>,
    /// 現在ラウンドの最小 RTT
    current_round_min_rtt: Option<Duration>,
    /// 現在ラウンドの RTT サンプル数
    rtt_sample_count: usize,
    /// ラウンド終了判定用の送信時刻境界
    ///
    /// RFC 9406 Section 4.2 は TCP のシーケンス番号でラウンドを区切る
    /// (windowEnd が ACK されたらラウンド終了)。QUIC ではパケット番号が
    /// 対応するが、本実装の HyStart++ は輻輳制御フック
    /// `on_ack_received` が受け取る「ACK された最新パケットの送信時刻」だけを
    /// 利用できる。パケット番号ベースの厳密なラウンド管理には CC フックへの
    /// 追加情報が必要なため、送信時刻による近似を使う。
    /// `start_new_round` で ACK 時刻を記録し、それ以降に送信されたパケットが
    /// ACK されたときにラウンド終了とみなす。近似はラウンド長を最大 1 RTT
    /// 程度過大にするが、RTT 増加検知の閾値判定への影響は小さい。
    round_end_time: Option<Timestamp>,
    /// CSS 開始時のベースライン最小 RTT
    css_baseline_min_rtt: Option<Duration>,
}

impl HyStartPlusPlus {
    fn new() -> Self {
        Self {
            phase: HyStartPhase::SlowStart,
            last_round_min_rtt: None,
            current_round_min_rtt: None,
            rtt_sample_count: 0,
            round_end_time: None,
            css_baseline_min_rtt: None,
        }
    }

    /// 新しいラウンドを開始する
    fn start_new_round(&mut self, now: Timestamp) {
        self.last_round_min_rtt = self.current_round_min_rtt;
        self.current_round_min_rtt = None;
        self.rtt_sample_count = 0;
        self.round_end_time = Some(now);
    }

    /// RTT サンプルを受け取る
    fn on_rtt_sample(&mut self, rtt: Duration) {
        self.current_round_min_rtt = Some(match self.current_round_min_rtt {
            Some(min) if rtt < min => rtt,
            Some(min) => min,
            None => rtt,
        });
        self.rtt_sample_count += 1;
    }

    /// ラウンド終了判定: newest_acked_time_sent が round_end_time を超えたか
    fn is_round_ended(&self, newest_acked_time_sent: Timestamp) -> bool {
        match self.round_end_time {
            Some(end) => newest_acked_time_sent >= end,
            None => true,
        }
    }

    /// ラウンド終了時にスロースタート終了判定を行う (RFC 9406 Section 3)
    ///
    /// 戻り値: true ならスロースタート終了、CSS に入る
    fn should_exit_slow_start(&self) -> bool {
        if self.rtt_sample_count < HYSTART_N_RTT_SAMPLE {
            return false;
        }

        let (current_min, last_min) = match (self.current_round_min_rtt, self.last_round_min_rtt) {
            (Some(c), Some(l)) => (c, l),
            _ => return false,
        };

        // RttThresh = max(MIN_RTT_THRESH, min(lastRoundMinRTT / MIN_RTT_DIVISOR, MAX_RTT_THRESH))
        let rtt_divisor = Duration::from_micros(last_min.as_micros() / HYSTART_MIN_RTT_DIVISOR);
        let rtt_thresh_inner = if rtt_divisor < HYSTART_MAX_RTT_THRESH {
            rtt_divisor
        } else {
            HYSTART_MAX_RTT_THRESH
        };
        let rtt_thresh = if HYSTART_MIN_RTT_THRESH > rtt_thresh_inner {
            HYSTART_MIN_RTT_THRESH
        } else {
            rtt_thresh_inner
        };

        // currentRoundMinRTT >= lastRoundMinRTT + RttThresh
        current_min >= last_min.saturating_add(rtt_thresh)
    }

    /// CSS でのウィンドウ増加量を計算する
    fn css_increment(&self, bytes_acknowledged: u64) -> u64 {
        bytes_acknowledged / HYSTART_CSS_GROWTH_DIVISOR
    }

    /// CSS で偽のスロースタート終了を検出した場合にスロースタートに戻る
    /// (RFC 9406 Section 3: currentRoundMinRTT < cssBaselineMinRtt)
    fn should_reenter_slow_start(&self) -> bool {
        match (self.current_round_min_rtt, self.css_baseline_min_rtt) {
            (Some(current), Some(baseline)) => current < baseline,
            _ => false,
        }
    }

    /// CSS のラウンド数が上限に達したか
    fn css_rounds_exceeded(&self) -> bool {
        matches!(self.phase, HyStartPhase::Css { rounds } if rounds >= HYSTART_CSS_ROUNDS)
    }
}

// ---------------------------------------------------------------------------
// CUBIC 状態
// ---------------------------------------------------------------------------

/// CUBIC の輻輳制御状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CubicState {
    /// スロースタート (HyStart++ 併用)
    SlowStart,
    /// リカバリ: ロス検出後、recovery_start_time 以降のパケットが ACK されるまで
    Recovery { recovery_start_time: Timestamp },
    /// 輻輳回避: CUBIC 関数に基づくウィンドウ増加
    CongestionAvoidance,
}

// ---------------------------------------------------------------------------
// CUBIC 輻輳制御器
// ---------------------------------------------------------------------------

/// CUBIC 輻輳制御 (RFC 9438) + HyStart++ (RFC 9406)
///
/// RFC 10069 Section 5.3:
/// パスごとに独立した輻輳制御状態を保持する。
#[derive(Debug)]
pub struct Cubic {
    /// 輻輳ウィンドウ (バイト、f64 で精密に計算する)
    congestion_window: f64,
    /// 送信中バイト数 (ACK 未受信)
    bytes_in_flight: u64,
    /// 直近の送信で cwnd を埋め切れたか (app-limited 判定、RFC 9002 Section 7.8)
    cwnd_limited: bool,
    /// アプリケーション制限中か
    ///
    /// [`CongestionControl::on_app_limited`] の通知で true になり、cwnd 律速の
    /// 送信に戻った時点で false になる。RFC 9002 Section 7.8 の app-limited は
    /// 「bytes in flight < cwnd かつ pacing 制限でない」で判定するが、このフラグは
    /// 送信データが尽きたことの通知だけに基づくため判定条件が異なる。
    /// RFC 9438 Section 5.8 は受信アプリケーションの広告ウィンドウによる制限も
    /// アプリケーション制限と定義するが、本実装が扱うのは通知された期間
    /// (送信データが尽きた期間) に限られる。接続全体が idle になると全パスへ
    /// 通知されるため、パス単位の遊休の一部は結果的に除外され得る。
    app_limited: bool,
    /// epoch の基準時刻
    ///
    /// アプリケーション制限期間を輻輳回避の経過時間 `t` から除外するために使う
    /// (RFC 9438 Section 4.2 / Section 5.8)。ACK の入口、スロースタートの終了、
    /// Recovery の終了、送信側の補正で更新する。
    ///
    /// 通常は最後に輻輳回避の ACK を受信した時刻であり、送信側の補正の直後だけ
    /// 補正した送信時刻になる。送信側の補正は、基準からアプリケーション制限後
    /// 最初の cwnd 律速送信までの区間を `t` から除外するため、データ枯渇の直前に
    /// cwnd 律速だった区間のうち最後の ACK からデータ枯渇までの部分 (最大 1 RTT
    /// 程度) と、再開後に cwnd 律速になるまでの区間も併せて除外され得る。
    /// いずれも増加が小さくなる方向であり、安全性の問題はない。
    epoch_reference_time: Option<Timestamp>,
    /// スロースタート閾値
    ssthresh: u64,
    /// 輻輳制御の状態
    state: CubicState,
    /// 最大データグラムサイズ
    max_datagram_size: u64,
    /// 最後の輻輳イベント時のウィンドウサイズ (パケット単位)
    w_max: f64,
    /// 前回の W_max (Fast Convergence 用、パケット単位)
    w_last_max: f64,
    /// W_max に到達するまでの時間パラメータ K (秒)
    k: f64,
    /// 輻輳回避開始時刻
    congestion_avoidance_start: Option<Timestamp>,
    /// Reno-フレンドリー領域での推定ウィンドウ W_est (パケット単位)
    w_est: f64,
    /// 平滑化 RTT (on_rtt_update で更新)
    smoothed_rtt: Duration,
    /// 最小 RTT (on_rtt_update で更新)
    min_rtt: Duration,
    /// HyStart++ 状態
    hystart: HyStartPlusPlus,
    /// Pacing (RFC 9002 Section 7.7)
    pacer: Pacer,
}

impl Cubic {
    /// 新しい CUBIC 輻輳制御器を作成する
    pub fn new(max_datagram_size: u64) -> Self {
        Self {
            congestion_window: initial_window(max_datagram_size) as f64,
            bytes_in_flight: 0,
            // 送信実績が無い間は cwnd 律速扱いにする
            cwnd_limited: true,
            // 送信実績が無い間はアプリケーション制限ではない
            app_limited: false,
            epoch_reference_time: None,
            ssthresh: u64::MAX,
            state: CubicState::SlowStart,
            max_datagram_size,
            w_max: 0.0,
            w_last_max: 0.0,
            k: 0.0,
            congestion_avoidance_start: None,
            w_est: 0.0,
            smoothed_rtt: Duration::from_millis(333), // INITIAL_RTT
            min_rtt: Duration::ZERO,
            hystart: HyStartPlusPlus::new(),
            pacer: Pacer::new(max_datagram_size),
        }
    }

    /// デフォルトのデータグラムサイズで作成する
    pub fn with_default_mtu() -> Self {
        Self::new(DEFAULT_MAX_DATAGRAM_SIZE)
    }

    /// smoothed RTT と cwnd から pacing rate を更新する
    ///
    /// RFC 9002 Section 7.7 の rate = N * congestion_window / smoothed_rtt
    /// (N = 1.25) を使う。RTT サンプルが 0 の間は pacing しない。
    ///
    /// `set_pacing_rate_value` は rate に合わせて send quantum も再計算するため、
    /// cwnd 変化時にも送信バーストの上限が追従する。
    fn update_pacing_rate(&mut self) {
        let rtt_us = self.smoothed_rtt.as_micros();
        if rtt_us == 0 {
            return;
        }
        let cwnd = self.congestion_window as u64;
        let rate = (cwnd as u128 * PACING_GAIN_NUM as u128 * 1_000_000)
            / (rtt_us as u128 * PACING_GAIN_DEN as u128);
        self.pacer
            .set_pacing_rate_value(rate.min(u64::MAX as u128) as u64);
    }

    /// 現在の輻輳状態を返す
    pub fn state(&self) -> CubicState {
        self.state
    }

    /// ssthresh を返す
    pub fn ssthresh(&self) -> u64 {
        self.ssthresh
    }

    /// バイトをパケット単位に変換する
    fn bytes_to_packets(&self, bytes: f64) -> f64 {
        bytes / self.max_datagram_size as f64
    }

    /// パケット単位をバイトに変換する
    fn packets_to_bytes(&self, packets: f64) -> f64 {
        packets * self.max_datagram_size as f64
    }

    /// W_cubic(t) を計算する (RFC 9438 Section 4.2)
    ///
    /// W_cubic(t) = C × (t - K)³ + W_max
    /// t, K: 秒、W_cubic: パケット単位
    fn w_cubic(&self, t_secs: f64) -> f64 {
        let dt = t_secs - self.k;
        C * dt * dt * dt + self.w_max
    }

    /// W_est(t) を更新する (RFC 9438 Section 4.3)
    ///
    /// W_est = W_est + α_cubic × (segments_acked / cwnd)
    fn update_w_est(&mut self, bytes_acknowledged: u64) {
        let cwnd_packets = self.bytes_to_packets(self.congestion_window);
        if cwnd_packets > 0.0 {
            let segments_acked = bytes_acknowledged as f64 / self.max_datagram_size as f64;
            self.w_est += ALPHA_CUBIC * segments_acked / cwnd_packets;
        }
    }

    /// 輻輳回避フェーズの処理 (RFC 9438 Section 4.2-4.4)
    fn congestion_avoidance_on_ack(&mut self, bytes_acknowledged: u64, now: Timestamp) {
        // 更新前の基準時刻を控えてから、この ACK 時刻を新しい基準にする。
        // アプリケーション制限期間の補正には、この ACK の直前までの経過時間を使う
        // (RFC 9438 Section 4.2 / Section 5.8)。
        let previous_reference_time = self.epoch_reference_time;
        self.epoch_reference_time = Some(now);

        if !self.cwnd_limited {
            // アプリケーション制限中は cwnd も W_est も更新しない
            // (RFC 9438 Section 5.8)。休止期間を輻輳回避の経過時間 t に含めない
            // よう、直前の基準時刻からの経過時間を開始時刻へ移す
            // (RFC 9438 Section 4.2)。
            if self.app_limited
                && let (Some(previous), Some(start)) =
                    (previous_reference_time, self.congestion_avoidance_start)
            {
                self.congestion_avoidance_start =
                    Some(start.add(now.saturating_duration_since(previous)));
            }
            // pacing 制限などアプリケーション制限でない場合も cwnd と W_est を
            // 増やさない (RFC 9002 Section 7.8)。この場合は t の開始時刻を
            // 動かさない。
            return;
        }

        let ca_start = match self.congestion_avoidance_start {
            Some(s) => s,
            None => return,
        };

        // 経過時間 t (秒)
        let t_secs = (now - ca_start).as_micros() as f64 / 1_000_000.0;
        let rtt_secs = self.smoothed_rtt.as_micros() as f64 / 1_000_000.0;

        if rtt_secs <= 0.0 {
            return;
        }

        // W_cubic(t + RTT) を目標とする (RFC 9438 Section 4.2)
        let w_cubic_target = self.w_cubic(t_secs + rtt_secs);
        let cwnd_packets = self.bytes_to_packets(self.congestion_window);

        // target の制約 (RFC 9438 Section 4.2)
        let target = if w_cubic_target < cwnd_packets {
            cwnd_packets
        } else if w_cubic_target > 1.5 * cwnd_packets {
            1.5 * cwnd_packets
        } else {
            w_cubic_target
        };

        // W_est を更新する (RFC 9438 Section 4.3)
        self.update_w_est(bytes_acknowledged);

        // TCP-Friendly 領域 (RFC 9438 Section 4.3): W_cubic < W_est の場合
        if target < self.w_est {
            // Reno-フレンドリー領域: W_est を使用する
            self.congestion_window = self.packets_to_bytes(self.w_est);
        } else {
            // CUBIC 領域 (凹・凸): target に向けて cwnd を増加する
            // cwnd += (target - cwnd_packets) / cwnd_packets × max_datagram_size (1 ACK あたり)
            let segments_acked = bytes_acknowledged as f64 / self.max_datagram_size as f64;
            if cwnd_packets > 0.0 {
                let increment = (target - cwnd_packets) / cwnd_packets * segments_acked;
                self.congestion_window += increment * self.max_datagram_size as f64;
            }
        }
    }

    /// 乗法的減少 (RFC 9438 Section 4.6)
    fn multiplicative_decrease(&mut self) {
        let cwnd_packets = self.bytes_to_packets(self.congestion_window);

        // Fast Convergence (RFC 9438 Section 4.7)
        // 前回の W_max より小さい場合はさらに W_max を削減する
        if cwnd_packets < self.w_last_max {
            self.w_last_max = cwnd_packets;
            self.w_max = cwnd_packets * (1.0 + BETA_CUBIC) / 2.0;
        } else {
            self.w_last_max = cwnd_packets;
            self.w_max = cwnd_packets;
        }

        // ssthresh = flight_size × β_cubic (RFC 9438 Section 4.6)
        // 本実装は flight_size の代わりに cwnd を使用する。RFC 9438 Section 4.6 は
        // cwnd の使用を許容するが、bytes in flight が cwnd より小さいときに cwnd を
        // 増やさない措置を MUST とする。この措置は on_packet_sent の cwnd_limited
        // 記録と slow start / congestion avoidance のガードで実装している。
        let new_ssthresh = (self.congestion_window * BETA_CUBIC) as u64;
        let min_window = minimum_window(self.max_datagram_size);
        self.ssthresh = new_ssthresh.max(min_window);
        self.congestion_window = self.ssthresh as f64;

        // K = ∛[(W_max - cwnd_epoch) / C] (RFC 9438 Section 4.2)
        // cwnd_epoch = 現在の cwnd (パケット単位)
        let cwnd_epoch_packets = self.bytes_to_packets(self.congestion_window);
        let diff = self.w_max - cwnd_epoch_packets;
        self.k = if diff > 0.0 {
            libm::cbrt(diff / C)
        } else {
            0.0
        };
    }

    /// スロースタート終了時の初期化
    fn on_slow_start_exit(&mut self, now: Timestamp) {
        self.congestion_avoidance_start = Some(now);
        // スロースタート終了時点を起点として、次の ACK からの経過時間を測る。
        self.epoch_reference_time = Some(now);
        self.w_max = self.bytes_to_packets(self.congestion_window);
        self.w_last_max = self.w_max;
        self.k = 0.0;
        self.w_est = self.bytes_to_packets(self.congestion_window);
    }

    /// 新しい輻輳イベントを処理する (RFC 9002 Section 7.3.2 / Appendix B.6)
    ///
    /// ロス検出と ECN-CE カウントの増加の両方から呼ばれる。CUBIC の乗法減少
    /// (RFC 9438 Section 4.6) を行って Recovery に入る。すでに Recovery 中の
    /// 場合は、同一 RTT 内で複数の輻輳イベントに反応しないよう何もしない。
    fn on_congestion_event(&mut self, now: Timestamp) {
        // Recovery 中は追加の輻輳イベントを無視する (RFC 9002 Appendix B.6)
        if matches!(self.state, CubicState::Recovery { .. }) {
            return;
        }

        // 乗法的減少 (RFC 9438 Section 4.6)
        self.multiplicative_decrease();

        self.state = CubicState::Recovery {
            recovery_start_time: now,
        };

        self.update_pacing_rate();
    }
}

impl CongestionControl for Cubic {
    fn state_kind(&self) -> CongestionStateKind {
        match self.state {
            CubicState::SlowStart => CongestionStateKind::SlowStart,
            CubicState::Recovery { .. } => CongestionStateKind::Recovery,
            CubicState::CongestionAvoidance => CongestionStateKind::CongestionAvoidance,
        }
    }

    /// in-flight パケットの送信時に呼び出す (RFC 9002 Appendix B.4)
    ///
    /// ACK / PATH_ACK 専用パケットは in-flight ではないため、呼び出し側が
    /// 通知しない契約とする (RFC 9002 Section 2)。
    fn on_packet_sent(&mut self, sent_bytes: u64) {
        self.bytes_in_flight += sent_bytes;
        // 直近の送信で cwnd を埋め切れたかを記録する (RFC 9002 Section 7.8)。
        // 送信のたびに上書きするので、アプリ律速から復帰すると再び true になる。
        self.cwnd_limited =
            self.bytes_in_flight + self.max_datagram_size > self.congestion_window as u64;
    }

    fn on_packet_acked_bytes(&mut self, acked_bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);
    }

    /// PMTU の更新を 1 データグラム長に反映する
    ///
    /// `is_congestion_limited` の判定と輻輳ウィンドウの増加量計算に使う
    /// 1 データグラム長を最新の PMTU に合わせる。PMTU が伸びたパスで
    /// 輻輳ウィンドウを超えて送らないようにするため
    /// (RFC 10069 Section 5.3)。
    ///
    /// RFC 8899 Section 3: PLPMTU の更新で輻輳ウィンドウをバイト単位で増やしては
    /// ならない (MUST NOT)。増減にかかわらず `cwnd` のバイト数を据え置き、
    /// 1 データグラム長・pacing の送信量子だけを更新する。
    ///
    /// RFC 9002 Section 7.2 の「ハンドシェイク完了のための縮小で初期ウィンドウを
    /// 設定する」SHOULD は実装しない。既定の PMTU は 1200 から始まるため、
    /// 通常はハンドシェイク中の縮小が発生しない。
    fn on_mtu_update(&mut self, new_mtu: u64) {
        self.max_datagram_size = new_mtu;
        self.pacer.set_send_quantum(new_mtu);
        self.update_pacing_rate();
    }

    /// 鍵破棄に伴い破棄したパケットのバイト数を bytes_in_flight から除去する
    /// (RFC 9002 Section 6.4)
    fn on_packet_discarded_bytes(&mut self, discarded_bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(discarded_bytes);
    }

    fn on_ack_received(
        &mut self,
        bytes_acknowledged: u64,
        newest_acked_time_sent: Timestamp,
        now: Timestamp,
    ) {
        match self.state {
            CubicState::SlowStart => {
                // HyStart++ のラウンド管理
                let round_ended = self.hystart.is_round_ended(newest_acked_time_sent);

                match self.hystart.phase {
                    HyStartPhase::SlowStart => {
                        // app-limited (bytes in flight < cwnd) のときは cwnd を
                        // 増やさない (RFC 9002 Section 7.8)
                        if self.cwnd_limited {
                            // 標準スロースタート: 指数的成長
                            self.congestion_window += bytes_acknowledged as f64;
                        }

                        if round_ended {
                            // ラウンド終了時にスロースタート終了判定
                            if self.hystart.should_exit_slow_start() {
                                // CSS に入る
                                self.hystart.css_baseline_min_rtt =
                                    self.hystart.current_round_min_rtt;
                                self.hystart.phase = HyStartPhase::Css { rounds: 0 };
                            }
                            self.hystart.start_new_round(now);
                        }
                    }
                    HyStartPhase::Css { rounds } => {
                        // app-limited (bytes in flight < cwnd) のときは cwnd を
                        // 増やさない (RFC 9002 Section 7.8)
                        if self.cwnd_limited {
                            // CSS: 成長率を抑制する (RFC 9406 Section 3)
                            let increment = self.hystart.css_increment(bytes_acknowledged);
                            self.congestion_window += increment as f64;
                        }

                        if round_ended {
                            // 偽のスロースタート終了検出
                            if self.hystart.should_reenter_slow_start() {
                                self.hystart.css_baseline_min_rtt = None;
                                self.hystart.phase = HyStartPhase::SlowStart;
                            } else {
                                let new_rounds = rounds + 1;
                                self.hystart.phase = HyStartPhase::Css { rounds: new_rounds };
                            }
                            self.hystart.start_new_round(now);

                            // CSS ラウンド数上限に達したら輻輳回避へ
                            if self.hystart.css_rounds_exceeded() {
                                self.ssthresh = self.congestion_window as u64;
                                self.on_slow_start_exit(now);
                                self.state = CubicState::CongestionAvoidance;
                                return;
                            }
                        }
                    }
                }

                // ssthresh を超えたら CongestionAvoidance へ
                if self.congestion_window as u64 >= self.ssthresh {
                    self.on_slow_start_exit(now);
                    self.state = CubicState::CongestionAvoidance;
                }
            }
            CubicState::Recovery {
                recovery_start_time,
            } => {
                // Recovery 中はウィンドウを増加しない
                // recovery_start_time 以降に送信されたパケットが ACK されたら終了
                if newest_acked_time_sent > recovery_start_time {
                    self.congestion_avoidance_start = Some(now);
                    // Recovery 終了時点を起点として、次の ACK からの経過時間を測る。
                    self.epoch_reference_time = Some(now);
                    // W_est を現在の cwnd に初期化する
                    self.w_est = self.bytes_to_packets(self.congestion_window);
                    self.state = CubicState::CongestionAvoidance;
                }
            }
            CubicState::CongestionAvoidance => {
                self.congestion_avoidance_on_ack(bytes_acknowledged, now);
            }
        }

        self.update_pacing_rate();
    }

    fn on_packets_lost(&mut self, lost_bytes: u64, now: Timestamp) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);

        self.on_congestion_event(now);
    }

    /// ECN-CE カウントの増加を新しい輻輳イベントとして扱う
    /// (RFC 9002 Section 7.1 / Appendix B.7)
    ///
    /// CE マークはパケットロスではないため bytes_in_flight は変更せず、
    /// RFC 9438 Section 4.6 の乗法減少 (β_cubic = 0.7) を行う。
    /// `ce_count` は前回の ACK からの増分であり、1 回の通知で複数の CE が
    /// まとめて届いても 1 回の輻輳イベントとして扱う。
    fn on_ecn_ce_count(&mut self, ce_count: u64, now: Timestamp) {
        if ce_count == 0 {
            return;
        }

        self.on_congestion_event(now);
    }

    fn on_persistent_congestion(&mut self) {
        self.congestion_window = minimum_window(self.max_datagram_size) as f64;
        self.ssthresh = u64::MAX;
        self.state = CubicState::SlowStart;
        self.w_max = 0.0;
        self.w_last_max = 0.0;
        self.k = 0.0;
        self.congestion_avoidance_start = None;
        self.epoch_reference_time = None;
        self.app_limited = false;
        self.w_est = 0.0;
        self.hystart = HyStartPlusPlus::new();

        self.update_pacing_rate();
    }

    fn congestion_window(&self) -> u64 {
        self.congestion_window as u64
    }

    fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    fn available_window(&self) -> u64 {
        (self.congestion_window as u64).saturating_sub(self.bytes_in_flight)
    }

    fn is_congestion_limited(&self) -> bool {
        self.available_window() < self.max_datagram_size
    }

    fn on_rtt_update(&mut self, smoothed_rtt: Duration, min_rtt: Duration, latest_rtt: Duration) {
        self.smoothed_rtt = smoothed_rtt;
        self.min_rtt = min_rtt;

        // HyStart++ に RTT サンプルを通知する
        if self.state == CubicState::SlowStart {
            self.hystart.on_rtt_sample(latest_rtt);
        }

        self.update_pacing_rate();
    }

    /// パケット送信時に pacer の departure time を更新する
    ///
    /// あわせて、アプリケーション制限から復帰した最初の cwnd 律速送信で、
    /// 休止期間を輻輳回避の経過時間 `t` から除外する。epoch の基準時刻からこの
    /// 送信までの経過時間を開始時刻へ移すことで、休止前の cwnd 律速期間の経過
    /// 時間は維持したまま休止期間だけを取り除く
    /// (RFC 9438 Section 4.2 / Section 5.8、RFC 9002 Section 7.8)。
    /// 補正後は基準時刻をこの送信時刻へ進める。進めないと、ACK を挟まずに再び
    /// アプリケーション制限と cwnd 律速送信が起きたときに同じ区間を二重に
    /// `t` から除外してしまう。
    fn on_packet_sent_cc(
        &mut self,
        _space: crate::recovery::loss_detection::PacketNumberSpace,
        _pn: u64,
        sent_bytes: u64,
        now: Timestamp,
    ) {
        self.pacer.on_packet_sent(now, sent_bytes);

        // アプリケーション制限中でも cwnd 律速でない送信では epoch を補正しない。
        if !self.app_limited || !self.cwnd_limited {
            return;
        }

        if matches!(self.state, CubicState::CongestionAvoidance)
            && let (Some(reference), Some(start)) =
                (self.epoch_reference_time, self.congestion_avoidance_start)
        {
            self.congestion_avoidance_start =
                Some(start.add(now.saturating_duration_since(reference)));
        }
        // 補正の基準をこの送信時刻へ進める。ACK を挟まずにアプリケーション制限と
        // cwnd 律速送信が繰り返されても、同じ区間を二重に除外しない。
        self.epoch_reference_time = Some(now);
        // cwnd 律速の送信に戻ったため、アプリケーション制限を解除する。
        // CongestionAvoidance 以外や時刻が未記録の場合も、休止期間の補正は
        // できないが制限状態からは復帰する。
        self.app_limited = false;
    }

    /// 送信可能なアプリケーションデータが尽きた通知
    ///
    /// 通知されたアプリケーション制限期間 (送信データが尽きた期間) を、輻輳回避の
    /// 経過時間 `t` から除外する (RFC 9438 Section 4.2 / Section 5.8)。
    /// RFC 9438 Section 5.8 のアプリケーション制限は受信アプリケーションの広告
    /// ウィンドウによる制限も含むが、本実装は接続層から通知される「送信データが
    /// 尽きた期間」だけを扱う。フロー制御制限で送れない期間は通知されないため
    /// `t` から除外されない。パス単位の遊休は、接続全体が idle になった時点で
    /// 全パスへ通知されるため、一部は結果的に除外され得る。
    fn on_app_limited(&mut self) {
        self.app_limited = true;
    }

    fn on_idle(&mut self, _reason: IdleReason) {
        self.app_limited = true;
    }

    fn is_app_limited(&self) -> bool {
        self.app_limited
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

/// CUBIC ファクトリ
#[derive(Debug, Clone)]
pub struct CubicFactory;

impl CongestionControlFactory for CubicFactory {
    type Controller = Cubic;

    fn create(&self, max_datagram_size: u64) -> Cubic {
        Cubic::new(max_datagram_size)
    }
}

#[cfg(test)]
mod tests;
