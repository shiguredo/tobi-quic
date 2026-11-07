// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 輻輳制御 (RFC 9002 Section 7)
//!
//! パスごとに独立したインスタンスを持つ (draft-ietf-quic-multipath-21 Section 5.3)。
//! 各パスの CWND を超えて送信してはならない。
//! CID 変更のみ (アドレス変更なし) の場合は輻輳状態を維持する。

use core::fmt::Debug;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use alloc::sync::Arc;

use crate::time::{Duration, Timestamp};

use super::bbr::{BbrV2, BbrV2Factory, BbrV3, BbrV3Factory};
use super::cubic::{Cubic, CubicFactory};
use super::loss_detection::PacketNumberSpace;
use super::pacing::Pacer;
use super::{initial_window, minimum_window};

// ---------------------------------------------------------------------------
// 輻輳制御 trait
// ---------------------------------------------------------------------------

/// 送信停止の理由
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleReason {
    /// 送信可能なアプリケーションデータが尽きた
    NoData,
    /// フロー制御クレジット不足で送れない
    FlowControlLimited,
    /// 送信可能だがスケジューラーに選ばれないパスがある
    PathNotSelected,
}

/// 輻輳制御アルゴリズムの抽象インターフェース
///
/// パスごとに独立したインスタンスを持つ (draft-ietf-quic-multipath-21 Section 5.3)。
/// CUBIC, BBRv2 等のアルゴリズムを差し替え可能にする。
pub trait CongestionControl: Debug + Send {
    /// パケット送信時に呼び出す
    ///
    /// BBR 実装を使う場合の前提: このメソッドの直後に、同じ `sent_bytes` で
    /// `on_packet_sent_cc` または `on_packet_sent_cc_unpaced` を呼ぶこと。
    /// 実送信経路 (tobi-transport) もこの順序で呼ぶ。BBR はこのメソッドで
    /// `sent_bytes` が in-flight に加算済みになった状態から送信前の値を復元し、
    /// アイドル復帰判定と Delivery Rate Sampling に使う。CUBIC / NewReno は
    /// この順序を必要としない。
    fn on_packet_sent(&mut self, sent_bytes: u64);

    /// ACK されたバイト数を bytes_in_flight から除去する
    ///
    /// RFC 9002 Appendix B.5: 呼び出し側は in-flight だったパケットの
    /// `sent_bytes` だけを渡す。ACK 専用パケットは in-flight ではないため、
    /// このメソッドにも渡してはならない。
    fn on_packet_acked_bytes(&mut self, acked_bytes: u64);

    /// 鍵破棄に伴い破棄したパケットのバイト数を bytes_in_flight から除去する
    ///
    /// RFC 9002 Section 6.4: Initial / Handshake 鍵を破棄した時点で、
    /// その空間の recovery state を破棄し bytes in flight から取り除かなければ
    /// ならない (MUST)。ACK による除去 (`on_packet_acked_bytes`) とは意味が
    /// 異なるため専用メソッドとする。cwnd には影響しない。
    fn on_packet_discarded_bytes(&mut self, discarded_bytes: u64);

    /// 鍵破棄などで送信済みパケットの状態を破棄するときに呼び出す
    ///
    /// RFC 9002 Section 6.4: Initial / Handshake 鍵を破棄した時点で、
    /// その空間の recovery state を破棄しなければならない (MUST)。
    /// `on_packet_discarded_bytes` が bytes in flight の会計を担当するのに対し、
    /// こちらは CC 固有の per-packet 状態 (BBR の Delivery Rate Sampling 用
    /// スナップショット) の削除を担当する。
    fn on_packets_discarded_cc(&mut self, _space: PacketNumberSpace, _packet_numbers: &[u64]) {}

    /// ACK 受信時にウィンドウを更新する
    ///
    /// RFC 9002 Appendix B.5: `bytes_acknowledged` は in-flight だったパケットの
    /// `sent_bytes` 合計、`newest_acked_time_sent` は in-flight だった ACK 済み
    /// パケットの最新送信時刻とする。ACK 専用パケットの送信時刻を Recovery の
    /// 終了判定に使ってはならない。
    fn on_ack_received(
        &mut self,
        bytes_acknowledged: u64,
        newest_acked_time_sent: Timestamp,
        now: Timestamp,
    );

    /// ロスト検出時に呼び出す
    fn on_packets_lost(&mut self, lost_bytes: u64, now: Timestamp);

    /// 持続的輻輳の検出時に呼び出す
    fn on_persistent_congestion(&mut self);

    /// 推定帯域 (bytes/sec) を返す
    ///
    /// 配送レートのサンプルから推定した帯域を返す。帯域推定を持たない
    /// アルゴリズム (NewReno / CUBIC など) は `None` を返す。
    /// マルチパスではパスごとに別のインスタンスが持つ値を返す。
    fn bandwidth_estimate(&self) -> Option<u64> {
        None
    }

    /// 輻輳ウィンドウ (バイト) を返す
    fn congestion_window(&self) -> u64;

    /// 観測用の輻輳制御状態の分類を返す
    ///
    /// 輻輳制御アルゴリズムごとに状態型が異なるため、既定では
    /// [`CongestionStateKind::Other`] を返す。状態遷移を持つアルゴリズムは
    /// オーバーライドして観測 API に状態変化を通知する。
    fn state_kind(&self) -> CongestionStateKind {
        CongestionStateKind::Other
    }

    /// 送信中バイト数を返す
    fn bytes_in_flight(&self) -> u64;

    /// 送信可能バイト数を返す
    fn available_window(&self) -> u64;

    /// 輻輳制限状態か (送信可能バイト数が 1 データグラム未満)
    fn is_congestion_limited(&self) -> bool;

    /// RTT 更新時に呼び出す
    ///
    /// CUBIC 等 RTT 情報に依存するアルゴリズムがオーバーライドする。
    fn on_rtt_update(
        &mut self,
        _smoothed_rtt: crate::time::Duration,
        _min_rtt: crate::time::Duration,
        _latest_rtt: crate::time::Duration,
    ) {
    }

    // -----------------------------------------------------------------------
    // 送信時の CC フック
    //
    // BBR は Delivery Rate Sampling の per-packet スナップショットを取るために、
    // CUBIC はアプリケーション制限から復帰した最初の cwnd 律速送信で epoch を
    // 補正するために、NewReno は pacer の departure time を更新するために使う。
    // -----------------------------------------------------------------------

    /// パケット送信時に CC 固有の送信時処理を行う
    ///
    /// BBR 実装を使う場合の前提: 同一 `sent_bytes` で `on_packet_sent` を
    /// 先に呼ぶこと。BBR は `sent_bytes` が in-flight に加算済みの状態を
    /// 前提に、送信前の in-flight を復元する。
    /// BBR は Delivery Rate Sampling の per-packet スナップショットを記録する。
    /// CUBIC はアプリケーション制限から復帰した最初の cwnd 律速送信で、
    /// 輻輳回避の epoch を補正するために使用する
    /// (RFC 9438 Section 4.2 / Section 5.8)。
    /// NewReno は pacer の departure time 更新だけを行う。
    /// パケット番号は空間ごとに独立して採番されるため、`space` と `pn` の
    /// 組で状態を識別する (RFC 9000 Section 12.3)。
    fn on_packet_sent_cc(
        &mut self,
        _space: PacketNumberSpace,
        _pn: u64,
        _sent_bytes: u64,
        _now: Timestamp,
    ) {
    }

    /// pacing の対象外の ack-eliciting パケット送信時に呼び出す
    ///
    /// Initial / Handshake / 0-RTT は pacing ゲートを適用しないため、
    /// Pacer は進めるが `P.send_time` には departure time ではなく実際の
    /// 送信時刻を使う。デフォルトは `on_packet_sent_cc` と同じ扱い。
    /// BBR 実装を使う場合の前提は `on_packet_sent_cc` と同じ。
    fn on_packet_sent_cc_unpaced(
        &mut self,
        space: PacketNumberSpace,
        pn: u64,
        sent_bytes: u64,
        now: Timestamp,
    ) {
        self.on_packet_sent_cc(space, pn, sent_bytes, now);
    }

    // -----------------------------------------------------------------------
    // ACK・ロス・ECN の CC フック (デフォルト実装)
    // -----------------------------------------------------------------------

    /// ACK されたパケットの詳細情報を受け取る
    ///
    /// BBR は per-packet state を参照して RateSample を生成する。
    /// RFC 9002 Appendix B.5: 呼び出し側は in-flight だったパケットだけを渡す。
    /// ACK 専用パケットを渡すと、配送レートと RTT サンプルに影響する。
    fn on_packets_acked_cc(&mut self, _packets: &[AckedPacketInfo], _now: Timestamp) {}

    /// ロスト検出の詳細情報を受け取る
    ///
    /// BBR は per-packet の PacketDeliveryState を参照してロスト率から
    /// モデルパラメータを更新する。
    fn on_packets_lost_cc(&mut self, _lost_packets: &[LostPacketInfo], _now: Timestamp) {}

    /// ECN CE カウント通知
    ///
    /// ACK フレームの ECN セクションから CE カウントの増分を受け取る。
    /// CE カウントの増加は新しい輻輳イベントである (RFC 9002 Section 7.1 /
    /// Appendix B.7)。NewReno と CUBIC はロス検出時と同じ回復遷移を行い、
    /// BBR は ECN CE マークを輻輳信号として利用する (draft-ietf-ccwg-bbr-06)。
    fn on_ecn_ce_count(&mut self, _ce_count: u64, _now: Timestamp) {}

    /// 送信可能なアプリケーションデータが尽きた通知
    ///
    /// BBR はアプリケーション制限状態 (C.app_limited) の検出に使う
    /// (draft-ietf-ccwg-bbr-06 Section 4.1.2.4 CheckIfApplicationLimited)。
    /// CUBIC はアプリケーション制限期間を輻輳回避の経過時間 t から除外する
    /// ために使う (RFC 9438 Section 4.2 / Section 5.8)。
    /// 呼び出し側は、未送信データ・送信待ち・再送待ちが無い時点で呼ぶこと。
    fn on_app_limited(&mut self) {}

    /// 送信停止の理由付き通知
    ///
    /// `on_app_limited` の拡張として、データ枯渇だけでなくフロー制御停止と
    /// パス単位の遊休も伝える。既定実装はデータ枯渇だけを既存の
    /// `on_app_limited` へ渡す (BBR の既存動作を維持する)。CUBIC は休止時間を
    /// 輻輳回避の経過時間から除外するため、すべての理由で同じ補正を行う。
    fn on_idle(&mut self, reason: IdleReason) {
        if matches!(reason, IdleReason::NoData) {
            self.on_app_limited();
        }
    }

    /// アプリケーション制限中か (休止補正の保留状態)
    ///
    /// 実装が休止補正を保留している間 true を返す。既定実装は false。
    fn is_app_limited(&self) -> bool {
        false
    }

    /// 損失回復が spurious だったことが判明した通知
    ///
    /// RFC 9002 Section 6.1: パケット閾値・時間閾値でロストと判定したパケットが
    /// 後から ACK された場合に呼ばれる。BBRv3 は損失回復の開始時に保存した
    /// cwnd・モデルパラメータを復元する
    /// (draft-ietf-ccwg-bbr-06 Section 5.5.11 HandleSpuriousLossDetection)。
    /// BBRv2 (draft-cardwell-iccrg-bbr-congestion-control-02) には
    /// SaveStateUponLoss / HandleSpuriousLossDetection に相当するモデル undo が
    /// 規定されていないため、既定実装 (no-op) のままとする。
    fn on_spurious_loss_detection(&mut self, _now: Timestamp) {}

    /// MTU 変更通知
    ///
    /// PMTU 変更時に最大データグラムサイズ・pacing・cwnd のスケーリングが
    /// 必要なアルゴリズムがオーバーライドする。既定実装は何もしない。
    ///
    /// RFC 8899 Section 3: PLPMTU の更新で輻輳ウィンドウをバイト単位で増やしては
    /// ならない (MUST NOT)。各実装は縮小更新で初期ウィンドウへ引き上げない。
    fn on_mtu_update(&mut self, _new_mtu: u64) {}

    /// Pacing rate を返す (bytes/sec)
    ///
    /// None なら pacing 不要 (NewReno/CUBIC)。
    /// BBR は帯域推定に基づく pacing rate を返す。
    fn pacing_rate(&self) -> Option<u64> {
        None
    }

    /// 次のパケットの最早送信時刻を返す (Sans I/O)
    ///
    /// None なら即座に送信可能。Some なら指定時刻まで待機する。
    /// BBR は Pacer の departure time を返す。
    fn earliest_departure_time(&self) -> Option<crate::time::Timestamp> {
        None
    }
}

/// ACK されたパケットの情報
///
/// on_packets_acked_cc() で渡される個別パケット情報。
#[derive(Debug, Clone, Copy)]
pub struct AckedPacketInfo {
    /// パケット番号空間
    ///
    /// Initial / Handshake / Application Data でパケット番号は独立して
    /// 採番されるため、状態を (空間, パケット番号) の組で識別する
    /// (RFC 9000 Section 12.3)。
    pub space: PacketNumberSpace,
    /// パケット番号
    pub pn: u64,
    /// 送信時刻
    pub time_sent: Timestamp,
    /// 送信バイト数
    pub sent_bytes: u64,
}

/// ロストしたパケットの情報
///
/// on_packets_lost_cc() で渡される個別パケット情報。
/// BBR は per-packet の PacketDeliveryState にアクセスするために
/// パケット番号と送信時刻を必要とする。
#[derive(Debug, Clone, Copy)]
pub struct LostPacketInfo {
    /// パケット番号空間
    ///
    /// Initial / Handshake / Application Data でパケット番号は独立して
    /// 採番されるため、状態を (空間, パケット番号) の組で識別する
    /// (RFC 9000 Section 12.3)。
    pub space: PacketNumberSpace,
    /// パケット番号
    pub pn: u64,
    /// 送信時刻
    pub time_sent: Timestamp,
    /// 送信バイト数
    pub sent_bytes: u64,
}

/// 輻輳制御アルゴリズムのファクトリ
///
/// パスごとに新しい輻輳制御インスタンスを生成する。
/// Connection 単位で同一アルゴリズムを使用する。
pub trait CongestionControlFactory: Debug + Send {
    /// 生成する輻輳制御の型
    type Controller: CongestionControl;

    /// 新しいパス用の輻輳制御器を作成する
    fn create(&self, max_datagram_size: u64) -> Self::Controller;
}

// ---------------------------------------------------------------------------
// New Reno 実装
// ---------------------------------------------------------------------------

/// デフォルトの最大データグラムサイズ (QUIC 最小値)
const DEFAULT_MAX_DATAGRAM_SIZE: u64 = 1200;

/// 損失削減係数の分子 (RFC 9002 Section 7.3.2: New Reno は 1/2)
const LOSS_REDUCTION_FACTOR_NUM: u64 = 1;

/// 損失削減係数の分母
const LOSS_REDUCTION_FACTOR_DEN: u64 = 2;

/// pacing rate のゲイン (RFC 9002 Section 7.7 の N = 1.25)
const PACING_GAIN_NUM: u64 = 5;

/// pacing rate のゲインの分母
const PACING_GAIN_DEN: u64 = 4;

/// 輻輳制御の状態 (RFC 9002 Section 7.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    /// スロースタート: 指数的にウィンドウを拡大
    SlowStart,
    /// リカバリ: ロス検出後、1 RTT の間ウィンドウを増加しない
    /// recovery_start_time 以降に送信されたパケットの ACK で終了
    Recovery { recovery_start_time: Timestamp },
    /// 輻輳回避: 線形にウィンドウを拡大
    CongestionAvoidance,
}

/// 観測用の輻輳制御状態の分類
///
/// 輻輳制御アルゴリズムごとに状態型が異なるため、観測 API 向けに共通の
/// 分類へ丸めたもの。NewReno / Cubic は各状態に対応し、BBR など独自の
/// 状態遷移を持つアルゴリズムは [`Self::Other`] になる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionStateKind {
    /// スロースタート
    SlowStart,
    /// リカバリ (ロス検出後の復旧期間)
    Recovery,
    /// 輻輳回避
    CongestionAvoidance,
    /// 上記以外 (アルゴリズム独自の状態)
    Other,
}

/// New Reno 輻輳制御 (RFC 9002 Section 7)
///
/// draft-ietf-quic-multipath-21 Section 5.3:
/// パスごとに独立した輻輳制御状態を保持する。
#[derive(Debug)]
pub struct NewReno {
    /// 輻輳ウィンドウ (バイト)
    congestion_window: u64,
    /// 送信中バイト数 (ACK 未受信)
    bytes_in_flight: u64,
    /// スロースタート閾値 (初期値: 無限大 = u64::MAX)
    ssthresh: u64,
    /// 輻輳制御の状態
    state: CongestionState,
    /// 最大データグラムサイズ
    max_datagram_size: u64,
    /// 直近の送信で cwnd を埋め切れたか (app-limited 判定、RFC 9002 Section 7.8)
    cwnd_limited: bool,
    /// 輻輳回避の増分計算で保留している剰余 (バイト × バイト)
    ///
    /// `cwnd += max_datagram_size * bytes_acknowledged / cwnd` の分子のうち、
    /// 除算で捨てられる端数を次回以降の ACK に繰り越す。整数除算で 1 ACK の
    /// 増分が 0 になっても、剰余が cwnd に達した時点で 1 バイト以上増加する
    /// (RFC 9002 Section 7.3.3)。
    ///
    /// 不変条件: `0 <= cwnd_remainder < congestion_window`。増分を適用した直後に
    /// cwnd で割った余りへ置き換えるため、この範囲を保つ。`max_datagram_size` が
    /// QUIC の最小値以上であれば `congestion_window` は 0 にならない (0 の場合は
    /// 除算を行わない防御がある)。`u128` の飽和
    /// (`saturating_mul` / `saturating_add`) は実入力では到達しない防御であり、
    /// 仮に飽和しても剰余を cwnd で割った余りに置き換えるため不変条件は破らない。
    cwnd_remainder: u128,
    /// Pacing (RFC 9002 Section 7.7)
    pacer: Pacer,
    /// 平滑化 RTT (pacing rate の計算に使う)
    smoothed_rtt: Option<Duration>,
}

impl NewReno {
    /// 新しい輻輳制御器を作成する
    pub fn new(max_datagram_size: u64) -> Self {
        Self {
            congestion_window: initial_window(max_datagram_size),
            bytes_in_flight: 0,
            ssthresh: u64::MAX,
            state: CongestionState::SlowStart,
            max_datagram_size,
            // 送信実績が無い間は cwnd 律速扱いにする
            cwnd_limited: true,
            cwnd_remainder: 0,
            pacer: Pacer::new(max_datagram_size),
            smoothed_rtt: None,
        }
    }

    /// デフォルトのデータグラムサイズで作成する
    pub fn with_default_mtu() -> Self {
        Self::new(DEFAULT_MAX_DATAGRAM_SIZE)
    }

    /// 現在の輻輳状態を返す
    pub fn state(&self) -> CongestionState {
        self.state
    }

    /// ssthresh を返す
    pub fn ssthresh(&self) -> u64 {
        self.ssthresh
    }

    /// smoothed RTT と cwnd から pacing rate を更新する
    ///
    /// RFC 9002 Section 7.7 の rate = N * congestion_window / smoothed_rtt
    /// (N = 1.25) を使う。RTT サンプルが未取得または 0 の間は pacing しない。
    ///
    /// `set_pacing_rate_value` は rate に合わせて send quantum も再計算するため、
    /// cwnd 変化時にも送信バーストの上限が追従する。
    fn update_pacing_rate(&mut self) {
        let Some(smoothed_rtt) = self.smoothed_rtt else {
            return;
        };
        let rtt_us = smoothed_rtt.as_micros();
        if rtt_us == 0 {
            return;
        }
        let rate = (self.congestion_window as u128 * PACING_GAIN_NUM as u128 * 1_000_000)
            / (rtt_us as u128 * PACING_GAIN_DEN as u128);
        self.pacer
            .set_pacing_rate_value(rate.min(u64::MAX as u128) as u64);
    }

    /// 新しい輻輳イベントを処理する (RFC 9002 Section 7.3.2 / Appendix B.6)
    ///
    /// ロス検出と ECN-CE カウントの増加の両方から呼ばれる。ssthresh と cwnd を
    /// 乗法減少させて Recovery に入る。すでに Recovery 中の場合は、同一 RTT 内で
    /// 複数の輻輳イベントに反応しないよう何もしない。
    fn on_congestion_event(&mut self, now: Timestamp) {
        // cwnd が乗法減少して剰余の分母が変わるため、繰り越し分を破棄する。
        self.cwnd_remainder = 0;

        // Recovery 中は追加の輻輳イベントを無視する (RFC 9002 Appendix B.6)
        if matches!(self.state, CongestionState::Recovery { .. }) {
            return;
        }

        // ssthresh = cwnd * LOSS_REDUCTION_FACTOR (NewReno は 1/2)
        self.ssthresh =
            self.congestion_window * LOSS_REDUCTION_FACTOR_NUM / LOSS_REDUCTION_FACTOR_DEN;
        let min_window = minimum_window(self.max_datagram_size);
        if self.ssthresh < min_window {
            self.ssthresh = min_window;
        }

        // cwnd = max(ssthresh, MINIMUM_WINDOW)
        self.congestion_window = self.ssthresh.max(min_window);

        self.state = CongestionState::Recovery {
            recovery_start_time: now,
        };

        self.update_pacing_rate();
    }
}

impl CongestionControl for NewReno {
    fn state_kind(&self) -> CongestionStateKind {
        match self.state {
            CongestionState::SlowStart => CongestionStateKind::SlowStart,
            CongestionState::Recovery { .. } => CongestionStateKind::Recovery,
            CongestionState::CongestionAvoidance => CongestionStateKind::CongestionAvoidance,
        }
    }

    /// in-flight パケットの送信時に呼び出す (RFC 9002 Appendix B.4)
    ///
    /// in-flight パケット (ack-eliciting、または PADDING フレームを含むパケット)
    /// のバイト数を `bytes_in_flight` に加算する。
    /// ACK / PATH_ACK 専用パケットは in-flight ではないため、呼び出し側が
    /// 通知しない契約とする (RFC 9002 Section 2)。本メソッドは受け取った
    /// バイト数を無条件に加算する。
    fn on_packet_sent(&mut self, sent_bytes: u64) {
        self.bytes_in_flight += sent_bytes;
        // 直近の送信で cwnd を埋め切れたかを記録する (RFC 9002 Section 7.8)。
        // 送信のたびに上書きするので、アプリ律速から復帰すると再び true になる。
        self.cwnd_limited = self.bytes_in_flight + self.max_datagram_size > self.congestion_window;
    }

    /// ACK されたバイト数を bytes_in_flight から除去する
    fn on_packet_acked_bytes(&mut self, acked_bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);
    }

    /// PMTU の更新を 1 データグラム長に反映する
    ///
    /// `is_congestion_limited` の判定と `on_ack_received` の増加量計算に使う
    /// 1 データグラム長を最新の PMTU に合わせる。PMTU が伸びたパスで
    /// 輻輳ウィンドウを超えて送らないようにするため
    /// (draft-ietf-quic-multipath-21 Section 5.3)。
    /// RFC 8899 Section 3: PLPMTU の更新で輻輳ウィンドウをバイト単位で増やしては
    /// ならない (MUST NOT)。増減にかかわらず `cwnd` のバイト数を据え置き、
    /// 1 データグラム長・pacing の送信量子だけを更新する。初期ウィンドウの
    /// 再計算は `initial_window(new_mtu)` を必要とする箇所で都度行う。
    ///
    /// RFC 9002 Section 7.2 の「ハンドシェイク完了のための縮小で初期ウィンドウを
    /// 設定する」SHOULD は実装しない。既定の PMTU は 1200 から始まるため、
    /// 通常はハンドシェイク中の縮小が発生しない。
    fn on_mtu_update(&mut self, new_mtu: u64) {
        // 1 データグラム長が変わり、剰余の分母を引き継げないため破棄する。
        self.cwnd_remainder = 0;
        self.max_datagram_size = new_mtu;
        self.pacer.set_send_quantum(new_mtu);
        self.update_pacing_rate();
    }

    /// 鍵破棄に伴い破棄したパケットのバイト数を bytes_in_flight から除去する
    /// (RFC 9002 Section 6.4)
    fn on_packet_discarded_bytes(&mut self, discarded_bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(discarded_bytes);
    }

    /// ACK 受信時にウィンドウを更新する (RFC 9002 Section 7.3)
    ///
    /// - `bytes_acknowledged`: 新しく ACK された in-flight バイト数
    /// - `newest_acked_time_sent`: in-flight だった ACK 済みパケットの最新送信時刻
    ///   (Recovery 終了判定用)
    /// - `now`: 現在時刻
    fn on_ack_received(
        &mut self,
        bytes_acknowledged: u64,
        newest_acked_time_sent: Timestamp,
        _now: Timestamp,
    ) {
        match self.state {
            CongestionState::SlowStart => {
                // app-limited (bytes in flight < cwnd) のときは cwnd を増やさない
                // (RFC 9002 Section 7.8)
                if self.cwnd_limited {
                    // RFC 9002 Section 7.3.1: 指数的成長
                    self.congestion_window += bytes_acknowledged;
                }
                // ssthresh を超えたら CongestionAvoidance へ
                if self.congestion_window >= self.ssthresh {
                    self.state = CongestionState::CongestionAvoidance;
                    // 輻輳回避の増分計算に切り替わるため、スロースタート中に
                    // 持ち越した剰余は使わない。
                    self.cwnd_remainder = 0;
                }
            }
            CongestionState::Recovery {
                recovery_start_time,
            } => {
                // Recovery 中はウィンドウを増加しない
                // recovery_start_time 以降に送信されたパケットが ACK されたら終了
                if newest_acked_time_sent > recovery_start_time {
                    self.state = CongestionState::CongestionAvoidance;
                }
            }
            CongestionState::CongestionAvoidance => {
                // app-limited (bytes in flight < cwnd) のときは cwnd を増やさない
                // (RFC 9002 Section 7.8)。確認応答バイト数が 0 の ACK も
                // 新しく確認応答されたデータが無いため増加させない。
                if self.cwnd_limited && bytes_acknowledged > 0 {
                    // RFC 9002 Section 7.3.3: AIMD 線形成長
                    // cwnd += max_datagram_size * bytes_acknowledged / cwnd
                    //
                    // 整数除算で捨てられる端数を cwnd_remainder に繰り越す。
                    // これにより 1 ACK の増分が 0 になる大きな cwnd でも、
                    // 継続する ACK で 1 バイト以上増加する。
                    let numerator = u128::from(self.max_datagram_size)
                        .saturating_mul(u128::from(bytes_acknowledged));
                    self.cwnd_remainder = self.cwnd_remainder.saturating_add(numerator);
                    if self.congestion_window > 0 {
                        let delta = (self.cwnd_remainder / u128::from(self.congestion_window))
                            .min(u128::from(u64::MAX)) as u64;
                        self.cwnd_remainder %= u128::from(self.congestion_window);
                        self.congestion_window = self.congestion_window.saturating_add(delta);
                    }
                }
            }
        }

        self.update_pacing_rate();
    }

    /// ロスト検出時に呼び出す (RFC 9002 Section 7.3.2)
    ///
    /// Recovery 中は再度 Recovery に入らない (同一 RTT 内で複数回反応しない)。
    fn on_packets_lost(&mut self, lost_bytes: u64, now: Timestamp) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);

        self.on_congestion_event(now);
    }

    /// ECN-CE カウントの増加を新しい輻輳イベントとして扱う
    /// (RFC 9002 Section 7.1 / Appendix B.7)
    ///
    /// CE マークはパケットロスではないため bytes_in_flight は変更せず、
    /// ロス検出と同じ回復遷移 (ssthresh と cwnd の乗法減少) だけを行う。
    /// `ce_count` は前回の ACK からの増分であり、1 回の通知で複数の CE が
    /// まとめて届いても 1 回の輻輳イベントとして扱う。
    fn on_ecn_ce_count(&mut self, ce_count: u64, now: Timestamp) {
        if ce_count == 0 {
            return;
        }

        self.on_congestion_event(now);
    }

    /// 持続的輻輳の検出時に呼び出す (RFC 9002 Section 7.6)
    ///
    /// TCP RTO と同等のリセット: 最小ウィンドウに戻してスロースタート再開。
    fn on_persistent_congestion(&mut self) {
        self.congestion_window = minimum_window(self.max_datagram_size);
        // cwnd が最小ウィンドウに変わり、剰余の分母が変わるため破棄する。
        self.cwnd_remainder = 0;
        // RFC 9002 Section 7.6.2 / Figure 1: 持続的輻輳後はスロースタートに戻る。
        // ssthresh を初期値 (u64::MAX = 制限なし) に戻すことで、ssthresh に到達するまで
        // 指数的成長を許可する (初期接続時と同等の挙動)。
        self.ssthresh = u64::MAX;
        self.state = CongestionState::SlowStart;

        self.update_pacing_rate();
    }

    fn congestion_window(&self) -> u64 {
        self.congestion_window
    }

    fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    /// 送信可能バイト数を返す
    ///
    /// パケットスケジューラはこの値を参照して送信量を決定する
    /// (draft-ietf-quic-multipath-21 Section 5.5)。
    fn available_window(&self) -> u64 {
        self.congestion_window.saturating_sub(self.bytes_in_flight)
    }

    /// 輻輳制限状態か (送信可能バイト数が 1 データグラム未満)
    fn is_congestion_limited(&self) -> bool {
        self.available_window() < self.max_datagram_size
    }

    /// RTT 更新時に smoothed RTT を保存し pacing rate を再計算する
    fn on_rtt_update(&mut self, smoothed_rtt: Duration, _min_rtt: Duration, _latest_rtt: Duration) {
        self.smoothed_rtt = Some(smoothed_rtt);
        self.update_pacing_rate();
    }

    /// パケット送信時に pacer の departure time を更新する
    fn on_packet_sent_cc(
        &mut self,
        _space: PacketNumberSpace,
        _pn: u64,
        sent_bytes: u64,
        now: Timestamp,
    ) {
        self.pacer.on_packet_sent(now, sent_bytes);
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

/// New Reno ファクトリ
#[derive(Debug, Clone)]
pub struct NewRenoFactory;

impl CongestionControlFactory for NewRenoFactory {
    type Controller = NewReno;

    fn create(&self, max_datagram_size: u64) -> NewReno {
        NewReno::new(max_datagram_size)
    }
}

// ---------------------------------------------------------------------------
// LIA (Linked Increases Algorithm): 結合輻輳制御 (RFC 6356)
// ---------------------------------------------------------------------------

/// 結合輻輳制御で同時に追跡するパス数の上限
///
/// `initial_max_path_id` は 32 ビットだが、実際に同時利用するパス数は
/// 数本程度である。上限を超えた場合は結合せず、単一パスと同じ増加にする。
const LIA_MAX_PATHS: usize = 32;

/// RTT がまだ観測されていないパスの RTT の代わりに使う値 (マイクロ秒)
const LIA_DEFAULT_RTT_US: u64 = 1_000;

/// 結合輻輳制御の共有状態の 1 スロット (1 パス分)
struct LiaSlot {
    /// このスロットが使用中か
    active: AtomicBool,
    /// 直近の輻輳ウィンドウ (バイト)
    ///
    /// no_std ターゲットでは 64 bit atomic が使えないため 32 bit に収める。
    /// u32::MAX (約 4 GiB) を超える cwnd は飽和させるが、LIA の alpha は
    /// 全パスで同じスケールなら不変であり、実際の cwnd が 4 GiB を超える
    /// 状況は稀である。
    cwnd: AtomicU32,
    /// 平滑化 RTT (マイクロ秒)
    rtt_us: AtomicU32,
}

impl LiaSlot {
    fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            cwnd: AtomicU32::new(0),
            rtt_us: AtomicU32::new(LIA_DEFAULT_RTT_US as u32),
        }
    }
}

/// 結合輻輳制御のパス間共有状態
///
/// 同じ接続のパス間で 1 つのインスタンスを共有し、各パスの
/// 輻輳ウィンドウと RTT から RFC 6356 の alpha を計算する。
/// ロックを使わず atomic だけで更新するため no_std でも利用できる。
struct LiaShared {
    slots: [LiaSlot; LIA_MAX_PATHS],
    /// 次に登録を試すスロットのヒント
    next_index: AtomicUsize,
}

impl LiaShared {
    fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| LiaSlot::new()),
            next_index: AtomicUsize::new(0),
        }
    }

    /// スロットを確保する。上限に達している場合は None を返す。
    fn register(&self) -> Option<usize> {
        let start = self.next_index.load(Ordering::Relaxed);
        for offset in 0..LIA_MAX_PATHS {
            let index = (start + offset) % LIA_MAX_PATHS;
            if self.slots[index]
                .active
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                self.slots[index].cwnd.store(0, Ordering::Relaxed);
                self.slots[index]
                    .rtt_us
                    .store(LIA_DEFAULT_RTT_US as u32, Ordering::Relaxed);
                self.next_index
                    .store((index + 1) % LIA_MAX_PATHS, Ordering::Relaxed);
                return Some(index);
            }
        }
        None
    }

    /// スロットを解放する
    fn release(&self, index: usize) {
        self.slots[index].active.store(false, Ordering::Release);
    }

    /// スロットの輻輳ウィンドウを更新する
    fn set_cwnd(&self, index: usize, cwnd: u64) {
        self.slots[index]
            .cwnd
            .store(cwnd.min(u64::from(u32::MAX)) as u32, Ordering::Relaxed);
    }

    /// スロットの RTT を更新する
    fn set_rtt(&self, index: usize, rtt_us: u64) {
        self.slots[index].rtt_us.store(
            rtt_us.max(1).min(u64::from(u32::MAX)) as u32,
            Ordering::Relaxed,
        );
    }

    /// 使用中のスロットの (輻輳ウィンドウ, RTT) を集める
    fn snapshot(&self) -> (alloc::vec::Vec<u64>, alloc::vec::Vec<u64>) {
        let mut cwnds = alloc::vec::Vec::with_capacity(LIA_MAX_PATHS);
        let mut rtts = alloc::vec::Vec::with_capacity(LIA_MAX_PATHS);
        for slot in &self.slots {
            if slot.active.load(Ordering::Acquire) {
                let cwnd = u64::from(slot.cwnd.load(Ordering::Relaxed));
                if cwnd > 0 {
                    cwnds.push(cwnd);
                    rtts.push(u64::from(slot.rtt_us.load(Ordering::Relaxed)).max(1));
                }
            }
        }
        (cwnds, rtts)
    }
}

/// RFC 6356 Section 3 の alpha を計算する
///
/// alpha = cwnd_total * max_i(cwnd_i / rtt_i^2) / (sum_i(cwnd_i / rtt_i))^2
///
/// パスが 1 本だけの場合は 1 になり、単一パスの増加と同じになる。
fn lia_alpha(cwnds: &[u64], rtts_us: &[u64]) -> Option<f64> {
    if cwnds.is_empty() || cwnds.len() != rtts_us.len() {
        return None;
    }
    let mut cwnd_total: u64 = 0;
    let mut sum_ratio = 0.0f64;
    let mut max_ratio_squared = 0.0f64;
    for (&cwnd, &rtt_us) in cwnds.iter().zip(rtts_us) {
        if cwnd == 0 {
            continue;
        }
        let rtt = rtt_us.max(1) as f64;
        cwnd_total = cwnd_total.saturating_add(cwnd);
        let ratio = cwnd as f64 / rtt;
        sum_ratio += ratio;
        let ratio_squared = cwnd as f64 / (rtt * rtt);
        if ratio_squared > max_ratio_squared {
            max_ratio_squared = ratio_squared;
        }
    }
    if cwnd_total == 0 || sum_ratio == 0.0 {
        return None;
    }
    Some(cwnd_total as f64 * max_ratio_squared / (sum_ratio * sum_ratio))
}

/// LIA の増分を 1 バイト = `2^32` とする固定小数点のスケール
const LIA_REMAINDER_SCALE: u64 = 1 << 32;

/// RFC 6356 Section 3 の式 (1) の増分を固定小数点で返す
///
/// 結合項 `alpha * bytes_acked * MSS / cwnd_total` と通常増加項
/// `bytes_acked * MSS / cwnd_i` を整数化する前に比較し、小さい方へ最小
/// 1 バイトの規則を適用する。戻り値は 1 バイトを [`LIA_REMAINDER_SCALE`]
/// とする固定小数点表現で、端数を次回の ACK へ繰り越せるようにする。
fn lia_increase_fixed_point(
    alpha: f64,
    bytes_acknowledged: u64,
    max_datagram_size: u64,
    cwnd_total: u64,
    cwnd_i: u64,
) -> u128 {
    if cwnd_total == 0 || cwnd_i == 0 {
        return 0;
    }
    let coupled = alpha * bytes_acknowledged as f64 * max_datagram_size as f64 / cwnd_total as f64;
    let regular = bytes_acknowledged.saturating_mul(max_datagram_size) as f64 / cwnd_i as f64;
    // 最小 1 バイトの規則は整数化の後ではなく、比較した式の値に対して適用する
    let increase = coupled.min(regular).max(1.0);
    libm::floor(increase * LIA_REMAINDER_SCALE as f64) as u128
}

/// 結合輻輳制御のファクトリ
///
/// 接続ごとに 1 つの共有状態を作り、その接続のパスへ配る。
#[derive(Clone)]
pub struct LiaFactory {
    shared: Arc<LiaShared>,
}

impl LiaFactory {
    /// 新しい結合輻輳制御ファクトリを作る
    pub fn new() -> Self {
        Self {
            shared: Arc::new(LiaShared::new()),
        }
    }
}

impl Default for LiaFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for LiaFactory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LiaFactory").finish_non_exhaustive()
    }
}

impl CongestionControlFactory for LiaFactory {
    type Controller = Lia;

    fn create(&self, max_datagram_size: u64) -> Lia {
        let slot = self.shared.register();
        if let Some(index) = slot {
            self.shared
                .set_cwnd(index, initial_window(max_datagram_size));
        }
        Lia {
            inner: NewReno::new(max_datagram_size),
            shared: Arc::clone(&self.shared),
            slot,
            remainder: 0,
        }
    }
}

/// LIA による結合輻輳制御 (RFC 6356)
///
/// NewReno の増加を RFC 6356 の式 (1) で抑え、複数パスが同じボトルネックを
/// 共有する場合に単一パス接続と同程度の帯域に抑える。スロースタートと
/// ロス時の乗法減少は NewReno の挙動をそのまま使う。
pub struct Lia {
    /// 単一パス向けの NewReno 実装
    inner: NewReno,
    /// パス間の共有状態
    shared: Arc<LiaShared>,
    /// このパスに割り当てた共有状態のスロット
    slot: Option<usize>,
    /// 前回までの結合増分の端数
    ///
    /// 1 バイトを [`LIA_REMAINDER_SCALE`] とする固定小数点で、
    /// `0 <= remainder < LIA_REMAINDER_SCALE` を保つ。
    remainder: u64,
}

impl Debug for Lia {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Lia")
            .field("slot", &self.slot)
            .field("remainder", &self.remainder)
            .field("inner", &self.inner)
            .finish()
    }
}

impl Drop for Lia {
    fn drop(&mut self) {
        if let Some(index) = self.slot {
            self.shared.release(index);
        }
    }
}

impl Lia {
    /// 結合後の輻輳ウィンドウで共有状態を更新する
    fn publish_cwnd(&self) {
        if let Some(index) = self.slot {
            self.shared.set_cwnd(index, self.inner.congestion_window);
        }
    }

    /// RFC 6356 の alpha と式 (1) で増加量を抑える
    fn apply_coupling(&mut self, bytes_acknowledged: u64, cwnd_before: u64) {
        // 結合を使えない場合は、別の増加計算へ端数を持ち越さない
        if self.slot.is_none() || cwnd_before == 0 {
            self.remainder = 0;
            return;
        }
        let (cwnds, rtts) = self.shared.snapshot();
        let Some(alpha) = lia_alpha(&cwnds, &rtts) else {
            self.remainder = 0;
            return;
        };
        let cwnd_total = cwnds.iter().copied().sum::<u64>();
        let increase = lia_increase_fixed_point(
            alpha,
            bytes_acknowledged,
            self.inner.max_datagram_size,
            cwnd_total,
            cwnd_before,
        );
        // 前回までの端数と今回の増分を合わせ、整数バイトだけを適用する。
        // 最小 1 バイトの規則により increase は 1 バイト以上なので、端数が
        // 残っていても整数部は必ず 1 以上になる。
        let total = increase + u128::from(self.remainder);
        self.remainder = (total % u128::from(LIA_REMAINDER_SCALE)) as u64;
        let applied = (total / u128::from(LIA_REMAINDER_SCALE)).min(u128::from(u64::MAX)) as u64;
        let target = cwnd_before.saturating_add(applied);
        // inner の NewReno が剰余の繰り越しで増やした分は、この target がその値を
        // 下回ると打ち消される (結合増加量で通常増加量を抑える意図した挙動)。
        // target > inner.congestion_window は、inner の増分が 0 で式 (1) の
        // 増加量が最小増分 1 になった場合の適用である。
        // target < inner.congestion_window は、結合増加量が通常増加量より
        // 小さい場合の抑制である。等しい場合は何もしない。
        if target != self.inner.congestion_window {
            self.inner.congestion_window = target;
            self.inner.update_pacing_rate();
        }
    }
}

impl CongestionControl for Lia {
    fn state_kind(&self) -> CongestionStateKind {
        self.inner.state_kind()
    }

    fn on_packet_sent(&mut self, sent_bytes: u64) {
        self.inner.on_packet_sent(sent_bytes);
    }

    fn on_packet_acked_bytes(&mut self, acked_bytes: u64) {
        self.inner.on_packet_acked_bytes(acked_bytes);
    }

    fn on_packet_discarded_bytes(&mut self, discarded_bytes: u64) {
        self.inner.on_packet_discarded_bytes(discarded_bytes);
    }

    fn on_packets_discarded_cc(&mut self, space: PacketNumberSpace, packet_numbers: &[u64]) {
        self.inner.on_packets_discarded_cc(space, packet_numbers);
    }

    fn on_ack_received(
        &mut self,
        bytes_acknowledged: u64,
        newest_acked_time_sent: Timestamp,
        now: Timestamp,
    ) {
        let state_before = self.inner.state;
        let cwnd_before = self.inner.congestion_window;
        self.inner
            .on_ack_received(bytes_acknowledged, newest_acked_time_sent, now);

        // 輻輳回避中の cwnd 律速 ACK では、inner の整数除算による増分が 0 でも
        // 結合増加量を適用する。RFC 6356 Section 3 は cwnd_total が大きいときに
        // 増加量が 0 になった場合、増加量を 1 にすることを MUST としている。
        // スロースタートから輻輳回避への遷移 ACK は、スロースタートの増加を
        // そのまま維持するため結合を適用しない (RFC 6356 Section 3)。
        // ACK 前後とも輻輳回避なら状態は変わらないため、ACK 後の状態は検査しない。
        if matches!(state_before, CongestionState::CongestionAvoidance)
            && self.inner.cwnd_limited
            && bytes_acknowledged > 0
        {
            self.apply_coupling(bytes_acknowledged, cwnd_before);
        } else if !matches!(state_before, CongestionState::CongestionAvoidance) {
            // スロースタートや Recovery からの遷移では端数を破棄する
            self.remainder = 0;
        }
        // 結合の有無にかかわらず、この ACK 後の cwnd を共有状態へ 1 回だけ反映する。
        self.publish_cwnd();
    }

    fn on_packets_lost(&mut self, lost_bytes: u64, now: Timestamp) {
        self.inner.on_packets_lost(lost_bytes, now);
        self.remainder = 0;
        self.publish_cwnd();
    }

    fn on_persistent_congestion(&mut self) {
        self.inner.on_persistent_congestion();
        self.remainder = 0;
        self.publish_cwnd();
    }

    fn bandwidth_estimate(&self) -> Option<u64> {
        self.inner.bandwidth_estimate()
    }

    fn congestion_window(&self) -> u64 {
        self.inner.congestion_window()
    }

    fn bytes_in_flight(&self) -> u64 {
        self.inner.bytes_in_flight()
    }

    fn available_window(&self) -> u64 {
        self.inner.available_window()
    }

    fn is_congestion_limited(&self) -> bool {
        self.inner.is_congestion_limited()
    }

    fn on_rtt_update(&mut self, smoothed_rtt: Duration, min_rtt: Duration, latest_rtt: Duration) {
        self.inner.on_rtt_update(smoothed_rtt, min_rtt, latest_rtt);
        if let Some(index) = self.slot {
            self.shared.set_rtt(index, smoothed_rtt.as_micros().max(1));
        }
    }

    fn on_packet_sent_cc(
        &mut self,
        space: PacketNumberSpace,
        pn: u64,
        sent_bytes: u64,
        now: Timestamp,
    ) {
        self.inner.on_packet_sent_cc(space, pn, sent_bytes, now);
    }

    fn on_packet_sent_cc_unpaced(
        &mut self,
        space: PacketNumberSpace,
        pn: u64,
        sent_bytes: u64,
        now: Timestamp,
    ) {
        self.inner
            .on_packet_sent_cc_unpaced(space, pn, sent_bytes, now);
    }

    fn on_packets_acked_cc(&mut self, packets: &[AckedPacketInfo], now: Timestamp) {
        self.inner.on_packets_acked_cc(packets, now);
    }

    fn on_packets_lost_cc(&mut self, lost_packets: &[LostPacketInfo], now: Timestamp) {
        self.inner.on_packets_lost_cc(lost_packets, now);
    }

    fn on_ecn_ce_count(&mut self, ce_count: u64, now: Timestamp) {
        self.inner.on_ecn_ce_count(ce_count, now);
        // CE カウントが増えていない通知は輻輳イベントではないため、
        // 端数を破棄しない (内側の NewReno と同じ判定)。
        if ce_count > 0 {
            self.remainder = 0;
        }
        self.publish_cwnd();
    }

    fn on_app_limited(&mut self) {
        self.inner.on_app_limited();
    }

    fn on_idle(&mut self, reason: IdleReason) {
        self.inner.on_idle(reason);
    }

    fn is_app_limited(&self) -> bool {
        self.inner.is_app_limited()
    }

    fn on_spurious_loss_detection(&mut self, now: Timestamp) {
        self.inner.on_spurious_loss_detection(now);
        self.publish_cwnd();
    }

    fn on_mtu_update(&mut self, new_mtu: u64) {
        self.inner.on_mtu_update(new_mtu);
        self.remainder = 0;
        self.publish_cwnd();
    }

    fn pacing_rate(&self) -> Option<u64> {
        self.inner.pacing_rate()
    }

    fn earliest_departure_time(&self) -> Option<crate::time::Timestamp> {
        self.inner.earliest_departure_time()
    }
}

// ---------------------------------------------------------------------------
// 輻輳制御アルゴリズムの選択 (enum dispatch)
// ---------------------------------------------------------------------------

/// 公開 API から選択できる輻輳制御アルゴリズム
///
/// `Connection` は `CongestionControlFactory` を型パラメータに取る generics 構成の
/// ため、アルゴリズムごとに `Connection` の型が変わってしまう。公開 API では
/// 型消去が必要になるため、enum dispatch で 1 つの型にまとめる。
///
/// 既定は `NewReno` (RFC 9002 Section 7)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionControlAlgorithm {
    /// NewReno (RFC 9002 Section 7)
    #[default]
    NewReno,
    /// CUBIC (RFC 9438)
    Cubic,
    /// BBRv2 (draft-ietf-ccwg-bbr-06)
    BbrV2,
    /// BBRv3 (draft-ietf-ccwg-bbr-06)
    BbrV3,
    /// LIA 結合輻輳制御 (RFC 6356)。マルチパスの共有ボトルネック時の公平性向け
    Lia,
}

impl CongestionControlAlgorithm {
    /// ファクトリを生成する
    pub fn factory(self) -> CongestionControlFactoryImpl {
        match self {
            Self::NewReno => CongestionControlFactoryImpl::NewReno(NewRenoFactory),
            Self::Cubic => CongestionControlFactoryImpl::Cubic(CubicFactory),
            Self::BbrV2 => CongestionControlFactoryImpl::BbrV2(BbrV2Factory),
            Self::BbrV3 => CongestionControlFactoryImpl::BbrV3(BbrV3Factory),
            Self::Lia => CongestionControlFactoryImpl::Lia(LiaFactory::new()),
        }
    }

    /// 設定名を返す (ログ / qlog 用)
    pub fn name(self) -> &'static str {
        match self {
            Self::NewReno => "newreno",
            Self::Cubic => "cubic",
            Self::BbrV2 => "bbrv2",
            Self::BbrV3 => "bbrv3",
            Self::Lia => "lia",
        }
    }
}

/// 輻輳制御器の enum dispatch
///
/// `CongestionControlAlgorithm::factory()` が返すファクトリが生成する。
#[derive(Debug)]
pub enum CongestionControlImpl {
    NewReno(NewReno),
    Cubic(Cubic),
    BbrV2(BbrV2),
    BbrV3(BbrV3),
    Lia(Lia),
}

/// 輻輳制御ファクトリの enum dispatch
#[derive(Debug, Clone)]
pub enum CongestionControlFactoryImpl {
    NewReno(NewRenoFactory),
    Cubic(CubicFactory),
    BbrV2(BbrV2Factory),
    BbrV3(BbrV3Factory),
    Lia(LiaFactory),
}

impl CongestionControlFactory for CongestionControlFactoryImpl {
    type Controller = CongestionControlImpl;

    fn create(&self, max_datagram_size: u64) -> Self::Controller {
        match self {
            Self::NewReno(f) => CongestionControlImpl::NewReno(f.create(max_datagram_size)),
            Self::Cubic(f) => CongestionControlImpl::Cubic(f.create(max_datagram_size)),
            Self::BbrV2(f) => CongestionControlImpl::BbrV2(f.create(max_datagram_size)),
            Self::BbrV3(f) => CongestionControlImpl::BbrV3(f.create(max_datagram_size)),
            Self::Lia(f) => CongestionControlImpl::Lia(f.create(max_datagram_size)),
        }
    }
}

/// `CongestionControlImpl` の各メソッドへ委譲するマクロ
macro_rules! dispatch_cc {
    ($self:expr, $inner:ident => $body:expr) => {
        match $self {
            CongestionControlImpl::NewReno($inner) => $body,
            CongestionControlImpl::Cubic($inner) => $body,
            CongestionControlImpl::BbrV2($inner) => $body,
            CongestionControlImpl::BbrV3($inner) => $body,
            CongestionControlImpl::Lia($inner) => $body,
        }
    };
}

impl CongestionControl for CongestionControlImpl {
    fn state_kind(&self) -> CongestionStateKind {
        dispatch_cc!(self, cc => cc.state_kind())
    }

    fn on_packet_sent(&mut self, sent_bytes: u64) {
        dispatch_cc!(self, cc => cc.on_packet_sent(sent_bytes));
    }

    fn on_packet_acked_bytes(&mut self, acked_bytes: u64) {
        dispatch_cc!(self, cc => cc.on_packet_acked_bytes(acked_bytes));
    }

    fn on_packet_discarded_bytes(&mut self, discarded_bytes: u64) {
        dispatch_cc!(self, cc => cc.on_packet_discarded_bytes(discarded_bytes));
    }

    fn on_packets_discarded_cc(&mut self, space: PacketNumberSpace, packet_numbers: &[u64]) {
        dispatch_cc!(self, cc => cc.on_packets_discarded_cc(space, packet_numbers));
    }

    fn on_ack_received(
        &mut self,
        bytes_acknowledged: u64,
        newest_acked_time_sent: Timestamp,
        now: Timestamp,
    ) {
        dispatch_cc!(self, cc => cc.on_ack_received(bytes_acknowledged, newest_acked_time_sent, now));
    }

    fn on_packets_lost(&mut self, lost_bytes: u64, now: Timestamp) {
        dispatch_cc!(self, cc => cc.on_packets_lost(lost_bytes, now));
    }

    fn on_persistent_congestion(&mut self) {
        dispatch_cc!(self, cc => cc.on_persistent_congestion());
    }

    fn bandwidth_estimate(&self) -> Option<u64> {
        dispatch_cc!(self, cc => cc.bandwidth_estimate())
    }

    fn congestion_window(&self) -> u64 {
        dispatch_cc!(self, cc => cc.congestion_window())
    }

    fn bytes_in_flight(&self) -> u64 {
        dispatch_cc!(self, cc => cc.bytes_in_flight())
    }

    fn available_window(&self) -> u64 {
        dispatch_cc!(self, cc => cc.available_window())
    }

    fn is_congestion_limited(&self) -> bool {
        dispatch_cc!(self, cc => cc.is_congestion_limited())
    }

    fn on_rtt_update(
        &mut self,
        smoothed_rtt: crate::time::Duration,
        min_rtt: crate::time::Duration,
        latest_rtt: crate::time::Duration,
    ) {
        dispatch_cc!(self, cc => cc.on_rtt_update(smoothed_rtt, min_rtt, latest_rtt));
    }

    fn on_packet_sent_cc(
        &mut self,
        space: PacketNumberSpace,
        pn: u64,
        sent_bytes: u64,
        now: Timestamp,
    ) {
        dispatch_cc!(self, cc => cc.on_packet_sent_cc(space, pn, sent_bytes, now));
    }

    fn on_packet_sent_cc_unpaced(
        &mut self,
        space: PacketNumberSpace,
        pn: u64,
        sent_bytes: u64,
        now: Timestamp,
    ) {
        dispatch_cc!(self, cc => cc.on_packet_sent_cc_unpaced(space, pn, sent_bytes, now));
    }

    fn on_packets_acked_cc(&mut self, packets: &[AckedPacketInfo], now: Timestamp) {
        dispatch_cc!(self, cc => cc.on_packets_acked_cc(packets, now));
    }

    fn on_packets_lost_cc(&mut self, lost_packets: &[LostPacketInfo], now: Timestamp) {
        dispatch_cc!(self, cc => cc.on_packets_lost_cc(lost_packets, now));
    }

    fn on_ecn_ce_count(&mut self, ce_count: u64, now: Timestamp) {
        dispatch_cc!(self, cc => cc.on_ecn_ce_count(ce_count, now));
    }

    fn on_app_limited(&mut self) {
        dispatch_cc!(self, cc => cc.on_app_limited());
    }

    fn on_idle(&mut self, reason: IdleReason) {
        dispatch_cc!(self, cc => cc.on_idle(reason));
    }

    fn is_app_limited(&self) -> bool {
        dispatch_cc!(self, cc => cc.is_app_limited())
    }

    fn on_spurious_loss_detection(&mut self, now: Timestamp) {
        dispatch_cc!(self, cc => cc.on_spurious_loss_detection(now));
    }

    fn on_mtu_update(&mut self, new_mtu: u64) {
        dispatch_cc!(self, cc => cc.on_mtu_update(new_mtu));
    }

    fn pacing_rate(&self) -> Option<u64> {
        dispatch_cc!(self, cc => cc.pacing_rate())
    }

    fn earliest_departure_time(&self) -> Option<crate::time::Timestamp> {
        dispatch_cc!(self, cc => cc.earliest_departure_time())
    }
}

#[cfg(test)]
mod tests;
