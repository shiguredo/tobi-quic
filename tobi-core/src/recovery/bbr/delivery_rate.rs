// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Delivery Rate Sampling (draft-ietf-ccwg-bbr-06 Section 4.1.2)
//!
//! BBRv2/BBRv3 共通の帯域推定基盤。
//! パケット送信時にコネクション状態をスナップショットし、
//! ACK 受信時に配信レートを計算する。

use crate::time::{Duration, Timestamp};

use super::bandwidth::Bandwidth;

// ---------------------------------------------------------------------------
// パケットごとの配信状態 (draft-ietf-ccwg-bbr-06 Section 4.1.2.1.2)
// ---------------------------------------------------------------------------

/// パケット送信時にスナップショットする配信情報
///
/// BBR 内部で HashMap<(PacketNumberSpace, u64), PacketDeliveryState> として
/// 管理する。パケット番号は空間ごとに独立して採番されるため (RFC 9000
/// Section 12.3)、(空間, パケット番号) の組をキーにする。
/// SentPacket 構造体は変更しない。
#[derive(Debug, Clone, Copy)]
pub struct PacketDeliveryState {
    /// パケット送信時の C.delivered (累計配送バイト数)
    pub delivered: u64,

    /// パケット送信時の C.delivered_time
    pub delivered_time: Timestamp,

    /// パケット送信時の C.first_send_time
    pub first_send_time: Timestamp,

    /// パケット送信時刻
    pub send_time: Timestamp,

    /// パケット送信時にアプリケーション制限状態だったか
    pub is_app_limited: bool,

    /// パケット送信直後の C.inflight (このパケット自身を含む)
    ///
    /// draft-ietf-ccwg-bbr-06 Section 4.1.2.1.2: P.tx_in_flight は
    /// 「パケット P の送信直後の C.inflight」であり、P を含む。
    pub tx_in_flight: u64,

    /// パケット送信時の C.lost_bytes (累計ロストバイト数)
    pub lost_bytes: u64,

    /// パケット送信時の累計 ECN CE カウント
    pub ecn_ce_count: u64,
}

// ---------------------------------------------------------------------------
// Rate Sample (draft-ietf-ccwg-bbr-06 Section 4.1.2.1.3)
// ---------------------------------------------------------------------------

/// ACK ごとに生成される配信レートサンプル
#[derive(Debug, Clone, Copy)]
pub struct RateSample {
    /// 配信レート (bytes/sec)
    pub delivery_rate: Bandwidth,

    /// サンプリング間隔
    pub interval: Duration,

    /// サンプリング間隔中に配信されたバイト数
    pub delivered: u64,

    /// サンプリング間隔中にロストしたバイト数
    pub lost: u64,

    /// サンプリング間隔中の ECN CE カウント差分
    pub ecn_ce_count: u64,

    /// 最近配信されたパケットの is_app_limited
    pub is_app_limited: bool,

    /// 最近配信されたパケット送信時の delivered
    pub prior_delivered: u64,

    /// 最近配信されたパケット送信時の delivered_time
    pub prior_time: Option<Timestamp>,

    /// 送信経過時間
    pub send_elapsed: Duration,

    /// ACK 経過時間
    pub ack_elapsed: Duration,

    /// 最近配信されたパケット送信時の inflight
    pub prior_inflight: u64,

    /// 最後に ACK されたパケット番号
    pub last_acked_pn: Option<u64>,
}

impl Default for RateSample {
    fn default() -> Self {
        Self {
            delivery_rate: Bandwidth::ZERO,
            interval: Duration::ZERO,
            delivered: 0,
            lost: 0,
            ecn_ce_count: 0,
            is_app_limited: false,
            prior_delivered: 0,
            prior_time: None,
            send_elapsed: Duration::ZERO,
            ack_elapsed: Duration::ZERO,
            prior_inflight: 0,
            last_acked_pn: None,
        }
    }
}

impl RateSample {
    /// 有効なレートサンプルかどうかを返す
    pub fn is_valid(&self) -> bool {
        self.prior_time.is_some() && self.interval.as_micros() > 0
    }
}

// ---------------------------------------------------------------------------
// Delivery Rate Estimator (draft-ietf-ccwg-bbr-06 Section 4.1.2.1.1)
// ---------------------------------------------------------------------------

/// コネクションごとの Delivery Rate 推定器
///
/// draft-ietf-ccwg-bbr-06 Section 4.1.2 に従い、
/// パケット送信時のスナップショットと ACK 受信時の差分から
/// 配信レートを計算する。
#[derive(Debug)]
pub struct DeliveryRateEstimator {
    /// 累計配送バイト数 (C.delivered)
    delivered: u64,

    /// delivered 最終更新時刻 (C.delivered_time)
    delivered_time: Option<Timestamp>,

    /// フライト開始時の送信時刻 (C.first_send_time)
    first_send_time: Option<Timestamp>,

    /// アプリケーション制限マーカー (C.app_limited)
    /// 0 なら制限なし、正の値ならその delivered 値を超えると制限解除
    app_limited: u64,

    /// 累計ロストバイト数
    lost_bytes: u64,

    /// 累計 ECN CE カウント
    ecn_ce_count: u64,

    /// 現在の ACK で構築中の RateSample の prior ECN CE カウント
    /// (update_rate_sample で newest パケットの値を保存し、generate_rate_sample で差分計算に使用)
    prior_ecn_ce_count: u64,

    /// 現在の ACK で構築中の RateSample の prior ロストバイト数
    /// (update_rate_sample で newest パケットの値を保存し、generate_rate_sample で差分計算に使用)
    /// draft-ietf-ccwg-bbr-06 Section 5.5.10.2 の `RS.lost = C.lost - P.lost` に対応する。
    prior_lost: u64,

    /// 現在の ACK で構築中の RateSample
    rate_sample: RateSample,
}

impl DeliveryRateEstimator {
    /// 新しい推定器を作成する
    pub fn new() -> Self {
        Self {
            delivered: 0,
            delivered_time: None,
            first_send_time: None,
            app_limited: 0,
            lost_bytes: 0,
            ecn_ce_count: 0,
            prior_ecn_ce_count: 0,
            prior_lost: 0,
            rate_sample: RateSample::default(),
        }
    }

    /// 累計配送バイト数を返す
    pub fn delivered(&self) -> u64 {
        self.delivered
    }

    /// 累計ロストバイト数を返す
    pub fn lost_bytes(&self) -> u64 {
        self.lost_bytes
    }

    /// 累計 ECN CE カウントを返す
    pub fn ecn_ce_count(&self) -> u64 {
        self.ecn_ce_count
    }

    /// アプリケーション制限状態かどうかを返す
    pub fn is_app_limited(&self) -> bool {
        self.app_limited != 0
    }

    /// 現在の RateSample を返す
    pub fn rate_sample(&self) -> &RateSample {
        &self.rate_sample
    }

    // -----------------------------------------------------------------------
    // OnPacketSent (draft-ietf-ccwg-bbr-06 Section 4.1.2.2)
    // -----------------------------------------------------------------------

    /// パケット送信時のスナップショットを取得する
    ///
    /// `prior_inflight` はこのパケットを送信する前の C.inflight、
    /// `tx_in_flight` はこのパケット送信直後の C.inflight (このパケットを含む)。
    /// 戻り値の PacketDeliveryState を BBR 内部の HashMap に保存する。
    ///
    /// draft-ietf-ccwg-bbr-06 Section 4.1.2.2:
    /// if (C.inflight == 0)
    ///   C.first_send_time = C.delivered_time = P.send_time
    /// P.tx_in_flight = C.inflight  /* includes data in P */
    pub fn on_packet_sent(
        &mut self,
        prior_inflight: u64,
        tx_in_flight: u64,
        send_time: Timestamp,
    ) -> PacketDeliveryState {
        // アイドルからの復帰 (送信前の inflight が 0) なら時刻をリセットする
        if prior_inflight == 0 {
            self.first_send_time = Some(send_time);
            self.delivered_time = Some(send_time);
        }

        PacketDeliveryState {
            delivered: self.delivered,
            delivered_time: self.delivered_time.unwrap_or(send_time),
            first_send_time: self.first_send_time.unwrap_or(send_time),
            send_time,
            is_app_limited: self.app_limited != 0,
            tx_in_flight,
            lost_bytes: self.lost_bytes,
            ecn_ce_count: self.ecn_ce_count,
        }
    }

    // -----------------------------------------------------------------------
    // InitRateSample / UpdateRateSample / GenerateRateSample
    // (draft-ietf-ccwg-bbr-06 Section 4.1.2.3)
    // -----------------------------------------------------------------------

    /// ACK 処理の開始時に RateSample を初期化する
    pub fn init_rate_sample(&mut self) {
        self.rate_sample = RateSample::default();
        self.prior_ecn_ce_count = 0;
        self.prior_lost = 0;
    }

    /// ACK された個別パケットに対して RateSample を更新する
    ///
    /// stretched ACK で複数パケットが ACK された場合、
    /// 最も最近送信されたパケットの情報を使う。
    pub fn update_rate_sample(
        &mut self,
        pn: u64,
        data_length: u64,
        packet_state: &PacketDeliveryState,
        now: Timestamp,
    ) {
        // C.delivered += P.data_length
        self.delivered += data_length;
        // C.delivered_time = Now()
        self.delivered_time = Some(now);

        // 最も新しいパケットの情報で RS を更新する
        // IsNewestPacket: P.send_time > C.first_send_time ||
        //   (P.send_time == C.first_send_time && P.packet_id > RS.last_packet_id)
        let is_newest = if let Some(first_send) = self.first_send_time {
            packet_state.send_time > first_send
                || (packet_state.send_time == first_send
                    && self.rate_sample.last_acked_pn.is_none_or(|last| pn > last))
        } else {
            true
        };

        if self.rate_sample.prior_time.is_none() || is_newest {
            self.rate_sample.prior_delivered = packet_state.delivered;
            self.rate_sample.prior_time = Some(packet_state.delivered_time);
            self.rate_sample.is_app_limited = packet_state.is_app_limited;
            self.rate_sample.send_elapsed = packet_state.send_time - packet_state.first_send_time;
            self.rate_sample.ack_elapsed = now - packet_state.delivered_time;
            self.rate_sample.last_acked_pn = Some(pn);
            self.rate_sample.prior_inflight = packet_state.tx_in_flight;

            self.prior_ecn_ce_count = packet_state.ecn_ce_count;
            self.prior_lost = packet_state.lost_bytes;

            // C.first_send_time = P.send_time
            self.first_send_time = Some(packet_state.send_time);
        }
    }

    /// ACK 処理の完了時に最終的な RateSample を生成する
    ///
    /// min_rtt は信頼性チェックに使用する。
    /// min_rtt が None の場合はチェックをスキップする。
    pub fn generate_rate_sample(&mut self, min_rtt: Option<Duration>) {
        // app_limited の解除チェック
        // draft-ietf-ccwg-bbr-06 Section 4.1.2.3:
        // if (C.app_limited && C.delivered > C.app_limited)
        //   C.app_limited = 0
        if self.app_limited != 0 && self.delivered > self.app_limited {
            self.app_limited = 0;
        }

        // prior_time が設定されていなければ何も配信されていない
        if self.rate_sample.prior_time.is_none() {
            return;
        }

        // RS.interval = max(RS.send_elapsed, RS.ack_elapsed)
        self.rate_sample.interval = if self.rate_sample.send_elapsed >= self.rate_sample.ack_elapsed
        {
            self.rate_sample.send_elapsed
        } else {
            self.rate_sample.ack_elapsed
        };

        // RS.delivered = C.delivered - RS.prior_delivered
        self.rate_sample.delivered = self.delivered - self.rate_sample.prior_delivered;

        // ECN CE カウントの差分
        // newest パケット送信時の累計値と現在の累計値の差分を計算する
        self.rate_sample.ecn_ce_count = self.ecn_ce_count.saturating_sub(self.prior_ecn_ce_count);

        // ロストバイト数の差分
        // draft-ietf-ccwg-bbr-06:
        //   Section 2.2 (RateSample フィールド定義)
        //   Section 5.5.10.2 BBRHandleLostPacket: RS.lost = C.lost - P.lost  /* data lost since transmit */
        // newest パケット送信時の累計値と現在の累計値の差分を計算する。
        // (以前の実装は `prior_time.map(|_| 0).unwrap_or(...)` で常に 0 を減算しており、
        //  結果として RS.lost が接続生涯の累積値になり is_inflight_too_high 等の
        //  損失信号を毎 ACK 発火させていた。ECN CE と同じ差分パターンに揃える)
        self.rate_sample.lost = self.lost_bytes.saturating_sub(self.prior_lost);

        // 信頼性チェック: interval < min_rtt なら信頼できない
        // draft-ietf-ccwg-bbr-06 Section 4.1.2.3:
        // if (RS.interval < C.min_rtt)
        //   return  /* no reliable rate sample */
        if let Some(min_rtt) = min_rtt
            && self.rate_sample.interval < min_rtt
        {
            return;
        }

        // RS.delivery_rate = RS.delivered / RS.interval
        if self.rate_sample.interval.as_micros() > 0 {
            self.rate_sample.delivery_rate = Bandwidth::from_bytes_and_interval(
                self.rate_sample.delivered,
                self.rate_sample.interval,
            );
        }
    }

    // -----------------------------------------------------------------------
    // ロスト処理
    // -----------------------------------------------------------------------

    /// パケットロスト時に累計ロストバイト数を更新する
    pub fn on_packets_lost(&mut self, lost_bytes: u64) {
        self.lost_bytes += lost_bytes;
    }

    // -----------------------------------------------------------------------
    // ECN CE 処理
    // -----------------------------------------------------------------------

    /// ECN CE カウントを累積する
    ///
    /// ACK フレームの ECN セクションから CE カウントの増分を受け取る。
    pub fn on_ecn_ce(&mut self, ce_count: u64) {
        self.ecn_ce_count += ce_count;
    }

    // -----------------------------------------------------------------------
    // アプリケーション制限検出 (draft-ietf-ccwg-bbr-06 Section 4.1.2.4)
    // -----------------------------------------------------------------------

    /// アプリケーション制限状態をマークする
    ///
    /// draft-ietf-ccwg-bbr-06 Section 4.1.2.4:
    /// C.app_limited = max(C.delivered + C.inflight, 1)
    pub fn mark_app_limited(&mut self, inflight: u64) {
        self.app_limited = (self.delivered + inflight).max(1);
    }

    /// アプリケーション制限状態を検出してマークする
    ///
    /// draft-ietf-ccwg-bbr-06 Section 4.1.2.4 の CheckIfApplicationLimited に相当する。
    /// 呼び出し側は以下を満たす時点で呼ぶ契約とする:
    ///
    /// - 送信可能なアプリケーションデータが無い (NoUnsentData)
    /// - 下位レイヤーに送信待ちが無い (C.pending_transmissions == 0)
    /// - 再送待ちが無い (C.lost_out <= C.retrans_out)
    ///
    /// この実装では下位レイヤーの送信待ちキューを持たないため
    /// C.pending_transmissions は常に 0 とみなし、再送待ちが無いことは
    /// 呼び出し側の契約で担保する。残る C.inflight < C.cwnd をここで判定する。
    pub fn check_if_application_limited(&mut self, inflight: u64, cwnd: u64) {
        if inflight < cwnd {
            self.mark_app_limited(inflight);
        }
    }
}

impl Default for DeliveryRateEstimator {
    fn default() -> Self {
        Self::new()
    }
}
