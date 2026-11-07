// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 輻輳信号追跡 (draft-cardwell-iccrg-bbr-congestion-control-02 Section 2.10, 4.5.6.3)
//!
//! 毎 ACK で bw_latest/inflight_latest を更新し、
//! 1 ラウンドに 1 回だけ下限モデルに反映する。
//! loss burst カウントと ECN per round も追跡する。

use crate::recovery::bbr::bandwidth::Bandwidth;
use crate::recovery::bbr::delivery_rate::RateSample;

use super::round;

/// 輻輳信号の状態
///
/// ロスラウンドの独立追跡、loss burst カウント、ECN マーク追跡を行う。
#[derive(Debug)]
pub struct State {
    /// ロスラウンド追跡用の独立カウンタ
    loss_round: round::Counter,

    /// このラウンドの最大配信帯域
    bw_latest: Bandwidth,

    /// このラウンドの最大配信ボリューム
    inflight_latest: u64,

    /// このラウンドでロストが発生したか
    loss_in_round: bool,

    /// このラウンドでのロスバースト数
    loss_bursts_in_round: u8,

    /// このラウンドで ECN CE マークがあったか
    ecn_in_round: bool,
}

impl State {
    /// 新しい輻輳信号状態を作成する
    pub fn new() -> Self {
        Self {
            loss_round: round::Counter::new(),
            bw_latest: Bandwidth::ZERO,
            inflight_latest: 0,
            loss_in_round: false,
            loss_bursts_in_round: 0,
            ecn_in_round: false,
        }
    }

    // --- アクセサ ---

    /// ロスラウンドの開始を返す
    pub fn loss_round_start(&self) -> bool {
        self.loss_round.round_start()
    }

    /// このラウンドでロストが発生したかを返す
    pub fn loss_in_round(&self) -> bool {
        self.loss_in_round
    }

    /// このラウンドでのロスバースト数を返す
    pub fn loss_bursts_in_round(&self) -> u8 {
        self.loss_bursts_in_round
    }

    /// このラウンドで ECN CE マークがあったかを返す
    pub fn ecn_in_round(&self) -> bool {
        self.ecn_in_round
    }

    /// このラウンドの最大配信帯域を返す
    pub fn bw_latest(&self) -> Bandwidth {
        self.bw_latest
    }

    /// このラウンドの最大配信ボリュームを返す
    pub fn inflight_latest(&self) -> u64 {
        self.inflight_latest
    }

    // --- 更新 ---

    /// ACK 受信時にロスラウンドと最新信号を更新する
    ///
    /// `rs` は現在の RateSample、`current_delivered` は累計配送バイト数。
    ///
    /// 注意: `advance()` より先に呼ぶこと。`advance()` はラウンド境界で
    /// bw_latest/inflight_latest をリセットするため、順序が逆転すると
    /// max() で蓄積した値が失われる。
    /// (draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.5.6:
    ///  BBRUpdateLatestDeliverySignals → BBRAdvanceLatestDeliverySignals の順)
    pub fn update_latest(&mut self, rs: &RateSample, current_delivered: u64) {
        self.loss_round
            .on_ack(rs.prior_delivered, current_delivered);
        self.bw_latest = self.bw_latest.max(rs.delivery_rate);
        self.inflight_latest = self.inflight_latest.max(rs.delivered);
    }

    /// ラウンド終了時に bw_latest/inflight_latest をリセットする
    ///
    /// loss_round_start の場合のみ呼ばれる。
    /// 注意: `update_latest()` の後に呼ぶこと (上記コメント参照)。
    pub fn advance(&mut self, rs: &RateSample) {
        if self.loss_round.round_start() {
            self.bw_latest = rs.delivery_rate;
            self.inflight_latest = rs.delivered;
        }
    }

    /// パケットロスト時にロスト信号を更新する
    ///
    /// `new_loss_burst` は新しいロスバーストの開始かどうか。
    /// 連続するロストパケットは同一バーストとして扱う。
    pub fn on_packet_lost(&mut self, new_loss_burst: bool) {
        self.loss_in_round = true;
        if new_loss_burst {
            self.loss_bursts_in_round = self.loss_bursts_in_round.saturating_add(1);
        }
    }

    /// ECN CE マークを記録する
    pub fn on_explicit_congestion(&mut self) {
        self.ecn_in_round = true;
    }

    /// spurious loss 検出時の復元で使う、ラウンド内の輻輳信号の全リセット
    ///
    /// BBRv2 本体の毎 ACK 更新では使わない。通常の更新は
    /// `reset_round_signals_except_bursts` を使い、Startup の損失終了判定が
    /// 読む loss burst 数を残す。こちらは spurious loss で損失回復前の
    /// 状態へ戻すときに、burst 数も含めて消すために使う。
    pub fn reset_round_signals(&mut self) {
        self.loss_in_round = false;
        self.loss_bursts_in_round = 0;
        self.ecn_in_round = false;
    }

    /// ロスラウンド開始時の輻輳信号更新で呼ぶ
    ///
    /// draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.5.6.3 と
    /// draft-ietf-ccwg-bbr-06 Section 5.5.10.3 の UpdateCongestionSignals は
    /// loss_in_round のリセットだけを定義しており、そのラウンドで観測した
    /// loss burst 数は Startup の損失終了判定 (CheckStartupHighLoss) の
    /// 入力として残す必要がある。burst 数は判定後に `reset_loss_bursts` で消す。
    /// `ecn_in_round` もあわせてリセットするのは、毎 ACK の輻輳信号更新で
    /// 前ラウンドの CE マークを残さない既存の挙動を維持するためである。
    pub(crate) fn reset_round_signals_except_bursts(&mut self) {
        self.loss_in_round = false;
        self.ecn_in_round = false;
    }

    /// ロスラウンドの loss burst 数をリセットする
    ///
    /// Startup の損失終了判定が burst 数を読み終えた後に呼ぶ。判定より前に
    /// 呼ぶと閾値判定が常に 0 burst になり、損失による Startup 終了が働かない。
    pub(crate) fn reset_loss_bursts(&mut self) {
        self.loss_bursts_in_round = 0;
    }

    /// 全信号をリセットする (ProbeBW_DOWN 遷移時等)
    pub fn reset(&mut self) {
        self.loss_in_round = false;
        self.loss_bursts_in_round = 0;
        self.ecn_in_round = false;
        self.bw_latest = Bandwidth::ZERO;
        self.inflight_latest = 0;
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
