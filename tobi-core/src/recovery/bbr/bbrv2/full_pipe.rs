// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! full pipe 検出 (BBRv2/BBRv3 共通)
//!
//! Startup フェーズの終了条件を 2 つのメカニズムで検出する:
//! 1. 帯域プラトー: 推定帯域が 3 ラウンド連続で 1.25x 未満の成長
//! 2. 過剰ロスト: loss burst 数とロスト率の閾値超過
//!
//! 帯域プラトー判定に使うサンプルは版ごとに異なる:
//! - BBRv2: BBR.max_bw (draft-cardwell-iccrg-bbr-congestion-control-02
//!   Section 4.3.1.2 の BBRCheckStartupFullBandwidth)
//! - BBRv3: 現在の RS.delivery_rate (draft-ietf-ccwg-bbr-06
//!   Section 5.3.1.2 の CheckFullBWReached)
//!
//! 過剰ロスト判定の loss burst 閾値も版ごとに異なるため、
//! インスタンス生成時に渡す。

use crate::recovery::bbr::bandwidth::Bandwidth;
use crate::recovery::bbr::delivery_rate::RateSample;

/// full_pipe 検出の帯域増加閾値 (1.25x)
const FULL_BW_THRESH_NUM: u64 = 5;
const FULL_BW_THRESH_DEN: u64 = 4;

/// 帯域プラトーの連続ラウンド数閾値 (両 draft とも 3)
const FULL_BW_COUNT_THRESH: u8 = 3;

/// 過剰ロストの loss burst 閾値 (BBRv2)
///
/// draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.1.3:
/// BBRStartupFullLossCnt = 3
pub const STARTUP_LOSS_BURST_THRESH_BBRV2: u8 = 3;

/// 過剰ロストの loss burst 閾値 (BBRv3)
///
/// draft-ietf-ccwg-bbr-06 Section 5.3.1.3:
/// BBRStartupFullLossCnt = 6
pub const STARTUP_LOSS_BURST_THRESH_BBRV3: u8 = 6;

/// 過剰ロストのロスト率閾値 (2%)
const LOSS_THRESH_NUM: u64 = 1;
const LOSS_THRESH_DEN: u64 = 50;

/// full pipe 推定器
///
/// Startup フェーズの終了を検出する。
/// 2 つの独立した検出メカニズムのいずれかが発火すると filled_pipe が true になる。
#[derive(Debug)]
pub struct Estimator {
    /// パイプが満杯かどうか
    filled_pipe: bool,

    /// 過去のラウンドで観測された最大帯域
    full_bw: Bandwidth,

    /// 帯域プラトーの連続ラウンド数
    full_bw_count: u8,

    /// 過剰ロストの loss burst 閾値 (版ごとに異なる)
    startup_loss_burst_thresh: u8,
}

impl Estimator {
    /// 新しい推定器を作成する
    ///
    /// `startup_loss_burst_thresh` は過剰ロスト判定の loss burst 閾値。
    /// BBRv2 は `STARTUP_LOSS_BURST_THRESH_BBRV2` (3)、
    /// BBRv3 は `STARTUP_LOSS_BURST_THRESH_BBRV3` (6) を渡す。
    pub fn new(startup_loss_burst_thresh: u8) -> Self {
        Self {
            filled_pipe: false,
            full_bw: Bandwidth::ZERO,
            full_bw_count: 0,
            startup_loss_burst_thresh,
        }
    }

    /// パイプが満杯かどうかを返す
    pub fn filled_pipe(&self) -> bool {
        self.filled_pipe
    }

    /// ラウンド開始時に帯域プラトーをチェックする
    ///
    /// `bw_sample` は版ごとに異なるサンプル:
    /// - BBRv2: 現在の BBR.max_bw
    /// - BBRv3: 現在の RS.delivery_rate
    ///
    /// - `is_app_limited`: app_limited サンプルか
    pub fn on_round_start(&mut self, bw_sample: Bandwidth, is_app_limited: bool) {
        if self.filled_pipe {
            return;
        }

        // 帯域プラトー検出
        if !is_app_limited {
            self.check_bandwidth_plateau(bw_sample);
        }
    }

    /// ロスラウンド開始時に過剰ロストをチェックする
    ///
    /// BBRv2: draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.1.3
    /// BBRv3: draft-ietf-ccwg-bbr-06 Section 5.3.1.3
    ///
    /// - `loss_bursts`: このラウンドの loss burst 数
    /// - `rs`: 現在の RateSample (ロスト情報参照)
    pub fn on_loss_round_start(&mut self, loss_bursts: u8, rs: &RateSample) {
        if self.filled_pipe {
            return;
        }

        // loss_bursts が版ごとの閾値以上 かつ ロスト率 > 2%
        if loss_bursts >= self.startup_loss_burst_thresh
            && rs.prior_inflight > 0
            && rs.lost * LOSS_THRESH_DEN > rs.prior_inflight * LOSS_THRESH_NUM
        {
            self.filled_pipe = true;
        }
    }

    /// full pipe 検出状態をリセットする (ResetFullBW)
    ///
    /// draft-ietf-ccwg-bbr-06 Section 5.3.1.2:
    /// BBR.full_bw = 0, BBR.full_bw_count = 0, BBR.full_bw_now = 0
    /// 損失回復が spurious と判明したときにもこのリセットを行う
    /// (Section 5.5.11.2)。
    pub fn reset(&mut self) {
        self.full_bw = Bandwidth::ZERO;
        self.full_bw_count = 0;
    }

    /// full pipe 到達フラグを解除する
    ///
    /// draft-ietf-ccwg-bbr-06 Section 5.5.11.2:
    /// spurious な損失回復で Startup に戻るときは BBR.full_bw_reached = false
    /// とする。帯域プラトーの学習値 (full_bw / full_bw_count) は reset() で
    /// 別途初期化する。
    pub fn clear_filled_pipe(&mut self) {
        self.filled_pipe = false;
    }

    /// 帯域プラトー検出
    ///
    /// bw_sample が full_bw の 1.25x 未満なら full_bw_count をインクリメント。
    /// 3 ラウンド連続で成長が鈍化したら filled_pipe = true。
    fn check_bandwidth_plateau(&mut self, bw_sample: Bandwidth) {
        if bw_sample.as_bytes_per_second()
            >= (self.full_bw.as_bytes_per_second() as u128 * FULL_BW_THRESH_NUM as u128
                / FULL_BW_THRESH_DEN as u128) as u64
        {
            // まだ成長中
            self.full_bw = bw_sample;
            self.full_bw_count = 0;
            return;
        }
        self.full_bw_count += 1;
        if self.full_bw_count >= FULL_BW_COUNT_THRESH {
            self.filled_pipe = true;
        }
    }
}

impl Default for Estimator {
    fn default() -> Self {
        Self::new(STARTUP_LOSS_BURST_THRESH_BBRV2)
    }
}
