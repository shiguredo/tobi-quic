// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 帯域モデル (draft-cardwell-iccrg-bbr-congestion-control-02 Section 2.9.1, 4.5.2, 4.5.6.3)
//!
//! BBRv2 の帯域推定とバウンディング。MaxBwFilter で推定した最大帯域に対して、
//! inflight_hi 設定後の安全な ACK で得た上限 (bw_hi) とロスト応答で得た下限
//! (bw_lo) を適用し、操作帯域 (bw) を決定する。
//! Multipath QUIC ではパスごとに独立したモデルを持つ。

use crate::recovery::bbr::bandwidth::Bandwidth;
use crate::recovery::bbr::delivery_rate::RateSample;
use crate::recovery::windowed_filter::RoundBasedMaxFilter;

/// MaxBwFilter のウィンドウ長 (2 サイクル)
const MAX_BW_FILTER_LEN: u64 = 2;

/// 損失時の乗算減少係数 (0.7)
const BETA_NUM: u64 = 7;
const BETA_DEN: u64 = 10;

/// 帯域モデル
///
/// max_bw (ラウンドベースの最大帯域フィルタ) を基準に、
/// inflight_hi 設定後の安全な ACK で得た bw_hi とロスト応答で得た bw_lo で
/// バウンディングして操作帯域 bw を決定する。
#[derive(Debug)]
pub struct Model {
    /// ラウンドベース最大帯域フィルタ
    max_bw_filter: RoundBasedMaxFilter,

    /// inflight_hi 設定後の安全な ACK で設定される長期上限
    ///
    /// ロスト応答で更新するのは inflight_hi と bw_lo であり、bw_hi は更新
    /// しない。bw_hi は Infinity (未設定) を許し、inflight_hi が有限になった
    /// 後の安全な ACK で有限化し、より大きいサンプルでのみ引き上げる。
    bw_hi: Bandwidth,

    /// 短期下限帯域 (ロスト応答で Beta を適用して縮小)
    bw_lo: Bandwidth,

    /// 操作帯域 = min(max_bw, bw_hi, bw_lo)
    bw: Bandwidth,

    /// フィルタの仮想時間 (ProbeBW サイクルごとにインクリメント)
    cycle_count: u64,
}

impl Model {
    /// 新しい帯域モデルを作成する
    pub fn new() -> Self {
        Self {
            max_bw_filter: RoundBasedMaxFilter::new(MAX_BW_FILTER_LEN),
            bw_hi: Bandwidth::INFINITE,
            bw_lo: Bandwidth::INFINITE,
            bw: Bandwidth::ZERO,
            cycle_count: 0,
        }
    }

    /// 推定最大帯域を返す
    pub fn max_bw(&self) -> Bandwidth {
        Bandwidth::from_bytes_per_second(self.max_bw_filter.value().unwrap_or(0))
    }

    /// 操作帯域を返す
    pub fn bw(&self) -> Bandwidth {
        self.bw
    }

    /// 長期上限帯域を返す
    pub fn bw_hi(&self) -> Bandwidth {
        self.bw_hi
    }

    /// 短期下限帯域を返す
    pub fn bw_lo(&self) -> Bandwidth {
        self.bw_lo
    }

    /// フィルタの仮想時間を返す
    pub fn cycle_count(&self) -> u64 {
        self.cycle_count
    }

    /// max_bw フィルタを更新する
    ///
    /// draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.5.2.4 の
    /// 疑似コードには 0 サンプルの除外が明記されていないが、共通の
    /// GenerateRateSample が RS.interval < C.min_rtt のとき RS.delivery_rate を
    /// 0 のまま返すため、その 0 をフィルタへ流すとフィルタ窓の期限切れと同時に
    /// max_bw が一時的に 0 まで崩落する。0 サンプルは帯域推定に使わない。
    pub fn update_max_bw(&mut self, rs: &RateSample) {
        if rs.delivery_rate > Bandwidth::ZERO
            && (rs.delivery_rate >= self.max_bw() || !rs.is_app_limited)
        {
            self.max_bw_filter
                .update(rs.delivery_rate.as_bytes_per_second(), self.cycle_count);
        }
    }

    /// cycle_count を進行させる (MaxBwFilter のウィンドウを回す)
    pub fn advance_max_bw_filter(&mut self) {
        self.cycle_count += 1;
    }

    /// 操作帯域を更新する: bw = min(max_bw, bw_hi, bw_lo)
    pub fn bound_bw_for_model(&mut self) {
        self.bw = self.max_bw().min(self.bw_lo).min(self.bw_hi);
    }

    /// 長期上限帯域を更新する
    pub fn update_upper_bound(&mut self, bw: Bandwidth) {
        self.bw_hi = bw;
    }

    /// 初回ロスト時に下限帯域を初期化する
    ///
    /// bw_lo が未設定 (INFINITE) の場合のみ max_bw で初期化する。
    pub fn init_lower_bounds(&mut self) {
        if self.bw_lo == Bandwidth::INFINITE {
            self.bw_lo = self.max_bw();
        }
    }

    /// ロスト応答で下限帯域を更新する
    ///
    /// bw_lo = max(bw_latest, Beta * bw_lo)
    /// Beta = 0.7 (draft-cardwell-iccrg-bbr-congestion-control-02 Section 2.8)
    pub fn update_lower_bound(&mut self, bw_latest: Bandwidth) {
        // bw_lo が未初期化 (INFINITE) のときは Beta * INFINITE = INFINITE なので
        // 値を変えずに戻す。u64 の乗算で整数オーバーフローを起こす経路を作らない。
        if self.bw_lo == Bandwidth::INFINITE {
            return;
        }
        // 有限値でも乗算結果が u64 を超えないよう、u128 で計算する mul_ratio を使う。
        self.bw_lo = bw_latest.max(self.bw_lo.mul_ratio(BETA_NUM, BETA_DEN));
    }

    /// 下限帯域をリセットする (ProbeBW_REFILL 遷移時等)
    pub fn reset_lower_bound(&mut self) {
        self.bw_lo = Bandwidth::INFINITE;
    }
}

impl Default for Model {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
