// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! BBRv3 帯域モデル (draft-ietf-ccwg-bbr-06 Section 5.5.6)
//!
//! BBRv2 との差分:
//! - bw_hi を廃止: bw = min(max_bw, bw_shortterm)
//! - 命名: bw_lo → bw_shortterm

use crate::recovery::bbr::bandwidth::Bandwidth;
use crate::recovery::bbr::delivery_rate::RateSample;
use crate::recovery::windowed_filter::RoundBasedMaxFilter;

/// MaxBwFilter のウィンドウ長 (2 ProbeBW サイクル)
///
/// draft-ietf-ccwg-bbr-06 Section 2.11: BBR.MaxBwFilterLen = 2
/// (現在のサイクルと直前の完全なサイクル)。
const MAX_BW_FILTER_LEN: u64 = 2;

/// 損失時の乗算減少係数 (0.7)
const BETA_NUM: u64 = 7;
const BETA_DEN: u64 = 10;

/// BBRv3 帯域モデル
///
/// BBRv2 の bw_hi を廃止し、bw = min(max_bw, bw_shortterm) のみで操作帯域を決定する。
#[derive(Debug)]
pub struct Model {
    /// ラウンドベース最大帯域フィルタ
    max_bw_filter: RoundBasedMaxFilter,

    /// 短期帯域 (BBRv2 の bw_lo に相当)
    bw_shortterm: Bandwidth,

    /// 操作帯域 = min(max_bw, bw_shortterm)
    bw: Bandwidth,

    /// フィルタの仮想時間
    cycle_count: u64,
}

impl Model {
    /// 新しい帯域モデルを作成する
    pub fn new() -> Self {
        Self {
            max_bw_filter: RoundBasedMaxFilter::new(MAX_BW_FILTER_LEN),
            bw_shortterm: Bandwidth::INFINITE,
            bw: Bandwidth::ZERO,
            cycle_count: 0,
        }
    }

    pub fn max_bw(&self) -> Bandwidth {
        Bandwidth::from_bytes_per_second(self.max_bw_filter.value().unwrap_or(0))
    }

    pub fn bw(&self) -> Bandwidth {
        self.bw
    }

    pub fn bw_shortterm(&self) -> Bandwidth {
        self.bw_shortterm
    }

    pub fn cycle_count(&self) -> u64 {
        self.cycle_count
    }

    /// max_bw フィルタを更新する
    ///
    /// draft-ietf-ccwg-bbr-06 Section 5.5.5:
    /// RS.delivery_rate > 0 のときのみフィルタを更新する。
    /// GenerateRateSample は RS.interval < C.min_rtt のとき RS.delivery_rate を
    /// 0 のまま早期 return する。この 0 をフィルタへ流すと、フィルタ窓の期限切れと
    /// 同時に max_bw が一時的に 0 まで崩落するため、必ず除外する。
    pub fn update_max_bw(&mut self, rs: &RateSample) {
        if rs.delivery_rate > Bandwidth::ZERO
            && (rs.delivery_rate >= self.max_bw() || !rs.is_app_limited)
        {
            self.max_bw_filter
                .update(rs.delivery_rate.as_bytes_per_second(), self.cycle_count);
        }
    }

    pub fn advance_max_bw_filter(&mut self) {
        self.cycle_count += 1;
    }

    /// 操作帯域を更新する: bw = min(max_bw, bw_shortterm)
    ///
    /// BBRv2 との差分: bw_hi がないため 2 値の min のみ
    pub fn bound_bw_for_model(&mut self) {
        self.bw = self.max_bw().min(self.bw_shortterm);
    }

    /// 初回ロスト時に短期帯域を初期化する
    pub fn init_lower_bounds(&mut self) {
        if self.bw_shortterm == Bandwidth::INFINITE {
            self.bw_shortterm = self.max_bw();
        }
    }

    /// ロスト応答で短期帯域を更新する
    ///
    /// bw_shortterm = max(bw_latest, Beta * bw_shortterm)
    /// Beta = 0.7 (draft-ietf-ccwg-bbr-06 Section 5.5.10.3)
    pub fn update_lower_bound(&mut self, bw_latest: Bandwidth) {
        // bw_shortterm が未初期化 (INFINITE) のときは Beta * INFINITE = INFINITE
        // なので値を変えずに戻す。u64 の乗算で整数オーバーフローを起こす経路を作らない。
        if self.bw_shortterm == Bandwidth::INFINITE {
            return;
        }
        // 有限値でも乗算結果が u64 を超えないよう、u128 で計算する mul_ratio を使う。
        self.bw_shortterm = bw_latest.max(self.bw_shortterm.mul_ratio(BETA_NUM, BETA_DEN));
    }

    /// 短期帯域をリセットする
    pub fn reset_lower_bound(&mut self) {
        self.bw_shortterm = Bandwidth::INFINITE;
    }

    /// 損失回復が spurious だったときに短期帯域を復元する
    ///
    /// draft-ietf-ccwg-bbr-06 Section 5.5.11.2:
    /// BBR.bw_shortterm = max(BBR.bw_shortterm, BBR.undo_bw_shortterm)
    pub fn restore_bw_shortterm(&mut self, saved: Bandwidth) {
        self.bw_shortterm = self.bw_shortterm.max(saved);
    }
}

impl Default for Model {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
