// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! ACK パスポリシー実装
//!
//! PATH_ACK をどのパスで送信するかを決定する。
//! PATH_ACK は輻輳制御対象外 (draft-ietf-quic-multipath-21 Section 5.4)。
//! ACK パスの選択は RTT 推定に直接影響するため、データスケジューラーとは独立に設計する。

use crate::path::PathId;

use super::{AckCtx, AckPathPolicy};

// ---------------------------------------------------------------------------
// SamePathAck: 受信パスと同じパスに ACK を返す
// ---------------------------------------------------------------------------

/// 受信パスと同じパスに PATH_ACK を返すポリシー
///
/// パスごとの往復対称性が高い環境で扱いやすい。
/// RTT サンプルが forward + return の同一パスの合成になるため推定が安定しやすい。
#[derive(Debug, Clone)]
pub struct SamePathAck;

impl AckPathPolicy for SamePathAck {
    fn select_ack_path(&mut self, ctx: &AckCtx, acked_path: PathId) -> Option<PathId> {
        // acked_path が usable なら同じパスに返す
        if ctx
            .paths
            .iter()
            .any(|p| p.path_id == acked_path && p.is_usable)
        {
            return Some(acked_path);
        }
        // acked_path が利用不可なら最短 RTT の usable パスにフォールバック
        ctx.paths
            .iter()
            .filter(|p| p.is_usable)
            .min_by_key(|p| p.smoothed_rtt)
            .map(|p| p.path_id)
    }
}

// ---------------------------------------------------------------------------
// ShortestPathAck: 最短 RTT のパスに ACK を返す
// ---------------------------------------------------------------------------

/// 最短 RTT の usable パスに PATH_ACK を返すポリシー
///
/// 制御ループを短縮し、特に satellite + terrestrial のような
/// 大きな RTT 差がある環境で効果的。
/// draft-ietf-quic-multipath-21 Section 5.4 で例示される方向。
#[derive(Debug, Clone)]
pub struct ShortestPathAck;

impl AckPathPolicy for ShortestPathAck {
    fn select_ack_path(&mut self, ctx: &AckCtx, _acked_path: PathId) -> Option<PathId> {
        ctx.paths
            .iter()
            .filter(|p| p.is_usable)
            .min_by_key(|p| p.smoothed_rtt)
            .map(|p| p.path_id)
    }
}

// ---------------------------------------------------------------------------
// StickyAckPath: ACK 返送パスを一定期間固定する
// ---------------------------------------------------------------------------

/// ACK 返送パスを固定し、RTT 推定を安定させるポリシー
///
/// draft-ietf-quic-multipath-21 Section 5.4:
/// ACK スケジューリングが安定しているほど RTT 推定は収束しやすい。
///
/// 基本は最短 RTT の健全パスに ACK を返すが、頻繁に切り替えない。
/// 切り替えトリガー:
/// - 現在の ACK パスが Active でなくなった場合
/// - 現在の ACK パスの smoothed_rtt が他パスの RTT_SWITCH_RATIO 倍を超えた場合
/// - 現在の ACK パスで PTO が発生した場合
#[derive(Debug, Clone)]
pub struct StickyAckPath {
    /// 現在固定している ACK パス
    current_path: Option<PathId>,
    /// RTT 切り替え倍率 (現在の ACK パスの RTT がベストパスの N 倍を超えたら切り替え)
    rtt_switch_ratio: u64,
}

/// RTT 切り替え倍率のデフォルト値
const DEFAULT_RTT_SWITCH_RATIO: u64 = 3;

impl StickyAckPath {
    /// 新しい StickyAckPath を作成する
    pub fn new() -> Self {
        Self {
            current_path: None,
            rtt_switch_ratio: DEFAULT_RTT_SWITCH_RATIO,
        }
    }

    /// RTT 切り替え倍率を指定して作成する
    pub fn with_rtt_switch_ratio(ratio: u64) -> Self {
        Self {
            current_path: None,
            rtt_switch_ratio: ratio,
        }
    }

    /// 現在の固定パスが切り替え条件を満たすか判定する
    fn should_switch(&self, ctx: &AckCtx) -> bool {
        let Some(current) = self.current_path else {
            return true; // まだ固定パスがない
        };

        let Some(current_metrics) = ctx.paths.iter().find(|p| p.path_id == current) else {
            return true; // 現在のパスが存在しない
        };

        // 条件 1: 現在のパスが usable でない
        if !current_metrics.is_usable {
            return true;
        }

        // 条件 2: PTO が発生している
        if current_metrics.pto_count > 0 {
            return true;
        }

        // 条件 3: 現在のパスの RTT がベストパスの N 倍を超えている
        if let Some(best) = ctx
            .paths
            .iter()
            .filter(|p| p.is_usable)
            .min_by_key(|p| p.smoothed_rtt)
            && best.path_id != current
            && current_metrics.smoothed_rtt.as_micros()
                > best
                    .smoothed_rtt
                    .as_micros()
                    .saturating_mul(self.rtt_switch_ratio)
        {
            return true;
        }

        false
    }

    /// 最適なパスを選択する (最短 RTT の usable パス)
    fn select_best(ctx: &AckCtx) -> Option<PathId> {
        ctx.paths
            .iter()
            .filter(|p| p.is_usable)
            .min_by_key(|p| p.smoothed_rtt)
            .map(|p| p.path_id)
    }
}

impl Default for StickyAckPath {
    fn default() -> Self {
        Self::new()
    }
}

impl AckPathPolicy for StickyAckPath {
    fn select_ack_path(&mut self, ctx: &AckCtx, _acked_path: PathId) -> Option<PathId> {
        if self.should_switch(ctx) {
            self.current_path = Self::select_best(ctx);
        }
        self.current_path
    }
}

#[cfg(test)]
mod tests;
