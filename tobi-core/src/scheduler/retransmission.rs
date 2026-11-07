// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 再送ポリシー実装
//!
//! ロスト判定されたデータの再送パスを決定する。
//! 新規データ送信の最適化 (throughput) ではなく、
//! 壊れた送信の修復 (回復の速さと副作用の少なさ) を扱う層。
//!
//! draft-ietf-quic-multipath-21 Section 5.6:
//! same-path / cross-path / duplicate のいずれも許容されるが詳細は実装依存。
//! 異なるパスへの再送時は PMTU が異なる可能性があり、パケットの再分割が必要。

use crate::path::PathId;

use super::{FrameClass, LossReason, PathMetrics, RetransmissionPolicy, RetxCtx, RetxDecision};

// ---------------------------------------------------------------------------
// SamePathThenCrossPath: PTO 超過時のみクロスパス再送
// ---------------------------------------------------------------------------

/// 元パスで再送し、PTO 超過時または元パス degraded 時のみクロスパス再送するポリシー
///
/// 軽い loss (packet-threshold / time-threshold) は same-path で再送する。
/// PTO 発火後または元パスの PTO カウントが閾値を超えた場合は best alternate path へ cross-path。
///
/// 最も conservative な再送ポリシー。挙動の予測しやすさを優先し、
/// PTO 超過時のフェイルオーバーも確保する。
#[derive(Debug, Clone)]
pub struct SamePathThenCrossPath {
    /// クロスパス再送に切り替える PTO カウント閾値
    pto_threshold: u32,
}

/// クロスパス切り替えの PTO カウント閾値のデフォルト値
const DEFAULT_PTO_THRESHOLD: u32 = 2;

impl SamePathThenCrossPath {
    /// 新しい SamePathThenCrossPath を作成する
    pub fn new() -> Self {
        Self {
            pto_threshold: DEFAULT_PTO_THRESHOLD,
        }
    }

    /// PTO 閾値を指定して作成する
    pub fn with_pto_threshold(threshold: u32) -> Self {
        Self {
            pto_threshold: threshold,
        }
    }
}

impl Default for SamePathThenCrossPath {
    fn default() -> Self {
        Self::new()
    }
}

impl RetransmissionPolicy for SamePathThenCrossPath {
    fn decide_retx(
        &mut self,
        ctx: &RetxCtx,
        original_path: PathId,
        candidates: &[PathId],
    ) -> RetxDecision {
        if candidates.is_empty() {
            return RetxDecision::Defer;
        }

        let original_metrics = ctx.paths.iter().find(|p| p.path_id == original_path);

        // 元パスが usable で PTO 閾値未満かつ PTO ロストでない場合は same-path
        if let Some(metrics) = original_metrics
            && metrics.is_usable
            && metrics.pto_count < self.pto_threshold
            && ctx.loss_reason != LossReason::Pto
        {
            return RetxDecision::SamePath;
        }

        // 元パスが degraded / PTO 超過 → best alternate path を選択
        // 候補から元パスを除外し、usable な最短 RTT パスを選ぶ
        let alt = ctx
            .paths
            .iter()
            .filter(|p| {
                p.path_id != original_path
                    && p.is_usable
                    && !p.is_congestion_limited
                    && candidates.contains(&p.path_id)
            })
            .min_by_key(|p| p.smoothed_rtt);

        if let Some(alt_metrics) = alt {
            return RetxDecision::CrossPath(alt_metrics.path_id);
        }

        // 代替パスがない場合: 元パスが usable なら same-path にフォールバック
        if original_metrics.is_some_and(|m| m.is_usable) {
            return RetxDecision::SamePath;
        }

        RetxDecision::Defer
    }
}

// ---------------------------------------------------------------------------
// CrossPathImmediate: ロスト判定後すぐに別パスで再送
// ---------------------------------------------------------------------------

/// ロスト判定後すぐにベストな別パスで再送するポリシー
///
/// 回復速度を優先する攻めた戦略。元パスの問題を避けて迅速に回復するが、
/// ストリームの再順序が悪化しやすく、スプリアス再送のリスクも高い。
#[derive(Debug, Clone)]
pub struct CrossPathImmediate;

impl RetransmissionPolicy for CrossPathImmediate {
    fn decide_retx(
        &mut self,
        ctx: &RetxCtx,
        original_path: PathId,
        candidates: &[PathId],
    ) -> RetxDecision {
        if candidates.is_empty() {
            return RetxDecision::Defer;
        }

        // usable で輻輳制限されていない候補から最短 RTT を選択 (元パスを除外)
        let alt = ctx
            .paths
            .iter()
            .filter(|p| {
                p.path_id != original_path
                    && p.is_usable
                    && !p.is_congestion_limited
                    && candidates.contains(&p.path_id)
            })
            .min_by_key(|p| p.smoothed_rtt);

        if let Some(alt_metrics) = alt {
            return RetxDecision::CrossPath(alt_metrics.path_id);
        }

        // 代替パスがなければ元パスで再送
        let original_metrics = ctx.paths.iter().find(|p| p.path_id == original_path);
        if original_metrics.is_some_and(|m| m.is_usable) {
            return RetxDecision::SamePath;
        }

        RetxDecision::Defer
    }
}

// ---------------------------------------------------------------------------
// EarliestRecoveryPath: 回復完了時間推定が最短のパスを選択
// ---------------------------------------------------------------------------

/// 回復完了時間推定が最短のパスで再送するポリシー
///
/// 候補パスごとに recovery completion time を推定し、最短のパスを選択する。
/// reorder penalty と PMTU penalty を加算する。
///
/// recovery_score(path) =
///     send_wait(path) + delivery_estimate(path) + reorder_penalty + pmtu_penalty
///
/// リオーダーペナルティ: クロスパス再送時にストリーム順序が乱れるコスト
/// PMTU ペナルティ: 異なる PMTU のパスでは再パケット化が必要
#[derive(Debug, Clone)]
pub struct EarliestRecoveryPath {
    /// リオーダーペナルティ (マイクロ秒)
    reorder_penalty_us: u64,
    /// hysteresis マージン (マイクロ秒)
    /// クロスパスに切り替える際の安定化マージン
    hysteresis_us: u64,
}

/// デフォルトのリオーダーペナルティ (5ms)
const DEFAULT_REORDER_PENALTY_US: u64 = 5_000;
/// デフォルトの hysteresis マージン (2ms)
const DEFAULT_HYSTERESIS_US: u64 = 2_000;

impl EarliestRecoveryPath {
    /// 新しい EarliestRecoveryPath を作成する
    pub fn new() -> Self {
        Self {
            reorder_penalty_us: DEFAULT_REORDER_PENALTY_US,
            hysteresis_us: DEFAULT_HYSTERESIS_US,
        }
    }

    /// パラメータを指定して作成する
    pub fn with_params(reorder_penalty_us: u64, hysteresis_us: u64) -> Self {
        Self {
            reorder_penalty_us,
            hysteresis_us,
        }
    }

    /// パスの回復スコアを計算する (マイクロ秒)
    fn recovery_score(&self, p: &PathMetrics, is_cross_path: bool, original_pmtu: u16) -> u64 {
        // 送信待ち時間 (輻輳制限中なら推定)
        let send_wait = if p.is_congestion_limited && p.congestion_window > 0 {
            // 乗算はピア由来の極端値で u64 を超え得るため saturating にする
            p.bytes_in_flight.saturating_mul(p.smoothed_rtt.as_micros()) / p.congestion_window
        } else {
            0
        };

        // 配送時間推定 (片方向)
        let delivery = p.delivery_time_estimate.as_micros() / 2;

        // リオーダーペナルティ (クロスパス再送時のみ)
        let reorder = if is_cross_path {
            self.reorder_penalty_us
        } else {
            0
        };

        // PMTU ペナルティ (異なる PMTU のパスへの再送は再パケット化が必要)
        // draft-ietf-quic-multipath-21 Section 5.6
        let pmtu_penalty = if is_cross_path && p.pmtu < original_pmtu {
            // PMTU が小さいパスへの再送: 分割コスト (1 RTT 分のペナルティ)
            p.smoothed_rtt.as_micros() / 4
        } else {
            0
        };

        send_wait
            .saturating_add(delivery)
            .saturating_add(reorder)
            .saturating_add(pmtu_penalty)
    }
}

impl Default for EarliestRecoveryPath {
    fn default() -> Self {
        Self::new()
    }
}

impl RetransmissionPolicy for EarliestRecoveryPath {
    fn decide_retx(
        &mut self,
        ctx: &RetxCtx,
        original_path: PathId,
        candidates: &[PathId],
    ) -> RetxDecision {
        if candidates.is_empty() {
            return RetxDecision::Defer;
        }

        let original_metrics = ctx.paths.iter().find(|p| p.path_id == original_path);
        let original_pmtu = original_metrics.map_or(1200, |m| m.pmtu);

        // 元パスの回復スコア
        let same_path_score = original_metrics
            .filter(|m| m.is_usable)
            .map(|m| self.recovery_score(m, false, original_pmtu));

        // 代替パスの中で最良のスコア
        let best_alt = ctx
            .paths
            .iter()
            .filter(|p| {
                p.path_id != original_path
                    && p.is_usable
                    && !p.is_congestion_limited
                    && candidates.contains(&p.path_id)
            })
            .min_by_key(|p| self.recovery_score(p, true, original_pmtu));

        match (same_path_score, best_alt) {
            (Some(same_score), Some(alt)) => {
                let alt_score = self.recovery_score(alt, true, original_pmtu);
                // hysteresis: 代替パスが十分に速い場合のみクロスパス
                // hysteresis_us は外部指定可能で u64 を超え得るため saturating にする
                if alt_score.saturating_add(self.hysteresis_us) < same_score {
                    RetxDecision::CrossPath(alt.path_id)
                } else {
                    RetxDecision::SamePath
                }
            }
            (None, Some(alt)) => RetxDecision::CrossPath(alt.path_id),
            (Some(_), None) => RetxDecision::SamePath,
            (None, None) => RetxDecision::Defer,
        }
    }
}

// ---------------------------------------------------------------------------
// SelectiveDuplicate: critical データのみ duplicate を許可
// ---------------------------------------------------------------------------

/// critical データのみ duplicate 再送を許可するポリシー
///
/// handshake / crypto、stream frontier を塞いでいるデータ等の
/// critical なフレームのみ duplicate (元パス + 代替パス) で再送する。
/// その他のデータは SamePathThenCrossPath に委譲する。
///
/// draft-ietf-quic-multipath-21 Section 5.6:
/// duplicate 送信は許容されるが帯域コストが高いため限定利用。
#[derive(Debug, Clone)]
pub struct SelectiveDuplicate {
    /// 内部の通常再送ポリシー
    fallback: SamePathThenCrossPath,
}

impl SelectiveDuplicate {
    /// 新しい SelectiveDuplicate を作成する
    pub fn new() -> Self {
        Self {
            fallback: SamePathThenCrossPath::new(),
        }
    }
}

impl Default for SelectiveDuplicate {
    fn default() -> Self {
        Self::new()
    }
}

impl RetransmissionPolicy for SelectiveDuplicate {
    fn decide_retx(
        &mut self,
        ctx: &RetxCtx,
        original_path: PathId,
        candidates: &[PathId],
    ) -> RetxDecision {
        if candidates.is_empty() {
            return RetxDecision::Defer;
        }

        // critical フレームか判定
        let is_critical = ctx.frame_class == FrameClass::Crypto;

        if is_critical {
            // critical データ: 元パスが usable なら duplicate、そうでなければクロスパス。
            // 1-RTT CRYPTO の再送では複製のみ代替パスへ送り、原本の再送パスは
            // データスケジューラーが選ぶ (元パス固定は保証しない)。
            let original_usable = ctx
                .paths
                .iter()
                .any(|p| p.path_id == original_path && p.is_usable);

            let alt = ctx
                .paths
                .iter()
                .filter(|p| {
                    p.path_id != original_path
                        && p.is_usable
                        && !p.is_congestion_limited
                        && candidates.contains(&p.path_id)
                })
                .min_by_key(|p| p.smoothed_rtt);

            if let Some(alt_metrics) = alt {
                if original_usable {
                    return RetxDecision::Duplicate(alt_metrics.path_id);
                }
                return RetxDecision::CrossPath(alt_metrics.path_id);
            }

            if original_usable {
                return RetxDecision::SamePath;
            }

            return RetxDecision::Defer;
        }

        // 非 critical データ: 通常の再送ポリシーに委譲
        self.fallback.decide_retx(ctx, original_path, candidates)
    }
}

#[cfg(test)]
mod tests;
