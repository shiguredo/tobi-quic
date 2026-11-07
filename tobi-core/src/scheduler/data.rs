// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! データスケジューラー実装
//!
//! 送信機会ごとに新規データ/制御フレームの送信パスを選択する。

use alloc::vec::Vec;

use crate::path::{PathId, PathStatus};
use crate::time::Duration;

use super::{DataScheduler, PathMetrics, ScheduleCtx};

// ---------------------------------------------------------------------------
// MinRtt: 最短 RTT パスを選択 (現在のデフォルト実装)
// ---------------------------------------------------------------------------

/// 最短 RTT パスを選択するデータスケジューラー
///
/// draft-ietf-quic-multipath-21 Section 5.5 に基づき:
/// 1. Available な Active パスで輻輳ウィンドウに空きがあるものを優先
/// 2. なければ Backup パスにフォールバック
/// 3. 複数候補がある場合は最短 smoothed_rtt のパスを選択
#[derive(Debug, Clone)]
pub struct MinRtt;

impl DataScheduler for MinRtt {
    fn select_path(&mut self, ctx: &ScheduleCtx) -> Option<PathId> {
        // ピアが Backup と指定したパスは、他に利用可能なパスがある場合に除外する
        // (draft-ietf-quic-multipath-21 Section 3.3)。
        let has_peer_preferred = ctx.has_peer_preferred_path();
        // Available な Active パスで輻輳ウィンドウに空きがあるものを探す
        let available = ctx
            .paths
            .iter()
            .filter(|p| {
                p.is_usable
                    && p.status == PathStatus::Available
                    && !p.is_congestion_limited
                    && !p.excluded_by_peer_preference(has_peer_preferred)
            })
            .min_by_key(|p| p.smoothed_rtt);

        if let Some(best) = available {
            return Some(best.path_id);
        }

        // Available パスがなければ Backup パスを試す
        ctx.paths
            .iter()
            .filter(|p| {
                p.is_usable
                    && p.status == PathStatus::Backup
                    && !p.is_congestion_limited
                    && !p.excluded_by_peer_preference(has_peer_preferred)
            })
            .min_by_key(|p| p.smoothed_rtt)
            .map(|p| p.path_id)
    }
}

// ---------------------------------------------------------------------------
// MinCompletionTime: 完了時間推定が最小のパスを選択
// ---------------------------------------------------------------------------

/// 完了時間推定が最小のパスを選択するデータスケジューラー
///
/// 各パスの「今送信したら、いつ到着するか」を推定し、最小のパスを選択する。
/// 推定スコア:
///   score(path) = cc_blocking_delay + pacing_delay + forward_delay
///
/// - cc_blocking_delay: 輻輳制限中なら輻輳ウィンドウが開くまでの推定時間
/// - pacing_delay: pacing rate から次の送信可能時刻を推定
/// - forward_delay: delivery_time_estimate の半分 (片方向遅延推定)
///
/// Available パスを優先し、全て利用不可なら Backup パスにフォールバックする。
#[derive(Debug, Clone)]
pub struct MinCompletionTime;

impl MinCompletionTime {
    /// パスの完了時間スコアを計算する (マイクロ秒)
    fn completion_score(p: &PathMetrics) -> u64 {
        // 片方向遅延推定 (delivery_time_estimate / 2)
        let forward_delay = p.delivery_time_estimate.as_micros() / 2;

        // 輻輳ウィンドウのブロック遅延推定
        let cc_blocking_delay = if p.is_congestion_limited {
            // 輻輳制限中: bytes_in_flight が cwnd を解放するまでの推定時間
            // bytes_in_flight / (cwnd / srtt) = bytes_in_flight * srtt / cwnd
            // 乗算はピア由来の極端値で u64 を超え得るため saturating にする
            p.bytes_in_flight
                .saturating_mul(p.smoothed_rtt.as_micros())
                .checked_div(p.congestion_window)
                .unwrap_or(p.smoothed_rtt.as_micros()) // cwnd が 0 なら 1 RTT 待ち
        } else {
            0
        };

        // ペーシング遅延推定
        let pacing_delay = p
            .pacing_rate
            .and_then(|rate| {
                // 1 PMTU 分のデータを送信するまでの遅延 (マイクロ秒)
                (p.pmtu as u64).saturating_mul(1_000_000).checked_div(rate)
            })
            .unwrap_or(0);

        forward_delay
            .saturating_add(cc_blocking_delay)
            .saturating_add(pacing_delay)
    }
}

impl DataScheduler for MinCompletionTime {
    fn select_path(&mut self, ctx: &ScheduleCtx) -> Option<PathId> {
        // ピアが Backup と指定したパスは、他に利用可能なパスがある場合に除外する
        // (draft-ietf-quic-multipath-21 Section 3.3)。
        let has_peer_preferred = ctx.has_peer_preferred_path();
        // Available パスで usable なものから最小スコアを選択
        let available = ctx
            .paths
            .iter()
            .filter(|p| {
                p.is_usable
                    && p.status == PathStatus::Available
                    && !p.is_congestion_limited
                    && !p.excluded_by_peer_preference(has_peer_preferred)
            })
            .min_by_key(|p| Self::completion_score(p));

        if let Some(best) = available {
            return Some(best.path_id);
        }

        // 輻輳制限中の Available パスも候補に含める (スコアで比較)
        let available_congested = ctx
            .paths
            .iter()
            .filter(|p| {
                p.is_usable
                    && p.status == PathStatus::Available
                    && !p.excluded_by_peer_preference(has_peer_preferred)
            })
            .min_by_key(|p| Self::completion_score(p));

        if let Some(best) = available_congested {
            return Some(best.path_id);
        }

        // Backup パスにフォールバック
        ctx.paths
            .iter()
            .filter(|p| {
                p.is_usable
                    && p.status == PathStatus::Backup
                    && !p.excluded_by_peer_preference(has_peer_preferred)
            })
            .min_by_key(|p| Self::completion_score(p))
            .map(|p| p.path_id)
    }
}

// ---------------------------------------------------------------------------
// BlestLike: 遅いパスへの送信を抑制する
// ---------------------------------------------------------------------------

/// BLEST-like スケジューラー
///
/// 遅いパスに送信するとストリーム配送を詰まらせる場合、そのパスを抑制する。
/// 基本は MinRtt と同じだが、遅いパスが速いパスの配送をブロックしそうなら
/// 遅いパスを使わない。
///
/// ブロック判定:
///   速いパスの available_window がまだあり、遅いパスの RTT が速いパスの
///   lambda 倍を超える場合、遅いパスを抑制する。
///
/// 参考: BLEST (BLocking ESTimation) - heterogeneous wireless 環境での
/// out-of-order 問題を軽減するスケジューラー。
#[derive(Debug, Clone)]
pub struct BlestLike {
    /// RTT 比率の閾値 (遅いパスの RTT が速いパスの lambda 倍を超えたら抑制)
    lambda: u64,
}

/// デフォルトの lambda 値
const DEFAULT_LAMBDA: u64 = 3;

impl BlestLike {
    /// 新しい BlestLike を作成する
    pub fn new() -> Self {
        Self {
            lambda: DEFAULT_LAMBDA,
        }
    }

    /// lambda を指定して作成する
    pub fn with_lambda(lambda: u64) -> Self {
        Self { lambda }
    }
}

impl Default for BlestLike {
    fn default() -> Self {
        Self::new()
    }
}

impl DataScheduler for BlestLike {
    fn select_path(&mut self, ctx: &ScheduleCtx) -> Option<PathId> {
        // ピアが Backup と指定したパスは、他に利用可能なパスがある場合に除外する
        // (draft-ietf-quic-multipath-21 Section 3.3)。
        let has_peer_preferred = ctx.has_peer_preferred_path();
        // usable かつ Available で輻輳制限されていないパスを収集
        let candidates: Vec<&PathMetrics> = ctx
            .paths
            .iter()
            .filter(|p| {
                p.is_usable
                    && p.status == PathStatus::Available
                    && !p.is_congestion_limited
                    && !p.excluded_by_peer_preference(has_peer_preferred)
            })
            .collect();

        if candidates.is_empty() {
            // Backup にフォールバック
            return ctx
                .paths
                .iter()
                .filter(|p| {
                    p.is_usable
                        && p.status == PathStatus::Backup
                        && !p.is_congestion_limited
                        && !p.excluded_by_peer_preference(has_peer_preferred)
                })
                .min_by_key(|p| p.smoothed_rtt)
                .map(|p| p.path_id);
        }

        // 最速パスの RTT を取得
        let fastest_rtt = candidates
            .iter()
            .map(|p| p.smoothed_rtt)
            .min()
            .unwrap_or(Duration::ZERO);

        let fastest_rtt_us = fastest_rtt.as_micros();
        if fastest_rtt_us == 0 {
            return candidates.first().map(|p| p.path_id);
        }

        // 最速パスの available_window を確認
        let fastest_has_window = candidates
            .iter()
            .any(|p| p.smoothed_rtt == fastest_rtt && p.available_window > 0);

        if fastest_has_window {
            // 速いパスにまだ余裕がある場合: 遅すぎるパスを抑制
            // lambda は外部指定可能で u64 を超え得るため saturating にする
            let non_blocked: Vec<&&PathMetrics> = candidates
                .iter()
                .filter(|p| {
                    p.smoothed_rtt.as_micros() <= fastest_rtt_us.saturating_mul(self.lambda)
                })
                .collect();

            if let Some(best) = non_blocked.iter().min_by_key(|p| p.smoothed_rtt) {
                return Some(best.path_id);
            }
        }

        // フォールバック: 最短 RTT を選択
        candidates
            .iter()
            .min_by_key(|p| p.smoothed_rtt)
            .map(|p| p.path_id)
    }
}

// ---------------------------------------------------------------------------
// RoundRobin: 利用可能なパスへ順番に振り分ける
// ---------------------------------------------------------------------------

/// 利用可能なパスへデータを順番に振り分けるラウンドロビン
///
/// draft-ietf-quic-multipath-21 Section 5.5 のスケジューリングは実装依存である。
/// Available な Active パスで輻輳制限でないものを PathId の昇順に並べ、前回
/// 選んだパスの次から 1 本を選ぶ。パスの追加・廃棄・状態変化があっても、
/// 毎回 PathId 順の候補列から次を決め直すため、カーソル位置が破綻しない。
///
/// 候補が 1 本だけの場合はそのパスを返し、巡回状態を進めない。
/// Available パスが無い場合は既存の実装と同様に Backup パスへフォールバックする。
#[derive(Debug, Clone, Default)]
pub struct RoundRobin {
    /// 直前に選んだパス
    last_selected: Option<PathId>,
}

impl RoundRobin {
    /// 新しいラウンドロビンスケジューラーを作成する
    pub fn new() -> Self {
        Self {
            last_selected: None,
        }
    }

    /// 送信候補のパス ID を PathId の昇順で返す
    ///
    /// ピアが Backup と指定したパスは、他に利用可能なパスがある場合に候補から
    /// 除外する (draft-ietf-quic-multipath-21 Section 3.3)。
    fn candidate_paths(ctx: &ScheduleCtx) -> Vec<PathId> {
        let has_peer_preferred = ctx.has_peer_preferred_path();
        let mut candidates: Vec<PathId> = ctx
            .paths
            .iter()
            .filter(|p| {
                p.is_usable
                    && p.status == PathStatus::Available
                    && !p.is_congestion_limited
                    && !p.excluded_by_peer_preference(has_peer_preferred)
            })
            .map(|p| p.path_id)
            .collect();
        if candidates.is_empty() {
            candidates = ctx
                .paths
                .iter()
                .filter(|p| {
                    p.is_usable
                        && p.status == PathStatus::Backup
                        && !p.is_congestion_limited
                        && !p.excluded_by_peer_preference(has_peer_preferred)
                })
                .map(|p| p.path_id)
                .collect();
        }
        candidates.sort_by_key(|path_id| path_id.0);
        candidates
    }

    /// 前回選んだパスの次を先頭にした巡回順を返す
    fn rotate(candidates: &[PathId], last_selected: Option<PathId>) -> Vec<PathId> {
        let start = last_selected
            .and_then(|last| candidates.iter().position(|path_id| path_id.0 > last.0))
            .unwrap_or(0);
        let mut ordered = Vec::with_capacity(candidates.len());
        ordered.extend_from_slice(&candidates[start..]);
        ordered.extend_from_slice(&candidates[..start]);
        ordered
    }
}

impl DataScheduler for RoundRobin {
    fn select_path(&mut self, ctx: &ScheduleCtx) -> Option<PathId> {
        let candidates = Self::candidate_paths(ctx);
        match candidates.as_slice() {
            [] => None,
            [only] => Some(*only),
            _ => {
                let selected = Self::rotate(&candidates, self.last_selected)[0];
                self.last_selected = Some(selected);
                Some(selected)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Redundant: 同じデータを複数パスへ重複送信する
// ---------------------------------------------------------------------------

/// 同じデータを複数パスへ重複送信する冗長スケジューラー
///
/// draft-ietf-quic-multipath-21 Section 5.6 は複数パスへの重複送信を再送戦略の
/// 一つとして挙げつつ、一般用途ではネットワーク負荷の観点から推奨していない。
/// このスケジューラーはアプリケーションが明示的に選択した場合だけ使う。
///
/// 1 回の送信機会に最大 `max_paths` 本のパスを返す。候補の選び方は
/// [`RoundRobin`] と同じで、前回の送信で最後に使ったパスの次から巡回する。
/// 複製の対象は STREAM フレームであり、DATAGRAM は複製しない。
#[derive(Debug, Clone)]
pub struct Redundant {
    /// 1 回の送信機会に使用する最大パス数
    max_paths: usize,
    /// 直前に選んだパス
    last_selected: Option<PathId>,
}

impl Redundant {
    /// 最大パス数を指定して作成する
    ///
    /// 0 が指定された場合は 1 として扱う (重複送信を行わない)。
    pub fn new(max_paths: usize) -> Self {
        Self {
            max_paths: max_paths.max(1),
            last_selected: None,
        }
    }

    /// 1 回の送信機会に使用する最大パス数を返す
    pub fn max_paths(&self) -> usize {
        self.max_paths
    }
}

impl DataScheduler for Redundant {
    fn select_path(&mut self, ctx: &ScheduleCtx) -> Option<PathId> {
        self.select_paths(ctx, 1).into_iter().next()
    }

    fn max_paths(&self) -> usize {
        self.max_paths
    }

    fn select_paths(&mut self, ctx: &ScheduleCtx, max_paths: usize) -> Vec<PathId> {
        if max_paths == 0 {
            return Vec::new();
        }
        let candidates = RoundRobin::candidate_paths(ctx);
        match candidates.as_slice() {
            [] => Vec::new(),
            [only] => alloc::vec![*only],
            _ => {
                let limit = self.max_paths.min(max_paths).max(1);
                let ordered = RoundRobin::rotate(&candidates, self.last_selected);
                let selected: Vec<PathId> = ordered.into_iter().take(limit).collect();
                self.last_selected = selected.last().copied();
                selected
            }
        }
    }
}

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// RateAware: 帯域推定に基づいて送信パスを選ぶ
// ---------------------------------------------------------------------------

/// 帯域推定に基づいて送信パスを選ぶスケジューラー
///
/// 各パスについて、次にデータグラムを送った場合の推定遅延
///   estimated_delay = smoothed_rtt + bytes_in_flight / bandwidth
/// を計算し、最小のパスを選ぶ。帯域推定を持たないパスは pacing rate を
/// 代替に使い、どちらも無ければ RTT だけで比較する。
///
/// 速いパスでも送信中バイト数が増えると推定遅延が大きくなるため、
/// 帯域の異なる複数パスに負荷が分散する。BBR のように配送レート推定を
/// 持つ輻輳制御と組み合わせて使うことを想定する。
#[derive(Debug, Clone, Copy, Default)]
pub struct RateAware;

/// 送信候補のパスを絞り込む
///
/// 他スケジューラーと同じく、Available を優先し、無ければ Backup に
/// フォールバックする。ピアが Backup と指定したパスは、他に利用可能な
/// パスがある場合に除外する (draft-ietf-quic-multipath-21 Section 3.3)。
fn sender_candidates<'a>(ctx: &'a ScheduleCtx) -> Vec<&'a PathMetrics> {
    let has_peer_preferred = ctx.has_peer_preferred_path();
    let available: Vec<&PathMetrics> = ctx
        .paths
        .iter()
        .filter(|p| {
            p.is_usable
                && p.status == PathStatus::Available
                && !p.is_congestion_limited
                && !p.excluded_by_peer_preference(has_peer_preferred)
        })
        .collect();
    if !available.is_empty() {
        return available;
    }
    ctx.paths
        .iter()
        .filter(|p| {
            p.is_usable
                && p.status == PathStatus::Backup
                && !p.is_congestion_limited
                && !p.excluded_by_peer_preference(has_peer_preferred)
        })
        .collect()
}

impl RateAware {
    /// 新しい RateAware スケジューラーを作成する
    pub fn new() -> Self {
        Self
    }

    /// 次に送信した場合の推定遅延 (マイクロ秒) を返す
    fn estimated_delay_us(path: &PathMetrics) -> u64 {
        let rtt_us = path.smoothed_rtt.as_micros();
        let rate = path
            .bandwidth_estimate
            .or(path.pacing_rate)
            .filter(|rate| *rate > 0);
        match rate {
            Some(rate) => {
                // bytes_in_flight / rate (秒) をマイクロ秒へ
                let queue_us = (u128::from(path.bytes_in_flight) * 1_000_000 / u128::from(rate))
                    .min(u128::from(u64::MAX)) as u64;
                rtt_us.saturating_add(queue_us)
            }
            None => rtt_us,
        }
    }
}

impl DataScheduler for RateAware {
    fn select_path(&mut self, ctx: &ScheduleCtx) -> Option<PathId> {
        sender_candidates(ctx)
            .into_iter()
            .min_by_key(|path| (Self::estimated_delay_us(path), path.path_id.0))
            .map(|path| path.path_id)
    }
}

// ---------------------------------------------------------------------------
// WeightedRoundRobin: 帯域推定に比例した重みで振り分ける
// ---------------------------------------------------------------------------

/// 帯域推定に比例した重みでパスへ振り分けるスケジューラー
///
/// パスごとの帯域推定 (無ければ pacing rate、どちらも無ければ 1) を重みとして、
/// これまでに選ばれた回数が重みに対して少ないパスを優先する。重み 1:3 の
/// 2 パスなら、送信機会のおよそ 1/4 と 3/4 をそれぞれに割り当てる。
/// 帯域の大きいパスへより多くのデータを流したい場合に使う。
#[derive(Debug, Clone, Default)]
pub struct WeightedRoundRobin {
    /// パスごとの選択回数 (重み付きの公平性計算に使う)
    counts: Vec<(PathId, u64)>,
    /// 最後に選択したパス (同率時の巡回開始位置に使う)
    last_selected: Option<PathId>,
    /// 前回の正規化に使った候補 (PathId と重み)
    ///
    /// 候補集合や重みが変わったときだけ、過去の選択回数を現在の候補を
    /// 基準に正規化する。新規参加パスへ参加前の送信分を補償しない。
    config: Vec<(PathId, u64)>,
}

impl WeightedRoundRobin {
    /// 新しい WeightedRoundRobin スケジューラーを作成する
    pub fn new() -> Self {
        Self {
            counts: Vec::new(),
            last_selected: None,
            config: Vec::new(),
        }
    }

    /// パスの重みを返す
    ///
    /// 帯域推定を優先し、無ければ pacing rate、どちらも無ければ 1 にする。
    fn weight(path: &PathMetrics) -> u64 {
        path.bandwidth_estimate
            .or(path.pacing_rate)
            .filter(|weight| *weight > 0)
            .unwrap_or(1)
            .min(u64::MAX / 2)
    }

    /// パスの選択回数を返す (未選択なら 0)
    fn count(&self, path_id: PathId) -> u64 {
        self.counts
            .iter()
            .find(|(id, _)| *id == path_id)
            .map(|(_, count)| *count)
            .unwrap_or(0)
    }

    /// 候補集合と重みの変化に合わせて選択回数を正規化する
    ///
    /// 選択は count/weight 比で行うため、単純に生の count の最小値を引くと
    /// 重み付き候補の比を壊す。既存候補の最小比 (count_j / weight_j) を基準に、
    /// 各候補の count から `count_j * weight_i / weight_j` を引く。これにより
    /// 既存候補間の重み比を保ったまま、新規参加パスを 0 から開始できる。
    ///
    /// 候補が減っただけ (重みも既存候補の重みも不変) の場合は、残った候補の
    /// 回数をそのまま保持する。除外のたびに 0 へ戻すと、再参加を繰り返す
    /// 構成で重み比が壊れるためである。
    fn normalize(&mut self, candidates: &[&PathMetrics]) {
        let mut config: Vec<(PathId, u64)> = candidates
            .iter()
            .map(|path| (path.path_id, Self::weight(path)))
            .collect();
        config.sort_unstable_by_key(|(path_id, _)| path_id.0);
        if config == self.config {
            return;
        }
        let previous_config = core::mem::replace(&mut self.config, config);

        // 重みが変わった候補は、過去の選択回数を新しい重みへ比例縮小する。
        // 生 count のまま比べると、重みを下げた候補が履歴の分だけ連続選択
        // される。既存の重み比に換算した後、最小比を基準に 0 へ正規化する。
        let mut rescaled: Vec<(PathId, u64, u64)> = Vec::with_capacity(candidates.len());
        for path in candidates {
            let new_weight = Self::weight(path);
            let old_weight = previous_config
                .iter()
                .find(|(path_id, _)| *path_id == path.path_id)
                .map(|(_, weight)| *weight);
            let count = self.count(path.path_id);
            let count = match old_weight {
                Some(old_weight) if old_weight != new_weight => {
                    let scaled =
                        u128::from(count) * u128::from(new_weight) / u128::from(old_weight.max(1));
                    scaled.min(u128::from(u64::MAX)) as u64
                }
                Some(_) => count,
                None => 0,
            };
            rescaled.push((path.path_id, new_weight, count));
        }

        // 事前に存在した候補の最小比 (count_j / weight_j) を基準にする。
        let reference = rescaled
            .iter()
            .filter(|(path_id, _, _)| {
                previous_config
                    .iter()
                    .any(|(previous_id, _)| previous_id == path_id)
            })
            .map(|(_, weight, count)| (*weight, *count))
            .min_by(|(weight_a, count_a), (weight_b, count_b)| {
                (u128::from(*count_a) * u128::from(*weight_b))
                    .cmp(&(u128::from(*count_b) * u128::from(*weight_a)))
            });

        let counts: Vec<(PathId, u64)> = rescaled
            .into_iter()
            .map(|(path_id, weight, count)| {
                let Some((reference_weight, reference_count)) = reference else {
                    return (path_id, 0);
                };
                let subtract = (u128::from(reference_count) * u128::from(weight)
                    / u128::from(reference_weight.max(1)))
                .min(u128::from(count)) as u64;
                (path_id, count - subtract)
            })
            .collect();
        self.counts = counts;
    }

    /// パスの選択回数を 1 増やす
    fn record(&mut self, path_id: PathId) {
        if let Some((_, count)) = self.counts.iter_mut().find(|(id, _)| *id == path_id) {
            *count = count.saturating_add(1);
        } else {
            self.counts.push((path_id, 1));
        }
    }
}

/// 同率時の選択順を、最後に選んだパスの次から始まる巡回順で返す
fn tie_order(index: usize, last_index: Option<usize>, len: usize) -> usize {
    match last_index {
        Some(last) => {
            let distance = (index + len - last) % len;
            if distance == 0 { len } else { distance }
        }
        None => index,
    }
}

impl DataScheduler for WeightedRoundRobin {
    fn select_path(&mut self, ctx: &ScheduleCtx) -> Option<PathId> {
        let candidates = sender_candidates(ctx);
        self.normalize(&candidates);
        let mut best: Option<(usize, PathId, u128, u128)> = None;
        let last_index = self
            .last_selected
            .and_then(|last| candidates.iter().position(|path| path.path_id == last));
        for (index, path) in candidates.iter().enumerate() {
            let weight = u128::from(Self::weight(path));
            let count = u128::from(Self::count(self, path.path_id));
            // count / weight が最小のパスを選ぶ。浮動小数点を避けるため
            // 交差積 (count * 他 weight) で比較する。
            let order_a = tie_order(index, last_index, candidates.len());
            let is_better = match best {
                None => true,
                Some((best_index, _, best_count, best_weight)) => {
                    let order_b = tie_order(best_index, last_index, candidates.len());
                    let lhs = count * best_weight;
                    let rhs = best_count * weight;
                    // 同率なら最後に選んだパスの次から巡回する
                    lhs < rhs || (lhs == rhs && order_a < order_b)
                }
            };
            if is_better {
                best = Some((index, path.path_id, count, weight));
            }
        }
        let (_, path_id, _, _) = best?;
        self.last_selected = Some(path_id);
        self.record(path_id);
        Some(path_id)
    }
}
