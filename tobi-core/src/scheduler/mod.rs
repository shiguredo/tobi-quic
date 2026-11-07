// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Multipath スケジューラー
//!
//! draft-ietf-quic-multipath-21 はスケジューリングポリシーを規定しておらず実装依存としている。
//! 本モジュールは以下の 3 つの独立した trait を提供し、差し替え可能にする:
//!
//! - DataScheduler: 新規データの送信パス選択
//! - AckPathPolicy: PATH_ACK の送信パス選択
//! - RetransmissionPolicy: ロスト判定済みデータの再送パス選択
//!
//! 3 つの最適化目標が異なるため、同一ロジックに閉じ込めない:
//! - データ送信は throughput / arrival time を見る
//! - ACK は制御ループの短縮と RTT 推定の安定化を見る (draft Section 5.4)
//! - 再送は回復の速さ、再順序の悪化、スプリアス再送の抑制を見る
//!
//! CongestionControlFactory パターンに合わせ generics で静的ディスパッチする。

pub mod ack_path;
pub mod data;
pub mod retransmission;

use alloc::vec::Vec;
use core::fmt::Debug;

use crate::path::state::PathState;
use crate::path::{PathId, PathStatus};
use crate::time::{Duration, Timestamp};

// ---------------------------------------------------------------------------
// パスメトリクス (スケジューラーと PathController が共有する読み取り専用ビュー)
// ---------------------------------------------------------------------------

/// スケジューラーと PathController が参照するパスごとのメトリクス
///
/// Path 構造体から必要な情報を抽出した読み取り専用スナップショット。
/// スケジューラーの trait メソッドに渡す Context 型の構成要素であり、
/// `PathController` にも `PathControlCtx` 経由で渡す。パスの重複判定のように
/// 4-tuple を比較する判断は `remote_addr` を使う。
///
/// 全フィールドが公開されており、利用者が構造体リテラルで構築できる。フィールド
/// の追加は利用者の構築コードと網羅的なパターンマッチに対する破壊的変更になる。
#[derive(Debug, Clone)]
pub struct PathMetrics {
    /// パス ID
    pub path_id: PathId,
    /// パス状態 (Active/Pending/Validating/Abandoning/Abandoned)
    pub state: PathState,
    /// パスの利用状態 (Available/Backup)
    pub status: PathStatus,
    /// ピアが PATH_STATUS で通知したパスの利用希望
    ///
    /// draft-ietf-quic-multipath-21 Section 3.3: ピアは PATH_STATUS_AVAILABLE /
    /// PATH_STATUS_BACKUP で自身の希望を通知する。`None` は未通知 (未知) を表す。
    /// 送信パス選択では、ピアが Backup と指定したパスを、他に利用可能なパスが
    /// ある場合に候補から除外する。
    pub peer_status: Option<PathStatus>,
    /// 平滑化 RTT
    pub smoothed_rtt: Duration,
    /// 最小 RTT
    ///
    /// RTT サンプルを受信する前は 0 である (`RttEstimator::new` は
    /// `smoothed_rtt` に初期値を入れるが `min_rtt` は 0 のまま)。0 は未計測を
    /// 表すため、品質判定では `min_rtt` が 0 のパスを対象外にする。
    pub min_rtt: Duration,
    /// 最新 RTT サンプル
    pub latest_rtt: Duration,
    /// 送信可能バイト数 (輻輳ウィンドウ - 送信中バイト数)
    pub available_window: u64,
    /// 輻輳ウィンドウ (バイト)
    pub congestion_window: u64,
    /// 送信中バイト数
    pub bytes_in_flight: u64,
    /// 輻輳制限状態か (送信可能バイト数が 1 データグラム未満)
    pub is_congestion_limited: bool,
    /// Pacing rate (bytes/sec, None なら pacing なし)
    pub pacing_rate: Option<u64>,
    /// 輻輳制御の帯域推定 (bytes/sec)
    ///
    /// BBR などの配送レート推定を持つアルゴリズムだけが値を返す。
    /// スケジューラーは送信先の選択にこの値を使える。
    pub bandwidth_estimate: Option<u64>,
    /// パスごとの PMTU
    pub pmtu: u16,
    /// パスのリモートアドレス
    ///
    /// 4-tuple の一致判定に使う。観測外部アドレスだけでは、同じクライアント
    /// 外部アドレスから異なるサーバーアドレスへ接続するパスを区別できない。
    /// migration でリモートアドレスが変わると新しい値になる。ローカルアドレス
    /// だけが変わる移行では変わらない。
    pub remote_addr: core::net::SocketAddr,
    /// パスが利用可能か (Active 状態)
    pub is_usable: bool,
    /// PTO 発火回数
    pub pto_count: u32,
    /// 配送時間推定 (スケジューラー向け)
    ///
    /// smoothed_rtt とは別に、ACK パスの影響を考慮した推定値。
    /// ACK パス変更直後は smoothed_rtt にフォールバックする。
    pub delivery_time_estimate: Duration,
    /// ACK 返送パスが直近で変更されたか
    pub ack_path_changed: bool,
    /// このパスの到達性が最後に確認できた時刻
    ///
    /// パケットの受信または送信パケットへの ACK のうち新しい方。keep-alive の
    /// PING 送信だけではそのパスが実際に通っていることを示さないため、
    /// 昇格前の到達性確認の要否はこの時刻で判定する。`None` はパス作成後に
    /// 一度も到達性を確認できていないことを表す。
    pub last_confirmed_at: Option<Timestamp>,
    /// パス単位の累積統計
    pub stats: crate::stats::PathStats,
}

// ---------------------------------------------------------------------------
// データスケジューラーの Context
// ---------------------------------------------------------------------------

/// データ送信パス選択の入力
pub struct ScheduleCtx<'a> {
    /// 全パスのメトリクス
    pub paths: &'a [PathMetrics],
}

impl ScheduleCtx<'_> {
    /// ピアが Backup と指定していない利用可能なパスが他にあるかを返す
    ///
    /// draft-ietf-quic-multipath-21 Section 3.3: ピアが PATH_STATUS_BACKUP で
    /// 指定したパスには、他に利用可能なパスがある場合に送信しないことが推奨される。
    /// 全パスが Backup 指定の場合はローカルの判断に委ねられるため、除外しない。
    pub fn has_peer_preferred_path(&self) -> bool {
        // 代替として数えるのは、ローカルでも Available かつ送信可能なパスに限る。
        // ローカルが Backup のパスしか無い場合は、ピアの Backup 指定を理由に
        // 送信を止めず、ローカルの Backup フォールバックに委ねる。
        self.paths.iter().any(|p| {
            p.is_usable
                && p.status == PathStatus::Available
                && !p.is_congestion_limited
                && p.peer_status != Some(PathStatus::Backup)
        })
    }
}

impl PathMetrics {
    /// ピアの希望により送信対象から除外すべきかを返す
    ///
    /// `has_peer_preferred` が true (ピアが Backup と指定していない利用可能な
    /// パスが他にある) の場合だけ、ピアが Backup と指定したパスを除外する。
    pub fn excluded_by_peer_preference(&self, has_peer_preferred: bool) -> bool {
        has_peer_preferred && self.peer_status == Some(PathStatus::Backup)
    }
}

// ---------------------------------------------------------------------------
// ACK パスポリシーの Context
// ---------------------------------------------------------------------------

/// ACK 送信パス選択の入力
pub struct AckCtx<'a> {
    /// 全パスのメトリクス
    pub paths: &'a [PathMetrics],
}

// ---------------------------------------------------------------------------
// 再送ポリシーの Context
// ---------------------------------------------------------------------------

/// ロスト理由
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossReason {
    /// パケット閾値によるロスト判定 (RFC 9002 Section 6.1.1)
    PacketThreshold,
    /// 時間閾値によるロスト判定 (RFC 9002 Section 6.1.2)
    TimeThreshold,
    /// PTO 満了 (RFC 9002 Section 6.2)
    Pto,
}

/// 再送対象のフレーム分類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameClass {
    /// ストリームデータ
    StreamData,
    /// CRYPTO フレーム
    Crypto,
    /// 制御フレーム (MaxData, MaxStreamData 等)
    Control,
}

/// 再送の意思決定結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetxDecision {
    /// 元のパスで再送する
    SamePath,
    /// 指定パスにクロスパス再送する
    CrossPath(PathId),
    /// 元のパスに加え指定パスにも複製送信する
    Duplicate(PathId),
    /// 今は再送しない (usable パスなし、spurious リスク等)
    Defer,
}

/// 再送パス選択の入力
pub struct RetxCtx<'a> {
    /// 全パスのメトリクス
    pub paths: &'a [PathMetrics],
    /// ロスト理由
    pub loss_reason: LossReason,
    /// 再送対象のフレーム分類
    pub frame_class: FrameClass,
    /// 再送済み回数
    pub retransmission_count: u32,
}

// ---------------------------------------------------------------------------
// スケジューラー trait
// ---------------------------------------------------------------------------

/// データ送信パスの選択ポリシー
///
/// 送信機会ごとに新規データ/制御フレームの送信パスを選択する。
pub trait DataScheduler: Debug + Send {
    /// 送信パスを選択する
    ///
    /// 送信可能なパスがない場合は None を返す。
    fn select_path(&mut self, ctx: &ScheduleCtx) -> Option<PathId>;

    /// 1 回の送信機会に選択する最大パス数を返す
    ///
    /// 既定は 1 で、[`Self::select_paths`] を呼ぶ必要が無いことを表す。
    /// 冗長送信のように複数パスを選ぶスケジューラーだけが 2 以上を返す。
    fn max_paths(&self) -> usize {
        1
    }

    /// 1 回の送信機会に使用する送信パスを複数選択する
    ///
    /// `max_paths` は呼び出し側が許容する最大件数。冗長送信のように同じ
    /// データを複数パスへ送るスケジューラーだけが 2 件以上を返す。既定実装は
    /// [`Self::select_path`] の結果を 1 件だけ返すため、既存のスケジューラーは
    /// 挙動が変わらない。
    ///
    /// 返すパスは重複を含まない。送信可能なパスがない場合は空を返す。
    fn select_paths(&mut self, ctx: &ScheduleCtx, max_paths: usize) -> Vec<PathId> {
        if max_paths == 0 {
            return Vec::new();
        }
        self.select_path(ctx).into_iter().collect()
    }
}

/// PATH_ACK 送信パスの選択ポリシー
///
/// PATH_ACK は輻輳制御対象外 (draft-ietf-quic-multipath-21 Section 5.4)。
/// ACK パスの選択は RTT 推定に直接影響するため、データスケジューラーとは独立に設計する。
pub trait AckPathPolicy: Debug + Send {
    /// ACK 送信パスを選択する
    ///
    /// `acked_path`: ACK 対象のパス (データを受信したパス)
    fn select_ack_path(&mut self, ctx: &AckCtx, acked_path: PathId) -> Option<PathId>;
}

/// 再送パスの選択ポリシー
///
/// 新規データ送信の最適化 (throughput) ではなく、
/// 壊れた送信の修復 (回復の速さと副作用の少なさ) を扱う層。
/// draft-ietf-quic-multipath-21 Section 5.6:
/// same-path / cross-path / duplicate のいずれも許容されるが詳細は実装依存。
pub trait RetransmissionPolicy: Debug + Send {
    /// 再送の意思決定を行う
    ///
    /// `original_path`: 元のデータを送信したパス
    /// `candidates`: 再送候補のパス ID 一覧 (usable なパス)
    fn decide_retx(
        &mut self,
        ctx: &RetxCtx,
        original_path: PathId,
        candidates: &[PathId],
    ) -> RetxDecision;
}

// ---------------------------------------------------------------------------
// スケジューラーファクトリ
// ---------------------------------------------------------------------------

/// スケジューラーの組み合わせを定義するファクトリ trait
///
/// CongestionControlFactory パターンに合わせ、Connection の型パラメータを
/// 1 つにまとめる。
pub trait SchedulerFactory: Debug + Send {
    /// データスケジューラーの型
    type Data: DataScheduler;
    /// ACK パスポリシーの型
    type Ack: AckPathPolicy;
    /// 再送ポリシーの型
    type Retx: RetransmissionPolicy;

    /// スケジューラーの組み合わせを生成する
    fn create(&self) -> MultipathScheduler<Self::Data, Self::Ack, Self::Retx>;
}

/// 3 つのスケジューラーを束ねる構造体
#[derive(Debug)]
pub struct MultipathScheduler<D: DataScheduler, A: AckPathPolicy, R: RetransmissionPolicy> {
    /// データ送信パスの選択
    pub data: D,
    /// ACK 送信パスの選択
    pub ack: A,
    /// 再送パスの選択
    pub retx: R,
}

// ---------------------------------------------------------------------------
// デフォルトスケジューラーファクトリ
// ---------------------------------------------------------------------------

/// デフォルトのスケジューラーファクトリ
///
/// - DataScheduler: MinRtt (最短 RTT パスを選択)
/// - AckPathPolicy: ShortestPathAck (最短 RTT パスに ACK を返す)
/// - RetransmissionPolicy: SamePathThenCrossPath (PTO 超過時のみクロスパス再送)
#[derive(Debug, Clone)]
pub struct DefaultSchedulerFactory;

impl SchedulerFactory for DefaultSchedulerFactory {
    type Data = data::MinRtt;
    type Ack = ack_path::ShortestPathAck;
    type Retx = retransmission::SamePathThenCrossPath;

    fn create(&self) -> MultipathScheduler<Self::Data, Self::Ack, Self::Retx> {
        MultipathScheduler {
            data: data::MinRtt,
            ack: ack_path::ShortestPathAck,
            retx: retransmission::SamePathThenCrossPath::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// 実行時選択
// ---------------------------------------------------------------------------

/// データ送信パスのスケジューラー実装の選択
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSchedulerKind {
    /// 最短 RTT のパスを選択する (既定)
    MinRtt,
    /// 完了時間推定が最小のパスを選択する
    MinCompletionTime,
    /// 遅いパスへの送信を抑制する BLEST-like スケジューラー
    BlestLike,
    /// 利用可能なパスへ順番に振り分けるラウンドロビン
    RoundRobin,
    /// パスごとの帯域推定に基づき、推定遅延が最小のパスを選ぶ
    RateAware,
    /// 帯域推定に比例した重みでパスへ振り分ける
    WeightedRoundRobin,
    /// 同じデータを複数パスへ重複送信する冗長スケジューラー
    ///
    /// `max_paths` は 1 回の送信機会に重複送信する最大パス数 (1 以上)。
    /// 1 の場合は通常の単一パス送信と同じになる。接続側にも上限があり、
    /// 実際に複製するパス数はその小さい方になる。
    Redundant {
        /// 1 回の送信機会に使用する最大パス数
        max_paths: u8,
    },
}

impl DataSchedulerKind {
    /// ログや観測に使う名前を返す
    pub fn name(self) -> &'static str {
        match self {
            Self::MinRtt => "min_rtt",
            Self::MinCompletionTime => "min_completion_time",
            Self::BlestLike => "blest_like",
            Self::RoundRobin => "round_robin",
            Self::RateAware => "rate_aware",
            Self::WeightedRoundRobin => "weighted_round_robin",
            Self::Redundant { .. } => "redundant",
        }
    }
}

/// ACK 返送パスのポリシー実装の選択
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckPathPolicyKind {
    /// 最短 RTT のパスに ACK を返す (既定)
    ShortestPath,
    /// ACK 対象のデータを受信したパスに ACK を返す
    SamePath,
    /// ACK 返送パスを一定期間固定する
    Sticky,
}

impl AckPathPolicyKind {
    /// ログや観測に使う名前を返す
    pub fn name(self) -> &'static str {
        match self {
            Self::ShortestPath => "shortest_path",
            Self::SamePath => "same_path",
            Self::Sticky => "sticky",
        }
    }
}

/// 再送パスのポリシー実装の選択
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetransmissionPolicyKind {
    /// 元パスで再送し、PTO 超過時のみクロスパス再送する (既定)
    SamePathThenCrossPath,
    /// ロスト時は常に代替パスへクロスパス再送する
    CrossPathImmediate,
    /// 回復完了時間推定が最短のパスで再送する
    EarliestRecoveryPath,
    /// critical なデータのみ duplicate 再送を許可する
    SelectiveDuplicate,
}

impl RetransmissionPolicyKind {
    /// ログや観測に使う名前を返す
    pub fn name(self) -> &'static str {
        match self {
            Self::SamePathThenCrossPath => "same_path_then_cross_path",
            Self::CrossPathImmediate => "cross_path_immediate",
            Self::EarliestRecoveryPath => "earliest_recovery_path",
            Self::SelectiveDuplicate => "selective_duplicate",
        }
    }
}

/// スケジューラーの構成
///
/// データ送信パス選択 / ACK 返送パス / 再送パスの 3 つをまとめて指定する。
/// 既定値は `DefaultSchedulerFactory` と同じ組み合わせであり、
/// 既存の挙動を変えない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerConfig {
    /// データ送信パスの選択
    pub data: DataSchedulerKind,
    /// ACK 返送パスの選択
    pub ack: AckPathPolicyKind,
    /// 再送パスの選択
    pub retx: RetransmissionPolicyKind,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            data: DataSchedulerKind::MinRtt,
            ack: AckPathPolicyKind::ShortestPath,
            retx: RetransmissionPolicyKind::SamePathThenCrossPath,
        }
    }
}

impl SchedulerConfig {
    /// 構成に対応するスケジューラーファクトリを作る
    pub fn factory(self) -> SchedulerFactoryImpl {
        SchedulerFactoryImpl::new(self)
    }
}

/// 実行時に選択されたスケジューラーを生成するファクトリ
///
/// 各実装を enum で包み、`Connection` の型パラメータは
/// `SchedulerFactoryImpl` の 1 つに固定する。設定の組み合わせごとに
/// 型が増えないため、Sans I/O 層の静的ディスパッチを維持しつつ
/// 実行時に実装を選べる。
#[derive(Debug, Clone)]
pub struct SchedulerFactoryImpl {
    /// 選択された構成
    config: SchedulerConfig,
}

impl SchedulerFactoryImpl {
    /// 構成を指定してファクトリを作る
    pub fn new(config: SchedulerConfig) -> Self {
        Self { config }
    }

    /// 保持している構成を返す
    pub fn config(&self) -> SchedulerConfig {
        self.config
    }
}

impl SchedulerFactory for SchedulerFactoryImpl {
    type Data = DataSchedulerImpl;
    type Ack = AckPathPolicyImpl;
    type Retx = RetransmissionPolicyImpl;

    fn create(&self) -> MultipathScheduler<Self::Data, Self::Ack, Self::Retx> {
        let data = match self.config.data {
            DataSchedulerKind::MinRtt => DataSchedulerImpl::MinRtt(data::MinRtt),
            DataSchedulerKind::MinCompletionTime => {
                DataSchedulerImpl::MinCompletionTime(data::MinCompletionTime)
            }
            DataSchedulerKind::BlestLike => DataSchedulerImpl::BlestLike(data::BlestLike::new()),
            DataSchedulerKind::RoundRobin => DataSchedulerImpl::RoundRobin(data::RoundRobin::new()),
            DataSchedulerKind::RateAware => DataSchedulerImpl::RateAware(data::RateAware::new()),
            DataSchedulerKind::WeightedRoundRobin => {
                DataSchedulerImpl::WeightedRoundRobin(data::WeightedRoundRobin::new())
            }
            DataSchedulerKind::Redundant { max_paths } => {
                DataSchedulerImpl::Redundant(data::Redundant::new(usize::from(max_paths.max(1))))
            }
        };
        let ack = match self.config.ack {
            AckPathPolicyKind::ShortestPath => {
                AckPathPolicyImpl::ShortestPath(ack_path::ShortestPathAck)
            }
            AckPathPolicyKind::SamePath => AckPathPolicyImpl::SamePath(ack_path::SamePathAck),
            AckPathPolicyKind::Sticky => AckPathPolicyImpl::Sticky(ack_path::StickyAckPath::new()),
        };
        let retx = match self.config.retx {
            RetransmissionPolicyKind::SamePathThenCrossPath => {
                RetransmissionPolicyImpl::SamePathThenCrossPath(
                    retransmission::SamePathThenCrossPath::new(),
                )
            }
            RetransmissionPolicyKind::CrossPathImmediate => {
                RetransmissionPolicyImpl::CrossPathImmediate(retransmission::CrossPathImmediate)
            }
            RetransmissionPolicyKind::EarliestRecoveryPath => {
                RetransmissionPolicyImpl::EarliestRecoveryPath(
                    retransmission::EarliestRecoveryPath::new(),
                )
            }
            RetransmissionPolicyKind::SelectiveDuplicate => {
                RetransmissionPolicyImpl::SelectiveDuplicate(
                    retransmission::SelectiveDuplicate::new(),
                )
            }
        };
        MultipathScheduler { data, ack, retx }
    }
}

/// 選択されたデータスケジューラー (enum ディスパッチ)
#[derive(Debug, Clone)]
pub enum DataSchedulerImpl {
    /// 最短 RTT のパスを選択する
    MinRtt(data::MinRtt),
    /// 完了時間推定が最小のパスを選択する
    MinCompletionTime(data::MinCompletionTime),
    /// 遅いパスへの送信を抑制する
    BlestLike(data::BlestLike),
    /// 利用可能なパスへ順番に振り分ける
    RoundRobin(data::RoundRobin),
    /// 帯域推定に基づいて推定遅延が最小のパスを選ぶ
    RateAware(data::RateAware),
    /// 帯域推定に比例した重みでパスへ振り分ける
    WeightedRoundRobin(data::WeightedRoundRobin),
    /// 同じデータを複数パスへ重複送信する
    Redundant(data::Redundant),
}

impl DataScheduler for DataSchedulerImpl {
    fn select_path(&mut self, ctx: &ScheduleCtx) -> Option<PathId> {
        match self {
            Self::MinRtt(scheduler) => scheduler.select_path(ctx),
            Self::MinCompletionTime(scheduler) => scheduler.select_path(ctx),
            Self::BlestLike(scheduler) => scheduler.select_path(ctx),
            Self::RoundRobin(scheduler) => scheduler.select_path(ctx),
            Self::RateAware(scheduler) => scheduler.select_path(ctx),
            Self::WeightedRoundRobin(scheduler) => scheduler.select_path(ctx),
            Self::Redundant(scheduler) => scheduler.select_path(ctx),
        }
    }

    fn max_paths(&self) -> usize {
        match self {
            Self::MinRtt(scheduler) => scheduler.max_paths(),
            Self::MinCompletionTime(scheduler) => scheduler.max_paths(),
            Self::BlestLike(scheduler) => scheduler.max_paths(),
            Self::RoundRobin(scheduler) => scheduler.max_paths(),
            Self::RateAware(scheduler) => scheduler.max_paths(),
            Self::WeightedRoundRobin(scheduler) => scheduler.max_paths(),
            Self::Redundant(scheduler) => scheduler.max_paths(),
        }
    }

    fn select_paths(&mut self, ctx: &ScheduleCtx, max_paths: usize) -> Vec<PathId> {
        match self {
            // 単一パスを選ぶ実装は既定実装のまま 1 件を返す
            Self::MinRtt(scheduler) => scheduler.select_paths(ctx, max_paths),
            Self::MinCompletionTime(scheduler) => scheduler.select_paths(ctx, max_paths),
            Self::BlestLike(scheduler) => scheduler.select_paths(ctx, max_paths),
            Self::RoundRobin(scheduler) => scheduler.select_paths(ctx, max_paths),
            Self::RateAware(scheduler) => scheduler.select_paths(ctx, max_paths),
            Self::WeightedRoundRobin(scheduler) => scheduler.select_paths(ctx, max_paths),
            Self::Redundant(scheduler) => scheduler.select_paths(ctx, max_paths),
        }
    }
}

/// 選択された ACK パスポリシー (enum ディスパッチ)
#[derive(Debug, Clone)]
pub enum AckPathPolicyImpl {
    /// 最短 RTT のパスに ACK を返す
    ShortestPath(ack_path::ShortestPathAck),
    /// ACK 対象のデータを受信したパスに返す
    SamePath(ack_path::SamePathAck),
    /// ACK 返送パスを固定する
    Sticky(ack_path::StickyAckPath),
}

impl AckPathPolicy for AckPathPolicyImpl {
    fn select_ack_path(&mut self, ctx: &AckCtx, acked_path: PathId) -> Option<PathId> {
        match self {
            Self::ShortestPath(policy) => policy.select_ack_path(ctx, acked_path),
            Self::SamePath(policy) => policy.select_ack_path(ctx, acked_path),
            Self::Sticky(policy) => policy.select_ack_path(ctx, acked_path),
        }
    }
}

/// 選択された再送ポリシー (enum ディスパッチ)
#[derive(Debug, Clone)]
pub enum RetransmissionPolicyImpl {
    /// 元パスで再送し、PTO 超過時のみクロスパス再送する
    SamePathThenCrossPath(retransmission::SamePathThenCrossPath),
    /// ロスト時は常に代替パスへクロスパス再送する
    CrossPathImmediate(retransmission::CrossPathImmediate),
    /// 回復完了時間推定が最短のパスで再送する
    EarliestRecoveryPath(retransmission::EarliestRecoveryPath),
    /// critical なデータのみ duplicate 再送を許可する
    SelectiveDuplicate(retransmission::SelectiveDuplicate),
}

impl RetransmissionPolicy for RetransmissionPolicyImpl {
    fn decide_retx(
        &mut self,
        ctx: &RetxCtx,
        original_path: PathId,
        candidates: &[PathId],
    ) -> RetxDecision {
        match self {
            Self::SamePathThenCrossPath(policy) => {
                policy.decide_retx(ctx, original_path, candidates)
            }
            Self::CrossPathImmediate(policy) => policy.decide_retx(ctx, original_path, candidates),
            Self::EarliestRecoveryPath(policy) => {
                policy.decide_retx(ctx, original_path, candidates)
            }
            Self::SelectiveDuplicate(policy) => policy.decide_retx(ctx, original_path, candidates),
        }
    }
}
