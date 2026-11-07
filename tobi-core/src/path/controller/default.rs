// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! DefaultPathController の実装
//!
//! MultipathPolicy に基づいてパスの開閉を自動判断するデフォルト実装。

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::SocketAddr;

use hashbrown::{HashMap, HashSet};

use super::{PathAction, PathControlCtx, PathControlEvent, PathController, PathControllerFactory};
use crate::path::PathId;
use crate::path::PathStatus;
use crate::path::policy::{MultipathMode, MultipathPolicy};
use crate::path::state::PathState;
use crate::scheduler::PathMetrics;
use crate::time::Duration;

/// デフォルトの PathController 実装
///
/// MultipathPolicy に基づいてパスの開閉を自動判断する。
///
/// 待機パス (Backup) の扱い:
///
/// - `MultipathMode::Handover` では、検証済みで待機に回ったパスに keep-alive を
///   設定し、PING で到達性を維持する。能動利用へ昇格する前にしばらく受信が無い
///   パスは PATH_CHALLENGE で到達性を確認してから切り替える。切り替えは RTT の
///   優劣で決める。
/// - `MultipathMode::Backup` では、最初に観測した利用可能なパスをプライマリとして
///   固定し、待機パスの RTT が優れていても切り替えない。プライマリが使えなく
///   なったときだけ、検証済みの待機パスから代替を選ぶ (待機パスが無ければ利用可能
///   なパスを使う)。代替は keep-alive 間隔以上到達性を確認できていない場合だけ
///   PATH_CHALLENGE で確認してから切り替える。待機パスは keep-alive で到達性を
///   維持する。
/// - `MultipathMode::Aggregate` では全パスを常時利用するため、パス単位の
///   keep-alive は既定で無効にする。品質が最良値の 5 倍超まで劣化したパスは
///   Backup へ降格して keep-alive を有効にし、最良値の 4 倍以下へ回復したら
///   Available へ戻して keep-alive を無効にする。降格で利用可能なパスが
///   無くならないよう、最良に近い 1 本は Available のまま残す。
#[derive(Debug)]
pub struct DefaultPathController {
    /// ポリシー設定
    policy: MultipathPolicy,
    /// インターフェース名 → (ローカルアドレス, PathId) のマッピング
    interface_paths: HashMap<String, (SocketAddr, Option<PathId>)>,
    /// インターフェース名 → 追跡アドレス以外の利用可能なアドレス
    ///
    /// 追跡中のアドレスが消えたときに、同じインターフェースに残っている
    /// アドレスから代替パスを開くために保持する。
    interface_available: HashMap<String, Vec<SocketAddr>>,
    /// PathId → インターフェース名のマッピング (逆引き用)
    path_interfaces: HashMap<PathId, String>,
    /// 観測された外部アドレスのマッピング (PathId → 外部アドレス)
    /// 重複パス検知に使用する
    observed_addresses: HashMap<PathId, SocketAddr>,
    /// 到達性確認中 (PATH_CHALLENGE 送信済み) の昇格候補
    ///
    /// PATH_RESPONSE を受信するまで昇格させない。パスが消えた場合は
    /// メトリクス更新時に掃除する。
    pending_promotions: HashSet<PathId>,
    /// `MultipathMode::Backup` で固定しているプライマリ
    ///
    /// 最初に観測した利用可能なパスを記録し、使えなくなるまで変更しない。
    backup_primary: Option<PathId>,
}

impl DefaultPathController {
    /// 新しい DefaultPathController を作成する
    pub fn new(policy: MultipathPolicy) -> Self {
        Self {
            policy,
            interface_paths: HashMap::new(),
            interface_available: HashMap::new(),
            path_interfaces: HashMap::new(),
            observed_addresses: HashMap::new(),
            pending_promotions: HashSet::new(),
            backup_primary: None,
        }
    }

    /// インターフェースがフィルタを通過するか判定する
    fn accepts_interface(&self, name: &str) -> bool {
        self.policy.interface_filter.accepts(name)
    }

    /// 候補アドレスが初期パスのリモートアドレスと同じファミリか判定する
    fn candidate_family_matches(ctx: &PathControlCtx, addr: SocketAddr) -> bool {
        ctx.path_metrics
            .iter()
            .find(|metrics| metrics.path_id == PathId::INITIAL)
            .is_none_or(|metrics| metrics.remote_addr.is_ipv4() == addr.is_ipv4())
    }

    /// 現在のパス数が上限に達しているか判定する
    fn is_at_max_paths(&self, ctx: &PathControlCtx) -> bool {
        ctx.current_path_count >= self.policy.max_paths
    }

    /// Active なパスの PathId を返す
    fn active_path_ids(&self, ctx: &PathControlCtx) -> Vec<PathId> {
        ctx.path_metrics
            .iter()
            .filter(|m| m.is_usable && m.status == PathStatus::Available)
            .map(|m| m.path_id)
            .collect()
    }

    /// 最良のパス (最小 smoothed_rtt) の PathId を返す
    fn best_path_id(&self, ctx: &PathControlCtx) -> Option<PathId> {
        ctx.path_metrics
            .iter()
            .filter(|m| m.is_usable)
            .min_by_key(|m| m.smoothed_rtt)
            .map(|m| m.path_id)
    }

    /// 同じ 4-tuple を観測した別のパスがあるか判定する (重複パス検知)
    ///
    /// `path_id` 自身のエントリは重複判定から除外する。同じパスの同じ外部
    /// アドレスの再通知は重複ではない (draft-ietf-quic-address-discovery-01
    /// Section 4.1)。NAT リバインディングで既存パスのリモートアドレスが
    /// 変わると、ピアは同じパスで OBSERVED_ADDRESS を送り直す
    /// (同 draft Section 5)。同じパスの通知は観測値の更新として扱う。
    ///
    /// 観測外部アドレスだけでは同一のネットワークパスを判定できない。同じ
    /// クライアント外部アドレスから異なるサーバーアドレスへ接続した 2 パスは
    /// どちらも同じ外部アドレスを観測するが、別のパスである。そのため観測外部
    /// アドレスとリモートアドレスの両方が一致する場合だけ重複と判断する。
    ///
    /// draft-ietf-quic-multipath-21 Section 5.2 は同一 4-tuple の複数パスが
    /// 冗長になり得るとするが、どちらかを閉じることは要求しない。ここでの
    /// 廃棄は既定 controller の選択であり、draft の必須動作ではない。
    ///
    /// 4-tuple の情報が揃わない場合は重複と断定せず、パスを維持する。
    ///
    /// 保存している観測外部アドレスは最後に受信した OBSERVED_ADDRESS の値で
    /// あり、観測時点のリモートアドレスは保持していない。観測後に migration で
    /// リモートアドレスが変わると、次の OBSERVED_ADDRESS を受信するまでは
    /// 古い観測値と新しい宛先の組み合わせで判定することになる。
    fn has_duplicate_network_path(
        &self,
        path_id: PathId,
        addr: &SocketAddr,
        ctx: &PathControlCtx,
    ) -> bool {
        let Some(current) = ctx.path_metrics.iter().find(|m| m.path_id == path_id) else {
            return false;
        };
        self.observed_addresses.iter().any(|(id, observed)| {
            *id != path_id
                && observed == addr
                && ctx
                    .path_metrics
                    .iter()
                    .any(|other| other.path_id == *id && other.remote_addr == current.remote_addr)
        })
    }

    /// NetworkInterfaceUp イベントを処理する
    fn on_interface_up(
        &mut self,
        name: &str,
        addr: SocketAddr,
        ctx: &PathControlCtx,
    ) -> Vec<PathAction> {
        if !self.accepts_interface(name) {
            return Vec::new();
        }

        // 既にこのインターフェースのパスが存在する場合は開設せず、追跡
        // アドレスと異なるアドレスを残存候補として保存する。
        if let Some((tracked_addr, _)) = self.interface_paths.get(name) {
            let available = self
                .interface_available
                .entry(name.to_string())
                .or_default();
            if *tracked_addr != addr
                && Self::candidate_family_matches(ctx, addr)
                && !available.contains(&addr)
            {
                available.push(addr);
            }
            return Vec::new();
        }

        if self.is_at_max_paths(ctx) {
            return Vec::new();
        }

        // リモートアドレスは初期パスのものを使う。PathMetrics の
        // `remote_addr` は参照できるが、OpenPath のリモートアドレスは
        // Connection のアクション実行層が初期パスの値で解決するため、ここでは
        // ダミー (ポート 0) を渡す。初期パスが無い接続では開設しない。
        if !ctx
            .path_metrics
            .iter()
            .any(|m| m.path_id == PathId::INITIAL)
        {
            return Vec::new();
        }

        // インターフェースを記録する (PathId は PathOpenSucceeded で設定される)
        self.interface_paths.insert(name.to_string(), (addr, None));

        // NOTE: 開設直後のパスを Handover / Backup モードで Backup として
        // 扱うかは PathValidated で決める。PathOpenSucceeded の時点でパス ID は
        // 分かるが、開設結果のハンドラはアクションを返せない契約であり、
        // 開設直後のパスはまだ利用可能ではないため、検証完了後に設定する。

        vec![PathAction::OpenPath {
            local_addr: addr,
            // リモートアドレスはダミー (ポート 0)。Connection のアクション実行層が
            // 初期パスのリモートアドレスを継承する
            remote_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
        }]
    }

    /// NetworkInterfaceDown イベントを処理する
    ///
    /// 記録済みのローカルアドレスと一致する場合だけ、関連付いたパスを
    /// 廃棄する。`NetworkMonitor` は 1 つのインターフェースが持つアドレスごとに
    /// Up / Down を通知するため、追跡していないアドレスの Down で追跡中の
    /// パスを閉じてはならない。
    fn on_interface_down(
        &mut self,
        name: &str,
        addr: SocketAddr,
        ctx: &PathControlCtx,
    ) -> Vec<PathAction> {
        self.on_interface_down_impl(name, addr, ctx, true)
    }

    /// NetworkInterfaceDown の本体
    ///
    /// `open_residual` が false のときは残存候補を開かない。
    /// `NetworkAddressChanged` は新しいアドレスを優先するため、旧アドレスの
    /// 廃棄だけを行ってから新アドレスの開設を評価する。
    fn on_interface_down_impl(
        &mut self,
        name: &str,
        addr: SocketAddr,
        ctx: &PathControlCtx,
        open_residual: bool,
    ) -> Vec<PathAction> {
        // 追跡エントリが無くても、消えたアドレスを残存候補から外す
        if let Some(available) = self.interface_available.get_mut(name) {
            available.retain(|available| *available != addr);
            if available.is_empty() {
                self.interface_available.remove(name);
            }
        }
        let Some((tracked_addr, associated)) = self.interface_paths.get(name) else {
            return Vec::new();
        };
        // 同じインターフェース名でもアドレスが異なる Down は、追跡中の
        // パスとは無関係である。エントリを保持し、残存候補からだけ外す。
        if *tracked_addr != addr {
            if let Some(available) = self.interface_available.get_mut(name) {
                available.retain(|available| *available != addr);
            }
            if self
                .interface_available
                .get(name)
                .is_some_and(Vec::is_empty)
            {
                self.interface_available.remove(name);
            }
            return Vec::new();
        }
        let associated = *associated;
        self.interface_paths.remove(name);
        let available = self.interface_available.remove(name).unwrap_or_default();
        let Some(path_id) = associated else {
            return Vec::new();
        };
        self.path_interfaces.remove(&path_id);
        self.observed_addresses.remove(&path_id);

        let mut actions = vec![PathAction::AbandonPath {
            path_id,
            error_code: 0,
        }];

        // Handover では Active パスが落ちた場合に Backup を昇格する。Backup は
        // プライマリの選出規則 (RTT 順と PathId 順) を守るため、ここでは昇格せず
        // PathAbandoned の再評価に委ねる。
        if self.policy.mode == MultipathMode::Handover {
            let active_paths = self.active_path_ids(ctx);
            // 廃棄するパスを除外して Active がなくなるか判定する
            let remaining_active: Vec<_> =
                active_paths.iter().filter(|&&id| id != path_id).collect();

            if remaining_active.is_empty() {
                // Backup パスを Active に昇格する
                if let Some(backup) = ctx
                    .path_metrics
                    .iter()
                    .filter(|m| {
                        m.path_id != path_id && m.is_usable && m.status == PathStatus::Backup
                    })
                    .min_by_key(|m| m.smoothed_rtt)
                {
                    actions.push(PathAction::SetStatus {
                        path_id: backup.path_id,
                        status: PathStatus::Available,
                    });
                }
            }
        }

        // 残存アドレスがあれば、廃棄で空いた分を考慮して代替パスを開く。
        // `current_path_count` は廃棄前のパスを含むため、AbandonPath の分を
        // 差し引いて max_paths を判定する (AddressChanged と同じ補正)。
        if !open_residual {
            if !available.is_empty() {
                self.interface_available.insert(name.to_string(), available);
            }
            return actions;
        }
        let candidate = available
            .iter()
            .copied()
            .find(|addr| Self::candidate_family_matches(ctx, *addr));
        if let Some(candidate) = candidate {
            let abandoned = actions
                .iter()
                .filter(|action| matches!(action, PathAction::AbandonPath { .. }))
                .count();
            let open_ctx = PathControlCtx {
                path_metrics: ctx.path_metrics,
                current_path_count: ctx.current_path_count.saturating_sub(abandoned),
                policy: ctx.policy,
                now: ctx.now,
                keep_alive_interval: ctx.keep_alive_interval,
            };
            let has_initial_path = ctx
                .path_metrics
                .iter()
                .any(|m| m.path_id == PathId::INITIAL);
            if !self.is_at_max_paths(&open_ctx) && has_initial_path {
                let mut remaining = available;
                remaining.remove(0);
                if !remaining.is_empty() {
                    self.interface_available.insert(name.to_string(), remaining);
                }
                self.interface_paths
                    .insert(name.to_string(), (candidate, None));
                actions.push(PathAction::OpenPath {
                    local_addr: candidate,
                    remote_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
                });
            } else {
                // 上限や初期パス不在で今は開けない場合も候補を保持し、
                // 次の Down / AddressChanged で再評価できるようにする。
                self.interface_available.insert(name.to_string(), available);
            }
        }

        actions
    }

    /// ローカルアドレスが一致する未関連付けのエントリを 1 件返す
    ///
    /// `OpenPath` にはインターフェース名が含まれないため、同じローカル
    /// アドレスを持つ未関連付けのエントリが複数ある場合は 1 件だけを対象に
    /// する。複数一致は通常起こらないが、起きた場合でも 1 つのパス ID を
    /// 複数のインターフェースへ割り当てない。
    fn find_unassociated(&self, local_addr: SocketAddr) -> Option<String> {
        self.interface_paths
            .iter()
            .find(|(_, (addr, associated))| *addr == local_addr && associated.is_none())
            .map(|(name, _)| name.clone())
    }

    /// PathOpenSucceeded イベントを処理する
    ///
    /// ローカルアドレスが一致する未関連付けのエントリへパス ID を設定し、
    /// 逆引きも登録する。
    fn on_path_open_succeeded(&mut self, path_id: PathId, local_addr: SocketAddr) {
        let Some(name) = self.find_unassociated(local_addr) else {
            return;
        };
        let entry = self
            .interface_paths
            .get_mut(&name)
            .expect("entry found by find_unassociated");
        entry.1 = Some(path_id);
        self.path_interfaces.insert(path_id, name);
    }

    /// PathOpenFailed イベントを処理する
    ///
    /// ローカルアドレスが一致する未関連付けのエントリを 1 件だけ取り消し、
    /// 次の `NetworkInterfaceUp` で再試行できるようにする。
    fn on_path_open_failed(&mut self, local_addr: SocketAddr) {
        if let Some(name) = self.find_unassociated(local_addr) {
            self.interface_paths.remove(&name);
            if let Some(available) = self.interface_available.get_mut(&name) {
                available.retain(|addr| *addr != local_addr);
            }
        }
    }

    /// PathAbandoned イベントを処理する
    ///
    /// 廃棄されたパスに関連する対応付けを破棄する。同じイベントが複数回
    /// 届いても安全なように、既に消えている場合は何もしない。
    fn on_path_abandoned(&mut self, path_id: PathId) {
        // 逆引きのインターフェース名に対応する「インターフェース名 → パス ID」
        // の記録が同じ `path_id` を指している場合だけ削除する。同じ
        // インターフェースに新しいパスが関連付いている場合に、その対応付けを
        // 消さないため。
        if let Some(name) = self.path_interfaces.remove(&path_id)
            && self
                .interface_paths
                .get(&name)
                .is_some_and(|(_, associated)| *associated == Some(path_id))
        {
            self.interface_paths.remove(&name);
        }
        self.observed_addresses.remove(&path_id);
        self.pending_promotions.remove(&path_id);
        // `backup_primary` は残す。失効したプライマリはメトリクス上で使えなく
        // なるため、PathAbandoned の再評価または次のメトリクス更新で代替が選ばれる。
    }

    /// PathValidated イベントを処理する
    fn on_path_validated(&mut self, path_id: PathId, ctx: &PathControlCtx) -> Vec<PathAction> {
        // 昇格前の到達性確認が完了したパスは、待機していた昇格を実行する。
        if self.pending_promotions.remove(&path_id) {
            match self.policy.mode {
                MultipathMode::Handover => {
                    // 降格する現在の Active パスは待機に戻るため keep-alive を
                    // 設定する。
                    let active_paths = self.active_path_ids(ctx);
                    let mut actions = Vec::new();
                    if let Some(&current_active) = active_paths.first()
                        && current_active != path_id
                    {
                        actions.push(PathAction::SetStatus {
                            path_id: current_active,
                            status: PathStatus::Backup,
                        });
                        actions.push(PathAction::SetKeepAlive {
                            path_id: current_active,
                            enabled: true,
                        });
                    }
                    actions.push(PathAction::SetStatus {
                        path_id,
                        status: PathStatus::Available,
                    });
                    return actions;
                }
                MultipathMode::Backup => {
                    // 選出候補が変わっている場合は昇格しない (古い応答で
                    // 現在のプライマリを降格しないため)。
                    if self.select_backup_primary(ctx) != Some(path_id) {
                        return Vec::new();
                    }
                    // 到達性を確認できた候補を新しいプライマリとして固定する。
                    self.backup_primary = Some(path_id);
                    self.pending_promotions.clear();
                    return self.backup_primary_actions(ctx, path_id);
                }
                MultipathMode::Aggregate => {
                    // 帯域集約では既存の利用可能パスを降格せず、確認できた
                    // 候補だけを Available へ戻す。
                    return vec![
                        PathAction::SetStatus {
                            path_id,
                            status: PathStatus::Available,
                        },
                        PathAction::SetKeepAlive {
                            path_id,
                            enabled: false,
                        },
                    ];
                }
            }
        }

        match self.policy.mode {
            MultipathMode::Handover => {
                // 既に利用可能なパスがあれば、検証されたパスは Backup として待機させる。
                // 検証直後のパス自身も利用可能としてメトリクスに現れるため、
                // 自分以外の利用可能なパスの有無で判定する。
                let has_other_active = self
                    .active_path_ids(ctx)
                    .into_iter()
                    .any(|active_id| active_id != path_id);
                if has_other_active {
                    return vec![
                        PathAction::SetStatus {
                            path_id,
                            status: PathStatus::Backup,
                        },
                        // 待機パスは middlebox のタイムアウトで失わないよう
                        // keep-alive で到達性を維持する
                        // (draft-ietf-quic-multipath-21 Section 5.9)。
                        PathAction::SetKeepAlive {
                            path_id,
                            enabled: true,
                        },
                    ];
                }
                Vec::new()
            }
            MultipathMode::Backup => {
                // 選出結果がこのパスならプライマリとして固定する。選出は
                // 失効した旧プライマリと待機パスの RTT を比較して決まるため、
                // 検証されただけのパスを無条件にプライマリにしない。
                if self.select_backup_primary(ctx) == Some(path_id) {
                    self.backup_primary = Some(path_id);
                    return self.backup_primary_actions(ctx, path_id);
                }
                // 他の Available が無い場合は、唯一の Available パスを
                // そのまま維持する。プライマリの決定は次の判断に委ねる。
                // 既に Backup のパスなら keep-alive を維持する。
                let has_other_available = ctx.path_metrics.iter().any(|m| {
                    m.is_usable && m.path_id != path_id && m.status == PathStatus::Available
                });
                let path_available = ctx
                    .path_metrics
                    .iter()
                    .any(|m| m.path_id == path_id && m.status == PathStatus::Available);
                if !has_other_available {
                    return vec![PathAction::SetKeepAlive {
                        path_id,
                        enabled: !path_available,
                    }];
                }
                // プライマリを固定するため、検証直後のパスは待機させる。
                // 既に Backup なら状態変更を再送しない。
                let mut actions = Vec::new();
                if path_available {
                    actions.push(PathAction::SetStatus {
                        path_id,
                        status: PathStatus::Backup,
                    });
                }
                actions.push(PathAction::SetKeepAlive {
                    path_id,
                    enabled: true,
                });
                actions
            }
            MultipathMode::Aggregate => {
                // 降格中のパスは到達性を維持するため keep-alive を有効のままにする。
                // migration 後の再検証のように、降格中でも PathValidated は届く。
                let demoted = ctx
                    .path_metrics
                    .iter()
                    .any(|m| m.path_id == path_id && m.status == PathStatus::Backup);
                if demoted {
                    return vec![PathAction::SetKeepAlive {
                        path_id,
                        enabled: true,
                    }];
                }
                // 利用中のパスは全パスで同時送信するため、パス単位の keep-alive は
                // 既定で無効にする。接続の既定値より優先し、不要な PING の
                // オーバーヘッドを避ける。
                vec![PathAction::SetKeepAlive {
                    path_id,
                    enabled: false,
                }]
            }
        }
    }

    /// 昇格候補の到達性を確認する必要があるか判定する
    ///
    /// 呼び出し側は、他に利用可能なパス (`PathStatus::Available` のパス) が
    /// 存在する場合にだけこの判定を使う。他に利用可能なパスが無い場合は、
    /// 確認の往復を待たずに切り替える (draft-ietf-quic-multipath-21 Section 5.9
    /// の "if there are still other paths that are currently usable")。
    fn needs_reachability_confirmation(
        &self,
        ctx: &PathControlCtx,
        candidate: &PathMetrics,
    ) -> bool {
        // keep-alive の間隔が無い場合は「しばらく使っていない」を判定する基準が
        // 無いため、確認を挟まずに切り替える。keep-alive 間隔を設定した接続では、
        // その間隔内に到達性の確認が続いているかを基準にできる。
        let Some(interval) = ctx.keep_alive_interval else {
            return false;
        };
        match candidate.last_confirmed_at {
            None => true,
            Some(last_confirmed) => ctx.now.saturating_duration_since(last_confirmed) >= interval,
        }
    }

    /// Handover モードの昇格判断を組み立てる
    fn handover_actions(&mut self, ctx: &PathControlCtx) -> Vec<PathAction> {
        self.retain_live_promotions(ctx);

        let active_paths = self.active_path_ids(ctx);
        let best = self.best_path_id(ctx);

        // 昇格候補が変わったら、前の候補の確認待ちは破棄する
        if let Some(best_id) = best {
            self.pending_promotions.retain(|id| *id == best_id);
        }

        let (Some(best_id), Some(&current_active)) = (best, active_paths.first()) else {
            return Vec::new();
        };
        if best_id == current_active {
            return Vec::new();
        }
        // 到達性確認の応答待ちなら、PATH_RESPONSE が届くまで切り替えない
        if self.pending_promotions.contains(&best_id) {
            return Vec::new();
        }
        let Some(candidate) = ctx.path_metrics.iter().find(|m| m.path_id == best_id) else {
            return Vec::new();
        };
        if self.needs_reachability_confirmation(ctx, candidate) {
            self.pending_promotions.insert(best_id);
            return vec![PathAction::ProbePath { path_id: best_id }];
        }

        // 昇格する。降格するパスは待機に戻るため keep-alive を設定する。
        vec![
            PathAction::SetStatus {
                path_id: current_active,
                status: PathStatus::Backup,
            },
            PathAction::SetKeepAlive {
                path_id: current_active,
                enabled: true,
            },
            PathAction::SetStatus {
                path_id: best_id,
                status: PathStatus::Available,
            },
        ]
    }

    /// 消えた・使えなくなったパスの昇格待ちを掃除する
    fn retain_live_promotions(&mut self, ctx: &PathControlCtx) {
        self.pending_promotions.retain(|id| {
            ctx.path_metrics
                .iter()
                .any(|m| m.path_id == *id && m.is_usable)
        });
    }

    /// プライマリとして残すパスを決める
    ///
    /// 現在のプライマリが使えるうちは変更しない。初回の選出では、利用可能な
    /// パスのうち PathId が最小のものをプライマリにする (最初に観測した
    /// Available パスを維持する)。利用可能なパスが無ければ、検証済みの待機
    /// パスから RTT の小さいものを選ぶ。
    ///
    /// プライマリが失効している場合は、検証済みの待機パスから `smoothed_rtt` の
    /// 小さいものを選び、同値なら PathId の小さいものを選ぶ。RTT を計測していない
    /// (`min_rtt` が 0 の) パスしか無ければ PathId が最小のものを選ぶ。待機パスが
    /// 無ければ、利用可能なパスをそのまま使う。
    ///
    /// プライマリの失効は「パスが消えた」「使えなくなった (`is_usable` が false)」
    /// 「パス廃棄通知が届いた」であり、cwnd や pacing による一時的な送信待ちは
    /// 失効としない。
    fn select_backup_primary(&self, ctx: &PathControlCtx) -> Option<PathId> {
        // 失効したプライマリの ID は残るため、使えるかどうかで失効を判定する
        let primary_invalid = self.backup_primary.is_some_and(|primary| {
            !ctx.path_metrics
                .iter()
                .any(|m| m.path_id == primary && m.is_usable)
        });
        if let Some(primary) = self.backup_primary
            && !primary_invalid
        {
            return Some(primary);
        }

        let available = ctx
            .path_metrics
            .iter()
            .filter(|m| m.is_usable && m.status == PathStatus::Available)
            .map(|m| m.path_id)
            .min();
        // 計測済みを優先し、計測済み同士では `smoothed_rtt` の小さい順、
        // 同値なら PathId の小さい順にする。計測済みが無ければ PathId の
        // 小さい順にする。
        let standby = || {
            ctx.path_metrics
                .iter()
                .filter(|m| m.is_usable && m.status == PathStatus::Backup)
                .min_by(|a, b| {
                    let a_measured = a.min_rtt > Duration::ZERO;
                    let b_measured = b.min_rtt > Duration::ZERO;
                    match (a_measured, b_measured) {
                        (true, false) => core::cmp::Ordering::Less,
                        (false, true) => core::cmp::Ordering::Greater,
                        (true, true) => a
                            .smoothed_rtt
                            .cmp(&b.smoothed_rtt)
                            .then_with(|| a.path_id.cmp(&b.path_id)),
                        (false, false) => a.path_id.cmp(&b.path_id),
                    }
                })
                .map(|m| m.path_id)
        };

        if primary_invalid {
            // 失効時は検証済みの待機パスを優先する
            if let Some(standby) = standby() {
                return Some(standby);
            }
            return available;
        }

        // 初回の選出。利用可能なパスを優先し、無ければ検証済みの待機パスを使う。
        available.or_else(standby)
    }

    /// プライマリ以外の Available を待機へ戻す
    ///
    /// Available のままのパスを Backup + keep-alive にする
    /// (draft-ietf-quic-multipath-21 Section 3.3 の再通知。draft のため将来
    /// 変更される可能性がある)。Abandoning / Abandoned のパスは廃棄中・
    /// 廃棄済みのため対象外にする。`include_unusable` が真なら、使用できなく
    /// なったがまだ廃棄中ではない Available パスも対象にする。
    fn demote_available_others(
        &self,
        ctx: &PathControlCtx,
        primary: PathId,
        include_unusable: bool,
    ) -> Vec<PathAction> {
        let mut actions = Vec::new();
        for m in ctx.path_metrics.iter() {
            if m.path_id == primary
                || m.status != PathStatus::Available
                || (!include_unusable && !m.is_usable)
                || matches!(m.state, PathState::Abandoning | PathState::Abandoned)
            {
                continue;
            }
            actions.push(PathAction::SetStatus {
                path_id: m.path_id,
                status: PathStatus::Backup,
            });
            actions.push(PathAction::SetKeepAlive {
                path_id: m.path_id,
                enabled: true,
            });
        }
        actions
    }

    /// プライマリを Available にし、他の Available を待機へ戻すアクションを組み立てる
    ///
    /// [`Self::demote_available_others`] でプライマリ以外を待機へ戻し、プライマリが
    /// Available でなければ Available にする。keep-alive は常に無効にする。
    fn backup_primary_actions(&self, ctx: &PathControlCtx, primary: PathId) -> Vec<PathAction> {
        let mut actions = self.demote_available_others(ctx, primary, true);
        let primary_available = ctx
            .path_metrics
            .iter()
            .any(|m| m.path_id == primary && m.status == PathStatus::Available);
        if !primary_available {
            actions.push(PathAction::SetStatus {
                path_id: primary,
                status: PathStatus::Available,
            });
        }
        actions.push(PathAction::SetKeepAlive {
            path_id: primary,
            enabled: false,
        });
        actions
    }

    /// `MultipathMode::Backup` のプライマリ維持の判断を組み立てる
    ///
    /// プライマリを固定し、正常なうちは RTT の優劣で切り替えない。プライマリが
    /// 使えなくなったときだけ、検証済みの待機パスから代替を選んで昇格する。
    /// 旧プライマリが回復しても自動で戻さない。
    fn backup_actions(&mut self, ctx: &PathControlCtx) -> Vec<PathAction> {
        self.retain_live_promotions(ctx);

        // プライマリがパス廃棄で失効した場合は、ここで再選出する
        let Some(primary) = self.select_backup_primary(ctx) else {
            return Vec::new();
        };

        let primary_metrics = ctx
            .path_metrics
            .iter()
            .find(|m| m.path_id == primary)
            .expect("selected backup primary must exist in path metrics");
        if primary_metrics.status == PathStatus::Available {
            // プライマリは正常。進行中のフェイルオーバー確認は取り消し、
            // 他の利用可能なパスを待機に戻すだけにする。
            self.pending_promotions.clear();
            self.backup_primary = Some(primary);
            return self.demote_available_others(ctx, primary, false);
        }

        // プライマリを Available へ戻す必要がある。他の利用可能なパスがある場合、
        // 久しく使っていないプライマリは到達性を確認してから切り替える
        // (draft-ietf-quic-multipath-21 Section 5.9)。
        let has_other_available = ctx
            .path_metrics
            .iter()
            .any(|m| m.is_usable && m.path_id != primary && m.status == PathStatus::Available);
        if has_other_available && self.needs_reachability_confirmation(ctx, primary_metrics) {
            // 候補が変わったら古い確認待ちを破棄し、現在の候補だけを待つ
            self.pending_promotions.retain(|id| *id == primary);
            if !self.pending_promotions.contains(&primary) {
                self.pending_promotions.insert(primary);
                return vec![PathAction::ProbePath { path_id: primary }];
            }
            return Vec::new();
        }

        self.backup_primary = Some(primary);
        self.pending_promotions.remove(&primary);
        self.backup_primary_actions(ctx, primary)
    }

    /// Aggregate モードの降格・再昇格の判断を組み立てる
    ///
    /// 比較基準には、使用可能 (`PathMetrics::is_usable`) で RTT を計測済みの
    /// 全パス (Backup を含む) の `smoothed_rtt` の最良値を用いる。待機中の
    /// パスを基準から外すと、回復した待機パスより遅い利用中のパスだけが残る
    /// ためである。
    ///
    /// 降格は最良値の 5 倍超、再昇格は 4 倍以下と閾値を分け、境界付近での状態
    /// 往復を抑える。降格で利用可能なパスが 1 本も無くならないよう、最良に
    /// 近い 1 本は Available のまま残す。
    ///
    /// RTT を計測していないパスは品質を判定できないため、降格・再昇格の対象に
    /// しない。未計測は `min_rtt` が 0 であることで判定する
    /// (`RttEstimator::new` は `smoothed_rtt` に初期値を入れるため、
    /// `smoothed_rtt == 0` では未計測を判定できない)。
    fn aggregate_actions(&mut self, ctx: &PathControlCtx) -> Vec<PathAction> {
        self.retain_live_promotions(ctx);

        let best_rtt = ctx
            .path_metrics
            .iter()
            .filter(|m| m.is_usable && m.min_rtt > Duration::ZERO)
            .map(|m| m.smoothed_rtt)
            .min();

        let Some(best_rtt) = best_rtt else {
            return Vec::new();
        };

        let mut actions = Vec::new();

        // 降格: 最良値の 5 倍超。利用可能なパスが全て降格しないよう、RTT の
        // 大きい順に降格し、最良に近い 1 本を Available のまま残す。
        // `active_path_ids` と同じ条件 (使用可能かつ Available) で数える
        let mut available_count = ctx
            .path_metrics
            .iter()
            .filter(|m| m.is_usable && m.status == PathStatus::Available)
            .count();
        let mut demotion_candidates: Vec<&PathMetrics> = ctx
            .path_metrics
            .iter()
            .filter(|m| {
                m.is_usable
                    && m.status == PathStatus::Available
                    && m.min_rtt > Duration::ZERO
                    && m.smoothed_rtt > best_rtt.mul(5)
            })
            .collect();
        demotion_candidates.sort_by_key(|m| core::cmp::Reverse(m.smoothed_rtt));
        for m in demotion_candidates {
            if available_count <= 1 {
                break;
            }
            available_count -= 1;
            actions.push(PathAction::SetStatus {
                path_id: m.path_id,
                status: PathStatus::Backup,
            });
            // Aggregate モードでは降格したパスを能動利用しないため、
            // 待機中は keep-alive で到達性を維持する。
            actions.push(PathAction::SetKeepAlive {
                path_id: m.path_id,
                enabled: true,
            });
        }

        // 再昇格: 最良値の 4 倍以下へ回復した Backup パスを候補とする。
        for m in ctx.path_metrics.iter() {
            if !m.is_usable
                || m.status != PathStatus::Backup
                || m.min_rtt == Duration::ZERO
                || m.smoothed_rtt > best_rtt.mul(4)
            {
                continue;
            }
            // PATH_RESPONSE を待っているパスは重ねて確認しない
            if self.pending_promotions.contains(&m.path_id) {
                continue;
            }
            // 他に利用可能なパスがある場合だけ、到達性を確認してから昇格する。
            // 確認の応答が届くまでは状態を変えない
            // (draft-ietf-quic-multipath-21 Section 5.9)。
            if available_count > 0 && self.needs_reachability_confirmation(ctx, m) {
                self.pending_promotions.insert(m.path_id);
                actions.push(PathAction::ProbePath { path_id: m.path_id });
                continue;
            }
            actions.push(PathAction::SetStatus {
                path_id: m.path_id,
                status: PathStatus::Available,
            });
            // 能動利用に戻るため、待機中に有効化していた keep-alive を止める。
            actions.push(PathAction::SetKeepAlive {
                path_id: m.path_id,
                enabled: false,
            });
            available_count += 1;
        }

        actions
    }

    /// PathMetricsUpdated イベントを処理する
    fn on_metrics_updated(&mut self, ctx: &PathControlCtx) -> Vec<PathAction> {
        match self.policy.mode {
            MultipathMode::Handover => self.handover_actions(ctx),
            MultipathMode::Backup => self.backup_actions(ctx),
            MultipathMode::Aggregate => self.aggregate_actions(ctx),
        }
    }

    /// ObservedAddressReceived イベントを処理する
    fn on_observed_address(
        &mut self,
        path_id: PathId,
        addr: SocketAddr,
        ctx: &PathControlCtx,
    ) -> Vec<PathAction> {
        // 観測外部アドレスとリモートアドレスの両方が一致する別のパスがあれば、
        // このパスは重複と判断して廃棄する。観測外部アドレスだけでは判定でき
        // ないため、宛先が異なるパスは維持する
        // (draft-ietf-quic-multipath-21 Section 5.2)。
        //
        // 同じパスの再通知は重複ではないため、観測アドレスを更新するだけに
        // して AbandonPath を返さない
        // (draft-ietf-quic-address-discovery-01 Section 4.1)。
        //
        // 廃棄するパスの観測アドレスは記録しない。PathAbandoned でも削除される
        // が、通知が届くまでの間、別のパスの重複判定に使われないようにする。
        if self.has_duplicate_network_path(path_id, &addr, ctx) {
            return vec![PathAction::AbandonPath {
                path_id,
                error_code: 0,
            }];
        }
        self.observed_addresses.insert(path_id, addr);
        Vec::new()
    }
}

impl PathController for DefaultPathController {
    fn on_event(&mut self, event: &PathControlEvent, ctx: &PathControlCtx) -> Vec<PathAction> {
        match event {
            PathControlEvent::NetworkInterfaceUp { name, addr } => {
                self.on_interface_up(name, *addr, ctx)
            }
            PathControlEvent::NetworkInterfaceDown { name, addr } => {
                self.on_interface_down(name, *addr, ctx)
            }
            PathControlEvent::NetworkAddressChanged {
                name,
                old_addr,
                new_addr,
            } => {
                // アドレス変更 = 旧パス廃棄 + 新パス作成。旧パスを廃棄する
                // アクションが返る場合、`ctx.current_path_count` は旧パスを
                // 含む。そのまま新パスの開設を評価すると `max_paths` に
                // 達したままとなり、新アドレスのパスを開かない。旧パスは
                // AbandonPath で 1 本減るため、その分を差し引いた状態で
                // 評価する。
                let mut actions = self.on_interface_down_impl(name, *old_addr, ctx, false);
                let abandoned = actions
                    .iter()
                    .filter(|action| matches!(action, PathAction::AbandonPath { .. }))
                    .count();
                let up_ctx = PathControlCtx {
                    path_metrics: ctx.path_metrics,
                    current_path_count: ctx.current_path_count.saturating_sub(abandoned),
                    policy: ctx.policy,
                    now: ctx.now,
                    keep_alive_interval: ctx.keep_alive_interval,
                };
                actions.extend(self.on_interface_up(name, *new_addr, &up_ctx));
                actions
            }
            PathControlEvent::PathOpenSucceeded {
                path_id,
                local_addr,
            } => {
                self.on_path_open_succeeded(*path_id, *local_addr);
                Vec::new()
            }
            PathControlEvent::PathOpenFailed { local_addr } => {
                self.on_path_open_failed(*local_addr);
                Vec::new()
            }
            PathControlEvent::PathValidated { path_id } => self.on_path_validated(*path_id, ctx),
            PathControlEvent::PathAbandoned { path_id, .. } => {
                self.on_path_abandoned(*path_id);
                // Backup モードでは失効と代替の有無を即座に再評価する。
                // プライマリの廃棄だけでなく、他の利用可能パスの廃棄で確認が
                // 不要になった場合も、応答を待たずに切り替える。
                if self.policy.mode == MultipathMode::Backup {
                    return self.backup_actions(ctx);
                }
                Vec::new()
            }
            PathControlEvent::PathMetricsUpdated { .. } => self.on_metrics_updated(ctx),
            PathControlEvent::ObservedAddressReceived { path_id, addr } => {
                self.on_observed_address(*path_id, *addr, ctx)
            }
        }
    }
}

/// DefaultPathController のファクトリ
#[derive(Debug, Clone, Copy)]
pub struct DefaultPathControllerFactory;

impl PathControllerFactory for DefaultPathControllerFactory {
    type Controller = DefaultPathController;

    fn create(&self, policy: MultipathPolicy) -> Self::Controller {
        DefaultPathController::new(policy)
    }
}

#[cfg(test)]
mod tests;
