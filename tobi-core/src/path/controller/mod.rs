// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! パスの自動判断ロジック
//!
//! PathController は Sans I/O パターンに従い、イベントを受け取ってアクションを返す。
//! Scheduler が「どのパスでパケットを送るか」を決めるのと同様に、
//! PathController は「どのパスを開く/閉じるか」を決める。

pub mod default;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::net::SocketAddr;

use super::PathId;
use super::PathStatus;
use super::policy::MultipathPolicy;
use crate::scheduler::PathMetrics;
use crate::time::{Duration, Timestamp};

/// PathController が受け取るイベント
#[derive(Debug, Clone)]
pub enum PathControlEvent {
    /// ネットワークインターフェースが利用可能になった
    NetworkInterfaceUp {
        /// インターフェース名
        name: String,
        /// インターフェースのアドレス
        addr: SocketAddr,
    },
    /// ネットワークインターフェースが利用不可になった
    NetworkInterfaceDown {
        /// インターフェース名
        name: String,
        /// インターフェースのアドレス
        addr: SocketAddr,
    },
    /// ネットワークインターフェースのアドレスが変更された
    NetworkAddressChanged {
        /// インターフェース名
        name: String,
        /// 旧アドレス
        old_addr: SocketAddr,
        /// 新アドレス
        new_addr: SocketAddr,
    },
    /// パスの開設要求が成功した
    ///
    /// `PathAction::OpenPath` で要求したパスが作成されたことを表す。
    /// `local_addr` は要求時に指定したローカルアドレスである。受け取った側は
    /// そのローカルアドレスに対応するインターフェースと `path_id` を関連付け、
    /// 以降の `NetworkInterfaceDown` でパスを廃棄できるようにする。
    ///
    /// このイベントは `PathAction::OpenPath` への応答としてのみ発行される。
    /// 公開 API の `Connection::open_path` / `Connection::open_path_with_addrs`
    /// から開いたパスはインターフェース起点ではないため発行されない。
    /// ハンドラは対応付けの更新だけを行い、`PathAction` を返してはならない。
    /// 返したアクションは実行されず、破棄される。
    PathOpenSucceeded {
        /// 作成されたパスの ID
        path_id: PathId,
        /// 開設要求で指定したローカルアドレス
        local_addr: SocketAddr,
    },
    /// パスの開設要求が失敗した
    ///
    /// `PathAction::OpenPath` で要求したパスを作成できなかったことを表す。
    /// `local_addr` は要求時に指定したローカルアドレスである。受け取った側は
    /// そのローカルアドレスに対応する未関連付けのインターフェースの記録を
    /// 取り消し、次の `NetworkInterfaceUp` で再試行できるようにする。
    ///
    /// 開設処理の途中で失敗した場合、作成済みのパスの後始末は `Connection` が
    /// 内部で行う。そのため、このイベントを受け取った時点で、その開設失敗に
    /// 対する [`PathControlEvent::PathAbandoned`] が `Connection` から届くことは
    /// ない。ピア起点の `PATH_ABANDON` は別途届き得る。
    ///
    /// 発行条件とハンドラの契約は [`PathControlEvent::PathOpenSucceeded`] と
    /// 同じである。
    PathOpenFailed {
        /// 開設要求で指定したローカルアドレス
        local_addr: SocketAddr,
    },
    /// PATH_CHALLENGE/RESPONSE が成功した
    PathValidated {
        /// 検証されたパスの ID
        path_id: PathId,
    },
    /// パスが廃棄された
    ///
    /// ピアからの `PATH_ABANDON` による廃棄だけでなく、パス検証の失敗、
    /// 重複ネットワークパスの検出、公開 API からの廃棄など、ローカルに廃棄した
    /// 場合にも発行される。同じパスについて複数回発行されうるため、
    /// 受け取った側は冪等に処理すること。
    ///
    /// 開設処理の途中で失敗したパスは、その後始末を
    /// [`PathControlEvent::PathOpenFailed`] で伝えるため、その時点ではこの
    /// イベントを発行しない。ピア起点の `PATH_ABANDON` は別途届き得る。
    PathAbandoned {
        /// 廃棄されたパスの ID
        path_id: PathId,
        /// エラーコード
        error_code: u64,
    },
    /// パスのメトリクスが更新された
    PathMetricsUpdated {
        /// 更新されたパスの ID
        path_id: PathId,
    },
    /// OBSERVED_ADDRESS で外部アドレスが判明した
    ///
    /// draft-ietf-quic-address-discovery-01 由来。
    /// draft であり将来変更される可能性がある。
    ObservedAddressReceived {
        /// アドレスを観測したパスの ID
        path_id: PathId,
        /// 観測された外部アドレス
        addr: SocketAddr,
    },
}

/// PathController が返すアクション
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathAction {
    /// 新しいパスを開く
    OpenPath {
        /// ローカルアドレス
        local_addr: SocketAddr,
        /// リモートアドレス
        ///
        /// ポートが 0 の場合、初期パスのリモートアドレスを継承する。
        remote_addr: SocketAddr,
    },
    /// パスを廃棄する
    AbandonPath {
        /// 廃棄するパスの ID
        path_id: PathId,
        /// エラーコード
        error_code: u64,
    },
    /// パスの状態を変更する
    SetStatus {
        /// 対象パスの ID
        path_id: PathId,
        /// 新しい状態
        status: PathStatus,
    },
    /// パスの keep-alive を有効化または無効化する
    ///
    /// keep-alive が有効なパスには、一定時間送受信が無いときに PING が送られる
    /// (RFC 10069 Section 5.9)。使用されない待機パスを
    /// middlebox のタイムアウトで失わないようにするために使う。
    SetKeepAlive {
        /// 対象パスの ID
        path_id: PathId,
        /// 有効にするか
        enabled: bool,
    },
    /// パスの到達性を確認する (PATH_CHALLENGE を送る)
    ///
    /// 未使用のパスを能動利用へ切り替える前に、まだ到達可能かを確認する
    /// (RFC 10069 Section 5.9)。PATH_RESPONSE を受信する
    /// までは状態を切り替えない。応答が無い場合はパス検証のリトライ上限で
    /// パスが廃棄される。
    ProbePath {
        /// 対象パスの ID
        path_id: PathId,
    },
}

/// PathController が参照する読み取り専用コンテキスト
pub struct PathControlCtx<'a> {
    /// 全パスのメトリクス
    pub path_metrics: &'a [PathMetrics],
    /// 現在のパス数
    ///
    /// `Abandoning` / `Abandoned` を除くパスの数である。検証中のパスも
    /// 含む。
    pub current_path_count: usize,
    /// Multipath ポリシー
    pub policy: &'a MultipathPolicy,
    /// 現在時刻
    ///
    /// 最終受信時刻からの経過を判定するために使う。
    pub now: Timestamp,
    /// keep-alive の送信間隔
    ///
    /// 接続設定から解決した実効値。`None` の場合は keep-alive が無効であり、
    /// 到達性の確認要否を時間で判定できない。昇格前の確認ではこの値を
    /// 「しばらく使っていない」の閾値として使う。
    pub keep_alive_interval: Option<Duration>,
}

/// パスの自動判断ロジック
///
/// Scheduler と同じ設計パターン。
/// イベントを受け取り、パスの開閉やステータス変更のアクションを返す。
///
/// 実装上の契約:
///
/// - [`PathControlEvent::PathAbandoned`] はピア起点とローカル起点の双方で
///   通知される (開設途中の失敗を除く)。同じパスについて複数回届きうるため、
///   `on_event` は同じイベントを繰り返し受け取っても状態が壊れないよう冪等に
///   実装すること。
/// - [`PathControlEvent::PathOpenSucceeded`] / [`PathControlEvent::PathOpenFailed`]
///   は対応付けの更新だけを行い、アクションを返してはならない。返したアクションは
///   `Connection` が警告ログを出して破棄する。
/// - `Connection` は 1 回の `execute_path_actions` 呼び出しで実行する
///   アクション数に上限を設ける。上限はポリシーの `max_paths` と実際の
///   アクティブパス数から導出し、超えた分は警告ログを出して破棄されるため、
///   多数のアクションを一度に返す実装は前提にしないこと。
/// - `AbandonPath` の実行は `PathAbandoned` の通知からアクション実行へ再入
///   しうる。`Connection` は再入深度にも上限を設け、超えた場合は警告ログを
///   出して実行しない。`PathAbandoned` から別のパスの廃棄を返す実装は、
///   有限回で終わることを保証すること。
pub trait PathController: Debug + Send {
    /// イベントを処理してアクションを返す
    ///
    /// 空の Vec を返すと「何もしない」を意味する。
    fn on_event(&mut self, event: &PathControlEvent, ctx: &PathControlCtx) -> Vec<PathAction>;
}

/// PathController のファクトリ
///
/// CongestionControlFactory, SchedulerFactory と同じパターン。
pub trait PathControllerFactory: Debug + Send {
    /// 生成する PathController の型
    type Controller: PathController;

    /// MultipathPolicy に基づいて PathController を生成する
    fn create(&self, policy: MultipathPolicy) -> Self::Controller;
}
