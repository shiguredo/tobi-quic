// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Multipath パス管理
//!
//! Multipath First: 全てのデータ構造は最初から Multipath を前提とする。
//! シングルパスは Path ID 0 のみの特殊ケース。

pub mod controller;
pub mod mtu;
pub mod policy;
pub mod state;
pub mod validation;

use alloc::vec::Vec;
use core::net::SocketAddr;

use hashbrown::{HashMap, HashSet};

use crate::connection_id::ConnectionId;
use crate::error::Error;
use crate::packet::number;
use crate::recovery::{
    AckTracker, CongestionControl, CongestionControlFactory, LossDetectors, NewReno,
    NewRenoFactory, RttEstimator, SentPackets,
};
use crate::scheduler::PathMetrics;
use crate::stats::PathStats;

use self::mtu::{BASE_MTU, MAX_UDP_PAYLOAD, MtuController};
use self::state::PathState;
use self::validation::PathValidation;
use crate::connection::MtuConfig;
use crate::time::Timestamp;

/// ECN 検証状態 (RFC 9000 Section 13.4.2)
///
/// 新しいパス開始時は Testing 状態で ECT(0) を送信し、ACK の ECN カウントを
/// 検証する。検証成功で Capable、失敗で Failed に遷移する。Failed 以降は
/// そのパスで NotEct を使用し続ける (本実装では再検証は行わない)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EcnValidationState {
    /// ECT(0) を送信中、まだ検証結果が確定していない
    #[default]
    Testing,
    /// ECN 検証成功、ECT(0) を送信し続ける
    Capable,
    /// ECN 検証失敗、NotEct にフォールバック
    Failed,
}

impl EcnValidationState {
    /// 送信時に ECT(0) を設定すべき状態か
    pub fn should_mark_ect0(self) -> bool {
        matches!(self, Self::Testing | Self::Capable)
    }
}

/// Path ID (0 から単調増加、再利用不可、最大 2^32-1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathId(pub u32);

impl PathId {
    /// 初期パスの Path ID
    pub const INITIAL: Self = Self(0);
}

impl core::fmt::Display for PathId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// パス状態 (Available / Backup)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStatus {
    Available,
    Backup,
}

/// 4-tuple 移行の確定記録
///
/// 移行確定直後には、移行前に送信された未受信パケットが旧 4-tuple から
/// 遅延して到着しうる。RFC 9000 Section 9.3 は「再順序されたパケットで
/// 旧アドレスへ送らない」ことを要求しており、最大パケット番号の
/// non-probing パケットだけが送信先を変える規則を置いているが、移行前に
/// 送信されたパケットが新たな最大番号として届く場合はこの規則だけでは
/// 区別できない。そのため確定時刻と旧 4-tuple を記録し、猶予期間中の
/// 旧 4-tuple からのパケットを再移行のトリガーにしない。ヒューリスティックに
/// よる検出を許容する RFC 9000 Section 9.3.3 の方針に沿う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationHint {
    /// 移行を確定した時刻
    pub committed_at: Timestamp,
    /// 移行確定前のリモートアドレス
    pub previous_remote_addr: SocketAddr,
    /// 移行確定前のローカルアドレス
    pub previous_local_addr: SocketAddr,
}

/// 個別パスの状態
pub struct Path<CC: CongestionControl = NewReno> {
    /// パス ID
    pub id: PathId,
    /// パス状態 (Pending/Validating/Active/...)
    pub state: PathState,
    /// パス状態 (Available/Backup)
    ///
    /// ローカルの設定 (`Connection::set_path_status`) と `DefaultPathController` の
    /// 判断で決まる。ピアの `PATH_STATUS` では変更しない
    /// (RFC 10069 Section 3.3 は両端点の preference が
    ///  独立だと定める)。
    pub status: PathStatus,
    /// ピアが通知したパスの preference
    ///
    /// 送信先の選択には使わない。`Connection::peer_path_status` で確認できる。
    pub peer_status: Option<PathStatus>,
    /// パスごとの送信パケット番号 (次に送信する番号)
    pub send_pn: u64,
    /// パスごとの受信パケット番号 (最大)
    pub recv_pn_largest: Option<u64>,
    /// 受信した non-probing パケットの最大パケット番号
    ///
    /// RFC 9000 Section 9.3: 送信先アドレスを変えてよいのは、受信した
    /// non-probing パケットのうち最大のパケット番号を持つものだけである。
    pub recv_pn_largest_non_probing: Option<u64>,
    /// パスごとの RTT 推定
    pub rtt: RttEstimator,
    /// パスごとの ACK 追跡
    pub ack_tracker: AckTracker,
    /// パスごとの送信済みパケット追跡
    pub sent_packets: SentPackets,
    /// パスごとのパケット番号空間別損失検出器
    ///
    /// Initial / Handshake / Application Data の各空間が独立した
    /// time_of_last_ack_eliciting_packet / loss_time / pto_count を持つ
    /// (RFC 9002 Section 4.1 / 6.2)。
    pub loss_detectors: LossDetectors,
    /// パスごとの輻輳制御 (RFC 10069 Section 5.3)
    pub congestion: CC,
    /// パス検証状態
    pub validation: PathValidation,
    /// パスステータスのシーケンス番号 (受信した最新)
    /// None は未受信を表す
    pub status_seq_recv: Option<u64>,
    /// パスステータスのシーケンス番号 (送信する次の値)
    pub status_seq_send: u64,
    /// パスごとの PMTU (RFC 10069 Section 5.8)
    pub pmtu: u16,
    /// DPLPMTUD コントローラ (RFC 8899)
    pub mtu_controller: MtuController,
    /// 前回 ACK で報告された ECN カウント (RFC 9000 Section 13.4.2.1)
    ///
    /// ECN CE の増分検出とリマーキング検出に使用する。ECN カウントは
    /// パケット番号空間ごとに独立する (RFC 9000 Section 13.4.1) が、本実装が
    /// ECT を付けるのは 1-RTT (Application Data 空間) だけなので、検証状態は
    /// パス単位・Application Data 空間の値として保持する。
    pub prev_ecn_counts: crate::frame::ack::EcnCounts,
    /// ECN 検証状態 (RFC 9000 Section 13.4.2)
    /// パスごとに独立して検証する (RFC 10069)
    pub ecn_state: EcnValidationState,
    /// このパスで ECT(0) マーキングで送信した 1-RTT パケット数の累計
    ///
    /// RFC 9000 Section 13.4.2.1 のリマーキング検知
    /// (ECN ect0 total <= sent total) に使用する。ECN を付けるのは 1-RTT
    /// (Application Data 空間) の送信だけなので、空間別の内訳は持たない。
    pub ecn_ect0_sent: u64,
    /// このパスで ECT(0) マーキングで送信し、ロスト判定されたパケット数の累計
    ///
    /// RFC 9000 Section 13.4.2: ECT 付きで送信したパケットがすべてロストした場合に
    /// ECN 検証失敗と判定するために使用する。
    pub ecn_ect0_lost: u64,
    /// パスごとの送信先 peer CID (RFC 10069 Section 4)
    /// このパスでパケットを送信する際に Short Header の DCID に使用する
    pub peer_cid: Option<ConnectionId>,
    /// パスごとのローカル CID シーケンス番号 (次に発行する番号)
    /// (RFC 10069 Section 4)
    pub next_local_cid_seq: u64,
    /// PATH_ABANDON が完了した時刻 (送受信の両方が完了した時点)
    /// 3 PTO 経過後にパス状態を削除するために使用する
    /// (RFC 10069 Section 5.3)
    pub abandoned_at: Option<crate::time::Timestamp>,

    /// このパスで最後にパケットを送信した時刻
    ///
    /// keep-alive の要否判定に使う。アプリケーションデータの送信も含む。
    last_send_at: Option<Timestamp>,
    /// このパスで最後にパケットを受信した時刻
    ///
    /// keep-alive の要否判定に使う。
    last_recv_at: Option<Timestamp>,
    /// このパスで送信したパケットが最後に ACK された時刻
    ///
    /// ACK は送信パスが機能している証拠であり、到達性の確認材料になる。
    /// ACK 自体は別のパスで受信してもよい (RFC 10069
    /// Section 5.5 は ACK を任意のパスで送れるとする)。
    pub last_acked_at: Option<Timestamp>,
    /// このパスで keep-alive を有効にするか
    ///
    /// 接続の既定値 (`Connection::set_keep_alive`) を継承して作成され、
    /// `Connection::set_path_keep_alive` と `DefaultPathController` が変更する。
    keep_alive_enabled: bool,

    // ネットワークパス (4-tuple)
    // RFC 10069 Section 3.1: PATH_RESPONSE は同じ network path で返す (MUST)
    // RFC 10069 Section 3.1.2: 4-tuple 変更は migration として扱う (MUST)
    /// リモートアドレス (ピアの IP:port)
    pub remote_addr: SocketAddr,
    /// ローカルアドレス (自身の IP:port)
    pub local_addr: SocketAddr,

    // パスごとのアンチアンプリフィケーション (RFC 9000 Section 8.1)
    // 新規パスのアドレス検証完了前は送信量を受信量の 3 倍以内に制限する
    /// パスのアドレス検証が完了したか
    pub address_validated: bool,
    /// アドレス検証完了前の受信バイト数
    pub recv_bytes_before_validated: u64,
    /// アドレス検証完了前の送信バイト数
    pub sent_bytes_before_validated: u64,
    /// Migration 後のパス検証が成功した時点で CC/RTT をリセットする必要があるか
    ///
    /// RFC 9000 Section 9.4 / RFC 10069 Section 5.1:
    /// 4-tuple 変更 (port-only を除く) を伴う migration が検出されると true に
    /// セットされ、PATH_RESPONSE で検証成功が確認された時点で CC と RTT を
    /// 初期値にリセットして `false` に戻す。port-only 変更 (ポート番号のみ差分)
    /// の migration では RFC の例外規定によりリセットしないので `false` のまま。
    pub migration_reset_pending: bool,
    /// 4-tuple 移行の確定記録 (旧 4-tuple からの遅延パケット抑止用)
    pub migration_hint: Option<MigrationHint>,

    // スケジューラーメトリクス
    /// 配送時間推定 (スケジューラー向け)
    ///
    /// RFC 10069 Section 5.4 の推奨に従い、パスの実 RTT では
    /// なく「送信パスの片道遅延 + ACK 返送パスの片道遅延」の和を推定する。
    /// 片道遅延は各パスの `rtt.smoothed_rtt` の半分で近似する。
    ///
    /// ACK 返送パスが変化した直後は `Duration::ZERO` にリセットされ、
    /// `Path::metrics` が `smoothed_rtt` にフォールバックする。返送パスが安定して
    /// 再び更新されるとこの推定値に戻る。
    pub delivery_time_estimate: crate::time::Duration,
    /// ACK 返送パスが直近で変更されたか
    ///
    /// ACK パス変更は RTT サンプルの意味を変える (forward + return の合成)。
    /// スケジューラーはこのフラグを見て推定を調整する。
    pub ack_path_changed: bool,

    // 統計カウンタ
    /// パス単位の累積カウンタ
    stats: PathStats,
}

impl<CC: CongestionControl> Path<CC> {
    /// ECT(0) マーキングで送信したパケット数を記録する (RFC 9000 Section 13.4.2)
    pub fn record_ecn_ect0_sent(&mut self) {
        self.ecn_ect0_sent = self.ecn_ect0_sent.saturating_add(1);
    }

    /// ECT(0) マーキングで送信したパケットのロストを記録する
    ///
    /// RFC 9000 Section 13.4.2: ECT 付きで送信したパケットがすべてロストした
    /// 場合は ECN 検証失敗とみなす。全ロストに達したとき true を返す。
    pub fn record_ecn_ect0_lost(&mut self) -> bool {
        self.ecn_ect0_lost = self.ecn_ect0_lost.saturating_add(1);
        self.ecn_ect0_sent > 0 && self.ecn_ect0_lost >= self.ecn_ect0_sent
    }

    /// ロスト判定後に ACK された ECT(0) パケットをロスト数から取り消す
    ///
    /// RFC 9002 Section 6.1 の spurious loss 検出で ACK されたパケットは
    /// 実際にはロストしていないため、全ロスト判定の根拠から除外する。
    pub fn record_ecn_ect0_spurious_ack(&mut self) {
        self.ecn_ect0_lost = self.ecn_ect0_lost.saturating_sub(1);
    }
    /// 新しいパスを作成する
    ///
    /// `mtu_controller` は `ConnectionConfig` の MTU 設定から作成したものを渡す。
    /// `pmtu` の初期値は `mtu_controller.current_mtu()` に合わせる
    /// (RFC 8899 Section 4.4: 探索開始時点の MPS)。
    pub fn new(
        id: PathId,
        congestion: CC,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        mtu_controller: MtuController,
    ) -> Self {
        // 初期 PMTU は MTU コントローラの確認済み MTU に合わせる
        let initial_pmtu = mtu_controller.current_mtu();
        Self {
            id,
            state: if id == PathId::INITIAL {
                // 初期パスは検証なしで Active
                PathState::Active
            } else {
                PathState::Pending
            },
            status: PathStatus::Available,
            peer_status: None,
            send_pn: 0,
            recv_pn_largest: None,
            recv_pn_largest_non_probing: None,
            rtt: RttEstimator::new(),
            ack_tracker: AckTracker::new(),
            sent_packets: SentPackets::new(),
            loss_detectors: LossDetectors::new(),
            congestion,
            validation: PathValidation::new(),
            status_seq_recv: None,
            status_seq_send: 0,
            pmtu: initial_pmtu,
            mtu_controller,
            prev_ecn_counts: Default::default(),
            ecn_state: EcnValidationState::Testing,
            ecn_ect0_sent: 0,
            ecn_ect0_lost: 0,
            // 初期パスの peer_cid は Connection 作成時に設定される
            peer_cid: None,
            // 初期パスは seq 0 が初期 CID なので 1 から開始
            next_local_cid_seq: if id == PathId::INITIAL { 1 } else { 0 },
            abandoned_at: None,
            last_send_at: None,
            last_recv_at: None,
            last_acked_at: None,
            // 既定では keep-alive を有効にする。接続の既定値
            // (`Connection::set_keep_alive`) はパス作成時に Connection が上書きする。
            keep_alive_enabled: true,
            remote_addr,
            local_addr,
            // 初期パスはハンドシェイクで検証済み、追加パスは未検証
            address_validated: id == PathId::INITIAL,
            recv_bytes_before_validated: 0,
            sent_bytes_before_validated: 0,
            migration_reset_pending: false,
            migration_hint: None,
            delivery_time_estimate: crate::time::Duration::ZERO,
            ack_path_changed: false,
            stats: PathStats::default(),
        }
    }

    /// 次のパケット番号を取得し、インクリメントする
    ///
    /// RFC 9000 Section 12.3: パケット番号は 0 から 2^62-1。送信に使用する
    /// パケット番号が 2^62-1 に達している場合は `None` を返す。呼び出し側は
    /// CONNECTION_CLOSE を送信せずに接続を閉じる必要がある (MUST)。
    pub fn next_pn(&mut self) -> Option<u64> {
        if self.send_pn >= number::MAX_PACKET_NUMBER {
            return None;
        }
        let pn = self.send_pn;
        self.send_pn += 1;
        Some(pn)
    }

    /// 受信パケット番号を更新する
    pub fn update_recv_pn(&mut self, pn: u64) {
        match self.recv_pn_largest {
            Some(largest) if pn > largest => self.recv_pn_largest = Some(pn),
            None => self.recv_pn_largest = Some(pn),
            _ => {}
        }
    }

    /// non-probing パケットの受信パケット番号を更新する
    ///
    /// 戻り値は、このパケット番号がそのパスで受信した non-probing パケットの
    /// 最大値だったかどうか。RFC 9000 Section 9.3 により、送信先アドレスの
    /// 変更は最大の non-probing パケットへの応答としてのみ行う。
    pub fn update_recv_pn_non_probing(&mut self, pn: u64) -> bool {
        let is_new_largest = self
            .recv_pn_largest_non_probing
            .is_none_or(|largest| pn > largest);
        if is_new_largest {
            self.recv_pn_largest_non_probing = Some(pn);
        }
        is_new_largest
    }

    /// パスが利用可能か (データ送信に使える状態)
    pub fn is_usable(&self) -> bool {
        self.state == PathState::Active
    }

    /// 4-tuple 移行の確定を記録する
    ///
    /// アドレスを書き換える直前に呼ぶことで、移行確定前の 4-tuple を
    /// 遅延パケット抑止の判定に使えるようにする。
    pub fn note_migration_committed(&mut self, now: Timestamp) {
        self.migration_hint = Some(MigrationHint {
            committed_at: now,
            previous_remote_addr: self.remote_addr,
            previous_local_addr: self.local_addr,
        });
    }

    /// 猶予期間中の旧 4-tuple から届いたパケットかを判定する
    ///
    /// 移行確定から `grace` 未満の期間に、移行前と同じ 4-tuple から届いた
    /// パケットは遅延パケットとして扱う。ACK 処理などパケット自体の処理は
    /// 呼び出し側が通常どおり行う。
    pub fn is_delayed_previous_tuple(
        &self,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        now: Timestamp,
        grace: crate::time::Duration,
    ) -> bool {
        let Some(hint) = self.migration_hint else {
            return false;
        };
        now.saturating_duration_since(hint.committed_at) < grace
            && hint.previous_remote_addr == remote_addr
            && hint.previous_local_addr == local_addr
    }

    /// アンチアンプリフィケーション制限内で送信可能か
    ///
    /// アドレス検証が完了していない場合、送信バイト数が
    /// 受信バイト数の 3 倍を超えてはならない (RFC 9000 Section 8.1)。
    pub fn can_send_bytes(&self, bytes: u64) -> bool {
        if self.address_validated {
            return true;
        }
        let limit = self.recv_bytes_before_validated.saturating_mul(3);
        self.sent_bytes_before_validated.saturating_add(bytes) <= limit
    }

    /// 送信バイト数を記録する (アンチアンプリフィケーション用)
    pub fn on_bytes_sent(&mut self, bytes: u64) {
        if !self.address_validated {
            self.sent_bytes_before_validated =
                self.sent_bytes_before_validated.saturating_add(bytes);
        }
    }

    /// 受信バイト数を記録する (アンチアンプリフィケーション用)
    pub fn on_bytes_received(&mut self, bytes: u64) {
        if !self.address_validated {
            self.recv_bytes_before_validated =
                self.recv_bytes_before_validated.saturating_add(bytes);
        }
    }

    /// アドレス検証をやり直し、旧アドレスで積んだ送受信量を捨てる
    ///
    /// RFC 9000 Section 9.3.1 は、検証できるまで Section 8 の増幅制限を適用する。
    /// Section 8 の上限は、その未検証アドレスから受信した量の 3 倍である。
    /// 4-tuple が変わったあとに旧アドレスの計測値を残すと、新しいアドレスへ
    /// 仕様より多く送れる。検証のやり直しは同じ分岐で何度でも起きるため、
    /// 検証成功を待たずにここで 0 に戻す。
    ///
    /// 呼び出し側は、この直後に新しいアドレスから届いたパケットを
    /// `on_bytes_received` で加算する。
    pub fn restart_address_validation(&mut self) {
        self.state = PathState::Validating;
        self.address_validated = false;
        self.recv_bytes_before_validated = 0;
        self.sent_bytes_before_validated = 0;
    }

    /// スケジューラーと PathController 向けのメトリクススナップショットを生成する
    pub fn metrics(&self) -> PathMetrics {
        // delivery_time_estimate が未初期化 (ZERO) の場合は smoothed_rtt にフォールバック
        let delivery_est = if self.delivery_time_estimate == crate::time::Duration::ZERO {
            self.rtt.smoothed_rtt
        } else {
            self.delivery_time_estimate
        };
        PathMetrics {
            path_id: self.id,
            state: self.state,
            status: self.status,
            peer_status: self.peer_status,
            smoothed_rtt: self.rtt.smoothed_rtt,
            min_rtt: self.rtt.min_rtt,
            latest_rtt: self.rtt.latest_rtt,
            available_window: self.congestion.available_window(),
            congestion_window: self.congestion.congestion_window(),
            bytes_in_flight: self.congestion.bytes_in_flight(),
            is_congestion_limited: self.congestion.is_congestion_limited(),
            pacing_rate: self.congestion.pacing_rate(),
            bandwidth_estimate: self.congestion.bandwidth_estimate(),
            pmtu: self.pmtu,
            remote_addr: self.remote_addr,
            // ピア CID が未確定の追加パスは送信先にできない
            // (RFC 10069 Section 3.1)。初期パスは接続の
            // ピア CID がそのパスの CID になるため対象外。
            is_usable: self.is_usable() && (self.peer_cid.is_some() || self.id == PathId::INITIAL),
            pto_count: self.loss_detectors.pto_count(),
            delivery_time_estimate: delivery_est,
            ack_path_changed: self.ack_path_changed,
            last_confirmed_at: self.last_confirmed_at(),
            stats: self.stats,
        }
    }

    /// パス単位の累積カウンタを返す
    pub fn stats(&self) -> PathStats {
        self.stats
    }

    /// 送信したパケットを記録する
    pub fn record_sent_packet(&mut self, bytes: u64) {
        self.stats.record_sent(bytes);
    }

    /// 受信したパケットを記録する
    pub fn record_received_packet(&mut self, bytes: u64) {
        self.stats.record_received(bytes);
    }

    /// ロストした in-flight パケットを記録する
    pub fn record_lost_packet(&mut self) {
        self.stats.record_lost();
    }

    /// 再送した in-flight パケットを記録する
    pub fn record_retransmitted_packet(&mut self) {
        self.stats.record_retransmitted();
    }

    /// このパスでパケットを送信したことを記録する
    ///
    /// keep-alive の要否判定に使う。PING を含むすべての送信で呼ぶ。
    pub fn record_sent(&mut self, now: Timestamp) {
        self.last_send_at = Some(now);
    }

    /// このパスでパケットを受信したことを記録する
    ///
    /// 復号に成功した受信だけを記録する。keep-alive の要否判定に使う。
    pub fn record_received(&mut self, now: Timestamp) {
        self.last_recv_at = Some(now);
    }

    /// このパスの最終送受信時刻を返す
    ///
    /// 送信と受信のうち新しい方を返す。一度も送受信していない場合は `None`。
    pub fn last_activity_at(&self) -> Option<Timestamp> {
        match (self.last_send_at, self.last_recv_at) {
            (Some(sent), Some(recv)) => Some(if sent > recv { sent } else { recv }),
            (Some(sent), None) => Some(sent),
            (None, recv) => recv,
        }
    }

    /// このパスで最後にパケットを受信した時刻を返す
    ///
    /// 一度も受信していない場合は `None`。
    pub fn last_recv_at(&self) -> Option<Timestamp> {
        self.last_recv_at
    }

    /// このパスの到達性が最後に確認できた時刻を返す
    ///
    /// パケットの受信または送信パケットへの ACK のうち新しい方を返す。
    /// 一度も確認できていない場合は `None`。
    pub fn last_confirmed_at(&self) -> Option<Timestamp> {
        match (self.last_recv_at, self.last_acked_at) {
            (Some(recv), Some(acked)) => Some(if recv > acked { recv } else { acked }),
            (Some(recv), None) => Some(recv),
            (None, acked) => acked,
        }
    }

    /// このパスで keep-alive が有効かを返す
    pub fn keep_alive_enabled(&self) -> bool {
        self.keep_alive_enabled
    }

    /// このパスの keep-alive の有効/無効を設定する
    pub fn set_keep_alive_enabled(&mut self, enabled: bool) {
        self.keep_alive_enabled = enabled;
    }
}

/// パスマネージャ
///
/// 全パスを統一管理する。初期パス (Path ID 0) はコンストラクタで自動生成。
/// `F` は輻輳制御ファクトリ。パス生成時に輻輳制御インスタンスを作成する。
///
/// 破壊的変更: 以前の `peer_cid_count` はワークスペース内に呼び出し元が
/// 無いため削除した。
pub struct PathManager<F: CongestionControlFactory = NewRenoFactory> {
    /// パスの一覧 (PathId → Path)
    paths: Vec<Path<F::Controller>>,
    /// 次に割り当てる Path ID
    next_path_id: u32,
    /// 自分が許容する最大 Path ID
    pub local_max_path_id: u32,
    /// ピアが許容する最大 Path ID
    pub remote_max_path_id: u32,
    /// 廃棄済み (tombstone) の path ID
    ///
    /// `remove_path` で Path オブジェクトを削除した後も保持する。tombstone の
    /// path ID は再度割り当てず、パスも作成しない
    /// (RFC 10069 Section 3.4)。
    abandoned_path_ids: HashSet<u32>,
    /// 未開設の path ID 宛に受信したピアの preference (シーケンス番号つき)
    ///
    /// RFC 10069 Section 4.3 は未使用の path ID にも
    /// PATH_STATUS を送れるとする。パスを開いた時点で反映する。
    peer_status_pending: HashMap<u32, (u64, PathStatus)>,
    /// CID → PathId のマッピング (受信パケットの振り分け用)
    cid_to_path: HashMap<ConnectionId, PathId>,
    /// 同時パス検証数の上限 (RFC 10069 Section 7.1 / Security Considerations)
    ///
    /// RFC 10069 Section 7.1 は「パスリソースはパス検証完了後に
    /// 割り当てるべき (SHOULD)」と述べている。本実装では遅延割り当てを行わず、
    /// `Path::new` 時点で輻輳制御 / RTT 推定 / Loss Detector / ACK Tracker 等を
    /// フル初期化する代わりに、以下の 3 つの緩和策で resource exhaustion 攻撃の
    /// 影響を抑える:
    ///
    /// 1. **同時検証数の上限 (本フィールド)**: 4 本まで。攻撃者が多数の検証中パスを
    ///    同時に抱えさせて DoS を狙うことを防ぐ。クライアント側 `open_path()` と
    ///    サーバー側 `create_path_for_peer()` の両方で本制限を適用する。
    /// 2. **PTO ベースのレート制限**: `Connection::open_path` は前回のパス開始から
    ///    PTO 以上経過していないと新パスを開かない (RFC 10069 Section 7.2)。クライアントの
    ///    攻撃的なパス生成を抑制する。
    /// 3. **パスごとの anti-amplification**: 未検証パスでは送信バイト数を受信バイト数の
    ///    3 倍以下に制限する (RFC 9000 Section 8.1 / RFC 10069 Section 3.1)。サーバー側で
    ///    偽装アドレスからの amplification を防ぐ。
    ///
    /// パス検証前のリソース割り当てを遅延しないため、これらの制限を併用して
    /// リソース消費を抑える。
    max_concurrent_validations: usize,
    /// 輻輳制御ファクトリ
    cc_factory: F,
    /// パス生成時に使う MTU 設定 (RFC 8899 / RFC 9000 Section 14)
    mtu_config: MtuConfig,
    /// DPLPMTUD を開始済みか
    ///
    /// ハンドシェイク完了後に `PathManager::enable_dplpmtud` で true になる。
    /// true の間は、生成されるパスの `MtuController` も生成直後から探索を始める。
    /// RFC 10069 Section 5.8 はパスごとに DPLPMTUD の MPS を
    /// 維持することを求めており、追加パスも探索対象にする必要がある。
    dplpmtud_enabled: bool,
    /// ピアが広告した `max_udp_payload_size` に基づく送信 MTU の上限
    ///
    /// ピアの受信上限を超えるパケットを送らないよう、全パスの DPLPMTUD と
    /// `Path::pmtu` をこの値以下に制限する。値は引き下げのみ行う。
    max_udp_payload_size: u16,
}

impl<F: CongestionControlFactory> PathManager<F> {
    /// 新しいパスマネージャを作成する
    ///
    /// 初期パス (Path ID 0) が自動的に作成される。`mtu_config` は全てのパスの
    /// `MtuController` の初期化に使う。
    ///
    /// `local_max_path_id` は実装が同時に保持するパス数の上限になる。
    /// ピアが大量のパスを作成してメモリを消費するのを防ぐため、
    /// `crate::transport_params::MAX_PATH_ID` 以下を推奨する。
    pub fn new(
        local_max_path_id: u32,
        cc_factory: F,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        mtu_config: MtuConfig,
    ) -> Self {
        // `PathManager` 単体では `MtuConfig` の検証を行わないため、無効な設定
        // (例: `max_mtu < initial_mtu`) では既定値へフォールバックする。
        // `tobi-quic` の builder や `tobi-platform` の接続作成など公開 API の
        // 入口は `MtuConfig::validate` で検証済みだが、`PathManager` を直接使う
        // 利用者もいるため、このフォールバックは防御として残す。輻輳制御の
        // 初期値は、実際に `Path::pmtu` の初期値になる実効 MTU に合わせる。
        let initial_controller = mtu_config.build_controller().unwrap_or_default();
        let initial_cc = cc_factory.create(u64::from(initial_controller.current_mtu()));
        let initial_path = Path::new(
            PathId::INITIAL,
            initial_cc,
            remote_addr,
            local_addr,
            initial_controller,
        );
        Self {
            paths: vec![initial_path],
            next_path_id: 1,
            local_max_path_id,
            remote_max_path_id: 0,
            abandoned_path_ids: HashSet::new(),
            peer_status_pending: HashMap::new(),
            cid_to_path: HashMap::new(),
            max_concurrent_validations: 4,
            cc_factory,
            max_udp_payload_size: MAX_UDP_PAYLOAD,
            mtu_config,
            dplpmtud_enabled: false,
        }
    }

    /// 同時に実行するパス検証の上限を設定する
    ///
    /// 0 は 1 として扱う。既定は 4。
    pub fn with_max_concurrent_validations(mut self, limit: usize) -> Self {
        self.max_concurrent_validations = limit.max(1);
        self
    }

    /// 同時に実行するパス検証の上限を返す
    pub fn max_concurrent_validations(&self) -> usize {
        self.max_concurrent_validations
    }

    /// DPLPMTUD を有効にして探索を開始する
    ///
    /// ハンドシェイク完了後に呼ぶ。既存のパスに加え、これ以降に生成される
    /// パスも生成直後から探索を開始する。`MtuController::enable` は
    /// 探索不要 (base_mtu == max_mtu) の場合と有効化済みの場合に早期 return する。
    pub fn enable_dplpmtud(&mut self) {
        self.dplpmtud_enabled = true;
        for path in self.paths.iter_mut() {
            path.mtu_controller.enable();
        }
    }

    /// ピアの `max_udp_payload_size` を全パスへ反映する
    ///
    /// RFC 9000 Section 18.2: ピアが広告した `max_udp_payload_size` を超える
    /// UDP データグラムは受信されない可能性がある。値は `BASE_MTU` 未満を
    /// 引き上げ、現在値以下にのみ引き下げる。保持値は `MAX_UDP_PAYLOAD` で
    /// 初期化して引き下げのみ行うため、上方向の clamp は不要である。ピアの
    /// 受信上限はハンドシェイクで確定するため、後から大きい値を設定しても
    /// 引き上げない。
    ///
    /// 全パスの DPLPMTUD の設定上限と現在の MTU をこの値以下に制限し、
    /// `Path::pmtu` が変化した場合は輻輳制御にも通知する。
    ///
    /// 旧探索で送信済みのプローブを回収すべきパスの ID を返す。BASE フェーズへ
    /// 遷移した場合と、探索上限の引き下げで探索をやり直す場合に返す。
    pub fn set_max_udp_payload_size(&mut self, limit: u16) -> Vec<PathId> {
        // 保持値は MAX_UDP_PAYLOAD で初期化して引き下げのみ行うため、上方向の
        // clamp は不要である。BASE_MTU 未満だけ引き上げる。
        let limit = limit.max(BASE_MTU).min(self.max_udp_payload_size);
        self.max_udp_payload_size = limit;
        let mut invalidated = Vec::new();
        for path in self.paths.iter_mut() {
            let before = path.mtu_controller.state();
            path.mtu_controller.set_max_udp_payload_size(limit);
            let after = path.mtu_controller.state();
            if before != after
                && matches!(
                    after,
                    crate::path::mtu::MtuState::BaseRequested
                        | crate::path::mtu::MtuState::SearchRequested
                        | crate::path::mtu::MtuState::SearchComplete
                )
            {
                invalidated.push(path.id);
            }
            let new_pmtu = path.mtu_controller.current_mtu();
            if path.pmtu != new_pmtu {
                path.pmtu = new_pmtu;
                path.congestion.on_mtu_update(u64::from(new_pmtu));
            }
        }
        invalidated
    }

    /// 新しいパス用の MTU コントローラを作成する
    ///
    /// ピアの受信上限を適用してから、DPLPMTUD を開始済みなら探索を開始する。
    /// これにより、ハンドシェイク完了後に生成される追加パスも探索対象になり、
    /// ピア上限を超えるプローブを送らない。
    fn new_mtu_controller(&self) -> MtuController {
        // `PathManager` 単体では `MtuConfig` を検証しないため、無効な設定では
        // 既定値へフォールバックする (公開 API の入口では
        // `MtuConfig::validate` で検証済み)。
        let mut controller = self.mtu_config.build_controller().unwrap_or_default();
        controller.set_max_udp_payload_size(self.max_udp_payload_size);
        if self.dplpmtud_enabled {
            controller.enable();
        }
        controller
    }

    /// パスを取得する
    pub fn get(&self, path_id: PathId) -> Option<&Path<F::Controller>> {
        self.paths.iter().find(|p| p.id == path_id)
    }

    /// パスを変更可能で取得する
    pub fn get_mut(&mut self, path_id: PathId) -> Option<&mut Path<F::Controller>> {
        self.paths.iter_mut().find(|p| p.id == path_id)
    }

    /// 初期パス (Path ID 0) を取得する
    pub fn initial_path(&self) -> &Path<F::Controller> {
        self.get(PathId::INITIAL).expect("initial path must exist")
    }

    /// 初期パスを変更可能で取得する
    pub fn initial_path_mut(&mut self) -> &mut Path<F::Controller> {
        self.get_mut(PathId::INITIAL)
            .expect("initial path must exist")
    }

    /// 次に割り当てる予定の Path ID が、ピアの `remote_max_path_id` により開けないか
    ///
    /// RFC 10069 Section 3.2.1:
    /// 未使用 path ID がないとき `PATHS_BLOCKED` を送る判断に使う。
    pub fn next_path_id_blocked_by_peer_limit(&self) -> bool {
        self.next_path_id > self.remote_max_path_id
    }

    /// path ID を廃棄済み (tombstone) として登録する
    ///
    /// 登録した path ID は `open_path` が割り当てず、`create_path_for_peer` も
    /// パスを作成しない。`remove_path` では消えない
    /// (RFC 10069 Section 3.4)。この path ID 向けに保持して
    /// いたピアの preference (`peer_status_pending`) も破棄する。
    pub fn abandon_path_id(&mut self, path_id: PathId) {
        self.abandoned_path_ids.insert(path_id.0);
        // 廃棄した path ID は再作成されないため、保持していたピアの preference は
        // 消費されない。登録時点で破棄する (RFC 10069
        // Section 3.4: 廃棄後の path ID を再利用してはならない)。
        self.peer_status_pending.remove(&path_id.0);
    }

    /// 未開設の path ID 宛に受信したピアの preference を記録する
    ///
    /// 同じ path ID について受信済みと同じかより古いシーケンス番号の通知は
    /// 保持しない (RFC 10069 Section 4.3 の順序判定と同じ扱い)。
    ///
    /// `local_max_path_id` を超える path ID はパスを作成しないため保持しない。
    /// ピアが任意の u32 を送っても `peer_status_pending` が無制限に増えない
    /// ようにするための防御である。廃棄済みの path ID も再作成されないため
    /// 保持しない (RFC 10069 Section 3.4)。
    pub fn record_pending_peer_status(&mut self, path_id: PathId, seq: u64, status: PathStatus) {
        if path_id.0 > self.local_max_path_id {
            return;
        }
        if self.abandoned_path_ids.contains(&path_id.0) {
            return;
        }
        if let Some((prev_seq, _)) = self.peer_status_pending.get(&path_id.0)
            && seq <= *prev_seq
        {
            return;
        }
        self.peer_status_pending.insert(path_id.0, (seq, status));
    }

    /// 未開設の path ID 宛に保持していたピアの preference を取り出す
    pub fn take_pending_peer_status(&mut self, path_id: PathId) -> Option<(u64, PathStatus)> {
        self.peer_status_pending.remove(&path_id.0)
    }

    /// path ID が廃棄済み (tombstone) として登録されているかを返す
    pub fn is_abandoned_path_id(&self, path_id: PathId) -> bool {
        self.abandoned_path_ids.contains(&path_id.0)
    }

    /// 次に割り当てる Path ID が自分の `initial_max_path_id` を超えるかを返す
    ///
    /// 自分の上限が理由でパスを作成できない場合、`PATHS_BLOCKED` は送らない
    /// (RFC 10069 Section 2.1 / Section 7.1)。`PATHS_BLOCKED` は
    /// ピアの上限に達したことをピアへ通知するフレームであり、自分の上限とは
    /// 無関係である。
    pub fn next_path_id_blocked_by_local_limit(&self) -> bool {
        self.next_path_id > self.local_max_path_id
    }

    /// クライアントとして新しいパス ID を払い出す
    ///
    /// 廃棄済み (tombstone) の path ID や、ピアが先に作成した path ID は飛ばす
    /// (RFC 10069 Section 3.4)。
    pub fn open_path(&mut self) -> Result<PathId, Error> {
        // 廃棄済みの path ID は再度割り当てない
        // (RFC 10069 Section 3.4)。飛ばした結果自分の上限を
        // 超える場合は下の検査で拒否される。ピア起点で先に作成されたパスと
        // 同じ path ID も飛ばす。path ID は接続内で再利用できず、同じ PathId の
        // パスを 2 本作ると CID とパケット番号空間の対応が壊れる。
        loop {
            let id = self.next_path_id;
            let duplicated = self.paths.iter().any(|p| p.id == PathId(id));
            if !self.abandoned_path_ids.contains(&id) && !duplicated {
                break;
            }
            if id == u32::MAX {
                return Err(Error::InvalidData("no available path ID left".into()));
            }
            self.next_path_id = id + 1;
        }
        let id = self.next_path_id;
        // 自分の `initial_max_path_id` を超えるパスは維持する意思が無いため
        // 作成しない (RFC 10069 Section 2.1 / Section 7.1)。
        // ピア起点のパス (`create_path_for_peer`) と同じ上限を適用する。
        if id > self.local_max_path_id {
            return Err(Error::InvalidData(format!(
                "path ID {id} exceeds local max path ID {}",
                self.local_max_path_id
            )));
        }
        if id > self.remote_max_path_id {
            return Err(Error::InvalidData(format!(
                "path ID {id} exceeds remote max path ID {}",
                self.remote_max_path_id
            )));
        }
        // 同時パス検証数の制限チェック (Security Considerations)
        let validating_count = self
            .paths
            .iter()
            .filter(|p| p.state == PathState::Pending || p.state == PathState::Validating)
            .count();
        if validating_count >= self.max_concurrent_validations {
            return Err(Error::InvalidData(format!(
                "concurrent path validation limit ({}) reached",
                self.max_concurrent_validations
            )));
        }
        let path_id = PathId(id);
        // u32::MAX を開設したときに next_path_id が overflow しないようにする。
        // 次の呼び出しでは PathId(u32::MAX) が既存パスとして検出され、
        // 利用可能な path ID が無い場合のエラーになる。
        self.next_path_id = self.next_path_id.saturating_add(1);
        // 追加パスの 4-tuple は後で設定される (I/O 層から渡される)
        let initial_path = self.initial_path();
        let remote_addr = initial_path.remote_addr;
        let local_addr = initial_path.local_addr;
        // ピア上限を反映した実効初期 MTU で輻輳制御を作成する。
        // `Path::pmtu` と輻輳制御の初期値が食い違わないようにする。
        let mtu_controller = self.new_mtu_controller();
        let cc = self
            .cc_factory
            .create(u64::from(mtu_controller.current_mtu()));
        self.paths.push(Path::new(
            path_id,
            cc,
            remote_addr,
            local_addr,
            mtu_controller,
        ));
        Ok(path_id)
    }

    /// ピアからの新しいパスを受け入れる (サーバー側)
    ///
    /// クライアントがプロアクティブ CID を使って新パスのパケットを送信した場合、
    /// サーバー側にパスを自動作成する。
    /// (RFC 10069 Section 3.1)
    pub fn create_path_for_peer(&mut self, path_id: PathId) -> Result<(), Error> {
        if self.get(path_id).is_some() {
            return Ok(()); // 既に存在する
        }
        // 廃棄済みの path ID は再度作成しない
        // (RFC 10069 Section 3.4)。遅延到着したパケットで
        // 廃棄済みパスが復活するのを防ぐ。
        if self.abandoned_path_ids.contains(&path_id.0) {
            return Err(Error::InvalidData(format!(
                "path ID {} is already abandoned",
                path_id.0
            )));
        }
        if path_id.0 > self.local_max_path_id {
            return Err(Error::InvalidData(format!(
                "path ID {} exceeds local max path ID {}",
                path_id.0, self.local_max_path_id
            )));
        }
        // 同時パス検証数の制限チェック (RFC 10069 Section 7.1)
        // サーバー側でもクライアント側と同様の制限を適用し、DoS を防ぐ
        let validating_count = self
            .paths
            .iter()
            .filter(|p| p.state == PathState::Pending || p.state == PathState::Validating)
            .count();
        if validating_count >= self.max_concurrent_validations {
            return Err(Error::InvalidData(format!(
                "concurrent path validation limit ({}) reached",
                self.max_concurrent_validations
            )));
        }
        // ピアからの新パスの 4-tuple は受信パケットから設定される
        let initial_path = self.initial_path();
        let remote_addr = initial_path.remote_addr;
        let local_addr = initial_path.local_addr;
        // ピア上限を反映した実効初期 MTU で輻輳制御を作成する。
        let mtu_controller = self.new_mtu_controller();
        let cc = self
            .cc_factory
            .create(u64::from(mtu_controller.current_mtu()));
        self.paths.push(Path::new(
            path_id,
            cc,
            remote_addr,
            local_addr,
            mtu_controller,
        ));
        Ok(())
    }

    /// CID からパスを検索する
    pub fn lookup_by_cid(&self, cid: &ConnectionId) -> Option<PathId> {
        self.cid_to_path.get(cid).copied()
    }

    /// CID とパスの紐付けを登録する
    ///
    /// 既存の登録があっても上書きする。呼び出し側で重複検出が必要な場合は
    /// 事前に `contains_cid` でチェックすること。
    pub fn register_cid(&mut self, cid: ConnectionId, path_id: PathId) {
        self.cid_to_path.insert(cid, path_id);
    }

    /// CID が既に登録されているかを返す
    ///
    /// RFC 10069 Section 3.2.1: "connection IDs cannot be
    /// issued more than once on the same connection". 接続全体の CID 一意性
    /// チェックに使用する。
    pub fn contains_cid(&self, cid: &ConnectionId) -> bool {
        self.cid_to_path.contains_key(cid)
    }

    /// Migration 後のパスの輻輳制御と RTT 推定器を初期状態に戻す
    ///
    /// RFC 9000 Section 9.4 / RFC 10069 Section 5.1:
    /// 4-tuple 変更を伴う migration のパス検証が成功した直後に呼び出す。
    /// 輻輳制御は cc_factory 経由で新規インスタンスを生成して差し替える。
    /// RTT 推定器は `RttEstimator::new()` で初期化する。
    /// loss_detectors の送信済みパケット追跡は引き続き必要なので保持する。
    pub fn reset_cc_and_rtt_for_migration(&mut self, path_id: PathId) -> Result<(), Error> {
        // RFC 9000 Section 14.2 / Section 14.3: 最大データグラムサイズを IP ペア
        // ごとに維持することが求められる。新 4-tuple はまだ未確認であるため、
        // 確認済みサイズを保守的な値へ戻して DPLPMTUD の探索をやり直す。
        let pmtu = {
            let Some(path) = self.get_mut(path_id) else {
                return Err(Error::InvalidData(format!(
                    "path {path_id} not found for migration reset"
                )));
            };
            path.mtu_controller.reset_for_migration();
            path.pmtu = path.mtu_controller.current_mtu();
            path.rtt = RttEstimator::new();
            path.delivery_time_estimate = crate::time::Duration::ZERO;
            path.migration_reset_pending = false;
            path.pmtu
        };
        let new_cc = self.cc_factory.create(u64::from(pmtu));
        let path = self
            .get_mut(path_id)
            .expect("path existence re-checked above");
        path.congestion = new_cc;
        Ok(())
    }

    /// Retry 受信時にパスの回復状態 (輻輳制御・RTT 推定・損失検出) を初期化する
    ///
    /// RFC 9002 Section 6.3: Retry を受信したクライアントは輻輳制御と損失回復の
    /// 状態をリセットし、保留中のタイマーも破棄する。輻輳制御は cc_factory 経由で
    /// 新規インスタンスを生成して差し替えるため、破棄するパケットの
    /// `bytes_in_flight` は新しい CC の初期値 (0) に含まれる。RTT 推定器と
    /// 損失検出器も新規作成し、ECN 検証状態も初期値に戻す。
    pub fn reset_recovery_for_retry(&mut self, path_id: PathId) -> Result<(), Error> {
        // 先に pmtu を借用せずに取得する
        let pmtu = match self.get(path_id) {
            Some(p) => p.pmtu,
            None => {
                return Err(Error::InvalidData(format!(
                    "path {path_id} not found for retry reset"
                )));
            }
        };
        // 新 CC を先に生成してから path を可変借用する (借用規則を満たすため)
        let new_cc = self.cc_factory.create(u64::from(pmtu));
        let path = self
            .get_mut(path_id)
            .expect("path existence re-checked above");
        path.congestion = new_cc;
        path.rtt = RttEstimator::new();
        path.loss_detectors = LossDetectors::new();
        path.delivery_time_estimate = crate::time::Duration::ZERO;
        // RFC 9002 Section 6.3: Retry は新しい接続試行の開始なので ECN 検証も
        // 初期状態からやり直す。前回 flight の ECN カウントを持ち越さない。
        path.ecn_state = EcnValidationState::Testing;
        path.ecn_ect0_sent = 0;
        path.ecn_ect0_lost = 0;
        path.prev_ecn_counts = Default::default();
        Ok(())
    }

    /// CID の紐付けを削除する
    pub fn unregister_cid(&mut self, cid: &ConnectionId) {
        self.cid_to_path.remove(cid);
    }

    /// 利用可能な (Active 状態の) パスをイテレートする
    pub fn active_paths(&self) -> impl Iterator<Item = &Path<F::Controller>> {
        self.paths.iter().filter(|p| p.is_usable())
    }

    /// keep-alive が有効なパスをイテレートする
    ///
    /// タイマーの設定対象を列挙するために使う。実際に PING を送ってよいか
    /// (Active かどうか) は呼び出し側で `Path::is_usable` を使って判定する。
    pub fn keep_alive_paths(&self) -> impl Iterator<Item = &Path<F::Controller>> {
        self.paths.iter().filter(|p| p.keep_alive_enabled())
    }

    /// keep-alive が有効なパスの ID を列挙する
    pub fn keep_alive_path_ids(&self) -> Vec<PathId> {
        self.keep_alive_paths().map(|p| p.id).collect()
    }

    /// 全パスをイテレートする
    pub fn all_paths(&self) -> impl Iterator<Item = &Path<F::Controller>> {
        self.paths.iter()
    }

    /// 全パスを変更可能でイテレートする
    pub fn all_paths_mut(&mut self) -> impl Iterator<Item = &mut Path<F::Controller>> {
        self.paths.iter_mut()
    }

    /// パスを廃棄状態にする
    pub fn abandon_path(&mut self, path_id: PathId) -> Result<(), Error> {
        let path = self
            .get_mut(path_id)
            .ok_or_else(|| Error::InvalidData(format!("path {path_id} not found")))?;
        path.state = PathState::Abandoning;
        Ok(())
    }

    /// パスの数を返す
    pub fn count(&self) -> usize {
        self.paths.len()
    }

    /// 全パスの基準 PTO の最大値を返す
    ///
    /// PTO の基準値はパスごとの RTT 推定値から求める (RFC 9002 Section 6.2.1)。
    /// Application Data 空間では実効 max_ack_delay を加算する必要があるため、
    /// ライフサイクル期限の計算にこの値をそのまま使わず、呼び出し側で実効
    /// max_ack_delay を加算した値を使うこと。
    /// RTT サンプルをまだ受信していないパスは、初期 RTT (333ms) から求めた
    /// 初期 PTO (約 999ms) を使う。パスが 1 つも無い場合も初期 PTO を返す。
    ///
    /// 全パスの中で最大の基準 PTO を選ぶのは、
    /// RFC 10069 Section 2.5 / Section 2.6 の SHOULD に
    /// 対応する。
    pub fn max_pto(&self) -> crate::time::Duration {
        self.paths
            .iter()
            .map(|p| p.rtt.pto())
            .max()
            // PTO を計算できるパスが 1 つも無い場合は初期 PTO を使う
            .unwrap_or_else(|| RttEstimator::new().pto())
    }

    /// アクティブ (非 Abandoned) なパスの数を返す
    pub fn active_path_count(&self) -> usize {
        self.paths
            .iter()
            .filter(|p| p.state != PathState::Abandoned && p.state != PathState::Abandoning)
            .count()
    }

    /// 指定パスの全状態を削除する
    pub fn remove_path(&mut self, path_id: PathId) {
        // CID マッピングを削除する
        let cids_to_remove: Vec<_> = self
            .cid_to_path
            .iter()
            .filter(|&(_, &pid)| pid == path_id)
            .map(|(cid, _)| cid.clone())
            .collect();
        for cid in cids_to_remove {
            self.cid_to_path.remove(&cid);
        }
        // パスを削除する
        self.paths.retain(|p| p.id != path_id);
    }

    /// 全パスのメトリクススナップショットを収集する
    ///
    /// スケジューラーの Context 型に渡すためのヘルパー。
    pub fn collect_metrics(&self) -> Vec<PathMetrics> {
        self.paths.iter().map(|p| p.metrics()).collect()
    }

    /// 全パスの累積カウンタを合計して返す
    pub fn aggregate_stats(&self) -> PathStats {
        let mut total = PathStats::default();
        for path in self.paths.iter() {
            let stats = path.stats();
            total.sent_bytes = total.sent_bytes.saturating_add(stats.sent_bytes);
            total.sent_packets = total.sent_packets.saturating_add(stats.sent_packets);
            total.received_bytes = total.received_bytes.saturating_add(stats.received_bytes);
            total.received_packets = total
                .received_packets
                .saturating_add(stats.received_packets);
            total.lost_packets = total.lost_packets.saturating_add(stats.lost_packets);
            total.retransmitted_packets = total
                .retransmitted_packets
                .saturating_add(stats.retransmitted_packets);
        }
        total
    }

    /// 指定パスを除外して送信先パスを選択する
    ///
    /// PATH_ABANDON の初回送信は、別のオープンパスがあればそこへ送る
    /// (RFC 10069 Section 3.4 の RECOMMENDED)。
    /// 輻輳ウィンドウの制限は適用しない (制御フレームは送信が必須)。
    pub fn select_alt_path(&self, exclude: PathId) -> Option<PathId> {
        self.paths
            .iter()
            .filter(|p| p.id != exclude && p.is_usable())
            .min_by_key(|p| p.rtt.smoothed_rtt)
            .map(|p| p.id)
    }

    /// Active なパスのうち smoothed RTT が最小のものを返す
    ///
    /// RFC 10069 Section 5.5:
    /// PATH_CHALLENGE と PATH_RESPONSE 以外の制御フレームは、任意の
    /// オープンパスで送れる。フレームが指す path ID は送信先の制約ではない。
    /// 候補が無ければ `None` を返す。廃棄済みパスへフォールバックしない。
    pub fn select_open_path(&self) -> Option<PathId> {
        self.paths
            .iter()
            .filter(|p| p.is_usable())
            .min_by_key(|p| p.rtt.smoothed_rtt)
            .map(|p| p.id)
    }
}
