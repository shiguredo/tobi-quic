// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;

use tobi_core::path::controller::PathControlEvent;
use tobi_core::path::state::PathState;
use tobi_core::path::{PathId, PathStatus};
use tobi_core::scheduler::PathMetrics;
use tobi_core::stats::PathStats;

/// パス識別子
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathHandle {
    id: PathId,
}

impl PathHandle {
    pub fn new(id: PathId) -> Self {
        Self { id }
    }

    pub fn id(&self) -> u32 {
        self.id.0
    }

    pub fn raw(&self) -> PathId {
        self.id
    }
}

/// パスのスナップショット
#[derive(Debug, Clone)]
pub struct PathSnapshot {
    pub handle: PathHandle,
    pub state: PathState,
    pub status: PathStatus,
    /// ピアが PATH_STATUS で通知したパスの利用希望 (未通知なら `None`)
    pub peer_path_status: Option<PathStatus>,
    pub smoothed_rtt: std::time::Duration,
    pub min_rtt: std::time::Duration,
    pub latest_rtt: std::time::Duration,
    pub congestion_window: u64,
    pub bytes_in_flight: u64,
    pub pacing_rate: Option<u64>,
    /// 輻輳制御の帯域推定 (bytes/sec、推定を持たないアルゴリズムは None)
    pub bandwidth_estimate: Option<u64>,
    pub pmtu: u16,
    pub is_usable: bool,
    pub pto_count: u32,
    /// パス単位の累積統計
    pub stats: PathStats,
}

impl PathSnapshot {
    pub fn from_metrics(metrics: &PathMetrics) -> Self {
        Self {
            handle: PathHandle::new(metrics.path_id),
            state: metrics.state,
            status: metrics.status,
            peer_path_status: metrics.peer_status,
            smoothed_rtt: std::time::Duration::from_micros(metrics.smoothed_rtt.as_micros()),
            min_rtt: std::time::Duration::from_micros(metrics.min_rtt.as_micros()),
            latest_rtt: std::time::Duration::from_micros(metrics.latest_rtt.as_micros()),
            congestion_window: metrics.congestion_window,
            bytes_in_flight: metrics.bytes_in_flight,
            pacing_rate: metrics.pacing_rate,
            bandwidth_estimate: metrics.bandwidth_estimate,
            pmtu: metrics.pmtu,
            is_usable: metrics.is_usable,
            pto_count: metrics.pto_count,
            stats: metrics.stats,
        }
    }
}

/// ネットワーク変化イベント
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    InterfaceUp {
        name: String,
        addr: SocketAddr,
    },
    InterfaceDown {
        name: String,
        addr: SocketAddr,
    },
    AddressChanged {
        name: String,
        old_addr: SocketAddr,
        new_addr: SocketAddr,
    },
}

impl From<NetworkEvent> for PathControlEvent {
    fn from(value: NetworkEvent) -> Self {
        match value {
            NetworkEvent::InterfaceUp { name, addr } => Self::NetworkInterfaceUp { name, addr },
            NetworkEvent::InterfaceDown { name, addr } => Self::NetworkInterfaceDown { name, addr },
            NetworkEvent::AddressChanged {
                name,
                old_addr,
                new_addr,
            } => Self::NetworkAddressChanged {
                name,
                old_addr,
                new_addr,
            },
        }
    }
}

/// パス関連イベント
#[derive(Debug, Clone)]
pub enum PathEvent {
    Opened {
        path: PathHandle,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    },
    /// パスが閉じた
    ///
    /// パスを閉じても、そのパス専用に用意したソケットは接続の終了まで残る。
    /// 同じローカルアドレスのソケットを他のパスが使っている可能性があり、
    /// 受信タスクを停止する手段も持たないためである。
    Closed {
        path: PathHandle,
    },
    Validated {
        path: PathHandle,
    },
    /// ローカルのパス状態 (Available / Backup) が変わった
    StatusChanged {
        path: PathHandle,
        status: PathStatus,
    },
    /// ピアが PATH_STATUS で通知したパスの利用希望が変わった
    PeerStatusChanged {
        path: PathHandle,
        status: PathStatus,
    },
    /// パスの検証に失敗した
    ///
    /// preferred_address への移行検証の失敗と、パス検証のリトライ上限超過の
    /// 両方を表す。パスはこの後に閉じられる。
    ValidationFailed {
        path: PathHandle,
    },
    Abandoned {
        path: PathHandle,
        error_code: u64,
    },
    Blocked {
        maximum_path_id: u32,
    },
    /// ピアから観測された自分のアドレスを受信した
    /// (draft-ietf-quic-address-discovery-01)
    ObservedAddress {
        path: PathHandle,
        addr: SocketAddr,
    },
}

/// パス作成要求
///
/// `Connection::open_path()` に渡す追加パスのアドレス指定。
/// `local_addr` / `remote_addr` のいずれも `None` の場合、初期パスのアドレスが
/// そのまま使用される (Multipath の 4-tuple 変更なし)。
///
/// RFC 10069 Section 3.1 に基づき、I/O 層は指定されたアドレスで
/// 新パスのパケットを送受信する。片方のみを指定した場合、指定しなかった方は
/// 初期パスの値を継続使用する。
///
/// 追加パスを開く場合、クライアント側の接続では、`local_addr` に具体的な IP と
/// 非 0 ポートを指定したときだけ、そのアドレスにバインドしたソケットを用意する。
/// 次の場合は専用のソケットを用意せず、既存のソケット選択に従うため、実際の
/// 送信元アドレスが指定値と一致しないことがある。
///
/// - ポート 0: 既存のソケット選択に従う。通常は初期ソケットと同じポートに
///   なるが、同じ IP の追加ソケットが既にある場合はそのポートになる
/// - unspecified IP (`0.0.0.0` / `::`): 宛先アドレスファミリでソケットを選ぶ
/// - サーバー側の接続: `open_path` 自体が使用できない (常にエラー)
///
/// IPv4-mapped IPv6 アドレス (`::ffff:a.b.c.d`) は IPv4 アドレスへ正規化されず、
/// `IPV6_V6ONLY` を立てた IPv6 ソケットへのバインドになる。Linux ではこの
/// バインドが `EINVAL` で失敗するため、IPv4 のアドレスを指定すること。
///
/// 専用ソケットは `SO_REUSEADDR` と `SO_REUSEPORT` を設定せずに bind する。
/// wildcard の初期ソケットと同じポートに具体 IP を指定するなど、既存ソケットの
/// 受信範囲と重なる場合は `Error::Io` になる。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NewPath {
    /// 新パスのローカルアドレス (None の場合は初期パスのローカルアドレスを使用)
    pub local_addr: Option<SocketAddr>,
    /// 新パスのリモートアドレス (None の場合は初期パスのリモートアドレスを使用)
    pub remote_addr: Option<SocketAddr>,
}

impl NewPath {
    /// 初期パスのアドレスをそのまま使用するリクエストを作成する
    pub const fn inherit() -> Self {
        Self {
            local_addr: None,
            remote_addr: None,
        }
    }

    /// ローカル / リモート両方のアドレスを指定するリクエストを作成する
    pub const fn with_addrs(local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            local_addr: Some(local_addr),
            remote_addr: Some(remote_addr),
        }
    }

    /// ローカルアドレスだけを指定するリクエストを作成する
    ///
    /// リモートアドレスは初期パスの値を継続使用する。
    pub const fn with_local_addr(local_addr: SocketAddr) -> Self {
        Self {
            local_addr: Some(local_addr),
            remote_addr: None,
        }
    }

    /// リモートアドレスだけを指定するリクエストを作成する
    ///
    /// ローカルアドレスは初期パスの値を継続使用する。
    pub const fn with_remote_addr(remote_addr: SocketAddr) -> Self {
        Self {
            local_addr: None,
            remote_addr: Some(remote_addr),
        }
    }
}
