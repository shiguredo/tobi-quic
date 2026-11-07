// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! QUIC サーバー
//!
//! Sans I/O の Connection を tokio の UdpSocket で駆動する。
//! SO_REUSEPORT + SO_REUSEADDR による 1 ポートマルチスレッド非同期設計。
//!
//! アーキテクチャ:
//! - パケットルーター: 専用タスクで CID ベースのデマルチプレクシング
//! - 接続ごと独立タスク: mpsc チャネル経由でパケットを受信

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::clock::Clock;
use crate::{DEFAULT_CID_LEN, RetryConfig, validate_cid_generator};
use tobi_core::connection::{
    ConnectionCloseFormatter, ConnectionConfig, ConnectionEvent, ConnectionIdGenerator,
    ConnectionObservationEvent, ConnectionOutput, ConnectionState, EndpointLimits,
    StatelessResetTokenGenerator, TimerId,
};
use tobi_core::connection_id::ConnectionId;
use tobi_core::packet::LongPacketType;
use tobi_core::packet::header::{LongHeader, is_long_header};
use tobi_core::path::controller::PathControlEvent;
use tobi_core::path::controller::default::DefaultPathControllerFactory;
use tobi_core::path::{PathId, PathStatus};
use tobi_core::recovery::CongestionControlFactoryImpl;
use tobi_core::scheduler::PathMetrics;
use tobi_core::scheduler::SchedulerFactoryImpl;
use tobi_core::transport_params::{PreferredAddress, TransportParams};
use tobi_qlog::QlogWriterFactory;
use tobi_transport::connection::Connection;
use tobi_transport::stream;

/// アプリケーションがイベントを消費しない場合に備えたキューの上限
///
/// トランスポート側のイベントキューも上限を持つが、プラットフォームが
/// トランスポートのイベントを引き出すため、ここでも上限を設けないと
/// アプリケーションの消費が遅いときにメモリが増え続ける。
const MAX_PENDING_EVENTS: usize = 1024;

/// 観測イベントを上限付きで積む
///
/// アプリが観測イベントを消費しない場合でもメモリが増え続けないよう、
/// 上限を超えたら最も古いイベントを捨てる。
fn push_observation_event(
    queue: &mut VecDeque<ConnectionObservationEvent>,
    event: ConnectionObservationEvent,
) {
    if queue.len() >= MAX_PENDING_EVENTS {
        queue.pop_front();
    }
    queue.push_back(event);
}

/// 送信元 IP ごとのレート制限が保持するエントリ数の上限
///
/// 送信元 IP を偽装した Initial が大量に届いてもメモリが増え続けないよう、
/// 上限を超えたら期限切れを削除し、それでも上限以上なら半分を捨てる。
/// 半分ずつ捨てることで、以降の挿入は償却 O(1) になる。
const MAX_SOURCE_RATE_ENTRIES: usize = 10_000;
use tobi_transport::tls::ServerTlsSession;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use tobi_core::connection::EcnCodepoint;

use crate::config::{BindOptions, PreferredAddressConfig, UdpBatchConfig};
use crate::error::{ConnectionError, Error, StartError, StreamError};
use crate::path::{NetworkEvent, NewPath, PathEvent, PathHandle};

/// accept キューのデフォルト容量
///
/// `Server::accept()` がこの容量を超える速度で呼ばれない場合、あふれた新規
/// Initial は `router_loop` が枠を予約できずに silent discard する
/// (`Server::accept_dropped_count()` で観測できる)。適切な値は accept の
/// 呼び出し頻度と接続バーストの想定サイズに依存するため、
/// `ServerBuilder::with_accept_queue_capacity` で調整できる。
pub const DEFAULT_ACCEPT_QUEUE_CAPACITY: usize = 64;

/// Initial を運ぶ UDP データグラムの最小長 (RFC 9000 Section 14.1)
///
/// サーバーは 1200 バイト未満のデータグラムで運ばれた Initial を破棄する
/// (MUST)。TLS セッションや Connection を作る前に判定する。
const MIN_INITIAL_DATAGRAM_SIZE: usize = 1200;

/// ハンドシェイクタイムアウト時に CONNECTION_CLOSE を送る期限
///
/// 送信自体が詰まる可能性があるため、タイムアウト処理を短い期限で打ち切る。
const HANDSHAKE_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// サーバー CID の長さ (バイト)
/// ルーターから接続へ配送するパケット
struct IncomingPacket {
    data: Vec<u8>,
    from: SocketAddr,
    /// 受信先ローカル IP (IP_PKTINFO から取得)
    local_addr: SocketAddr,
    /// 受信パケットの ECN コードポイント (IP_RECVTOS / IPV6_RECVTCLASS から取得)
    ecn: EcnCodepoint,
}

/// 接続からルーターへの CID マップ操作コマンド
///
/// CID ローテーション時にルーティングテーブルを更新するために使用する。
enum CidMapCommand {
    /// CID をルーティングテーブルに登録する
    Register {
        cid: Vec<u8>,
        tx: mpsc::Sender<IncomingPacket>,
    },
    /// CID をルーティングテーブルから削除する
    Unregister { cid: Vec<u8> },
    /// 接続が終了したので shutdown チャネルを破棄する
    UnregisterConnection { connection_id: u64 },
}

/// 接続からルーターへのソケット受信タスク起動要求
///
/// ソケットプールは router が所有し、受信タスクも router が起動する。
/// 接続がパスの送信でソケットを遅延作成した場合、そのソケットの受信タスクは
/// まだ無い。起動しないとそのソケットで受信したパケットを配送できないため、
/// 接続から router へ起動を依頼する。
enum ReaderCommand {
    /// 渡されたソケットの受信タスクが無ければ起動する
    Ensure { socket: Arc<UdpSocket> },
}

/// ソケットの受信タスクが未起動なら起動する
///
/// 起動済みのソケットは `spawned` に記録して二重起動を防ぐ。二重に起動すると
/// 同じパケットが 2 回配送され、重複パケットとして破棄されるか、
/// 未登録 CID の判定を誤る。
fn ensure_socket_reader(
    socket: &Arc<UdpSocket>,
    spawned: &mut std::collections::HashSet<usize>,
    tx: &mpsc::Sender<RouterInput>,
    udp_batch: Option<UdpBatchConfig>,
) -> bool {
    // ポインタを識別子にする。プールがソケットを保持し続けるため、
    // 生存中のソケットでアドレスが再利用されることはない。
    let key = Arc::as_ptr(socket) as usize;
    if !spawned.insert(key) {
        return false;
    }
    // 受信タスクは router の終了 (packet_rx の閉鎖) で自分から終了する。
    // ハンドルは await せず drop して detached のまま動かす。
    drop(spawn_socket_reader(
        Arc::clone(socket),
        tx.clone(),
        udp_batch,
    ));
    true
}

/// エンドポイントの接続数カウンタ
///
/// router が新規接続を受け入れてよいかを判定するために使う。予約した枠は
/// `ConnectionSlot` が保持し、接続の drop で自動的に解放される。
///
/// 予約を行うのは `router_loop` の 1 タスクだけなので、確認と加算の間に
/// 競合は生じない (解放は接続側のタスクから並行して起きるが、減算のみ)。
struct ConnectionCounters {
    /// ハンドシェイクが完了していない接続数
    inflight_handshakes: Arc<AtomicUsize>,
    /// ハンドシェイク中と確立済みを合わせた接続数
    active_connections: Arc<AtomicUsize>,
    /// 上限超過で破棄した Initial の累計 (運用メトリクス / テスト観測用)
    limit_rejected: Arc<AtomicU64>,
    /// 設定された上限
    limits: EndpointLimits,
}

impl ConnectionCounters {
    fn new(limits: EndpointLimits) -> Self {
        Self {
            inflight_handshakes: Arc::new(AtomicUsize::new(0)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            limit_rejected: Arc::new(AtomicU64::new(0)),
            limits,
        }
    }

    /// 新規接続の枠を予約する
    ///
    /// 上限に達している場合は `None` を返し、破棄したことを記録する。
    /// RFC 9000 Section 21.2 は、リソース枯渇を防ぐために未検証の Initial を
    /// 破棄することを勧めている。
    fn try_reserve(&self) -> Option<ConnectionSlot> {
        if self.inflight_handshakes.load(Ordering::Relaxed) >= self.limits.max_inflight_handshakes {
            self.limit_rejected.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if let Some(max) = self.limits.max_connections
            && self.active_connections.load(Ordering::Relaxed) >= max
        {
            self.limit_rejected.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        self.inflight_handshakes.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        Some(ConnectionSlot {
            inflight_handshakes: Arc::clone(&self.inflight_handshakes),
            active_connections: Arc::clone(&self.active_connections),
            handshaking: true,
        })
    }
}

/// 予約した接続枠
///
/// drop で枠を解放する。ハンドシェイク完了時は `handshake_completed` を呼び、
/// ハンドシェイク中のカウントからのみ外す。
struct ConnectionSlot {
    inflight_handshakes: Arc<AtomicUsize>,
    active_connections: Arc<AtomicUsize>,
    /// まだハンドシェイク中として数えられているか
    handshaking: bool,
}

impl ConnectionSlot {
    /// ハンドシェイク完了を記録する (冪等)
    fn handshake_completed(&mut self) {
        if self.handshaking {
            self.handshaking = false;
            self.inflight_handshakes.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        if self.handshaking {
            self.inflight_handshakes.fetch_sub(1, Ordering::Relaxed);
        }
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// router への graceful shutdown 指示
enum RouterShutdown {
    /// 新規受付を停止し、全接続を閉じて完了を通知する
    Close {
        /// CONNECTION_CLOSE のエラーコード
        error_code: u64,
        /// CONNECTION_CLOSE の理由
        reason: Vec<u8>,
        /// 既存接続への送信完了を通知する
        done: tokio::sync::oneshot::Sender<()>,
    },
}

/// ルーターから接続への graceful shutdown 指示
///
/// router は接続の `packet` チャネルではなくこのチャネルで停止を伝える。
/// アプリケーションが駆動していない接続にも確実に停止を届けるため、
/// パケット経路とは独立した専用チャネルを使う。
#[derive(Debug, Clone)]
pub struct ConnectionShutdown {
    /// CONNECTION_CLOSE のエラーコード (RFC 9000 Section 19.19)
    pub error_code: u64,
    /// CONNECTION_CLOSE の理由
    pub reason: Vec<u8>,
}

/// QUIC サーバー
pub struct QuicServer {
    /// accept チャネルの受信側
    accept_rx: mpsc::Receiver<QuicServerConnection>,
    /// 初期ソケットのローカルアドレス
    local_addr: SocketAddr,
    /// 実際に待ち受けている全アドレス (初期ソケットと追加ソケット)
    local_addrs: Vec<SocketAddr>,
    /// ルータータスクのハンドル
    router_handle: tokio::task::JoinHandle<()>,
    /// graceful shutdown を router へ伝えるチャネル
    shutdown_tx: mpsc::UnboundedSender<RouterShutdown>,
    /// shutdown 済みかどうか (`accept()` がエラーを返すかの判定に使う)
    shutdown: bool,
    /// accept キュー満杯で破棄した接続の累計数 (運用メトリクス / テスト観測用)
    accept_dropped: Arc<AtomicU64>,
    /// router の `cid_map` に登録されている CID の現在数 (運用メトリクス / テスト観測用)
    active_cid_count: Arc<AtomicU64>,
    /// ハンドシェイク中の接続数 (運用メトリクス / テスト観測用)
    inflight_handshakes: Arc<AtomicUsize>,
    /// ハンドシェイク中と確立済みを合わせた接続数 (運用メトリクス / テスト観測用)
    active_connections: Arc<AtomicUsize>,
    /// `EndpointLimits` の上限超過で破棄した Initial の累計 (運用メトリクス / テスト観測用)
    limit_rejected: Arc<AtomicU64>,
}

impl QuicServer {
    /// 指定アドレスにバインドする
    ///
    /// SO_REUSEPORT + SO_REUSEADDR を設定してソケットを作成し、
    /// パケットルータータスクを起動する。
    pub fn bind(addr: SocketAddr, tls_config: Arc<rustls::ServerConfig>) -> Result<Self, Error> {
        Self::bind_with_config(
            addr,
            tls_config,
            ConnectionConfig::default(),
            BindOptions::default(),
        )
    }

    /// 指定アドレスにカスタム設定でバインドする
    ///
    /// `replay_filter` が `Some` の場合、各接続の transport Connection に同一の
    /// `ReplayFilter` を設定する (RFC 9001 Section 9.2)。`None` なら
    /// 0-RTT リプレイチェックは行わない。
    ///
    /// `qlog_factory` が `Some` の場合、新規接続ごとに `factory.create(odcid)`
    /// を呼び出し、返された writer を Connection に装着する。`None` なら qlog は
    /// 完全に無効化される (draft-ietf-quic-qlog-main-schema-14 Section 14.2 の
    /// 「明示的な操作なしに qlog を有効化しない」recommendation に沿ったデフォルト)。
    ///
    /// `close_formatter` が `Some` の場合、各接続の `Connection::close` /
    /// `Connection::close_application` 経路で CONNECTION_CLOSE の reason phrase
    /// 整形に適用される。application close を Initial / Handshake へ 0x1c 変換
    /// して送るときは、RFC 9000 Section 10.2.3 の MUST により reason phrase を
    /// 空にするため整形結果は載らない。`None` の場合は reason バイト列が
    /// そのまま送信される。
    ///
    /// `stateless_reset_generator` が `Some` の場合、各接続の CID 発行で
    /// Stateless Reset Token をこの生成器から得る。`None` の場合は乱数で生成する。
    ///
    /// `cid_generator` が `Some` の場合、新規接続のサーバー CID をこの生成器で
    /// 生成し、Short Header の DCID 抽出にもその CID 長を使う。`None` の場合は
    /// 従来どおり 8 バイトの乱数を生成する。
    ///
    /// 任意の設定は [`BindOptions`] に集約する。`replay_filter` / `qlog_factory` /
    /// `close_formatter` / `stateless_reset_generator` / `cid_generator` /
    /// `retry_config` / `endpoint_limits` / `accept_queue_capacity` /
    /// `handshake_timeout` をそれぞれフィールドで指定する。
    /// `accept_queue_capacity` が `None` の場合は
    /// [`DEFAULT_ACCEPT_QUEUE_CAPACITY`] を使い、`Some(0)` は tokio の mpsc が
    /// panic するため受け付けない (`Error::Internal` を返す)。
    /// `handshake_timeout` が `None` の場合はタイムアウトしない。既定は
    /// [`crate::config::DEFAULT_HANDSHAKE_TIMEOUT`]。
    pub fn bind_with_config(
        addr: SocketAddr,
        tls_config: Arc<rustls::ServerConfig>,
        config: ConnectionConfig,
        options: BindOptions,
    ) -> Result<Self, Error> {
        // 送信するトランスポートパラメータの妥当性を bind 前に検証する
        config
            .transport_params
            .validate_local()
            .map_err(|e| Error::Protocol(format!("invalid transport parameters: {e}")))?;
        // draft-ietf-quic-reliable-stream-reset-11 Section 3:
        // 「サーバーが 0-RTT データを受理する場合、再開接続でこの拡張を
        // 無効化してはならない (MUST NOT)」。TLS の early_data 受理と QUIC の
        // 拡張広告が食い違う構成を起動時に拒否する。
        if tls_config.max_early_data_size > 0 && !config.transport_params.reset_stream_at {
            return Err(StartError::Config(
                "max_early_data_size > 0 requires transport_params.reset_stream_at = true".into(),
            )
            .into());
        }
        let BindOptions {
            versioned_tls_configs,
            replay_filter,
            qlog_factory,
            close_formatter,
            stateless_reset_generator,
            cid_generator,
            retry_config,
            endpoint_limits,
            accept_queue_capacity,
            udp_batch,
            preferred_address,
            token_provider,
            allow_dual_stack,
            reuse_port,
            handshake_timeout,
        } = options;
        // 0 秒のハンドシェイクタイムアウトは即座に打ち切られ、ハンドシェイクが
        // 完了しないため拒否する。
        if let Some(timeout) = handshake_timeout
            && timeout.is_zero()
        {
            return Err(
                StartError::Config("handshake timeout must be greater than zero".into()).into(),
            );
        }
        // RFC 9001 Section 4.6.1: QUIC のサーバーは early_data 拡張の
        // max_early_data_size に 0xffffffff だけを設定できる。クライアントは
        // 他の値を PROTOCOL_VIOLATION として扱うため、起動時に拒否する。
        if tls_config.max_early_data_size != 0 && tls_config.max_early_data_size != u32::MAX {
            return Err(StartError::Config(format!(
                "max_early_data_size must be 0 or 0xffffffff for QUIC, got {}",
                tls_config.max_early_data_size
            ))
            .into());
        }
        // RFC 9001 Section 9.2: 0-RTT を受理するサーバーは、同一セッションチケットを
        // 使ったリプレイを検出できなければならない。フィルター無しで early_data を
        // 有効にすると、冪等でない操作が二重実行される。
        if tls_config.max_early_data_size > 0 && replay_filter.is_none() {
            return Err(StartError::Config(
                "max_early_data_size > 0 requires a 0-RTT replay filter".into(),
            )
            .into());
        }
        // Retry を有効にする場合は鍵の強度を検証する
        if let Some(ref retry) = retry_config {
            retry
                .validate()
                .map_err(|e| StartError::Config(e.to_string()))?;
        }
        // RFC 9000 Section 14 / RFC 8899: MTU 設定を入口で検証する
        config
            .mtu
            .validate()
            .map_err(|e| Error::Protocol(format!("invalid MTU config: {e}")))?;
        // UDP バッチ I/O の設定を入口で検証する
        if let Some(ref batch) = udp_batch {
            batch
                .validate()
                .map_err(|e| Error::Protocol(format!("invalid UDP batch config: {e}")))?;
        }
        // RFC 9000 Section 18.2: preferred_address の設定を入口で検証する
        if let Some(ref preferred) = preferred_address {
            preferred
                .validate()
                .map_err(|e| Error::Protocol(format!("invalid preferred_address: {e}")))?;
        }
        // RFC 9369 Section 5: バージョンごとの TLS 設定を渡す場合、先頭バージョン
        // 以外の全バージョンの設定が揃っている必要がある。先頭バージョンは
        // `tls_config` をフォールバックとして使う。欠けたバージョンで共有
        // `tls_config` にフォールバックすると、バージョン間でチケットが
        // 混ざる可能性がある。
        if let Some(ref configs) = versioned_tls_configs {
            let fallback = config.supported_versions.first().copied();
            for version in &config.supported_versions {
                if Some(*version) == fallback {
                    continue;
                }
                if !configs.contains_key(version) {
                    return Err(StartError::Config(format!(
                        "versioned TLS config is missing QUIC version {version:#010x}"
                    ))
                    .into());
                }
            }
        }
        // RFC 9000 Section 17.2: CID 長は 1..=20
        if let Some(generator) = cid_generator.as_ref() {
            validate_cid_generator(generator.as_ref())?;
        }
        let socket =
            crate::socket::bind_primary_socket_with_reuse_port(addr, udp_batch, reuse_port)
                .map_err(Error::Io)?;
        let socket = Arc::new(socket);
        let local_addr = socket.local_addr()?;
        // パスごとにアドレスファミリが異なりうるため、ソケットプールで管理する。
        // 追加ソケットは別ファミリのパスが要求された時点で遅延作成する。
        let dual_stack = allow_dual_stack || local_addr.ip().is_unspecified();
        let pool = Arc::new(
            crate::socket::SocketPool::new(socket, udp_batch)
                .with_dual_stack(dual_stack)
                .with_reuse_port(reuse_port),
        );

        // デュアルスタックが許可されている場合だけ両方のアドレスファミリで待ち受ける。
        // 特定アドレスへの bind では、指定されたアドレスだけを待ち受ける。
        // バインドできない場合はそのファミリを提供しない縮退動作とする
        // (同じポートを別プロセスが使っている場合など)。
        if dual_stack {
            for ipv6 in [false, true] {
                if let Err(e) = pool.bind_family(ipv6) {
                    tracing::debug!(
                        "server: no {} socket: {}",
                        if ipv6 { "IPv6" } else { "IPv4" },
                        e
                    );
                }
            }
        }
        // preferred_address の port 0 は「実際にバインドしたポート」を意味する。
        // サーバーは両アドレスファミリを同じポートで待ち受けるため、
        // 初期ソケットのポートをそのまま使う。
        let preferred_address =
            preferred_address.map(|config| config.with_bind_port(local_addr.port()));

        // 広告する別ポートも CID ルーターへ接続する。同じポートの具体 IP は
        // 既存の wildcard ソケットで受信できるので、重複して bind しない。
        if let Some(preferred) = preferred_address {
            for addr in [preferred.ipv4, preferred.ipv6].into_iter().flatten() {
                if addr.port() != 0 && addr.port() != local_addr.port() {
                    pool.ensure_socket_for_local_addr(addr).map_err(Error::Io)?;
                }
            }
        }
        let local_addrs = pool.local_addrs().map_err(Error::Io)?;

        // accept キュー容量。0 は tokio の mpsc が panic するため拒否する。
        let accept_queue_capacity = match accept_queue_capacity {
            Some(0) => {
                return Err(Error::Internal(
                    "accept queue capacity must be greater than 0".into(),
                ));
            }
            Some(capacity) => capacity,
            None => DEFAULT_ACCEPT_QUEUE_CAPACITY,
        };
        let (accept_tx, accept_rx) = mpsc::channel(accept_queue_capacity);
        let accept_dropped = Arc::new(AtomicU64::new(0));
        let active_cid_count = Arc::new(AtomicU64::new(0));
        let counters = ConnectionCounters::new(endpoint_limits);
        // 観測用にカウンタを QuicServer 側でも保持する
        let inflight_handshakes = Arc::clone(&counters.inflight_handshakes);
        let active_connections = Arc::clone(&counters.active_connections);
        let limit_rejected = Arc::clone(&counters.limit_rejected);
        let (shutdown_tx, shutdown_rx) = mpsc::unbounded_channel::<RouterShutdown>();

        let router_handle = tokio::spawn(router_loop(
            pool,
            RouterContext {
                tls_config,
                base_config: config,
                options: RouterOptions {
                    replay_filter,
                    qlog_factory,
                    close_formatter,
                    stateless_reset_generator,
                    cid_generator,
                    retry_config,
                    udp_batch,
                    preferred_address,
                    token_provider,
                    versioned_tls_configs,
                    handshake_timeout,
                },
                counters,
                router_counters: RouterCounters {
                    accept_dropped: Arc::clone(&accept_dropped),
                    active_cid_count: Arc::clone(&active_cid_count),
                },
            },
            accept_tx,
            shutdown_rx,
        ));

        tracing::info!("server listening on {}", local_addr);

        Ok(Self {
            accept_rx,
            local_addr,
            local_addrs,
            router_handle,
            shutdown_tx,
            shutdown: false,
            accept_dropped,
            active_cid_count,
            inflight_handshakes,
            active_connections,
            limit_rejected,
        })
    }

    /// 接続を受け付ける
    ///
    /// Initial パケット受信済みの接続を返す。
    /// `handshake()` を呼んでハンドシェイクを完了させること。
    /// 返された接続の `handshake()` は既定で 10 秒のタイムアウトを持つ。
    pub async fn accept(&mut self) -> Result<QuicServerConnection, Error> {
        if self.shutdown {
            return Err(Error::Internal("server is shutting down".into()));
        }
        self.accept_rx
            .recv()
            .await
            .ok_or_else(|| Error::Internal("server closed".into()))
    }

    /// graceful shutdown を実行する (RFC 9000 Section 10.2)
    ///
    /// 1. 新規 Initial の受付を停止する
    /// 2. 既存の全接続へ指定のエラーコードと理由で CONNECTION_CLOSE の送信を指示する
    /// 3. router を停止する
    ///
    /// 各接続の CONNECTION_CLOSE の送信完了は待たない。接続の driver task が
    /// 停止指示を受けて自身で送信する。`timeout` は router の停止処理の上限。
    /// 超過した場合は router を強制終了して戻る (呼び出し側をブロックし続けない
    /// ため)。`None` を渡すと無制限に待つ。二重に呼んだ場合は 2 回目以降を
    /// 何もしない no-op として成功させる。
    pub async fn shutdown(
        &mut self,
        error_code: u64,
        reason: &[u8],
        timeout: Option<std::time::Duration>,
    ) -> Result<(), Error> {
        if self.shutdown {
            return Ok(());
        }
        self.shutdown = true;

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        if self
            .shutdown_tx
            .send(RouterShutdown::Close {
                error_code,
                reason: reason.to_vec(),
                done: done_tx,
            })
            .is_err()
        {
            // router が既に終了している場合は何もしなくてよい
            return Ok(());
        }

        let wait = async {
            let _ = done_rx.await;
            let _ = (&mut self.router_handle).await;
        };
        match timeout {
            Some(duration) => {
                if tokio::time::timeout(duration, wait).await.is_err() {
                    tracing::warn!("graceful shutdown timed out; aborting router");
                    self.router_handle.abort();
                }
            }
            None => wait.await,
        }
        Ok(())
    }

    /// shutdown 済みかどうかを返す
    pub fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    /// 初期ソケットのローカルアドレスを返す
    ///
    /// 追加の待ち受けアドレスは [`Self::local_addrs`] で取得する。
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 実際に待ち受けている全アドレスを返す
    ///
    /// デュアルスタックが有効な場合、初期ソケットと追加ソケットの両方が含まれる。
    /// 利用者が指定した bind 範囲を越えた待ち受けが無いことを確認できる。
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.local_addrs
    }

    /// accept キュー満杯で破棄した接続の累計数を返す
    ///
    /// 運用監視やテスト検証で「backpressure が働いた回数」を観測するためのアクセサ。
    /// `accept()` を呼ばずに新規接続が積み上がった際、router が accept キューの
    /// 枠を予約できずに Initial を破棄した回数がここに反映される。
    pub fn accept_dropped_count(&self) -> u64 {
        self.accept_dropped.load(Ordering::Relaxed)
    }

    /// router の `cid_map` に登録されている CID の現在数を返す
    ///
    /// 運用監視やテスト検証で CID リークを観測するためのアクセサ。
    /// 接続 drop 時に `QuicServerConnection::drop` が全 CID を Unregister するため、
    /// 全接続 drop 後は 0 に戻る。ただし Unregister は router の unbounded channel を
    /// 経由するため、Drop 直後に読むと router 処理待ちのラグでまだ非ゼロが観測される
    /// ことがある (ポーリング前提)。1 接続あたり 1 CID ではなく、Initial DCID +
    /// サーバー CID + プロアクティブ発行 CID + ローテーション後 CID の合算になる点にも注意。
    pub fn active_cid_count(&self) -> u64 {
        self.active_cid_count.load(Ordering::Relaxed)
    }

    /// ハンドシェイク中の接続数を返す
    ///
    /// `EndpointLimits::max_inflight_handshakes` の判定に使う値と同じ。
    /// ハンドシェイクが完了した接続、または drop された接続は含まない。
    pub fn inflight_handshake_count(&self) -> usize {
        self.inflight_handshakes.load(Ordering::Relaxed)
    }

    /// ハンドシェイク中と確立済みを合わせた接続数を返す
    ///
    /// `EndpointLimits::max_connections` の判定に使う値と同じ。
    pub fn active_connection_count(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// `EndpointLimits` の上限超過で破棄した Initial の累計数を返す
    pub fn limit_rejected_count(&self) -> u64 {
        self.limit_rejected.load(Ordering::Relaxed)
    }
}

/// Initial パケットの Token フィールドを取り出す (RFC 9000 Section 17.2.2)
///
/// レイアウト: Long Header 固定部 || Token Length (i) || Token
/// Token が無い場合は空ベクタを返す。
fn extract_initial_token(data: &[u8], header_len: usize) -> Option<Vec<u8>> {
    let rest = data.get(header_len..)?;
    let (len, consumed) = tobi_core::varint::VarInt::decode(rest).ok()?;
    let len = usize::try_from(len.as_u64()).ok()?;
    let start = header_len + consumed;
    let end = start.checked_add(len)?;
    if len == 0 {
        return Some(Vec::new());
    }
    data.get(start..end).map(|t| t.to_vec())
}

/// サーバー CID を生成する
///
/// CID 生成器が設定されていればそれを使い、未設定なら 8 バイトの乱数を生成する。
fn generate_server_cid(
    cid_generator: Option<&Arc<dyn ConnectionIdGenerator>>,
) -> Option<ConnectionId> {
    let bytes = match cid_generator {
        Some(generator) => generator.generate(),
        None => {
            let mut bytes = [0u8; DEFAULT_CID_LEN];
            if aws_lc_rs::rand::fill(&mut bytes).is_err() {
                tracing::error!("router: failed to generate random CID");
                return None;
            }
            bytes.to_vec()
        }
    };
    match ConnectionId::from_slice(&bytes) {
        Ok(cid) => Some(cid),
        Err(e) => {
            tracing::error!("router: CID creation failed: {e}");
            None
        }
    }
}

/// サーバーが広告する preferred_address を構築する
///
/// RFC 9000 Section 18.2: preferred_address は移行先のアドレスに加えて、
/// パス 0 で使う Connection ID と Stateless Reset Token を含む。CID は接続の
/// ローカル CID として登録する必要があるため、transport parameter を
/// エンコードする前に [`generate_server_cid`] で確定させる。
///
/// 広告しないアドレスファミリは未指定アドレスと port 0 を設定する
/// (RFC 9000 Section 18.2 の「利用できないアドレスファミリ」表現)。
fn build_preferred_address(
    config: &PreferredAddressConfig,
    cid_generator: Option<&Arc<dyn ConnectionIdGenerator>>,
    stateless_reset_generator: Option<&Arc<dyn StatelessResetTokenGenerator>>,
) -> Result<PreferredAddress, Error> {
    let connection_id = generate_server_cid(cid_generator)
        .ok_or_else(|| Error::Internal("failed to generate preferred_address CID".into()))?;
    // 生成器が設定されていれば CID から決定的に Token を生成する。
    // 未設定なら乱数で生成する (RFC 9000 Section 10.3.2)。
    let stateless_reset_token = match stateless_reset_generator {
        Some(generator) => generator.generate(connection_id.as_bytes()),
        None => {
            let mut token = [0u8; 16];
            aws_lc_rs::rand::fill(&mut token).map_err(|_| {
                Error::Internal("failed to generate preferred_address reset token".into())
            })?;
            token
        }
    };
    // 広告しないファミリは「利用できないアドレス」として 0 アドレスと port 0 を
    // 設定する (RFC 9000 Section 18.2)。設定値の検証でファミリは保証済みだが、
    // 取り違えても未指定として扱い、不正なアドレスを広告しない。
    let (ipv4_address, ipv4_port) = match config.ipv4 {
        Some(addr) => match addr.ip() {
            std::net::IpAddr::V4(v4) => (v4.octets(), addr.port()),
            std::net::IpAddr::V6(_) => (std::net::Ipv4Addr::UNSPECIFIED.octets(), 0),
        },
        None => (std::net::Ipv4Addr::UNSPECIFIED.octets(), 0),
    };
    let (ipv6_address, ipv6_port) = match config.ipv6 {
        Some(addr) => match addr.ip() {
            std::net::IpAddr::V6(v6) => (v6.octets(), addr.port()),
            std::net::IpAddr::V4(_) => (std::net::Ipv6Addr::UNSPECIFIED.octets(), 0),
        },
        None => (std::net::Ipv6Addr::UNSPECIFIED.octets(), 0),
    };
    Ok(PreferredAddress {
        ipv4_address,
        ipv4_port,
        ipv6_address,
        ipv6_port,
        connection_id,
        stateless_reset_token,
    })
}

/// Stateless Reset の送信レート制限
///
/// RFC 9000 Section 10.3 は未検証のパケットへの応答で増幅攻撃が成立しないよう
/// 注意を求める。ここでは「送信間隔の下限」と「単位時間あたりの上限」の
/// 2 段で制限する。上限に達した場合は Reset を送らずにパケットを破棄する。
struct StatelessResetLimiter {
    /// 直近に送信した時刻
    last_sent: Option<std::time::Instant>,
    /// 現在の観測ウィンドウの開始時刻
    window_start: std::time::Instant,
    /// 現在のウィンドウで送信した回数
    window_count: u32,
}

impl StatelessResetLimiter {
    /// Reset 送信の最小間隔
    const MIN_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);
    /// 観測ウィンドウの長さ
    const WINDOW: std::time::Duration = std::time::Duration::from_secs(1);
    /// ウィンドウあたりの最大送信回数
    const MAX_PER_WINDOW: u32 = 20;

    fn new() -> Self {
        Self {
            last_sent: None,
            window_start: std::time::Instant::now(),
            window_count: 0,
        }
    }

    /// 送信してよいかを判定し、送信する場合は内部状態を更新する
    fn allow(&mut self, now: std::time::Instant) -> bool {
        if now.duration_since(self.window_start) >= Self::WINDOW {
            self.window_start = now;
            self.window_count = 0;
        }
        if let Some(last) = self.last_sent
            && now.duration_since(last) < Self::MIN_INTERVAL
        {
            return false;
        }
        if self.window_count >= Self::MAX_PER_WINDOW {
            return false;
        }
        self.last_sent = Some(now);
        self.window_count += 1;
        true
    }
}

/// 未知 CID の Short Header パケットに対する Stateless Reset を生成する
///
/// RFC 9000 Section 10.3:
/// - Token は CID から決定的に生成する (再起動をまたいで再現できる MUST)
/// - 応答は受信パケットより厳密に小さい (ループ防止 MUST、`generate_stateless_reset` が保証)
/// - 21 バイト未満のパケットには応答しない
///
/// レート制限に達した場合や応答を生成できない場合は `None` を返す。
fn build_stateless_reset_response(
    generator: &dyn StatelessResetTokenGenerator,
    received: &[u8],
    local_cid_len: usize,
    limiter: &mut StatelessResetLimiter,
) -> Option<Vec<u8>> {
    // 未知 CID は先頭バイトの直後から始まる (長さは endpoint 側の CID 長)
    let dcid = received.get(1..1 + local_cid_len)?;
    if dcid.is_empty() {
        return None;
    }
    if !limiter.allow(std::time::Instant::now()) {
        return None;
    }
    let token = generator.generate(dcid);
    tobi_crypto::keys::generate_stateless_reset(&token, received.len())
}

/// パケットから DCID を抽出する
///
/// Long Header: 自己記述的な DCID 長フィールドから取得する。
/// Short Header: 長さフィールドがないため、endpoint が持つ `local_cid_len` を使う
/// (RFC 9000 Section 5.1)。
fn extract_dcid(data: &[u8], local_cid_len: usize) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    if is_long_header(data[0]) {
        // Long Header: byte 5 = DCID 長, bytes 6.. = DCID
        if data.len() < 6 {
            return None;
        }
        let dcid_len = data[5] as usize;
        if data.len() < 6 + dcid_len {
            return None;
        }
        Some(data[6..6 + dcid_len].to_vec())
    } else {
        // Short Header: byte 1 から local_cid_len バイト
        if data.len() < 1 + local_cid_len {
            return None;
        }
        Some(data[1..1 + local_cid_len].to_vec())
    }
}

/// ソケット受信タスクからルーターへ渡す入力
enum RouterInput {
    /// 受信したパケット (宛先 IP を含む)
    Packet(IncomingPacket),
    /// ソケット受信エラー
    RecvError(std::io::Error),
}

/// 共有 UDP ソケットからパケットを読み続け、router へ転送する専用タスクを起動する
///
/// パスごとにソケットが増えうるため、ソケット 1 本につき 1 本起動する。
///
/// `tx` に対応する receiver が drop されたら、受信待ちを打ち切ってタスクを
/// 終了する。タスクが保持する socket の `Arc` はここで解放されるが、FD が解放
/// されるのは他の保持者が無い場合に限る。待ち受けソケットは `SocketPool` が保持
/// しており、接続も同じ pool を共有する。router の終了で router の pool は解放
/// されるが、接続が残っている間はその接続が pool を保持するため FD が残り得る。
/// 個々の接続が drop されても receiver は閉じないため、共有ソケットの受信は
/// 継続する。
///
/// 受信バッファはタスクが所有して使い回す。`udp_batch` で `recvmmsg` を有効に
/// している場合は複数のデータグラムを 1 回のシステムコールで受け取り、GRO で
/// 結合されたデータグラムはセグメント単位に分けてから router へ渡す。router は
/// データグラム先頭の DCID で配送先を決めるため、結合されたままだと同一 4-tuple を
/// 共有する別接続宛のパケットを誤配送する。
///
/// 戻り値は起動したタスクのハンドル。通常の呼び出し側は await せず drop して
/// detached のまま動かし、タスクの終了を待つ必要がある場合だけ保持する。
fn spawn_socket_reader(
    socket: Arc<UdpSocket>,
    tx: mpsc::Sender<RouterInput>,
    udp_batch: Option<UdpBatchConfig>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // バッチ受信・単発受信・GRO の分割は DatagramReceiver にまとめてある
        let mut receiver = crate::socket::DatagramReceiver::new(udp_batch);
        loop {
            tokio::select! {
                // router が receiver を drop して終了したら、受信待ちを打ち切る。
                // ここでタスクを終了すると、タスクが保持するソケットの Arc も
                // drop される。FD は pool など他の保持者が無くなった時点で解放される。
                // 停止要求を優先するため closed() を先に評価する。
                biased;
                _ = tx.closed() => return,
                // 受信の待機中にキャンセルされても、カーネルからまだ受け取って
                // いないデータグラムは失われない。受信済みのデータグラムは
                // この分岐の中で drain して送信し終えてから次を待つ。
                result = receiver.recv(&socket) => {
                    if let Err(e) = result {
                        // 受信エラーの既存挙動を変えない。router へエラーを渡して
                        // 受信を続け、router が既に終了している場合だけ終了する。
                        if tx.send(RouterInput::RecvError(e)).await.is_err() {
                            return;
                        }
                        continue;
                    }
                    for datagram in receiver.drain() {
                        let packet = IncomingPacket {
                            data: datagram.data,
                            from: datagram.remote,
                            local_addr: datagram.local_addr,
                            ecn: datagram.ecn,
                        };
                        if tx.send(RouterInput::Packet(packet)).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    })
}

/// 未処理の CID マップ操作コマンドを全て適用する
///
/// router 停止時に、終了した接続の `Drop` が送出した `Unregister` を
/// 取りこぼすと `cid_map` がリークするため、停止直前にドレインする。
fn drain_cid_map_commands(
    cid_map: &mut HashMap<Vec<u8>, mpsc::Sender<IncomingPacket>>,
    map_cmd_rx: &mut mpsc::UnboundedReceiver<CidMapCommand>,
    active_cid_count: &AtomicU64,
) {
    // shutdown_map は停止後は使わないため、ドレイン中はダミーへ逃がす
    let mut discarded = HashMap::new();
    while let Ok(cmd) = map_cmd_rx.try_recv() {
        apply_cid_map_command(cid_map, &mut discarded, cmd, active_cid_count);
    }
}

/// CID マップ操作コマンドを 1 件適用する
fn apply_cid_map_command(
    cid_map: &mut HashMap<Vec<u8>, mpsc::Sender<IncomingPacket>>,
    shutdown_map: &mut HashMap<u64, mpsc::UnboundedSender<ConnectionShutdown>>,
    cmd: CidMapCommand,
    active_cid_count: &AtomicU64,
) {
    match cmd {
        CidMapCommand::Register { cid, tx } => {
            cid_map.insert(cid, tx);
        }
        CidMapCommand::Unregister { cid } => {
            cid_map.remove(&cid);
            tracing::debug!(cid_len = cid.len(), "router: unregistered CID from cid_map");
        }
        CidMapCommand::UnregisterConnection { connection_id } => {
            shutdown_map.remove(&connection_id);
        }
    }
    active_cid_count.store(cid_map.len() as u64, Ordering::Relaxed);
}

/// `router_loop` が使うオプション設定
///
/// `BindOptions` のうち接続生成に必要なものだけを運ぶ。`endpoint_limits` と
/// `accept_queue_capacity` は `bind_with_config` 側で消費済みのため含まない。
struct RouterOptions {
    replay_filter: Option<Arc<dyn tobi_core::token::ReplayFilter>>,
    qlog_factory: Option<Arc<dyn QlogWriterFactory>>,
    close_formatter: Option<Arc<dyn ConnectionCloseFormatter>>,
    stateless_reset_generator: Option<Arc<dyn StatelessResetTokenGenerator>>,
    cid_generator: Option<Arc<dyn ConnectionIdGenerator>>,
    retry_config: Option<RetryConfig>,
    /// UDP のバッチ I/O の設定。`None` なら 1 データグラムずつ送受信する
    udp_batch: Option<UdpBatchConfig>,
    /// サーバーが広告する preferred_address の設定 (RFC 9000 Section 18.2)
    preferred_address: Option<PreferredAddressConfig>,
    /// NEW_TOKEN のトークン生成・検証に使うプロバイダ (RFC 9000 Section 8.1.3)
    token_provider: Option<Arc<dyn tobi_core::token::TokenProvider>>,
    /// QUIC バージョンごとの TLS 設定 (チケット鍵を分離するため)
    versioned_tls_configs: Option<Arc<std::collections::HashMap<u32, Arc<rustls::ServerConfig>>>>,
    /// ハンドシェイク完了までのタイムアウト
    handshake_timeout: Option<Duration>,
}

/// `router_loop` が更新する観測用カウンタ
///
/// 値は `QuicServer` 側が保持し、router が加算する。`QuicServer` の
/// `accept_dropped_count()` / `active_cid_count()` から読める。
struct RouterCounters {
    /// accept キュー満杯で破棄した接続の累計
    accept_dropped: Arc<AtomicU64>,
    /// router の `cid_map` に登録されている CID の現在数
    active_cid_count: Arc<AtomicU64>,
}

/// `router_loop` のエンドポイント設定と観測用カウンタ
struct RouterContext {
    /// 接続生成に使う TLS 設定
    tls_config: Arc<rustls::ServerConfig>,
    /// 接続生成の基礎になる transport 設定
    base_config: ConnectionConfig,
    /// 接続生成のオプション
    options: RouterOptions,
    /// `EndpointLimits` の予約枠を扱うカウンタ
    counters: ConnectionCounters,
    /// 観測用カウンタ
    router_counters: RouterCounters,
}

/// 送信元 IP ごとのレート制限
///
/// Retry の反射 (RFC 9000 Section 8.1.2) と、同一送信元からの Initial による
/// ハンドシェイク枠の占有 (RFC 9000 Section 21.2) を抑えるために使う。
struct SourceRateLimiter {
    /// 制限の時間窓
    window: Duration,
    /// 時間窓あたりの上限
    max_per_window: u32,
    /// 送信元 IP ごとの (窓の開始時刻, 送信数)
    entries: HashMap<IpAddr, (Instant, u32)>,
}

impl SourceRateLimiter {
    fn new(max_per_window: u32, window: Duration) -> Self {
        Self {
            window,
            max_per_window,
            entries: HashMap::new(),
        }
    }

    /// 送信してよいか判定し、送信数を記録する
    fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        // 既存の送信元なら、エントリ数を増やさずに窓の状態だけを更新する。
        let is_existing = self.entries.contains_key(&ip);
        if !is_existing && self.entries.len() >= MAX_SOURCE_RATE_ENTRIES {
            // 期限切れを削除する。時間窓内のエントリがすべて新しい場合は
            // 削除されないため、続けて半分を捨てて hard cap を守る。
            self.entries
                .retain(|_, (started, _)| now.duration_since(*started) < self.window);
            if self.entries.len() >= MAX_SOURCE_RATE_ENTRIES {
                let mut keep = false;
                self.entries.retain(|_, _| {
                    keep = !keep;
                    keep
                });
            }
        }
        let entry = self.entries.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        if entry.1 >= self.max_per_window {
            return false;
        }
        entry.1 += 1;
        true
    }
}

/// パケットルーターのメインループ
///
/// 全パケットを受信し、CID でデマルチプレクシングして
/// 対応する接続タスクに配送する。
async fn router_loop(
    pool: Arc<crate::socket::SocketPool>,
    context: RouterContext,
    accept_tx: mpsc::Sender<QuicServerConnection>,
    mut shutdown_rx: mpsc::UnboundedReceiver<RouterShutdown>,
) {
    let RouterContext {
        tls_config,
        base_config,
        options,
        counters,
        router_counters,
    } = context;
    let RouterOptions {
        replay_filter,
        qlog_factory,
        close_formatter,
        stateless_reset_generator,
        cid_generator,
        retry_config,
        udp_batch,
        preferred_address: preferred_address_config,
        token_provider,
        versioned_tls_configs,
        handshake_timeout,
    } = options;
    let RouterCounters {
        accept_dropped,
        active_cid_count,
    } = router_counters;
    // 1 つの送信元 IP から 1 秒あたり 100 回まで Retry を返す。NAT 配下の
    // 正規クライアントを巻き込みにくい値にしつつ、反射の増幅を抑える。
    let mut retry_limiter = SourceRateLimiter::new(100, Duration::from_secs(1));
    // 1 つの送信元 IP からの新規 Initial は 1 秒あたり 1000 回までとする。
    // 単一の送信元がハンドシェイク枠を占有し続けるのを防ぐ。
    let mut initial_limiter = SourceRateLimiter::new(1000, Duration::from_secs(1));
    // Short Header の DCID 長は endpoint 側の CID 長で決まる (RFC 9000 Section 5.1)
    let local_cid_len = cid_generator
        .as_ref()
        .map_or(DEFAULT_CID_LEN, |g| g.cid_len());
    // Stateless Reset の送信レート制限 (RFC 9000 Section 10.3 の増幅対策)
    let mut reset_limiter = StatelessResetLimiter::new();
    // DCID -> 接続 task のルーティングテーブル。
    // CID rotation にも追従できるよう接続 task から更新を受ける。
    let mut cid_map: HashMap<Vec<u8>, mpsc::Sender<IncomingPacket>> = HashMap::new();
    let mut shutdown_map: HashMap<u64, mpsc::UnboundedSender<ConnectionShutdown>> = HashMap::new();
    let mut next_connection_id: u64 = 0;
    let (map_cmd_tx, mut map_cmd_rx) = mpsc::unbounded_channel::<CidMapCommand>();
    let (reader_cmd_tx, mut reader_cmd_rx) = mpsc::unbounded_channel::<ReaderCommand>();
    let (packet_tx, mut packet_rx) = mpsc::channel::<RouterInput>(256);
    // プール内の全ソケットの受信タスクを起動する。起動済みソケットを記録し、
    // 接続から起動要求が来ても二重起動しないようにする。
    let mut spawned_readers = std::collections::HashSet::new();
    for socket in pool.sockets() {
        ensure_socket_reader(&socket, &mut spawned_readers, &packet_tx, udp_batch);
    }

    loop {
        tokio::select! {
            biased;

            // graceful shutdown: 新規 Initial の受付を止め、全接続を閉じる
            Some(shutdown) = shutdown_rx.recv() => {
                match shutdown {
                    RouterShutdown::Close { error_code, reason, done } => {
                        tracing::info!(
                            connections = shutdown_map.len(),
                            "router: graceful shutdown requested"
                        );
                        // 各接続の driver task へ停止を伝える。各 task は
                        // CONNECTION_CLOSE を送って自身で終了する。
                        for tx in shutdown_map.values() {
                            let _ = tx.send(ConnectionShutdown {
                                error_code,
                                reason: reason.clone(),
                            });
                        }
                        // 新規 Initial の受付を止める。ここで即 return すると
                        // 接続の Drop が送る Unregister を取りこぼして cid_map が
                        // リークするため、CID マップの更新をドレインしてから終了する。
                        drain_cid_map_commands(&mut cid_map, &mut map_cmd_rx, &active_cid_count);
                        let _ = done.send(());
                        tracing::info!("router: stopped");
                        return;
                    }
                }
            }

            // CID マップの更新を優先処理する
            Some(cmd) = map_cmd_rx.recv() => {
                apply_cid_map_command(&mut cid_map, &mut shutdown_map, cmd, &active_cid_count);
            }

            // 接続が遅延作成したソケットの受信タスクを起動する
            Some(cmd) = reader_cmd_rx.recv() => {
                match cmd {
                    ReaderCommand::Ensure { socket } => {
                        ensure_socket_reader(&socket, &mut spawned_readers, &packet_tx, udp_batch);
                    }
                }
            }

            // ソケット受信タスクから届いたパケットをルーティングする
            Some(input) = packet_rx.recv() => {
                let pkt = match input {
                    RouterInput::Packet(pkt) => pkt,
                    RouterInput::RecvError(e) => {
                        tracing::error!("router recv error: {}", e);
                        continue;
                    }
                };
                let data = &pkt.data;
                let from = pkt.from;
                let recv_local_addr = pkt.local_addr;
                let ecn = pkt.ecn;

                // 既知 CID に一致した packet は既存接続へ配送する。
                if let Some(dcid) = extract_dcid(data, local_cid_len)
                    && let Some(tx) = cid_map.get(&dcid)
                {
                    let _ = tx.try_send(IncomingPacket {
                        data: data.to_vec(),
                        from,
                        local_addr: recv_local_addr,
                        ecn,
                    });
                    continue;
                }

                // 未知 CID の Short Header には Stateless Reset を返す (RFC 9000 Section 10.3)
                //
                // 状態を失った endpoint (再起動・状態破棄) がピアに接続の終了を
                // 伝えるための経路。CID から決定的に Token を生成するため、
                // 再起動をまたいでも同じ Token を再計算できる。
                if data.is_empty() || !is_long_header(data[0]) {
                    if let Some(ref generator) = stateless_reset_generator
                        && let Some(reset) = build_stateless_reset_response(
                            generator.as_ref(),
                            data,
                            local_cid_len,
                            &mut reset_limiter,
                        )
                    {
                        // 送信はルーターの受信ループを止めないよう別タスクで行う。
                        // 受信したのと同じファミリのソケットから返す。
                        // Stateless Reset (RFC 9000 Section 10.3) は接続の ECN 会計
                        // (ACK_ECN) に含まれない応答であるため、NotEct を明示して送る。
                        match pool.socket_for_local(recv_local_addr) {
                            Ok(socket) => {
                                tokio::spawn(async move {
                                    if let Err(e) = crate::socket::send_with_local_addr(
                                        &socket,
                                        &reset,
                                        from,
                                        recv_local_addr,
                                        EcnCodepoint::NotEct,
                                    )
                                    .await
                                    {
                                        tracing::debug!("router: failed to send stateless reset: {e}");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::debug!("router: no socket for stateless reset: {e}");
                            }
                        }
                    } else {
                        tracing::debug!("router: dropping short header for unknown CID");
                    }
                    continue;
                }

                // 未対応バージョンの Long Header には Version Negotiation を返す
                // (RFC 9000 Section 6.1 / Section 17.2.1)。ステートレスに応答でき、
                // 接続状態を生成しない。1200 バイト未満や VN パケットへの応答は
                // `build_response` が除外する (RFC 9000 Section 5.2.2 / Section 6.1)。
                if let Some(response) = tobi_core::packet::version_negotiation::build_response(
                    data,
                    &base_config.supported_versions,
                ) {
                    // 受信パケットのバージョンは Long Header の Version フィールド
                    let unsupported = if data.len() >= 5 {
                        u32::from_be_bytes([data[1], data[2], data[3], data[4]])
                    } else {
                        0
                    };
                    tracing::debug!(
                        "router: sending version negotiation for unsupported version {} ({:#010x})",
                        tobi_core::packet::version_name(unsupported),
                        unsupported
                    );
                    match pool.socket_for_local(recv_local_addr) {
                        Ok(socket) => {
                            tokio::spawn(async move {
                                // Version Negotiation (RFC 9000 Section 17.2.1) は
                                // 接続の ECN 会計 (ACK_ECN) に含まれない応答である。
                                // NotEct を明示して送る。
                                if let Err(e) = crate::socket::send_with_local_addr(
                                    &socket,
                                    &response,
                                    from,
                                    recv_local_addr,
                                    EcnCodepoint::NotEct,
                                )
                                .await
                                {
                                    tracing::debug!(
                                        "router: failed to send version negotiation: {e}"
                                    );
                                }
                            });
                        }
                        Err(e) => {
                            tracing::debug!("router: no socket for version negotiation: {e}");
                        }
                    }
                    continue;
                }

                // RFC 9287 Section 3: ルーターは接続のローカル広告を知らないため、
                // QUIC Bit 0 を許容してデコードする。受信可否の最終判定は
                // 接続側で自分の grease_quic_bit 広告に基づいて行う。
                let hdr = match LongHeader::decode_allow_zero_quic_bit(data) {
                    Ok(hdr) => hdr,
                    Err(e) => {
                        tracing::debug!("router: failed to decode long header: {}", e);
                        continue;
                    }
                };

                // Version Negotiation パケット (Version が 0) はサーバーでは破棄する。
                // VN はクライアントだけが処理する (RFC 9000 Section 6.2)。
                if hdr.version == 0 {
                    tracing::debug!("router: dropping version negotiation packet");
                    continue;
                }

                // サポート外バージョンの小さなパケットは接続を生成せず破棄する
                // (RFC 9000 Section 5.2.2)。1200 バイト以上なら上で VN を返している。
                if !base_config.supported_versions.contains(&hdr.version) {
                    tracing::debug!(
                        "router: dropping unsupported version {:#010x}",
                        hdr.version
                    );
                    continue;
                }

                // 未知 CID を新規接続として扱うのは Initial だけに限定する。
                if hdr.packet_type != LongPacketType::Initial {
                    tracing::debug!("router: dropping non-Initial for unknown CID");
                    continue;
                }

                // RFC 9000 Section 14.1: サーバーは 1200 バイト未満の UDP
                // データグラムで運ばれた Initial を破棄する (MUST)。
                // TLS セッション・Connection・accept 枠を作る前に判定し、
                // 小さな Initial で接続状態を消費しない。Retry も返さない。
                if data.len() < MIN_INITIAL_DATAGRAM_SIZE {
                    tracing::debug!(
                        "router: dropping Initial in a datagram smaller than {MIN_INITIAL_DATAGRAM_SIZE} bytes"
                    );
                    continue;
                }

                // 同一送信元からの新規 Initial のレートを制限する。上限を超えた
                // Initial は応答せずに破棄し、ハンドシェイク枠の占有を防ぐ。
                if !initial_limiter.allow(from.ip(), Instant::now()) {
                    tracing::debug!("router: dropping Initial because rate limit is exceeded");
                    continue;
                }

                // EndpointLimits: 接続数・ハンドシェイク数の上限を超えていたら
                // TLS セッションも Connection も作らずに Initial を破棄する。
                // RFC 9000 Section 21.2 は、リソース枯渇を防ぐために未検証の
                // Initial を破棄することを勧めている。破棄した Initial は
                // ピアが PTO で再送するため、上限が空けばその時点で受理される。
                let Some(connection_slot) = counters.try_reserve() else {
                    tracing::debug!(
                        inflight = counters.inflight_handshakes.load(Ordering::Relaxed),
                        active = counters.active_connections.load(Ordering::Relaxed),
                        "router: dropping Initial due to endpoint limits"
                    );
                    continue;
                };

                // `initial_dcid` は RFC 9000 Section 7.3 の
                // original_destination_connection_id として通知する値
                // (Retry 前の最初の Initial の DCID)。
                let mut initial_dcid = hdr.dcid.clone();
                // Retry の SCID (Retry 後の Initial の DCID でもある)。
                // Initial 鍵の導出に使う DCID は Retry 後の値になる。
                let mut retry_source_cid: Option<ConnectionId> = None;
                let peer_cid = hdr.scid.clone();

                // Retry によるアドレス検証 (RFC 9000 Section 8.1)
                //
                // - Retry が有効で token が無い場合は Retry を返して接続を作らない
                // - token がある場合は検証し、失敗したら Initial を破棄する
                // - 検証成功時は token に埋め込まれた元の DCID を使う
                //   (RFC 9000 Section 7.3: original_destination_connection_id は
                //    Retry 前の最初の Initial の DCID)
                if let Some(ref retry) = retry_config {
                    let token = extract_initial_token(data, hdr.header_len).unwrap_or_default();
                    if token.is_empty() {
                        // 同一送信元 IP からの Retry がレート上限に達している場合は
                        // 応答せずに破棄し、反射攻撃の増幅を抑える。
                        if !retry_limiter.allow(from.ip(), Instant::now()) {
                            tracing::debug!(
                                "router: dropping Initial because retry rate limit is exceeded"
                            );
                            continue;
                        }
                        // token 未検証: Retry を返して切断する
                        let new_scid = match generate_server_cid(cid_generator.as_ref()) {
                            Some(cid) => cid,
                            None => continue,
                        };
                        let retry_token = match tobi_crypto::keys::generate_retry_token_with_scid(
                            &initial_dcid,
                            &new_scid,
                            from,
                            &retry.token_key,
                            hdr.version,
                        ) {
                            Ok(t) => t,
                            Err(e) => {
                                tracing::error!("router: failed to generate retry token: {e}");
                                continue;
                            }
                        };
                        let packet = match tobi_crypto::keys::generate_retry_packet(
                            hdr.version,
                            &initial_dcid,
                            &peer_cid,
                            &new_scid,
                            &retry_token,
                        ) {
                            Ok(p) => p,
                            Err(e) => {
                                tracing::error!("router: failed to generate Retry packet: {e}");
                                continue;
                            }
                        };
                        // 受信したのと同じファミリのソケットから返す
                        match pool.socket_for_local(recv_local_addr) {
                            Ok(socket) => {
                                let local = recv_local_addr;
                                tokio::spawn(async move {
                                    // Retry (RFC 9000 Section 17.2.5) は接続の ECN 会計
                                    // (ACK_ECN) に含まれない応答であるため、NotEct を明示して送る。
                                    if let Err(e) = crate::socket::send_with_local_addr(
                                        &socket,
                                        &packet,
                                        from,
                                        local,
                                        EcnCodepoint::NotEct,
                                    )
                                    .await
                                    {
                                        tracing::debug!("router: failed to send Retry: {e}");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::debug!("router: no socket for Retry: {e}");
                            }
                        }
                        continue;
                    }
                    match tobi_crypto::keys::validate_retry_token_with_scid(
                        &token,
                        from,
                        &retry.token_key,
                        retry.max_age_secs,
                        hdr.version,
                    ) {
                        Ok((odcid, retry_scid)) => {
                            // Retry 前の DCID を original_destination_connection_id に使う
                            initial_dcid = odcid;
                            // RFC 9000 Section 7.3: Retry の SCID を通知する必要がある
                            retry_source_cid = Some(retry_scid);
                        }
                        Err(e) => {
                            tracing::debug!("router: dropping Initial with invalid token: {e}");
                            continue;
                        }
                    }
                }

                // サーバーの CID を決める。
                //
                // Retry 後の Initial では、クライアントは Retry の SCID を DCID に
                // 使う。この SCID をサーバー CID として引き継ぐことで、
                // クライアントの後続パケットが同じ接続にルーティングされる
                // (新たに生成すると DCID が変わり新規接続として扱われる)。
                let server_cid = match retry_source_cid.clone() {
                    Some(cid) => cid,
                    None => {
                        let Some(cid) = generate_server_cid(cid_generator.as_ref()) else {
                            continue;
                        };
                        cid
                    }
                };

                // accept キューの枠を先に予約する。満杯なら TLS セッション構築と
                // Initial の復号を行う前に破棄する。
                //
                // Initial の鍵は DCID から導出できるため (RFC 9001 Section 5.2)、
                // 攻撃者は Initial を送るだけでハンドシェイク完了を待たずに
                // サーバーの CPU を消費できる。満杯時に TLS 生成まで進めてから
                // 破棄すると、その CPU 消費がそのまま攻撃の増幅になる。
                // 予約した枠は Permit が保持し、`permit.send` まで他タスクに
                // 取られないため、予約と投入の間に満杯になることはない。
                let accept_permit = match accept_tx.try_reserve() {
                    Ok(permit) => permit,
                    Err(TrySendError::Full(())) => {
                        accept_dropped.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            from = %from,
                            initial_dcid = ?initial_dcid.as_bytes(),
                            server_cid = ?server_cid.as_bytes(),
                            "router: accept channel full, dropping Initial before TLS setup"
                        );
                        continue;
                    }
                    Err(TrySendError::Closed(())) => {
                        tracing::error!("router: accept channel closed");
                        return;
                    }
                };

                // トランスポートパラメータを設定する
                let mut config = base_config.clone();
                // RFC 9368 Section 2.3: クライアントの最初の Initial に含まれる
                // version_information から互換バージョンを選ぶ。選択には Initial の
                // 復号と ClientHello のトランスポートパラメータの解析が必要なため、
                // 接続を生成する前にステートレスに行う。
                let negotiated_version = if config.supported_versions.len() > 1 {
                    tobi_transport::initial_version::select_compatible_version(
                        data,
                        &config.supported_versions,
                    )
                    .unwrap_or(hdr.version)
                } else {
                    hdr.version
                };
                // 受理した Initial のバージョン、または互換バージョン交渉で選んだ
                // バージョンで接続を作る (RFC 9000 Section 6 / RFC 9368 Section 2.3)。
                config.version = negotiated_version;
                if negotiated_version != hdr.version {
                    // クライアントの最初の flight は Chosen Version で届くため、
                    // そのバージョンの Initial も受信できるようにする。
                    config.compatible_client_version = Some(hdr.version);
                }
                // RFC 9369 Section 4 / RFC 9368 Section 3:
                // version_information をローカル TP に設定する。
                config.apply_version_information(tobi_core::role::Role::Server);
                // RFC 9000 Section 7.3: サーバーは initial_source_connection_id を送信する (MUST)
                config.transport_params.initial_source_connection_id =
                    Some(server_cid.clone());
                // RFC 9000 Section 7.3: サーバーは original_destination_connection_id を送信する (MUST)
                config.transport_params.original_destination_connection_id =
                    Some(initial_dcid.clone());
                // RFC 9000 Section 7.3: Retry を送った場合は retry_source_connection_id を
                // 送信する (MUST)。Retry を送っていない場合は送信してはならない (MUST NOT)。
                config.transport_params.retry_source_connection_id = retry_source_cid.clone();

                // RFC 9000 Section 10.3.1 / Section 18.2: ハンドシェイクで使う
                // Connection ID に対応する Stateless Reset Token を広告する。
                // 生成器が設定されていない場合は、状態を失った後に同じ Token を
                // 再生成できないため広告しない (RFC 9000 Section 18.2)。
                if let Some(generator) = stateless_reset_generator.as_ref() {
                    config.transport_params.stateless_reset_token =
                        Some(generator.generate(server_cid.as_bytes()));
                }

                // RFC 9000 Section 18.2: preferred_address を広告する場合、
                // transport parameter をエンコードする前に CID と
                // Stateless Reset Token を確定させる必要がある。
                let preferred_address = match preferred_address_config.as_ref() {
                    Some(preferred_config) => match build_preferred_address(
                        preferred_config,
                        cid_generator.as_ref(),
                        stateless_reset_generator.as_ref(),
                    ) {
                        Ok(preferred) => {
                            config.transport_params.preferred_address = Some(preferred.clone());
                            Some(preferred)
                        }
                        Err(e) => {
                            tracing::error!(
                                "router: failed to prepare preferred_address: {}",
                                e
                            );
                            None
                        }
                    },
                    None => None,
                };

                let mut tp_buf = Vec::new();
                config.transport_params.encode(&mut tp_buf);

                // TLS セッションを作成する
                // RFC 9369 Section 5: バージョンごとにチケット鍵を分離した
                // TLS 設定があれば、ネゴシエートしたバージョン用の設定を使う。
                // これにより別バージョンで発行されたチケットの再開を拒否する (MUST)。
                let session_tls_config = versioned_tls_configs
                    .as_ref()
                    .and_then(|configs| configs.get(&negotiated_version))
                    .cloned()
                    .unwrap_or_else(|| Arc::clone(&tls_config));
                let tls_session = match ServerTlsSession::new(
                    session_tls_config,
                    negotiated_version,
                    tp_buf,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("router: TLS session creation failed: {}", e);
                        continue;
                    }
                };

                // Sans I/O 接続を作成する (pktinfo から取得したローカルアドレスを使う)
                // RFC 9001 Section 5.2: サーバーはクライアントが Initial を送る際の
                // DCID で Initial 鍵を導出する。Retry 後はクライアントが Retry の SCID を
                // DCID にするため、鍵導出にもその値を使う。
                let key_dcid = retry_source_cid
                    .clone()
                    .unwrap_or_else(|| initial_dcid.clone());
                let cc_factory = config.congestion_control.factory();
                let scheduler_factory = config.scheduler.factory();
                tracing::debug!(
                    data = config.scheduler.data.name(),
                    ack = config.scheduler.ack.name(),
                    retx = config.scheduler.retx.name(),
                    "scheduler configuration"
                );
                let mut conn = match Connection::server(
                    config,
                    tls_session,
                    server_cid.clone(),
                    peer_cid,
                    key_dcid,
                    cc_factory,
                    scheduler_factory,
                    DefaultPathControllerFactory,
                    from,
                    recv_local_addr,
                ) {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::error!("router: connection setup failed: {}", e);
                        continue;
                    }
                };

                // preferred_address の CID を path 0 のローカル CID として登録する。
                // 登録しないと、クライアントが移行後にその CID を宛先に使っても
                // 接続を解決できない。transport parameter はエンコード済みのため、
                // 同じ CID と Stateless Reset Token をそのまま渡す。
                if let Some(preferred) = preferred_address.as_ref()
                    && let Err(e) = conn.set_preferred_address_with_cid(
                        std::net::Ipv4Addr::from(preferred.ipv4_address),
                        preferred.ipv4_port,
                        std::net::Ipv6Addr::from(preferred.ipv6_address),
                        preferred.ipv6_port,
                        preferred.connection_id.clone(),
                        preferred.stateless_reset_token,
                    )
                {
                    tracing::error!("router: failed to register preferred_address CID: {}", e);
                }

                // qlog Factory が設定されていれば writer を装着する。
                // Initial 処理より前 (`conn.receive` の前) に装着することで、
                // 初期状態遷移 (idle -> handshaking) やパケット受信の qlog イベントを取りこぼさない。
                if let Some(writer) = qlog_factory
                    .as_ref()
                    .and_then(|f| f.create(initial_dcid.as_bytes()))
                {
                    conn.set_qlog(writer);
                }

                // サーバー全体で共有する 0-RTT リプレイフィルターを適用する
                if let Some(ref filter) = replay_filter {
                    conn.set_replay_filter(filter.clone());
                }

                // CONNECTION_CLOSE の reason phrase フォーマッタを適用する
                if let Some(ref formatter) = close_formatter {
                    conn.set_close_formatter(Arc::clone(formatter));
                }

                // Stateless Reset Token 生成器を適用する
                if let Some(ref generator) = stateless_reset_generator {
                    conn.set_stateless_reset_generator(Arc::clone(generator));
                }

                // NEW_TOKEN のトークン生成・検証器を適用する。Initial の
                // トークン検証はこの直後の `receive` で行われるため、
                // 受信より前に設定する必要がある (RFC 9000 Section 8.1.3)。
                if let Some(ref provider) = token_provider {
                    conn.set_token_provider(Arc::clone(provider));
                }

                let clock = Clock::new();
                let now = clock.now();

                // Initial パケットを処理する
                // 最初の Initial も ECN 情報を保ったまま渡す。ここで Not-ECT に
                // 置き換えると最初の ACK_ECN が返らず、ピアの ECN 検証が失敗する
                // (RFC 9000 Section 13.4 / Section 13.4.2)。
                if let Err(e) = conn.receive_with_ecn(data, from, recv_local_addr, now, ecn) {
                    tracing::error!("router: failed to process Initial: {}", e);
                    continue;
                }

                // 以後この接続宛 packet は router から channel 経由で届く。
                let (packet_tx, packet_rx) = mpsc::channel(256);
                // graceful shutdown を接続の driver task へ伝えるチャネル
                let (conn_shutdown_tx, conn_shutdown_rx) = mpsc::unbounded_channel();
                let connection_id = next_connection_id;
                next_connection_id += 1;
                shutdown_map.insert(connection_id, conn_shutdown_tx);

                // Initial で使われた DCID と新規 server CID の両方を登録する。
                // accept キュー満杯や正常終了で server_conn が drop されたときは、
                // Drop 実装が active_local_cids に沿って Unregister を送るため、
                // ここで登録した 2 エントリも自動的に rollback される。
                let initial_dcid_bytes = initial_dcid.as_bytes().to_vec();
                let server_cid_bytes = server_cid.as_bytes().to_vec();
                cid_map.insert(initial_dcid_bytes.clone(), packet_tx.clone());
                cid_map.insert(server_cid_bytes.clone(), packet_tx.clone());
                active_cid_count.store(cid_map.len() as u64, Ordering::Relaxed);

                let server_conn = QuicServerConnection {
                    conn,
                    pool: Arc::clone(&pool),
                    reader_cmd_tx: reader_cmd_tx.clone(),
                    packet_rx,
                    peer_addr: from,
                    timers: HashMap::new(),
                    clock,
                    cid_cmd_tx: map_cmd_tx.clone(),
                    packet_tx,
                    active_local_cids: HashSet::from([initial_dcid_bytes, server_cid_bytes]),
                    events: VecDeque::new(),
                    path_events: VecDeque::new(),
                    stop_sending_events: VecDeque::new(),
                    stop_sending_dropped: 0,
                    stop_sending_warned: false,
                    close_reason: None,
                    network_rx: None,
                    connection_id,
                    shutdown_rx: conn_shutdown_rx,
                    connection_slot,
                    udp_batch,
                    observation_enabled: false,
                    observation_events: VecDeque::new(),
                    requested_readers: HashSet::new(),
                    handshake_timeout,
                };

                // 予約した枠へ投入する。`permit.send` は戻り値を持たないため
                // ここでの Closed 判定はできないが、受信側が閉じるのはエンドポイントの
                // 停止時だけであり、その場合は接続も破棄される。
                //
                // 既知トレードオフ: 満杯継続中は Initial ごとに warn! が発火するため
                // ログが線形に増える。サンプリング化は別途扱う。
                accept_permit.send(server_conn);
            }
        }
    }
}

/// QUIC サーバー接続
///
/// accept() で取得後、handshake() でハンドシェイクを完了し、
/// ストリーム API で通信する。
/// 接続ごとに独立したタスクで駆動できる。
pub struct QuicServerConnection {
    /// Sans I/O 接続
    conn: Connection<CongestionControlFactoryImpl, SchedulerFactoryImpl>,
    /// パスごとのローカルアドレスを扱うソケットプール
    ///
    /// デュアルスタック multipath ではアドレスファミリごとにソケットが要る。
    /// プールは router が所有し、全接続で共有する。
    pool: Arc<crate::socket::SocketPool>,
    /// ソケット受信タスクの起動を router へ依頼するチャネル
    ///
    /// パスの送信でソケットを遅延作成したときに、そのソケットの受信タスクを
    /// router に起動してもらう。router が停止している場合は送信に失敗するが、
    /// その時点で接続も終了しているため無視してよい。
    reader_cmd_tx: mpsc::UnboundedSender<ReaderCommand>,
    /// ルーターからのパケット受信チャネル
    packet_rx: mpsc::Receiver<IncomingPacket>,
    /// クライアントアドレス
    peer_addr: SocketAddr,
    /// タイマー管理
    timers: HashMap<TimerId, tobi_core::time::Timestamp>,
    /// クロック
    clock: Clock,
    /// CID マップ操作チャネル
    cid_cmd_tx: mpsc::UnboundedSender<CidMapCommand>,
    /// この接続宛のパケットを受け取る channel の送信側 (CID 追加登録時に使う)
    packet_tx: mpsc::Sender<IncomingPacket>,
    /// 本接続が router の cid_map に登録している CID の集合。
    /// Register/Unregister 経路と初期投入 (initial_dcid / server_cid) で同期的に増減させ、
    /// `Drop` 時にここに残る全 CID を Unregister として router に送出する。
    active_local_cids: HashSet<Vec<u8>>,
    /// 未処理イベント
    events: VecDeque<ConnectionEvent>,
    /// 未処理のパスイベント
    path_events: VecDeque<PathEvent>,
    /// 未処理の STOP_SENDING (stream ID, エラーコード)
    stop_sending_events: VecDeque<(u64, u64)>,
    /// STOP_SENDING キューが満杯で捨てた件数
    stop_sending_dropped: u64,
    /// STOP_SENDING の破棄警告を出したか
    stop_sending_warned: bool,
    /// 接続クローズ情報 (型付き)
    close_reason: Option<ConnectionError>,
    /// NetworkMonitor からのネットワーク変化イベント
    network_rx: Option<mpsc::Receiver<NetworkEvent>>,
    /// router の `shutdown_map` のキー
    connection_id: u64,
    /// graceful shutdown 指示の受信側
    shutdown_rx: mpsc::UnboundedReceiver<ConnectionShutdown>,
    /// `EndpointLimits` の予約枠 (drop で解放される)
    connection_slot: ConnectionSlot,
    /// UDP のバッチ I/O の設定。`None` なら 1 データグラムずつ送受信する
    udp_batch: Option<UdpBatchConfig>,
    /// 観測イベントの記録が有効か
    observation_enabled: bool,
    /// 未処理の観測イベント
    observation_events: VecDeque<ConnectionObservationEvent>,
    /// ソケット受信タスクの起動を依頼済みのソケット
    ///
    /// `SendDatagram` ごとに `ReaderCommand::Ensure` を送ると、router が
    /// 追いつかない場合に unbounded チャネルが伸び続ける。ソケットごとに
    /// 1 回だけ送ることで、コマンド数をソケット数に抑える。
    requested_readers: HashSet<usize>,
    /// ハンドシェイク完了までのタイムアウト
    handshake_timeout: Option<Duration>,
}

impl QuicServerConnection {
    /// ハンドシェイクを完了する
    ///
    /// `handshake_timeout` が設定されている場合、期限を超えると
    /// CONNECTION_CLOSE (NO_ERROR) を送ってから
    /// [`Error::Connection`] の [`ConnectionError::TimedOut`] を返す。
    pub async fn handshake(&mut self) -> Result<(), Error> {
        let Some(timeout) = self.handshake_timeout else {
            return self.drive_handshake().await;
        };
        match tokio::time::timeout(timeout, self.drive_handshake()).await {
            Ok(result) => result,
            Err(_) => {
                // ピアへ終了を伝える。送信自体が詰まる可能性があるため、
                // 短い期限で打ち切る。
                let _ = tokio::time::timeout(
                    HANDSHAKE_CLOSE_TIMEOUT,
                    self.close_with_error(0, b"handshake timeout"),
                )
                .await;
                Err(Error::Connection(ConnectionError::TimedOut))
            }
        }
    }

    /// ハンドシェイク完了までのタイムアウトを設定する
    ///
    /// `None` ならタイムアウトしない。0 を設定した場合は即座にタイムアウトする。
    pub fn set_handshake_timeout(&mut self, timeout: Option<Duration>) {
        self.handshake_timeout = timeout;
    }

    async fn drive_handshake(&mut self) -> Result<(), Error> {
        loop {
            // server 側もまず output を吐き切ってから packet / timer を待つ。
            self.flush_outputs().await?;

            let state = self.conn.state();
            tracing::debug!("server handshake state: {:?}", state);

            if state == ConnectionState::Connected {
                // EndpointLimits のハンドシェイク中カウントから外す
                self.connection_slot.handshake_completed();
                return Ok(());
            }

            if matches!(
                state,
                ConnectionState::Closing | ConnectionState::Draining | ConnectionState::Closed
            ) {
                return Err(Error::Protocol(format!(
                    "connection closed during handshake: {:?}",
                    state
                )));
            }

            self.wait_and_process().await?;
        }
    }

    /// 未送信フレームを生成して送信する
    ///
    /// transport が保持する保留フレーム (ACK / MAX_DATA / MAX_STREAM_DATA /
    /// PATH_STATUS / RESET_STREAM / STOP_SENDING 等) をパケット化してから
    /// 出力キューを送信する。コマンド処理で生成された出力を次のパケット受信まで
    /// 滞留させないため、command driver はコマンド処理後にこれを呼ぶ。
    pub async fn flush_pending(&mut self) -> Result<(), Error> {
        let now = self.clock.now();
        self.conn
            .flush(now)
            .map_err(|e| Error::Protocol(format!("flush failed: {e}")))?;
        self.flush_outputs().await
    }

    /// 出力キューをフラッシュする
    pub async fn flush_outputs(&mut self) -> Result<(), Error> {
        // アプリへ届くイベントを先にキューへ移す。パス検証の失敗では
        // `PathValidationFailed` イベントが `PathClosed` 出力より先に生成される
        // ため、出力を先に処理するとアプリへ届く順序が逆になる。
        self.enqueue_events();
        // まとめて送れる SendDatagram を溜める。バッチが無効な場合や送信先が
        // 変わる場合は、溜めた時点で送る (溜めるのは PendingSend の組み立てだけ)。
        let mut pending = crate::socket::PendingSends::new();
        loop {
            let output = match self.conn.poll_output(self.clock.now()) {
                Ok(Some(output)) => output,
                Ok(None) => break,
                Err(error) => {
                    // poll 中の終了理由と観測を回収し、準備済みの正常な出力を送る。
                    self.enqueue_events();
                    self.enqueue_observations();
                    pending.flush(self.udp_batch).await.map_err(Error::Io)?;
                    return Err(Error::Protocol(format!(
                        "output preparation failed: {error}"
                    )));
                }
            };
            match output {
                ConnectionOutput::SendDatagram {
                    data,
                    path_id,
                    remote_addr,
                    local_addr,
                    ecn,
                } => {
                    tracing::debug!(
                        "send {} bytes, first=0x{:02x}, path={:?}, local={}, remote={}",
                        data.len(),
                        data[0],
                        path_id,
                        local_addr,
                        remote_addr,
                    );
                    // パスの 4-tuple の両方に合うソケットを選ぶ。migration で
                    // アドレスファミリが変わったパスに、以前のファミリの
                    // ソケットを使い回すと送信できない。
                    let socket = match self.pool.socket_for_path(local_addr, remote_addr) {
                        Ok(socket) => socket,
                        Err(e) => {
                            // 送信先のソケットを選べない場合も、溜めていた分は送ってから
                            // エラーを返す (取りこぼしを増やさない)。
                            pending.flush(self.udp_batch).await.map_err(Error::Io)?;
                            return Err(Error::Io(e));
                        }
                    };
                    // 遅延作成されたソケットの受信タスク起動を router に依頼する。
                    // 起動しないと、そのソケットで受信したパケットを配送できない。
                    // 同じソケットには 1 回だけ依頼する。SendDatagram ごとに送ると、
                    // router が追いつかないときに unbounded チャネルが伸び続ける。
                    let socket_key = Arc::as_ptr(&socket) as usize;
                    if self.requested_readers.insert(socket_key) {
                        let _ = self.reader_cmd_tx.send(ReaderCommand::Ensure {
                            socket: Arc::clone(&socket),
                        });
                    }
                    // これ以上まとめられない場合と、溜めすぎた場合は push の中で送られる
                    pending
                        .push(
                            crate::socket::PendingSend::new(
                                socket,
                                data,
                                remote_addr,
                                local_addr,
                                ecn,
                            ),
                            self.udp_batch,
                        )
                        .await
                        .map_err(Error::Io)?;
                }
                ConnectionOutput::SetTimer { id, deadline } => {
                    tracing::trace!("set timer {:?} deadline={:?}", id, deadline);
                    self.timers.insert(id, deadline);
                }
                ConnectionOutput::ClearTimer { id } => {
                    tracing::trace!("clear timer {:?}", id);
                    self.timers.remove(&id);
                }
                ConnectionOutput::PathOpened {
                    path_id,
                    local_addr,
                    remote_addr,
                } => {
                    tracing::debug!(
                        "path opened: path={:?} local={} remote={}",
                        path_id,
                        local_addr,
                        remote_addr
                    );
                    if self.path_events.len() < MAX_PENDING_EVENTS {
                        self.path_events.push_back(PathEvent::Opened {
                            path: PathHandle::new(path_id),
                            local_addr,
                            remote_addr,
                        });
                    }
                    // IP_PKTINFO で送信元 IP を制御するため、パスごとのソケットは不要
                }
                ConnectionOutput::PathClosed { path_id } => {
                    tracing::debug!("path closed: path={:?}", path_id);
                    if self.path_events.len() < MAX_PENDING_EVENTS {
                        self.path_events.push_back(PathEvent::Closed {
                            path: PathHandle::new(path_id),
                        });
                    }
                    // ソケットは router が全接続で共有するため、パスを閉じても
                    // 個別に閉じない。
                }
                ConnectionOutput::RegisterLocalCid { cid, path_id } => {
                    // Sans I/O が NEW_CONNECTION_ID / PATH_NEW_CONNECTION_ID で
                    // 発行した CID をルーターの CID マップに登録する。
                    // active_local_cids にも同時に反映することで、Drop 時の Unregister 一括発行に含める。
                    let cid_bytes = cid.as_bytes().to_vec();
                    tracing::debug!(
                        "register local CID path={:?} len={}",
                        path_id,
                        cid_bytes.len()
                    );
                    self.active_local_cids.insert(cid_bytes.clone());
                    let _ = self.cid_cmd_tx.send(CidMapCommand::Register {
                        cid: cid_bytes,
                        tx: self.packet_tx.clone(),
                    });
                }
                ConnectionOutput::UnregisterLocalCid { cid } => {
                    // RETIRE_CONNECTION_ID / PATH_RETIRE_CONNECTION_ID で
                    // リタイアした CID をルーターの CID マップから削除する。
                    let cid_bytes = cid.as_bytes().to_vec();
                    tracing::debug!("unregister local CID len={}", cid_bytes.len());
                    self.active_local_cids.remove(&cid_bytes);
                    let _ = self
                        .cid_cmd_tx
                        .send(CidMapCommand::Unregister { cid: cid_bytes });
                }
            }
        }
        // PN 上限など、poll 自体が生成した終了イベントも回収する。
        self.enqueue_events();
        self.enqueue_observations();
        pending.flush(self.udp_batch).await.map_err(Error::Io)?;
        Ok(())
    }

    /// 観測イベントの記録を有効化・無効化する
    ///
    /// アプリケーションがイベントを購読したときだけ有効化する。
    pub fn set_observation_enabled(&mut self, enabled: bool) {
        self.observation_enabled = enabled;
        self.conn.set_observation_enabled(enabled);
        if !enabled {
            self.observation_events.clear();
        }
    }

    /// 観測イベントを 1 件取り出す
    pub fn poll_observation_event(&mut self) -> Option<ConnectionObservationEvent> {
        self.observation_events.pop_front()
    }

    /// transport の観測イベントをアプリ側のキューへ移す
    fn enqueue_observations(&mut self) {
        if !self.observation_enabled {
            return;
        }
        while let Some(event) = self.conn.poll_observation_event() {
            push_observation_event(&mut self.observation_events, event);
        }
    }

    /// パケット受信またはタイマー発火を待って処理する
    /// Pacing タイマーが残っているかを返す
    ///
    /// 命令駆動 driver (background 無効) で、送信完了までタイマーを
    /// 処理すべきかの判定に使う。
    pub fn has_pending_pacing_timer(&self) -> bool {
        self.timers
            .keys()
            .any(|id| matches!(id, TimerId::Pacing { .. }))
    }

    pub async fn wait_and_process(&mut self) -> Result<(), Error> {
        // server connection は router から packet を受けるため、
        // 共有ソケットではなく packet channel と timer を待つ。
        let next_deadline = self
            .timers
            .values()
            .min()
            .copied()
            .map(|ts| self.clock.to_tokio_instant(ts));

        // timer が空の区間は packet と network event だけを待つ
        let timer = async {
            match next_deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };

        // NetworkMonitor が無効な場合は pending で待機対象にしない
        let network = async {
            match self.network_rx.as_mut() {
                Some(rx) => rx.recv().await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            // パケットとタイマーが同時に準備できたとき、タイマー優先だと
            // アイドル期限が先に発火してハンドシェイクが潰れることがあるため、受信を優先する。
            biased;
            packet = self.packet_rx.recv() => {
                let packet = packet.ok_or_else(|| Error::Internal("router closed".into()))?;
                tracing::debug!(
                    "recv {} bytes from {}, local={}, first=0x{:02x}",
                    packet.data.len(),
                    packet.from,
                    packet.local_addr,
                    packet.data[0]
                );
                let now = self.clock.now();
                if let Err(e) = self.conn.receive_with_ecn(
                    &packet.data,
                    packet.from,
                    packet.local_addr,
                    now,
                    packet.ecn,
                ) {
                    tracing::error!("receive error: {}", e);
                }
                // このパケットでハンドシェイクが完了した可能性がある
                self.mark_handshake_completed_if_connected();
                // パケット受信で生成された ACK 等を即座に送信する
                self.flush_outputs().await?;
            }
            _ = timer => {
                tracing::debug!("timer expired, state={:?}", self.conn.state());
                self.fire_expired_timers();
                self.flush_outputs().await?;
            }
            event = network => {
                if let Some(event) = event {
                    tracing::debug!("network event: {:?}", event);
                    let now = self.clock.now();
                    self.conn.on_network_event(PathControlEvent::from(event), now);
                    self.flush_outputs().await?;
                }
            }
        }
        // flush_outputs() 内で enqueue_events() が呼ばれるため追加の呼び出しは不要
        Ok(())
    }

    /// 期限切れタイマーを発火する
    fn fire_expired_timers(&mut self) {
        let now = self.clock.now();
        let expired: Vec<TimerId> = self
            .timers
            .iter()
            .filter(|(_, deadline)| now >= **deadline)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.timers.remove(&id);
            let _ = self.conn.handle_timer(id, now);
        }
    }

    fn enqueue_events(&mut self) {
        while let Some(event) = self.conn.poll_event() {
            // ConnectionEvent を queue 化し、
            // accept 系 API が pull 型で扱えるようにする。
            match &event {
                ConnectionEvent::ConnectionClosed {
                    error_code,
                    reason,
                    kind,
                } => {
                    let error =
                        ConnectionError::from_close_event(*error_code, reason.clone(), *kind);
                    match crate::close_log::close_log_level(&error) {
                        crate::close_log::CloseLogLevel::Debug => tracing::debug!(
                            "ConnectionClosed error_code=0x{:x} kind={:?} reason={}",
                            error_code,
                            kind,
                            crate::error::sanitize_reason_for_log(reason)
                        ),
                        crate::close_log::CloseLogLevel::Info => tracing::info!(
                            "ConnectionClosed error_code=0x{:x} kind={:?} reason={}",
                            error_code,
                            kind,
                            crate::error::sanitize_reason_for_log(reason)
                        ),
                        crate::close_log::CloseLogLevel::Warn => tracing::warn!(
                            "ConnectionClosed error_code=0x{:x} kind={:?} reason={}",
                            error_code,
                            kind,
                            crate::error::sanitize_reason_for_log(reason)
                        ),
                    }
                    self.close_reason = Some(error);
                }
                _ => {
                    tracing::debug!("event {:?}", event);
                }
            }
            // アプリケーションがイベントを消費しない場合でもメモリを増やし続けない
            // よう、プラットフォーム側のキューにも上限を設ける。上限超過時は
            // 新しいイベントを破棄する。接続終了の理由は `close_reason` に
            // 別途記録されるため、イベントを捨てても失われない。
            if let Some(path_event) = Self::path_event_from(&event)
                && self.path_events.len() < MAX_PENDING_EVENTS
            {
                // path 系イベントは `path_events` から `accept_path_event` で
                // 取り出す。`self.events` へは積まない。
                self.path_events.push_back(path_event);
            }
            if let Some(stop_sending) = Self::stop_sending_from(&event) {
                // STOP_SENDING は `accept_stop_sending_now` で取り出す。汎用の
                // `self.events` を占有して他のイベントを締め出さないよう、
                // 専用キューへ積む。溢れた分は捨てて件数を数える。
                let dropped = crate::stop_sending::enqueue_stop_sending_events(
                    &mut self.stop_sending_events,
                    std::iter::once(stop_sending),
                    MAX_PENDING_EVENTS,
                );
                if dropped > 0 {
                    self.stop_sending_dropped = self.stop_sending_dropped.saturating_add(dropped);
                    let warned = crate::stop_sending::next_stop_sending_warn_state(
                        true,
                        self.stop_sending_events.is_empty(),
                        self.stop_sending_warned,
                    );
                    if !self.stop_sending_warned && warned {
                        tracing::warn!(
                            "stop_sending queue is full; dropping notifications. Check ConnectionStats::stop_sending_dropped"
                        );
                    }
                    self.stop_sending_warned = warned;
                }
            }
            if Self::is_enqueue_target(&event) && self.events.len() < MAX_PENDING_EVENTS {
                self.events.push_back(event);
            }
        }
    }

    /// path 系イベントを `PathEvent` に変換する
    ///
    /// path 系イベントは `path_events` から `accept_path_event` で取り出す。
    /// `self.events` へは積まない。
    fn path_event_from(event: &ConnectionEvent) -> Option<PathEvent> {
        match event {
            ConnectionEvent::PathValidated { path_id } => Some(PathEvent::Validated {
                path: PathHandle::new(*path_id),
            }),
            ConnectionEvent::PathValidationFailed { path_id } => {
                Some(PathEvent::ValidationFailed {
                    path: PathHandle::new(*path_id),
                })
            }
            ConnectionEvent::PathStatusChanged { path_id, status } => {
                Some(PathEvent::StatusChanged {
                    path: PathHandle::new(*path_id),
                    status: *status,
                })
            }
            ConnectionEvent::PeerPathStatusChanged { path_id, status } => {
                Some(PathEvent::PeerStatusChanged {
                    path: PathHandle::new(*path_id),
                    status: *status,
                })
            }
            ConnectionEvent::PathAbandoned {
                path_id,
                error_code,
            } => Some(PathEvent::Abandoned {
                path: PathHandle::new(*path_id),
                error_code: *error_code,
            }),
            ConnectionEvent::PathsBlocked { maximum_path_id } => Some(PathEvent::Blocked {
                maximum_path_id: *maximum_path_id,
            }),
            ConnectionEvent::ObservedAddress { path_id, addr } => {
                Some(PathEvent::ObservedAddress {
                    path: PathHandle::new(*path_id),
                    addr: *addr,
                })
            }
            _ => None,
        }
    }

    /// STOP_SENDING イベントを専用キューの要素へ変換する
    ///
    /// STOP_SENDING は `accept_stop_sending_now` で取り出すため、汎用の
    /// `self.events` を占有しないよう専用キューへ配送する。
    fn stop_sending_from(event: &ConnectionEvent) -> Option<(u64, u64)> {
        match event {
            ConnectionEvent::StreamStopSending {
                stream_id,
                error_code,
            } => Some((*stream_id, *error_code)),
            _ => None,
        }
    }

    /// イベントが `self.events` に積む対象かどうかを返す
    ///
    /// `take_event` の述語で取り出せるイベントだけを対象にする。取り出す手段が
    /// 無いイベントを積むと、ピアがフレームを送るほどキューが増え続ける。
    fn is_enqueue_target(event: &ConnectionEvent) -> bool {
        matches!(
            event,
            ConnectionEvent::NewStream { .. }
                // 読み書きの可否とリセット理由は transport の状態から判定する。
                // 再試行は受信進捗で起こすため、可読・書き込み可能・リセットの
                // 通知は保持しない。STOP_SENDING は専用の stop_sending_events
                // キューで保持する。
                | ConnectionEvent::DatagramReceived { .. }
                | ConnectionEvent::NewToken { .. }
                | ConnectionEvent::SessionTicketReceived
                | ConnectionEvent::ZeroRttRejected
        )
    }

    fn take_event<F>(&mut self, predicate: F) -> Option<ConnectionEvent>
    where
        F: FnMut(&ConnectionEvent) -> bool,
    {
        let index = self.events.iter().position(predicate)?;
        self.events.remove(index)
    }

    fn take_path_event(&mut self) -> Option<PathEvent> {
        self.path_events.pop_front()
    }

    fn take_stop_sending(&mut self) -> Option<(u64, u64)> {
        let event = self.stop_sending_events.pop_front();
        self.stop_sending_warned = crate::stop_sending::next_stop_sending_warn_state(
            false,
            self.stop_sending_events.is_empty(),
            self.stop_sending_warned,
        );
        event
    }

    /// 双方向ストリームを開く
    ///
    /// # エラー
    ///
    /// - ピアが許可した上限に達している場合は [`Error::StreamLimitReached`]。
    ///   接続は閉じず、ピアから MAX_STREAMS を受信した後に再試行できる
    /// - 接続が閉鎖中の場合は [`Error::Connection`]
    /// - それ以外は [`Error::Protocol`]。transport 層のエラーに操作の文脈を
    ///   付けたものである
    pub fn open_stream_bidi(&mut self) -> Result<u64, Error> {
        self.conn
            .open_stream_bidi()
            .map_err(|e| self.map_connection_error(e, "open stream failed"))
    }

    pub fn accept_bidirectional_stream_now(&mut self) -> Result<u64, Error> {
        if let Some(ConnectionEvent::NewStream { stream_id }) = self.take_event(
            |event| matches!(event, ConnectionEvent::NewStream { stream_id } if stream::is_bidirectional(*stream_id)),
        ) {
            Ok(stream_id)
        } else {
            Err(Error::Internal("bidirectional stream not ready".into()))
        }
    }

    pub fn accept_receive_stream_now(&mut self) -> Result<u64, Error> {
        if let Some(ConnectionEvent::NewStream { stream_id }) = self.take_event(|event| {
            matches!(event, ConnectionEvent::NewStream { stream_id }
                if !stream::is_bidirectional(*stream_id) && stream::is_client_initiated(*stream_id))
        }) {
            Ok(stream_id)
        } else {
            Err(Error::Internal("receive stream not ready".into()))
        }
    }

    /// 種別不問でストリームを受け入れる
    ///
    /// 返り値: (stream_id, is_bidirectional)
    pub fn accept_stream_now(&mut self) -> Result<(u64, bool), Error> {
        if let Some(ConnectionEvent::NewStream { stream_id }) =
            self.take_event(|event| matches!(event, ConnectionEvent::NewStream { .. }))
        {
            Ok((stream_id, stream::is_bidirectional(stream_id)))
        } else {
            Err(Error::Internal("stream not ready".into()))
        }
    }

    /// 単方向ストリームを開く
    ///
    /// # エラー
    ///
    /// [`Self::open_stream_bidi`] と同じ。上限到達は
    /// [`Error::StreamLimitReached`]、閉鎖中は [`Error::Connection`]、それ以外は
    /// [`Error::Protocol`] になる。
    pub fn open_stream_uni(&mut self) -> Result<u64, Error> {
        self.conn
            .open_stream_uni()
            .map_err(|e| self.map_connection_error(e, "open uni stream failed"))
    }

    /// ピアが許可した双方向ストリームの残枠を返す
    ///
    /// ピアの累積許可数から、ローカルが既に開いた数を引いた値。許可数は接続の
    /// 生存期間における累積値であり、ストリームを閉じても残枠は戻らない
    /// (RFC 9000 Section 19.11)。ピアから MAX_STREAMS を受信すると増える。
    ///
    /// 返り値は参照時点の値であり、後続の [`Self::open_stream_bidi`] に対する
    /// 予約ではない。ハンドシェイク完了までは 0 を返し得る。
    pub fn remaining_bidi_streams(&self) -> u64 {
        self.conn.remaining_bidi_streams()
    }

    /// ピアが許可した単方向ストリームの残枠を返す
    ///
    /// [`Self::remaining_bidi_streams`] の単方向版。残枠の意味と、返り値が
    /// 参照時点の値であることは同じ。
    pub fn remaining_uni_streams(&self) -> u64 {
        self.conn.remaining_uni_streams()
    }

    /// ピアが起動できる双方向ストリームの累積上限を引き上げ、MAX_STREAMS を送る
    ///
    /// RFC 9000 Section 19.11: MAX_STREAMS はピアが接続の生存期間に開ける
    /// 累積数を通知する。現在の上限以下の値は広告しても効果がないため無視し、
    /// フレームを送らずに `Ok(())` を返す (同 Section 4.6 / Section 19.11)。
    ///
    /// [`Self`] には現在広告している上限を取得する API がないため、値が適用
    /// されたかを呼び出し側で確認できない。現在の上限は transport の
    /// `StreamManager::local_max_streams_bidi` が保持しており、公開 API からは
    /// 観測できない。現在値と同じ値や小さい値を渡してもエラーにせず、何も送ら
    /// ない (silent no-op)。
    ///
    /// # エラー
    ///
    /// - 2^60 を超える値は [`Error::Protocol`] (2^60 は受理する)
    /// - 接続が確立していない場合も [`Error::Protocol`]
    /// - 接続が閉鎖中の場合は [`Error::Connection`]
    ///
    /// 送信できた場合は出力をフラッシュしてから戻る。
    pub async fn set_max_streams_bidi(&mut self, maximum_streams: u64) -> Result<(), Error> {
        let now = self.clock.now();
        self.conn
            .set_max_streams_bidi(maximum_streams, now)
            .map_err(|e| self.map_connection_error(e, "set max streams bidi failed"))?;
        self.flush_outputs().await
    }

    /// ピアが起動できる単方向ストリームの累積上限を引き上げ、MAX_STREAMS を送る
    ///
    /// [`Self::set_max_streams_bidi`] の単方向版。現在の上限以下の値を無視して
    /// `Ok(())` を返す点、現在値を取得する API がない点、エラーの条件も同じ。
    /// 現在の上限は transport の `StreamManager::local_max_streams_uni` が
    /// 保持している。
    pub async fn set_max_streams_uni(&mut self, maximum_streams: u64) -> Result<(), Error> {
        let now = self.clock.now();
        self.conn
            .set_max_streams_uni(maximum_streams, now)
            .map_err(|e| self.map_connection_error(e, "set max streams uni failed"))?;
        self.flush_outputs().await
    }

    /// ストリームをリセットする (RESET_STREAM フレームを送信する)
    ///
    /// 確定した peer transport parameter のフロー制御上限 (ストリーム上限・
    /// 接続上限) を Final Size が超える場合は `Err` を返す
    /// (RFC 9000 Section 19.9, 19.10)。
    pub async fn stream_reset(&mut self, stream_id: u64, error_code: u64) -> Result<(), Error> {
        self.conn
            .stream_reset(stream_id, error_code)
            .map_err(|e| self.map_send_stream_error(stream_id, e))?;
        let now = self.clock.now();
        self.conn
            .flush(now)
            .map_err(|e| Error::Protocol(format!("flush failed: {e}")))?;
        self.flush_outputs().await?;
        Ok(())
    }

    /// `reliable_size` までのデータ配信を保証してストリームをリセットする
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 5。ピアが
    /// `reset_stream_at` transport parameter を提示していない場合は
    /// `Err(Error::Protocol)` を返す。既にリセットを送信済みで `error_code` が
    /// 異なる場合も `Err` を返す (同 Section 5.2 MUST NOT)。確定した peer
    /// transport parameter のフロー制御上限 (ストリーム上限・接続上限) を
    /// Final Size が超える場合も `Err` を返す (同 Section 4 / RFC 9000
    /// Section 19.9, 19.10)。0-RTT 拒否後に上限が縮小した場合などに発生する。
    pub async fn stream_reset_at(
        &mut self,
        stream_id: u64,
        error_code: u64,
        reliable_size: u64,
    ) -> Result<(), Error> {
        self.conn
            .stream_reset_at(stream_id, error_code, reliable_size)
            .map_err(|e| self.map_send_stream_error(stream_id, e))?;
        let now = self.clock.now();
        self.conn
            .flush(now)
            .map_err(|e| Error::Protocol(format!("flush failed: {e}")))?;
        self.flush_outputs().await?;
        Ok(())
    }

    /// ストリームの送信停止を要求する (STOP_SENDING フレームを送信する)
    pub async fn stream_stop_sending(
        &mut self,
        stream_id: u64,
        error_code: u64,
    ) -> Result<(), Error> {
        self.conn
            .stream_stop_sending(stream_id, error_code)
            .map_err(|e| self.map_stream_error(stream_id, e))?;
        let now = self.clock.now();
        self.conn
            .flush(now)
            .map_err(|e| Error::Protocol(format!("flush failed: {e}")))?;
        self.flush_outputs().await?;
        Ok(())
    }

    /// 待機せず、ストリームの送信バッファへデータを書き込む
    ///
    /// 非空入力の `Ok(0)` はフロー制御待ちを表す。空入力と空 FIN は
    /// `Ok(0)` で完了する。出力の送信は `flush_pending` で行う。
    ///
    /// 空入力でも状態を検証する。接続終了は `StreamError::ConnectionLost`、
    /// ピアによる送信停止は `StreamError::Stopped`、送信終了は
    /// `StreamError::FinishedSending` を `Error::Stream` で返す。GC 済みの
    /// ストリームも送信終了として扱う。まだ作成されていないストリームなど、
    /// その他の送信操作の失敗は `Error::Protocol` を返す。
    pub fn stream_send_now(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, Error> {
        if self.is_connection_closed() {
            return Err(Error::Stream(StreamError::ConnectionLost(
                self.connection_error(),
            )));
        }
        self.conn
            .stream_send(stream_id, data, fin)
            .map_err(|e| self.map_send_stream_error(stream_id, e))
    }

    /// ストリームにデータを送信する
    pub async fn stream_send(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, Error> {
        loop {
            let n = self.stream_send_now(stream_id, data, fin)?;
            let now = self.clock.now();
            self.conn
                .flush(now)
                .map_err(|e| Error::Protocol(format!("flush failed: {e}")))?;
            self.flush_outputs().await?;
            if n > 0 || data.is_empty() {
                return Ok(n);
            }

            self.wait_and_process().await?;
        }
    }

    pub fn stream_recv_now(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error> {
        self.conn
            .stream_recv(stream_id, buf)
            .map_err(|e| self.map_stream_error(stream_id, e))
    }

    /// データグラムを送信する (RFC 9221)
    ///
    /// RFC 9221 Section 5.4 は、輻輳制御が送信を許すまで DATAGRAM を遅延させるか、
    /// 送信せずに破棄するかのいずれかを実装に求めている。このメソッドは破棄を
    /// 選ぶ。送信キューが満杯の場合は最も古いデータグラムを破棄して新しいものを
    /// 追加する。破棄回数は [`Self::stats`] の
    /// `ConnectionStats::datagram_send_dropped` で観測できる。
    ///
    /// # エラー
    ///
    /// 接続が終了している (Closing / Draining / Closed) 場合は
    /// [`Error::Connection`] を返し、送信キューは変更しない。次の検証エラーは
    /// [`Error::Protocol`] を返す。
    ///
    /// - ピアが `max_datagram_frame_size` を通知していない場合
    /// - エンコード後のフレームサイズ (フレームタイプ + Length + payload) が
    ///   ピアの `max_datagram_frame_size` を超える場合 (RFC 9221 Section 3)
    /// - payload が PMTU から求めたペイロード上限を超える場合 (RFC 9000 Section 14.2)
    ///
    /// payload 単体の上限は [`Self::max_datagram_size`] で取得できる。
    pub async fn send_datagram(&mut self, data: Vec<u8>) -> Result<(), Error> {
        if self.is_connection_closed() {
            return Err(self.connection_closed_error());
        }
        self.conn
            .send_datagram(data)
            .map_err(|e| self.map_connection_error(e, "send datagram failed"))?;
        let now = self.clock.now();
        self.conn
            .flush(now)
            .map_err(|e| Error::Protocol(format!("flush failed: {e}")))?;
        self.flush_outputs().await?;
        Ok(())
    }

    /// データグラムを送信キューへ積み、flush は行わない (RFC 9221)
    ///
    /// 送信キューの状態だけを変更し、UDP 出力は行わない。driver のように
    /// 呼び出し側が後でまとめて flush する場合に使う。送信キューが満杯の
    /// 場合は最も古いデータグラムを破棄する点は [`Self::send_datagram`] と
    /// 同じである。破棄を避けたい場合は [`Self::datagram_send_queue_has_space`]
    /// で空きを確認してから呼ぶ。
    ///
    /// # エラー
    ///
    /// 接続が終了している (Closing / Draining / Closed) 場合は
    /// [`Error::Connection`] を返し、送信キューは変更しない。次の検証エラーは
    /// [`Error::Protocol`] を返す。
    ///
    /// - ピアが `max_datagram_frame_size` を通知していない場合
    /// - エンコード後のフレームサイズ (フレームタイプ + Length + payload) が
    ///   ピアの `max_datagram_frame_size` を超える場合 (RFC 9221 Section 3)
    /// - payload が PMTU から求めたペイロード上限を超える場合 (RFC 9000 Section 14.2)
    ///
    /// payload 単体の上限は [`Self::max_datagram_size`] で取得できる。
    pub fn send_datagram_now(&mut self, data: Vec<u8>) -> Result<(), Error> {
        if self.is_connection_closed() {
            return Err(self.connection_closed_error());
        }
        self.conn
            .send_datagram(data)
            .map_err(|e| self.map_connection_error(e, "send datagram failed"))
    }

    /// データグラムの送信内容を検証する (RFC 9221 / RFC 9000 Section 14.2)
    ///
    /// 送信キューの状態は変更しない。ピアが `max_datagram_frame_size` を
    /// 通知していない場合、エンコード後のフレームサイズ (フレームタイプ +
    /// Length + payload) がピアの `max_datagram_frame_size` を超える場合
    /// (RFC 9221 Section 3)、payload が PMTU から求めたペイロード上限を超える場合
    /// (RFC 9000 Section 14.2) は [`Error::Protocol`] を返す。payload 単体の
    /// 上限は [`Self::max_datagram_size`] で取得できる。
    ///
    /// 接続が終了している (Closing / Draining / Closed) 場合は、検証より先に
    /// [`Error::Connection`] を返す。
    pub fn validate_datagram(&self, data: &[u8]) -> Result<(), Error> {
        if self.is_connection_closed() {
            return Err(self.connection_closed_error());
        }
        self.conn
            .validate_datagram(data)
            .map_err(|e| self.map_connection_error(e, "validate datagram failed"))
    }

    /// DATAGRAM の送信キューに空きがあるかを返す
    pub fn datagram_send_queue_has_space(&self) -> bool {
        self.conn.datagram_send_queue_has_space()
    }

    pub fn recv_datagram_now(&mut self) -> Result<Vec<u8>, Error> {
        if let Some(ConnectionEvent::DatagramReceived { data }) =
            self.take_event(|event| matches!(event, ConnectionEvent::DatagramReceived { .. }))
        {
            Ok(data)
        } else {
            Err(Error::Internal("datagram not ready".into()))
        }
    }

    /// 送信可能な最大データグラムペイロードサイズを返す (RFC 9221)
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    /// 全パスのメトリクスを返す
    pub fn path_metrics(&self) -> Vec<PathMetrics> {
        self.conn.path_metrics()
    }

    pub fn usable_path_metrics(&self) -> Vec<PathMetrics> {
        self.conn
            .path_metrics()
            .into_iter()
            .filter(|path| path.is_usable)
            .collect()
    }

    /// 新しいパスを開く
    ///
    /// `request` の `local_addr` / `remote_addr` が指定されている場合、その値で
    /// 新パスの 4-tuple を上書きする。いずれも `None` の場合は初期パスのアドレスを
    /// 継承する。
    ///
    /// 注意: draft-ietf-quic-multipath-21 ではパスはクライアントのみが開始できる。
    /// サーバー側の `open_path` はトランスポート層でエラーが返る。
    pub async fn open_path(&mut self, request: NewPath) -> Result<PathId, Error> {
        let now = self.clock.now();
        let path_id = self
            .conn
            .open_path_with_addrs(now, request.local_addr, request.remote_addr)
            .map_err(|e| Error::Protocol(format!("open path failed: {e}")))?;
        self.flush_outputs().await?;
        Ok(path_id)
    }

    /// パスを廃棄する
    pub async fn abandon_path(&mut self, path_id: PathId, error_code: u64) -> Result<(), Error> {
        let now = self.clock.now();
        self.conn
            .abandon_path(path_id, error_code, now)
            .map_err(|e| Error::Protocol(format!("abandon path failed: {e}")))?;
        self.flush_outputs().await?;
        Ok(())
    }

    /// 指定パスで使用するピア Connection ID を未使用のものへ切り替える
    ///
    /// 戻り値は切り替えたかどうか。未使用の CID が無い場合は false を返し、
    /// multipath がネゴシエーション済みなら PATH_CIDS_BLOCKED をピアへ送る。
    /// 接続は閉じない。
    pub async fn rotate_path_cid(&mut self, path_id: PathId) -> Result<bool, Error> {
        let now = self.clock.now();
        let rotated = self
            .conn
            .rotate_path_cid(path_id, now)
            .map_err(|e| Error::Protocol(format!("rotate path cid failed: {e}")))?;
        self.flush_outputs().await?;
        Ok(rotated)
    }

    /// パス状態を変更する
    pub async fn set_path_status(
        &mut self,
        path_id: PathId,
        status: PathStatus,
    ) -> Result<(), Error> {
        let now = self.clock.now();
        self.conn
            .set_path_status(path_id, status, now)
            .map_err(|e| Error::Protocol(format!("set path status failed: {e}")))?;
        self.flush_outputs().await?;
        Ok(())
    }

    /// 1-RTT 鍵更新を開始する (RFC 9001 Section 6.1)
    pub async fn update_keys(&mut self) -> Result<(), Error> {
        let now = self.clock.now();
        self.conn
            .update_keys(now)
            .map_err(|e| Error::Protocol(format!("update keys failed: {e}")))?;
        self.flush_outputs().await?;
        Ok(())
    }

    /// 許容する最大 Path ID を拡張する
    pub async fn set_max_path_id(&mut self, max_path_id: u32) -> Result<(), Error> {
        let now = self.clock.now();
        self.conn
            .set_max_path_id(max_path_id, now)
            .map_err(|e| Error::Protocol(format!("set max path id failed: {e}")))?;
        self.flush_outputs().await?;
        Ok(())
    }

    pub async fn ping_on(&mut self, path_id: PathId) -> Result<(), Error> {
        let now = self.clock.now();
        self.conn
            .send_ping(path_id, now)
            .map_err(|e| Error::Protocol(format!("send ping failed: {e}")))?;
        self.flush_outputs().await?;
        Ok(())
    }

    /// ピアに ACK の送信頻度と遅延を要求する (ACK_FREQUENCY)
    ///
    /// draft-ietf-quic-ack-frequency-14 Section 4。
    /// ピアが `min_ack_delay` を広告していない場合や要求値が不正な場合は
    /// エラーになる。
    pub async fn send_ack_frequency(
        &mut self,
        path_id: PathId,
        ack_eliciting_threshold: u64,
        requested_max_ack_delay: std::time::Duration,
        reordering_threshold: u64,
    ) -> Result<(), Error> {
        let now = self.clock.now();
        let requested_max_ack_delay_us = u64::try_from(requested_max_ack_delay.as_micros())
            .map_err(|_| Error::Internal("requested max ack delay is too large".into()))?;
        self.conn
            .send_ack_frequency(
                path_id,
                ack_eliciting_threshold,
                requested_max_ack_delay_us,
                reordering_threshold,
                now,
            )
            .map_err(|e| Error::Protocol(format!("send ACK_FREQUENCY failed: {e}")))?;
        self.flush_outputs().await?;
        Ok(())
    }

    /// ピアに即時 ACK を要求する (IMMEDIATE_ACK)
    ///
    /// draft-ietf-quic-ack-frequency-14 Section 5。
    pub async fn send_immediate_ack(&mut self, path_id: PathId) -> Result<(), Error> {
        let now = self.clock.now();
        self.conn
            .send_immediate_ack(path_id, now)
            .map_err(|e| Error::Protocol(format!("send IMMEDIATE_ACK failed: {e}")))?;
        self.flush_outputs().await?;
        Ok(())
    }

    pub async fn notify_network_event(&mut self, event: NetworkEvent) -> Result<(), Error> {
        let now = self.clock.now();
        self.conn
            .on_network_event(PathControlEvent::from(event), now);
        self.flush_outputs().await?;
        Ok(())
    }

    /// NetworkMonitor を有効化する
    ///
    /// 指定間隔で `getifaddrs` をポーリングし、インターフェースの変化を
    /// `Connection::on_network_event` 経由で PathController に渡す。
    /// 監視タスクはバックグラウンドで動き続け、この接続が drop されるか
    /// [`Self::disable_network_monitor`] が呼ばれると終了する。
    pub fn enable_network_monitor(&mut self, interval: std::time::Duration) {
        let (tx, rx) = mpsc::channel(16);
        let monitor = crate::network_monitor::NetworkMonitor::new(interval);
        tokio::spawn(monitor.run(tx));
        self.network_rx = Some(rx);
    }

    /// NetworkMonitor を無効化する
    ///
    /// 受信側を drop するため、監視タスクは受信側の閉鎖を検出して終了する。
    pub fn disable_network_monitor(&mut self) {
        self.network_rx = None;
    }

    /// 未処理のパスイベント数を返す
    ///
    /// ローカル操作によるイベントの追加を driver が検出するために使う。
    pub fn pending_path_event_count(&self) -> usize {
        self.path_events.len()
    }

    /// 待機せず、パスイベントを 1 件取り出す
    ///
    /// 空なら `Ok(None)` を返す。接続終了時も既にあるイベントを先に返し、
    /// キューを読み切ってから終了エラーを返す。
    pub fn accept_path_event_now(&mut self) -> Result<Option<PathEvent>, Error> {
        if let Some(event) = self.take_path_event() {
            return Ok(Some(event));
        }
        if self.is_connection_closed() {
            return Err(Error::Connection(self.connection_error()));
        }
        Ok(None)
    }

    /// 待機せず、受信した STOP_SENDING を 1 件取り出す
    ///
    /// 戻り値は `(stream_id, error_code)` である。専用キューに STOP_SENDING が
    /// 残っていれば接続終了後もそれを返し、キューが空で接続が終了している
    /// 場合だけ終了エラーを返す。専用キューの上限を超えて破棄された
    /// STOP_SENDING は返らない。破棄件数は
    /// `ConnectionStats::stop_sending_dropped` で観測できる。
    pub fn accept_stop_sending_now(&mut self) -> Result<Option<(u64, u64)>, Error> {
        if let Some(event) = self.take_stop_sending() {
            return Ok(Some(event));
        }
        if self.is_connection_closed() {
            return Err(Error::Connection(self.connection_error()));
        }
        Ok(None)
    }

    pub async fn accept_path_event(&mut self) -> Result<PathEvent, Error> {
        loop {
            if let Some(event) = self.accept_path_event_now()? {
                return Ok(event);
            }

            self.flush_outputs().await?;
            self.wait_and_process().await?;
        }
    }

    /// 次のアプリケーション関連イベント (0-RTT 受理/拒否、NewSessionTicket、NEW_TOKEN 等)
    /// が既にキューに存在すれば 1 件取り出す
    pub fn accept_application_event_now(&mut self) -> Result<ConnectionEvent, Error> {
        if let Some(event) = self.take_event(|event| {
            matches!(
                event,
                ConnectionEvent::SessionTicketReceived
                    | ConnectionEvent::ZeroRttRejected
                    | ConnectionEvent::NewToken { .. }
            )
        }) {
            Ok(event)
        } else {
            Err(Error::Internal("application event not ready".into()))
        }
    }

    /// エラーコードと理由を指定して接続を閉じる
    ///
    /// transport-level の CONNECTION_CLOSE (type 0x1c, RFC 9000 Section 19.19) を
    /// 送る。`error_code` 0 は NO_ERROR (RFC 9000 Section 20.1) として正常クローズ
    /// (`ConnectionError::Closed`) になる。アプリケーションのエラーコードを
    /// 通知する場合は [`Self::close_with_application_error`] を使う。
    ///
    /// `close_reason` は、すでにクローズ理由が記録されている場合は上書きしない
    /// (最初の close を優先する)。接続が既に閉じ始めている場合、transport 層の
    /// close はフレームを送らずに成功するため、後から別の close を呼んでも
    /// 最初に送った種別と理由が保持される。
    ///
    /// transport 層の close / close_application 呼び出しが失敗した場合は
    /// `Error::Protocol` を返し、`close_reason` は変更しない。`flush_outputs` が
    /// 失敗した場合は `close_reason` を設定したまま `Err` を返す。
    pub async fn close_with_error(&mut self, error_code: u64, reason: &[u8]) -> Result<(), Error> {
        let now = self.clock.now();
        self.conn
            .close(error_code, reason, now)
            .map_err(|e| Error::Protocol(format!("close failed: {e}")))?;
        if self.close_reason.is_none() {
            self.close_reason = Some(ConnectionError::from_local_close(error_code, reason));
        }
        self.flush_outputs().await?;
        Ok(())
    }

    /// アプリケーションのエラーコードと理由を指定して接続を閉じる
    ///
    /// application-level の CONNECTION_CLOSE (type 0x1d, RFC 9000 Section 19.19) を
    /// 送る。この呼び出しで新たにクローズを開始した場合は、成功後に
    /// `close_reason` が `ConnectionError::Application` になる。すでにクローズ理由が
    /// 記録されている場合はそれを保持する。
    /// `error_code` はアプリケーションプロトコルが定義する code space
    /// (RFC 9000 Section 20.2) の値であり、0 は本実装の規約により正常クローズ
    /// (`ConnectionError::Closed`) として扱う。
    /// ハンドシェイク確定前は、保持している Initial / Handshake 空間にも
    /// RFC 9000 Section 10.2.3 に従って 0x1c へ変換したフレームを送る。
    ///
    /// `close_reason` は、すでにクローズ理由が記録されている場合は上書きしない
    /// (最初の close を優先する)。接続が既に閉じ始めている場合、transport 層の
    /// close_application はフレームを送らずに成功するため、後から別の close を
    /// 呼んでも最初に送った種別と理由が保持される。
    ///
    /// transport 層の close / close_application 呼び出しが失敗した場合は
    /// `Error::Protocol` を返し、`close_reason` は変更しない。`flush_outputs` が
    /// 失敗した場合は `close_reason` を設定したまま `Err` を返す。
    pub async fn close_with_application_error(
        &mut self,
        error_code: u64,
        reason: &[u8],
    ) -> Result<(), Error> {
        let now = self.clock.now();
        self.conn
            .close_application(error_code, reason, now)
            .map_err(|e| Error::Protocol(format!("application close failed: {e}")))?;
        if self.close_reason.is_none() {
            self.close_reason = Some(ConnectionError::from_local_application_close(
                error_code, reason,
            ));
        }
        self.flush_outputs().await?;
        Ok(())
    }

    /// 接続を閉じる
    pub async fn close(&mut self) -> Result<(), Error> {
        self.close_with_error(0, b"").await
    }

    /// 接続状態を返す
    pub fn state(&self) -> ConnectionState {
        self.conn.state()
    }

    /// この接続で使用している QUIC バージョンを返す
    ///
    /// サーバーはクライアントの Initial で受信したバージョンを使う
    /// (RFC 9000 Section 6)。
    pub fn version(&self) -> u32 {
        self.conn.version()
    }

    /// 接続全体の累積統計を返す
    ///
    /// 経過時間は最初の送受信を観測した時点を起点に、現在時刻で計算する。
    /// `stop_sending_dropped` はこの接続の専用キューが満杯で捨てた
    /// STOP_SENDING の件数である。
    pub fn stats(&self) -> tobi_core::stats::ConnectionStats {
        let mut stats = self.conn.stats(self.clock.now());
        stats.stop_sending_dropped = self.stop_sending_dropped;
        stats
    }

    /// ハンドシェイク中かどうかを返す
    pub fn is_handshaking(&self) -> bool {
        self.state() == ConnectionState::Handshaking
    }

    /// 接続クローズ情報を返す
    pub fn close_reason(&self) -> Option<ConnectionError> {
        self.close_reason.clone()
    }

    /// 接続が閉じている場合のエラーを組み立てる
    ///
    /// クローズ理由が判明していればそれを返し、不明な場合は正常クローズ
    /// ([`ConnectionError::Closed`]) として扱う。理由が残っていないのは
    /// driver が理由を記録する前に停止した場合であり、明示的なエラーを伴わない
    /// 終了と区別できないためである。
    fn connection_error(&self) -> ConnectionError {
        self.close_reason.clone().unwrap_or(ConnectionError::Closed)
    }

    /// 接続終了後の操作に対する型付きエラーを組み立てる
    ///
    /// [`Self::connection_error`] が返す接続終了理由を [`Error::Connection`] で
    /// 包む。ストリーム API は同じ理由を [`StreamError::ConnectionLost`] として
    /// 返すため、外側の型は [`Error::Connection`] と [`Error::Stream`] で異なる。
    fn connection_closed_error(&self) -> Error {
        Error::Connection(self.connection_error())
    }

    /// 接続が終了状態かを返す
    fn is_connection_closed(&self) -> bool {
        matches!(
            self.conn.state(),
            ConnectionState::Closing | ConnectionState::Draining | ConnectionState::Closed
        )
    }

    /// ストリーム操作の失敗を型付きエラーへ変換する
    fn map_stream_error(&self, stream_id: u64, error: tobi_core::error::Error) -> Error {
        if let Some(error_code) = self.conn.stream_recv_reset_error_code(stream_id) {
            return Error::Stream(StreamError::Reset {
                error_code,
                final_size: self
                    .conn
                    .stream_recv_final_size(stream_id)
                    .unwrap_or_default(),
                reliable_size: self.conn.stream_recv_reset_at_reliable_size(stream_id),
            });
        }
        if let Some(error_code) = self.conn.stream_send_stopped_error_code(stream_id) {
            return Error::Stream(StreamError::Stopped { error_code });
        }
        if self.is_connection_closed() {
            return Error::Stream(StreamError::ConnectionLost(self.connection_error()));
        }
        Error::Protocol(format!("stream operation failed: {error}"))
    }

    /// 送信系ストリーム操作の失敗を型付きエラーへ変換する
    ///
    /// RFC 9000 Section 4.4: RESET_STREAM は一方向のみを終端し、逆方向の
    /// データフローに影響しない。受信方向のリセットを送信系 API の
    /// `StreamError::Reset` に変換してはならない。
    fn map_send_stream_error(&self, stream_id: u64, error: tobi_core::error::Error) -> Error {
        if let Some(error_code) = self.conn.stream_send_stopped_error_code(stream_id) {
            return Error::Stream(StreamError::Stopped { error_code });
        }
        if self.conn.stream_send_finished(stream_id) {
            return Error::Stream(StreamError::FinishedSending);
        }
        if self.is_connection_closed() {
            return Error::Stream(StreamError::ConnectionLost(self.connection_error()));
        }
        Error::Protocol(format!("stream operation failed: {error}"))
    }

    /// 接続の終了に起因するエラーを型付きにする
    ///
    /// 接続が閉鎖中なら終了理由を [`Error::Connection`] で返し、それ以外は
    /// transport 層のエラーを公開 API の型へ変換する。変換の共通処理は
    /// [`crate::error::map_transport_error`] に置く。
    fn map_connection_error(&self, error: tobi_core::error::Error, context: &str) -> Error {
        if self.is_connection_closed() {
            return Error::Connection(self.connection_error());
        }
        crate::error::map_transport_error(error, context)
    }

    /// 初期パスへ PING を送信する
    pub async fn ping(&mut self) -> Result<(), Error> {
        let now = self.clock.now();
        self.conn
            .send_ping(PathId::INITIAL, now)
            .map_err(|e| Error::Protocol(format!("send ping failed: {e}")))?;
        self.flush_outputs().await?;
        Ok(())
    }

    /// 初期パスのローカルアドレスを返す
    ///
    /// 待ち受けが `0.0.0.0` / `::` のとき、ソケットの `local_addr` はその
    /// ワイルドカードのままになる。接続のアドレスは、受信パケットの宛先として
    /// 確定した初期パスのアドレスを返す。まだ確定していなければソケットの
    /// アドレス (少なくともポートは入っている) に戻す。
    ///
    /// preferred_address への移行が確定すると、初期パスのローカルアドレスは
    /// 移行先アドレスに更新されるため、この値も移行先を指す。
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        let learned = self
            .conn
            .path_addrs(PathId::INITIAL)
            .map_or_else(|| self.conn.initial_local_addr(), |(local, _)| local);
        if !learned.ip().is_unspecified() {
            return Ok(learned);
        }
        self.pool.primary().local_addr().map_err(Error::Io)
    }

    /// リモートアドレスを返す
    ///
    /// 初期パスの現在のリモートアドレスを返す。migration 後は移行先の
    /// アドレスになる。
    pub fn remote_addr(&self) -> SocketAddr {
        self.conn
            .path_addrs(PathId::INITIAL)
            .map_or(self.peer_addr, |(_, remote)| remote)
    }

    /// ピアが広告した preferred_address を返す (RFC 9000 Section 18.2)
    ///
    /// クライアントは preferred_address を広告しないため、サーバー側では
    /// 通常 `None` になる。
    pub fn peer_preferred_address(&self) -> Option<&tobi_core::transport_params::PreferredAddress> {
        self.conn.peer_preferred_address()
    }

    /// 初期パスで送信に使うピアの Connection ID を返す
    ///
    /// preferred_address への移行が確定したクライアントでは、移行先の CID が
    /// 返る。
    pub fn path_peer_cid(&self) -> Option<ConnectionId> {
        self.conn.path_peer_cid(PathId::INITIAL).cloned()
    }

    /// Initial で受信したアドレストークンが検証できたかを返す
    /// (RFC 9000 Section 8.1.3)
    ///
    /// サーバー側の接続では、クライアントが Initial に有効なアドレストークンを
    /// 含めていた場合に `true` になる。クライアント側の接続では常に `false`。
    pub fn initial_token_validated(&self) -> bool {
        self.conn.initial_token_validated()
    }

    /// ネゴシエートされた ALPN プロトコルを返す
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }

    /// ピアが `reset_stream_at` transport parameter を提示しているかを返す
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 3 に従って交換される
    /// 値で、ハンドシェイク未完了時は `false` を返す。
    pub fn peer_supports_reset_stream_at(&self) -> bool {
        self.conn
            .peer_transport_params()
            .map(|p| p.reset_stream_at)
            .unwrap_or(false)
    }

    /// パス単位 Keep-Alive の有効/無効の既定値を設定する (RFC 9000 Section 10.1.2)
    ///
    /// 既存の全パスに適用し、以降に作成されるパスにも継承される。
    /// パスごとに設定する場合は [`Self::set_path_keep_alive`] を使う。
    pub async fn set_keep_alive(&mut self, enabled: bool) -> Result<(), Error> {
        let now = self.clock.now();
        self.conn.set_keep_alive(enabled, now);
        self.flush_outputs().await
    }

    /// パス単位 Keep-Alive の有効/無効を設定する (RFC 9000 Section 10.1.2)
    ///
    /// 指定したパスだけに PING による keep-alive を適用する。使用されない
    /// 待機パスを middlebox のタイムアウトで失わないようにするために使う
    /// (draft-ietf-quic-multipath-21 Section 5.9)。
    pub async fn set_path_keep_alive(
        &mut self,
        path_id: PathId,
        enabled: bool,
    ) -> Result<(), Error> {
        let now = self.clock.now();
        self.conn
            .set_path_keep_alive(path_id, enabled, now)
            .map_err(|e| Error::Protocol(format!("set path keep alive failed: {e}")))?;
        self.flush_outputs().await
    }

    /// サーバーが 0-RTT を受理したかを返す (RFC 9001 Section 4.6)
    pub fn zero_rtt_accepted(&self) -> bool {
        self.conn.zero_rtt_accepted()
    }

    /// ネゴシエート済みのピア transport parameter を返す
    pub fn peer_transport_params(&self) -> Option<&TransportParams> {
        self.conn.peer_transport_params()
    }

    /// ハンドシェイクが完了していれば上限カウンタへ反映する
    ///
    /// `handshake()` を呼ばずにアプリケーションが接続を駆動した場合でも、
    /// 実際の状態に追従して `max_inflight_handshakes` の枠を解放する。
    fn mark_handshake_completed_if_connected(&mut self) {
        if self.conn.state() == ConnectionState::Connected {
            self.connection_slot.handshake_completed();
        }
    }

    /// graceful shutdown 指示の受信側を取り出す
    pub fn take_shutdown_receiver(
        &mut self,
    ) -> Option<mpsc::UnboundedReceiver<ConnectionShutdown>> {
        let (_tx, rx) = mpsc::unbounded_channel();
        Some(std::mem::replace(&mut self.shutdown_rx, rx))
    }
}

impl Drop for QuicServerConnection {
    fn drop(&mut self) {
        // router の cid_map から本接続の全 CID を削除する。
        // Connection::close 経路で CID 一括 Unregister が保証されないため
        // (Draining/Closing 遷移で個別 Unregister を emit しない)、Drop に
        // 一元化する safety-net として全 CID を回収する。
        //
        // `UnboundedSender::send` は非 async (同期) シグネチャで返るため、
        // await できない Drop 内から安全に呼べる。router_loop が既に終了
        // している場合は Err を返すが、ベストエフォートで無視する
        // (どのみち router が終わっているので cid_map も参照されない)。
        tracing::debug!(
            peer = %self.peer_addr,
            cid_count = self.active_local_cids.len(),
            "QuicServerConnection dropped, releasing CIDs"
        );
        for cid in self.active_local_cids.drain() {
            let _ = self.cid_cmd_tx.send(CidMapCommand::Unregister { cid });
        }
        let _ = self.cid_cmd_tx.send(CidMapCommand::UnregisterConnection {
            connection_id: self.connection_id,
        });
    }
}

#[cfg(test)]
mod tests;
