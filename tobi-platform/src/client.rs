// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! QUIC クライアント
//!
//! Sans I/O の Connection を tokio の UdpSocket で駆動する。

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::clock::Clock;
use crate::{DEFAULT_CID_LEN, validate_cid_generator};
use tobi_core::connection::{
    ConnectionConfig, ConnectionEvent, ConnectionObservationEvent, ConnectionOutput,
    ConnectionState, TimerId,
};
use tobi_core::connection_id::ConnectionId;
use tobi_core::path::controller::PathControlEvent;
use tobi_core::path::controller::default::DefaultPathControllerFactory;
use tobi_core::path::{PathId, PathStatus};
use tobi_core::recovery::CongestionControlFactoryImpl;
use tobi_core::scheduler::PathMetrics;
use tobi_core::scheduler::SchedulerFactoryImpl;
use tobi_core::transport_params::TransportParams;
use tobi_transport::connection::Connection;
use tobi_transport::stream;

/// アプリケーションがイベントを消費しない場合に備えたキューの上限
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
use tobi_transport::tls::ClientTlsSession;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::config::{ConnectOptions, UdpBatchConfig};
use crate::error::{ConnectionError, Error, StreamError};
use crate::path::{NetworkEvent, NewPath, PathEvent, PathHandle};

/// 追加パスに専用のソケットを確保すべきローカルアドレスを返す
///
/// 具体的な IP と非 0 ポートが指定された場合だけ、そのアドレスにバインドした
/// ソケットを用意する。`None` は初期パスの継承、ポート 0 は既存のソケット選択
/// (通常は初期ソケットと同じポート、同じ IP の追加ソケットが既にある場合は
/// そのポート)、unspecified IP は宛先アドレスファミリによる既存の選択に任せる。
fn dedicated_path_local_addr(local_addr: Option<SocketAddr>) -> Option<SocketAddr> {
    local_addr.filter(|addr| !addr.ip().is_unspecified() && addr.port() != 0)
}

/// QUIC クライアント接続の結果
pub struct QuicConnection {
    /// Sans I/O 接続
    conn: Connection<CongestionControlFactoryImpl, SchedulerFactoryImpl>,
    /// パスごとのローカルアドレスを扱うソケットプール
    ///
    /// デュアルスタック multipath ではアドレスファミリごとにソケットが要る。
    /// 追加ソケットはパス追加時に遅延作成され、受信タスクは
    /// [`Self::ensure_socket_readers`] が起動する。
    pool: Arc<crate::socket::SocketPool>,
    /// 受信パケットの受信待ち行列 (全ソケットの受信タスクが送る)
    packet_rx: mpsc::Receiver<Result<crate::socket::ReceivedDatagram, std::io::Error>>,
    /// 受信パケットの送信側 (追加ソケットの受信タスク起動に使う)
    packet_tx: mpsc::Sender<Result<crate::socket::ReceivedDatagram, std::io::Error>>,
    /// 受信タスクを起動済みのソケット ID とハンドル
    readers: Vec<(crate::socket::SocketId, tokio::task::JoinHandle<()>)>,
    /// パス ID と専用ソケット ID の対応
    path_sockets: HashMap<tobi_core::path::PathId, crate::socket::SocketId>,
    /// サーバーアドレス
    server_addr: SocketAddr,
    /// タイマー管理
    timers: HashMap<TimerId, tobi_core::time::Timestamp>,
    /// クロック
    clock: Clock,
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
    /// UDP のバッチ I/O の設定。`None` なら 1 データグラムずつ送受信する
    udp_batch: Option<UdpBatchConfig>,
    /// 観測イベントの記録が有効か
    observation_enabled: bool,
    /// 未処理の観測イベント
    observation_events: VecDeque<ConnectionObservationEvent>,
}

impl QuicConnection {
    /// サーバーに接続する
    pub async fn connect(
        server_addr: SocketAddr,
        server_name: &str,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<Self, Error> {
        let bind_addr: SocketAddr = if server_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        Self::connect_with_config_and_bind(
            server_addr,
            bind_addr,
            server_name,
            tls_config,
            ConnectionConfig::default(),
            ConnectOptions::default(),
        )
        .await
    }

    /// カスタム設定でサーバーに接続する
    pub async fn connect_with_config(
        server_addr: SocketAddr,
        server_name: &str,
        tls_config: Arc<rustls::ClientConfig>,
        config: ConnectionConfig,
    ) -> Result<Self, Error> {
        let bind_addr: SocketAddr = if server_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        Self::connect_with_config_and_bind(
            server_addr,
            bind_addr,
            server_name,
            tls_config,
            config,
            ConnectOptions::default(),
        )
        .await
    }

    /// カスタム設定とバインドアドレスでサーバーに接続する
    ///
    /// 任意の設定は [`ConnectOptions`] に集約する。
    ///
    /// - `early_peer_params` が `Some` の場合、前回セッションで取得したピアの
    ///   `TransportParams` を Connection::client() と conn.connect() の間で
    ///   `set_early_peer_params` によって適用する。この呼び出しにより 0-RTT
    ///   パケットの送信が可能になる (RFC 9001 Section 4.6.1)。
    /// - `qlog_factory` が `Some` の場合、`Connection::client` 生成直後に
    ///   `factory.create(odcid)` を呼び出し、返された writer を装着する。
    ///   `None` なら qlog は完全に無効化される (draft-ietf-quic-qlog-main-schema-14
    ///   Section 14.2 の「明示的な操作なしに qlog を有効化しない」recommendation に沿ったデフォルト)。
    /// - `close_formatter` が `Some` の場合、`Connection::close` /
    ///   `Connection::close_application` 経路で CONNECTION_CLOSE の reason phrase
    ///   整形に適用される。application close を Initial / Handshake へ 0x1c 変換
    ///   して送るときは、RFC 9000 Section 10.2.3 の MUST により reason phrase を
    ///   空にするため整形結果は載らない。`None` の場合は reason バイト列が
    ///   そのまま送信される。
    /// - `cid_generator` が `Some` の場合、クライアント自身の SCID をこの生成器で
    ///   生成する。初期 DCID (クライアント視点の ODCID) は RFC 9000 Section 7.2 が
    ///   8 バイト以上を MUST とするため、生成器を使わず 8 バイトの乱数にする。
    pub async fn connect_with_config_and_bind(
        server_addr: SocketAddr,
        bind_addr: SocketAddr,
        server_name: &str,
        tls_config: Arc<rustls::ClientConfig>,
        mut config: ConnectionConfig,
        options: ConnectOptions,
    ) -> Result<Self, Error> {
        // 送信するトランスポートパラメータの妥当性を接続開始前に検証する
        config
            .transport_params
            .validate_local()
            .map_err(|e| Error::Protocol(format!("invalid transport parameters: {e}")))?;
        let ConnectOptions {
            early_peer_params,
            qlog_factory,
            close_formatter,
            cid_generator,
            udp_batch,
            address_token,
            allow_dual_stack,
            handshake_timeout,
        } = options;
        // 0 秒のハンドシェイクタイムアウトは即座に打ち切られ、ハンドシェイクが
        // 完了しないため拒否する。
        if let Some(timeout) = handshake_timeout
            && timeout.is_zero()
        {
            return Err(Error::Protocol(
                "handshake timeout must be greater than zero".into(),
            ));
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

        // tokio 側のソケットはここで 1 本だけ生成し、
        // 以降は Sans I/O の接続をこのソケットで駆動する。
        // デュアルスタックのパスでは、プールが追加ソケットを初期ソケットと
        // 同じポートにバインドする。そのためには初期ソケット側にも
        // SO_REUSEADDR / SO_REUSEPORT が要る (Linux では無いと EADDRINUSE)。
        let socket = crate::socket::bind_primary_socket(bind_addr, udp_batch).map_err(Error::Io)?;
        tracing::info!("local={}, remote={}", socket.local_addr()?, server_addr);

        let clock = Clock::new();

        // 自身の SCID は CID 生成器が設定されていればそれを使う。
        // 未設定なら従来どおり 8 バイトの乱数を生成する (後方互換)。
        let client_cid_bytes = match cid_generator.as_ref() {
            Some(generator) => {
                validate_cid_generator(generator.as_ref())?;
                generator.generate()
            }
            None => {
                let mut bytes = [0u8; DEFAULT_CID_LEN];
                aws_lc_rs::rand::fill(&mut bytes)
                    .map_err(|_| Error::Internal("failed to generate CID".into()))?;
                bytes.to_vec()
            }
        };
        let client_cid = ConnectionId::from_slice(&client_cid_bytes)
            .map_err(|e| Error::Internal(format!("CID creation failed: {e}")))?;

        let mut server_cid_bytes = [0u8; 8];
        aws_lc_rs::rand::fill(&mut server_cid_bytes)
            .map_err(|_| Error::Internal("failed to generate CID".into()))?;
        let server_cid = ConnectionId::from_slice(&server_cid_bytes)
            .map_err(|e| Error::Internal(format!("CID creation failed: {e}")))?;

        // RFC 9000 Section 7.3: initial_source_connection_id を設定する (MUST)
        config.transport_params.initial_source_connection_id = Some(client_cid.clone());

        // RFC 9369 Section 4 / RFC 9368 Section 3:
        // version_information をローカル TP に設定してからエンコードする。
        config.apply_version_information(tobi_core::role::Role::Client);

        // トランスポートパラメータをエンコードする
        let mut tp_buf = Vec::new();
        config.transport_params.encode(&mut tp_buf);

        // TLS セッションを作成する
        let sni: rustls::pki_types::ServerName<'static> = server_name
            .to_string()
            .try_into()
            .map_err(|_| Error::Internal("invalid server name".into()))?;
        let tls_session = ClientTlsSession::new(tls_config, config.version, sni, tp_buf)
            .map_err(|e| Error::Internal(format!("TLS session creation failed: {e}")))?;

        // この時点では packet I/O 自体はまだ始めず、
        // transport / TLS / 4-tuple を束ねて接続を初期化する。
        let local_addr = socket.local_addr()?;
        let cc_factory = config.congestion_control.factory();
        let scheduler_factory = config.scheduler.factory();
        tracing::debug!(
            data = config.scheduler.data.name(),
            ack = config.scheduler.ack.name(),
            retx = config.scheduler.retx.name(),
            "scheduler configuration"
        );
        let mut conn = Connection::client(
            config,
            tls_session,
            client_cid,
            server_cid,
            cc_factory,
            scheduler_factory,
            DefaultPathControllerFactory,
            server_addr,
            local_addr,
        )
        .map_err(|e| crate::error::map_transport_error(e, "connection setup failed"))?;

        // qlog Factory が設定されていれば writer を装着する。
        // conn.connect(now) より前に装着することで、初期状態遷移 (idle -> handshaking) や
        // parameters_set の qlog イベントを取りこぼさない。
        // server_cid_bytes はクライアント視点の ODCID (Initial 送信時に使う DCID)。
        if let Some(writer) = qlog_factory
            .as_ref()
            .and_then(|f| f.create(&server_cid_bytes))
        {
            conn.set_qlog(writer);
        }

        // CONNECTION_CLOSE の reason phrase フォーマッタを適用する
        if let Some(ref formatter) = close_formatter {
            conn.set_close_formatter(Arc::clone(formatter));
        }

        // RFC 9001 Section 4.6.1: 前回セッションで取得したピアの transport parameter
        // を Initial 送信前に適用する必要がある。0-RTT パケットはこの値に従う。
        if let Some(params) = early_peer_params {
            conn.set_early_peer_params(params);
        }

        // RFC 9000 Section 8.1.3: 前回接続で受信した NEW_TOKEN を Initial に
        // 載せる。サーバーがトークンを検証できればアドレス検証済みとして
        // 受理され、検証往復を省略できる。
        if let Some(token) = address_token {
            conn.set_address_token(token);
        }

        // 接続生成の直前で時刻を取得する。ソケット生成・TLS セッション生成・
        // Connection 構築には時間がかかるため、そこで得た古い時刻を最初の
        // Initial の送信時刻に使うと、最初の ACK の RTT サンプルが実測より
        // 大きく膨らむ。RTT が過大になると PTO が伸び、損失時の再送が遅れて
        // 短い期限のピアでハンドシェイクが完了しなくなる。
        let now = clock.now();
        conn.connect(now)
            .map_err(|e| Error::Protocol(format!("connect failed: {e}")))?;

        // 全ソケットの受信タスクを起動してから handshake を駆動する。
        // 受信タスクを先に起動しないと、最初の flight への応答を取りこぼす。
        let pool = Arc::new(
            crate::socket::SocketPool::new(Arc::new(socket), udp_batch)
                .with_dual_stack(allow_dual_stack),
        );
        let (packet_tx, packet_rx) = mpsc::channel(256);
        let mut endpoint = Self {
            conn,
            pool,
            packet_rx,
            packet_tx: packet_tx.clone(),
            readers: Vec::new(),
            path_sockets: HashMap::new(),
            server_addr,
            timers: HashMap::new(),
            clock,
            events: VecDeque::new(),
            path_events: VecDeque::new(),
            stop_sending_events: VecDeque::new(),
            stop_sending_dropped: 0,
            stop_sending_warned: false,
            close_reason: None,
            network_rx: None,
            udp_batch,
            observation_enabled: false,
            observation_events: VecDeque::new(),
        };
        endpoint.ensure_socket_readers();

        // 公開 API は「接続済み handle」を返す前提なので、
        // constructor 内で handshake 完了まで責任を持つ。
        // 応答しないサーバーに対して永遠に待たないよう、既定のタイムアウトを
        // 適用する。`None` の場合は呼び出し側が明示的に無効化している。
        match handshake_timeout {
            Some(timeout) => {
                tokio::time::timeout(timeout, endpoint.drive_handshake())
                    .await
                    .map_err(|_| Error::Connection(ConnectionError::TimedOut))??;
            }
            None => endpoint.drive_handshake().await?,
        }

        Ok(endpoint)
    }

    /// ハンドシェイク完了を待たずに接続を開始する (0-RTT 用)
    ///
    /// RFC 9001 Section 4.6: 前回セッションの `early_peer_params` を渡した場合、
    /// ClientHello を送った直後の `flush` で 0-RTT 鍵が導出され、アプリケーション
    /// データを 0-RTT パケットで送信できる。`connect_with_config_and_bind` は
    /// ハンドシェイク完了まで待つため 0-RTT の送信機会がない。
    ///
    /// このメソッドは最初の flight を送った直後に戻る。呼び出し側は返された
    /// `QuicConnection` を `Connection` (高水準 handle) へ移し、ハンドシェイク中に
    /// ストリームを開いて書き込む。ハンドシェイクの継続は driver task が行う。
    ///
    /// 0-RTT が拒否された場合、送信したストリームデータは transport が 1-RTT で
    /// 再送する (RFC 9001 Section 4.6.2)。
    pub async fn connect_early_with_config_and_bind(
        server_addr: SocketAddr,
        bind_addr: SocketAddr,
        server_name: &str,
        tls_config: Arc<rustls::ClientConfig>,
        mut config: ConnectionConfig,
        options: ConnectOptions,
    ) -> Result<Self, Error> {
        // 送信するトランスポートパラメータの妥当性を接続開始前に検証する
        config
            .transport_params
            .validate_local()
            .map_err(|e| Error::Protocol(format!("invalid transport parameters: {e}")))?;
        let ConnectOptions {
            early_peer_params,
            qlog_factory,
            close_formatter,
            cid_generator,
            udp_batch,
            address_token,
            allow_dual_stack,
            handshake_timeout: _,
        } = options;
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
        // デュアルスタックのパスでは、プールが追加ソケットを初期ソケットと
        // 同じポートにバインドする。そのためには初期ソケット側にも
        // SO_REUSEADDR / SO_REUSEPORT が要る (Linux では無いと EADDRINUSE)。
        let socket = crate::socket::bind_primary_socket(bind_addr, udp_batch).map_err(Error::Io)?;
        tracing::info!("local={}, remote={}", socket.local_addr()?, server_addr);

        let clock = Clock::new();

        let client_cid_bytes = match cid_generator.as_ref() {
            Some(generator) => {
                validate_cid_generator(generator.as_ref())?;
                generator.generate()
            }
            None => {
                let mut bytes = [0u8; DEFAULT_CID_LEN];
                aws_lc_rs::rand::fill(&mut bytes)
                    .map_err(|_| Error::Internal("failed to generate CID".into()))?;
                bytes.to_vec()
            }
        };
        let client_cid = ConnectionId::from_slice(&client_cid_bytes)
            .map_err(|e| Error::Internal(format!("CID creation failed: {e}")))?;

        let mut server_cid_bytes = [0u8; 8];
        aws_lc_rs::rand::fill(&mut server_cid_bytes)
            .map_err(|_| Error::Internal("failed to generate CID".into()))?;
        let server_cid = ConnectionId::from_slice(&server_cid_bytes)
            .map_err(|e| Error::Internal(format!("CID creation failed: {e}")))?;

        config.transport_params.initial_source_connection_id = Some(client_cid.clone());

        // RFC 9369 Section 4 / RFC 9368 Section 3:
        // version_information をローカル TP に設定してからエンコードする。
        config.apply_version_information(tobi_core::role::Role::Client);

        let mut tp_buf = Vec::new();
        config.transport_params.encode(&mut tp_buf);

        let sni: rustls::pki_types::ServerName<'static> = server_name
            .to_string()
            .try_into()
            .map_err(|_| Error::Internal("invalid server name".into()))?;
        let tls_session = ClientTlsSession::new(tls_config, config.version, sni, tp_buf)
            .map_err(|e| Error::Internal(format!("TLS session creation failed: {e}")))?;

        let local_addr = socket.local_addr()?;
        let cc_factory = config.congestion_control.factory();
        let scheduler_factory = config.scheduler.factory();
        tracing::debug!(
            data = config.scheduler.data.name(),
            ack = config.scheduler.ack.name(),
            retx = config.scheduler.retx.name(),
            "scheduler configuration"
        );
        let mut conn = Connection::client(
            config,
            tls_session,
            client_cid,
            server_cid,
            cc_factory,
            scheduler_factory,
            DefaultPathControllerFactory,
            server_addr,
            local_addr,
        )
        .map_err(|e| crate::error::map_transport_error(e, "connection setup failed"))?;

        if let Some(writer) = qlog_factory
            .as_ref()
            .and_then(|f| f.create(&server_cid_bytes))
        {
            conn.set_qlog(writer);
        }
        if let Some(ref formatter) = close_formatter {
            conn.set_close_formatter(Arc::clone(formatter));
        }
        if let Some(params) = early_peer_params {
            conn.set_early_peer_params(params);
        }

        // RFC 9000 Section 8.1.3: 前回接続で受信した NEW_TOKEN を Initial に
        // 載せる。サーバーがトークンを検証できればアドレス検証済みとして
        // 受理され、検証往復を省略できる。
        if let Some(token) = address_token {
            conn.set_address_token(token);
        }

        // 接続生成の直前で時刻を取得する。古い時刻を connect へ渡すと、最初の
        // Initial の送信時刻が実際より前になり、最初の ACK の RTT サンプルが
        // 実測より大きくなる。RTT が過大になると PTO が伸び、損失時の再送が
        // 遅れて短い期限のピアでハンドシェイクが完了しなくなる。
        let now = clock.now();
        conn.connect(now)
            .map_err(|e| Error::Protocol(format!("connect failed: {e}")))?;

        // 最初の flight (Initial + 0-RTT) を送信する前に受信タスクを起動する。
        // 受信タスクを先に起動しないと、最初の flight への応答を取りこぼす。
        let (packet_tx, packet_rx) = mpsc::channel(256);
        let mut endpoint = Self {
            conn,
            pool: Arc::new(
                crate::socket::SocketPool::new(Arc::new(socket), udp_batch)
                    .with_dual_stack(allow_dual_stack),
            ),
            packet_rx,
            packet_tx: packet_tx.clone(),
            readers: Vec::new(),
            path_sockets: HashMap::new(),
            server_addr,
            timers: HashMap::new(),
            clock,
            events: VecDeque::new(),
            path_events: VecDeque::new(),
            stop_sending_events: VecDeque::new(),
            stop_sending_dropped: 0,
            stop_sending_warned: false,
            close_reason: None,
            network_rx: None,
            udp_batch,
            observation_enabled: false,
            observation_events: VecDeque::new(),
        };
        endpoint.ensure_socket_readers();

        // 最初の flight (Initial + 0-RTT) を送信して即座に戻る
        endpoint.flush_outputs().await?;
        Ok(endpoint)
    }

    /// ハンドシェイク完了まで駆動する
    /// 接続で使用している QUIC バージョンを返す
    pub fn version(&self) -> u32 {
        self.conn.version()
    }

    /// Version Negotiation が提示したバージョン一覧を返す
    pub fn version_negotiation_versions(&self) -> Option<&[u32]> {
        self.conn.version_negotiation_versions()
    }

    /// 互換バージョン交渉でサーバーが選んだバージョンを返す
    ///
    /// `Some` の場合、rustls の QUIC セッションがバージョンに束縛されるため
    /// 接続内では切り替えられない。呼び出し側はこのバージョンで新しい接続試行を
    /// 開始する (RFC 9368 Section 2.3)。
    pub fn compatible_version_switch(&self) -> Option<u32> {
        self.conn.compatible_version_switch()
    }

    async fn drive_handshake(&mut self) -> Result<(), Error> {
        loop {
            // 出力を送信する
            self.flush_outputs().await?;

            let state = self.conn.state();
            tracing::debug!("handshake state: {:?}", state);

            if state == ConnectionState::Connected {
                return Ok(());
            }

            if matches!(
                state,
                ConnectionState::Closing | ConnectionState::Draining | ConnectionState::Closed
            ) {
                // 互換バージョン交渉でサーバーが別バージョンを選んだ場合、
                // 上位層がそのバージョンで再試行できるよう返す
                // (RFC 9368 Section 2.3)。
                if let Some(version) = self.conn.compatible_version_switch() {
                    return Err(Error::CompatibleVersionNegotiation { version });
                }
                // Version Negotiation で接続試行を中止した場合、上位層が
                // 別バージョンで再試行できるよう提示バージョン一覧を返す
                // (RFC 9000 Section 6.2)。
                if let Some(offered) = self.conn.version_negotiation_versions() {
                    return Err(Error::VersionNegotiation {
                        offered: offered.to_vec(),
                    });
                }
                return Err(Error::Protocol(format!(
                    "connection closed during handshake: {:?}",
                    state
                )));
            }

            // データ受信またはタイマー発火を待つ
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
        let mut release_candidates: Vec<crate::socket::SocketId> = Vec::new();
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
                    // multipath 時は output ごとに path が異なりうる。
                    // 4-tuple の両方に合うソケットを選び、IP_PKTINFO で
                    // 送信元 IP を指定して送信する。
                    tracing::debug!(
                        "send {} bytes, first=0x{:02x}, path={:?}, local={}, remote={}",
                        data.len(),
                        data[0],
                        path_id,
                        local_addr,
                        remote_addr,
                    );
                    let socket = match self.pool.socket_for_path(local_addr, remote_addr) {
                        Ok(socket) => socket,
                        Err(e) => {
                            // 送信先のソケットを選べない場合も、溜めていた分は送ってから
                            // エラーを返す (取りこぼしを増やさない)。
                            pending.flush(self.udp_batch).await.map_err(Error::Io)?;
                            return Err(Error::Io(e));
                        }
                    };
                    // ソケットが遅延作成された場合に備えて受信タスクを起動する。
                    // 起動しないと、そのソケットで受信したパケットを配送できない。
                    self.ensure_socket_readers();
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
                    // パスの 4-tuple を扱えるソケットを用意する。宛先の
                    // アドレスファミリを扱えるソケットでないと送信できない。
                    // 同一ファミリ内は IP_PKTINFO の cmsg で送信元 IP を指定できる。
                    match self.pool.socket_for_path(local_addr, remote_addr) {
                        Ok(socket) => {
                            if let Some(socket_id) = self
                                .pool
                                .find_socket_exact(local_addr)
                                .and_then(|exact| self.pool.socket_id_for(&exact))
                                .or_else(|| self.pool.socket_id_for(&socket))
                            {
                                if socket_id == crate::socket::SocketId::PRIMARY {
                                    self.path_sockets.remove(&path_id);
                                } else {
                                    self.path_sockets.insert(path_id, socket_id);
                                }
                            }
                            // 追加ソケットが増えた場合は受信タスクを起動する
                            self.ensure_socket_readers();
                            tracing::debug!(
                                "path {:?}: socket {} for {} -> {}",
                                path_id,
                                socket
                                    .local_addr()
                                    .map_or_else(|_| "<unknown>".to_string(), |a| a.to_string()),
                                local_addr,
                                remote_addr,
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "path {:?}: no socket for {} -> {}: {}",
                                path_id,
                                local_addr,
                                remote_addr,
                                e
                            );
                        }
                    }
                }
                ConnectionOutput::PathClosed { path_id } => {
                    tracing::debug!("path closed: path={:?}", path_id);
                    if self.path_events.len() < MAX_PENDING_EVENTS {
                        self.path_events.push_back(PathEvent::Closed {
                            path: PathHandle::new(path_id),
                        });
                    }
                    if let Some(socket_id) = self.path_sockets.remove(&path_id) {
                        eprintln!(
                            "DEBUG closed path={:?} release candidate {:?}",
                            path_id, socket_id
                        );
                        release_candidates.push(socket_id);
                    }
                }
                ConnectionOutput::RegisterLocalCid { cid, path_id } => {
                    // クライアントの全ソケットは同一接続に属するため、CID に
                    // よるルーティングは不要。CID 発行ログのみ残す。
                    tracing::trace!(
                        "client issued local CID path={:?} len={}",
                        path_id,
                        cid.as_bytes().len()
                    );
                }
                ConnectionOutput::UnregisterLocalCid { cid } => {
                    tracing::trace!("client retired local CID len={}", cid.as_bytes().len());
                }
            }
        }
        // PN 上限など、poll 自体が生成した終了イベントも回収する。
        self.enqueue_events();
        self.enqueue_observations();
        pending.flush(self.udp_batch).await.map_err(Error::Io)?;
        // 送信を終えてから、閉じたパスが使っていた専用ソケットを解放する。
        for socket_id in release_candidates {
            self.release_socket_if_unused(socket_id);
        }
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

    /// 未起動のソケットの受信タスクを起動する
    ///
    /// パス追加でソケットが増えたときに呼ぶ。起動済みのソケットは
    /// `reader_count` で数えており、増えた分だけを起動する。
    fn ensure_socket_readers(&mut self) {
        for (id, socket) in self.pool.sockets_with_ids() {
            if self.readers.iter().any(|(reader_id, _)| *reader_id == id) {
                continue;
            }
            let handle = spawn_client_socket_reader(socket, self.packet_tx.clone(), self.udp_batch);
            self.readers.push((id, handle));
        }
    }

    /// ソケットの受信タスクを停止する
    /// パスが使わなくなった専用ソケットを解放する
    fn release_socket_if_unused(&mut self, id: crate::socket::SocketId) {
        if id == crate::socket::SocketId::PRIMARY {
            return;
        }
        if self.path_sockets.values().any(|used| *used == id) {
            return;
        }
        self.stop_socket_reader(id);
        if let Some(socket) = self.pool.remove_socket(id) {
            drop(socket);
        }
    }

    pub fn stop_socket_reader(&mut self, id: crate::socket::SocketId) {
        if let Some(position) = self
            .readers
            .iter()
            .position(|(reader_id, _)| *reader_id == id)
        {
            let (_, handle) = self.readers.remove(position);
            handle.abort();
        }
    }

    /// Pacing タイマーが残っているかを返す
    ///
    /// 命令駆動 driver (background 無効) で、送信完了までタイマーを
    /// 処理すべきかの判定に使う。
    pub fn has_pending_pacing_timer(&self) -> bool {
        self.timers
            .keys()
            .any(|id| matches!(id, TimerId::Pacing { .. }))
    }

    /// データ受信、タイマー発火、ネットワーク変化を待って処理する
    pub async fn wait_and_process(&mut self) -> Result<(), Error> {
        // loss detection / PTO / idle timeout を進めるため、
        // もっとも近い deadline を待機対象にする。
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
            // サーバー側と同様、タイマーがパケットより先に選ばれると接続が進まないことがある。
            biased;
            received = self.packet_rx.recv() => {
                match received {
                    Some(Ok(pkt)) => {
                        tracing::debug!(
                            "recv {} bytes from {}, local={}",
                            pkt.data.len(),
                            pkt.remote,
                            pkt.local_addr,
                        );
                        let now = self.clock.now();
                        if let Err(e) = self.conn.receive_with_ecn(
                            &pkt.data,
                            pkt.remote,
                            pkt.local_addr,
                            now,
                            pkt.ecn,
                        ) {
                            tracing::error!("receive error: {}", e);
                        }
                        // パケット受信で生成された ACK 等を即座に送信する
                        self.flush_outputs().await?;
                    }
                    Some(Err(e)) => return Err(Error::Io(e)),
                    None => {
                        // 全受信タスクが終了した (ソケットが drop された)
                        return Err(Error::Internal("all socket readers closed".into()));
                    }
                }
            }
            _ = timer => {
                tracing::debug!("timer expired, state={:?}", self.conn.state());
                self.fire_expired_timers();
                // タイマー発火で生成されたパケットを即座に送信する
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
            // 公開 API は pull 型でイベントを消費するので、
            // ここで queue 化しておく。
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
                if !stream::is_bidirectional(*stream_id) && !stream::is_client_initiated(*stream_id))
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
    /// `local_addr` に具体的な IP と非 0 ポートを指定した場合、そのアドレスに
    /// バインドしたソケットを用意し、新しいパスの送受信に使う。PATH_RESPONSE を
    /// 受け取れるよう受信タスクも起動する。完全一致するソケットが既にあれば
    /// 再利用する。新規に用意するソケットは `SO_REUSEADDR` と `SO_REUSEPORT` を
    /// 設定せず、既存ソケットの受信範囲と重なるアドレスは [`Error::Io`] になる。
    /// ポート 0 は既存のソケット選択に従う。通常は初期ソケットと同じポートに
    /// なるが、同じ IP の追加ソケットが既にある場合はそのポートになる。
    /// unspecified IP は宛先アドレスファミリによる従来の選択に従う。
    ///
    /// # エラー
    ///
    /// 指定アドレスにバインドできない場合は transport を呼ばずに
    /// [`Error::Io`] を返し、パスも通知もしない。バインドに成功しても transport
    /// がパス作成を拒否した場合は [`Error::Protocol`] を返し、仮確保した新規
    /// ソケットをプールへ登録せず破棄する。
    ///
    /// パス作成後の送信 (flush) に失敗した場合はエラーを返し、作成済みの
    /// パスを best-effort で破棄する。廃棄は [`PathEvent::Closed`] として通知され
    /// うるが、[`PathEvent::Opened`] が通知されない可能性がある。新しく
    /// バインドしたソケットとその受信タスクは、後始末の手段が無いため接続の
    /// 終了まで残る。
    pub async fn open_path(&mut self, request: NewPath) -> Result<PathId, Error> {
        // 明示された 4-tuple で送受信するため、パス作成の前にソケットを
        // 仮確保する。パス作成が失敗した場合に備え、プールへの登録は
        // パス作成の成功後に行う。
        let prepared = match dedicated_path_local_addr(request.local_addr) {
            Some(local) => Some(
                self.pool
                    .prepare_socket_for_local_addr(local)
                    .map_err(Error::Io)?,
            ),
            None => None,
        };
        // transport へは実際に確保したアドレスを渡す。通知するアドレスと
        // 送受信に使うアドレスを同じ値にするためである。
        let mut local_addr = prepared
            .as_ref()
            .map_or(request.local_addr, |prepared| Some(prepared.local_addr()));
        if let Some(local) = local_addr.as_mut()
            && local.port() == 0
        {
            // ポート 0 は既存ソケットを選ぶ指定であり、通信時のアドレスではない。
            // 実ポートを transport に渡さないと、最初の受信を経路移行と誤認し、
            // 完了した検証を破棄して新しい検証を始めてしまう。
            let remote = request.remote_addr.unwrap_or(self.remote_addr());
            let socket = self
                .pool
                .socket_for_path(*local, remote)
                .map_err(Error::Io)?;
            local.set_port(socket.local_addr().map_err(Error::Io)?.port());
        }
        // パス作成とレート制限の記録に使う時刻は、ソケットのバインド後に取得する。
        // バインドには時間がかかりうるため、事前に取得するとパス作成時刻が
        // 実際より古くなる。
        let now = self.clock.now();
        let path_id = match self
            .conn
            .open_path_with_addrs(now, local_addr, request.remote_addr)
        {
            Ok(path_id) => path_id,
            Err(error) => {
                // ここから return すると `prepared` は drop される。プールへ
                // 登録していない新規ソケットは参照が無くなった時点で FD が閉じ、
                // このソケットのバインドが解放される。完全一致する既存ソケットを
                // 再利用していた場合は、プールが参照を保持し続けるため解放されない。
                return Err(Error::Protocol(format!("open path failed: {error}")));
            }
        };
        // PATH_CHALLENGE を送る前にソケットを登録して受信タスクを起動する。
        // 起動が遅れると、ピアが返す PATH_RESPONSE をそのソケットで
        // 受け取れない。
        if let Some(prepared) = prepared {
            self.pool.register_prepared_socket(prepared);
            self.ensure_socket_readers();
        }
        if let Err(error) = self.flush_outputs().await {
            // パスは作成済みだが、I/O 層からはパス ID を返せないため、呼び出し
            // 側に後始末を任せられない。使えないパスを接続に残さないよう、
            // ここで best-effort に廃棄する。
            //
            // 廃棄は PATH_ABANDON の送信を伴い、それも最初の失敗と同じ I/O
            // 障害で失敗しうる。呼び出し側へ返すべきは最初の送信失敗なので、
            // 後始末の失敗は無視する。パスを廃棄できた場合は、後で
            // `PathEvent::Closed` が通知される。
            let _ = self.abandon_path(path_id, 0).await;
            return Err(error);
        }
        Ok(path_id)
    }

    /// 初期パス (Path ID 0) を新しい 4-tuple へ移行する
    ///
    /// `request.local_addr` が `Some` でポート 0 の場合、移行先用のソケットを
    /// 新しくバインドして実際のアドレスを使う。ポートが指定されている場合は
    /// そのアドレスにバインドする。移行用のソケットは `SO_REUSEADDR` と
    /// `SO_REUSEPORT` を設定せず、既存ソケットの受信範囲と重なるアドレスは
    /// `Err(Error::Io)` になる。`request.remote_addr` は変更しない場合は
    /// `None` を指定する。
    ///
    /// 移行先の宛先アドレスには、そのパスで未使用の最小シーケンス番号のピア CID を
    /// 予約して使う (RFC 9000 Section 9.5)。検証パケットの DCID にもこの CID を
    /// 使い、移行前のアドレスで使っている CID を移行先へ再利用しない。
    ///
    /// # エラー
    ///
    /// 次の場合は `Err(Error::Protocol)` を返す。
    ///
    /// - クライアント以外、接続が確立していない
    /// - ハンドシェイクが確定していない (RFC 9000 Section 9)
    /// - 同じ移行が検証中
    /// - 移行先が現在の 4-tuple と同じ
    /// - ピアの `disable_active_migration` で禁止されている
    /// - 未使用のピア CID が無い
    ///
    /// 移行先用のソケットを用意できない場合は `Err(Error::Io)` を返す。移行の
    /// 開始が受理された後の送信に失敗した場合は、[`Error::Io`] または
    /// [`Error::Protocol`] を返す。
    ///
    /// 移行先のソケットは transport が移行の開始を受理してからプールへ登録し、
    /// 受信タスクを起動する。開始が拒否された場合は新しくバインドしたソケットを
    /// 解放し、完全一致で再利用した既存ソケットとその受信タスクは維持する。
    /// 受理後の送信に失敗した場合は、登録済みのソケットを無条件に削除しない。
    pub async fn migrate(&mut self, request: NewPath) -> Result<(), Error> {
        // 移行用のソケットは transport の受理が確定するまでプールへ登録せず、
        // 受信タスクも起動しない。開始が拒否された場合は仮確保したソケットを
        // drop するだけで新規ソケットを解放でき、再利用した既存ソケットと
        // その受信タスクは維持される。
        let prepared = match request.local_addr {
            Some(local) => Some(
                self.pool
                    .prepare_socket_for_local_addr(local)
                    .map_err(Error::Io)?,
            ),
            None => None,
        };
        let local_addr = prepared.as_ref().map(|prepared| prepared.local_addr());
        // 移行の記録に使う時刻は、ソケットのバインド後に取得する。バインドには
        // 時間がかかりうるため、事前に取得すると移行時刻が実際より古くなる。
        let now = self.clock.now();
        if let Err(error) = self.conn.migrate(now, local_addr, request.remote_addr) {
            drop(prepared);
            return Err(Error::Protocol(format!("migrate failed: {error}")));
        }
        if let Some(prepared) = prepared {
            // 受理された移行の PATH_CHALLENGE を flush する前に登録と受信タスクの
            // 起動を済ませ、同じソケットで PATH_RESPONSE を受信できるようにする。
            self.pool.register_prepared_socket(prepared);
            self.ensure_socket_readers();
        }
        self.flush_outputs().await?;
        Ok(())
    }

    /// パスを廃棄する
    ///
    /// 追加パス / 移行用にソケットを用意していた場合も、そのソケットは解放
    /// しない。同じローカルアドレスのソケットを他のパスが使っている可能性が
    /// あり、受信タスクを停止する手段も持たないためである。ソケットは接続の
    /// 終了まで残る。
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
    ///
    /// 待機はせず、存在しなければ `Err(Error::Internal)` を返す。非同期で待機する場合は
    /// 呼び出し元で `wait_and_process` と組み合わせる。
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
    /// preferred_address への移行が確定した場合は、初期パスのリモートアドレス
    /// として移行先アドレスを返す。
    pub fn remote_addr(&self) -> SocketAddr {
        self.conn
            .path_addrs(PathId::INITIAL)
            .map_or(self.server_addr, |(_, remote)| remote)
    }

    /// ピアが広告した preferred_address を返す (RFC 9000 Section 18.2)
    ///
    /// ハンドシェイク完了前や、ピアが広告していない場合は `None`。
    pub fn peer_preferred_address(&self) -> Option<&tobi_core::transport_params::PreferredAddress> {
        self.conn.peer_preferred_address()
    }

    /// サーバーが広告した preferred_address へ移行を開始する (RFC 9000 Section 9.6.1)
    ///
    /// PATH_CHALLENGE を候補アドレスへ送信し、PATH_RESPONSE の受信で検証が
    /// 完了した時点で初期パスの 4-tuple と宛先 CID を移行先へ更新する。
    /// 検証の完了は `PathEvent` の `Validated` / `ValidationFailed` で通知される。
    /// 検証パケットの DCID には preferred_address の CID を使う
    /// (RFC 9000 Section 9.5)。
    ///
    /// # エラー
    ///
    /// 次の場合は `Err(Error::Protocol)` を返す。
    ///
    /// - 接続が確立していない、クライアント以外
    /// - 同じ初期パスの移行がすでに検証中
    /// - ピアが preferred_address を広告していない、または使用可能なアドレスが
    ///   無い
    /// - preferred_address の CID が退役済み (RFC 9000 Section 5.1.2)
    /// - preferred_address の CID が能動回転などで既に送信に使われている
    ///   (未使用の CID だけを移行に使う。RFC 9000 Section 9.5)
    ///
    /// 検証パケットの送信に失敗した場合は `Err(Error::Io)` を返す。
    pub async fn migrate_to_preferred_address(&mut self) -> Result<(), Error> {
        let now = self.clock.now();
        self.conn
            .migrate_to_preferred_address(now)
            .map_err(|e| Error::Protocol(format!("migrate to preferred_address failed: {e}")))?;
        self.conn
            .flush(now)
            .map_err(|e| Error::Protocol(format!("flush failed: {e}")))?;
        self.flush_outputs().await?;
        Ok(())
    }

    /// 初期パスで送信に使うピアの Connection ID を返す
    ///
    /// preferred_address への移行が確定した場合は移行先の CID を返す。
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
    ///
    /// 次回接続で 0-RTT を利用するためにアプリ側が保存する用途で使う。
    pub fn peer_transport_params(&self) -> Option<&TransportParams> {
        self.conn.peer_transport_params()
    }
}

/// ソケットからデータグラムを読み続け、接続の処理ループへ転送する専用タスクを起動する
///
/// パスごとにソケットが増えうるため、ソケット 1 本につき 1 本起動する。
/// 受信ループで `select!` する代わりにタスクへ分離することで、
/// ソケット数が増えても待機対象の取りこぼしが起きない。
///
/// `tx` に対応する receiver が drop されたら、受信待ちを打ち切ってタスクを
/// 終了する。接続の drop で `packet_rx` が閉じたときに、受信が来るまでタスクと
/// ソケットの FD を保持し続けないようにするためである。
///
/// 受信バッファはタスクが所有して使い回す。`udp_batch` で `recvmmsg` を
/// 有効にしている場合は、複数のデータグラムを 1 回のシステムコールで受け取る。
///
/// 戻り値は起動したタスクのハンドル。通常の呼び出し側は await せず drop して
/// detached のまま動かし、タスクの終了を待つ必要がある場合だけ保持する。
fn spawn_client_socket_reader(
    socket: Arc<UdpSocket>,
    tx: mpsc::Sender<Result<crate::socket::ReceivedDatagram, std::io::Error>>,
    udp_batch: Option<UdpBatchConfig>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // バッチ受信・単発受信・GRO の分割は DatagramReceiver にまとめてある
        let mut receiver = crate::socket::DatagramReceiver::new(udp_batch);
        loop {
            tokio::select! {
                // 接続側の receiver が drop されたら、受信待ちを打ち切る。
                // ここでタスクを終了すると、タスクが保持するソケットの Arc も
                // drop され、FD が解放される。
                // 停止要求を優先するため closed() を先に評価する。
                biased;
                _ = tx.closed() => return,
                // 受信の待機中にキャンセルされても、カーネルからまだ受け取って
                // いないデータグラムは失われない。受信済みのデータグラムは
                // この分岐の中で drain して送信し終えてから次を待つ。
                result = receiver.recv(&socket) => {
                    if let Err(e) = result {
                        // 受信エラーの既存挙動を変えない。接続側へエラーを渡して
                        // 受信を続け、接続側が既に閉じている場合だけ終了する。
                        if tx.send(Err(e)).await.is_err() {
                            return;
                        }
                        continue;
                    }
                    for pkt in receiver.drain() {
                        if tx.send(Ok(pkt)).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests;
