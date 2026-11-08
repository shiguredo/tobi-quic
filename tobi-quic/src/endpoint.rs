// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tobi_core::connection::ConnectionConfig;
use tobi_core::scheduler::SchedulerConfig;
use tobi_core::token::TokenProvider;
use tobi_platform::config::PreferredAddressConfig;
use tobi_qlog::QlogWriterFactory;

use crate::config::{
    ClientTlsConfig, CongestionControlAlgorithm, Connect, ConnectionCloseFormatter, DatagramConfig,
    EndpointLimits, IoConfig, MtuConfig, MultipathConfig, ServerTlsConfig,
    versioned_server_tls_configs,
};
use crate::connection::{Connection, ConnectionTracker};
use crate::error::Error;
use tobi_platform::{BindOptions, ConnectOptions, QuicConnection, QuicServer};

/// Connection ID の生成をカスタマイズするトレイト
///
/// 実体は tobi-core に移設した。`tobi_quic` クレート経由の import パス
/// (`tobi_quic::ConnectionIdGenerator` および `tobi_quic::endpoint::ConnectionIdGenerator`
/// の両方) を維持するため re-export する。
pub use tobi_core::connection::ConnectionIdGenerator;

/// デフォルトの Connection ID 生成器 (8 バイトランダム)
pub struct DefaultConnectionIdGenerator {
    len: usize,
}

impl DefaultConnectionIdGenerator {
    pub fn new(len: usize) -> Self {
        Self { len }
    }
}

impl Default for DefaultConnectionIdGenerator {
    fn default() -> Self {
        Self { len: 8 }
    }
}

impl ConnectionIdGenerator for DefaultConnectionIdGenerator {
    fn generate(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.len];
        aws_lc_rs::rand::fill(&mut buf).expect("failed to generate random CID");
        buf
    }

    fn cid_len(&self) -> usize {
        self.len
    }
}

/// Stateless Reset Token の生成をカスタマイズするトレイト
///
/// 実体は tobi-core に移設した。`tobi_quic` クレート経由の import パス
/// (`tobi_quic::StatelessResetTokenGenerator` および
/// `tobi_quic::endpoint::StatelessResetTokenGenerator` の両方) を維持するため
/// re-export する。
pub use tobi_core::connection::StatelessResetTokenGenerator;

/// デフォルトの Stateless Reset Token 生成器 (HMAC-SHA256 ベース)
///
/// 生の static key バイト列を保持し、Token 生成は
/// `tobi_crypto::keys::generate_stateless_reset_token` に委譲する。
pub struct DefaultStatelessResetTokenGenerator {
    key_bytes: [u8; 32],
}

impl DefaultStatelessResetTokenGenerator {
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        Self {
            key_bytes: *key_bytes,
        }
    }
}

impl StatelessResetTokenGenerator for DefaultStatelessResetTokenGenerator {
    fn generate(&self, connection_id: &[u8]) -> [u8; 16] {
        tobi_crypto::keys::generate_stateless_reset_token(connection_id, &self.key_bytes)
    }
}

/// ネットワーク監視のポーリング間隔を検証する
///
/// `tokio::time::interval` は間隔 0 を許容しないため、有効化時の 0 指定を
/// エラーとして弾く。
fn validate_network_monitor_interval(interval: Option<Duration>) -> Result<(), Error> {
    if let Some(interval) = interval
        && interval.is_zero()
    {
        return Err(Error::Protocol(
            "network monitor interval must be greater than zero".into(),
        ));
    }
    Ok(())
}

/// バージョン一覧の重複を除去する (優先順は先勝ち)
///
/// 同じバージョンを複数指定しても最初の出現位置だけを残す。再試行の候補が
/// 重複すると同じバージョンへ無駄に再試行し得るため、設定時に正規化する。
fn dedupe_versions(versions: Vec<u32>) -> Vec<u32> {
    let mut deduped = Vec::new();
    for version in versions {
        if !deduped.contains(&version) {
            deduped.push(version);
        }
    }
    deduped
}

/// クライアント
pub struct Client {
    tls: ClientTlsConfig,
    transport: ConnectionConfig,
    io: IoConfig,
    cid_generator: Arc<dyn ConnectionIdGenerator>,
    qlog_factory: Option<Arc<dyn QlogWriterFactory>>,
    close_formatter: Option<Arc<dyn ConnectionCloseFormatter>>,
    /// このクライアントから生成した接続の追跡
    ///
    /// [`Client::wait_idle`] が全接続の終了を待つために使う。
    connections: Arc<ConnectionTracker>,
    /// ネットワークインターフェース監視のポーリング間隔。
    /// `None` なら監視しない (既定)。
    network_monitor_interval: Option<Duration>,
    /// ハンドシェイク完了までのタイムアウト。`None` ならタイムアウトしない。
    handshake_timeout: Option<Duration>,
    /// クライアントが対応し、Version Negotiation 後の再試行候補にもなる
    /// QUIC バージョンの一覧 (優先順)
    versions: Vec<u32>,
    /// 接続生成時から background driver を有効にするか
    background_driver: bool,
}

/// サーバー
pub struct Server {
    inner: QuicServer,
    /// 未完了の接続を並行して駆動し、完了した順に受理する。
    /// 接続数は inner の EndpointLimits によって制限される。
    handshakes: tokio::task::JoinSet<Result<tobi_platform::QuicServerConnection, Error>>,
    /// 接続に使うスケジューラー構成
    scheduler_config: SchedulerConfig,
    /// 受け付けた接続で有効化するネットワーク監視のポーリング間隔。
    /// `None` なら監視しない (既定)。
    network_monitor_interval: Option<Duration>,
    /// 接続生成時から background driver を有効にするか
    background_driver: bool,
}

/// クライアントビルダー
pub struct ClientBuilder {
    tls: Option<ClientTlsConfig>,
    transport: ConnectionConfig,
    io: Option<IoConfig>,
    cid_generator: Option<Arc<dyn ConnectionIdGenerator>>,
    mtu_config: Option<MtuConfig>,
    close_formatter: Option<Arc<dyn ConnectionCloseFormatter>>,
    qlog_factory: Option<Arc<dyn QlogWriterFactory>>,
    network_monitor_interval: Option<Duration>,
    /// ハンドシェイク完了までのタイムアウト。`None` ならタイムアウトしない。
    handshake_timeout: Option<Duration>,
    /// 対応する QUIC バージョンの優先順一覧
    versions: Vec<u32>,
    /// 接続生成時から background driver を有効にするか
    background_driver: bool,
    /// `start()` で適用する DATAGRAM 設定
    datagram: Option<DatagramConfig>,
    /// `start()` で適用する Multipath 設定
    multipath: Option<MultipathConfig>,
    /// `start()` で適用するスケジューラー構成
    scheduler: Option<SchedulerConfig>,
    /// `start()` で適用する輻輳制御アルゴリズム
    congestion_control: Option<CongestionControlAlgorithm>,
}

/// サーバービルダー
pub struct ServerBuilder {
    tls: Option<ServerTlsConfig>,
    transport: ConnectionConfig,
    io: Option<IoConfig>,
    endpoint_limits: EndpointLimits,
    cid_generator: Option<Arc<dyn ConnectionIdGenerator>>,
    stateless_reset_generator: Option<Arc<dyn StatelessResetTokenGenerator>>,
    retry_config: Option<tobi_platform::RetryConfig>,
    mtu_config: Option<MtuConfig>,
    close_formatter: Option<Arc<dyn ConnectionCloseFormatter>>,
    qlog_factory: Option<Arc<dyn QlogWriterFactory>>,
    /// accept キューの容量 (None なら既定値)
    accept_queue_capacity: Option<usize>,
    /// サーバーが広告する preferred_address (RFC 9000 Section 18.2)
    preferred_address: Option<PreferredAddressConfig>,
    /// NEW_TOKEN のトークン生成・検証に使うプロバイダ (RFC 9000 Section 8.1.3)
    token_provider: Option<Arc<dyn TokenProvider>>,
    /// 受け付けた接続で有効化するネットワーク監視のポーリング間隔
    network_monitor_interval: Option<Duration>,
    /// ハンドシェイク完了までのタイムアウト
    handshake_timeout: Option<Duration>,
    /// `start()` で適用する DATAGRAM 設定
    datagram: Option<DatagramConfig>,
    /// `start()` で適用する Multipath 設定
    multipath: Option<MultipathConfig>,
    /// `start()` で適用するスケジューラー構成
    scheduler: Option<SchedulerConfig>,
    /// `start()` で適用する輻輳制御アルゴリズム
    congestion_control: Option<CongestionControlAlgorithm>,
    /// `start()` で適用する対応 QUIC バージョンの優先順一覧
    versions: Option<Vec<u32>>,
    /// 接続生成時から background driver を有効にするか
    background_driver: bool,
}

/// ビルダーに保持した設定を `ConnectionConfig` へ固定順に適用する
///
/// `with_transport` で渡された設定を base とし、個別 setter の設定を
/// 呼び出し順に関係なく上書きする。設定はそれぞれ独立したフィールドを
/// 書くため順序に意味はないが、再現性のため固定順に適用する。
/// MTU、DATAGRAM、Multipath、Scheduler、Congestion Control の順である。
pub(crate) fn build_transport(
    mut transport: ConnectionConfig,
    mtu: Option<&MtuConfig>,
    datagram: Option<&DatagramConfig>,
    multipath: Option<&MultipathConfig>,
    scheduler: Option<SchedulerConfig>,
    congestion_control: Option<CongestionControlAlgorithm>,
) -> ConnectionConfig {
    if let Some(mtu) = mtu {
        mtu.apply_to(&mut transport);
    }
    if let Some(datagram) = datagram {
        datagram.apply_to(&mut transport);
    }
    if let Some(multipath) = multipath {
        multipath.apply_to(&mut transport);
    }
    if let Some(scheduler) = scheduler {
        transport.scheduler = scheduler;
    }
    if let Some(congestion_control) = congestion_control {
        transport.congestion_control = congestion_control;
    }
    transport
}

/// DATAGRAM のキュー上限を検証する
///
/// 0 件のキューは DATAGRAM を保持できず、送信側は常に最古破棄、受信側は
/// 常に破棄になる。設定ミスを接続開始前に検出するため、0 は受け付けない。
/// DATAGRAM を使わない場合は `max_datagram_frame_size` を 0 にする。
fn validate_datagram_queue_config(config: &ConnectionConfig) -> Result<(), Error> {
    if config.datagram_send_queue_max == 0 {
        return Err(Error::Protocol(
            "datagram_send_queue_max must be greater than zero".into(),
        ));
    }
    if config.datagram_recv_queue_max == 0 {
        return Err(Error::Protocol(
            "datagram_recv_queue_max must be greater than zero".into(),
        ));
    }
    Ok(())
}

/// サーバーが使用する QUIC バージョン一覧を解決する
///
/// `with_versions` が指定されていればその値を、無ければ `with_transport` で
/// 渡された base の一覧を使う。重複を除去した後、空一覧と未対応バージョンを
/// 検証する。戻り値は組み立て後の `ConnectionConfig` へ反映する。
fn resolve_versions(explicit: Option<Vec<u32>>, base: &[u32]) -> Result<Vec<u32>, Error> {
    let versions = dedupe_versions(explicit.unwrap_or_else(|| base.to_vec()));
    if versions.is_empty() {
        return Err(Error::Protocol(
            "at least one QUIC version is required".into(),
        ));
    }
    if let Some(version) = versions
        .iter()
        .find(|version| !tobi_core::packet::is_supported_version(**version))
    {
        return Err(Error::Protocol(format!(
            "unsupported QUIC version in configuration: {version:#010x}"
        )));
    }
    Ok(versions)
}

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder {
            tls: None,
            transport: ConnectionConfig::default(),
            io: None,
            cid_generator: None,
            mtu_config: None,
            close_formatter: None,
            qlog_factory: None,
            network_monitor_interval: None,
            handshake_timeout: Some(Duration::from_secs(10)),
            versions: vec![tobi_core::packet::QUIC_VERSION_1],
            datagram: None,
            multipath: None,
            scheduler: None,
            congestion_control: None,
            background_driver: false,
        }
    }

    /// サーバーへ接続する
    ///
    /// Version Negotiation を受信した場合は、設定された対応バージョンの
    /// 優先順に従って、サーバーが提示したバージョンのうち未試行のものを選び
    /// 新しい接続試行を開始する (RFC 9000 Section 6.2)。互換バージョンが
    /// 無い場合は [`Error::VersionNegotiation`] を返す。
    ///
    /// RFC 9368 Section 2.3 の互換バージョン交渉でサーバーが Chosen Version と
    /// 異なるバージョンを選んだ場合も、そのバージョンで新しい接続試行を開始する。
    /// rustls の QUIC セッションがバージョンに束縛され、接続内でバージョンを
    /// 切り替えられないためである。
    ///
    /// Version Negotiation 後の再試行では 0-RTT を使わない。セッションチケットは
    /// バージョンに紐づくため、別バージョンで 0-RTT を送ってもピアに受理されない。
    pub async fn connect(&self, connect: Connect) -> Result<Connection, Error> {
        let mut attempted_versions: Vec<u32> = Vec::new();
        let mut version = self.versions[0];
        // Version Negotiation に反応した再試行か。互換バージョン交渉の再試行は
        // VN ではないため false のままにする (RFC 9368 Section 4 の検証対象外)。
        let mut vn_retry = false;
        // RFC 9368 Section 2.3 の互換バージョン交渉でサーバーが別バージョンを選んだ
        // 後の再試行か。再試行では選ばれたバージョンに合わせて送信 TP を作り直す。
        let mut compatible_retry = false;
        loop {
            attempted_versions.push(version);
            // 最初の試行だけ、利用者が渡した 0-RTT 用の早期パラメータを使う
            let is_retry = attempted_versions.len() > 1;
            let early_peer_params = if is_retry {
                None
            } else {
                connect.early_peer_params.clone()
            };
            // RFC 9369 Section 5: アドレストークンは発行バージョンに固有である。
            // 別バージョンでの試行や Version Negotiation 後の再試行では送らない。
            let address_token = address_token_for_attempt(&connect, version, is_retry);
            match self
                .connect_with_version(
                    &connect,
                    version,
                    early_peer_params,
                    address_token,
                    vn_retry,
                    compatible_retry,
                )
                .await
            {
                Ok(mut inner) => {
                    // 監視が設定されていれば、driver task 起動前に有効化する。
                    // 初回ポーリングで現在のインターフェースが通知される。
                    if let Some(interval) = self.network_monitor_interval {
                        inner.enable_network_monitor(interval);
                    }
                    // 接続の生成に成功した時点で追跡を開始する。driver task の終了
                    // または接続の終了で解除される。
                    let tracker = Arc::clone(&self.connections);
                    tracker.register();
                    return Ok(Connection::from_client(
                        inner,
                        Some(tracker),
                        self.background_driver,
                    ));
                }
                Err(Error::VersionNegotiation { offered }) => {
                    // クライアントの優先順で、サーバーが提示した未試行バージョンを選ぶ。
                    // 予約バージョンは対応一覧に含まれないため自然に無視される
                    // (RFC 9000 Section 6.3)。
                    let Some(candidate) = self
                        .versions
                        .iter()
                        .copied()
                        .find(|v| offered.contains(v) && !attempted_versions.contains(v))
                    else {
                        return Err(Error::VersionNegotiation { offered });
                    };
                    version = candidate;
                    vn_retry = true;
                }
                Err(Error::CompatibleVersionNegotiation { version: selected }) => {
                    // RFC 9368 Section 2.3: サーバーが互換バージョンを選んだ。
                    // rustls の QUIC セッションがバージョンに束縛されるため、
                    // そのバージョンで新しい接続試行を開始する。未試行かつ
                    // 対応済みのバージョンだけを受理する。
                    if attempted_versions.contains(&selected) || !self.versions.contains(&selected)
                    {
                        return Err(Error::CompatibleVersionNegotiation { version: selected });
                    }
                    version = selected;
                    vn_retry = false;
                    compatible_retry = true;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// 指定バージョンで 1 回だけ接続を試行する
    ///
    /// `early_peer_params` は 0-RTT を試行する場合のみ渡す。
    /// `vn_retry` は VN に反応した接続試行かを表し、再試行中の VN を
    /// 無視するために transport へ伝える (RFC 9368 Section 4 MUST)。
    async fn connect_with_version(
        &self,
        connect: &Connect,
        version: u32,
        early_peer_params: Option<tobi_core::transport_params::TransportParams>,
        address_token: Option<Vec<u8>>,
        vn_retry: bool,
        compatible_retry: bool,
    ) -> Result<QuicConnection, Error> {
        let mut transport = self.transport.clone();
        transport.version = version;
        transport.supported_versions = self.versions.clone();
        if compatible_retry {
            // サーバーが選んだ互換バージョンで再試行する。Available Versions の
            // 先頭を選ばれたバージョンに揃え、多くの実装が先頭から選ぶ処理でも
            // 同じバージョンに留まるようにする。送信 TP は再計算させる。
            transport
                .supported_versions
                .retain(|candidate| *candidate != version);
            transport.supported_versions.insert(0, version);
            transport.transport_params.version_information = None;
        }
        transport.vn_retry = vn_retry;
        QuicConnection::connect_with_config_and_bind(
            connect.remote_addr,
            self.io.bind_addr,
            &connect.server_name,
            self.tls.config_for_version(version),
            transport,
            ConnectOptions {
                early_peer_params,
                qlog_factory: self.qlog_factory.clone(),
                close_formatter: self.close_formatter.clone(),
                cid_generator: Some(Arc::clone(&self.cid_generator)),
                udp_batch: self.io.udp_batch,
                address_token,
                allow_dual_stack: self.io.dual_stack,
                handshake_timeout: self.handshake_timeout,
            },
        )
        .await
    }

    /// ハンドシェイク完了を待たずに接続を開始する (0-RTT)
    ///
    /// `Connect::with_early_peer_params` で前回セッションのピアトランスポート
    /// パラメータを渡した場合、最初の flight を送った直後に戻るため、
    /// ハンドシェイク中にストリームを開いて 0-RTT でアプリケーションデータを
    /// 送信できる (RFC 9001 Section 4.6)。
    ///
    /// 0-RTT でアプリケーションデータを送信できるのは、返された `Connection` が
    /// ハンドシェイク中の間だけである。1-RTT 鍵が利用可能になると transport は
    /// 0-RTT 鍵を破棄し (RFC 9001 Section 4.9.3)、以後の送信は自動的に 1-RTT に
    /// 切り替わる。呼び出し側が送信先を切り替える必要はない。
    ///
    /// 0-RTT で送信できるフレームは RFC 9000 Section 12.4 Table 3 で 0-RTT が
    /// 許可されたものだけである (STREAM など)。ACK / CRYPTO / HANDSHAKE_DONE /
    /// NEW_TOKEN / PATH_RESPONSE / RETIRE_CONNECTION_ID は送信できず、
    /// CONNECTION_CLOSE は送信できる。ACK は受信側で生成されるため、アプリ側が
    /// 明示的に送ることはない。
    ///
    /// 0-RTT が拒否された場合、送信したストリームデータは transport が再送キューへ
    /// 戻して 1-RTT で送り直す (RFC 9001 Section 4.6.2)。
    /// `Connection::zero_rtt_accepted()` で受理されたかを確認でき、拒否時には
    /// [`ApplicationEvent::ZeroRttRejected`](crate::ApplicationEvent::ZeroRttRejected)
    /// が通知される。受理可否はハンドシェイク完了後に確定するため、0-RTT 送信中に
    /// `zero_rtt_accepted()` を呼ぶと `false` を返すことがある。
    ///
    /// 0-RTT で送ったパケットの ACK を拒否後に受信した場合、transport は
    /// `PROTOCOL_VIOLATION` で接続を閉じる (RFC 9001 Section 4.6.2 の SHOULD)。
    ///
    /// ハンドシェイクの継続とその後の通信は返された `Connection` の driver task が
    /// 行うため、呼び出し側が明示的に駆動する必要はない。
    ///
    /// 0-RTT のセッションチケットはバージョンに紐づくため、Version Negotiation を
    /// 受信した場合は自動再試行しない。互換バージョン交渉でサーバーが Chosen
    /// Version と異なるバージョンを選んだ場合も自動再試行しない。再試行が
    /// 必要な場合は通常の [`Client::connect`] を使う。本メソッドは最初の flight を送った時点で
    /// `Ok(Connection)` を返すため、Version Negotiation は戻り値ではなく、返された
    /// 接続がドライバータスク内で Closed になる形で観測される。提示された
    /// バージョン一覧は
    /// [`Connection::version_negotiation_versions`](crate::Connection::version_negotiation_versions)
    /// で取得できる。終了理由は
    /// [`Connection::closed`](crate::Connection::closed) /
    /// [`Connection::close_reason`](crate::Connection::close_reason) で確認できるが、
    /// Version Negotiation による中止は CONNECTION_CLOSE を伴わないため `None`
    /// になる。再試行が必要な場合は通常の [`Client::connect`] を使う。
    ///
    /// [`ClientBuilder::with_background_driver`] に `true` を指定した場合、
    /// driver がハンドシェイク完了前から受信するため、アプリが早期データを
    /// 書く前にハンドシェイクが完了し得る。この挙動は明示的に opt-in した
    /// 場合だけ発生する。
    pub async fn connect_early(&self, connect: Connect) -> Result<Connection, Error> {
        // 0-RTT 接続は VN 再試行を行わないため、試行バージョンで判定する。
        let version = self.transport.version;
        let address_token = address_token_for_attempt(&connect, version, false);
        let mut inner = QuicConnection::connect_early_with_config_and_bind(
            connect.remote_addr,
            self.io.bind_addr,
            &connect.server_name,
            self.tls.config_for_version(version),
            self.transport.clone(),
            ConnectOptions {
                early_peer_params: connect.early_peer_params,
                qlog_factory: self.qlog_factory.clone(),
                close_formatter: self.close_formatter.clone(),
                cid_generator: Some(Arc::clone(&self.cid_generator)),
                udp_batch: self.io.udp_batch,
                address_token,
                allow_dual_stack: self.io.dual_stack,
                handshake_timeout: None,
            },
        )
        .await?;
        // 監視が設定されていれば、driver task 起動前に有効化する。
        if let Some(interval) = self.network_monitor_interval {
            inner.enable_network_monitor(interval);
        }
        // 0-RTT 接続も `connect()` と同じく追跡する
        let tracker = Arc::clone(&self.connections);
        tracker.register();
        Ok(Connection::from_client(
            inner,
            Some(tracker),
            self.background_driver,
        ))
    }

    /// このクライアントから生成した接続がすべて終了するまで待つ
    ///
    /// 接続の終了は [`Connection::closed`](crate::Connection::closed) と同じく
    /// driver task が終了状態を観測した時点、または driver task が停止した時点で
    /// 判定する。待機開始時点で接続が 1 本も無い場合は即座に完了する。
    ///
    /// この future は接続を進めない。ピア主導の終了を待つ場合は、対象の接続で
    /// [`Connection::enable_background_driver`](crate::Connection::enable_background_driver)
    /// を有効にするか、別のタスクから `drive()` などで接続を進める必要がある。
    ///
    /// 待機中に新しく生成された接続も、接続数が 0 に戻るまで待機対象に含まれる。
    /// 呼び出し時点で接続が 1 本も無い場合は即座に完了する。
    pub async fn wait_idle(&self) {
        self.connections.wait_idle().await;
    }

    /// 接続に使うスケジューラー構成を返す
    ///
    /// `ClientBuilder::with_scheduler` で設定した値、または既定値を返す。
    /// 実際の接続はこの構成に対応するスケジューラーで生成される。
    pub fn scheduler_config(&self) -> SchedulerConfig {
        self.transport.scheduler
    }

    /// 設定されている Connection ID 生成器を返す
    ///
    /// `ClientBuilder::with_connection_id` で設定した生成器を取得する。
    /// この生成器は接続時のクライアント SCID 生成に使われる
    /// (初期 DCID は RFC 9000 Section 7.2 の MUST により 8 バイトの乱数)。
    pub fn cid_generator(&self) -> &dyn ConnectionIdGenerator {
        self.cid_generator.as_ref()
    }
}

impl Server {
    pub fn builder() -> ServerBuilder {
        ServerBuilder {
            tls: None,
            transport: ConnectionConfig::default(),
            io: None,
            endpoint_limits: EndpointLimits::default(),
            cid_generator: None,
            stateless_reset_generator: None,
            retry_config: None,
            mtu_config: None,
            close_formatter: None,
            qlog_factory: None,
            accept_queue_capacity: None,
            preferred_address: None,
            token_provider: None,
            network_monitor_interval: None,
            handshake_timeout: Some(tobi_platform::DEFAULT_HANDSHAKE_TIMEOUT),
            datagram: None,
            multipath: None,
            scheduler: None,
            congestion_control: None,
            versions: None,
            background_driver: false,
        }
    }

    /// ハンドシェイクが完了した接続を受け付ける。
    ///
    /// 未完了のハンドシェイクは並行して処理し、先頭の接続が応答しなくても
    /// 後続を受理する。この待機をキャンセルしても処理中の接続は維持される。
    /// サーバー停止後や、接続の TLS / I/O 処理に失敗した場合はエラーを返す。
    pub async fn accept(&mut self) -> Result<Connection, Error> {
        if self.inner.is_shutdown() {
            return Err(Error::Internal("server is shutting down".into()));
        }
        loop {
            tokio::select! {
                completed = self.handshakes.join_next(), if !self.handshakes.is_empty() => {
                    let mut conn = completed
                        .expect("pending handshake task exists")
                        .expect("server handshake task must not panic")?;
                    // 監視はハンドシェイク完了後に開始し、初回の InterfaceUp を
                    // PathController が利用可能になる前に消費しない。
                    if let Some(interval) = self.network_monitor_interval {
                        conn.enable_network_monitor(interval);
                    }
                    return Ok(Connection::from_server(conn, self.background_driver));
                }
                accepted = self.inner.accept() => {
                    let mut conn = accepted?;
                    // 失われた Initial の待機や指数バックオフを、ほかの接続の
                    // ハンドシェイクとアプリケーション処理へ波及させない。
                    self.handshakes.spawn(async move {
                        conn.handshake().await?;
                        Ok(conn)
                    });
                }
            }
        }
    }

    /// graceful shutdown を実行する (RFC 9000 Section 10.2)
    ///
    /// 新規接続の受付を停止し、既存の全接続へ指定のエラーコードと理由で
    /// CONNECTION_CLOSE を送信してから router を停止する。停止後は `accept()` が
    /// エラーを返す。サーバーを安全に再起動・停止するための経路。
    ///
    /// `timeout` は停止処理全体の上限。超過した場合は残タスクを強制終了して戻る。
    /// `None` を渡すと無制限に待つ。二重に呼んだ場合は 2 回目以降を no-op とする。
    pub async fn shutdown(
        &mut self,
        error_code: u64,
        reason: &[u8],
        timeout: Option<std::time::Duration>,
    ) -> Result<(), Error> {
        // 受理待ちのタスクも停止し、shutdown 後に完了済み接続を返さない。
        // JoinSet の drop が未完了タスクを中断し、その接続の枠も解放する。
        self.handshakes = tokio::task::JoinSet::new();
        self.inner.shutdown(error_code, reason, timeout).await
    }

    /// shutdown 済みかどうかを返す
    pub fn is_shutdown(&self) -> bool {
        self.inner.is_shutdown()
    }

    /// ハンドシェイク中の接続数を返す
    ///
    /// `EndpointLimits::max_inflight_handshakes` の判定に使う値と同じ。
    pub fn inflight_handshake_count(&self) -> usize {
        self.inner.inflight_handshake_count()
    }

    /// ハンドシェイク中と確立済みを合わせた接続数を返す
    ///
    /// `EndpointLimits::max_connections` の判定に使う値と同じ。
    pub fn active_connection_count(&self) -> usize {
        self.inner.active_connection_count()
    }

    /// `EndpointLimits` の上限超過で破棄した Initial の累計数を返す
    pub fn limit_rejected_count(&self) -> u64 {
        self.inner.limit_rejected_count()
    }

    /// サーバーの poll_accept
    pub fn poll_accept(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Connection, Error>> {
        let mut fut = Box::pin(self.accept());
        fut.as_mut().poll(cx)
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.inner.local_addr()
    }

    /// 接続に使うスケジューラー構成を返す
    ///
    /// `ServerBuilder::with_scheduler` で設定した値、または既定値を返す。
    /// このサーバーが受け付ける接続は、この構成に対応するスケジューラーで
    /// 生成される。
    pub fn scheduler_config(&self) -> SchedulerConfig {
        self.scheduler_config
    }

    /// accept キュー満杯で破棄された接続の累計数を返す
    ///
    /// 運用監視やテスト検証で backpressure が働いた回数を観測するためのアクセサ。
    /// `accept()` を呼ばずに新規接続が積み上がった際、router が accept キューの
    /// 枠を予約できずに Initial を破棄した回数がここに反映される。
    pub fn accept_dropped_count(&self) -> u64 {
        self.inner.accept_dropped_count()
    }

    /// router の CID マップに登録されている CID の現在数を返す
    ///
    /// 運用監視やテスト検証で CID リークを観測するためのアクセサ。
    /// 詳細は `tobi_platform::QuicServer::active_cid_count` を参照 (ポーリング前提、
    /// 1 接続あたり複数 CID になる点に注意)。
    pub fn active_cid_count(&self) -> u64 {
        self.inner.active_cid_count()
    }
}

impl ClientBuilder {
    pub fn with_tls(mut self, tls: ClientTlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    pub fn with_io(mut self, io: IoConfig) -> Self {
        self.io = Some(io);
        self
    }

    /// ネットワークインターフェースの変化を監視する (opt-in)
    ///
    /// OS のインターフェース一覧を `getifaddrs` で `interval` ごとにポーリングし、
    /// 変化を `NetworkEvent` として接続へ通知する。通知されたイベントは接続の
    /// PathController に渡され、パスの自動開設・廃棄・状態変更に使われる。
    ///
    /// OS の変化検出はイベント駆動ではなくポーリングであるため、変化が反映される
    /// まで最大で `interval` 分の遅延が生じる。
    ///
    /// 有効化直後の初回ポーリングでは、その時点で存在するインターフェースの
    /// アドレスが `InterfaceUp` として通知される。対象インターフェースは
    /// [`MultipathConfig`] の `interface_filter` で絞り込める。
    ///
    /// 通知されたイベントの処理は接続を駆動したときに行われる。API を呼んで
    /// いない間も自動で処理したい場合は、接続に対して
    /// [`Connection::enable_background_driver`](crate::Connection::enable_background_driver)
    /// を呼ぶ。既定のコマンド駆動では、`drive()` や `accept_path_event()` などの
    /// パケット処理を伴う API を呼んだときに処理される。
    ///
    /// 0-RTT (`connect_early`) で有効化した場合、ハンドシェイク完了前に通知
    /// された初回の `InterfaceUp` は PathController に渡らない。ハンドシェイク
    /// 完了後の変化から反映される。
    ///
    /// `interval` は 0 より大きい必要がある。0 を指定した場合、`start()` は
    /// エラーを返す。
    pub fn with_network_monitor(mut self, interval: Duration) -> Self {
        self.network_monitor_interval = Some(interval);
        self
    }

    /// Multipath の設定を行う
    ///
    /// `with_transport` で渡した `ConnectionConfig` を base とし、この設定を
    /// `start()` で上書きする。呼び出し順は結果に影響しない。
    pub fn with_multipath(mut self, config: MultipathConfig) -> Self {
        self.multipath = Some(config);
        self
    }

    /// DATAGRAM の設定を行う
    ///
    /// `with_transport` で渡した `ConnectionConfig` を base とし、この設定を
    /// `start()` で上書きする。呼び出し順は結果に影響しない。
    pub fn with_datagram(mut self, config: DatagramConfig) -> Self {
        self.datagram = Some(config);
        self
    }

    /// 接続設定を直接指定する
    ///
    /// この設定は base であり、`with_datagram` / `with_multipath` /
    /// `with_scheduler` / `with_congestion_control` / `with_mtu` の設定は
    /// 呼び出し順に関係なく `start()` で優先される。
    ///
    /// `supported_versions` と `version` は `with_versions` (未指定なら既定の
    /// v1) が優先され、この設定の値は使われない。バージョンは `with_versions`
    /// で指定すること。
    pub fn with_transport(mut self, config: ConnectionConfig) -> Self {
        self.transport = config;
        self
    }

    /// ハンドシェイク完了までのタイムアウトを設定する
    ///
    /// 既定は 10 秒。`None` を指定するとタイムアウトしない。
    /// 0 を指定した場合は `start()` がエラーを返す。応答しないサーバーに対して
    /// 接続処理が永遠に待ち続けるのを防ぐために使う。
    pub fn with_handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// 接続生成時から background driver を有効にする (opt-in)
    ///
    /// 有効にすると、[`Client::connect`] と [`Client::connect_early`] が返した
    /// 時点から、アプリケーションが接続 API を待っていない間も受信とタイマーが
    /// 動く。RFC 9000 Section 13.2.1 の ACK と Section 10.1 の idle timeout を、
    /// アプリの API 呼び出しパターンに依存させないために使う。
    ///
    /// 既定は無効 (コマンド駆動)。無効の場合、アプリが API を待っていない間は
    /// 受信とアイドルタイマーが処理されない。接続取得後に
    /// [`Connection::enable_background_driver`] を呼ぶ既存の方法と併用でき、
    /// この設定で有効にした接続では同メソッドは不要である。
    ///
    /// [`Client::connect_early`] で 0-RTT を使う場合、driver がハンドシェイク
    /// 完了前から受信するため、アプリが早期データを書く前にハンドシェイクが
    /// 完了し得る。
    pub fn with_background_driver(mut self, enabled: bool) -> Self {
        self.background_driver = enabled;
        self
    }

    /// スケジューラーの構成を設定する
    ///
    /// データ送信パス選択 / ACK 返送パス / 再送パスの各実装を選択する。
    /// 既定は `SchedulerConfig::default()` (MinRtt / ShortestPath /
    /// SamePathThenCrossPath) であり、設定しない場合は従来と同じ挙動になる。
    /// 型は `tobi_quic::core::scheduler::SchedulerConfig` を参照する。
    pub fn with_scheduler(mut self, config: SchedulerConfig) -> Self {
        self.scheduler = Some(config);
        self
    }

    /// Connection ID 生成器を設定する
    pub fn with_connection_id(mut self, generator: impl ConnectionIdGenerator + 'static) -> Self {
        self.cid_generator = Some(Arc::new(generator));
        self
    }

    /// 輻輳制御アルゴリズムを選択する (RFC 9002 Section 7)
    ///
    /// 既定は `CongestionControlAlgorithm::NewReno`。CUBIC (RFC 9438) /
    /// BBRv2 / BBRv3 も選択できる。
    pub fn with_congestion_control(mut self, algorithm: CongestionControlAlgorithm) -> Self {
        self.congestion_control = Some(algorithm);
        self
    }

    /// MTU 設定を適用する
    ///
    /// `initial_mtu` / `base_mtu` / `max_mtu` は DPLPMTUD の初期値・下限・上限として
    /// 各パスの `MtuController` に反映される。不正な組み合わせ
    /// (`base_mtu < 1200` / `initial_mtu < base_mtu` / `max_mtu < initial_mtu` /
    /// `max_mtu > 65_527`) は `start` でエラーになる。`Client` / `Server` は
    /// `start` を経由してのみ作られるため、`connect` 系の呼び出しや接続受理に
    /// 不正な設定が渡ることはない。
    pub fn with_mtu(mut self, config: MtuConfig) -> Self {
        self.mtu_config = Some(config);
        self
    }

    /// CONNECTION_CLOSE の reason phrase フォーマッタを設定する
    ///
    /// 設定した場合、`Connection::close` と `Connection::close_application` が送る
    /// CONNECTION_CLOSE の reason phrase を `formatter.format(error_code, reason)` の
    /// 戻り値にする。整形はクローズ 1 回につき 1 回だけ行う。
    /// `SilentConnectionCloseFormatter` を使うと本番向けに reason を空文字列で
    /// 送信できる。未設定なら reason バイト列をそのまま送信する。
    /// application close を Initial / Handshake へ 0x1c 変換して送るときは、
    /// RFC 9000 Section 10.2.3 の MUST により reason phrase を空にする。
    pub fn with_connection_close_formatter(
        mut self,
        formatter: impl ConnectionCloseFormatter + 'static,
    ) -> Self {
        self.close_formatter = Some(Arc::new(formatter));
        self
    }

    /// qlog writer Factory を設定する
    ///
    /// 設定した場合、接続ごとに `factory.create(odcid)` が呼ばれ、返された
    /// writer が `Connection` に装着される。未設定または factory が `None` を
    /// 返した接続では qlog は完全に無効化される (デフォルト)。
    ///
    /// qlog は Session/Connection ID、パケットサイズ、フレーム内容など機微データを
    /// 含み得る (draft-ietf-quic-qlog-main-schema-14 Section 14.1 参照)。Section 14.2 の
    /// recommendation「enabling qlog conspicuous」に沿って、利用者が明示的に factory を
    /// 指定した場合のみ有効化する設計。
    pub fn with_qlog_writer_factory(mut self, factory: Arc<dyn QlogWriterFactory>) -> Self {
        self.qlog_factory = Some(factory);
        self
    }

    /// 対応する QUIC バージョンと優先順を設定する
    ///
    /// 一覧の先頭が最初の接続試行で使うバージョンになる。Version Negotiation を
    /// 受信した場合は、この順序で未試行の対応バージョンを選んで再試行する
    /// (RFC 9000 Section 6.2)。既定は v1 のみ。
    ///
    /// 重複したバージョンは順序を保って除去する。空の一覧や本実装が対応しない
    /// バージョンを含む場合は `start()` がエラーを返す。
    pub fn with_versions(mut self, versions: Vec<u32>) -> Self {
        self.versions = versions;
        self
    }

    pub fn start(self) -> Result<Client, Error> {
        validate_network_monitor_interval(self.network_monitor_interval)?;
        if let Some(timeout) = self.handshake_timeout
            && timeout.is_zero()
        {
            return Err(Error::Protocol(
                "handshake timeout must be greater than zero".into(),
            ));
        }
        // バージョン一覧の妥当性を起動時に検証する
        if self.versions.is_empty() {
            return Err(Error::Protocol(
                "at least one QUIC version is required".into(),
            ));
        }
        if let Some(version) = self
            .versions
            .iter()
            .find(|version| !tobi_core::packet::is_supported_version(**version))
        {
            return Err(Error::Protocol(format!(
                "unsupported QUIC version in configuration: {version:#010x}"
            )));
        }
        let versions = dedupe_versions(self.versions);
        let tls = self
            .tls
            .ok_or_else(|| Error::Internal("client TLS config is required".into()))?;
        let io = self
            .io
            .ok_or_else(|| Error::Internal("client I/O config is required".into()))?;
        let cid_generator = self
            .cid_generator
            .unwrap_or_else(|| Arc::new(DefaultConnectionIdGenerator::default()));
        // MTU / DATAGRAM / Multipath / Scheduler / Congestion Control を
        // `with_transport` の設定へ固定順に適用する。個別 setter の設定は
        // 呼び出し順に関係なくここで優先される。
        let mut transport = build_transport(
            self.transport,
            self.mtu_config.as_ref(),
            self.datagram.as_ref(),
            self.multipath.as_ref(),
            self.scheduler,
            self.congestion_control,
        );
        // RFC 9000 Section 14 / RFC 8899: MTU 設定を start の入口で検証する。
        // `PathManager::new` は不正な設定を既定値へフォールバックするため、
        // ここで拒否しないと利用者が誤った設定に気づけない。`with_transport` で
        // 直接渡された `ConnectionConfig::mtu` も同じ検証を通す。
        transport
            .mtu
            .validate()
            .map_err(|e| Error::Protocol(format!("invalid MTU config: {e}")))?;
        // DATAGRAM のキュー上限は 0 を許さない。0 のキューは DATAGRAM を
        // 保持できず、設定ミスに気づけないまま常に破棄する状態になる。
        validate_datagram_queue_config(&transport)?;
        // 送信するトランスポートパラメータの妥当性を起動時に検証する
        transport
            .transport_params
            .validate_local()
            .map_err(|e| Error::Protocol(format!("invalid transport parameters: {e}")))?;
        transport.supported_versions = versions.clone();
        // 最初の試行に使うバージョン。再試行時は connect() が上書きする。
        transport.version = versions[0];
        Ok(Client {
            tls,
            transport,
            io,
            cid_generator,
            qlog_factory: self.qlog_factory,
            close_formatter: self.close_formatter,
            connections: Arc::new(ConnectionTracker::default()),
            network_monitor_interval: self.network_monitor_interval,
            handshake_timeout: self.handshake_timeout,
            versions,
            background_driver: self.background_driver,
        })
    }
}

impl ServerBuilder {
    pub fn with_tls(mut self, tls: ServerTlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    pub fn with_io(mut self, io: IoConfig) -> Self {
        self.io = Some(io);
        self
    }

    /// 受け付けた接続でネットワークインターフェースの変化を監視する (opt-in)
    ///
    /// OS のインターフェース一覧を `getifaddrs` で `interval` ごとにポーリングし、
    /// 変化を `NetworkEvent` として各接続へ通知する。通知されたイベントは接続の
    /// PathController に渡され、パスの自動開設・廃棄・状態変更に使われる。
    ///
    /// 監視はハンドシェイク完了後の接続で有効化される。OS の変化検出は
    /// イベント駆動ではなくポーリングであるため、変化が反映されるまで最大で
    /// `interval` 分の遅延が生じる。
    ///
    /// 通知されたイベントの処理は接続を駆動したときに行われる。API を呼んで
    /// いない間も自動で処理したい場合は、`accept()` で得た接続に対して
    /// [`Connection::enable_background_driver`](crate::Connection::enable_background_driver)
    /// を呼ぶ。
    ///
    /// `interval` は 0 より大きい必要がある。0 を指定した場合、`start()` は
    /// エラーを返す。
    pub fn with_network_monitor(mut self, interval: Duration) -> Self {
        self.network_monitor_interval = Some(interval);
        self
    }

    /// Multipath の設定を行う
    ///
    /// `with_transport` で渡した `ConnectionConfig` を base とし、この設定を
    /// `start()` で上書きする。呼び出し順は結果に影響しない。
    pub fn with_multipath(mut self, config: MultipathConfig) -> Self {
        self.multipath = Some(config);
        self
    }

    /// DATAGRAM の設定を行う
    ///
    /// `with_transport` で渡した `ConnectionConfig` を base とし、この設定を
    /// `start()` で上書きする。呼び出し順は結果に影響しない。
    pub fn with_datagram(mut self, config: DatagramConfig) -> Self {
        self.datagram = Some(config);
        self
    }

    /// 接続設定を直接指定する
    ///
    /// この設定は base であり、`with_datagram` / `with_multipath` /
    /// `with_scheduler` / `with_congestion_control` / `with_mtu` /
    /// `with_versions` の設定は呼び出し順に関係なく `start()` で優先される。
    /// `supported_versions` は `with_versions` を呼ばない場合だけ使われ、
    /// `version` は一覧の先頭バージョンで上書きされる。
    pub fn with_transport(mut self, config: ConnectionConfig) -> Self {
        self.transport = config;
        self
    }

    /// スケジューラーの構成を設定する
    ///
    /// データ送信パス選択 / ACK 返送パス / 再送パスの各実装を選択する。
    /// 既定は `SchedulerConfig::default()` (MinRtt / ShortestPath /
    /// SamePathThenCrossPath) であり、設定しない場合は従来と同じ挙動になる。
    /// 型は `tobi_quic::core::scheduler::SchedulerConfig` を参照する。
    pub fn with_scheduler(mut self, config: SchedulerConfig) -> Self {
        self.scheduler = Some(config);
        self
    }

    /// エンドポイントの接続制限を設定する
    /// エンドポイントの接続数制限を設定する
    ///
    /// DoS 対策として同時ハンドシェイク数と同時接続数を制限する。
    /// `max_inflight_handshakes` は既定で 100、`max_connections` は既定で 1000。
    /// 上限に達している間、router は新規 Initial を破棄する
    /// (RFC 9000 Section 21.2)。
    pub fn with_endpoint_limits(mut self, limits: EndpointLimits) -> Self {
        self.endpoint_limits = limits;
        self
    }

    /// Connection ID 生成器を設定する
    pub fn with_connection_id(mut self, generator: impl ConnectionIdGenerator + 'static) -> Self {
        self.cid_generator = Some(Arc::new(generator));
        self
    }

    /// 輻輳制御アルゴリズムを選択する (RFC 9002 Section 7)
    ///
    /// 既定は `CongestionControlAlgorithm::NewReno`。CUBIC (RFC 9438) /
    /// BBRv2 / BBRv3 も選択できる。
    pub fn with_congestion_control(mut self, algorithm: CongestionControlAlgorithm) -> Self {
        self.congestion_control = Some(algorithm);
        self
    }

    /// Stateless Reset Token 生成器を設定する
    ///
    /// 設定した場合、CID 発行 (`generate_new_cid` / `issue_proactive_cids`) が
    /// 生成する Stateless Reset Token をこの生成器から得る。静的鍵を渡すことで
    /// 同一 CID から決定的に Token を再生成でき、マルチインスタンス / 再起動を
    /// またいだ Stateless Reset に使用できる (RFC 9000 Section 10.3.2)。
    /// 未設定の場合は従来どおり乱数で Token を生成する。
    pub fn with_stateless_reset_token(
        mut self,
        generator: impl StatelessResetTokenGenerator + 'static,
    ) -> Self {
        self.stateless_reset_generator = Some(Arc::new(generator));
        self
    }

    /// MTU 設定を適用する
    /// Retry によるアドレス検証を有効にする (RFC 9000 Section 8.1)
    ///
    /// 有効にすると、サーバーは token を持たない Initial に対して Retry を返し、
    /// token 付きの Initial で再接続させる。token は `token_key` で AEAD 保護し、
    /// `max_age_secs` を過ぎた token は拒否する。
    ///
    /// これにより未検証のクライアントからの状態枯渇と増幅攻撃を防げる。
    pub fn with_retry(mut self, token_key: [u8; 16], max_age_secs: u64) -> Self {
        self.retry_config = Some(tobi_platform::RetryConfig::new(token_key, max_age_secs));
        self
    }

    /// MTU 設定を適用する
    ///
    /// `initial_mtu` / `base_mtu` / `max_mtu` は DPLPMTUD の初期値・下限・上限として
    /// 各パスの `MtuController` に反映される。不正な組み合わせ
    /// (`base_mtu < 1200` / `initial_mtu < base_mtu` / `max_mtu < initial_mtu` /
    /// `max_mtu > 65_527`) は `start` でエラーになる。`Client` / `Server` は
    /// `start` を経由してのみ作られるため、`connect` 系の呼び出しや接続受理に
    /// 不正な設定が渡ることはない。
    pub fn with_mtu(mut self, config: MtuConfig) -> Self {
        self.mtu_config = Some(config);
        self
    }

    /// CONNECTION_CLOSE の reason phrase フォーマッタを設定する
    ///
    /// 設定した場合、`Connection::close` と `Connection::close_application` が送る
    /// CONNECTION_CLOSE の reason phrase を `formatter.format(error_code, reason)` の
    /// 戻り値にする。整形はクローズ 1 回につき 1 回だけ行う。
    /// `SilentConnectionCloseFormatter` を使うと本番向けに reason を空文字列で
    /// 送信できる。未設定なら reason バイト列をそのまま送信する。
    /// application close を Initial / Handshake へ 0x1c 変換して送るときは、
    /// RFC 9000 Section 10.2.3 の MUST により reason phrase を空にする。
    pub fn with_connection_close_formatter(
        mut self,
        formatter: impl ConnectionCloseFormatter + 'static,
    ) -> Self {
        self.close_formatter = Some(Arc::new(formatter));
        self
    }

    /// qlog writer Factory を設定する
    ///
    /// 設定した場合、新規接続ごとに `factory.create(odcid)` が呼ばれ、返された
    /// writer が `Connection` に装着される。未設定または factory が `None` を
    /// 返した接続では qlog は完全に無効化される (デフォルト)。
    ///
    /// draft-ietf-quic-qlog-main-schema-14 Section 14.1 (Data at risk) と
    /// Section 14.2 (明示的オプトイン) を踏まえたデフォルト無効化。
    pub fn with_qlog_writer_factory(mut self, factory: Arc<dyn QlogWriterFactory>) -> Self {
        self.qlog_factory = Some(factory);
        self
    }

    /// accept キューの容量を設定する
    ///
    /// `Server::accept()` がこの容量を超える速度で呼ばれない場合、あふれた
    /// 新規 Initial は silent discard される (`Server::accept_dropped_count()` で
    /// 観測できる)。既定値は
    /// [`tobi_platform::DEFAULT_ACCEPT_QUEUE_CAPACITY`]。
    /// 0 を指定した場合は [`ServerBuilder::start`] が `Error::Internal` を返す。
    pub fn with_accept_queue_capacity(mut self, capacity: usize) -> Self {
        self.accept_queue_capacity = Some(capacity);
        self
    }

    /// ハンドシェイク完了までのタイムアウトを設定する
    ///
    /// `None` ならタイムアウトしない。既定は
    /// [`tobi_platform::DEFAULT_HANDSHAKE_TIMEOUT`]。停滞したハンドシェイクで
    /// `accept()` が永久に待ち続けるのを防ぐ。0 を指定した場合は
    /// [`ServerBuilder::start`] が `Error::Protocol` を返す。
    pub fn with_handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// 接続生成時から background driver を有効にする (opt-in)
    ///
    /// 有効にすると、[`Server::accept`] が返した時点から、アプリケーションが
    /// 接続 API を待っていない間も受信とタイマーが動く。RFC 9000 Section 13.2.1
    /// の ACK と Section 10.1 の idle timeout を、アプリの API 呼び出しパターンに
    /// 依存させないために使う。
    ///
    /// 既定は無効 (コマンド駆動)。無効の場合、アプリが API を待っていない間は
    /// 受信とアイドルタイマーが処理されない。接続取得後に
    /// [`Connection::enable_background_driver`] を呼ぶ既存の方法と併用でき、
    /// この設定で有効にした接続では同メソッドは不要である。
    pub fn with_background_driver(mut self, enabled: bool) -> Self {
        self.background_driver = enabled;
        self
    }

    /// サーバーがハンドシェイク応答で広告する preferred_address を設定する
    /// (RFC 9000 Section 18.2)
    ///
    /// クライアントは広告されたアドレスへ `Connection::migrate_to_preferred_address`
    /// で移行できる。`ipv4` / `ipv6` はアドレスファミリごとの広告先で、
    /// `None` のファミリは広告しない。両方 `None` を指定した場合は
    /// [`ServerBuilder::start`] が `Error::Protocol` を返す。
    ///
    /// port に 0 を指定した場合は、サーバーが実際にバインドしたポートを使う。
    /// CID と Stateless Reset Token はサーバーの CID 生成器と
    /// Stateless Reset Token 生成器から接続ごとに発行される。
    pub fn with_preferred_address(
        mut self,
        ipv4: Option<SocketAddr>,
        ipv6: Option<SocketAddr>,
    ) -> Self {
        self.preferred_address = Some(PreferredAddressConfig::new(ipv4, ipv6));
        self
    }

    /// NEW_TOKEN のトークン生成・検証に使うプロバイダを設定する
    /// (RFC 9000 Section 8.1.3)
    ///
    /// 設定した場合、サーバーは Initial に載っているアドレストークンを検証し、
    /// パス検証に成功したクライアントへ NEW_TOKEN を自動発行する。
    /// トークン形式はプロバイダの実装に依存する。HMAC-SHA256 ベースの
    /// 実装は `tobi_crypto::token::HmacTokenProvider` にある。
    ///
    /// サーバー全体で同一のプロバイダを共有するため `Arc` で渡す。
    pub fn with_token_provider(mut self, provider: Arc<dyn TokenProvider>) -> Self {
        self.token_provider = Some(provider);
        self
    }

    /// サーバーが受理する QUIC バージョンと優先順を設定する
    ///
    /// 一覧に含まれないバージョンの Initial には Version Negotiation を返す
    /// (RFC 9000 Section 6.1)。既定は v1 のみ。
    ///
    /// 重複したバージョンは順序を保って除去する。空の一覧や本実装が対応しない
    /// バージョンを含む場合は `start()` がエラーを返す。呼ばない場合は
    /// `with_transport` の `supported_versions` を使う。
    pub fn with_versions(mut self, versions: Vec<u32>) -> Self {
        self.versions = Some(versions);
        self
    }

    pub fn start(self) -> Result<Server, Error> {
        validate_network_monitor_interval(self.network_monitor_interval)?;
        if let Some(timeout) = self.handshake_timeout
            && timeout.is_zero()
        {
            return Err(Error::Protocol(
                "handshake timeout must be greater than zero".into(),
            ));
        }
        let versions = resolve_versions(self.versions, &self.transport.supported_versions)?;
        let tls = self
            .tls
            .ok_or_else(|| Error::Internal("server TLS config is required".into()))?;
        let io = self
            .io
            .ok_or_else(|| Error::Internal("server I/O config is required".into()))?;
        let replay_filter = tls.replay_filter.clone();
        // MTU / DATAGRAM / Multipath / Scheduler / Congestion Control を
        // `with_transport` の設定へ固定順に適用する。個別 setter の設定は
        // 呼び出し順に関係なくここで優先される。
        let mut transport = build_transport(
            self.transport,
            self.mtu_config.as_ref(),
            self.datagram.as_ref(),
            self.multipath.as_ref(),
            self.scheduler,
            self.congestion_control,
        );
        // 検証済みのバージョン一覧を base 設定へ反映する。接続ごとのバージョンは
        // ルーターが Initial に合わせて設定する。ベース設定には先頭バージョンを
        // 入れておく。
        transport.version = versions[0];
        transport.supported_versions = versions;
        // RFC 9000 Section 14 / RFC 8899: MTU 設定を start の入口で検証する。
        // `PathManager::new` は不正な設定を既定値へフォールバックするため、
        // ここで拒否しないと利用者が誤った設定に気づけない。`with_transport` で
        // 直接渡された `ConnectionConfig::mtu` も同じ検証を通す。
        transport
            .mtu
            .validate()
            .map_err(|e| Error::Protocol(format!("invalid MTU config: {e}")))?;
        // DATAGRAM のキュー上限は 0 を許さない。0 のキューは DATAGRAM を
        // 保持できず、設定ミスに気づけないまま常に破棄する状態になる。
        validate_datagram_queue_config(&transport)?;
        // 送信するトランスポートパラメータの妥当性を起動時に検証する
        transport
            .transport_params
            .validate_local()
            .map_err(|e| Error::Protocol(format!("invalid transport parameters: {e}")))?;
        let scheduler_config = transport.scheduler;
        // RFC 9369 Section 5: セッションチケットをバージョンに束縛するため、
        // バージョンごとにチケット鍵を分離した TLS 設定を渡す。
        let versioned_tls_configs =
            versioned_server_tls_configs(&tls.inner, &transport.supported_versions)?;
        let inner = QuicServer::bind_with_config(
            io.bind_addr,
            tls.inner,
            transport,
            BindOptions {
                versioned_tls_configs: Some(versioned_tls_configs),
                replay_filter,
                qlog_factory: self.qlog_factory,
                close_formatter: self.close_formatter,
                stateless_reset_generator: self.stateless_reset_generator,
                cid_generator: self.cid_generator,
                retry_config: self.retry_config,
                endpoint_limits: self.endpoint_limits,
                accept_queue_capacity: self.accept_queue_capacity,
                udp_batch: io.udp_batch,
                allow_dual_stack: io.dual_stack,
                reuse_port: io.reuse_port,
                preferred_address: self.preferred_address,
                token_provider: self.token_provider,
                handshake_timeout: self.handshake_timeout,
            },
        )?;
        Ok(Server {
            inner,
            handshakes: tokio::task::JoinSet::new(),
            scheduler_config,
            network_monitor_interval: self.network_monitor_interval,
            background_driver: self.background_driver,
        })
    }
}

/// 接続試行に使うアドレストークンを決める
///
/// RFC 9369 Section 5: トークンは発行した QUIC バージョンに固有であり、
/// クライアントは別バージョンの接続で使用してはならない (MUST)。
/// Version Negotiation 後の再試行 (バージョンが変わる) ではトークンを捨てる。
fn address_token_for_attempt(connect: &Connect, version: u32, is_retry: bool) -> Option<Vec<u8>> {
    if is_retry {
        return None;
    }
    let token = connect.address_token.as_ref()?;
    if token.version != version {
        return None;
    }
    Some(token.token.clone())
}

#[cfg(test)]
mod tests;
