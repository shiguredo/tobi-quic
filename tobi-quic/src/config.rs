// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::sync::Arc;

use crate::error::Error;
use tobi_core::connection::ConnectionConfig;
use tobi_core::path::policy::{
    InterfaceFilter as CoreInterfaceFilter, MultipathMode as CoreMultipathMode, MultipathPolicy,
};
use tobi_core::transport_params::TransportParams;
// `IoConfig` のフィールド型を利用者が名前解決できるよう re-export する。
pub use tobi_platform::UdpBatchConfig;

// ConnectionCloseFormatter とその実装は tobi-core に移設した。
// `tobi_quic` クレート経由の import パス (`tobi_quic::config::ConnectionCloseFormatter` および
// `tobi_quic::ConnectionCloseFormatter` の両方) を維持するため re-export する。
// EndpointLimits も tobi-core に移設した (`tobi-platform` から参照するため)。
// `tobi_quic` クレート経由の import パスを維持するため re-export する。
pub use tobi_core::connection::{
    ConnectionCloseFormatter, EndpointLimits, SilentConnectionCloseFormatter,
};

/// Multipath モード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultipathMode {
    Handover,
    Aggregate,
    Backup,
}

impl From<MultipathMode> for CoreMultipathMode {
    fn from(value: MultipathMode) -> Self {
        match value {
            MultipathMode::Handover => Self::Handover,
            MultipathMode::Aggregate => Self::Aggregate,
            MultipathMode::Backup => Self::Backup,
        }
    }
}

/// インターフェースフィルタ
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceFilter {
    All,
    Allow(Vec<String>),
    Deny(Vec<String>),
}

impl From<InterfaceFilter> for CoreInterfaceFilter {
    fn from(value: InterfaceFilter) -> Self {
        match value {
            InterfaceFilter::All => Self::All,
            InterfaceFilter::Allow(v) => Self::Allow(v),
            InterfaceFilter::Deny(v) => Self::Deny(v),
        }
    }
}

/// Multipath 設定
#[derive(Debug, Clone)]
pub struct MultipathConfig {
    pub mode: MultipathMode,
    pub interface_filter: InterfaceFilter,
    pub max_paths: usize,
    pub initial_max_path_id: u32,
    /// 同時に実行するパス検証の上限 (既定 4、0 は 1 として扱う)
    pub max_concurrent_validations: usize,
}

impl Default for MultipathConfig {
    fn default() -> Self {
        Self {
            mode: MultipathMode::Handover,
            interface_filter: InterfaceFilter::All,
            max_paths: 2,
            initial_max_path_id: 4,
            max_concurrent_validations: 4,
        }
    }
}

impl MultipathConfig {
    pub(crate) fn apply_to(&self, config: &mut ConnectionConfig) {
        config.transport_params.initial_max_path_id = Some(self.initial_max_path_id);
        config.max_concurrent_path_validations = self.max_concurrent_validations;
        config.multipath_policy = MultipathPolicy {
            mode: self.mode.into(),
            interface_filter: self.interface_filter.clone().into(),
            max_paths: self.max_paths,
        };
    }
}

/// DATAGRAM 設定
#[derive(Debug, Clone, Copy)]
pub struct DatagramConfig {
    pub max_datagram_frame_size: u64,
}

impl Default for DatagramConfig {
    fn default() -> Self {
        Self {
            max_datagram_frame_size: 65535,
        }
    }
}

impl DatagramConfig {
    pub(crate) fn apply_to(&self, config: &mut ConnectionConfig) {
        config.transport_params.max_datagram_frame_size = Some(self.max_datagram_frame_size);
    }
}

/// I/O 設定
#[derive(Debug, Clone, Copy)]
pub struct IoConfig {
    /// バインドするローカルアドレス
    pub bind_addr: SocketAddr,
    /// UDP のバッチ I/O の設定。`None` なら 1 データグラムずつ送受信する
    ///
    /// Linux / Android では `sendmmsg` / `recvmmsg` と GSO / GRO が使える。
    /// 既定は無効で、有効にしない限り従来の 1 データグラム 1 システムコールで
    /// 動作する。
    pub udp_batch: Option<UdpBatchConfig>,
    /// 特定アドレスへ bind した場合も別アドレスファミリの wildcard で待ち受ける
    ///
    /// 既定は `false`。`0.0.0.0` / `::` の wildcard を指定した場合だけ
    /// デュアルスタックで待ち受ける。loopback や特定インターフェースを指定した
    /// サーバーの公開範囲を意図せず広げないための opt-in。
    pub dual_stack: bool,
    /// サーバーの初期ソケットに `SO_REUSEPORT` を設定する
    ///
    /// 既定は `true`。`false` にすると同じポートへの別プロセスの bind を
    /// OS が拒否する。クライアントは使用しない。
    pub reuse_port: bool,
}

impl IoConfig {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            udp_batch: None,
            dual_stack: false,
            reuse_port: true,
        }
    }

    /// サーバーの初期ソケットで `SO_REUSEPORT` を設定するか指定する
    pub fn with_reuse_port(mut self, enabled: bool) -> Self {
        self.reuse_port = enabled;
        self
    }

    /// 特定アドレスへの bind でも別ファミリの wildcard で待ち受ける
    pub fn with_dual_stack(mut self, enabled: bool) -> Self {
        self.dual_stack = enabled;
        self
    }

    /// UDP のバッチ I/O を有効にする
    pub fn with_udp_batch(mut self, config: UdpBatchConfig) -> Self {
        self.udp_batch = Some(config);
        self
    }
}

/// クライアント TLS 設定
#[derive(Clone)]
pub struct ClientTlsConfig {
    pub(crate) inner: Arc<rustls::ClientConfig>,
    /// QUIC バージョンごとに分離したセッションチケットストア
    ///
    /// 設定時は接続試行ごとに rustls の ClientConfig を複製し、そのバージョン専用の
    /// ストアを組み込む。RFC 9369 Section 5: セッションチケットは発行した QUIC
    /// バージョンに固有であり、別バージョンの接続で使用してはならない (MUST)。
    pub(crate) versioned_session_store: Option<Arc<crate::session::VersionedSessionStore>>,
}

impl ClientTlsConfig {
    pub fn new(inner: Arc<rustls::ClientConfig>) -> Self {
        Self {
            inner,
            versioned_session_store: None,
        }
    }

    /// バージョンごとに分離したセッションチケットストアを設定する
    ///
    /// `SessionTicketStore` をバージョンごとに保持するため、QUIC バージョン間で
    /// セッションチケットが混ざらない。複数バージョンを取り扱うクライアントでは
    /// 本メソッドを使うこと。
    pub fn with_versioned_session_store(
        mut self,
        store: Arc<crate::session::VersionedSessionStore>,
    ) -> Self {
        self.versioned_session_store = Some(store);
        self
    }

    /// 指定バージョンの接続で使う rustls ClientConfig を返す
    ///
    /// バージョン分離ストアが設定されている場合は、そのバージョン専用の
    /// ストアを組み込んだ複製を返す。未設定の場合は元の設定を共有する。
    pub(crate) fn config_for_version(&self, version: u32) -> Arc<rustls::ClientConfig> {
        match &self.versioned_session_store {
            Some(store) => {
                let mut config = (*self.inner).clone();
                config.resumption = rustls::client::Resumption::store(store.store_for(version));
                Arc::new(config)
            }
            None => Arc::clone(&self.inner),
        }
    }

    /// セッション再開に使うストアを設定する
    ///
    /// `rustls::ClientConfig::resumption` を指定したストアに差し替える。
    /// 次回接続用に別の `ClientConfig` を作る場合も同じストアを渡すことで、
    /// プロセス内で TLS 1.3 のセッションを再開できる。典型的な使い方は
    /// `tobi_quic::session::SessionTicketStore` を `Arc` で共有する方法である。
    ///
    /// rustls はクライアントセッションのバイト列表現を公開しないため、
    /// ストアをプロセス外へ永続化することはできない。
    ///
    /// 異なる `ClientConfig` 間の再開には追加の制約がある。rustls は
    /// `ServerCertVerifier` と `ResolvesClientCert` が同一インスタンス
    /// (`Arc::ptr_eq`) の場合のみ再開を許可するため、両方の設定で同じ
    /// インスタンスを共有する必要がある。
    ///
    /// `Arc` が他の場所と共有されている場合は `rustls::ClientConfig` を
    /// 書き換えられないためエラーを返す。`ClientTlsConfig::new(Arc::new(config))`
    /// の直後に呼ぶこと。
    ///
    /// 複数の QUIC バージョンを取り扱う場合は、セッションチケットが
    /// バージョン間で混ざらないよう [`ClientTlsConfig::with_versioned_session_store`]
    /// を使うこと (RFC 9369 Section 5)。
    pub fn with_session_store(
        mut self,
        store: Arc<dyn rustls::client::ClientSessionStore>,
    ) -> Result<Self, Error> {
        let config = Arc::get_mut(&mut self.inner).ok_or_else(|| {
            Error::Internal(
                "client TLS config is shared; session store must be installed before cloning"
                    .to_string(),
            )
        })?;
        config.resumption = rustls::client::Resumption::store(store);
        Ok(self)
    }
}

/// サーバー TLS 設定
#[derive(Clone)]
pub struct ServerTlsConfig {
    pub(crate) inner: Arc<rustls::ServerConfig>,
    pub(crate) replay_filter: Option<Arc<dyn tobi_core::token::ReplayFilter>>,
}

impl ServerTlsConfig {
    pub fn new(inner: Arc<rustls::ServerConfig>) -> Self {
        Self {
            inner,
            replay_filter: None,
        }
    }

    /// 0-RTT リプレイフィルターを設定する (RFC 9001 Section 9.2)
    ///
    /// サーバー全体で共有するフィルター。同じセッションチケット由来の 0-RTT
    /// パケットが同時に複数到着した場合に二重処理を防ぐ。`rustls::ServerConfig`
    /// 側で `max_early_data_size > 0` に設定する場合は、本フィルターの設定が
    /// 必須である。未設定のままサーバーを起動するとエラーになる。
    pub fn with_replay_filter(mut self, filter: Arc<dyn tobi_core::token::ReplayFilter>) -> Self {
        self.replay_filter = Some(filter);
        self
    }
}

/// アドレス検証トークンと発行バージョン
///
/// RFC 9369 Section 5: NEW_TOKEN で配布されるトークンは発行した QUIC バージョンに
/// 固有であり、別バージョンの接続で使用してはならない (MUST)。トークンを保存する
/// 場合は、`Connection::version()` などで取得した発行時のバージョンと一緒に保持し、
/// 次回接続時に本型で指定する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressToken {
    /// トークンを発行した接続の QUIC バージョン
    pub version: u32,
    /// トークンのバイト列
    pub token: Vec<u8>,
}

impl AddressToken {
    /// トークンと発行バージョンを指定して作成する
    pub fn new(token: Vec<u8>, version: u32) -> Self {
        Self { version, token }
    }
}

/// 接続要求
#[derive(Debug, Clone)]
pub struct Connect {
    pub(crate) remote_addr: SocketAddr,
    pub(crate) server_name: String,
    pub(crate) early_peer_params: Option<TransportParams>,
    pub(crate) address_token: Option<AddressToken>,
}

impl Connect {
    pub fn new(remote_addr: SocketAddr, server_name: impl Into<String>) -> Self {
        Self {
            remote_addr,
            server_name: server_name.into(),
            early_peer_params: None,
            address_token: None,
        }
    }

    /// 前回セッションで取得したピアの transport parameter を 0-RTT 用に設定する
    ///
    /// RFC 9001 Section 4.6.1 / RFC 9000 Section 7.4.1: クライアントは前回セッションで
    /// 使用されたサーバーの transport parameter を記憶し、0-RTT 送信に使用しなければならない。
    /// 本 API で渡された値は Initial 送信前に Connection へ適用される。
    ///
    /// 別プロセスや次回起動時に再利用する場合は、`Connection::peer_transport_params()`
    /// で取得した値を `TransportParams::encode` でバイト列として保存し、
    /// 次回接続時に `TransportParams::decode` で復元して本 API に渡す。
    /// TLS のセッションチケットは `ClientTlsConfig::with_session_store` で
    /// 共有したストアが保持する。サーバー名とチケットの対応は利用者が管理する。
    pub fn with_early_peer_params(mut self, params: TransportParams) -> Self {
        self.early_peer_params = Some(params);
        self
    }

    /// 前回接続で受信した NEW_TOKEN を Initial に載せる (RFC 9000 Section 8.1.3)
    ///
    /// `ApplicationEvent::NewToken` で受け取ったトークンをそのまま渡す。
    /// サーバーがトークンを検証できれば、クライアントのアドレスは検証済みと
    /// して受理され、接続開始時のアドレス検証を省略できる。
    ///
    /// トークンの形式と有効期限はサーバーの `TokenProvider` の実装に依存する。
    /// サーバーが拒否した場合も接続は継続し、アドレス未検証として扱われる。
    ///
    /// サーバー名や前回接続時のアドレスが変わると、トークンが無効になる
    /// 実装 (アドレスを含めて検証する `HmacTokenProvider` など) があるため、
    /// 同じ接続先への再接続でのみ使うこと。
    /// アドレス検証トークンと発行バージョンを設定する
    ///
    /// RFC 9369 Section 5: トークンは発行元の QUIC バージョンに固有である。
    /// 発行時のバージョンと異なるバージョンで接続する場合、このトークンは
    /// 送信されない (クライアント MUST NOT)。Version Negotiation による
    /// 再試行でもトークンは破棄される。
    pub fn with_address_token(mut self, token: AddressToken) -> Self {
        self.address_token = Some(token);
        self
    }
}

/// 輻輳制御アルゴリズムの選択 (RFC 9002 Section 7)
///
/// 実体は tobi-core に定義した enum を再公開する。既定は NewReno。
pub use tobi_core::recovery::CongestionControlAlgorithm;

/// MTU 設定
///
/// DPLPMTUD の初期値・下限・上限をカスタマイズする。
///
/// 既定値は `tobi_core::connection::MtuConfig` と一致する
/// (`max_mtu` は IPv6 40 + UDP 8 を引いた QUIC ペイロード上限相当の 1452)。
///
/// `max_mtu` は RFC 9000 Section 18.2 の最大 UDP ペイロード 65,527 以下で
/// なければならない。
#[derive(Debug, Clone, Copy)]
pub struct MtuConfig {
    /// 初期 MTU (デフォルト: 1200)
    pub initial_mtu: u16,
    /// DPLPMTUD が下回らない最小 MTU (デフォルト: 1200)
    pub base_mtu: u16,
    /// 探索上限 MTU (デフォルト: 1452、最大 65,527)
    pub max_mtu: u16,
}

impl Default for MtuConfig {
    fn default() -> Self {
        Self {
            initial_mtu: 1200,
            base_mtu: 1200,
            max_mtu: 1452,
        }
    }
}

impl MtuConfig {
    /// `ConnectionConfig` の MTU 設定へ反映する
    ///
    /// 検証は `ClientBuilder::start` / `ServerBuilder::start` で行うため、
    /// ここでは値の反映だけを行う。`PathManager::new` は不正な設定を既定値へ
    /// フォールバックするが、公開 API の入口で拒否するためその経路は通らない。
    pub(crate) fn apply_to(&self, config: &mut ConnectionConfig) {
        config.mtu = tobi_core::connection::MtuConfig {
            initial_mtu: self.initial_mtu,
            base_mtu: self.base_mtu,
            max_mtu: self.max_mtu,
        };
    }
}

/// バージョンごとにチケット鍵を分離した rustls サーバー設定を作る
///
/// RFC 9369 Section 5: TLS セッションチケットは発行した QUIC バージョンに固有で
/// あり、サーバーは別バージョンのチケットを受け入れてはならない (MUST)。
/// バージョンごとにチケット鍵を変えると、別バージョンで発行されたチケットは
/// TLS 層で復号できず、再開が拒否されてフルハンドシェイクにフォールバックする。
pub(crate) fn versioned_server_tls_configs(
    inner: &Arc<rustls::ServerConfig>,
    versions: &[u32],
) -> Result<Arc<std::collections::HashMap<u32, Arc<rustls::ServerConfig>>>, Error> {
    let mut configs = std::collections::HashMap::new();
    for (index, version) in versions.iter().enumerate() {
        if index == 0 {
            // 先頭バージョンは元の設定 (fallback) をそのまま使う。
            // map に含めないことで router は `tls_config` を使う。
            continue;
        }
        let mut config = (**inner).clone();
        // チケット鍵とセッション保存領域の両方を分離する。rustls の既定値では
        // セッション再開は `session_storage` (ステートフル) で行われるため、
        // チケット鍵だけを変えても別バージョンのセッションを再開できてしまう。
        config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new()
            .map_err(|e| Error::Internal(format!("failed to create TLS ticket key: {e}")))?;
        config.session_storage = rustls::server::ServerSessionMemoryCache::new(256);
        configs.insert(*version, Arc::new(config));
    }
    Ok(Arc::new(configs))
}

#[cfg(test)]
mod tests;
