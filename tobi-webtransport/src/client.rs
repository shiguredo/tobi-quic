// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! WebTransport クライアントの接続とセッション開設
//!
//! tobi-quic の QUIC 接続に tobi-http3 の共通 I/O を接続し、WebTransport over
//! HTTP/3 のセッションを開設する。
//! (draft-ietf-webtrans-http3-02 / -07 / -14 / -15)

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use shiguredo_http3::webtransport::connect::DraftVersion;
use shiguredo_http3::{Settings, VarInt};
use tobi_quic::core::connection::ConnectionConfig;
use tobi_quic::{Client as QuicClient, ClientTlsConfig, Connect, DatagramConfig, IoConfig};

use crate::driver;
use crate::error::Error;
use crate::session::Session;

/// WebTransport over HTTP/3 で使う ALPN
pub const ALPN_H3: &[u8] = b"h3";

/// セッション確立までの既定タイムアウト
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// WebTransport セッションで使うフロー制御の初期値
///
/// サーバーとクライアントの両方が 0 でない値を宣言した場合だけ
/// WebTransport のフロー制御が有効になる。
/// (draft-ietf-webtrans-http3-15 Section 5.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// WebTransport 対応を表明する最大セッション数 (draft-07 / 14 で使用)
    ///
    /// draft-07 と draft-14 では SETTINGS で 0 より大きい値を送る必要がある
    /// ため、0 は指定できない。draft-02 と draft-15 では使われない。
    pub max_sessions: u64,
    /// 初期の単方向ストリーム数上限 (draft-14 / 15 で使用)
    pub initial_max_streams_uni: u64,
    /// 初期の双方向ストリーム数上限 (draft-14 / 15 で使用)
    pub initial_max_streams_bidi: u64,
    /// 初期のセッション全体のデータ量上限 (draft-14 / 15 で使用)
    pub initial_max_data: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sessions: 1,
            initial_max_streams_uni: 100,
            initial_max_streams_bidi: 100,
            initial_max_data: 8 * 1024 * 1024,
        }
    }
}

/// WebTransport セッションの設定
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// クライアントが送信する SETTINGS の draft
    pub(crate) draft: DraftVersion,
    /// 拡張 CONNECT の `:authority`
    pub(crate) authority: String,
    /// 拡張 CONNECT の `:path`
    pub(crate) path: String,
    /// 拡張 CONNECT の `origin` ヘッダー
    pub(crate) origin: Option<String>,
    /// 拡張 CONNECT の `wt-available-protocols` ヘッダー
    pub(crate) available_protocols: Vec<String>,
    /// WebTransport のフロー制御の初期値
    pub(crate) limits: Limits,
    /// セッション確立までのタイムアウト
    ///
    /// `None` の場合は [`ClientBuilder`] で指定した値を使う。
    pub(crate) handshake_timeout: Option<Duration>,
    /// アプリケーションが読み出すまで保持する DATAGRAM の件数
    pub(crate) datagram_receive_capacity: NonZeroUsize,
}

impl ClientConfig {
    /// 必須の authority と path から設定を作る
    ///
    /// draft は draft-15、フロー制御の初期値は [`Limits::default`] になる。
    pub fn new(authority: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            draft: DraftVersion::Draft15,
            authority: authority.into(),
            path: path.into(),
            origin: None,
            available_protocols: Vec::new(),
            limits: Limits::default(),
            handshake_timeout: None,
            datagram_receive_capacity: NonZeroUsize::new(32).expect("capacity is nonzero"),
        }
    }

    /// クライアントが送信する SETTINGS の draft を設定する
    ///
    /// draft-07 を指定した場合も、Safari 26.4 (Network.framework) と同じく
    /// draft-14 の初期フロー制御の SETTINGS を併せて送る。draft-07 のサーバーは
    /// 未知の SETTINGS を無視するため (RFC 9114 Section 7.2.4)、フロー制御を
    /// 実装しないサーバーとの接続には影響しない。
    /// (draft-ietf-webtrans-http3-14 Section 5.1)
    pub fn with_draft(mut self, draft: DraftVersion) -> Self {
        self.draft = draft;
        self
    }

    /// `origin` ヘッダーを設定する
    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = Some(origin.into());
        self
    }

    /// `wt-available-protocols` ヘッダーを設定する
    ///
    /// サーバーが選択したプロトコルは [`Session::protocol`] で取得する。
    /// (draft-ietf-webtrans-http3-15 Section 3.3)
    pub fn with_available_protocols(mut self, protocols: Vec<String>) -> Self {
        self.available_protocols = protocols;
        self
    }

    /// フロー制御の初期値を設定する
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// セッション確立までのタイムアウトを設定する
    ///
    /// ピアのストリーム上限の引き上げ待ちを含む、セッション確立の全体に適用する。
    /// `None` の場合はビルダー側の設定を使い、それも未設定なら無期限に待つ。
    pub fn with_handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// アプリケーションが読み出すまで保持する DATAGRAM の件数を設定する
    ///
    /// 既定は 32 件。上限を超えた DATAGRAM は破棄する。DATAGRAM にフロー制御や
    /// 再送はなく、容量を増やしても配送は保証されない (RFC 9221 Section 5.3)。
    pub fn with_datagram_receive_capacity(mut self, capacity: NonZeroUsize) -> Self {
        self.datagram_receive_capacity = capacity;
        self
    }

    /// クライアントが送信する SETTINGS の draft を返す
    pub fn draft(&self) -> DraftVersion {
        self.draft
    }

    /// 拡張 CONNECT の `:authority` を返す
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// 拡張 CONNECT の `:path` を返す
    pub fn path(&self) -> &str {
        &self.path
    }

    /// 拡張 CONNECT の `origin` ヘッダーを返す
    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }

    /// 拡張 CONNECT の `wt-available-protocols` ヘッダーを返す
    pub fn available_protocols(&self) -> &[String] {
        &self.available_protocols
    }

    /// フロー制御の初期値を返す
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// セッション確立までのタイムアウトを返す
    pub fn handshake_timeout(&self) -> Option<Duration> {
        self.handshake_timeout
    }

    /// DATAGRAM の受信キューの容量を返す
    pub fn datagram_receive_capacity(&self) -> NonZeroUsize {
        self.datagram_receive_capacity
    }
}

/// WebTransport クライアントのビルダー
///
/// QUIC 層に必要な設定をまとめて適用する。
/// - `max_datagram_frame_size` を広告する
/// - `reset_stream_at` transport parameter を広告する
pub struct ClientBuilder {
    tls: Option<ClientTlsConfig>,
    io: Option<IoConfig>,
    pub(crate) handshake_timeout: Option<Duration>,
}

impl ClientBuilder {
    /// TLS 設定を設定する
    ///
    /// ALPN の設定は呼び出し側の責任である。[`ClientTlsConfig`] の ALPN に
    /// [`ALPN_H3`] を設定すること。ALPN の設定をこのクレートに任せる場合は
    /// [`ClientBuilder::with_tls_config`] を使う。
    pub fn with_tls(mut self, tls: ClientTlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    /// rustls のクライアント TLS 設定から TLS 設定を作る
    ///
    /// ALPN を [`ALPN_H3`] に設定した複製を作って使う。証明書の検証方法などは
    /// 渡した設定のまま使われる。
    pub fn with_tls_config(mut self, config: Arc<rustls::ClientConfig>) -> Self {
        let mut config = (*config).clone();
        config.alpn_protocols = vec![ALPN_H3.to_vec()];
        self.tls = Some(ClientTlsConfig::new(Arc::new(config)));
        self
    }

    /// ソケットの I/O 設定を設定する
    pub fn with_io(mut self, io: IoConfig) -> Self {
        self.io = Some(io);
        self
    }

    /// QUIC と WebTransport のハンドシェイクに共通のタイムアウトを設定する
    ///
    /// `None` を指定するとタイムアウトしない。
    pub fn with_handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// QUIC クライアントを起動する
    ///
    /// # エラー
    ///
    /// TLS 設定または I/O 設定が未指定の場合はエラーを返す。
    /// QUIC クライアントの起動に失敗した場合は QUIC 層のエラーを返す。
    pub fn start(self) -> Result<Client, Error> {
        let tls = self.tls.ok_or(Error::MissingTlsConfig)?;
        let io = self.io.ok_or(Error::MissingIoConfig)?;

        // WebTransport over HTTP/3 の前提となる QUIC transport parameter を設定する。
        // draft-14 / 15 では reset_stream_at の広告が必須であり、draft-02 / 07 でも
        // 広告自体は問題にならない。(draft-ietf-webtrans-http3-14 Section 3.1)
        let mut transport = ConnectionConfig::default();
        transport.transport_params.reset_stream_at = true;

        // with_transport と with_datagram の設定は start() で統合される。
        let quic = QuicClient::builder()
            .with_tls(tls)
            .with_io(io)
            .with_handshake_timeout(self.handshake_timeout)
            .with_transport(transport)
            .with_datagram(DatagramConfig::default())
            .start()?;

        Ok(Client {
            quic,
            handshake_timeout: self.handshake_timeout,
        })
    }
}

/// WebTransport クライアント
///
/// 1 つの QUIC 接続に対して 1 つの WebTransport セッションを開設する。
/// 接続を別の目的で再利用したり、複数のセッションを開いたりすることはできない。
pub struct Client {
    quic: QuicClient,
    pub(crate) handshake_timeout: Option<Duration>,
}

impl Client {
    /// ビルダーを作る
    pub fn builder() -> ClientBuilder {
        ClientBuilder {
            tls: None,
            io: None,
            handshake_timeout: Some(DEFAULT_HANDSHAKE_TIMEOUT),
        }
    }

    /// サーバーへ接続し、WebTransport セッションを開設する
    ///
    /// 接続後、HTTP/3 の制御ストリームと QPACK ストリーム、拡張 CONNECT を
    /// 結線し、サーバーの SETTINGS と CONNECT の応答を検証してから
    /// [`Session`] を返す。
    ///
    /// 設定の検証は QUIC 接続を開始する前に行う。
    ///
    /// # 前提
    ///
    /// - ALPN が h3 であること
    /// - ピアが `max_datagram_frame_size > 0` を広告していること
    /// - クライアントが指定した draft が draft-14 / 15 の場合は、
    ///   ピアが `reset_stream_at` を広告していること
    ///
    /// # エラー
    ///
    /// 設定が不正な場合は [`Error::InvalidConfig`] または [`Error::InvalidLimit`]
    /// を返す。上記の前提を満たさない場合、CONNECT が最終レスポンスで 2xx 以外の
    /// `:status` で応答された場合、セッション確立がタイムアウトした場合は
    /// エラーを返す。
    pub async fn connect(&self, connect: Connect, config: ClientConfig) -> Result<Session, Error> {
        validate_config(&config)?;
        let connection = self.quic.connect(connect).await?;
        // タイムアウトは establish の内側で扱う。外側で timeout を使うと
        // タイムアウト時に establish の後始末が中断され、QUIC 接続が
        // 残留するためである
        let mut config = config;
        if config.handshake_timeout.is_none() {
            config.handshake_timeout = self.handshake_timeout;
        }
        driver::establish(connection, config).await
    }
}

/// セッションを開設する前に設定を検証する
///
/// QUIC 接続を開始してから設定の不正に気づくと、不要な接続とハンドシェイクを
/// 行うことになるため、接続前に検証する。
fn validate_config(config: &ClientConfig) -> Result<(), Error> {
    if config.authority.is_empty() {
        return Err(Error::InvalidConfig { name: "authority" });
    }
    if !config.path.starts_with('/') {
        return Err(Error::InvalidConfig { name: "path" });
    }
    // SETTINGS に載せる値は VarInt の範囲に収まる必要がある
    varint("max_sessions", config.limits.max_sessions)?;
    varint(
        "initial_max_streams_uni",
        config.limits.initial_max_streams_uni,
    )?;
    varint(
        "initial_max_streams_bidi",
        config.limits.initial_max_streams_bidi,
    )?;
    varint("initial_max_data", config.limits.initial_max_data)?;
    // draft-07 / 14 では SETTINGS_WEBTRANSPORT_MAX_SESSIONS が WebTransport
    // 対応の表明を兼ねるため、0 は指定できない。draft-02 / 15 では使われない。
    // (draft-ietf-webtrans-http3-14 Section 9.2)
    if matches!(config.draft, DraftVersion::Draft07 | DraftVersion::Draft14)
        && config.limits.max_sessions == 0
    {
        return Err(Error::InvalidLimit {
            name: "max_sessions",
        });
    }
    Ok(())
}

/// draft に対応するクライアント SETTINGS を構築する
pub(crate) fn build_client_settings(config: &ClientConfig) -> Result<Settings, Error> {
    let params = shiguredo_http3::webtransport::ServerSettingsParams {
        max_sessions: varint("max_sessions", config.limits.max_sessions)?,
        initial_max_streams_uni: varint(
            "initial_max_streams_uni",
            config.limits.initial_max_streams_uni,
        )?,
        initial_max_streams_bidi: varint(
            "initial_max_streams_bidi",
            config.limits.initial_max_streams_bidi,
        )?,
        initial_max_data: varint("initial_max_data", config.limits.initial_max_data)?,
    };

    let wt = config.draft.build_client_settings(&params);
    // Safari 26.4 (Network.framework) は draft-07 の SETTINGS ID で
    // WebTransport をネゴシエートしつつ、draft-14 用の初期フロー制御の
    // SETTINGS も併せて送る。draft-07 のサーバーは未知の SETTINGS を無視する
    // ため (RFC 9114 Section 7.2.4)、この併送は仕様違反にならない。
    // これにより draft-07 のままフロー制御を有効にするサーバー
    // (Safari 互換パターン) と相互運用できる
    // (draft-ietf-webtrans-http3-14 Section 5.1)。
    let wt = match config.draft {
        DraftVersion::Draft07 => wt
            .wt_initial_max_streams_uni(params.initial_max_streams_uni)
            .wt_initial_max_streams_bidi(params.initial_max_streams_bidi)
            .wt_initial_max_data(params.initial_max_data),
        _ => wt,
    };
    Ok(Settings::default().enable_webtransport_client(wt))
}

/// u64 を VarInt に変換する
fn varint(name: &'static str, value: u64) -> Result<VarInt, Error> {
    VarInt::new(value).map_err(|_| Error::InvalidLimit { name })
}
