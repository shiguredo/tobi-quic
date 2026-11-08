// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! WebTransport セッションの結線
//!
//! QUIC の接続・ストリーム・DATAGRAM と `shiguredo_http3` の Sans I/O
//! HTTP/3 実装を結線する。公開 API は [`crate::client`] と [`crate::session`]
//! にあり、このモジュールはその内部実装である。
//!
//! # タスク構成
//!
//! セッションごとに 1 つのドライバータスクが結線状態を所有し、アプリケーションは
//! チャネル経由で操作を依頼する。ストリームの読み取りはストリームごとのタスクが
//! 行い、受信データをドライバータスクへ渡す。状態を 1 つのタスクに閉じ込める
//! ことで、ロックを使わずに整合性を保つ。
//!
//! # フロー制御の分担
//!
//! `shiguredo_http3::ClientConnection` は受信側のセッション内フロー制御
//! (WT_MAX_STREAMS / WT_MAX_DATA の生成と違反検出) を担う。一方、ピアが通知した
//! 上限の反映と、それを超えないような送信側の制御は上位層の責務である
//! (draft-ietf-webtrans-http3-15 Section 5)。このため結線側でも
//! `shiguredo_http3::webtransport::Session` を保持し、受信したフロー制御カプセルを
//! `Session::process_capsule` へ渡して送信側の上限を管理する。
//!
//! # ブロッキングの可能性
//!
//! ドライバーはコマンド処理の一部で QUIC のフロー制御待ちになることがある。
//! 具体的には、WT ヘッダーと HTTP/3 の制御ストリーム・CONNECT ストリームの送信
//! データを QUIC ストリームへ書き込む処理で、接続のフロー制御が回復するまで
//! 待機する。この間は他のコマンドも処理されない。[`crate::session::Session`]
//! の [`Session::close`](crate::session::Session::close) や
//! [`Session::send_datagram`](crate::session::Session::send_datagram) も
//! ドライバー経由で実行されるため、ドライバーが滞留している間は完了しない。
//! アプリケーションのペイロード送信はドライバーを経由しないため、この待機の
//! 影響を受けない。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use shiguredo_http3::webtransport::MAX_STREAMS_LIMIT;
use shiguredo_http3::webtransport::capsule::Capsule;
use shiguredo_http3::webtransport::connect::{ConnectRequest, ConnectResponse, DraftVersion};
use shiguredo_http3::webtransport::error::ErrorCode as WtErrorCode;
use shiguredo_http3::webtransport::session::{CapsuleProcessError, Session as WtSession};
use shiguredo_http3::webtransport::stream::StreamHeader;
use shiguredo_http3::{
    ClientConnection, ErrorCode as H3ErrorCode, Event, Settings, WebTransportEvent,
};
use tobi_http3::io::{ControlStreams, ReadEvent as ReaderMessage, spawn_reader};
use tobi_quic::{Connection, PeerStream, SendStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::client::{ALPN_H3, ClientConfig, build_client_settings};
use crate::error::Error;
use crate::session::{CloseInfo, Command, Session, SessionEnd, SessionParts};
use crate::stream::{
    Consumed, SendCredit, StreamControl, StreamEvent, WtBidirectionalStream, WtReceiveStream,
    WtSendStream, app_error_from_http3, app_error_to_http3, write_all,
};

/// 受信メッセージのチャネル容量
const READER_CHANNEL_CAPACITY: usize = 64;
/// アプリケーションへ渡す受信ストリームのチャネル容量
const INCOMING_STREAM_CHANNEL_CAPACITY: usize = 32;
/// コマンドのチャネル容量
const COMMAND_CHANNEL_CAPACITY: usize = 16;
/// 1 ストリームでアプリケーションへ配送する未消費データの上限
///
/// アプリケーションが受信を読まないままストリームを保持し続けても
/// メモリ使用量が増え続けないようにするための上限である。上限を超えた
/// ストリームは読み取りを停止し、アプリケーションへ失敗を通知する。
const MAX_STREAM_BUFFER_BYTES: u64 = 8 * 1024 * 1024;
/// ローカルからクローズした後にピアの CONNECT ストリーム終了を待つ上限
const CONNECT_CLOSE_TIMEOUT: Duration = Duration::from_millis(500);

/// 結線が管理する HTTP/3 ストリーム
struct H3Streams {
    /// CONNECT ストリーム ID
    connect_id: u64,
    /// HTTP/3 が管理する制御ストリームと QPACK ストリーム
    control: ControlStreams,
    /// CONNECT ストリームの送信側
    connect_send: SendStream,
}

/// アプリケーションへ渡す受信ストリームの状態
struct StreamState {
    /// アプリケーションへのイベント送信側
    tx: mpsc::UnboundedSender<StreamEvent>,
    /// アプリケーションへ配送済みで未消費のバイト数
    pending_bytes: u64,
    /// 受信バッファ上限を超えてデータ配送を停止したか
    ///
    /// true の間は Data と追加の Failed を配送しない。QUIC / H3 の受信は
    /// 継続し、配送しなかったデータはフロー制御へ返す。
    delivery_stopped: bool,
}

/// セッションで共有するチャネル
struct ProcessorChannels {
    reader_tx: mpsc::Sender<ReaderMessage>,
    consumed_tx: mpsc::UnboundedSender<Consumed>,
    control_tx: mpsc::UnboundedSender<StreamControl>,
    incoming_bidi_tx: mpsc::Sender<WtBidirectionalStream>,
    incoming_uni_tx: mpsc::Sender<WtReceiveStream>,
    datagram_tx: mpsc::Sender<Vec<u8>>,
    close_tx: watch::Sender<Option<SessionEnd>>,
    draining: Arc<AtomicBool>,
}

/// ドライバーが受け取る非同期入力
pub(crate) struct DriverContext {
    commands: mpsc::Receiver<Command>,
    reader: mpsc::Receiver<ReaderMessage>,
    consumed: mpsc::UnboundedReceiver<Consumed>,
    control: mpsc::UnboundedReceiver<StreamControl>,
}

/// ピアの SETTINGS が通知した初期フロー制御値
#[derive(Debug, Clone, Copy, Default)]
struct PeerLimits {
    streams_uni: u64,
    streams_bidi: u64,
    max_data: u64,
}

/// セッション開設の失敗要因
///
/// 接続を閉じる際のアプリケーションエラーコードの選択に使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetupFailureKind {
    /// WebTransport の前提 (SETTINGS / transport parameter) が満たされていない
    RequirementsNotMet,
    /// クリティカルストリームが閉じられた
    ClosedCriticalStream,
    /// その他の失敗
    Other,
}

/// WebTransport の結線状態
///
/// HTTP/3 の Sans I/O 状態機械と QUIC のハンドルを所有し、ストリームの
/// 読み書きとイベントの配送を一手に行う。
pub(crate) struct Processor {
    h3: ClientConnection,
    /// 送信側のフロー制御とカプセル処理を担うセッション
    wt: WtSession,
    connection: Connection,
    session_id: u64,
    peer_reset_stream_at: bool,
    /// WT ヘッダーのエンコード長
    header_len: u64,
    h3_streams: H3Streams,
    /// ピア開始双方向ストリームの送信側 (BidiStreamOpen まで保持する)
    peer_bidi: HashMap<u64, SendStream>,
    /// アプリケーション向け受信ストリーム
    streams_rx: HashMap<u64, StreamState>,
    /// ストリームごとの読み取りタスク
    reader_tasks: HashMap<u64, JoinHandle<()>>,
    /// ローカルが開始した WebTransport データストリームの ID
    local_streams: HashSet<u64>,
    /// STOP_SENDING の通知先 (ストリームごと)
    stop_txs: HashMap<u64, watch::Sender<Option<u64>>>,
    /// セッションの送信データクレジット
    credit: Arc<SendCredit>,
    channels: ProcessorChannels,
    peer_limits: PeerLimits,
    /// SETTINGS から判定したサーバーの draft
    settings_draft: Option<DraftVersion>,
    established: bool,
    closed: bool,
    /// CONNECT ストリームを FIN 済みか (FIN 後のカプセル送信を止める)
    closing: bool,
    /// CONNECT ストリームの終了を観測済みか
    connect_stream_ended: bool,
    /// ピアが CONNECT ストリームの送信側に STOP_SENDING を送った
    connect_send_stopped: bool,
    /// CONNECT ストリームが RESET_STREAM で終了した場合のエラーコード
    connect_stream_error_code: Option<u64>,
    flow_control_enabled: bool,
    /// 最終レスポンスの `:status`
    final_status: Option<u16>,
    /// 最終レスポンスの `:protocol`
    final_protocol: Option<String>,
    /// 処理中のレスポンスの `:status`
    pending_status: Option<u16>,
    /// 処理中のレスポンスの `:protocol`
    pending_protocol: Option<String>,
    /// 送信済みの WT_DATA_BLOCKED の上限値
    last_data_blocked: Option<u64>,
    /// クライアントが提示したアプリケーションプロトコル
    requested_protocols: Vec<String>,
    /// サーバーが選択したプロトコルが提示した一覧にない
    protocol_mismatch: bool,
    /// QUIC 接続を閉じる際のアプリケーションエラーコード
    shutdown_code: u64,
    /// セッション開設の失敗要因 (後始末でのエラーコード選択に使う)
    setup_failure_kind: SetupFailureKind,
    /// CONNECT ストリームの読み取りタスク
    _connect_reader: JoinHandle<()>,
}

/// 結線を構築するための構成要素
struct ProcessorParts {
    h3: ClientConnection,
    connection: Connection,
    session_id: u64,
    peer_reset_stream_at: bool,
    header_len: u64,
    h3_streams: H3Streams,
    channels: ProcessorChannels,
    credit: Arc<SendCredit>,
    connect_reader: JoinHandle<()>,
    requested_protocols: Vec<String>,
}

/// driver の失敗時に QUIC 接続を閉じるエラーコードを選ぶ
///
/// HTTP/3 のクリティカルストリームが閉じられた場合は
/// H3_CLOSED_CRITICAL_STREAM を使う (control stream は RFC 9114 Section 6.2.1、
/// QPACK encoder / decoder stream は RFC 9204 Section 4.2)。それ以外の失敗は
/// H3_INTERNAL_ERROR とする。
fn shutdown_code_for_error(error: &Error) -> u64 {
    match error {
        Error::Http3(shiguredo_http3::Error::ConnectionError(
            H3ErrorCode::ClosedCriticalStream,
        )) => H3ErrorCode::ClosedCriticalStream as u64,
        _ => H3ErrorCode::InternalError as u64,
    }
}

/// セッション開設の失敗を接続終了コードの選択に使う分類へ変換する
fn setup_failure_kind(error: &Error) -> SetupFailureKind {
    match error {
        Error::AlpnMismatch { .. }
        | Error::DatagramNotSupported
        | Error::TransportParametersUnavailable
        | Error::ResetStreamAtNotSupported
        | Error::WebTransportNotEnabled
        | Error::MissingSetting { .. } => SetupFailureKind::RequirementsNotMet,
        Error::Http3(shiguredo_http3::Error::ConnectionError(
            H3ErrorCode::ClosedCriticalStream,
        )) => SetupFailureKind::ClosedCriticalStream,
        _ => SetupFailureKind::Other,
    }
}

/// セッション開設の失敗時に QUIC 接続を閉じるエラーコードを選ぶ
fn setup_shutdown_code(kind: SetupFailureKind) -> u64 {
    match kind {
        SetupFailureKind::RequirementsNotMet => WtErrorCode::RequirementsNotMet as u64,
        SetupFailureKind::ClosedCriticalStream => H3ErrorCode::ClosedCriticalStream as u64,
        SetupFailureKind::Other => H3ErrorCode::NoError as u64,
    }
}

impl Processor {
    fn new(parts: ProcessorParts) -> Self {
        Self {
            wt: WtSession::new(parts.session_id),
            h3: parts.h3,
            connection: parts.connection,
            session_id: parts.session_id,
            peer_reset_stream_at: parts.peer_reset_stream_at,
            header_len: parts.header_len,
            h3_streams: parts.h3_streams,
            peer_bidi: HashMap::new(),
            streams_rx: HashMap::new(),
            reader_tasks: HashMap::new(),
            local_streams: HashSet::new(),
            stop_txs: HashMap::new(),
            credit: parts.credit,
            channels: parts.channels,
            peer_limits: PeerLimits::default(),
            settings_draft: None,
            established: false,
            closed: false,
            closing: false,
            connect_stream_ended: false,
            connect_send_stopped: false,
            connect_stream_error_code: None,
            flow_control_enabled: false,
            final_status: None,
            final_protocol: None,
            pending_status: None,
            pending_protocol: None,
            last_data_blocked: None,
            requested_protocols: parts.requested_protocols,
            protocol_mismatch: false,
            shutdown_code: H3ErrorCode::NoError as u64,
            setup_failure_kind: SetupFailureKind::Other,
            _connect_reader: parts.connect_reader,
        }
    }

    /// SETTINGS から判定したサーバーの draft を返す
    fn settings_draft(&self) -> Option<DraftVersion> {
        self.settings_draft
    }

    /// 確立したセッションで確定した `:protocol` を返す
    fn protocol(&self) -> Option<String> {
        self.final_protocol.clone()
    }

    /// 入力チャネルを 1 件処理する
    ///
    /// セッション確立前の待機ループと、確立後のドライバーループで共用する。
    async fn step(&mut self, ctx: &mut DriverContext) -> Result<(), Error> {
        tokio::select! {
            command = ctx.commands.recv() => {
                match command {
                    Some(command) => self.handle_command(command).await,
                    // セッションのハンドルが破棄された: 明示的なクローズとして扱う
                    None => self.close_local(0, String::new()).await,
                }
            }
            message = ctx.reader.recv() => {
                if let Some(message) = message {
                    self.handle_reader(message)?;
                }
                Ok(())
            }
            accepted = self.connection.accept_stream() => {
                self.handle_accept(accepted?);
                Ok(())
            }
            stop_sending = self.connection.accept_stop_sending() => {
                let (stream_id, error_code) = stop_sending?;
                // QUIC の STOP_SENDING を HTTP/3 に供給する。WebTransport の
                // データストリームでは WebTransportEvent::StreamStopSending が
                // 生成され、handle_stop_sending が watch に通知する。クリティカル
                // ストリームでは接続エラーになり、未知のストリームは汎用
                // イベントとして無視される。
                //
                // CONNECT ストリームは HTTP/3 がセッション終了として扱うため、
                // WT_CLOSE_SESSION と STOP_SENDING の到着順が入れ替わると
                // クローズ情報を失う。ここでは渡さず、終了は FIN / RESET_STREAM
                // で判定する。送信側の RESET_STREAM は transport が STOP_SENDING
                // の受信時に送る (RFC 9000 Section 3.5)。
                if stream_id == self.h3_streams.connect_id {
                    // CONNECT 送信側は transport が RESET_STREAM で終端する。
                    // 以降のカプセルと FIN は送れないため、pump と close で
                    // 送信をスキップする。
                    self.connect_send_stopped = true;
                } else {
                    self.h3.stop_sending(stream_id, error_code)?;
                }
                Ok(())
            }
            datagram = self.connection.receive_datagram() => {
                let datagram = datagram?;
                self.handle_datagram(&datagram);
                Ok(())
            }
            consumed = ctx.consumed.recv() => {
                if let Some(consumed) = consumed {
                    self.handle_consumed(consumed);
                }
                Ok(())
            }
            control = ctx.control.recv() => {
                if let Some(control) = control {
                    self.handle_control(control).await?;
                }
                Ok(())
            }
        }
    }

    /// サーバーの制御ストリームから SETTINGS を受信するまで待つ
    async fn wait_for_peer_settings(&mut self, ctx: &mut DriverContext) -> Result<(), Error> {
        loop {
            if self.h3.peer_settings().is_some() {
                return Ok(());
            }
            if self.closed {
                return Err(Error::SessionClosed);
            }
            self.step(ctx).await?;
            self.drain_events().await?;
            self.pump().await?;
        }
    }

    /// サーバーの SETTINGS を検証し、拡張 CONNECT を送信する
    async fn prepare_connect(&mut self, config: &ClientConfig) -> Result<(), Error> {
        // SETTINGS の受信は wait_for_peer_settings が確認している
        let peer = self
            .h3
            .peer_settings()
            .cloned()
            .expect("peer SETTINGS are received before the CONNECT request");
        let server = self.negotiate_draft(&peer, config)?;
        self.validate_peer_settings(&peer, config)?;
        let peer_wt = peer.wt_settings.as_ref();
        self.peer_limits = PeerLimits {
            streams_uni: peer_wt.map_or(0, |wt| wt.wt_initial_max_streams_uni.get()),
            streams_bidi: peer_wt.map_or(0, |wt| wt.wt_initial_max_streams_bidi.get()),
            max_data: peer_wt.map_or(0, |wt| wt.wt_initial_max_data.get()),
        };
        self.settings_draft = Some(server);

        let mut request =
            ConnectRequest::new("https", config.authority.clone(), config.path.clone())
                .draft_version(server);
        if let Some(origin) = &config.origin {
            request = request.origin(origin.clone());
        }
        if !config.available_protocols.is_empty() {
            request = request.available_protocols(config.available_protocols.clone());
        }
        let headers = request.to_headers()?;
        let stream_id = self.h3.send_request(&headers, false)?;
        if stream_id != self.h3_streams.connect_id {
            return Err(Error::StreamIdMismatch {
                expected: self.h3_streams.connect_id,
                actual: stream_id,
            });
        }
        self.wt.set_connecting();
        // CONNECT のヘッダーをすぐに QUIC へ流さないと、サーバーの応答を待つ
        // ループが送信待ちのまま停止する。
        self.pump().await
    }

    /// サーバーの SETTINGS から draft を判定し、指定した draft と両立するか確認する
    fn negotiate_draft(
        &self,
        peer: &Settings,
        config: &ClientConfig,
    ) -> Result<DraftVersion, Error> {
        if !peer.is_webtransport_enabled() {
            return Err(Error::WebTransportNotEnabled);
        }
        let server = peer
            .webtransport_draft_pattern()
            .ok_or(Error::MissingSetting {
                name: "WebTransport SETTINGS",
            })?;
        // draft-14 のサーバーは draft-07 の SETTINGS ID も返すため、
        // draft-07 として判定されることがある。両方を受理する。
        let compatible = match config.draft {
            DraftVersion::Draft14 => {
                matches!(server, DraftVersion::Draft07 | DraftVersion::Draft14)
            }
            draft => server == draft,
        };
        if !compatible {
            return Err(Error::DraftMismatch {
                requested: config.draft,
                server,
            });
        }
        Ok(server)
    }

    /// サーバーの SETTINGS が WebTransport の前提を満たすか確認する
    fn validate_peer_settings(&self, peer: &Settings, config: &ClientConfig) -> Result<(), Error> {
        let server = peer
            .webtransport_draft_pattern()
            .ok_or(Error::MissingSetting {
                name: "WebTransport SETTINGS",
            })?;
        if server.requires_enable_connect_protocol() && peer.enable_connect_protocol != Some(true) {
            return Err(Error::MissingSetting {
                name: "SETTINGS_ENABLE_CONNECT_PROTOCOL",
            });
        }
        if peer.h3_datagram != Some(true) {
            return Err(Error::MissingSetting {
                name: "SETTINGS_H3_DATAGRAM",
            });
        }
        if config.draft.requires_reset_stream_at() && !self.peer_reset_stream_at {
            return Err(Error::ResetStreamAtNotSupported);
        }
        Ok(())
    }

    /// CONNECT の応答を受信してセッションが確立するまで待つ
    async fn wait_for_session(&mut self, ctx: &mut DriverContext) -> Result<(), Error> {
        loop {
            // 最終レスポンスの判定をセッション終了より先に行う。CONNECT の拒否は
            // 応答の FIN でセッションが終了するため、到着順に依存させない。
            // 1xx の中間レスポンスは最終レスポンスではない (RFC 9114 Section 4.1)。
            if let Some(status) = self.final_status
                && !(200..=299).contains(&status)
            {
                return Err(Error::ConnectRejected { status });
            }
            // プロトコルネゴシエーションの不一致はセッション確立イベントより
            // 後に判定されることがある。確立済みでも先に不一致を返す
            // (draft-ietf-webtrans-http3-15 Section 3.3)。
            if self.protocol_mismatch {
                // プロトコルネゴシエーションの失敗はセッションエラーである。
                // WT_CLOSE_SESSION のアプリケーションエラーコード空間には
                // WT プロトコルエラーコードを入れられないため、CONNECT
                // ストリームを WT_ALPN_ERROR でリセットする
                // (draft-ietf-webtrans-http3-15 Section 3.3 / Section 6)。
                self.reset_connect_stream(WtErrorCode::AlpnError as u64)
                    .await;
                return Err(Error::ProtocolMismatch {
                    requested: self.requested_protocols.clone(),
                    selected: self.final_protocol.clone(),
                });
            }
            if self.established {
                return Ok(());
            }
            if self.closed {
                return Err(Error::SessionClosed);
            }
            self.step(ctx).await?;
            self.drain_events().await?;
            self.pump().await?;
        }
    }

    /// セッションのドライバータスクを実行する
    pub(crate) async fn run(mut self, mut ctx: DriverContext) {
        loop {
            if self.closed {
                break;
            }
            if let Err(error) = self.step(&mut ctx).await {
                self.fail(error);
                break;
            }
            if self.closed {
                break;
            }
            if let Err(error) = self.drain_events().await {
                self.fail(error);
                break;
            }
            if self.closed {
                break;
            }
            if let Err(error) = self.pump().await {
                self.fail(error);
                break;
            }
        }
        self.shutdown(&mut ctx).await;
        // 残っている読み取りタスクを停止する
        for (_, task) in self.reader_tasks.drain() {
            task.abort();
        }
        debug!(session_id = self.session_id, "WebTransport driver stopped");
    }

    /// セッションを開設できなかった場合の後始末
    async fn cleanup_failed_setup(&mut self) {
        for (_, task) in self.reader_tasks.drain() {
            task.abort();
        }
        self._connect_reader.abort();
        // WebTransport の前提が満たされずに接続を閉じる場合は
        // WT_REQUIREMENTS_NOT_MET を使う (draft-ietf-webtrans-http3-15
        // Section 3.1)。障害の原因が前提未達ではない場合は H3_NO_ERROR のままにする
        let code = setup_shutdown_code(self.setup_failure_kind);
        let _ = self.connection.close_application(code, b"").await;
    }

    /// セッション終了後に QUIC 接続を閉じる
    ///
    /// ローカルから CONNECT ストリームを FIN している場合は、ピアが CONNECT
    /// ストリームを閉じるまで待ってから接続を閉じる。WT_CLOSE_SESSION と FIN の
    /// 配送が CONNECTION_CLOSE に追い越されないようにするためである。
    /// (draft-ietf-webtrans-http3-15 Section 6)
    async fn shutdown(&mut self, ctx: &mut DriverContext) {
        if self.closing {
            self.wait_for_connect_stream_end(ctx).await;
        }
        let _ = self
            .connection
            .close_application(self.shutdown_code, b"")
            .await;
    }

    /// ピアが CONNECT ストリームを終了するまで待つ
    ///
    /// CONNECT ストリームを RESET_STREAM や FIN で閉じた直後に接続を閉じると、
    /// ピアがストリームの終了を観測する前に CONNECTION_CLOSE が届き、
    /// 終了理由が失われることがある。上限時間までピアの終了を待ってから
    /// 接続を閉じる (draft-ietf-webtrans-http3-15 Section 6)。
    async fn wait_for_connect_stream_end(&mut self, ctx: &mut DriverContext) {
        if self.connect_stream_ended {
            return;
        }
        let deadline = tokio::time::sleep(CONNECT_CLOSE_TIMEOUT);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                message = ctx.reader.recv() => {
                    match message {
                        Some(message) => {
                            let ended = matches!(
                                &message,
                                ReaderMessage::Fin { stream_id }
                                    | ReaderMessage::Reset { stream_id, .. }
                                    | ReaderMessage::ConnectionClosed { stream_id, .. }
                                    if *stream_id == self.h3_streams.connect_id
                            );
                            if ended {
                                self.connect_stream_ended = true;
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    }

    /// コマンドを処理する
    async fn handle_command(&mut self, command: Command) -> Result<(), Error> {
        match command {
            Command::OpenBidirectional { reply } => {
                let result = self.open_bidirectional().await;
                let _ = reply.send(result);
                Ok(())
            }
            Command::OpenUnidirectional { reply } => {
                let result = self.open_unidirectional().await;
                let _ = reply.send(result);
                Ok(())
            }
            Command::SendDatagram { payload, reply } => {
                let result = self.send_datagram(&payload).await;
                let _ = reply.send(result);
                Ok(())
            }
            Command::Close {
                error_code,
                message,
                reply,
            } => {
                let result = self.close_local(error_code, message).await;
                let _ = reply.send(result);
                Ok(())
            }
        }
    }

    /// 双方向ストリームを開く
    async fn open_bidirectional(&mut self) -> Result<WtBidirectionalStream, Error> {
        if self.closed {
            return Err(Error::SessionClosed);
        }
        if self.channels.draining.load(Ordering::Relaxed) {
            return Err(Error::SessionDraining);
        }
        // ピアが通知した WT_MAX_STREAMS の範囲でのみ開く
        // (draft-ietf-webtrans-http3-15 Section 5.3)
        if !self.wt.try_open_stream(true) {
            // WT_STREAMS_BLOCKED を送ってから上限に達したことを返す
            self.pump().await?;
            return Err(Error::StreamsBlocked {
                bidirectional: true,
            });
        }
        // QUIC 層のストリーム上限は WT 層より小さいことがある。上限到達は
        // ピアの MAX_STREAMS 増加で回復するリトライ可能な状態であり、接続を
        // 閉じるべきではないため、待機版でピアの進捗を待つ
        let stream = self.connection.open_bidirectional_stream_wait().await?;
        let stream_id = stream.id();
        let header = StreamHeader::new(self.session_id)?;
        let mut buffer = Vec::new();
        header.encode_bidirectional(&mut buffer);
        let (mut send, recv) = stream.split();
        write_all(stream_id, &mut send, &buffer).await?;
        if let Err(error) = self.h3.register_local_wt_stream(self.session_id, stream_id) {
            let _ = send.reset_stream(WtErrorCode::SessionGone as u64).await;
            return Err(error.into());
        }
        self.local_streams.insert(stream_id);
        let (tx, rx) = mpsc::unbounded_channel();
        self.streams_rx.insert(
            stream_id,
            StreamState {
                tx,
                pending_bytes: 0,
                delivery_stopped: false,
            },
        );
        let reader = spawn_reader(
            recv,
            self.channels.reader_tx.clone(),
            WtErrorCode::SessionGone as u64,
        );
        self.reader_tasks.insert(stream_id, reader);
        let (stop_tx, stop_rx) = watch::channel(None);
        self.stop_txs.insert(stream_id, stop_tx);
        Ok(WtBidirectionalStream::from_parts(
            WtSendStream::new(
                stream_id,
                send,
                self.credit.clone(),
                stop_rx,
                Some(self.header_len),
                self.channels.control_tx.clone(),
            ),
            WtReceiveStream::new(
                stream_id,
                rx,
                self.channels.consumed_tx.clone(),
                self.channels.control_tx.clone(),
            ),
        ))
    }

    /// 単方向ストリームを開く
    async fn open_unidirectional(&mut self) -> Result<WtSendStream, Error> {
        if self.closed {
            return Err(Error::SessionClosed);
        }
        if self.channels.draining.load(Ordering::Relaxed) {
            return Err(Error::SessionDraining);
        }
        // ピアが通知した WT_MAX_STREAMS の範囲でのみ開く
        // (draft-ietf-webtrans-http3-15 Section 5.3)
        if !self.wt.try_open_stream(false) {
            self.pump().await?;
            return Err(Error::StreamsBlocked {
                bidirectional: false,
            });
        }
        // QUIC 層のストリーム上限は WT 層より小さいことがある。上限到達は
        // ピアの MAX_STREAMS 増加で回復するリトライ可能な状態であり、接続を
        // 閉じるべきではないため、待機版でピアの進捗を待つ
        let mut send = self.connection.open_send_stream_wait().await?;
        let stream_id = send.id();
        let header = StreamHeader::new(self.session_id)?;
        let mut buffer = Vec::new();
        header.encode_unidirectional(&mut buffer);
        write_all(stream_id, &mut send, &buffer).await?;
        if let Err(error) = self.h3.register_local_wt_stream(self.session_id, stream_id) {
            let _ = send.reset_stream(WtErrorCode::SessionGone as u64).await;
            return Err(error.into());
        }
        self.local_streams.insert(stream_id);
        let (stop_tx, stop_rx) = watch::channel(None);
        self.stop_txs.insert(stream_id, stop_tx);
        Ok(WtSendStream::new(
            stream_id,
            send,
            self.credit.clone(),
            stop_rx,
            Some(self.header_len),
            self.channels.control_tx.clone(),
        ))
    }

    /// データグラムを送信する
    async fn send_datagram(&mut self, payload: &[u8]) -> Result<(), Error> {
        if self.closed {
            return Err(Error::SessionClosed);
        }
        if self.channels.draining.load(Ordering::Relaxed) {
            return Err(Error::SessionDraining);
        }
        let encoded = self.h3.send_datagram(self.session_id, payload)?;
        let maximum = self
            .connection
            .max_datagram_size()
            .await
            .ok_or(Error::DatagramNotSupported)?;
        if encoded.len() > maximum {
            return Err(Error::DatagramTooLarge {
                size: encoded.len(),
                maximum,
            });
        }
        self.connection.send_datagram(encoded).await?;
        Ok(())
    }

    /// サーバーから受け入れたストリームを処理する
    ///
    /// ストリームの種類 (HTTP/3 の制御・QPACK・WebTransport) の判定は
    /// `shiguredo_http3` に任せ、ここでは読み取りを開始するだけにする。
    fn handle_accept(&mut self, stream: PeerStream) {
        match stream {
            PeerStream::Bidirectional(stream) => {
                let stream_id = stream.id();
                let (send, recv) = stream.split();
                // 送信側は BidiStreamOpen イベントでアプリケーションへ渡す
                self.peer_bidi.insert(stream_id, send);
                let reader = spawn_reader(
                    recv,
                    self.channels.reader_tx.clone(),
                    WtErrorCode::SessionGone as u64,
                );
                self.reader_tasks.insert(stream_id, reader);
            }
            PeerStream::Receive(recv) => {
                let stream_id = recv.id();
                let reader = spawn_reader(
                    recv,
                    self.channels.reader_tx.clone(),
                    WtErrorCode::SessionGone as u64,
                );
                self.reader_tasks.insert(stream_id, reader);
            }
        }
    }

    /// 受信したデータグラムを H3 に注入する
    fn handle_datagram(&mut self, datagram: &[u8]) {
        if let Err(error) = self.h3.feed_datagram(datagram) {
            debug!(
                session_id = self.session_id,
                "discarding HTTP datagram: {error}"
            );
        }
    }

    /// ストリームの読み取り結果を処理する
    fn handle_reader(&mut self, message: ReaderMessage) -> Result<(), Error> {
        match message {
            ReaderMessage::Data { stream_id, data } => {
                self.h3.feed_stream(stream_id, &data, false)?;
                Ok(())
            }
            ReaderMessage::Fin { stream_id } => {
                if stream_id == self.h3_streams.connect_id {
                    self.connect_stream_ended = true;
                }
                self.h3.feed_stream(stream_id, &[], true)?;
                // 終了したタスクのハンドルを手放す
                self.reader_tasks.remove(&stream_id);
                Ok(())
            }
            ReaderMessage::Reset {
                stream_id,
                error_code,
                final_size,
            } => {
                if stream_id == self.h3_streams.connect_id {
                    self.connect_stream_ended = true;
                    self.connect_stream_error_code = Some(error_code);
                }
                // H3 は RESET_STREAM を WebTransport のストリーム終了または
                // セッション終了へ変換する。イベントの処理で後始末する。
                self.h3.stream_reset(stream_id, error_code, final_size)?;
                self.reader_tasks.remove(&stream_id);
                Ok(())
            }
            ReaderMessage::ConnectionClosed { reason, .. } => {
                Err(Error::Quic(tobi_quic::Error::Connection(reason)))
            }
            ReaderMessage::Failed { stream_id, message } => {
                if stream_id == self.h3_streams.connect_id {
                    return Err(Error::DriverFailed(message));
                }
                // タスクのハンドルを手放す (タスクはこの通知で終了する)
                self.reader_tasks.remove(&stream_id);
                // アプリケーションへ渡していないストリームの失敗は、HTTP/3 の
                // クリティカルストリームの失敗でありうるため接続全体の失敗とする。
                if !self.streams_rx.contains_key(&stream_id)
                    && !self.local_streams.contains(&stream_id)
                    && !self.peer_bidi.contains_key(&stream_id)
                {
                    return Err(Error::DriverFailed(message));
                }
                warn!(
                    session_id = self.session_id,
                    stream_id, "WebTransport stream read failed: {message}"
                );
                self.fail_stream(stream_id, message);
                Ok(())
            }
        }
    }

    /// アプリケーションが消費した受信データを処理する
    fn handle_consumed(&mut self, consumed: Consumed) {
        if let Some(state) = self.streams_rx.get_mut(&consumed.stream_id) {
            state.pending_bytes = state.pending_bytes.saturating_sub(consumed.bytes);
        }
        // ストリームが既に破棄されていても、消費したデータはフロー制御へ返す
        self.h3.wt_data_consumed(self.session_id, consumed.bytes);
        self.prune_stream_state(consumed.stream_id);
    }

    /// ストリームからの制御通知を処理する
    async fn handle_control(&mut self, control: StreamControl) -> Result<(), Error> {
        match control {
            StreamControl::Dropped {
                stream_id,
                error_code,
            } => {
                debug!(
                    session_id = self.session_id,
                    stream_id, "WebTransport receive stream dropped"
                );
                // 受信側だけを停止する。双方向ストリームの送信側は維持する。
                // 配送上限で既に STOP_SENDING を送っている場合は重ねて送らない。
                let already_stopped = self
                    .streams_rx
                    .get(&stream_id)
                    .is_some_and(|state| state.delivery_stopped);
                if !already_stopped {
                    // 終端との競合で STOP_SENDING を送れなくても、配送停止と
                    // 後始末は続行する。個別ストリームの要求失敗でセッション全体を
                    // 終了しない。
                    let code = app_error_to_http3(error_code);
                    if let Err(error) = self.connection.stop_sending(stream_id, code).await {
                        debug!(
                            session_id = self.session_id,
                            stream_id, "failed to stop WebTransport stream: {error}"
                        );
                    }
                }
                // アプリケーションが読まなかったデータをフロー制御へ返す
                self.drop_stream_state(stream_id);
                self.finish_stream(stream_id);
                Ok(())
            }
            StreamControl::SendClosed { stream_id } => {
                self.stop_txs.remove(&stream_id);
                // 送信側と受信側の両方が終了したストリームは、ローカル開始の
                // 記録も解放する
                if !self.streams_rx.contains_key(&stream_id) {
                    self.local_streams.remove(&stream_id);
                }
                self.prune_stream_state(stream_id);
                Ok(())
            }
            StreamControl::DataBlocked { maximum } => {
                // 同じ上限に対して WT_DATA_BLOCKED を繰り返し送らない
                // (draft-ietf-webtrans-http3-15 Section 5.6.5)
                if self.last_data_blocked != Some(maximum) {
                    self.last_data_blocked = Some(maximum);
                    self.wt.queue_capsule(Capsule::DataBlocked { maximum });
                    self.pump().await?;
                }
                Ok(())
            }
        }
    }

    /// H3 のイベントを処理する
    async fn drain_events(&mut self) -> Result<(), Error> {
        let events = self.h3.drain_events()?;
        for event in events {
            self.handle_event(event).await?;
        }
        Ok(())
    }

    /// H3 のイベントを 1 つ処理する
    async fn handle_event(&mut self, event: Event) -> Result<(), Error> {
        match event {
            Event::HeadersBegin { stream_id } if stream_id == self.h3_streams.connect_id => {
                self.pending_status = None;
                self.pending_protocol = None;
            }
            Event::Header {
                stream_id,
                name,
                value,
            } if stream_id == self.h3_streams.connect_id => {
                if name == b":status"
                    && let Ok(status) = std::str::from_utf8(&value)
                    && let Ok(status) = status.parse::<u16>()
                {
                    self.pending_status = Some(status);
                } else if name == b"wt-protocol" {
                    // 値は Structured Field の Item 形式 (RFC 9651) である
                    // (draft-ietf-webtrans-http3-15 Section 3.3)
                    self.pending_protocol = std::str::from_utf8(&value)
                        .ok()
                        .and_then(ConnectResponse::parse_protocol);
                }
            }
            Event::HeadersEnd { stream_id } if stream_id == self.h3_streams.connect_id => {
                // 1xx の中間レスポンスは最終レスポンスではない (RFC 9114 Section 4.1)
                match self.pending_status {
                    Some(status) if (100..=199).contains(&status) => {
                        debug!(
                            session_id = self.session_id,
                            status, "ignoring informational CONNECT response"
                        );
                    }
                    status => {
                        self.final_status = status;
                        self.final_protocol = self.pending_protocol.take();
                        // wt-available-protocols を送った場合、サーバーは提示した
                        // 一覧から 1 つを wt-protocol で返さなければならない。
                        // 返さない、または一覧にない値を返した場合は WT_ALPN_ERROR で
                        // セッションを終了する (draft-ietf-webtrans-http3-15 Section 3.3)。
                        if status.is_some_and(|status| (200..=299).contains(&status))
                            && !self.requested_protocols.is_empty()
                        {
                            self.protocol_mismatch =
                                !self.final_protocol.as_ref().is_some_and(|selected| {
                                    self.requested_protocols.contains(selected)
                                });
                        }
                    }
                }
            }
            Event::WebTransport(event) => {
                self.handle_webtransport_event(event).await?;
            }
            _ => {}
        }
        Ok(())
    }

    /// WebTransport イベントを処理する
    async fn handle_webtransport_event(&mut self, event: WebTransportEvent) -> Result<(), Error> {
        match event {
            WebTransportEvent::SessionEstablished {
                session_id,
                flow_control_enabled,
            } if session_id == self.session_id => {
                self.established = true;
                self.flow_control_enabled = flow_control_enabled;
                self.wt.set_flow_control_enabled(flow_control_enabled);
                self.wt.set_established();
                if flow_control_enabled {
                    // ピアの初期上限は SETTINGS で通知される。以降の更新は
                    // WT_MAX_STREAMS / WT_MAX_DATA カプセルで届く。
                    // (draft-ietf-webtrans-http3-15 Section 5.5)
                    let limits = self.wt.remote_limits_mut();
                    limits.max_streams_uni = self.peer_limits.streams_uni;
                    limits.max_streams_bidi = self.peer_limits.streams_bidi;
                    limits.max_data = self.peer_limits.max_data;
                    self.credit.set_limit(self.peer_limits.max_data);
                } else {
                    self.credit.set_limit(u64::MAX);
                }
                debug!(
                    session_id = self.session_id,
                    flow_control_enabled, "WebTransport session established"
                );
            }
            WebTransportEvent::SessionClosed {
                session_id,
                reset_streams,
                error_code,
                close_error_code,
                close_message,
            } if session_id == self.session_id => {
                let mut reliable_sizes = HashMap::new();
                for reset in &reset_streams {
                    reliable_sizes.insert(reset.stream_id, reset.reliable_size);
                }
                // WT_SESSION_GONE の通知だけで終了した場合は正常クローズ、
                // それ以外と CONNECT ストリームの RESET_STREAM は異常終了として
                // 扱う (draft-ietf-webtrans-http3-15 Section 6 / Section 9.5)。
                let normal_close = error_code == WtErrorCode::SessionGone as u64
                    && self.connect_stream_error_code.is_none();
                if normal_close {
                    // 正常クローズでは WT_CLOSE_SESSION を送って FIN する
                    self.closing = true;
                    if self.h3.send_body(session_id, &[], true).is_err() {
                        let _ = self.h3_streams.connect_send.finish().await;
                    } else {
                        let _ = self.pump().await;
                    }
                } else {
                    // セッションエラーは WT プロトコルエラーコードを持つため、
                    // アプリケーションエラーコード空間の WT_CLOSE_SESSION では
                    // 通知できない。CONNECT ストリームを RESET_STREAM で閉じる
                    // (draft-ietf-webtrans-http3-15 Section 6)。
                    self.reset_connect_stream(error_code).await;
                    // プロトコルネゴシエーションの失敗は H3 層が検出して
                    // AlpnError でセッションを終了する。公開 API では
                    // ProtocolMismatch として返す
                    // (draft-ietf-webtrans-http3-15 Section 3.3)。
                    if error_code == WtErrorCode::AlpnError as u64 {
                        self.protocol_mismatch = true;
                    }
                }
                // セッション終了を知った側も、関連する全ストリームを
                // WT_SESSION_GONE でリセットする
                // (draft-ietf-webtrans-http3-15 Section 6)。
                self.reset_all_streams(WtErrorCode::SessionGone as u64, &reliable_sizes)
                    .await;
                self.wt.close(None);
                if normal_close {
                    self.finish(CloseInfo {
                        error_code: close_error_code,
                        message: close_message,
                        transport_error_code: Some(error_code),
                    });
                } else {
                    warn!(
                        session_id = self.session_id,
                        error_code, "WebTransport session aborted by the peer"
                    );
                    self.abort(
                        error_code,
                        self.connect_stream_error_code,
                        H3ErrorCode::NoError as u64,
                    );
                }
            }
            WebTransportEvent::SessionDraining { session_id } if session_id == self.session_id => {
                debug!(
                    session_id = self.session_id,
                    "WebTransport session is draining"
                );
                self.channels.draining.store(true, Ordering::Relaxed);
            }
            WebTransportEvent::BidiStreamOpen {
                stream_id,
                session_id,
            } if session_id == self.session_id => {
                if let Some(send) = self.peer_bidi.remove(&stream_id) {
                    self.ensure_incoming_bidi(stream_id, send).await;
                }
            }
            WebTransportEvent::BidiStreamData { stream_id, data } => {
                self.deliver_data(stream_id, data).await;
            }
            WebTransportEvent::BidiStreamEnd { stream_id } => {
                self.deliver_stream_event(stream_id, StreamEvent::Fin);
                self.finish_stream(stream_id);
            }
            WebTransportEvent::UniStreamOpen {
                stream_id,
                session_id,
            } if session_id == self.session_id => {
                self.ensure_incoming_uni(stream_id).await;
            }
            WebTransportEvent::UniStreamData { stream_id, data } => {
                self.deliver_data(stream_id, data).await;
            }
            WebTransportEvent::UniStreamEnd { stream_id } => {
                self.deliver_stream_event(stream_id, StreamEvent::Fin);
                self.finish_stream(stream_id);
            }
            WebTransportEvent::Datagram { payload, .. } => {
                // 受信キューが満杯の場合は DATAGRAM を破棄する (RFC 9221 Section 5.3)
                if self.channels.datagram_tx.try_send(payload).is_err() {
                    debug!(
                        session_id = self.session_id,
                        "discarding datagram: receive queue is full"
                    );
                }
            }
            WebTransportEvent::StreamReset {
                session_id,
                stream_id,
                error_code,
                ..
            } if session_id == self.session_id => {
                // アプリケーションエラーコードへ変換する
                // (draft-ietf-webtrans-http3-15 Section 4.4)。
                // 範囲外のコードはアプリケーションエラーコードが無いリセットとして
                // 通知する
                self.deliver_stream_event(
                    stream_id,
                    StreamEvent::Reset {
                        error_code: app_error_from_http3(error_code),
                    },
                );
                self.finish_stream(stream_id);
            }
            WebTransportEvent::StreamStopSending {
                session_id,
                stream_id,
                error_code,
            } if session_id == self.session_id => {
                self.handle_stop_sending(stream_id, error_code);
            }
            WebTransportEvent::BufferedStreamRejected {
                stream_id,
                error_code,
            } => {
                // セッションに属さないストリームなどは、そのストリームだけを
                // リセットしてセッションを継続する
                // (draft-ietf-webtrans-http3-15 Section 4.6)
                debug!(
                    session_id = self.session_id,
                    stream_id, error_code, "resetting rejected WebTransport stream"
                );
                self.reset_stream(stream_id, error_code, 0).await;
                self.finish_stream(stream_id);
                self.drop_stream_state(stream_id);
            }
            WebTransportEvent::Capsule {
                session_id,
                capsule,
            } if session_id == self.session_id => {
                self.handle_capsule(&capsule).await?;
            }
            WebTransportEvent::Capsule { .. }
            | WebTransportEvent::BidiStreamOpen { .. }
            | WebTransportEvent::UniStreamOpen { .. }
            | WebTransportEvent::SessionClosed { .. }
            | WebTransportEvent::SessionEstablished { .. }
            | WebTransportEvent::SessionDraining { .. }
            | WebTransportEvent::StreamReset { .. }
            | WebTransportEvent::StreamStopSending { .. } => {}
        }
        Ok(())
    }

    /// ピアから受信したフロー制御カプセルを反映する
    async fn handle_capsule(&mut self, capsule: &Capsule) -> Result<(), Error> {
        // 直前の上限と同じ値を繰り返すカプセルは上限を増やさないため無視する。
        // SETTINGS で通知済みの初期上限をカプセルでも送る相互運用実装
        // (Safari 26.4 など) が存在する。セッションエラーになるのは
        // 直前の値より小さい場合である
        // (draft-ietf-webtrans-http3-15 Section 5.6.2 / 5.6.4)。
        if self.is_duplicate_flow_control_capsule(capsule) {
            return Ok(());
        }
        if let Err(CapsuleProcessError::Session(error)) = self.wt.process_capsule(capsule) {
            // セッションレベルのエラーである。フロー制御違反やプロトコル違反は
            // WT プロトコルエラーコードで通知する必要があり、アプリケーション
            // エラーコード空間の WT_CLOSE_SESSION は使えない。CONNECT ストリーム
            // を該当するエラーコードでリセットする
            // (draft-ietf-webtrans-http3-15 Section 5.6.2 / 5.6.4 / Section 6)。
            let (code, message) = webtransport_error(&error);
            warn!(
                session_id = self.session_id,
                error_code = code,
                "closing WebTransport session: {message}"
            );
            let transport_error_code = match &error {
                shiguredo_http3::webtransport::error::Error::Protocol(code) => *code as u64,
                // 禁止カプセル (WT_MAX_STREAM_DATA 等) はフロー制御に関わる
                // セッションエラーとして扱う (draft-15 Section 5.4)
                _ => WtErrorCode::FlowControlError as u64,
            };
            self.reset_connect_stream(transport_error_code).await;
            self.reset_all_streams(WtErrorCode::SessionGone as u64, &HashMap::new())
                .await;
            self.abort(transport_error_code, None, H3ErrorCode::NoError as u64);
            return Ok(());
        }
        if self.flow_control_enabled {
            // ピアの WT_MAX_DATA を送信側のクレジットへ反映する
            self.credit.set_limit(self.wt.remote_limits().max_data);
        }
        debug!(
            session_id = self.session_id,
            "WebTransport flow control capsule processed"
        );
        Ok(())
    }

    /// 直前の上限と等しいフロー制御カプセルか判定する
    ///
    /// 上限を増やさないカプセルのうち、直前の値と同じものは無視できる。
    /// 直前の値より小さい場合はセッションエラーである
    /// (draft-ietf-webtrans-http3-15 Section 5.6.2 / 5.6.4)。
    fn is_duplicate_flow_control_capsule(&self, capsule: &Capsule) -> bool {
        let limits = self.wt.remote_limits();
        match capsule {
            Capsule::MaxData { maximum } => *maximum == limits.max_data,
            Capsule::MaxStreams {
                bidirectional,
                maximum,
            } => {
                // 上限を超える値は重複判定より先にセッションエラーとする
                // (draft-ietf-webtrans-http3-15 Section 5.6.2)
                if *maximum > MAX_STREAMS_LIMIT {
                    return false;
                }
                let current = if *bidirectional {
                    limits.max_streams_bidi
                } else {
                    limits.max_streams_uni
                };
                *maximum == current
            }
            _ => false,
        }
    }

    /// アプリケーションへ受信ストリームを渡す
    async fn ensure_incoming_uni(&mut self, stream_id: u64) {
        if self.streams_rx.contains_key(&stream_id) {
            return;
        }
        let (tx, rx) = mpsc::unbounded_channel();
        self.streams_rx.insert(
            stream_id,
            StreamState {
                tx,
                pending_bytes: 0,
                delivery_stopped: false,
            },
        );
        let stream = WtReceiveStream::new(
            stream_id,
            rx,
            self.channels.consumed_tx.clone(),
            self.channels.control_tx.clone(),
        );
        if let Err(error) = self.channels.incoming_uni_tx.try_send(stream) {
            match &error {
                mpsc::error::TrySendError::Full(_) => warn!(
                    session_id = self.session_id,
                    stream_id, "rejecting WebTransport stream: accept queue is full"
                ),
                mpsc::error::TrySendError::Closed(_) => debug!(
                    session_id = self.session_id,
                    stream_id, "rejecting WebTransport stream: accept queue is closed"
                ),
            }
            self.reject_stream(stream_id).await;
        }
    }

    /// アプリケーションへ双方向ストリームを渡す
    async fn ensure_incoming_bidi(&mut self, stream_id: u64, send: SendStream) {
        if self.streams_rx.contains_key(&stream_id) {
            return;
        }
        let (tx, rx) = mpsc::unbounded_channel();
        self.streams_rx.insert(
            stream_id,
            StreamState {
                tx,
                pending_bytes: 0,
                delivery_stopped: false,
            },
        );
        let (stop_tx, stop_rx) = watch::channel(None);
        self.stop_txs.insert(stream_id, stop_tx);
        let stream = WtBidirectionalStream::from_parts(
            WtSendStream::new(
                stream_id,
                send,
                self.credit.clone(),
                stop_rx,
                None,
                self.channels.control_tx.clone(),
            ),
            WtReceiveStream::new(
                stream_id,
                rx,
                self.channels.consumed_tx.clone(),
                self.channels.control_tx.clone(),
            ),
        );
        if self.channels.incoming_bidi_tx.try_send(stream).is_err() {
            warn!(
                session_id = self.session_id,
                stream_id, "rejecting WebTransport stream: accept queue is full"
            );
            self.reject_stream(stream_id).await;
        }
    }

    /// アプリケーションへイベントを配送する
    fn deliver_stream_event(&mut self, stream_id: u64, event: StreamEvent) {
        if let Some(state) = self.streams_rx.get(&stream_id) {
            // 配送停止後は追加の Failed を通知しない。Fin / Reset は
            // WtReceiveStream が終端エラーを保持しているため無視される。
            if state.delivery_stopped && matches!(&event, StreamEvent::Failed(_)) {
                return;
            }
            let _ = state.tx.send(event);
        }
    }

    /// 受信データをアプリケーションへ配送する
    ///
    /// 未消費データが上限を超えるチャンクは配送せず、そのストリームの配送を
    /// 停止する。上限ちょうどのデータは受理する。停止後も QUIC / H3 の受信は
    /// 継続し、届いたデータはアプリケーションへ渡さずフロー制御へ返す。
    /// 読み取りタスクを止めないため、FIN / RESET_STREAM と final_size は
    /// H3 へ届き、後続ストリームの受信クレジットも維持される。
    async fn deliver_data(&mut self, stream_id: u64, data: Vec<u8>) {
        let bytes = data.len() as u64;
        let Some(state) = self.streams_rx.get(&stream_id) else {
            // アプリケーションへ渡していない、または拒否したストリーム。
            // 受信は済んでいるため、フロー制御の消費として計上する
            self.h3.wt_data_consumed(self.session_id, bytes);
            return;
        };
        if state.delivery_stopped {
            // 配送停止後のデータはアプリケーションへ渡さず、消費だけ返す
            self.h3.wt_data_consumed(self.session_id, bytes);
            return;
        }
        let pending = state.pending_bytes.saturating_add(bytes);
        if pending > MAX_STREAM_BUFFER_BYTES {
            // 上限を超えるチャンクは配送しない。Failed は 1 回だけ通知し、
            // 以後の Data と Failed は配送しない。
            self.deliver_stream_event(
                stream_id,
                StreamEvent::Failed("receive buffer limit exceeded".to_string()),
            );
            if let Some(state) = self.streams_rx.get_mut(&stream_id) {
                state.delivery_stopped = true;
            }
            // 配送しなかったチャンクをフロー制御へ返す
            self.h3.wt_data_consumed(self.session_id, bytes);
            warn!(
                session_id = self.session_id,
                stream_id, pending, "WebTransport receive buffer limit exceeded"
            );
            // 受信側だけを止め、双方向ストリームの送信側はリセットしない。
            // 終端との競合で STOP_SENDING を送れなくても配送停止は解除しない。
            let code = app_error_to_http3(0);
            if let Err(error) = self.connection.stop_sending(stream_id, code).await {
                debug!(
                    session_id = self.session_id,
                    stream_id, "failed to stop WebTransport stream: {error}"
                );
            }
            // 送信側の後始末。未消費データが残るため状態は残る。
            self.finish_stream(stream_id);
            return;
        }
        // 上限内のデータは配送する。チャネルが閉じている場合は受信側が
        // 既にドロップされているため、消費として計上して後始末する。
        let sent = match self.streams_rx.get(&stream_id) {
            Some(state) => state.tx.send(StreamEvent::Data(data)).is_ok(),
            None => false,
        };
        if !sent {
            self.h3.wt_data_consumed(self.session_id, bytes);
            self.drop_stream_state(stream_id);
            self.finish_stream(stream_id);
            return;
        }
        if let Some(state) = self.streams_rx.get_mut(&stream_id) {
            state.pending_bytes = pending;
        }
    }

    /// 受信ストリームへ失敗を通知して後始末する
    fn fail_stream(&mut self, stream_id: u64, message: String) {
        self.deliver_stream_event(stream_id, StreamEvent::Failed(message));
        self.finish_stream(stream_id);
    }

    /// ストリームの終了後の後始末
    ///
    /// 送信側の停止通知とローカル開始の記録を破棄する。読み取りタスクは
    /// 止めない。FIN や RESET_STREAM を H3 へ届けて WT_MAX_STREAMS の
    /// 受信クレジットを返すためである (draft-ietf-webtrans-http3-15
    /// Section 5.6)。タスクはストリームの終了を検知して自発的に終了する。
    /// アプリケーションへ配送済みで未消費のデータは、アプリケーションが
    /// 読み切るかドロップするまで会計を保持する。
    fn finish_stream(&mut self, stream_id: u64) {
        // 送信側がまだ開いている場合はローカル開始の記録を残す
        if !self.stop_txs.contains_key(&stream_id) {
            self.local_streams.remove(&stream_id);
        }
        self.peer_bidi.remove(&stream_id);
        self.prune_stream_state(stream_id);
    }

    /// ストリームの受信状態を破棄する
    ///
    /// 未消費データのフロー制御への返却は、受信ストリームのドロップ時に
    /// チャネルへ残っている Data を数えて `Consumed` として通知する経路に
    /// 一本化している。ここで pending をまとめて返すと、同時に処理待ちの
    /// `Consumed` と二重計上になるため返さない
    /// (draft-ietf-webtrans-http3-15 Section 5.4)。
    fn drop_stream_state(&mut self, stream_id: u64) {
        self.streams_rx.remove(&stream_id);
    }

    /// 未消費データがなく、送受信とも終了したストリームの状態を破棄する
    fn prune_stream_state(&mut self, stream_id: u64) {
        let finished = self
            .streams_rx
            .get(&stream_id)
            .is_some_and(|state| state.pending_bytes == 0)
            && !self.reader_tasks.contains_key(&stream_id)
            && !self.stop_txs.contains_key(&stream_id);
        if finished {
            self.streams_rx.remove(&stream_id);
        }
    }

    /// ストリームを拒否する
    async fn reject_stream(&mut self, stream_id: u64) {
        self.reset_stream(stream_id, WtErrorCode::BufferedStreamRejected as u64, 0)
            .await;
        // STOP_SENDING の配送先が残らないように解放する
        self.stop_txs.remove(&stream_id);
        self.finish_stream(stream_id);
        self.drop_stream_state(stream_id);
    }

    /// STOP_SENDING を受信したストリームをアプリケーションへ通知する
    ///
    /// ピアはこちらの送信停止を要求しただけであり、受信方向は維持する。
    /// 送信側の RESET_STREAM は transport が STOP_SENDING の受信時に送る
    /// (RFC 9000 Section 3.5 / 19.5)。ここでは watch の通知だけを行う。
    fn handle_stop_sending(&mut self, stream_id: u64, error_code: u64) {
        debug!(
            session_id = self.session_id,
            stream_id, error_code, "WebTransport stream stopped by the peer"
        );
        if let Some(tx) = self.stop_txs.get(&stream_id) {
            let _ = tx.send(Some(error_code));
        }
    }

    /// セッションをクローズする
    async fn close_local(&mut self, error_code: u32, message: String) -> Result<(), Error> {
        if self.closed {
            return Err(Error::SessionClosed);
        }
        debug!(
            session_id = self.session_id,
            error_code, "closing WebTransport session"
        );
        let send_result = self.send_close_session(error_code, &message).await;
        self.reset_all_streams(WtErrorCode::SessionGone as u64, &HashMap::new())
            .await;
        self.wt.close(None);
        self.finish(CloseInfo {
            error_code,
            message,
            transport_error_code: None,
        });
        send_result
    }

    /// WT_CLOSE_SESSION を送信し、CONNECT ストリームを FIN で閉じる
    async fn send_close_session(&mut self, error_code: u32, message: &str) -> Result<(), Error> {
        if self.closing || self.connect_send_stopped {
            return Ok(());
        }
        self.wt.close_with_error(error_code, message.to_string());
        // 送信待ちのカプセル (WT_CLOSE_SESSION を含む) を流してから FIN する
        self.pump().await?;
        self.closing = true;
        self.h3.send_body(self.session_id, &[], true)?;
        self.pump().await
    }

    /// セッションエラーとして CONNECT ストリームを RESET_STREAM で閉じる
    ///
    /// フロー制御違反やプロトコルネゴシエーションの失敗は WT プロトコル
    /// エラーコードで通知する必要があるため、アプリケーションエラーコード
    /// 空間の WT_CLOSE_SESSION ではなく RESET_STREAM を使う
    /// (draft-ietf-webtrans-http3-15 Section 6)。
    async fn reset_connect_stream(&mut self, error_code: u64) {
        // 既にクローズ処理を開始している場合は、CONNECT ストリームの終端方法を
        // 変えない (FIN 送信後の RESET_STREAM は送れない)。ピアの STOP_SENDING
        // で transport が RESET_STREAM を送済みの場合も同様。
        if self.closing || self.connect_send_stopped {
            return;
        }
        // カプセルの送信は行わない。RESET_STREAM 以降の CONNECT ストリームの
        // 送信データはピアに届かないためである
        self.closing = true;
        if let Err(error) = self
            .connection
            .reset_stream(self.h3_streams.connect_id, error_code)
            .await
        {
            debug!(
                session_id = self.session_id,
                "failed to reset the CONNECT stream: {error}"
            );
        }
    }

    /// 全 WebTransport ストリームをリセットする
    async fn reset_all_streams(&mut self, error_code: u64, reliable_sizes: &HashMap<u64, u64>) {
        let mut stream_ids: HashSet<u64> = self.local_streams.iter().copied().collect();
        stream_ids.extend(self.streams_rx.keys().copied());
        stream_ids.extend(self.peer_bidi.keys().copied());
        for stream_id in stream_ids {
            let reliable_size = reliable_sizes.get(&stream_id).copied().unwrap_or(0);
            self.reset_stream(stream_id, error_code, reliable_size)
                .await;
        }
    }

    /// 1 つの WebTransport ストリームをリセットする
    async fn reset_stream(&mut self, stream_id: u64, error_code: u64, reliable_size: u64) {
        let local = self.local_streams.contains(&stream_id);
        let bidirectional = stream_id & 0x2 == 0;
        let can_send = bidirectional || local;
        let can_receive = bidirectional || !local;

        if can_send {
            // ローカル開始のストリームは WT ヘッダーを送信済みのため、
            // RESET_STREAM_AT の reliable size をヘッダー長以上にして
            // ヘッダーの配信を保証する (draft-ietf-webtrans-http3-15 Section 4.4)。
            // ピア開始のストリームは自身の送信側にヘッダーがないため 0 でよい。
            let reliable = if local {
                reliable_size.max(self.header_len)
            } else {
                0
            };
            let result = if self.peer_reset_stream_at {
                self.connection
                    .reset_stream_at(stream_id, error_code, reliable)
                    .await
            } else {
                self.connection.reset_stream(stream_id, error_code).await
            };
            if let Err(error) = result {
                debug!(
                    session_id = self.session_id,
                    stream_id, "failed to reset WebTransport stream: {error}"
                );
            }
        }
        if can_receive && let Err(error) = self.connection.stop_sending(stream_id, error_code).await
        {
            debug!(
                session_id = self.session_id,
                stream_id, "failed to stop WebTransport stream: {error}"
            );
        }
    }

    /// アプリケーションの受信側へセッション終了を配り、終了を通知する
    fn finish(&mut self, info: CloseInfo) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.credit.close();
        self.shutdown_code = H3ErrorCode::NoError as u64;
        // セッション終了時は関連ストリームを WT_SESSION_GONE で中断する
        // (draft-ietf-webtrans-http3-15 Section 6)
        for (stream_id, state) in self.take_stream_states() {
            // WT_SESSION_GONE はプロトコルエラーコードであり、アプリケーション
            // エラーコードとして解釈できない。エラーコードなしのリセットとして
            // 通知する (draft-ietf-webtrans-http3-15 Section 4.4)
            let _ = state.tx.send(StreamEvent::Reset { error_code: None });
            debug!(
                session_id = self.session_id,
                stream_id, "terminated WebTransport stream"
            );
        }
        let _ = self.channels.close_tx.send(Some(SessionEnd::Closed(info)));
        debug!(session_id = self.session_id, "WebTransport session closed");
    }

    /// セッションの異常終了を通知する
    fn abort(
        &mut self,
        transport_error_code: u64,
        connect_stream_error_code: Option<u64>,
        shutdown_code: u64,
    ) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.credit.close();
        self.shutdown_code = shutdown_code;
        for (stream_id, state) in self.take_stream_states() {
            let _ = state.tx.send(StreamEvent::Reset {
                error_code: app_error_from_http3(transport_error_code),
            });
            debug!(
                session_id = self.session_id,
                stream_id, "terminated WebTransport stream"
            );
        }
        let _ = self.channels.close_tx.send(Some(SessionEnd::Aborted {
            transport_error_code,
            connect_stream_error_code,
        }));
    }

    /// ドライバーの失敗をアプリケーションへ通知する
    fn fail(&mut self, error: Error) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.credit.close();
        self.shutdown_code = shutdown_code_for_error(&error);
        let message = error.to_string();
        warn!(
            session_id = self.session_id,
            "WebTransport driver failed: {message}"
        );
        for (stream_id, state) in self.take_stream_states() {
            let _ = state.tx.send(StreamEvent::Failed(message.clone()));
            debug!(
                session_id = self.session_id,
                stream_id, "terminated WebTransport stream"
            );
        }
        let end = match error {
            Error::Quic(tobi_quic::Error::Connection(reason))
            | Error::Quic(tobi_quic::Error::Stream(tobi_quic::StreamError::ConnectionLost(
                reason,
            ))) => SessionEnd::TransportClosed(reason),
            _ => SessionEnd::Failed(message),
        };
        let _ = self.channels.close_tx.send(Some(end));
    }

    /// 全ストリームの状態を取り出し、未消費データをフロー制御へ返す
    fn take_stream_states(&mut self) -> Vec<(u64, StreamState)> {
        let states: Vec<(u64, StreamState)> = self.streams_rx.drain().collect();
        for (_, state) in &states {
            if state.pending_bytes > 0 {
                // セッション終了後は H3 側のセッションが破棄されているため
                // フロー制御の更新は発生しない
                self.h3
                    .wt_data_consumed(self.session_id, state.pending_bytes);
            }
        }
        self.local_streams.clear();
        self.stop_txs.clear();
        self.peer_bidi.clear();
        states
    }

    /// H3 の送信データを QUIC ストリームへ流し、CONNECT のカプセルを送る
    ///
    /// `connect_send_stopped` が立っている場合は、ピアが CONNECT の送信側に
    /// STOP_SENDING を送っており、transport が RESET_STREAM を送っている。
    /// カプセルも FIN も送れないため CONNECT の送信だけをスキップする。
    /// HTTP/3 の control stream のフラッシュは続ける。フラグが立つ前に
    /// CONNECT の flush が `Stopped` になった場合も、ここでフラグを立てて
    /// 以降の送信を止める。
    async fn pump(&mut self) -> Result<(), Error> {
        // closing 中は CONNECT の FIN を流す必要があるため、カプセルだけを
        // 止める。connect_send_stopped の場合は FIN も送れないため、
        // フラッシュも止める。
        if !self.closing && !self.connect_send_stopped {
            // H3 の内部セッションが生成したカプセル (受信側のフロー制御更新)
            let capsules = self.h3.take_wt_pending_capsules(self.session_id);
            for capsule in capsules {
                let mut buffer = Vec::new();
                capsule.encode(&mut buffer);
                self.h3.send_body(self.session_id, &buffer, false)?;
            }
            // 送信側のフロー制御で生成したカプセル
            let capsules = self.wt.take_pending_capsules();
            for capsule in capsules {
                let mut buffer = Vec::new();
                capsule.encode(&mut buffer);
                self.h3.send_body(self.session_id, &buffer, false)?;
            }
        }

        self.h3_streams.control.flush_client(&mut self.h3).await?;
        if !self.connect_send_stopped {
            // STOP_SENDING は transport が accept_stop_sending より先に処理して
            // 送信側を ResetSent にする。driver がイベントを処理する前に flush
            // すると Stopped になるため、ここでフラグを立てて以降の送信を止める。
            match tobi_http3::io::flush_client_stream(
                &mut self.h3,
                &mut self.h3_streams.connect_send,
            )
            .await
            {
                Ok(()) => {}
                Err(tobi_http3::Error::Quic(tobi_quic::Error::Stream(
                    tobi_quic::StreamError::Stopped { .. },
                ))) => {
                    self.connect_send_stopped = true;
                    debug!(
                        session_id = self.session_id,
                        "CONNECT stream was stopped by the peer"
                    );
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

/// WT のエラーを WT_CLOSE_SESSION のエラーコードとメッセージへ変換する
fn webtransport_error(error: &shiguredo_http3::webtransport::error::Error) -> (u32, String) {
    use shiguredo_http3::webtransport::error::Error as WtSessionError;
    match error {
        // プロトコルエラーは HTTP/3 のエラーコード空間の値を持つ。
        WtSessionError::Protocol(code) => (*code as u32, code.description().to_string()),
        WtSessionError::Application { code, message } => (*code, message.clone()),
        WtSessionError::Unknown(code) => (
            u32::try_from(*code).unwrap_or(WtErrorCode::RequirementsNotMet as u32),
            "unknown WebTransport error".to_string(),
        ),
    }
}

/// QUIC 接続から WebTransport セッションを開設する
///
/// 開設に失敗した場合は、理由を通知するために QUIC 接続を閉じる。
/// タイムアウトはこの関数の内側で扱う。外側で `tokio::time::timeout` を
/// 使うと、タイムアウト時にこの future が中断されて後始末
/// (`close_application`) が実行されず、QUIC 接続と読み取りタスクが
/// 残ってしまうためである。
pub(crate) async fn establish(
    connection: Connection,
    config: ClientConfig,
) -> Result<Session, Error> {
    // establish の全体をタイムアウトで包む。キャンセルされても establish の
    // 内側の後始末は動かないため、タイムアウト時の後始末はこの関数が行う
    let timeout = config.handshake_timeout;
    let future = establish_inner(connection.clone(), config);
    let result = match timeout {
        Some(timeout) => match tokio::time::timeout(timeout, future).await {
            Ok(result) => result,
            Err(_) => Err(Error::HandshakeTimeout),
        },
        None => future.await,
    };
    if result.is_err() {
        // セッションを開設できなかった場合は QUIC 接続を閉じる。
        // タイムアウト時に establish_inner が中断されていても、この関数は
        // 最後まで実行されるため、接続と読み取りタスクが残留しない。
        // ハンドルを落とすだけではピアに終了が通知されない。
        let _ = connection
            .close_application(H3ErrorCode::NoError as u64, b"")
            .await;
    }
    result
}

/// QUIC 接続から WebTransport セッションを開設する本体
async fn establish_inner(connection: Connection, config: ClientConfig) -> Result<Session, Error> {
    let alpn = connection.application_protocol().await;
    if alpn.as_deref() != Some(ALPN_H3) {
        return Err(Error::AlpnMismatch { actual: alpn });
    }

    let peer_params = connection
        .peer_transport_params()
        .await
        .ok_or(Error::TransportParametersUnavailable)?;
    if peer_params
        .max_datagram_frame_size
        .is_none_or(|size| size == 0)
    {
        return Err(Error::DatagramNotSupported);
    }
    let peer_reset_stream_at = connection.peer_supports_reset_stream_at().await;

    let settings = build_client_settings(&config)?;

    // HTTP/3 の制御ストリームと QPACK ストリームを開く。
    // H3 の ClientConnection は最初の双方向ストリーム ID を 0 と仮定するため、
    // WebTransport では接続で最初に開く双方向ストリームを CONNECT に使う。
    // ピアの初期ストリーム上限が 0 でも、ピアが MAX_STREAMS で上限を増やせば
    // 開設できるよう待機版を使う。上限到達は回復可能な待機であり、セッション
    // 開設の失敗として扱わない。待機中も QUIC の受信とタイマーは進み、
    // `establish` のハンドシェイクタイムアウトで打ち切られる (タイムアウト未設定
    // の場合は無期限に待つ)。
    let (mut h3, control) = ControlStreams::client(&connection, settings).await?;
    for (stream_id, expected) in control.ids().into_iter().zip([2, 6, 10]) {
        if stream_id != expected {
            return Err(Error::StreamIdMismatch {
                expected,
                actual: stream_id,
            });
        }
    }
    // QUIC transport parameter の検証結果を H3 に注入する。CONNECT 送信前に必要。
    h3.set_webtransport_transport_verified(true, peer_reset_stream_at)?;

    // CONNECT 用の双方向ストリームも同じ理由で待機版を使う。
    let connect_stream = connection.open_bidirectional_stream_wait().await?;
    let connect_id = connect_stream.id();
    if connect_id != 0 {
        return Err(Error::StreamIdMismatch {
            expected: 0,
            actual: connect_id,
        });
    }
    let (connect_send, connect_recv) = connect_stream.split();
    // WT データストリームのヘッダーは signal value / stream type (1 バイト) と
    // セッション ID の VarInt で構成される。H3 は同じ長さを内部で計算するが
    // 公開 API がないため、同じ規則でここで求める。
    // (draft-ietf-webtrans-http3-15 Section 4.2 / 4.3)
    let header_len = StreamHeader::new(connect_id)?.encoded_size() as u64;

    let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
    let (reader_tx, reader_rx) = mpsc::channel(READER_CHANNEL_CAPACITY);
    let (consumed_tx, consumed_rx) = mpsc::unbounded_channel();
    let (control_tx, control_rx) = mpsc::unbounded_channel();
    let (incoming_bidi_tx, incoming_bidi_rx) = mpsc::channel(INCOMING_STREAM_CHANNEL_CAPACITY);
    let (incoming_uni_tx, incoming_uni_rx) = mpsc::channel(INCOMING_STREAM_CHANNEL_CAPACITY);
    let (datagram_tx, datagram_rx) = mpsc::channel(config.datagram_receive_capacity.get());
    let (close_tx, close_rx) = watch::channel(None);
    let draining = Arc::new(AtomicBool::new(false));
    let credit = SendCredit::new(control_tx.clone());

    let h3_streams = H3Streams {
        connect_id,
        control,
        connect_send,
    };
    let channels = ProcessorChannels {
        reader_tx,
        consumed_tx,
        control_tx,
        incoming_bidi_tx,
        incoming_uni_tx,
        datagram_tx,
        close_tx,
        draining,
    };
    // CONNECT ストリームの読み取りタスクは接続の生存期間だけ動かす
    let connect_reader = spawn_reader(connect_recv, channels.reader_tx.clone(), 0);
    let mut processor = Processor::new(ProcessorParts {
        h3,
        connection,
        session_id: connect_id,
        peer_reset_stream_at,
        header_len,
        h3_streams,
        channels,
        credit,
        connect_reader,
        requested_protocols: config.available_protocols.clone(),
    });

    let mut ctx = DriverContext {
        commands: command_rx,
        reader: reader_rx,
        consumed: consumed_rx,
        control: control_rx,
    };
    let prepared = async {
        processor.wait_for_peer_settings(&mut ctx).await?;
        processor.prepare_connect(&config).await?;
        processor.wait_for_session(&mut ctx).await
    }
    .await;
    if let Err(error) = prepared {
        // 前提 (SETTINGS / transport parameter) 未達の失敗は
        // WT_REQUIREMENTS_NOT_MET で接続を閉じる
        // (draft-ietf-webtrans-http3-15 Section 3.1)
        processor.setup_failure_kind = setup_failure_kind(&error);
        // CONNECT ストリームを閉じた場合は、ピアがその終了を観測するまで
        // 接続を閉じるのを待つ。待たずに閉じると、ピアは RESET_STREAM を
        // 観測できずセッションエラーの理由が失われる。
        if processor.closing {
            processor.wait_for_connect_stream_end(&mut ctx).await;
        }
        processor.cleanup_failed_setup().await;
        return Err(error);
    }

    let session = Session::new(SessionParts {
        session_id: connect_id,
        requested_draft: config.draft,
        settings_draft: processor
            .settings_draft()
            .expect("settings draft is decided before the session is established"),
        protocol: processor.protocol(),
        flow_control_enabled: processor.flow_control_enabled,
        commands: command_tx,
        incoming_bidi: incoming_bidi_rx,
        incoming_uni: incoming_uni_rx,
        datagrams: datagram_rx,
        end: close_rx,
        draining: processor.channels.draining.clone(),
    });
    tokio::spawn(processor.run(ctx));
    Ok(session)
}

#[cfg(test)]
mod tests;
