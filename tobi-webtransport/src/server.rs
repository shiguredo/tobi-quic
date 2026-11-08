// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! WebTransport サーバー側実装
//!
//! tobi_quic + shiguredo_http3 (Sans I/O) を使い WebTransport セッションを受け付ける。
//! draft-ietf-webtrans-http3 の draft-02 / 07 / 14 / 15 に対応する。
//! ドラフト判定は `Settings::webtransport_draft_pattern()`、CONNECT 拒否は `WtSessionRequest::reject()` を利用する。

use std::sync::{Arc, Mutex as StdMutex};

use shiguredo_http3::webtransport::Datagram;
use shiguredo_http3::webtransport::capsule::Capsule;
use shiguredo_http3::webtransport::connect::DraftVersion;
use shiguredo_http3::webtransport::connect::{ConnectRequest, ConnectResponse};
use shiguredo_http3::webtransport::error::ErrorCode as WtErrorCode;
use shiguredo_http3::webtransport::stream::{
    ClassifiedUniStream, StreamHeader, StreamHeaderDecodeError, classify_uni_stream_checked,
};
use shiguredo_http3::{
    Event, ServerConnection, Setting, Settings as H3Settings, SettingsPayload, VarInt,
};
use tobi_quic::connection::Connection;
use tobi_quic::stream::{ReceiveStream, SendStream};
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};

// 異常な応答を送る検証用の処理は、公開スナップショットから除外する。
#[cfg(test)]
#[path = "server/tests.rs"]
mod tests;

// ---------------------------------------------------------------------------
// エラー型
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    /// セッションが異常終了した
    ///
    /// `WT_CLOSE_SESSION` の 0 以外のアプリケーションエラーコード、
    /// CONNECT ストリームの RESET_STREAM、CONNECT ストリーム上の
    /// プロトコル違反のいずれかである。
    /// (draft-ietf-webtrans-http3-15 Section 6)
    SessionAborted(SessionAbort),
    /// QUIC 層のエラー
    ///
    /// 接続の終了理由を種別のまま保持する。正常終了と異常終了の区別に使う。
    Quic(tobi_quic::Error),
    /// QUIC トランスポートエラー
    Transport(String),
    /// HTTP/3 プロトコルエラー
    Http3(shiguredo_http3::Error),
    /// 接続がクローズ済み
    ConnectionClosed,
    /// セッションが終了した
    ///
    /// ピアが正常にセッションを終了した場合に返る。異常終了は
    /// [`Error::SessionAborted`] で区別する。
    SessionClosed,
    /// ストリームがクローズ済み
    StreamClosed,
    /// 無効な状態
    InvalidState(String),
    /// 内部エラー
    Internal(String),
}

impl Error {
    fn transport(e: impl std::fmt::Display) -> Self {
        Self::Transport(e.to_string())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionAborted(abort) => match abort {
                SessionAbort::ConnectStreamReset { error_code } => {
                    write!(f, "session aborted by CONNECT stream reset ({error_code})")
                }
                SessionAbort::SessionError {
                    error_code,
                    message,
                } => write!(f, "session aborted with code {error_code}: {message}"),
                SessionAbort::ProtocolViolation { message } => {
                    write!(f, "session aborted by protocol violation: {message}")
                }
            },
            Self::Quic(e) => write!(f, "quic error: {e}"),
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::Http3(e) => write!(f, "http3 error: {e}"),
            Self::ConnectionClosed => write!(f, "connection closed"),
            Self::SessionClosed => write!(f, "session closed"),
            Self::StreamClosed => write!(f, "stream closed"),
            Self::InvalidState(msg) => write!(f, "invalid state: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<shiguredo_http3::Error> for Error {
    fn from(e: shiguredo_http3::Error) -> Self {
        Self::Http3(e)
    }
}

impl From<tobi_quic::error::Error> for Error {
    fn from(e: tobi_quic::error::Error) -> Self {
        Self::Transport(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// HTTP/3 接続状態 (Sans I/O ラッパー)
// ---------------------------------------------------------------------------

struct ServerConnectionState {
    h3_conn: ServerConnection,
    control_stream_id: Option<u64>,
}

impl ServerConnectionState {
    fn new(settings: H3Settings) -> Self {
        Self {
            h3_conn: ServerConnection::new(settings),
            control_stream_id: None,
        }
    }

    fn set_control_stream_id(&mut self, id: u64) {
        self.control_stream_id = Some(id);
    }

    fn process_stream_data(&mut self, id: u64, data: &[u8], fin: bool) -> Result<Vec<Event>> {
        self.h3_conn.feed_stream(id, data, fin)?;
        Ok(self.h3_conn.drain_events()?)
    }

    fn feed_stream_only(&mut self, id: u64, data: &[u8], fin: bool) -> Result<()> {
        self.h3_conn.feed_stream(id, data, fin)?;
        Ok(())
    }

    fn take_control_pending(&mut self) -> Option<Vec<u8>> {
        let id = self.control_stream_id?;
        self.h3_conn.take_stream_data(id).map(|(d, _)| d)
    }

    fn drain_events(&mut self) -> Result<Vec<Event>> {
        Ok(self.h3_conn.drain_events()?)
    }
}

// ---------------------------------------------------------------------------
// tobi_quic ReceiveStream ヘルパー
// ---------------------------------------------------------------------------

/// tobi_quic の ReceiveStream からデータを受信する
///
/// tobi_quic は `receive(&mut buf) -> StreamRead { len, fin }` を返すため、
/// FIN の後は None を返す内部形式へ変換する。
async fn recv_data(recv: &mut ReceiveStream) -> Result<Option<Vec<u8>>> {
    let mut buf = vec![0u8; 65536];
    match recv.receive(&mut buf).await {
        Ok(read) => {
            if read.len == 0 && read.fin {
                Ok(None)
            } else {
                buf.truncate(read.len);
                Ok(Some(buf))
            }
        }
        // ストリームがリセットされた場合
        Err(_) => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// サーバーのフロー制御設定
// ---------------------------------------------------------------------------

/// サーバーが広告する WebTransport のフロー制御の初期値
///
/// draft-07 / 14 では最大セッション数を、draft-14 / 15 ではストリーム数と
/// データ量の初期上限を SETTINGS で通知する。
/// 最大セッション数は (draft-ietf-webtrans-http3-14 Section 9.2 /
/// draft-ietf-webtrans-http3-07 Section 3.2)、初期上限は
/// (draft-ietf-webtrans-http3-15 Section 5.5) を参照すること。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerLimits {
    /// 最大セッション数 (draft-07 / 14 で使用)
    pub max_sessions: u64,
    /// 初期の単方向ストリーム数上限 (draft-14 / 15 で使用)
    pub initial_max_streams_uni: u64,
    /// 初期の双方向ストリーム数上限 (draft-14 / 15 で使用)
    pub initial_max_streams_bidi: u64,
    /// 初期のデータ量上限 (draft-14 / 15 で使用)
    pub initial_max_data: u64,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_sessions: 100,
            initial_max_streams_uni: 100,
            initial_max_streams_bidi: 100,
            initial_max_data: 8 * 1024 * 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// WebTransport セッションリクエスト
// ---------------------------------------------------------------------------

/// WebTransport セッションリクエスト
///
/// accept 済み QUIC 接続から HTTP/3 CONNECT ハンドシェイクを処理する。
pub struct WtSessionRequest {
    path: String,
    authority: String,
    /// クライアントが希望するアプリケーションプロトコル (優先順)。
    available_protocols: Vec<String>,
    draft: DraftVersion,
    stream_id: u64,
    /// 受理時の応答に付ける `wt-protocol`
    protocol: Option<String>,
    /// 受理前に送る 1xx 中間レスポンスのステータス
    informational_status: Option<u16>,
    state: Arc<StdMutex<ServerConnectionState>>,
    send_stream: SendStream,
    /// CONNECT ストリームの受信半分 (ドロップすると STOP_SENDING が送信されるため保持する)
    _recv_stream: ReceiveStream,
    connection: Connection,
    uni_rx: mpsc::Receiver<WtRecvStream>,
    _control_task: JoinHandle<()>,
    _uni_task: JoinHandle<()>,
}

impl WtSessionRequest {
    /// QUIC 接続から WebTransport セッションリクエストを作成する
    ///
    /// クライアントの SETTINGS を先に受信し、draft バージョンを判定してから
    /// そのバージョンに合わせたサーバー SETTINGS を返す。
    pub async fn from_connection(
        connection: Connection,
        limits: ServerLimits,
        safari_compat: bool,
    ) -> Result<Self> {
        let (conn_handle, acceptor) = connection.split();

        // ── Phase 1: クライアントの制御ストリームを受信し SETTINGS を取得する ──

        tracing::info!("WebTransport: waiting for client control stream...");
        let mut pending_uni: Vec<(u64, ReceiveStream, Vec<u8>)> = Vec::new();
        let (client_settings, client_control_id, client_control_recv, client_control_buf) = 'find_control: {
            loop {
                let mut recv = acceptor.accept_receive_stream().await?;
                let sid = recv.id();
                tracing::debug!("WebTransport: received uni stream {} (0x{:x})", sid, sid);

                let first = recv_data(&mut recv).await?.ok_or(Error::StreamClosed)?;
                let mut buf = first;

                // ストリームタイプを判定する
                let (stream_type, _) = shiguredo_http3::varint::decode(&buf)
                    .map_err(|_| Error::InvalidState("stream type decode error".into()))?;

                tracing::info!(
                    "WebTransport: uni stream {} type: 0x{:x}",
                    sid,
                    stream_type.get()
                );

                if stream_type != VarInt::ZERO {
                    // 制御ストリーム以外は保留する
                    tracing::info!(
                        "WebTransport: uni stream {} is not control (type=0x{:x}), pending",
                        sid,
                        stream_type.get(),
                    );
                    pending_uni.push((sid, recv, buf));
                    continue;
                }

                tracing::info!(
                    "WebTransport: found client control stream {} (0x{:x})",
                    sid,
                    sid
                );

                // H3 制御ストリーム: SETTINGS フレームを読み切る
                loop {
                    match parse_settings_from_control(&buf) {
                        Ok(settings) => break 'find_control (settings, sid, recv, buf),
                        Err(SettingsParseState::NeedMoreData) => {
                            tracing::debug!(
                                "WebTransport: control stream {}: need more data for SETTINGS ({} bytes so far)",
                                sid,
                                buf.len()
                            );
                            let more = recv_data(&mut recv).await?.ok_or(Error::StreamClosed)?;
                            buf.extend_from_slice(&more);
                        }
                        Err(SettingsParseState::Error(msg)) => {
                            return Err(Error::InvalidState(msg));
                        }
                    }
                }
            }
        };

        // shiguredo_http3 のドラフト検出
        let draft = client_settings
            .webtransport_draft_pattern()
            .unwrap_or_else(|| {
                tracing::warn!(
                    "WebTransport: no recognized draft in client SETTINGS, fallback to draft-02"
                );
                DraftVersion::Draft02
            });
        tracing::info!("WebTransport: client draft detected: {draft:?}");
        // ── Phase 2: draft に合わせたサーバー SETTINGS を構築する ──

        let server_wt = build_server_wt_settings(draft, limits, safari_compat);
        let server_settings = H3Settings::default().enable_webtransport_server(server_wt);
        tracing::info!("WebTransport: server SETTINGS: {server_settings:?}");
        let state = Arc::new(StdMutex::new(ServerConnectionState::new(server_settings)));

        // ── Phase 3: サーバー H3 ストリームを初期化して SETTINGS を送信する ──

        tracing::info!("WebTransport: initializing H3 streams...");
        let mut control_send = conn_handle.open_send_stream().await?;
        let mut encoder_send = conn_handle.open_send_stream().await?;
        let mut decoder_send = conn_handle.open_send_stream().await?;

        let init_data = {
            let mut s = state.lock().unwrap();
            let data = s.h3_conn.init_h3_streams(
                control_send.id(),
                encoder_send.id(),
                decoder_send.id(),
            )?;
            s.set_control_stream_id(control_send.id());
            data
        };

        tracing::info!(
            "WebTransport: server control stream data ({} bytes): {:02x?}",
            init_data.control_data.len(),
            init_data.control_data
        );
        control_send.send(&init_data.control_data).await?;
        encoder_send.send(&init_data.encoder_data).await?;
        decoder_send.send(&init_data.decoder_data).await?;
        // 送信完了を示すために FIN は送らない (制御ストリームは接続中保持する)
        tracing::info!("WebTransport: H3 streams initialized (control, encoder, decoder)");

        // QUIC transport parameter レベルの前提条件を注入する
        // tobi_quic は DATAGRAM (RFC 9221) をサポートするため max_datagram_frame_size > 0
        // reset_stream_at は draft-ietf-quic-reliable-stream-reset-11 でピアが advertise した場合のみ true
        let reset_stream_at_supported = conn_handle.peer_supports_reset_stream_at().await;
        tracing::info!("WebTransport: peer reset_stream_at support: {reset_stream_at_supported}");
        {
            let mut s = state.lock().unwrap();
            s.h3_conn
                .set_webtransport_transport_verified(true, reset_stream_at_supported)
                .map_err(|e| Error::Internal(format!("transport verify failed: {e:?}")))?;
        }
        tracing::info!("WebTransport: transport parameters verified");

        // ── Phase 4: クライアントの制御ストリームデータを H3 に注入する ──

        let delayed_control_data = {
            let mut s = state.lock().unwrap();
            s.feed_stream_only(client_control_id, &client_control_buf, false)?;
            for event in s.drain_events()? {
                tracing::info!("WebTransport: client control stream event: {event:?}");
            }
            // サーバー SETTINGS はクライアント SETTINGS 受信後に初めてエンキューされる
            // (shiguredo_http3 の WebTransport サーバーはピアの draft を見て SETTINGS を組み立てるため)
            s.take_control_pending()
        };
        tracing::debug!("WebTransport: client control stream data injected into H3 state machine");

        if let Some(data) = delayed_control_data {
            tracing::info!(
                "WebTransport: sending delayed server control SETTINGS ({} bytes): {:02x?}",
                data.len(),
                data
            );
            if !data.is_empty() {
                control_send.send(&data).await?;
            }
        }

        // ── Phase 5: バックグラウンドタスクを開始する ──

        // 制御ストリームと QPACK ストリームを接続中保持する
        let control_task = tokio::spawn(async move {
            let _control_send = control_send;
            let _encoder_send = encoder_send;
            let _decoder_send = decoder_send;
            std::future::pending::<()>().await;
        });

        let unblock_notify = Arc::new(Notify::new());
        let (uni_tx, uni_rx) = mpsc::channel::<WtRecvStream>(16);

        // 単方向ストリーム受信タスク
        let state_for_uni = Arc::clone(&state);
        let notify_for_uni = Arc::clone(&unblock_notify);
        let acceptor_for_uni = conn_handle.clone();
        let uni_task = tokio::spawn(async move {
            // クライアント制御ストリームの残りデータを処理する
            {
                let state = Arc::clone(&state_for_uni);
                let notify = Arc::clone(&notify_for_uni);
                let cid = client_control_id;
                tokio::spawn(async move {
                    let mut recv = client_control_recv;
                    while let Ok(Some(data)) = recv_data(&mut recv).await {
                        tracing::debug!(
                            "WebTransport: client control stream {} received {} bytes",
                            cid,
                            data.len()
                        );
                        {
                            let mut s = state.lock().unwrap();
                            let _ = s.feed_stream_only(cid, &data, false);
                        }
                        notify.notify_one();
                    }
                    tracing::debug!("WebTransport: client control stream {} closed", cid);
                    {
                        let mut s = state.lock().unwrap();
                        let _ = s.feed_stream_only(cid, &[], true);
                    }
                    notify.notify_one();
                });
            }

            // 保留中の uni ストリームを処理する
            tracing::debug!(
                "WebTransport: processing {} pending uni streams",
                pending_uni.len()
            );
            for (stream_id, recv_stream, initial_data) in pending_uni {
                let state = Arc::clone(&state_for_uni);
                let notify = Arc::clone(&notify_for_uni);
                let uni_tx = uni_tx.clone();
                tokio::spawn(route_uni_stream_with_initial(
                    stream_id,
                    recv_stream,
                    initial_data,
                    state,
                    notify,
                    uni_tx,
                ));
            }

            // 新しいストリームを受け付ける
            let (_, acceptor) = acceptor_for_uni.split();
            while let Ok(recv_stream) = acceptor.accept_receive_stream().await {
                let state = Arc::clone(&state_for_uni);
                let notify = Arc::clone(&notify_for_uni);
                let uni_tx = uni_tx.clone();
                let stream_id = recv_stream.id();
                tracing::info!(
                    "WebTransport: new uni stream {} (0x{:x})",
                    stream_id,
                    stream_id
                );
                tokio::spawn(route_uni_stream(
                    stream_id,
                    recv_stream,
                    state,
                    notify,
                    uni_tx,
                ));
            }
            tracing::debug!("WebTransport: uni stream acceptor closed");
        });

        // ── Phase 6: 最初の双方向ストリーム (CONNECT リクエスト) を受け付ける ──

        tracing::info!("WebTransport: waiting for CONNECT bidi stream...");
        let stream = conn_handle.accept_bidirectional_stream().await?;

        let connect_stream_id = stream.id();
        tracing::info!(
            "WebTransport: received CONNECT bidi stream {} (0x{:x})",
            connect_stream_id,
            connect_stream_id
        );
        let (send_stream, mut recv_stream) = stream.split();

        {
            let mut s = state.lock().unwrap();
            let _ = s.h3_conn.feed_stream(connect_stream_id, &[], false);
            for event in s.drain_events()? {
                tracing::debug!("WebTransport: bidi stream init event: {event:?}");
            }
        }

        // CONNECT リクエストを受信する
        let mut collected_headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut headers_complete = false;

        tracing::info!("WebTransport: waiting for CONNECT headers...");
        while !headers_complete {
            {
                let events = state.lock().unwrap().drain_events()?;
                for event in events {
                    match event {
                        Event::Header { name, value, .. } => {
                            let n = String::from_utf8_lossy(&name);
                            let v = String::from_utf8_lossy(&value);
                            tracing::info!("WebTransport: CONNECT header: {n}: {v}");
                            collected_headers.push((name, value));
                        }
                        Event::HeadersEnd { .. } => {
                            tracing::info!("WebTransport: CONNECT headers complete");
                            headers_complete = true;
                        }
                        other => {
                            tracing::debug!("WebTransport: event: {other:?}");
                        }
                    }
                }
                if headers_complete {
                    break;
                }
            }

            tokio::select! {
                received = recv_data(&mut recv_stream) => {
                    let (data, fin) = match received {
                        Ok(Some(data)) => {
                            tracing::info!(
                                "WebTransport: received {} bytes on CONNECT stream",
                                data.len()
                            );
                            tracing::info!(
                                "WebTransport: CONNECT stream data: {:02x?}",
                                &data
                            );
                            (data, false)
                        }
                        Ok(None) => {
                            tracing::debug!("WebTransport: CONNECT stream ended (FIN)");
                            (vec![], true)
                        }
                        Err(e) => {
                            tracing::error!(
                                "WebTransport: CONNECT stream receive error: {e:?}"
                            );
                            return Err(e);
                        }
                    };
                    let events = {
                        let mut s = state.lock().unwrap();
                        s.process_stream_data(connect_stream_id, &data, fin)?
                    };
                    for event in events {
                        match event {
                            Event::Header { name, value, .. } => {
                                let n = String::from_utf8_lossy(&name);
                                let v = String::from_utf8_lossy(&value);
                                tracing::info!("WebTransport: CONNECT header: {n}: {v}");
                                collected_headers.push((name, value));
                            }
                            Event::HeadersEnd { .. } => {
                                tracing::info!("WebTransport: CONNECT headers complete");
                                headers_complete = true;
                            }
                            other => {
                                tracing::debug!("WebTransport: event: {other:?}");
                            }
                        }
                    }
                    if fin { break; }
                }
                _ = unblock_notify.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
            }
        }

        // ConnectRequest::from_headers() で検証付きパースする
        let header_refs: Vec<(&[u8], &[u8])> = collected_headers
            .iter()
            .map(|(n, v)| (n.as_slice(), v.as_slice()))
            .collect();
        let connect_request = ConnectRequest::from_headers(&header_refs)
            .map_err(|e| Error::Internal(format!("invalid CONNECT request: {e}")))?;

        tracing::info!(
            "WebTransport: CONNECT request parsed: path={}, authority={}",
            connect_request.path,
            connect_request.authority
        );

        Ok(Self {
            path: connect_request.path,
            authority: connect_request.authority,
            available_protocols: connect_request.available_protocols,
            draft,
            stream_id: connect_stream_id,
            protocol: None,
            informational_status: None,
            state,
            send_stream,
            _recv_stream: recv_stream,
            connection: conn_handle,
            uni_rx,
            _control_task: control_task,
            _uni_task: uni_task,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// クライアントが提示したアプリケーションプロトコルを優先順に返す。
    pub fn available_protocols(&self) -> &[String] {
        &self.available_protocols
    }

    pub fn draft(&self) -> DraftVersion {
        self.draft
    }

    /// 受理済み QUIC 接続のハンドルを返す
    ///
    /// 2xx を返さずに接続の終了を待つなど、ハンドシェイクを完了せずに
    /// 接続状態を観測する用途に使う。
    pub fn connection(&self) -> Connection {
        self.connection.clone()
    }

    /// 受理時の応答に付ける `wt-protocol` を設定する
    ///
    /// クライアントが `wt-available-protocols` を送っている場合だけ指定できる。
    /// (draft-ietf-webtrans-http3-15 Section 3.3)
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    /// 最終レスポンスの前に送る 1xx 中間レスポンスのステータスを設定する
    ///
    /// (RFC 9114 Section 4.1)
    pub fn with_informational_status(mut self, status: u16) -> Self {
        self.informational_status = Some(status);
        self
    }

    /// セッションリクエストを受け入れる
    pub async fn accept(mut self) -> Result<WtSession> {
        // 1xx の中間レスポンスを先に送る (RFC 9114 Section 4.1)
        if let Some(status) = self.informational_status {
            tracing::info!("WebTransport: sending {status} informational response for CONNECT");
            let interim_headers = ConnectResponse::new(status).to_headers().map_err(|e| {
                Error::InvalidState(format!("interim response headers failed: {e}"))
            })?;
            let interim_data = {
                let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
                s.h3_conn
                    .send_response(self.stream_id, &interim_headers, false)?;
                let mut all_data = Vec::new();
                while let Some((chunk, _fin)) = s.h3_conn.take_stream_data(self.stream_id) {
                    all_data.extend_from_slice(&chunk);
                }
                all_data
            };
            self.send_stream
                .send(&interim_data)
                .await
                .map_err(Error::transport)?;
        }

        tracing::info!("WebTransport: sending 200 response for CONNECT...");
        let mut response = ConnectResponse::new(200);
        if let Some(protocol) = &self.protocol {
            response = response.with_protocol(protocol.clone());
        }
        let response_headers = response
            .to_headers()
            .map_err(|e| Error::InvalidState(format!("CONNECT response headers failed: {e}")))?;

        let data = {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            s.h3_conn
                .send_response(self.stream_id, &response_headers, false)?;
            let mut all_data = Vec::new();
            while let Some((chunk, _fin)) = s.h3_conn.take_stream_data(self.stream_id) {
                all_data.extend_from_slice(&chunk);
            }
            all_data
        };

        self.send_stream
            .send(&data)
            .await
            .map_err(Error::transport)?;
        tracing::info!("WebTransport: session accepted (200 response sent)");

        // Safari 26.4 は draft-07 の SETTINGS ID と draft-14 の初期フロー制御を
        // 併用する。SETTINGS で初期上限を通知しても相手が draft-14 用の ID を
        // 解釈しない場合に備え、H3 層が初期フロー制御カプセルを保留している
        // 場合は CONNECT ストリームへ送る
        // (draft-ietf-webtrans-http3-14 Section 5)。
        let pending_capsules = {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            s.h3_conn.take_wt_pending_capsules(self.stream_id)
        };
        if !pending_capsules.is_empty() {
            let mut buf = Vec::new();
            for capsule in pending_capsules {
                capsule.encode_as_data_frame(&mut buf);
            }
            tracing::info!(
                "WebTransport: sending initial flow control capsules ({} bytes)",
                buf.len()
            );
            self.send_stream
                .send(&buf)
                .await
                .map_err(Error::transport)?;
        }

        Ok(self.into_accepted_session())
    }

    /// 受理済みの送信ストリームからセッションを組み立てる
    fn into_accepted_session(self) -> WtSession {
        WtSession {
            session_id: self.stream_id,
            draft: self.draft,
            connection: self.connection,
            connect_send: self.send_stream,
            connect_recv: self._recv_stream,
            connect_buffer: Vec::new(),
            bidi_headers: JoinSet::new(),
            close_info: None,
            abort_reason: None,
            close_sent: false,
            uni_rx: self.uni_rx,
        }
    }

    /// セッションリクエストを拒否する (4xx / 5xx)
    pub async fn reject(self, status: u16) -> Result<()> {
        if !(400..=599).contains(&status) {
            return Err(Error::InvalidState(format!(
                "reject status must be 4xx or 5xx, got {status}"
            )));
        }
        let response_headers = ConnectResponse::new(status)
            .to_headers()
            .map_err(|e| Error::InvalidState(format!("CONNECT response headers failed: {e}")))?;
        let data = {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            s.h3_conn
                .send_response(self.stream_id, &response_headers, true)?;
            let mut all_data = Vec::new();
            while let Some((chunk, _fin)) = s.h3_conn.take_stream_data(self.stream_id) {
                all_data.extend_from_slice(&chunk);
            }
            all_data
        };
        let mut send_stream = self.send_stream;
        send_stream
            .send_fin(&data)
            .await
            .map_err(Error::transport)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WebTransport セッション
// ---------------------------------------------------------------------------

pub struct WtSession {
    session_id: u64,
    draft: DraftVersion,
    connection: Connection,
    connect_send: SendStream,
    /// CONNECT ストリームの受信半分
    ///
    /// ドロップすると STOP_SENDING が送信されるため保持する。ピアが送る
    /// `WT_CLOSE_SESSION` と FIN はここから読む。
    connect_recv: ReceiveStream,
    /// CONNECT ストリームから受信済みで、まだ解析していないデータ
    connect_buffer: Vec<u8>,
    /// ヘッダー読み込み中のピア起点双方向ストリーム
    bidi_headers: JoinSet<Result<Option<WtBiStream>>>,
    /// ピアから通知されたクローズ情報 (正常終了)
    close_info: Option<CloseInfo>,
    /// セッションの異常終了理由
    abort_reason: Option<SessionAbort>,
    /// こちらから `WT_CLOSE_SESSION` と FIN を送って正常終了を開始したか
    ///
    /// 開始後の CONNECT ストリームのリセットは、終了への応答である可能性がある。
    close_sent: bool,
    uni_rx: mpsc::Receiver<WtRecvStream>,
}

/// こちらから正常終了を開始した後なら、`WT_SESSION_GONE` のリセットを正常終了として扱うかを返す
///
/// ピアはセッションの終了を知ると、関連するストリームを `WT_SESSION_GONE` で
/// 中断する。`WT_SESSION_GONE` はセッションが閉じたことを示すプロトコル
/// エラーコードであり、アプリケーションの異常終了ではない
/// (draft-ietf-webtrans-http3-15 Section 6)。したがって開始済みの正常終了への
/// 応答は成功として扱う。こちらから要求していないリセットは、エラーコードに
/// かかわらず異常終了のままにする。
fn session_gone_is_close_response(error_code: u64, close_sent: bool) -> bool {
    close_sent && error_code == WtErrorCode::SessionGone as u64
}

/// CONNECT ストリームの終了を待つ
///
/// クローズカプセルを観測した場合と、CONNECT ストリームが終端した場合は
/// 判定結果を返す。まだ届いていない場合は `None` を返す。
async fn receive_connect_end(
    connect_recv: &mut ReceiveStream,
    buffer: &mut Vec<u8>,
    close_sent: bool,
) -> Result<Option<std::result::Result<CloseInfo, SessionAbort>>> {
    let mut chunk = [0u8; 4096];
    match connect_recv.receive(&mut chunk).await {
        Ok(read) => {
            buffer.extend_from_slice(&chunk[..read.len]);
            let ended = read.fin;
            Ok(process_close_frame(buffer, ended))
        }
        Err(tobi_quic::Error::Stream(tobi_quic::StreamError::Reset { error_code, .. })) => {
            if session_gone_is_close_response(error_code, close_sent) {
                return Ok(Some(Ok(normal_close_info())));
            }
            Ok(Some(Err(SessionAbort::ConnectStreamReset { error_code })))
        }
        Err(error) => Err(Error::Quic(error)),
    }
}

/// ピアが開始した単方向ストリームを受け付ける
///
/// 別セッション宛てのストリームは破棄する。ブラウザーは同じ接続で複数の
/// セッションを扱うため、他セッション宛てのストリームが届いてもセッションを
/// 閉じない (draft-ietf-webtrans-http3-15 Section 4.2)。
async fn accept_uni_stream(
    uni_rx: &mut mpsc::Receiver<WtRecvStream>,
    session_id: u64,
) -> Result<WtRecvStream> {
    loop {
        let stream = uni_rx.recv().await.ok_or(Error::StreamClosed)?;
        if stream.session_id() != session_id {
            tracing::debug!(
                "WebTransport: discarding uni stream {} for another session ({} != {})",
                stream.stream_id(),
                stream.session_id(),
                session_id
            );
            continue;
        }
        tracing::debug!(
            "WebTransport: accepted uni recv stream {} (0x{:x})",
            stream.stream_id(),
            stream.stream_id()
        );
        return Ok(stream);
    }
}

/// ピアが開始した双方向ストリームを 1 本受理し、WT ヘッダーを読む
///
/// 受理したストリームは専用タスクでヘッダーまで読み進める。`select!` の
/// キャンセルでヘッダー読み込みが中断されると、受理済みストリームが失われる
/// ためである。読み終えたストリームは `headers` に積まれ、次の呼び出しで
/// 取り出される。
///
/// 別セッション宛てのストリームは破棄する
/// (draft-ietf-webtrans-http3-15 Section 4.3)。
async fn accept_bidi_stream(
    connection: &Connection,
    session_id: u64,
    headers: &mut JoinSet<Result<Option<WtBiStream>>>,
) -> Result<WtBiStream> {
    loop {
        // ヘッダーの読み込みが終わったストリームを先に返す。
        if let Some(finished) = headers.try_join_next() {
            match finished.map_err(|error| Error::Internal(error.to_string()))? {
                Ok(Some(stream)) => return Ok(stream),
                Ok(None) => continue,
                Err(error) => return Err(error),
            }
        }
        if headers.len() >= MAX_PENDING_BIDI_HEADERS {
            match headers
                .join_next()
                .await
                .expect("JoinSet が空でない")
                .map_err(|error| Error::Internal(error.to_string()))?
            {
                Ok(Some(stream)) => return Ok(stream),
                Ok(None) => continue,
                Err(error) => return Err(error),
            }
        }
        let stream = connection
            .accept_bidirectional_stream()
            .await
            .map_err(Error::transport)?;
        // ヘッダー読み込みは所有タスクで続ける。
        headers.spawn(read_bidi_header(stream, session_id));
    }
}

/// 双方向ストリームの WT ヘッダーを読み、アプリケーションのペイロードを取り出す
///
/// 別セッション宛てのストリームは `Ok(None)` を返して破棄する。
async fn read_bidi_header(
    stream: tobi_quic::BidirectionalStream,
    session_id: u64,
) -> Result<Option<WtBiStream>> {
    let stream_id = stream.id();
    let (send, mut recv) = stream.split();

    let mut header_buf: Vec<u8> = Vec::new();
    let pending = loop {
        let mut buf = vec![0u8; 65536];
        let read = recv.receive(&mut buf).await.map_err(Error::Quic)?;
        if read.len == 0 && read.fin {
            return Err(Error::StreamClosed);
        }
        header_buf.extend_from_slice(&buf[..read.len]);
        match StreamHeader::decode_bidirectional_checked(&header_buf) {
            Ok((parsed, consumed)) => {
                if parsed.session_id() != session_id {
                    tracing::debug!(
                        "WebTransport: discarding bidi stream {} for another session \
                         ({} != {})",
                        stream_id,
                        parsed.session_id(),
                        session_id
                    );
                    return Ok(None);
                }
                break header_buf[consumed..].to_vec();
            }
            Err(StreamHeaderDecodeError::BufferTooShort) => continue,
            Err(e) => {
                return Err(Error::Internal(format!("bidi header decode error: {e:?}")));
            }
        }
    };

    tracing::debug!(
        "WebTransport: accepted bidi stream {} (0x{:x})",
        stream_id,
        stream_id
    );

    Ok(Some(WtBiStream {
        stream_id,
        session_id,
        recv,
        send,
        pending,
    }))
}

/// このセッション宛ての DATAGRAM を 1 件受信する
///
/// 別セッション宛ての DATAGRAM は読み捨てる
/// (draft-ietf-webtrans-http3-15 Section 4.5)。
async fn receive_session_datagram(connection: &Connection, session_id: u64) -> Result<Vec<u8>> {
    loop {
        let raw = connection.receive_datagram().await.map_err(Error::Quic)?;
        let (datagram, _) = Datagram::decode(&raw)
            .map_err(|error| Error::InvalidState(format!("invalid DATAGRAM payload: {error:?}")))?;
        if datagram.session_id == session_id {
            return Ok(datagram.payload);
        }
        tracing::debug!(
            "WebTransport: discarding DATAGRAM for another session ({} != {})",
            datagram.session_id,
            session_id
        );
    }
}

/// WT ヘッダーの読み込みを並行して進める双方向ストリームの上限
///
/// 悪意あるピアがヘッダーを送らないまま大量のストリームを開いても、
/// タスクとメモリが増え続けないようにする。
const MAX_PENDING_BIDI_HEADERS: usize = 32;

/// サーバー側のセッションへ到着したデータまたはピアが開始したストリーム
pub enum Incoming {
    /// ピアが開始した双方向ストリーム。
    ///
    /// WT ヘッダーは受信済みで、アプリケーションのペイロードから読み出せる。
    Bidirectional(WtBiStream),
    /// ピアが開始した単方向ストリーム。
    Unidirectional(WtRecvStream),
    /// このセッション宛ての DATAGRAM のペイロード。
    Datagram(Vec<u8>),
}

/// サーバー側で観測したセッションのクローズ情報
///
/// クライアント側の `session::CloseInfo` と同じ内容を持つが、テスト用の
/// サーバー実装がこのモジュールを取り込んで動かすため、クレート内の他の
/// モジュールへ依存しないよう独立して定義する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseInfo {
    /// アプリケーションが指定したクローズコード
    ///
    /// ピアが `WT_CLOSE_SESSION` を送らずに CONNECT ストリームを正常に閉じた
    /// 場合は 0 になる。これはクローズコード 0・理由が空の
    /// `WT_CLOSE_SESSION` と等価である (draft-ietf-webtrans-http3-15 Section 6)。
    pub error_code: u32,
    /// アプリケーションが指定したクローズ理由
    pub message: String,
    /// セッション終了時に使われたトランスポート側のエラーコード
    pub transport_error_code: Option<u64>,
}

/// CONNECT ストリームのバッファから `WT_CLOSE_SESSION` を取り出す
///
/// DATA フレームとカプセルはどちらも分割されて届くため、判定できない場合は
/// `None` を返して呼び出し側に持ち越させる。`ended` が真なら、クローズ
/// カプセルを受け取らずに CONNECT ストリームが終端したとみなす。
/// (draft-ietf-webtrans-http3-15 Section 6)
fn process_close_frame(
    data: &[u8],
    ended: bool,
) -> Option<std::result::Result<CloseInfo, SessionAbort>> {
    let mut frames = data.to_vec();
    loop {
        let (frame, consumed) = match shiguredo_http3::frame::decode_frame(&frames) {
            Ok(frame) => frame,
            Err(shiguredo_http3::error::FrameDecodeError::BufferTooShort) => {
                return ended.then(|| Ok(normal_close_info()));
            }
            Err(error) => {
                return Some(Err(SessionAbort::ProtocolViolation {
                    message: format!("invalid CONNECT frame: {error}"),
                }));
            }
        };
        frames.drain(..consumed);
        let shiguredo_http3::frame::Frame::Data(payload) = frame else {
            continue;
        };
        let mut capsules = payload.data().to_vec();
        loop {
            let decoded = match Capsule::decode(&capsules) {
                Ok(Some(decoded)) => decoded,
                Ok(None) => break,
                Err(error) => {
                    return Some(Err(SessionAbort::ProtocolViolation {
                        message: format!("invalid CONNECT capsule: {error:?}"),
                    }));
                }
            };
            let (capsule, consumed) = decoded;
            capsules.drain(..consumed);
            if let Capsule::CloseSession {
                error_code,
                message,
            } = capsule
            {
                if error_code != 0 {
                    return Some(Err(SessionAbort::SessionError {
                        error_code,
                        message,
                    }));
                }
                return Some(Ok(normal_close_info()));
            }
        }
    }
}

/// クローズコード 0・理由が空のクローズ情報を作る
///
/// `WT_CLOSE_SESSION` を受け取らずに CONNECT ストリームが終了した場合も、
/// これと同じ扱いになる (draft-ietf-webtrans-http3-15 Section 6)。
fn normal_close_info() -> CloseInfo {
    CloseInfo {
        error_code: 0,
        message: String::new(),
        transport_error_code: None,
    }
}

/// 正常な QUIC 終了かどうかを判定する
///
/// アプリケーションエラーコード `0x100` は WebTransport のセッション終了を
/// 伝えるために使う (draft-ietf-webtrans-http3-15 Section 9.5)。
/// HTTP/3 のエラーコードや、それ以外のアプリケーションエラーは異常終了として
/// 扱う。
fn normal_session_close(error: &tobi_quic::Error) -> bool {
    let reason = match error {
        tobi_quic::Error::Connection(reason)
        | tobi_quic::Error::Stream(tobi_quic::StreamError::ConnectionLost(reason)) => reason,
        _ => return false,
    };
    matches!(
        reason,
        tobi_quic::ConnectionError::Closed
            | tobi_quic::ConnectionError::Application { code: 0x100, .. }
    )
}

/// サーバー側でセッションが異常終了した理由
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAbort {
    /// ピアが `WT_CLOSE_SESSION` 以外の方法で CONNECT ストリームを終了した
    ///
    /// RESET_STREAM のアプリケーションエラーコードを保持する。こちらから
    /// 正常終了を開始した後に届いた `WT_SESSION_GONE` のリセットは、終了への
    /// 応答であるためこの理由にならない。
    ConnectStreamReset {
        /// RESET_STREAM のアプリケーションエラーコード
        error_code: u64,
    },
    /// `WT_CLOSE_SESSION` に 0 以外のアプリケーションエラーコードが付いていた
    SessionError {
        /// `WT_CLOSE_SESSION` のアプリケーションエラーコード
        error_code: u32,
        /// アプリケーションが指定したクローズ理由
        message: String,
    },
    /// CONNECT ストリームのデータが WebTransport のカプセルとして解釈できない
    ProtocolViolation {
        /// 観測したエラーの説明
        message: String,
    },
}

/// セッションの終了状態
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEnd {
    /// 正常に終了した
    Closed(CloseInfo),
    /// 異常終了した
    Aborted(SessionAbort),
}

/// WtSession を分解した各コンポーネント
pub struct WtSessionParts {
    pub session_id: u64,
    pub draft: DraftVersion,
    pub connection: Connection,
    pub uni_rx: mpsc::Receiver<WtRecvStream>,
    /// CONNECT ストリームの送信側 (ドロップ防止のため保持する)
    pub _connect_send: SendStream,
    /// CONNECT ストリームの受信側 (ドロップ防止のため保持する)
    pub _connect_recv: ReceiveStream,
}

impl WtSession {
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn draft(&self) -> DraftVersion {
        self.draft
    }

    /// 受理済み QUIC 接続のハンドルを返す
    ///
    /// 2xx を返さずに接続の終了を待つなど、ハンドシェイクを完了せずに
    /// 接続状態を観測する用途に使う。
    pub fn connection(&self) -> Connection {
        self.connection.clone()
    }

    /// セッションを独立したコンポーネントに分解する
    ///
    /// CONNECT ストリームの監視と `WT_CLOSE_SESSION` の処理は分解後は
    /// 呼び出し側の責任になる。`wait_closed` などのセッション API を使わず、
    /// すべてのストリームを自前で扱う場合に使う。
    pub fn into_parts(self) -> WtSessionParts {
        WtSessionParts {
            session_id: self.session_id,
            draft: self.draft,
            connection: self.connection,
            uni_rx: self.uni_rx,
            _connect_send: self.connect_send,
            _connect_recv: self.connect_recv,
        }
    }

    /// 単方向送信ストリームを開く
    pub async fn open_uni_stream(&mut self) -> Result<WtSendStream> {
        let mut send = self
            .connection
            .open_send_stream()
            .await
            .map_err(Error::transport)?;
        let stream_id = send.id();

        let mut header = Vec::new();
        StreamHeader::new(self.session_id)
            .expect("session_id must be a client-initiated bidirectional stream id")
            .encode_unidirectional(&mut header);
        send.send(&header).await.map_err(Error::transport)?;

        tracing::debug!(
            "WebTransport: opened uni send stream {} (0x{:x})",
            stream_id,
            stream_id
        );

        Ok(WtSendStream { stream_id, send })
    }

    /// 単方向受信ストリームを受け付ける
    pub async fn accept_uni_stream(&mut self) -> Result<WtRecvStream> {
        accept_uni_stream(&mut self.uni_rx, self.session_id).await
    }

    /// 双方向ストリームを受け付ける
    pub async fn accept_bi_stream(&mut self) -> Result<WtBiStream> {
        accept_bidi_stream(&self.connection, self.session_id, &mut self.bidi_headers).await
    }

    /// 双方向ストリームを開く
    pub async fn open_bi_stream(&mut self) -> Result<WtBiStream> {
        let stream = self
            .connection
            .open_bidirectional_stream()
            .await
            .map_err(Error::transport)?;
        let stream_id = stream.id();
        let (mut send, recv) = stream.split();

        let mut header = Vec::new();
        StreamHeader::new(self.session_id)
            .expect("session_id must be a client-initiated bidirectional stream id")
            .encode_bidirectional(&mut header);
        send.send(&header).await.map_err(Error::transport)?;

        tracing::debug!(
            "WebTransport: opened bidi stream {} (0x{:x})",
            stream_id,
            stream_id
        );

        Ok(WtBiStream {
            stream_id,
            session_id: self.session_id,
            recv,
            send,
            pending: Vec::new(),
        })
    }

    /// このセッション宛ての DATAGRAM を送信する
    ///
    /// HTTP Datagram のセッション ID の付与はこの API が行うため、利用側は
    /// ペイロードだけを渡す。送信は接続の送信キューを待つため `&mut self` を
    /// 要求する。エンコード後のサイズが
    /// `Connection::max_datagram_size` を超える場合はエラーを返す。
    /// (draft-ietf-webtrans-http3-15 Section 4.5)
    ///
    /// # エラー
    ///
    /// ピアが DATAGRAM に対応していない場合、ペイロードが大きすぎる場合、
    /// セッションが終了している場合はエラーを返す。
    pub async fn send_datagram(&mut self, payload: &[u8]) -> Result<()> {
        let mut data = Vec::new();
        Datagram::new(self.session_id, payload.to_vec())
            .map_err(|error| Error::InvalidState(format!("invalid DATAGRAM: {error:?}")))?
            .encode(&mut data);
        self.connection
            .send_datagram_wait(data)
            .await
            .map_err(Error::Quic)
    }

    /// このセッション宛ての DATAGRAM を 1 件受信する
    ///
    /// 他セッション宛ての DATAGRAM は読み捨て、このセッション宛てだけを返す。
    /// DATAGRAM は再送されないため、受信キューが満杯の場合は破棄される
    /// (RFC 9221 Section 5.3)。
    ///
    /// # エラー
    ///
    /// QUIC 接続が終了した場合はエラーを返す。
    pub async fn receive_datagram(&mut self) -> Result<Vec<u8>> {
        receive_session_datagram(&self.connection, self.session_id).await
    }

    /// セッションの終了を待つ
    ///
    /// 正常に終了した場合はクローズ情報を返す。CONNECT ストリームの
    /// RESET_STREAM や、`WT_CLOSE_SESSION` の 0 以外のアプリケーション
    /// エラーコードで終了した場合は [`Error::SessionAborted`] を返す。
    /// ただし、こちらから正常終了を開始した後に `WT_SESSION_GONE` で
    /// リセットされた場合は、セッション終了への応答であるため正常終了として
    /// 扱う (draft-ietf-webtrans-http3-15 Section 6)。
    /// QUIC 接続が終了した場合は終了理由を保持した [`Error::Quic`] を返す。
    pub async fn wait_closed(&mut self) -> Result<CloseInfo> {
        if let Some(info) = self.close_info.clone() {
            return Ok(info);
        }
        if let Some(abort) = self.abort_reason.clone() {
            return Err(Error::SessionAborted(abort));
        }
        // CONNECT ストリームの監視と QUIC 接続の終了を同時に待つ。
        let mut buffer = [0u8; 4096];
        loop {
            tokio::select! {
                received = self.connect_recv.receive(&mut buffer) => match received {
                    Ok(read) => {
                        self.connect_buffer.extend_from_slice(&buffer[..read.len]);
                        let ended = read.fin;
                        if let Some(result) = self.process_connect_stream(ended) {
                            return result;
                        }
                    }
                    Err(tobi_quic::Error::Stream(tobi_quic::StreamError::Reset { error_code, .. })) => {
                        if session_gone_is_close_response(error_code, self.close_sent) {
                            return Ok(normal_close_info());
                        }
                        let abort = SessionAbort::ConnectStreamReset { error_code };
                        self.abort_reason = Some(abort.clone());
                        return Err(Error::SessionAborted(abort));
                    }
                    Err(error) => return Err(Error::Quic(error)),
                },
                reason = self.connection.closed() => {
                    return match reason {
                        // ピアが CONNECT ストリームを閉じずに接続だけを終了した
                        None => Ok(CloseInfo {
                            error_code: 0,
                            message: String::new(),
                            transport_error_code: None,
                        }),
                        Some(reason) => {
                            let error = tobi_quic::Error::Connection(reason);
                            match normal_session_close(&error) {
                                true => Ok(CloseInfo {
                                    error_code: 0,
                                    message: String::new(),
                                    transport_error_code: None,
                                }),
                                false => Err(Error::Quic(error)),
                            }
                        }
                    };
                }
            }
        }
    }

    /// CONNECT ストリームの受信データから `WT_CLOSE_SESSION` を取り出す
    ///
    /// クローズを観測した場合は `Some(Ok(info))`、異常終了は `Some(Err(error))`
    /// を返す。まだ判定できない場合は `None` を返す。
    fn process_connect_stream(&mut self, ended: bool) -> Option<Result<CloseInfo>> {
        let buffered = std::mem::take(&mut self.connect_buffer);
        let mut data = buffered;
        let outcome = process_close_frame(&data, ended);
        // 解析しきれなかった分だけを持ち越す。判定が済んだ場合は破棄する。
        if outcome.is_none() && !ended {
            data.clear();
        }
        self.connect_buffer = data;
        match outcome {
            Some(Ok(info)) => {
                self.close_info = Some(info.clone());
                Some(Ok(info))
            }
            Some(Err(abort)) => {
                self.abort_reason = Some(abort.clone());
                Some(Err(Error::SessionAborted(abort)))
            }
            None => None,
        }
    }

    /// 到着した双方向ストリーム、単方向ストリーム、DATAGRAM のいずれかを返す
    ///
    /// 受信種別が分からないアプリケーションで、複数の受信を同時に待つために使う。
    /// 別セッション宛てのストリームと DATAGRAM は読み捨て、このセッション宛ての
    /// ものだけを返す。
    ///
    /// ピアがセッションを終了した場合と、QUIC 接続が正常に終了した場合は
    /// [`Error::SessionClosed`] を返す。異常終了は
    /// [`Error::SessionAborted`] または [`Error::Quic`] を返す。
    /// (draft-ietf-webtrans-http3-15 Section 6)
    ///
    /// # エラー
    ///
    /// セッションの終了、または QUIC 接続の異常終了でエラーを返す。
    pub async fn receive(&mut self) -> Result<Incoming> {
        loop {
            if self.close_info.is_some() || self.abort_reason.is_some() {
                return Err(self.take_session_end());
            }
            // 受信は 3 種類と CONNECT ストリームの終了を同時に待つため、
            // `&mut self` を 1 つに絞れない。フィールドごとに分けた自由関数へ
            // 委譲し、借用を分離する。
            let connection = &self.connection;
            let session_id = self.session_id;
            let uni_rx = &mut self.uni_rx;
            let connect_recv = &mut self.connect_recv;
            let connect_buffer = &mut self.connect_buffer;
            let bidi_headers = &mut self.bidi_headers;
            let close_sent = self.close_sent;
            tokio::select! {
                accepted = accept_bidi_stream(connection, session_id, bidi_headers) => {
                    return Ok(Incoming::Bidirectional(accepted?));
                }
                accepted = accept_uni_stream(uni_rx, session_id) => {
                    return Ok(Incoming::Unidirectional(accepted?));
                }
                payload = receive_session_datagram(connection, session_id) => {
                    return Ok(Incoming::Datagram(payload?));
                }
                // CONNECT ストリームの終了はセッションの終了を意味する。
                // 読まずに放置すると、ピアのクローズを観測できない。
                received = receive_connect_end(connect_recv, connect_buffer, close_sent) => {
                    // クローズカプセルが分割されて届いた場合は、まだ判定できない
                    // ので次の受信を待つ。
                    if let Some(result) = received? {
                        match result {
                            Ok(info) => self.close_info = Some(info),
                            Err(abort) => self.abort_reason = Some(abort),
                        }
                        return Err(self.take_session_end());
                    }
                }
            }
        }
    }

    /// 観測済みのセッション終了をエラーとして取り出す
    fn take_session_end(&self) -> Error {
        match &self.abort_reason {
            Some(abort) => Error::SessionAborted(abort.clone()),
            None => Error::SessionClosed,
        }
    }

    /// セッションをクローズする
    ///
    /// `WT_CLOSE_SESSION` を DATA フレームに載せて送信し、CONNECT ストリームを
    /// FIN で閉じる。セッション終了時は両端が CONNECT ストリームを閉じる必要が
    /// ある (draft-ietf-webtrans-http3-15 Section 6)。
    ///
    /// クローズ理由は 1024 バイトを超える場合、UTF-8 の文字境界で切り詰める
    /// (draft-ietf-webtrans-http3-15 Section 6)。
    pub async fn close(&mut self, code: u32, reason: &str) -> Result<()> {
        tracing::info!(
            "WebTransport: closing session (code={}, reason={})",
            code,
            reason
        );
        // CONNECT ストリーム上のカプセルは HTTP/3 の DATA フレームのペイロードで
        // なければならない (RFC 9114 Section 7.2.1)。
        let capsule = Capsule::CloseSession {
            error_code: code,
            message: reason.to_string(),
        };
        let mut buf = Vec::new();
        capsule.encode_as_data_frame(&mut buf);
        self.connect_send
            .send(&buf)
            .await
            .map_err(Error::transport)?;
        // FIN で CONNECT ストリームを閉じ、ピアにセッションの終端を伝える。
        self.connect_send.finish().await.map_err(Error::transport)?;
        // ここから先の CONNECT ストリームのリセットは、終了への応答でありうる。
        self.close_sent = true;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ストリーム型
// ---------------------------------------------------------------------------

pub struct WtSendStream {
    stream_id: u64,
    send: SendStream,
}

impl WtSendStream {
    pub fn new(stream_id: u64, send: SendStream) -> Self {
        Self { stream_id, send }
    }

    /// データを送信する
    ///
    /// QUIC の送信はフロー制御で部分受理される。受理されたバイト数がデータ長に
    /// 満たない場合は、残りを送り終えるまで繰り返す。
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        let mut sent = 0;
        while sent < data.len() {
            let accepted = self
                .send
                .send(&data[sent..])
                .await
                .map_err(Error::transport)?;
            if accepted == 0 {
                return Err(Error::Transport(
                    "the stream accepted zero bytes".to_string(),
                ));
            }
            sent += accepted;
        }
        Ok(())
    }

    /// 送信側を終了する
    ///
    /// 送信待ちのデータが残っている場合は、すべて受理されるまで待ってから FIN を送る。
    pub async fn finish(&mut self) -> Result<()> {
        self.send.finish().await.map_err(Error::transport)
    }

    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }
}

pub struct WtRecvStream {
    stream_id: u64,
    /// このストリームが属するセッション ID
    session_id: u64,
    recv: ReceiveStream,
    pending: Vec<u8>,
}

impl WtRecvStream {
    /// 受信ストリームを作る
    ///
    /// `session_id` はこのストリームが属するセッションである。別セッション宛ての
    /// ストリームを受け入れないための照合に使う
    /// (draft-ietf-webtrans-http3-15 Section 4.2)。
    pub fn new(stream_id: u64, session_id: u64, recv: ReceiveStream, pending: Vec<u8>) -> Self {
        Self {
            stream_id,
            session_id,
            recv,
            pending,
        }
    }

    /// このストリームが属するセッション ID を返す
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        if !self.pending.is_empty() {
            return Ok(std::mem::take(&mut self.pending));
        }
        match recv_data(&mut self.recv).await {
            Ok(Some(data)) => Ok(data),
            Ok(None) => Err(Error::StreamClosed),
            Err(e) => Err(e),
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }
}

pub struct WtBiStream {
    stream_id: u64,
    /// このストリームが属するセッション ID
    session_id: u64,
    recv: ReceiveStream,
    send: SendStream,
    pending: Vec<u8>,
}

impl WtBiStream {
    /// 送信と受信のストリームから双方向ストリームを構築する
    pub fn from_parts(send: WtSendStream, recv: WtRecvStream) -> Self {
        Self {
            stream_id: send.stream_id,
            session_id: recv.session_id,
            recv: recv.recv,
            send: send.send,
            pending: recv.pending,
        }
    }

    /// 双方向ストリームを送信側と受信側に分解する
    pub fn into_parts(self) -> (WtSendStream, WtRecvStream) {
        (
            WtSendStream {
                stream_id: self.stream_id,
                send: self.send,
            },
            WtRecvStream::new(self.stream_id, self.session_id, self.recv, self.pending),
        )
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.send.send(data).await.map_err(Error::transport)?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        if !self.pending.is_empty() {
            return Ok(std::mem::take(&mut self.pending));
        }
        match recv_data(&mut self.recv).await {
            Ok(Some(data)) => Ok(data),
            Ok(None) => Err(Error::StreamClosed),
            Err(e) => Err(e),
        }
    }

    pub async fn finish(&mut self) -> Result<()> {
        self.send.finish().await.map_err(Error::transport)
    }

    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }
}

// ---------------------------------------------------------------------------
// SETTINGS パースと draft 判定
// ---------------------------------------------------------------------------

/// SETTINGS パース中間状態
enum SettingsParseState {
    NeedMoreData,
    Error(String),
}

/// H3 制御ストリームのバッファから SETTINGS をパースする
fn parse_settings_from_control(buf: &[u8]) -> std::result::Result<H3Settings, SettingsParseState> {
    // ストリームタイプバイト (0x00) をスキップする
    let (stream_type, type_len) =
        shiguredo_http3::varint::decode(buf).map_err(|_| SettingsParseState::NeedMoreData)?;
    if stream_type != VarInt::ZERO {
        return Err(SettingsParseState::Error(format!(
            "expected control stream type 0x00, got {:#x}",
            stream_type.get()
        )));
    }
    let rest = &buf[type_len..];

    // フレームタイプを読む
    let (frame_type, ft_len) =
        shiguredo_http3::varint::decode(rest).map_err(|_| SettingsParseState::NeedMoreData)?;
    if frame_type != VarInt::from_static(0x04) {
        return Err(SettingsParseState::Error(format!(
            "expected SETTINGS frame type 0x04, got {:#x}",
            frame_type.get()
        )));
    }

    // フレーム長を読む
    let (payload_len, pl_len) = shiguredo_http3::varint::decode(&rest[ft_len..])
        .map_err(|_| SettingsParseState::NeedMoreData)?;
    let payload_start = ft_len + pl_len;
    let payload_end = payload_start + payload_len.get() as usize;
    if rest.len() < payload_end {
        return Err(SettingsParseState::NeedMoreData);
    }

    // SETTINGS ペイロードをパースする
    let payload_buf = &rest[payload_start..payload_end];
    tracing::info!(
        "WebTransport: client SETTINGS payload ({} bytes): {:02x?}",
        payload_buf.len(),
        payload_buf
    );
    let mut payload = SettingsPayload::new();
    let mut pos = 0;
    while pos < payload_buf.len() {
        let (id, id_len) = shiguredo_http3::varint::decode(&payload_buf[pos..])
            .map_err(|_| SettingsParseState::Error("settings id decode error".into()))?;
        pos += id_len;
        let (value, value_len) = shiguredo_http3::varint::decode(&payload_buf[pos..])
            .map_err(|_| SettingsParseState::Error("settings value decode error".into()))?;
        pos += value_len;
        tracing::info!(
            "WebTransport: client SETTINGS entry: id=0x{:x}, value={value}",
            id.get()
        );
        let setting = Setting::from_wire(id, value)
            .map_err(|e| SettingsParseState::Error(format!("settings wire error: {e}")))?;
        payload
            .add(setting)
            .map_err(|e| SettingsParseState::Error(format!("settings add error: {e}")))?;
    }

    let settings = H3Settings::from_payload(&payload);
    tracing::info!("WebTransport: client SETTINGS parsed: {settings:?}");
    Ok(settings)
}

/// draft バージョンに合わせたサーバー WT 設定を構築する
///
/// フロー制御の初期値は draft-14 / 15 / 17 では SETTINGS で通知する。
/// draft-02 / 07 にはフロー制御の仕組みがないため、最大セッション数だけを
/// 通知する (draft-ietf-webtrans-http3-15 Section 5.1 / 5.5)。
/// draft-17 は SETTINGS_WT_ENABLED のコードポイントが draft-15 / 16 と異なる
/// (draft-ietf-webtrans-http3-17 Section 3.1)。
/// `safari_compat` を指定すると、Safari 26.4 が観測された draft-07 用の
/// 最大セッション数と draft-14 用の初期上限の併用パターンになる。
fn build_server_wt_settings(
    draft: DraftVersion,
    limits: ServerLimits,
    safari_compat: bool,
) -> shiguredo_http3::webtransport::Settings {
    tracing::info!("WebTransport: building server settings for {draft:?}");
    // SETTINGS の値は VarInt で表現できる必要がある
    let varint = |value: u64| VarInt::new(value).expect("settings value fits in VarInt");
    if safari_compat {
        // Safari 26.4 相当: draft-07 の SETTINGS ID で WebTransport を表明しつつ、
        // draft-14 用の ID で初期フロー制御の上限を広告する
        return shiguredo_http3::webtransport::Settings::new()
            .webtransport_max_sessions_draft07(varint(limits.max_sessions))
            .wt_initial_max_streams_uni(varint(limits.initial_max_streams_uni))
            .wt_initial_max_streams_bidi(varint(limits.initial_max_streams_bidi))
            .wt_initial_max_data(varint(limits.initial_max_data));
    }
    match draft {
        DraftVersion::Draft17 => shiguredo_http3::webtransport::Settings::new()
            .wt_enabled_draft17(VarInt::from_static(1))
            .wt_initial_max_streams_uni(varint(limits.initial_max_streams_uni))
            .wt_initial_max_streams_bidi(varint(limits.initial_max_streams_bidi))
            .wt_initial_max_data(varint(limits.initial_max_data)),
        DraftVersion::Draft15 => shiguredo_http3::webtransport::Settings::new()
            .wt_enabled(VarInt::from_static(1))
            .wt_initial_max_streams_uni(varint(limits.initial_max_streams_uni))
            .wt_initial_max_streams_bidi(varint(limits.initial_max_streams_bidi))
            .wt_initial_max_data(varint(limits.initial_max_data)),
        // draft-07 判定のクライアント (Safari 26.4 など) は draft-14 用の
        // SETTINGS ID を解釈しないため、draft-07 用の ID も併せて返す。
        // draft-14 のクライアントは draft-07 用の ID を無視するだけなので
        // 両方返しても問題ない。
        DraftVersion::Draft14 => shiguredo_http3::webtransport::Settings::new()
            .wt_max_sessions_draft14(varint(limits.max_sessions))
            .webtransport_max_sessions_draft07(varint(limits.max_sessions))
            .wt_initial_max_streams_uni(varint(limits.initial_max_streams_uni))
            .wt_initial_max_streams_bidi(varint(limits.initial_max_streams_bidi))
            .wt_initial_max_data(varint(limits.initial_max_data)),
        DraftVersion::Draft07 => shiguredo_http3::webtransport::Settings::new()
            .webtransport_max_sessions_draft07(varint(limits.max_sessions)),
        DraftVersion::Draft02 => {
            shiguredo_http3::webtransport::Settings::new().enable_webtransport_draft02(true)
        }
    }
}

// ---------------------------------------------------------------------------
// 単方向ストリームルーティング
// ---------------------------------------------------------------------------

/// 初期データ付きの単方向ストリームルーティング
async fn route_uni_stream_with_initial(
    stream_id: u64,
    mut recv_stream: ReceiveStream,
    initial_data: Vec<u8>,
    state: Arc<StdMutex<ServerConnectionState>>,
    notify: Arc<Notify>,
    uni_tx: mpsc::Sender<WtRecvStream>,
) {
    let mut type_buf = initial_data;

    let classified = loop {
        match classify_uni_stream_checked(&type_buf) {
            Ok(result) => break Some(result),
            Err(StreamHeaderDecodeError::BufferTooShort) => {}
            Err(e) => {
                tracing::warn!(
                    "WebTransport: uni stream {} classification error: {e:?}",
                    stream_id
                );
                return;
            }
        }
        match recv_data(&mut recv_stream).await {
            Ok(Some(data)) => type_buf.extend_from_slice(&data),
            Ok(None) => {
                let _ = state.lock().unwrap().feed_stream_only(stream_id, &[], true);
                notify.notify_one();
                return;
            }
            Err(_) => return,
        }
    };

    route_classified_stream(
        stream_id,
        recv_stream,
        type_buf,
        classified,
        state,
        notify,
        uni_tx,
    )
    .await;
}

async fn route_uni_stream(
    stream_id: u64,
    mut recv_stream: ReceiveStream,
    state: Arc<StdMutex<ServerConnectionState>>,
    notify: Arc<Notify>,
    uni_tx: mpsc::Sender<WtRecvStream>,
) {
    let mut type_buf: Vec<u8> = Vec::new();

    let classified = loop {
        match recv_data(&mut recv_stream).await {
            Ok(Some(data)) => {
                type_buf.extend_from_slice(&data);
                match classify_uni_stream_checked(&type_buf) {
                    Ok(result) => break Some(result),
                    Err(StreamHeaderDecodeError::BufferTooShort) => continue,
                    Err(e) => {
                        tracing::warn!(
                            "WebTransport: uni stream {} classification error: {e:?}",
                            stream_id
                        );
                        return;
                    }
                }
            }
            Ok(None) => {
                let _ = state.lock().unwrap().feed_stream_only(stream_id, &[], true);
                notify.notify_one();
                return;
            }
            Err(_) => return,
        }
    };

    route_classified_stream(
        stream_id,
        recv_stream,
        type_buf,
        classified,
        state,
        notify,
        uni_tx,
    )
    .await;
}

/// 分類済みストリームを処理する共通関数
async fn route_classified_stream(
    stream_id: u64,
    mut recv_stream: ReceiveStream,
    type_buf: Vec<u8>,
    classified: Option<ClassifiedUniStream>,
    state: Arc<StdMutex<ServerConnectionState>>,
    notify: Arc<Notify>,
    uni_tx: mpsc::Sender<WtRecvStream>,
) {
    match classified {
        Some(ClassifiedUniStream::WebTransport {
            session_id,
            data_offset,
        }) => {
            // 別セッション宛てのストリームは受け付けない
            // (draft-ietf-webtrans-http3-15 Section 4.2)。ブラウザーは複数の
            // セッションを同じ接続で扱うため、他セッション宛てのストリームが
            // 届いてもセッションを閉じずに破棄する。セッション ID の照合は
            // 受信側の `WtSession` が受け持つため、ここでは配送する。
            tracing::info!(
                "WebTransport: uni stream {} classified as WebTransport \
                 (session_id={}, data_offset={})",
                stream_id,
                session_id,
                data_offset
            );
            let pending = type_buf[data_offset..].to_vec();
            let wt_recv = WtRecvStream::new(stream_id, session_id, recv_stream, pending);
            let _ = uni_tx.send(wt_recv).await;
        }
        _ => {
            tracing::info!(
                "WebTransport: uni stream {} classified as H3 stream, raw: {:02x?}",
                stream_id,
                &type_buf[..std::cmp::min(type_buf.len(), 64)]
            );
            {
                let mut s = state.lock().unwrap();
                let _ = s.feed_stream_only(stream_id, &type_buf, false);
            }
            notify.notify_one();
            while let Ok(Some(data)) = recv_data(&mut recv_stream).await {
                {
                    let mut s = state.lock().unwrap();
                    let _ = s.feed_stream_only(stream_id, &data, false);
                }
                notify.notify_one();
            }
            {
                let mut s = state.lock().unwrap();
                let _ = s.feed_stream_only(stream_id, &[], true);
            }
            notify.notify_one();
        }
    }
}
