// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! tobi-http3 — tobi-quic を使った HTTP/3 のクライアント / サーバー結線。
//!
//! ALPN が `h3` の QUIC 接続を受け取り、`shiguredo_http3` の Sans I/O 実装へ
//! ストリームを対応付ける。HTTP のヘッダーとイベントは `shiguredo_http3` の型を使う。
//! 接続は 1 タスクで所有し、受信タスクとの間は上限付きチャネルで通信する。

use std::collections::HashMap;
use std::fmt;

use shiguredo_http3::{ClientConnection, Event, H3InitData, Header, ServerConnection, Settings};
use tobi_quic::{ReceiveStream, SendStream};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

#[cfg(test)]
mod tests;

pub mod io;

/// HTTP/3 と QUIC の結線で発生するエラー。
#[derive(Debug)]
pub enum Error {
    /// QUIC の接続またはストリーム操作が失敗した。
    Quic(tobi_quic::Error),
    /// HTTP/3 の状態機械がエラーを検出した。
    Http3(shiguredo_http3::Error),
    /// ALPN が h3 ではない。
    InvalidAlpn,
    /// 操作に必要なクライアント / サーバーの役割と一致しない。
    InvalidRole,
    /// QUIC と HTTP/3 が割り当てたストリーム ID が一致しない。
    StreamIdMismatch,
    /// 送信側が既に終了した、または未知のストリームを送信対象に指定した。
    UnknownStream(u64),
    /// 接続が閉じた。
    Closed(String),
    /// ピアが接続を閉じた。正常終了か障害かは [`is_graceful_close`] で判定する。
    PeerClosed(tobi_quic::ConnectionError),
    /// 受信タスクが異常終了した。
    Reader(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quic(error) => write!(formatter, "QUIC error: {error}"),
            Self::Http3(error) => write!(formatter, "HTTP/3 error: {error}"),
            Self::InvalidAlpn => formatter.write_str("expected h3 ALPN"),
            Self::InvalidRole => {
                formatter.write_str("HTTP/3 operation does not match the connection role")
            }
            Self::StreamIdMismatch => formatter.write_str("QUIC and HTTP/3 stream IDs differ"),
            Self::UnknownStream(id) => write!(formatter, "unknown or finished send stream: {id}"),
            Self::Closed(reason) => write!(formatter, "HTTP/3 connection closed: {reason}"),
            Self::PeerClosed(reason) => write!(formatter, "HTTP/3 peer closed: {reason}"),
            Self::Reader(reason) => write!(formatter, "HTTP/3 stream reader failed: {reason}"),
        }
    }
}

/// QUIC の接続終了を、ピアによる終了かその他のエラーかに分ける。
fn connection_error(error: tobi_quic::Error) -> Error {
    match error {
        tobi_quic::Error::Connection(reason) => Error::PeerClosed(reason),
        error => Error::Quic(error),
    }
}

/// ピアが正常終了として接続を閉じたかを返す。
///
/// HTTP/3 は H3_NO_ERROR (0x100)、QUIC のトランスポートは error code 0 を
/// 正常終了に使う。それ以外の終了は接続の失敗として扱う。
pub fn is_graceful_close(reason: &tobi_quic::ConnectionError) -> bool {
    matches!(
        reason,
        tobi_quic::ConnectionError::Closed
            | tobi_quic::ConnectionError::Application { code: 0x100, .. }
    )
}

impl std::error::Error for Error {}
impl From<tobi_quic::Error> for Error {
    fn from(error: tobi_quic::Error) -> Self {
        Self::Quic(error)
    }
}
impl From<shiguredo_http3::Error> for Error {
    fn from(error: shiguredo_http3::Error) -> Self {
        Self::Http3(error)
    }
}

/// 接続の役割に応じた Sans I/O の状態機械。
enum Protocol {
    Client(ClientConnection),
    Server(ServerConnection),
}

impl Protocol {
    fn init(&mut self, ids: [u64; 3]) -> Result<H3InitData, Error> {
        Ok(match self {
            Self::Client(state) => state.init_h3_streams(ids[0], ids[1], ids[2])?,
            Self::Server(state) => state.init_h3_streams(ids[0], ids[1], ids[2])?,
        })
    }

    fn feed(&mut self, input: io::ReadEvent) -> Result<(), Error> {
        let (id, data, fin) = match input {
            io::ReadEvent::Data { stream_id, data } => (stream_id, data, false),
            io::ReadEvent::Fin { stream_id } => (stream_id, Vec::new(), true),
            io::ReadEvent::Reset {
                stream_id,
                error_code,
                final_size,
            } => {
                match self {
                    Self::Client(state) => state.stream_reset(stream_id, error_code, final_size)?,
                    Self::Server(state) => state.stream_reset(stream_id, error_code, final_size)?,
                }
                return Ok(());
            }
            io::ReadEvent::ConnectionClosed { reason, .. } => {
                return Err(Error::PeerClosed(reason));
            }
            io::ReadEvent::Failed { message, .. } => return Err(Error::Reader(message)),
        };
        match self {
            Self::Client(state) => state.feed_stream(id, &data, fin)?,
            Self::Server(state) => state.feed_stream(id, &data, fin)?,
        }
        Ok(())
    }

    fn event(&mut self) -> Result<Option<Event>, Error> {
        Ok(match self {
            Self::Client(state) => state.poll_event()?,
            Self::Server(state) => state.poll_event()?,
        })
    }

    fn writable(&self) -> Vec<u64> {
        match self {
            Self::Client(state) => state.writable_streams().collect(),
            Self::Server(state) => state.writable_streams().collect(),
        }
    }

    fn take_data(&mut self, id: u64) -> Option<(Vec<u8>, bool)> {
        let (mut data, mut fin) = self.take_chunk(id)?;
        // Sans I/O は全データを交付した次の呼び出しで空の FIN を返す。
        // 既に生成済みの終端を取り出し、QUIC の最後のデータと一緒に渡す。
        if !fin && let Some((remaining, final_fin)) = self.take_chunk(id) {
            data.extend_from_slice(&remaining);
            fin = final_fin;
        }
        Some((data, fin))
    }

    fn take_chunk(&mut self, id: u64) -> Option<(Vec<u8>, bool)> {
        match self {
            Self::Client(state) => state.take_stream_data(id),
            Self::Server(state) => state.take_stream_data(id),
        }
    }
}

/// キャンセル後も未送信データを保持する。
struct PendingSend {
    id: u64,
    data: Vec<u8>,
    fin: bool,
}

/// HTTP/3 の接続。
///
/// 要求 / 応答をキューへ追加し、[`Self::next_event`] で送受信を進める。
/// ボディはイベント単位で受け取るため、アプリケーションでサイズ上限を管理できる。
/// ドロップすると受信タスクを中止する。QUIC の終了は [`Self::close`] で明示する。
pub struct Connection {
    quic: tobi_quic::Connection,
    protocol: Protocol,
    outgoing: HashMap<u64, mpsc::Sender<PendingSend>>,
    input: mpsc::Receiver<io::ReadEvent>,
    sender: mpsc::Sender<io::ReadEvent>,
    readers: HashMap<u64, tokio::task::JoinHandle<()>>,
    writers: JoinSet<()>,
    pending: Option<PendingSend>,
}

impl Connection {
    /// 確立済みの QUIC 接続を HTTP/3 クライアントとして初期化する。
    ///
    /// この接続で HTTP/3 の要求ストリームをまだ開いていないことを前提とする。
    /// ALPN が h3 でない場合や、初期制御ストリームを開けない場合はエラーを返す。
    pub async fn client(quic: tobi_quic::Connection, settings: Settings) -> Result<Self, Error> {
        Self::start(quic, Protocol::Client(ClientConnection::new(settings))).await
    }

    /// 受理済みの QUIC 接続を HTTP/3 サーバーとして初期化する。
    ///
    /// ALPN が h3 でない場合や、初期制御ストリームを開けない場合はエラーを返す。
    pub async fn server(quic: tobi_quic::Connection, settings: Settings) -> Result<Self, Error> {
        Self::start(quic, Protocol::Server(ServerConnection::new(settings))).await
    }

    async fn start(quic: tobi_quic::Connection, mut protocol: Protocol) -> Result<Self, Error> {
        if quic.application_protocol().await.as_deref() != Some(b"h3") {
            return Err(Error::InvalidAlpn);
        }
        let mut streams = io::ControlStreams::open(&quic).await?;
        let ids = streams.ids();
        let init = protocol.init(ids)?;
        streams.send_initial(&init).await?;
        let (sender, input) = mpsc::channel(16);
        let mut connection = Self {
            quic,
            protocol,
            outgoing: HashMap::new(),
            input,
            sender,
            readers: HashMap::new(),
            writers: JoinSet::new(),
            pending: None,
        };
        for stream in streams.into_streams() {
            connection.write_stream(stream);
        }
        Ok(connection)
    }

    /// 要求ヘッダーを送信キューへ追加し、QUIC ストリーム ID を返す。
    ///
    /// ボディを送る場合は fin を false にし、続けて [`Self::send_body`] を使う。
    /// サーバー接続で呼んだ場合や、ヘッダーが不正な場合はエラーを返す。
    /// 送信は [`Self::next_event`] の呼び出しで進む。
    /// QUIC のストリーム開設を伴うため、この操作はキャンセルせず完了まで待つこと。
    pub async fn send_request(&mut self, headers: &[Header], fin: bool) -> Result<u64, Error> {
        let Protocol::Client(state) = &mut self.protocol else {
            return Err(Error::InvalidRole);
        };
        let id = state.send_request(headers, fin)?;
        let stream = self.quic.open_bidirectional_stream_wait().await?;
        if stream.id() != id {
            return Err(Error::StreamIdMismatch);
        }
        let (send, recv) = stream.split();
        self.write_stream(send);
        self.read_stream(recv);
        Ok(id)
    }

    /// 受信した要求の応答ヘッダーを送信キューへ追加する。
    ///
    /// クライアント接続で呼んだ場合や、要求 ID / ヘッダーが不正な場合はエラーを返す。
    /// 送信は [`Self::next_event`] の呼び出しで進む。
    pub fn send_response(&mut self, id: u64, headers: &[Header], fin: bool) -> Result<(), Error> {
        let Protocol::Server(state) = &mut self.protocol else {
            return Err(Error::InvalidRole);
        };
        state.send_response(id, headers, fin)?;
        Ok(())
    }

    /// 指定した要求 / 応答のボディを送信キューへ追加する。
    ///
    /// 一度に保持するボディ量は呼び出し側で管理する。終了済みや未知の ID はエラーになる。
    /// fin が true ならボディの後に FIN を送る。送信は [`Self::next_event`] で進む。
    pub fn send_body(&mut self, id: u64, data: &[u8], fin: bool) -> Result<(), Error> {
        match &mut self.protocol {
            Protocol::Client(state) => state.send_body(id, data, fin)?,
            Protocol::Server(state) => state.send_body(id, data, fin)?,
        }
        Ok(())
    }

    /// 送受信を進め、次の HTTP/3 イベントを返す。
    ///
    /// 制御 / QPACK / 要求の各ストリームを並行して受信する。切断や不正な HTTP/3 は
    /// エラーを返す。待機をキャンセルしても受信済みの入力はチャネルに残る。
    pub async fn next_event(&mut self) -> Result<Event, Error> {
        loop {
            while let Some(completed) = self.writers.try_join_next() {
                completed.map_err(|error| Error::Reader(error.to_string()))?;
            }
            match self.protocol.event() {
                Ok(Some(event)) => return Ok(event),
                Ok(None) => {}
                Err(error) => return Err(self.close_on_connection_error(error).await),
            }
            if self.pending.is_none() {
                self.pending = self.protocol.writable().into_iter().find_map(|id| {
                    self.protocol
                        .take_data(id)
                        .map(|(data, fin)| PendingSend { id, data, fin })
                });
            }
            let has_pending = self.pending.is_some();
            tokio::select! {
                result = queue_pending(&mut self.pending, &mut self.outgoing), if has_pending => result?,
                Some(input) = self.input.recv() => {
                    match &input {
                        io::ReadEvent::Fin { stream_id }
                        | io::ReadEvent::Reset { stream_id, .. }
                        | io::ReadEvent::ConnectionClosed { stream_id, .. }
                        | io::ReadEvent::Failed { stream_id, .. } => {
                            self.readers.remove(stream_id);
                        }
                        _ => {},
                    }
                    match self.protocol.feed(input) {
                        Ok(()) => {}
                        Err(error) => {
                            return Err(self.close_on_connection_error(error).await);
                        }
                    }
                }
                // 接続終了と受理のどちらが先に観測されても、同じ終了として扱う。
                stream = self.quic.accept_receive_stream() => {
                    match stream {
                        Ok(stream) => self.read_stream(stream),
                        Err(error) => return Err(connection_error(error)),
                    }
                }
                stream = self.quic.accept_bidirectional_stream() => {
                    match stream {
                        Ok(stream) => {
                            let (send, recv) = stream.split();
                            self.write_stream(send);
                            self.read_stream(recv);
                        }
                        Err(error) => return Err(connection_error(error)),
                    }
                }
                reason = self.quic.closed() => {
                    // driver が理由を残さずに停止した場合も、切断として扱う。
                    let reason = reason.unwrap_or(tobi_quic::ConnectionError::Closed);
                    return Err(Error::PeerClosed(reason));
                }
            }
        }
    }

    /// HTTP/3 の接続エラーを検出したら、QUIC の CONNECTION_CLOSE で対向へ通知する。
    ///
    /// RFC 9114 Section 8 は接続エラーを CONNECTION_CLOSE で閉じることを要求する。
    /// 通知しないと対向は接続の終了を待ち続け、Interop Test Runner の http3 は
    /// タイムアウトする。
    async fn close_on_connection_error(&mut self, error: Error) -> Error {
        if let Error::Http3(shiguredo_http3::Error::ConnectionError(code)) = &error {
            let reason = code.to_string();
            // 対向が既に閉じている場合など、通知できないこと自体は新しい誤りではない。
            let _ = self.close(code.code(), reason.as_bytes()).await;
        }
        error
    }

    /// HTTP/3 のアプリケーションエラーコードで QUIC 接続を閉じる。
    pub async fn close(&mut self, code: u64, reason: &[u8]) -> Result<(), Error> {
        for task in self.readers.values() {
            task.abort();
        }
        self.writers.abort_all();
        self.quic.close_application(code, reason).await?;
        Ok(())
    }

    fn read_stream(&mut self, recv: ReceiveStream) {
        let id = recv.id();
        // 読み取り中断は H3_REQUEST_CANCELLED として通知する。
        self.readers
            .insert(id, io::spawn_reader(recv, self.sender.clone(), 0x10c));
    }

    /// QUIC の send はキャンセルせず、専用タスクで部分書き込みを完了させる。
    fn write_stream(&mut self, mut stream: SendStream) {
        let (sender, mut receiver) = mpsc::channel::<PendingSend>(8);
        self.outgoing.insert(stream.id(), sender);
        let errors = self.sender.clone();
        self.writers.spawn(async move {
            while let Some(input) = receiver.recv().await {
                let result = if input.fin {
                    io::write_all_fin(&mut stream, &input.data).await
                } else {
                    io::write_all(&mut stream, &input.data).await
                };
                if let Err(error) = result {
                    let _ = errors
                        .send(io::ReadEvent::Failed {
                            stream_id: input.id,
                            message: error.to_string(),
                        })
                        .await;
                    return;
                }
                if input.fin {
                    return;
                }
            }
        });
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        for task in self.readers.values() {
            task.abort();
        }
    }
}

/// キューの空きを待つ reserve はキャンセルしてもバイト列を消費しない。
async fn queue_pending(
    pending: &mut Option<PendingSend>,
    outgoing: &mut HashMap<u64, mpsc::Sender<PendingSend>>,
) -> Result<(), Error> {
    let Some(item) = pending.as_ref() else {
        return Ok(());
    };
    let sender = outgoing
        .get(&item.id)
        .ok_or(Error::UnknownStream(item.id))?
        .clone();
    let permit = sender
        .reserve_owned()
        .await
        .map_err(|_| Error::Closed("send stream worker stopped".into()))?;
    if let Some(item) = pending.take() {
        if item.fin {
            outgoing.remove(&item.id);
        }
        permit.send(item);
    }
    Ok(())
}
