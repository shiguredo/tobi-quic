// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! WebTransport セッションの公開 API
//!
//! セッションの開設後にアプリケーションが使う操作を提供する。
//! ストリームとデータグラムの実体は結線側のドライバータスクが管理し、
//! このモジュールはチャネル経由で操作を依頼する。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use shiguredo_http3::webtransport::connect::DraftVersion;
use tokio::sync::{mpsc, oneshot, watch};

use crate::error::Error;
use crate::stream::{WtBidirectionalStream, WtReceiveStream, WtSendStream};

/// セッションのクローズ情報
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseInfo {
    /// アプリケーションが指定したクローズコード
    ///
    /// ピアが WT_CLOSE_SESSION を送らずに CONNECT ストリームを正常に閉じた
    /// 場合は 0 になる。これはクローズコード 0・理由が空の WT_CLOSE_SESSION と
    /// 等価である (draft-ietf-webtrans-http3-15 Section 6)。
    pub error_code: u32,
    /// アプリケーションが指定したクローズ理由
    pub message: String,
    /// セッション終了時に使われたトランスポート側のエラーコード
    ///
    /// ピアが終了した場合は `WT_SESSION_GONE`、ローカルから終了した場合は
    /// `None` になる。`WT_SESSION_GONE` 以外の値はセッションエラーであり、
    /// その場合は [`Session::wait_closed`] が [`Error::SessionAborted`] を
    /// 返すため、このフィールドには現れない。
    /// (draft-ietf-webtrans-http3-15 Section 9.5)
    pub transport_error_code: Option<u64>,
}

/// セッションの受信と並行して使える DATAGRAM 送信ハンドル。
///
/// 複製したハンドルも同じセッションへ送る。ハンドルを保持している間は
/// ドライバーへのコマンド送信口が残るため、[`Session`] をドロップしても
/// クローズコード 0 の終了は始まらない。すべての [`Session`] と
/// [`DatagramSender`] をドロップすると終了する。明示的な
/// [`Session::close`] はハンドルを保持していても実行できる。
#[derive(Clone)]
pub struct DatagramSender {
    commands: mpsc::Sender<Command>,
}

impl DatagramSender {
    /// DATAGRAM を送信する。対応範囲、サイズ、終了状態の検証は
    /// [`Session::send_datagram`] と同じで、送信待ちにも同じ上限を適用する。
    pub async fn send(&self, payload: &[u8]) -> Result<(), Error> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::SendDatagram {
                payload: payload.to_vec(),
                reply,
            })
            .await
            .map_err(|_| Error::SessionClosed)?;
        response.await.map_err(|_| Error::DriverStopped)?
    }
}

/// セッションの終了状態
#[derive(Debug, Clone)]
pub(crate) enum SessionEnd {
    /// 正常にクローズした
    Closed(CloseInfo),
    /// 異常終了した
    Aborted {
        /// セッション終了時のトランスポート側エラーコード
        transport_error_code: u64,
        /// CONNECT ストリームの RESET_STREAM で通知されたエラーコード
        connect_stream_error_code: Option<u64>,
    },
    /// ドライバーでエラーが発生した
    Failed(String),
    /// QUIC 接続が終了した。文字列に変換せず種別を保持する。
    TransportClosed(tobi_quic::ConnectionError),
}

impl SessionEnd {
    /// 公開 API の終了結果へ変換する
    ///
    /// 正常終了だけを `Ok` とし、異常終了は原因を保持したままエラーへ写す。
    fn into_result(self) -> Result<CloseInfo, Error> {
        match self {
            Self::Closed(info) => Ok(info),
            Self::Aborted {
                transport_error_code,
                connect_stream_error_code,
            } => Err(Error::SessionAborted {
                transport_error_code,
                connect_stream_error_code,
            }),
            Self::Failed(message) => Err(Error::DriverFailed(message)),
            Self::TransportClosed(reason) => Err(Error::Quic(tobi_quic::Error::Connection(reason))),
        }
    }
}

/// セッションへの操作依頼
pub(crate) enum Command {
    /// 双方向ストリームを開く
    OpenBidirectional {
        /// 開設結果の通知先
        reply: oneshot::Sender<Result<WtBidirectionalStream, Error>>,
    },
    /// 単方向ストリームを開く
    OpenUnidirectional {
        /// 開設結果の通知先
        reply: oneshot::Sender<Result<WtSendStream, Error>>,
    },
    /// データグラムを送信する
    SendDatagram {
        /// 送信するペイロード
        payload: Vec<u8>,
        /// 送信結果の通知先
        reply: oneshot::Sender<Result<(), Error>>,
    },
    /// セッションをクローズする
    Close {
        /// アプリケーションのクローズコード
        error_code: u32,
        /// アプリケーションのクローズ理由
        message: String,
        /// クローズ結果の通知先
        reply: oneshot::Sender<Result<(), Error>>,
    },
}

/// セッションを構築するための構成要素
pub(crate) struct SessionParts {
    pub(crate) session_id: u64,
    pub(crate) requested_draft: DraftVersion,
    pub(crate) settings_draft: DraftVersion,
    pub(crate) protocol: Option<String>,
    pub(crate) flow_control_enabled: bool,
    pub(crate) commands: mpsc::Sender<Command>,
    pub(crate) incoming_bidi: mpsc::Receiver<WtBidirectionalStream>,
    pub(crate) incoming_uni: mpsc::Receiver<WtReceiveStream>,
    pub(crate) datagrams: mpsc::Receiver<Vec<u8>>,
    pub(crate) end: watch::Receiver<Option<SessionEnd>>,
    pub(crate) draining: Arc<AtomicBool>,
}

/// WebTransport セッション
///
/// サーバーとの間で確立した 1 つの WebTransport セッションを表す。
/// ストリームの送受信とデータグラムの送受信、セッションのクローズを行う。
///
/// セッションの終了は、このオブジェクトの [`Session::close`] か、
/// [`Session::wait_closed`] で待つ。[`Session`] とすべての
/// [`DatagramSender`] をドロップした場合も、ドライバーがクローズコード 0 で
/// 終了処理を行う。
///
/// # 受信系の分離
///
/// [`Session::split_receivers`] で受信系を [`SessionReceivers`] として分離
/// できる。分離後もこのオブジェクトはストリームの開設、DATAGRAM の送信、
/// クローズ、セッション終了の待機を続けられる。accept 系 /
/// [`Session::receive`] / [`Session::receive_datagram`] は受信系を保持して
/// いないため [`Error::SessionClosed`] を返す。
///
/// # 待機について
///
/// ストリームを開く操作は、WT ヘッダーを QUIC ストリームへ書き込む際に
/// 接続のフロー制御待ちになることがある。この間は同じセッションの他の操作も
/// 待機する。[`Session::close`] と [`Session::send_datagram`] もドライバー
/// 経由で実行されるため、ドライバーが接続のフロー制御待ちで滞留している間は
/// 完了しない。アプリケーションのペイロード送信 ([`WtSendStream::send`]) は
/// ドライバーを経由しないため、この待機の影響を受けない。
/// 受信系を分離しても、ドライバーがコマンドと受信配送を直列に処理する性質は
/// 変わらない。
pub struct Session {
    session_id: u64,
    requested_draft: DraftVersion,
    settings_draft: DraftVersion,
    protocol: Option<String>,
    flow_control_enabled: bool,
    commands: mpsc::Sender<Command>,
    incoming_bidi: Option<mpsc::Receiver<WtBidirectionalStream>>,
    incoming_uni: Option<mpsc::Receiver<WtReceiveStream>>,
    datagrams: Option<mpsc::Receiver<Vec<u8>>>,
    end: watch::Receiver<Option<SessionEnd>>,
    draining: Arc<AtomicBool>,
}

/// セッションへ到着したデータまたはピアが開始したストリーム。
pub enum Incoming {
    /// ピアが開始した双方向ストリーム。
    BidirectionalStream(WtBidirectionalStream),
    /// ピアが開始した単方向ストリーム。
    UnidirectionalStream(WtReceiveStream),
    /// このセッション宛ての DATAGRAM のペイロード。
    Datagram(Vec<u8>),
}

/// セッションから分離した受信系
///
/// [`Session::split_receivers`] で取得し、受信タスクへ move して使う。
/// このハンドルはピア開始ストリーム、DATAGRAM、セッション終了の監視を
/// 受け持つ。ストリームの開設、DATAGRAM の送信、クローズは分離後の
/// [`Session`] で引き続き行える。
///
/// このハンドルをドロップすると、以降のピア開始ストリームはドライバーが
/// `WT_BUFFERED_STREAM_REJECTED` での拒否を試み、DATAGRAM は破棄される
/// (draft-ietf-webtrans-http3-15 Section 4.6 / 9.5)。ドロップに伴う
/// RESET_STREAM / STOP_SENDING と競合するため、ピアが観測するコードや
/// 送信側の終了状態は一意でない。セッションの寿命は延ばさない。
pub struct SessionReceivers {
    incoming_bidi: mpsc::Receiver<WtBidirectionalStream>,
    incoming_uni: mpsc::Receiver<WtReceiveStream>,
    datagrams: mpsc::Receiver<Vec<u8>>,
    end: watch::Receiver<Option<SessionEnd>>,
}

impl SessionReceivers {
    /// セッションが終了するまで待つ
    ///
    /// 戻り値とエラーの分類は [`Session::wait_closed`] と同じである。
    /// この future をキャンセルしても終了状態は失われない。再度呼ぶと
    /// 現在の状態から判定する。
    pub async fn wait_closed(&mut self) -> Result<CloseInfo, Error> {
        wait_closed_impl(&mut self.end).await
    }

    /// 個々の受信チャネルと終了監視ハンドルに分解する
    ///
    /// 複数の受信を同時に待つ場合は、取り出した各チャネルを
    /// `tokio::select!` の別々の分岐へ置く。
    pub fn into_parts(self) -> SessionReceiverParts {
        SessionReceiverParts {
            bidirectional: self.incoming_bidi,
            unidirectional: self.incoming_uni,
            datagrams: self.datagrams,
            closed: SessionClosedWatcher { end: self.end },
        }
    }
}

/// [`SessionReceivers::into_parts`] で取り出した受信チャネル
pub struct SessionReceiverParts {
    /// ピアが開始した双方向ストリームを受信する
    ///
    /// このチャネルをドロップすると、以降のピア開始双方向ストリームは
    /// ドライバーが `WT_BUFFERED_STREAM_REJECTED` での拒否を試みる
    /// (draft-ietf-webtrans-http3-15 Section 4.6 / 9.5)。
    pub bidirectional: mpsc::Receiver<WtBidirectionalStream>,
    /// ピアが開始した単方向ストリームを受信する
    ///
    /// このチャネルをドロップすると、以降のピア開始単方向ストリームは
    /// ドライバーが `WT_BUFFERED_STREAM_REJECTED` での拒否を試みる
    /// (draft-ietf-webtrans-http3-15 Section 4.6 / 9.5)。
    pub unidirectional: mpsc::Receiver<WtReceiveStream>,
    /// このセッション宛ての DATAGRAM を受信する
    ///
    /// このチャネルをドロップすると、受信した DATAGRAM は破棄される。
    pub datagrams: mpsc::Receiver<Vec<u8>>,
    /// セッションの終了を監視する
    pub closed: SessionClosedWatcher,
}

/// セッションの終了だけを待つハンドル
///
/// [`SessionReceivers::into_parts`] で取得する。ストリームと DATAGRAM の
/// 受信とは独立して、セッションの終了を待てる。
pub struct SessionClosedWatcher {
    end: watch::Receiver<Option<SessionEnd>>,
}

impl SessionClosedWatcher {
    /// セッションが終了するまで待つ
    ///
    /// 戻り値とエラーの分類は [`Session::wait_closed`] と同じである。
    /// 現在値を先に確認し、未終了なら通知を待つため、生成時点で既に
    /// 終了している場合も取りこぼさない。この future をキャンセルしても
    /// 終了状態は失われず、再度呼ぶと現在の状態から判定する。
    pub async fn wait_closed(&mut self) -> Result<CloseInfo, Error> {
        wait_closed_impl(&mut self.end).await
    }
}

/// セッション終了待機の共通処理
///
/// `end` に終了状態が入っていれば即座に返し、まだなら通知を待つ。
async fn wait_closed_impl(
    end: &mut watch::Receiver<Option<SessionEnd>>,
) -> Result<CloseInfo, Error> {
    loop {
        if let Some(state) = end.borrow().clone() {
            return state.into_result();
        }
        if end.changed().await.is_err() {
            return Err(Error::SessionClosed);
        }
    }
}

impl Session {
    pub(crate) fn new(parts: SessionParts) -> Self {
        Self {
            session_id: parts.session_id,
            requested_draft: parts.requested_draft,
            settings_draft: parts.settings_draft,
            protocol: parts.protocol,
            flow_control_enabled: parts.flow_control_enabled,
            commands: parts.commands,
            incoming_bidi: Some(parts.incoming_bidi),
            incoming_uni: Some(parts.incoming_uni),
            datagrams: Some(parts.datagrams),
            end: parts.end,
            draining: parts.draining,
        }
    }

    /// セッション ID (CONNECT ストリームの QUIC ストリーム ID) を返す
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// クライアントが SETTINGS で指定した draft を返す
    pub fn requested_draft(&self) -> DraftVersion {
        self.requested_draft
    }

    /// サーバーの SETTINGS から判定した draft を返す
    ///
    /// この値はサーバーが通知した SETTINGS のパターンから判定したもので、
    /// 使用する `:protocol` の値が決まる。draft-14 のサーバーは draft-07 の
    /// SETTINGS ID も返すため、draft-14 を指定した場合は draft-07 になることが
    /// ある。`:protocol` の値は draft-07 と draft-14 で同じ `webtransport` である。
    pub fn settings_draft(&self) -> DraftVersion {
        self.settings_draft
    }

    /// サーバーが選択したアプリケーションプロトコルを返す
    ///
    /// CONNECT 応答の `:protocol` ヘッダーの値である。サーバーが
    /// `:protocol` を返さなかった場合は `None` になる。
    /// (draft-ietf-webtrans-http3-15 Section 3.3)
    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    /// WebTransport のフロー制御が有効かを返す
    ///
    /// 両端が 0 でないフロー制御の初期値を宣言した場合だけ `true` になる。
    /// (draft-ietf-webtrans-http3-15 Section 5.1)
    pub fn flow_control_enabled(&self) -> bool {
        self.flow_control_enabled
    }

    /// ピアがセッションの終了準備 (WT_DRAIN_SESSION) を通知したかを返す
    ///
    /// (draft-ietf-webtrans-http3-15 Section 4.7)
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// 双方向ストリームを開く
    ///
    /// ストリーム先頭の WT ヘッダーは結線側が送信する。ピアが通知した
    /// WT_MAX_STREAMS の上限に達している場合は [`Error::StreamsBlocked`] を
    /// 返す。ピアが上限を増やすと開設できるようになるため、待ってから
    /// 呼び直すこと (draft-ietf-webtrans-http3-15 Section 5.3)。
    ///
    /// # エラー
    ///
    /// セッションが終了している場合、ピアが WT_DRAIN_SESSION を通知している
    /// 場合、ピアのストリーム数上限に達している場合はエラーを返す。
    pub async fn open_bidirectional_stream(&self) -> Result<WtBidirectionalStream, Error> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::OpenBidirectional { reply })
            .await
            .map_err(|_| Error::SessionClosed)?;
        response.await.map_err(|_| Error::DriverStopped)?
    }

    /// 単方向ストリームを開く
    ///
    /// ストリーム先頭の WT ヘッダーは結線側が送信する。ピアが通知した
    /// WT_MAX_STREAMS の上限に達している場合は [`Error::StreamsBlocked`] を
    /// 返す (draft-ietf-webtrans-http3-15 Section 5.3)。
    ///
    /// # エラー
    ///
    /// セッションが終了している場合、ピアが WT_DRAIN_SESSION を通知している
    /// 場合、ピアのストリーム数上限に達している場合はエラーを返す。
    pub async fn open_unidirectional_stream(&self) -> Result<WtSendStream, Error> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::OpenUnidirectional { reply })
            .await
            .map_err(|_| Error::SessionClosed)?;
        response.await.map_err(|_| Error::DriverStopped)?
    }

    /// 受信系を分離し、受信と送信の操作を並行して行えるようにする
    ///
    /// 戻り値の [`SessionReceivers`] はピア開始ストリームと DATAGRAM の受信、
    /// およびセッション終了の監視を受け持つ。分離後の [`Session`] はストリーム
    /// の開設、DATAGRAM の送信、クローズ、セッション終了の待機を引き続き
    /// 行える。一方、accept 系 / [`Session::receive`] /
    /// [`Session::receive_datagram`] は受信系を保持していないため
    /// [`Error::SessionClosed`] を返す。
    ///
    /// 受信側を別タスクへ move することで、受信待ちでストリームの開設が
    /// 詰まらない。複数の受信を同時に待つ場合は
    /// [`SessionReceivers::into_parts`] を使う。
    ///
    /// このメソッドは 1 回だけ呼べる。分割後の [`Session`] で再度呼ぶのは
    /// 呼び出し側の論理エラーである。
    ///
    /// # Panics
    ///
    /// 分割済みの [`Session`] で呼ぶとパニックする。
    pub fn split_receivers(mut self) -> (Session, SessionReceivers) {
        // 3 つの受信チャネルは同時に take する。2 回目の呼び出しでは最初の
        // take が None になり、ここでパニックする。
        let receivers = SessionReceivers {
            incoming_bidi: self
                .incoming_bidi
                .take()
                .expect("receivers are separated only once"),
            incoming_uni: self
                .incoming_uni
                .take()
                .expect("receivers are separated only once"),
            datagrams: self
                .datagrams
                .take()
                .expect("receivers are separated only once"),
            // 終了監視は clone して Session 側にも残す。分離後も
            // Session::wait_closed を維持するためである。
            end: self.end.clone(),
        };
        (self, receivers)
    }

    /// サーバーが開始した双方向ストリームを受け付ける
    ///
    /// [`Session::split_receivers`] で受信系を分離した後は、このメソッドでは
    /// 受信できないため [`Error::SessionClosed`] を返す。
    ///
    /// # エラー
    ///
    /// セッションが終了している場合は [`Error::SessionClosed`] を返す。
    pub async fn accept_bidirectional_stream(&mut self) -> Result<WtBidirectionalStream, Error> {
        let receivers = self.incoming_bidi.as_mut().ok_or(Error::SessionClosed)?;
        receivers.recv().await.ok_or(Error::SessionClosed)
    }

    /// サーバーが開始した単方向ストリームを受け付ける
    ///
    /// [`Session::split_receivers`] で受信系を分離した後は、このメソッドでは
    /// 受信できないため [`Error::SessionClosed`] を返す。
    ///
    /// # エラー
    ///
    /// セッションが終了している場合は [`Error::SessionClosed`] を返す。
    pub async fn accept_unidirectional_stream(&mut self) -> Result<WtReceiveStream, Error> {
        let receivers = self.incoming_uni.as_mut().ok_or(Error::SessionClosed)?;
        receivers.recv().await.ok_or(Error::SessionClosed)
    }

    /// 到着した双方向ストリーム、単方向ストリーム、DATAGRAM のいずれかを返す。
    ///
    /// 受信種別が分からないアプリケーションで、複数の受信を同時に待つために使う。
    /// キャンセルしても未受信の項目はキューへ残る。すべての受信キューが閉じた場合は
    /// [`Error::SessionClosed`] を返す。
    ///
    /// [`Session::split_receivers`] で受信系を分離した後は、このメソッドでは
    /// 受信できないため [`Error::SessionClosed`] を返す。
    pub async fn receive(&mut self) -> Result<Incoming, Error> {
        if let Some(incoming_bidi) = self.incoming_bidi.as_mut()
            && let Some(incoming_uni) = self.incoming_uni.as_mut()
            && let Some(datagrams) = self.datagrams.as_mut()
        {
            return tokio::select! {
                Some(stream) = incoming_bidi.recv() => Ok(Incoming::BidirectionalStream(stream)),
                Some(stream) = incoming_uni.recv() => Ok(Incoming::UnidirectionalStream(stream)),
                Some(data) = datagrams.recv() => Ok(Incoming::Datagram(data)),
                else => Err(Error::SessionClosed),
            };
        }
        Err(Error::SessionClosed)
    }

    /// データグラムを送信する
    ///
    /// HTTP Datagram にエンコードした後のサイズが
    /// `Connection::max_datagram_size` を超える場合はエラーを返す。
    /// ドライバーが接続のフロー制御待ちで滞留している間は完了しない。
    ///
    /// # エラー
    ///
    /// セッションが終了している場合、ピアが WT_DRAIN_SESSION を通知している
    /// 場合、ピアが DATAGRAM に対応していない場合、サイズが上限を超える場合は
    /// エラーを返す。
    pub async fn send_datagram(&self, payload: &[u8]) -> Result<(), Error> {
        self.datagram_sender().send(payload).await
    }

    /// セッションの受信を待つタスクとは別のタスクから送るハンドルを取得する。
    ///
    /// 返したハンドルを保持している間は、[`Session`] をドロップしても
    /// セッションは終了しない。
    pub fn datagram_sender(&self) -> DatagramSender {
        DatagramSender {
            commands: self.commands.clone(),
        }
    }

    /// データグラムを 1 件受信する
    ///
    /// このセッション宛てのデータグラムだけが返る。DATAGRAM は再送されない
    /// ため、受信キューが満杯の場合は破棄される。破棄されたデータグラムは
    /// この API からは観測できない (RFC 9221 Section 5.3)。
    ///
    /// [`Session::split_receivers`] で受信系を分離した後は、このメソッドでは
    /// 受信できないため [`Error::SessionClosed`] を返す。
    ///
    /// # エラー
    ///
    /// セッションが終了している場合は [`Error::SessionClosed`] を返す。
    pub async fn receive_datagram(&mut self) -> Result<Vec<u8>, Error> {
        let receivers = self.datagrams.as_mut().ok_or(Error::SessionClosed)?;
        receivers.recv().await.ok_or(Error::SessionClosed)
    }

    /// セッションをクローズする
    ///
    /// WT_CLOSE_SESSION カプセルを送信して CONNECT ストリームを FIN で閉じ、
    /// 関連するストリームを WT_SESSION_GONE でリセットする。ピアが CONNECT
    /// ストリームを閉じるのを待ってから、QUIC 接続をアプリケーションエラー
    /// (H3_NO_ERROR) で閉じる (draft-ietf-webtrans-http3-15 Section 6)。
    /// ドライバーが接続のフロー制御待ちで滞留している間は完了しない。
    ///
    /// ピアが CONNECT ストリームの送信側に STOP_SENDING を送っている場合は、
    /// transport が RESET_STREAM を送っており WT_CLOSE_SESSION / FIN を送れない。
    /// この場合も成功を返すが、クローズコードと理由はピアへ届かない。
    ///
    /// # エラー
    ///
    /// `message` が 1024 バイトを超える場合、またはセッションが既に終了している
    /// 場合はエラーを返す。
    pub async fn close(&self, error_code: u32, message: impl Into<String>) -> Result<(), Error> {
        let message = message.into();
        if message.len() > 1024 {
            return Err(Error::CloseReasonTooLong {
                length: message.len(),
            });
        }
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::Close {
                error_code,
                message,
                reply,
            })
            .await
            .map_err(|_| Error::SessionClosed)?;
        response.await.map_err(|_| Error::DriverStopped)?
    }

    /// セッションが終了するまで待つ
    ///
    /// 正常に終了した場合はクローズ情報を返す。CONNECT ストリームの
    /// RESET_STREAM や、`WT_SESSION_GONE` 以外のセッションエラーで終了した
    /// 場合は [`Error::SessionAborted`] を返す。ドライバーでエラーが発生した
    /// 場合は [`Error::DriverFailed`] を返す。QUIC 接続の終了は、終了理由を
    /// 保持した [`Error::Quic`] を返す。
    ///
    /// [`Session::split_receivers`] で受信系を分離した後も、終了監視は
    /// このオブジェクトに残るため、このメソッドで待てる。
    pub async fn wait_closed(&mut self) -> Result<CloseInfo, Error> {
        wait_closed_impl(&mut self.end).await
    }
}

#[cfg(test)]
mod tests;
