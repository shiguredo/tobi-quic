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
/// 複製したハンドルも同じセッションへ送る。ハンドルはセッションの終了を妨げず、
/// 終了後の送信は失敗する。
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
/// [`Session::wait_closed`] で待つ。セッションをドロップしただけでも
/// ドライバーがクローズコード 0 で終了処理を行う。
///
/// # 待機について
///
/// ストリームを開く操作は、WT ヘッダーを QUIC ストリームへ書き込む際に
/// 接続のフロー制御待ちになることがある。この間は同じセッションの他の操作も
/// 待機する。[`Session::close`] と [`Session::send_datagram`] もドライバー
/// 経由で実行されるため、ドライバーが接続のフロー制御待ちで滞留している間は
/// 完了しない。アプリケーションのペイロード送信 ([`WtSendStream::send`]) は
/// ドライバーを経由しないため、この待機の影響を受けない。
pub struct Session {
    session_id: u64,
    requested_draft: DraftVersion,
    settings_draft: DraftVersion,
    protocol: Option<String>,
    flow_control_enabled: bool,
    commands: mpsc::Sender<Command>,
    incoming_bidi: mpsc::Receiver<WtBidirectionalStream>,
    incoming_uni: mpsc::Receiver<WtReceiveStream>,
    datagrams: mpsc::Receiver<Vec<u8>>,
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

impl Session {
    pub(crate) fn new(parts: SessionParts) -> Self {
        Self {
            session_id: parts.session_id,
            requested_draft: parts.requested_draft,
            settings_draft: parts.settings_draft,
            protocol: parts.protocol,
            flow_control_enabled: parts.flow_control_enabled,
            commands: parts.commands,
            incoming_bidi: parts.incoming_bidi,
            incoming_uni: parts.incoming_uni,
            datagrams: parts.datagrams,
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

    /// サーバーが開始した双方向ストリームを受け付ける
    ///
    /// # エラー
    ///
    /// セッションが終了している場合は [`Error::SessionClosed`] を返す。
    pub async fn accept_bidirectional_stream(&mut self) -> Result<WtBidirectionalStream, Error> {
        self.incoming_bidi.recv().await.ok_or(Error::SessionClosed)
    }

    /// サーバーが開始した単方向ストリームを受け付ける
    ///
    /// # エラー
    ///
    /// セッションが終了している場合は [`Error::SessionClosed`] を返す。
    pub async fn accept_unidirectional_stream(&mut self) -> Result<WtReceiveStream, Error> {
        self.incoming_uni.recv().await.ok_or(Error::SessionClosed)
    }

    /// 到着した双方向ストリーム、単方向ストリーム、DATAGRAM のいずれかを返す。
    ///
    /// 受信種別が分からないアプリケーションで、複数の受信を同時に待つために使う。
    /// キャンセルしても未受信の項目はキューへ残る。すべての受信キューが閉じた場合は
    /// [`Error::SessionClosed`] を返す。
    pub async fn receive(&mut self) -> Result<Incoming, Error> {
        tokio::select! {
            Some(stream) = self.incoming_bidi.recv() => Ok(Incoming::BidirectionalStream(stream)),
            Some(stream) = self.incoming_uni.recv() => Ok(Incoming::UnidirectionalStream(stream)),
            Some(data) = self.datagrams.recv() => Ok(Incoming::Datagram(data)),
            else => Err(Error::SessionClosed),
        }
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
    /// # エラー
    ///
    /// セッションが終了している場合は [`Error::SessionClosed`] を返す。
    pub async fn receive_datagram(&mut self) -> Result<Vec<u8>, Error> {
        self.datagrams.recv().await.ok_or(Error::SessionClosed)
    }

    /// セッションをクローズする
    ///
    /// WT_CLOSE_SESSION カプセルを送信して CONNECT ストリームを FIN で閉じ、
    /// 関連するストリームを WT_SESSION_GONE でリセットする。ピアが CONNECT
    /// ストリームを閉じるのを待ってから、QUIC 接続をアプリケーションエラー
    /// (H3_NO_ERROR) で閉じる (draft-ietf-webtrans-http3-15 Section 6)。
    /// ドライバーが接続のフロー制御待ちで滞留している間は完了しない。
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
    pub async fn wait_closed(&mut self) -> Result<CloseInfo, Error> {
        loop {
            if let Some(end) = self.end.borrow().clone() {
                return match end {
                    SessionEnd::Closed(info) => Ok(info),
                    SessionEnd::Aborted {
                        transport_error_code,
                        connect_stream_error_code,
                    } => Err(Error::SessionAborted {
                        transport_error_code,
                        connect_stream_error_code,
                    }),
                    SessionEnd::Failed(message) => Err(Error::DriverFailed(message)),
                    SessionEnd::TransportClosed(reason) => {
                        Err(Error::Quic(tobi_quic::Error::Connection(reason)))
                    }
                };
            }
            if self.end.changed().await.is_err() {
                return Err(Error::SessionClosed);
            }
        }
    }
}
