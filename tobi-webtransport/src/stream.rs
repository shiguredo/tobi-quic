// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! WebTransport データストリーム
//!
//! WebTransport の双方向ストリームと単方向ストリームを表現する。
//! ストリーム先頭の WT ヘッダーは結線側が送信済みであり、ここでは
//! アプリケーションのペイロードだけを扱う。

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use shiguredo_http3::webtransport::error::ApplicationErrorCode;
use tobi_quic::SendStream;

use crate::error::Error;

/// HTTP/3 のエラーコードを WebTransport のアプリケーションエラーコードへ変換する
///
/// 範囲外のコードはアプリケーションエラーコードとして解釈できないため
/// `None` を返す (draft-ietf-webtrans-http3-15 Section 4.4)。
pub(crate) fn app_error_from_http3(http3_code: u64) -> Option<u32> {
    ApplicationErrorCode::from_http3_code(http3_code)
}

/// WebTransport のアプリケーションエラーコードを HTTP/3 のエラーコードへ変換する
///
/// (draft-ietf-webtrans-http3-15 Section 4.4)
pub(crate) fn app_error_to_http3(error_code: u32) -> u64 {
    ApplicationErrorCode::to_http3_code(error_code)
}

/// 受信ストリームに配送するイベント
#[derive(Debug)]
pub(crate) enum StreamEvent {
    /// アプリケーションのペイロード
    Data(Vec<u8>),
    /// FIN を受信した
    Fin,
    /// ピアがストリームをリセットした
    ///
    /// アプリケーションエラーコードは結線側で変換済みである。
    /// `WT_APPLICATION_ERROR` の範囲外のコードはアプリケーション
    /// エラーコードとして解釈できないため `None` になる
    /// (draft-ietf-webtrans-http3-15 Section 4.4)。
    Reset {
        /// ピアが通知したアプリケーションエラーコード
        error_code: Option<u32>,
    },
    /// 受信側で回復不能なエラーが発生した
    Failed(String),
}

/// 受信データの消費通知
///
/// アプリケーションが受信データを消費したことをドライバーへ伝える。
/// ドライバーはセッションのフロー制御へ消費量を反映し、必要に応じて
/// WT_MAX_DATA カプセルを送信する (draft-ietf-webtrans-http3-15 Section 5.4)。
#[derive(Debug, Clone, Copy)]
pub(crate) struct Consumed {
    /// QUIC ストリーム ID
    pub(crate) stream_id: u64,
    /// 消費したバイト数
    pub(crate) bytes: u64,
}

/// ストリームからドライバーへの制御通知
#[derive(Debug)]
pub(crate) enum StreamControl {
    /// 受信側がドロップされた
    ///
    /// ドライバーは読み取りタスクを停止して STOP_SENDING を送り、
    /// ストリームの後始末と未消費データのフロー制御反映を行う。
    Dropped {
        /// QUIC ストリーム ID
        stream_id: u64,
        /// ドロップ時にアプリケーションが指定したエラーコード
        error_code: u32,
    },
    /// 送信側がドロップされた
    ///
    /// ドライバーは STOP_SENDING の通知先を解放する。
    SendClosed {
        /// QUIC ストリーム ID
        stream_id: u64,
    },
    /// WT_DATA_BLOCKED の送信要求
    DataBlocked {
        /// 送信が停止した時点の WT_MAX_DATA
        maximum: u64,
    },
}

/// セッション全体で共有する送信データのクレジット
///
/// ピアが通知した WT_MAX_DATA と送信済みバイト数を管理する。複数の
/// 送信ストリームから並行に予約されるため、アトミックな操作で排他する。
/// (draft-ietf-webtrans-http3-15 Section 5.4)
pub(crate) struct SendCredit {
    /// ピアが通知した WT_MAX_DATA (フロー制御が無効な場合は `u64::MAX`)
    limit: AtomicU64,
    /// 送信を許可した累計バイト数
    used: AtomicU64,
    /// セッションが終了したか
    closed: AtomicBool,
    /// クレジット更新の通知 (値を更新するたびに待機者を起こす)
    updates: watch::Sender<u64>,
    /// WT_DATA_BLOCKED の送信要求先
    blocked: mpsc::UnboundedSender<StreamControl>,
}

impl SendCredit {
    /// クレジットを作る
    pub(crate) fn new(blocked: mpsc::UnboundedSender<StreamControl>) -> Arc<Self> {
        let (updates, _) = watch::channel(0u64);
        Arc::new(Self {
            limit: AtomicU64::new(u64::MAX),
            used: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            updates,
            blocked,
        })
    }

    /// クレジット更新の待機に使う受信側を作る
    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.updates.subscribe()
    }

    /// ピアが通知した WT_MAX_DATA を設定する
    pub(crate) fn set_limit(&self, limit: u64) {
        self.limit.store(limit, Ordering::Release);
        // 待機中の送信を起こす
        self.updates.send_modify(|generation| {
            *generation = generation.wrapping_add(1);
        });
    }

    /// セッションの終了を通知する
    ///
    /// 待機中の送信は [`Error::SessionClosed`] で終了する。
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.updates.send_modify(|generation| {
            *generation = generation.wrapping_add(1);
        });
    }

    /// セッションが終了しているか
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// 送信可能なバイト数を予約する
    ///
    /// 戻り値は予約できたバイト数で、0 の場合はクレジットが尽きている。
    /// セッションが終了している場合も 0 を返す。予約と返却は呼び出し側の
    /// 責任で行うため、ここでは終了チェックだけを行う。
    fn reserve(&self, bytes: u64) -> u64 {
        if self.closed.load(Ordering::Acquire) {
            return 0;
        }
        loop {
            let limit = self.limit.load(Ordering::Acquire);
            let used = self.used.load(Ordering::Acquire);
            let remaining = limit.saturating_sub(used);
            if remaining == 0 {
                return 0;
            }
            let granted = remaining.min(bytes);
            if self
                .used
                .compare_exchange_weak(
                    used,
                    used.saturating_add(granted),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return granted;
            }
        }
    }

    /// 送信できなかった分の予約を戻す
    fn release(&self, bytes: u64) {
        self.used.fetch_sub(bytes, Ordering::AcqRel);
    }

    /// WT_DATA_BLOCKED の送信をドライバーへ依頼する
    fn notify_blocked(&self) {
        let maximum = self.limit.load(Ordering::Acquire);
        if maximum != u64::MAX {
            let _ = self.blocked.send(StreamControl::DataBlocked { maximum });
        }
    }
}

/// WebTransport の送信ストリーム
///
/// WebTransport データストリームの送信側だけを扱う。ストリーム先頭の
/// WT ヘッダーはセッションが送信済みであるため、`send` で渡したデータは
/// そのままアプリケーションのペイロードとして送られる。
pub struct WtSendStream {
    stream_id: u64,
    send: SendStream,
    credit: Arc<SendCredit>,
    updates: watch::Receiver<u64>,
    /// ピアから STOP_SENDING を受けたアプリケーションエラーコード
    stopped: watch::Receiver<Option<u64>>,
    /// WT ヘッダー長 (RESET_STREAM_AT の reliable size)
    ///
    /// このストリームを開始した側だけがヘッダーを送信しているため、
    /// ピア開始のストリームでは `None` になる。
    reset_at: Option<u64>,
    /// FIN を送信済みか
    fin_sent: bool,
    /// RESET_STREAM を送信済みのアプリケーションエラーコード
    reset_sent: Option<u32>,
    /// 呼び出し側の future から独立して継続する先行の送信操作
    ///
    /// `send` future がキャンセルされてもこのタスクは継続し、受理済み
    /// バイト数の反映と未受理分の返却を行う。次の `send` / `finish` は
    /// このタスクの完了を待ってから進む。
    pending_send: Option<JoinHandle<Result<usize, Error>>>,
    /// ドライバーへの制御通知
    control: mpsc::UnboundedSender<StreamControl>,
}

impl WtSendStream {
    pub(crate) fn new(
        stream_id: u64,
        send: SendStream,
        credit: Arc<SendCredit>,
        stopped: watch::Receiver<Option<u64>>,
        reset_at: Option<u64>,
        control: mpsc::UnboundedSender<StreamControl>,
    ) -> Self {
        let updates = credit.subscribe();
        Self {
            stream_id,
            send,
            credit,
            updates,
            stopped,
            reset_at,
            fin_sent: false,
            reset_sent: None,
            pending_send: None,
            control,
        }
    }

    /// QUIC ストリーム ID を返す
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// データを送信する
    ///
    /// アプリケーションのペイロードだけを送信する。セッションの
    /// WT_MAX_DATA の範囲を超えるデータは、ピアが上限を増やすまで待機する。
    /// (draft-ietf-webtrans-http3-15 Section 5.4)
    ///
    /// クレジットは部分送信ごとに確保し、QUIC が受理しなかった分だけを返す。
    /// 送信操作は呼び出し側の future から独立したタスクが所有するため、
    /// この future をキャンセルしても既に投入した操作の結果は回収され、
    /// 未受理分が返る。キャンセル時に次の部分送信は開始しない。ただし、
    /// キャンセルは既に受理されたデータの送信取り消しを保証しない。
    ///
    /// 同じストリームの後続の `send` / `finish` は、先行する操作の結果を
    /// 回収してから進む。`reset` / drop / STOP_SENDING は先行操作を終端させ、
    /// その場合も受理済みバイト数の清算を行う。
    ///
    /// # エラー
    ///
    /// 送信側が終端済みの場合は [`Error::StreamClosed`] を返す。
    /// ピアが STOP_SENDING を送っている場合は [`Error::StreamStopped`] を返す。
    /// セッションが終了した場合は [`Error::SessionClosed`] を返す。
    pub async fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        self.check_sendable()?;
        if data.is_empty() {
            return Ok(());
        }
        // 先行操作の結果を回収してから新しい入力を送る。古い入力の結果を
        // 新しい入力の完了として返さない。
        self.wait_pending().await;
        self.check_sendable()?;
        let mut rest = data;
        loop {
            let granted = self.credit.reserve(rest.len() as u64) as usize;
            if granted == 0 {
                // クレジットが尽きている: ピアの WT_MAX_DATA 更新を待つ
                self.credit.notify_blocked();
                self.wait_for_credit().await?;
                continue;
            }
            let operation = self.send.start_send(&rest[..granted]);
            let accepted = operation.accepted_handle();
            let credit = Arc::clone(&self.credit);
            let granted_bytes = granted as u64;
            let stream_id = self.stream_id;
            self.pending_send = Some(tokio::spawn(async move {
                let result = operation
                    .await
                    .map_err(|error| map_send_error(stream_id, error));
                let accepted = accepted.load(Ordering::Acquire) as u64;
                // 受理済み分は WT_MAX_DATA を消費したままにし、未受理分だけを返す。
                credit.release(granted_bytes.saturating_sub(accepted));
                result
            }));
            let result = {
                let handle = self.pending_send.as_mut().expect("pending send must exist");
                std::future::poll_fn(|cx| Pin::new(&mut *handle).poll(cx)).await
            };
            self.pending_send = None;
            let accepted = match result {
                Ok(result) => result?,
                Err(error) => {
                    return Err(Error::DriverFailed(format!(
                        "WebTransport send task failed: {error}"
                    )));
                }
            };
            if accepted == 0 || accepted > granted {
                return Err(Error::DriverFailed(format!(
                    "QUIC stream {} accepted {accepted} of {granted} bytes",
                    self.stream_id
                )));
            }
            rest = &rest[accepted..];
            if rest.is_empty() {
                return Ok(());
            }
        }
    }

    /// FIN を送信して送信側を終端する
    ///
    /// 一度終端した後に再度呼び出しても成功する。先行する送信操作が
    /// ある場合は、その結果を回収してから FIN を送る。
    ///
    /// # エラー
    ///
    /// リセット済みの場合は [`Error::StreamClosed`] を返す。
    /// ピアが STOP_SENDING を送っている場合は [`Error::StreamStopped`] を返す。
    /// 接続が終了した場合は QUIC 層のエラーを返す。
    pub async fn finish(&mut self) -> Result<(), Error> {
        if self.fin_sent {
            return Ok(());
        }
        if self.reset_sent.is_some() {
            return Err(Error::StreamClosed {
                stream_id: self.stream_id,
            });
        }
        if let Some(error_code) = self.stopped_code() {
            return Err(Error::StreamStopped {
                stream_id: self.stream_id,
                error_code: Some(error_code),
            });
        }
        self.wait_pending().await;
        self.check_sendable()?;
        // FIN は `SendStream` 自身の終端状態を確定させる必要がある。ここで
        // 独立した送信操作を使うと `SendStream` が終端済みにならず、drop 時に
        // RESET_STREAM を送ってピアの受信データを切り詰めてしまう。
        self.send
            .finish()
            .await
            .map_err(|error| map_send_error(self.stream_id, error))?;
        self.fin_sent = true;
        Ok(())
    }

    /// 先行する送信操作の結果を回収する
    ///
    /// 呼び出し側の future がキャンセルされても、送信操作はタスクとして
    /// 継続する。ここでは結果だけを回収し、古い入力の結果を新しい入力の
    /// 完了として返さない。`wait_pending` 自身がキャンセルされた場合は
    /// ハンドルを保持したままにする。
    async fn wait_pending(&mut self) {
        if let Some(handle) = self.pending_send.as_mut() {
            let _ = std::future::poll_fn(|cx| Pin::new(&mut *handle).poll(cx)).await;
        }
        self.pending_send = None;
    }

    /// ストリームをリセットする
    ///
    /// `error_code` は WebTransport のアプリケーションエラーコード
    /// (0x00000000 - 0xffffffff) である。送信前に WT_APPLICATION_ERROR の
    /// HTTP/3 エラーコード範囲へ変換する
    /// (draft-ietf-webtrans-http3-15 Section 4.4)。
    /// ピアが `reset_stream_at` transport parameter を広告しており、この
    /// ストリームを開始した側である場合は、WT ヘッダーの配信を保証するため
    /// RESET_STREAM_AT を使う (draft-ietf-webtrans-http3-15 Section 4.4)。
    ///
    /// FIN を送信した後でもリセットできる。ただし FIN の肯定応答を受信済みの
    /// ストリームは QUIC の終端状態であり、RESET_STREAM を送信できない
    /// (RFC 9000 Section 3.1)。この場合はピアが全データを受信済みのため、
    /// リセット要求を成功として扱う。ピアが STOP_SENDING を送っている場合は
    /// ドライバーが同じアプリケーションエラーコードでリセット済みのため、
    /// 何もせずに成功を返す。同じストリームを異なるエラーコードで再び
    /// リセットすることはできない (RFC 9000 Section 19.4)。
    ///
    /// # エラー
    ///
    /// 異なるエラーコードで既にリセット済みの場合は [`Error::StreamClosed`] を
    /// 返す。接続が終了した場合は QUIC 層のエラーを返す。
    pub async fn reset(&mut self, error_code: u32) -> Result<(), Error> {
        if let Some(sent) = self.reset_sent {
            return if sent == error_code {
                Ok(())
            } else {
                Err(Error::StreamClosed {
                    stream_id: self.stream_id,
                })
            };
        }
        if let Some(stopped) = self.stopped_code() {
            // ドライバーが STOP_SENDING と同じエラーコードでリセット済みである
            self.reset_sent = Some(stopped);
            return Ok(());
        }
        // アプリケーションエラーコードを WT_APPLICATION_ERROR の範囲へ変換する
        // (draft-ietf-webtrans-http3-15 Section 4.4)
        let http3_code = app_error_to_http3(error_code);
        let result = match self.reset_at {
            Some(reliable_size) => self.send.reset_stream_at(http3_code, reliable_size).await,
            None => self.send.reset_stream(http3_code).await,
        };
        match result {
            Ok(()) => {}
            // FIN の肯定応答を受信済みのストリームは終端状態である
            // (RFC 9000 Section 3.1)。ピアは全データを受信済みのため、
            // RESET_STREAM を送らずに成功として扱う
            Err(tobi_quic::Error::Stream(tobi_quic::StreamError::FinishedSending)) => {}
            Err(error) => return Err(error.into()),
        }
        self.reset_sent = Some(error_code);
        Ok(())
    }

    /// 送信可能な状態かを確認する
    fn check_sendable(&self) -> Result<(), Error> {
        if let Some(error_code) = self.stopped_code() {
            return Err(Error::StreamStopped {
                stream_id: self.stream_id,
                error_code: Some(error_code),
            });
        }
        if self.reset_sent.is_some() || self.fin_sent {
            return Err(Error::StreamClosed {
                stream_id: self.stream_id,
            });
        }
        Ok(())
    }

    /// ピアから受け取った STOP_SENDING のアプリケーションエラーコードを返す
    ///
    /// HTTP/3 のエラーコードをアプリケーションエラーコードへ変換する。
    /// WT_APPLICATION_ERROR の範囲外のコードはアプリケーションエラーコードと
    /// 解釈できないため `None` を返す (draft-ietf-webtrans-http3-15 Section 4.4)。
    fn stopped_code(&self) -> Option<u32> {
        let borrowed = self.stopped.borrow();
        let http3_code = (*borrowed)?;
        app_error_from_http3(http3_code)
    }

    /// ピアの WT_MAX_DATA 更新と STOP_SENDING を待つ
    async fn wait_for_credit(&mut self) -> Result<(), Error> {
        loop {
            if self.credit.is_closed() {
                return Err(Error::SessionClosed);
            }
            if let Some(error_code) = self.stopped_code() {
                return Err(Error::StreamStopped {
                    stream_id: self.stream_id,
                    error_code: Some(error_code),
                });
            }
            tokio::select! {
                changed = self.updates.changed() => {
                    if changed.is_err() {
                        return Err(Error::SessionClosed);
                    }
                    return Ok(());
                }
                changed = self.stopped.changed() => {
                    if changed.is_err() {
                        return Err(Error::SessionClosed);
                    }
                }
            }
        }
    }
}

impl Drop for WtSendStream {
    fn drop(&mut self) {
        // 送信側を手放したことをドライバーへ通知する。
        // ドライバーは STOP_SENDING の配送先を解放する。
        // QUIC の SendStream のドロップは、終端していない場合に RESET_STREAM を送る。
        let _ = self.control.send(StreamControl::SendClosed {
            stream_id: self.stream_id,
        });
    }
}

/// WebTransport の受信ストリーム
///
/// 受信データは結線側のタスクからチャネル経由で配送される。
/// FIN まで読み切らずにドロップした場合は、ドライバーが STOP_SENDING を送り、
/// 未消費データをセッションのフロー制御へ返す。
pub struct WtReceiveStream {
    stream_id: u64,
    events: mpsc::UnboundedReceiver<StreamEvent>,
    consumed: mpsc::UnboundedSender<Consumed>,
    control: mpsc::UnboundedSender<StreamControl>,
    finished: bool,
    /// 観測済みの終端エラー
    ///
    /// Reset / Failed を 1 度返した後も同じエラーを返し続けるため保持する。
    terminal_error: Option<StreamEvent>,
    /// ドロップ時にピアへ通知するアプリケーションエラーコード
    ///
    /// `Drop` で `STOP_SENDING` の要求に載せる。既定値は 0。
    drop_error_code: u32,
}

impl WtReceiveStream {
    pub(crate) fn new(
        stream_id: u64,
        events: mpsc::UnboundedReceiver<StreamEvent>,
        consumed: mpsc::UnboundedSender<Consumed>,
        control: mpsc::UnboundedSender<StreamControl>,
    ) -> Self {
        Self {
            stream_id,
            events,
            consumed,
            control,
            finished: false,
            terminal_error: None,
            drop_error_code: 0,
        }
    }

    /// ドロップ時にピアへ通知するアプリケーションエラーコードを設定する
    ///
    /// ピアは `STOP_SENDING` を受けると送信を中止し、このコードを
    /// WT_APPLICATION_ERROR の HTTP/3 エラーコードへ変換して観測する
    /// (draft-ietf-webtrans-http3-15 Section 4.4)。`WtBidirectionalStream` は
    /// `split` 後の受信側で指定する。
    pub fn set_drop_error_code(&mut self, error_code: u32) {
        self.drop_error_code = error_code;
    }

    /// QUIC ストリーム ID を返す
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// データを 1 チャンク受信する
    ///
    /// 戻り値が `None` の場合は FIN を受信してストリームが終了している。
    /// 受信したデータは、このメソッドが返した時点で消費済みとして
    /// セッションのフロー制御へ通知する。
    ///
    /// # エラー
    ///
    /// ピアがストリームをリセットした場合は [`Error::StreamReset`] を返す。
    /// セッションが終了した場合も、関連ストリームは WT_SESSION_GONE で中断される
    /// ため [`Error::StreamReset`] を返す
    /// (draft-ietf-webtrans-http3-15 Section 6)。セッションの終了自体は
    /// `Session::wait_closed` で確認すること。
    /// 受信側で回復不能なエラーが発生した場合は [`Error::StreamFailed`] を返す。
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, Error> {
        // 終端エラーを観測済みの場合は、同じエラーを繰り返し返す。
        // Reset / Failed の後に Ok(None) を返すと、エラーを読み飛ばした
        // 呼び出し側が正常終了と誤認する。
        if let Some(error) = &self.terminal_error {
            return match error {
                StreamEvent::Reset { error_code } => Err(Error::StreamReset {
                    stream_id: self.stream_id,
                    error_code: *error_code,
                }),
                StreamEvent::Failed(message) => Err(Error::StreamFailed {
                    stream_id: self.stream_id,
                    message: message.clone(),
                }),
                // 来ないはずだが、来た場合は FIN 扱いにする
                StreamEvent::Fin | StreamEvent::Data(_) => Ok(None),
            };
        }
        if self.finished {
            return Ok(None);
        }
        match self.events.recv().await {
            Some(StreamEvent::Data(data)) => {
                let _ = self.consumed.send(Consumed {
                    stream_id: self.stream_id,
                    bytes: data.len() as u64,
                });
                Ok(Some(data))
            }
            Some(StreamEvent::Fin) => {
                self.finished = true;
                Ok(None)
            }
            Some(event @ (StreamEvent::Reset { .. } | StreamEvent::Failed(_))) => {
                self.finished = true;
                // 終端エラーを保持し、以降の recv で同じエラーを返す
                match event {
                    StreamEvent::Reset { error_code } => {
                        self.terminal_error = Some(StreamEvent::Reset { error_code });
                        Err(Error::StreamReset {
                            stream_id: self.stream_id,
                            error_code,
                        })
                    }
                    StreamEvent::Failed(message) => {
                        self.terminal_error = Some(StreamEvent::Failed(message.clone()));
                        Err(Error::StreamFailed {
                            stream_id: self.stream_id,
                            message,
                        })
                    }
                    StreamEvent::Fin | StreamEvent::Data(_) => {
                        unreachable!("matched Reset or Failed above")
                    }
                }
            }
            None => {
                self.finished = true;
                Err(Error::SessionClosed)
            }
        }
    }
}

impl Drop for WtReceiveStream {
    fn drop(&mut self) {
        // FIN まで読み切っていない場合は、ドライバーへ読み取り停止を依頼する。
        // 受信を中断したままにすると、未消費データがセッションのフロー制御を
        // 占有し続けるため (draft-ietf-webtrans-http3-15 Section 5.4)。
        if self.finished {
            return;
        }
        // 受信済みでアプリケーションがまだ読んでいないデータを、消費として
        // フロー制御へ返す。チャネルに残っている Data をすべて数えることで、
        // ドライバーの pending 会計と二重に返さない (draft-ietf-webtrans-http3-15
        // Section 5.4)。
        let mut unreported = 0_u64;
        while let Ok(event) = self.events.try_recv() {
            if let StreamEvent::Data(data) = event {
                unreported = unreported.saturating_add(data.len() as u64);
            }
        }
        if unreported > 0 {
            let _ = self.consumed.send(Consumed {
                stream_id: self.stream_id,
                bytes: unreported,
            });
        }
        let _ = self.control.send(StreamControl::Dropped {
            stream_id: self.stream_id,
            error_code: self.drop_error_code,
        });
    }
}

/// WebTransport の双方向ストリーム
///
/// 送信側と受信側をまとめて扱う。`split` で独立したストリームに分解できる。
pub struct WtBidirectionalStream {
    send: WtSendStream,
    recv: WtReceiveStream,
}

impl WtBidirectionalStream {
    pub(crate) fn from_parts(send: WtSendStream, recv: WtReceiveStream) -> Self {
        Self { send, recv }
    }

    /// QUIC ストリーム ID を返す
    pub fn stream_id(&self) -> u64 {
        self.send.stream_id()
    }

    /// 送信側と受信側に分解する
    pub fn split(self) -> (WtSendStream, WtReceiveStream) {
        (self.send, self.recv)
    }

    /// データを送信する
    ///
    /// # エラー
    ///
    /// [`WtSendStream::send`] と同じ条件でエラーを返す。
    pub async fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        self.send.send(data).await
    }

    /// データを 1 チャンク受信する
    ///
    /// # エラー
    ///
    /// [`WtReceiveStream::recv`] と同じ条件でエラーを返す。
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.recv.recv().await
    }

    /// FIN を送信して送信側を終端する
    ///
    /// # エラー
    ///
    /// [`WtSendStream::finish`] と同じ条件でエラーを返す。
    pub async fn finish(&mut self) -> Result<(), Error> {
        self.send.finish().await
    }

    /// ストリームをリセットする
    ///
    /// # エラー
    ///
    /// [`WtSendStream::reset`] と同じ条件でエラーを返す。
    pub async fn reset(&mut self, error_code: u32) -> Result<(), Error> {
        self.send.reset(error_code).await
    }
}

/// 全データが受理されるまで送信する
///
/// 戻り値は成功またはエラーだけであり、QUIC が受理したバイト数は返さない。
/// この関数は WT ヘッダーや HTTP/3 の制御ストリームなど、WT_MAX_DATA の
/// 会計対象外のデータに使う。WebTransport のペイロードは
/// [`WtSendStream::send`] がクレジットと受理量を管理する。
pub(crate) async fn write_all(
    stream_id: u64,
    send: &mut SendStream,
    mut data: &[u8],
) -> Result<(), Error> {
    while !data.is_empty() {
        let written = send
            .send(data)
            .await
            .map_err(|error| map_send_error(stream_id, error))?;
        if written == 0 {
            // 0 バイトの受理は進行不能である
            return Err(Error::DriverFailed(format!(
                "QUIC stream {stream_id} accepted no data"
            )));
        }
        data = &data[written..];
    }
    Ok(())
}

/// QUIC 層の送信エラーをアプリケーション向けのエラーへ変換する
///
/// ピアの STOP_SENDING はドライバー経由の通知より先に QUIC 層の送信 API が
/// 検出することがあるため、同じ [`Error::StreamStopped`] に揃える。
/// エラーコードは HTTP/3 の値のまま保持し、公開 API の返却時に
/// アプリケーションエラーコードへ変換する。
fn map_send_error(stream_id: u64, error: tobi_quic::Error) -> Error {
    match error {
        tobi_quic::Error::Stream(tobi_quic::StreamError::Stopped { error_code }) => {
            Error::StreamStopped {
                stream_id,
                error_code: app_error_from_http3(error_code),
            }
        }
        other => Error::Quic(other),
    }
}
