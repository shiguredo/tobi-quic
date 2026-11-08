// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

use crate::connection::{Command, SharedConnection, wait_for_command};
use crate::error::{Error, StreamError};

/// `AsyncWrite` が内部で保持する送信 future。
type WriteFuture = Pin<Box<dyn Future<Output = Result<usize, Error>> + Send + Sync + 'static>>;
/// `poll_shutdown()` が FIN 送信を追跡する future。
type ShutdownFuture = Pin<Box<dyn Future<Output = Result<(), Error>> + Send + Sync + 'static>>;
/// 呼び出し側から独立して完了できる送信操作の future。
type SendOperationFuture = Pin<Box<dyn Future<Output = Result<usize, Error>> + Send + Sync>>;
/// 受信要求 1 回分の future。
///
/// ストリーム自身が保持するため、外側の `receive` future がキャンセルされても
/// driver の返信を受け取り続けられる。
type ReadFuture =
    Pin<Box<dyn Future<Output = Result<(Vec<u8>, usize, bool), Error>> + Send + Sync + 'static>>;

/// `AsyncWrite` が保持する進行中の送信
///
/// 送信 future と、その future を作成した入力のバイト列を対応付けて保持する。
/// 外側の `write` future がキャンセルされても、次の `poll_write` に同じ入力が
/// 渡されたときに同じ future を再開するために使う。
struct WriteInFlight {
    /// future の作成に使った入力
    ///
    /// 入力の同一性は内容で比較する。`Arc` のポインタ比較では、同じ内容を
    /// 別のバッファで再書き込みしたときに別入力と誤認する。内容比較は O(n)
    /// だが、入力のハッシュ計算も同程度のコストであり、1 回の書き込みで扱う
    /// データ長は限られるため、内容比較を採る。
    input: Arc<[u8]>,
    /// 進行中の送信 future
    future: WriteFuture,
}

/// 次の受信呼び出しへ引き継ぐ受信データ
///
/// キャンセルされた `receive` / `receive_vectored` / `AsyncRead` が確保していた
/// 受信容量が、次の呼び出しのバッファより大きい場合に、返し切れなかった分を
/// 保持する。
struct PendingRecv {
    /// 受信したデータ (実際に受信した長さに切り詰めてある)
    data: Vec<u8>,
    /// 次に返すデータの位置
    offset: usize,
    /// 未返却データを返し切った時点で FIN 到達済みになるか
    fin: bool,
}

impl PendingRecv {
    /// 未返却のバイト数
    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    /// `ReadBuf` へ未返却データをコピーする
    ///
    /// `ReadBuf` の残量を超える分はコピーせず、次の呼び出しへ持ち越す。
    /// `AsyncRead` は現在の `ReadBuf` の容量に従って返す必要があるため、
    /// `put_slice` に渡す前に必ず残量で切り詰める。
    fn copy_to_read_buf(&mut self, buf: &mut ReadBuf<'_>) {
        let len = self.remaining().min(buf.remaining());
        if len == 0 {
            return;
        }
        buf.put_slice(&self.data[self.offset..self.offset + len]);
        self.offset += len;
    }

    /// 複数のバッファへ順にコピーし、コピーした長さを返す
    ///
    /// 単一バッファへのコピーも 1 要素のスライスとして、この関数に集約する。
    fn copy_to(&mut self, bufs: &mut [&mut [u8]]) -> usize {
        let mut copied = 0;
        for buf in bufs.iter_mut() {
            let remaining = self.remaining();
            if remaining == 0 {
                break;
            }
            let len = buf.len().min(remaining);
            buf[..len].copy_from_slice(&self.data[self.offset..self.offset + len]);
            self.offset += len;
            copied += len;
        }
        copied
    }

    /// 保持しているデータを返し切ったか
    fn is_drained(&self) -> bool {
        self.remaining() == 0
    }
}

/// 受信側の終端状態
///
/// 終端した理由を保持する。`Fin` は EOF を繰り返し返し、`Reset` は同じ
/// `StreamError::Reset` を繰り返し返す。`Other` は接続断・内部エラー・明示的な
/// STOP_SENDING を表し、受信経路の挙動は従来どおり driver に委ねる。
#[derive(Debug, Clone)]
enum TerminalState {
    /// まだ終端していない
    Open,
    /// FIN まで到達した
    Fin,
    /// リセットを観測した。観測したエラーをそのまま保持する
    Reset(StreamError),
    /// FIN / リセット以外の理由で終端した
    Other,
}

impl TerminalState {
    /// 終端しているか
    fn is_terminal(&self) -> bool {
        !matches!(self, Self::Open)
    }
}

/// ストリームの受信状態
///
/// [`ReceiveStream`] と [`BidirectionalStream`] が共有する受信 future・持ち越し
/// データ・終端判定を保持する。`receive` / `receive_vectored` / `AsyncRead` は
/// 同じ状態を使う。完了結果の検証と持ち越しへの格納は [`Self::complete_read`]
/// に、FIN とエラーの終端判定は [`Self::observe_fin`] と
/// [`Self::observe_error`] に寄せる。
struct RecvState {
    /// 進行中の `receive` / `receive_vectored` / `AsyncRead` が共有する読み取り future
    ///
    /// 外側の future がキャンセルされても破棄せず、次の呼び出しで poll を
    /// 再開する。`receive` と `AsyncRead` のどちらからでも同じ future を
    /// 進められるため、混在時の読み取り順序が保たれる。
    recv_future: Option<ReadFuture>,
    /// 次の `receive` / `receive_vectored` / `AsyncRead` 呼び出しへ引き継ぐ受信データ
    pending_recv: Option<PendingRecv>,
    /// 受信側の終端状態
    ///
    /// FIN 到達、リセットの観測、明示的な STOP_SENDING の送信で更新する。
    /// 終端済みの drop で STOP_SENDING を送ると、ピアが送信済みデータを破棄して
    /// RESET_STREAM で応答するため、不要な競合を生む。
    terminal: TerminalState,
}

impl RecvState {
    /// 未終端の受信状態を作る
    fn new() -> Self {
        Self {
            recv_future: None,
            pending_recv: None,
            terminal: TerminalState::Open,
        }
    }

    /// 保持している受信 future を進める
    ///
    /// 進行中の future が無ければ `capacity` の読み取りを開始する。
    /// キャンセルされても future を破棄しないため、driver の返信は次の
    /// 呼び出しでも受け取れる。完了した future はここで手放す。
    async fn poll_recv(
        &mut self,
        conn: &SharedConnection,
        stream_id: u64,
        capacity: usize,
    ) -> Result<(Vec<u8>, usize, bool), Error> {
        if self.recv_future.is_none() {
            self.recv_future = Some(start_read(conn.clone(), stream_id, capacity));
        }
        let future = self
            .recv_future
            .as_mut()
            .expect("recv future must exist after initialization");
        let result = std::future::poll_fn(|cx| future.as_mut().poll(cx)).await;
        self.recv_future = None;
        result
    }

    /// 1 つのバッファへ受信する
    ///
    /// 複数バッファとの共通処理は [`Self::receive_buffers`] に集約する。
    async fn receive(
        &mut self,
        conn: &SharedConnection,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<StreamRead, Error> {
        self.receive_buffers(conn, stream_id, &mut [buf]).await
    }

    /// 複数のバッファへ受信する
    ///
    /// 単一バッファとの共通処理は [`Self::receive_buffers`] に集約する。
    async fn receive_vectored(
        &mut self,
        conn: &SharedConnection,
        stream_id: u64,
        bufs: &mut [&mut [u8]],
    ) -> Result<StreamRead, Error> {
        self.receive_buffers(conn, stream_id, bufs).await
    }

    /// バッファ群へ受信する (単一バッファとベクター受信の共通実装)
    ///
    /// 持ち越しデータの返却・0 長判定・受信 future の開始を扱う。完了した
    /// future の結果検証と持ち越しへの格納は [`Self::complete_read`] に委ねる。
    async fn receive_buffers(
        &mut self,
        conn: &SharedConnection,
        stream_id: u64,
        bufs: &mut [&mut [u8]],
    ) -> Result<StreamRead, Error> {
        // キャンセルされた呼び出しが持ち越したデータを先に返す。
        if let Some(read) = self.take_pending(bufs) {
            return Ok(read);
        }
        let capacity: usize = bufs.iter().map(|buf| buf.len()).sum();
        if capacity == 0 {
            // 0 長の読み取りはデータを消費しない。ただし、キャンセルされた
            // 非 0 長の読み取りが保持する future が既にデータと FIN を
            // 受け取っている場合がある。driver に 0 長で問い合わせると、
            // そのデータを無視した fin が返り、呼び出し側が終了すると
            // 保持中のデータが失われる。保持中の future がある間は fin を
            // 返さず、次の非 0 長の受信へ委ねる。
            if self.recv_future.is_some() {
                return Ok(StreamRead { len: 0, fin: false });
            }
            // 0 長の処理は終端状態より優先する。リセット済みでも
            // `(0, false)` を返す既存の契約を変えない。
            match self.terminal {
                TerminalState::Fin => return Ok(StreamRead { len: 0, fin: true }),
                TerminalState::Reset(_) => return Ok(StreamRead { len: 0, fin: false }),
                TerminalState::Open | TerminalState::Other => {}
            }
            return self.receive_empty(conn, stream_id).await;
        }
        // 終端状態を観測済みなら driver を呼ばずに同じ結果を返す。
        match self.terminal.clone() {
            TerminalState::Fin => return Ok(StreamRead { len: 0, fin: true }),
            TerminalState::Reset(error) => return Err(Error::Stream(error)),
            TerminalState::Open | TerminalState::Other => {}
        }
        let (data, n, fin) = match self.poll_recv(conn, stream_id, capacity).await {
            Ok(result) => result,
            Err(error) => return Err(self.observe_error(error)),
        };
        self.complete_read(data, n, fin)?;
        // `complete_read` が結果を保持しているため、その場で現在のバッファへ
        // 返す。返し切れない分は次の呼び出しへ持ち越す。
        Ok(self
            .take_pending(bufs)
            .expect("receive result must be pending after completion"))
    }

    /// 所有 `Vec` で受信する
    ///
    /// `max_len` は 1 回の呼び出しで返すデータ長の上限である。`pending_recv` が
    /// あれば先頭から `max_len` までを取り出し、残りを保持する。無ければ
    /// `poll_recv(max_len)` で受信し、`min(n, max_len)` を返して超過分を保持する。
    async fn receive_vec(
        &mut self,
        conn: &SharedConnection,
        stream_id: u64,
        max_len: usize,
    ) -> Result<StreamChunk, Error> {
        // 持ち越しデータを先に返す。max_len = 0 ではデータを消費しない。
        if let Some(pending) = self.pending_recv.as_mut() {
            if max_len == 0 {
                return Ok(StreamChunk {
                    data: Vec::new(),
                    fin: false,
                });
            }
            let available = pending.data.len() - pending.offset;
            let take = available.min(max_len);
            let data = pending.data[pending.offset..pending.offset + take].to_vec();
            pending.offset += take;
            let fin = pending.fin && pending.offset == pending.data.len();
            if pending.is_drained() {
                self.pending_recv = None;
            }
            return Ok(StreamChunk { data, fin });
        }
        if max_len == 0 {
            // 保持中の future がある間は fin を返さず、次の非 0 長の受信へ委ねる。
            if self.recv_future.is_some() {
                return Ok(StreamChunk {
                    data: Vec::new(),
                    fin: false,
                });
            }
            match self.terminal {
                TerminalState::Fin => {
                    return Ok(StreamChunk {
                        data: Vec::new(),
                        fin: true,
                    });
                }
                TerminalState::Reset(_) => {
                    return Ok(StreamChunk {
                        data: Vec::new(),
                        fin: false,
                    });
                }
                TerminalState::Open | TerminalState::Other => {}
            }
            // 0 長経路では driver が (Vec::new(), 0, false) を返すことがあるため、
            // n == 0 && !fin の実装不整合判定は適用しない。
            return match start_read(conn.clone(), stream_id, 0).await {
                Ok((_data, _n, fin)) => {
                    self.observe_fin(fin);
                    Ok(StreamChunk {
                        data: Vec::new(),
                        fin,
                    })
                }
                Err(error) => Err(self.observe_error(error)),
            };
        }
        // 終端状態を観測済みなら driver を呼ばずに同じ結果を返す。
        match self.terminal.clone() {
            TerminalState::Fin => {
                return Ok(StreamChunk {
                    data: Vec::new(),
                    fin: true,
                });
            }
            TerminalState::Reset(error) => return Err(Error::Stream(error)),
            TerminalState::Open | TerminalState::Other => {}
        }
        let (mut data, n, fin) = match self.poll_recv(conn, stream_id, max_len).await {
            Ok(result) => result,
            Err(error) => return Err(self.observe_error(error)),
        };
        if n == 0 && !fin {
            return Err(self.observe_error(Error::Internal(
                "stream receive returned empty data without fin".into(),
            )));
        }
        self.observe_fin(fin);
        data.truncate(n);
        if n > max_len {
            // 保持中の future が前回の容量で受信した場合、max_len を超える。
            // 超過分は次の呼び出しへ持ち越す。
            let rest = data.split_off(max_len);
            self.pending_recv = Some(PendingRecv {
                data: rest,
                offset: 0,
                fin,
            });
            return Ok(StreamChunk { data, fin: false });
        }
        Ok(StreamChunk { data, fin })
    }

    /// 容量 0 の読み取りをその場で待つ
    ///
    /// 0 長の読み取りはストリームのデータを消費しないため、外側の future を
    /// キャンセルしても失うものは無い。保持中の受信 future が無いことを
    /// 前提に、driver から終端状態だけを観測する。
    async fn receive_empty(
        &mut self,
        conn: &SharedConnection,
        stream_id: u64,
    ) -> Result<StreamRead, Error> {
        match start_read(conn.clone(), stream_id, 0).await {
            Ok((_data, _n, fin)) => {
                self.observe_fin(fin);
                Ok(StreamRead { len: 0, fin })
            }
            Err(error) => Err(self.observe_error(error)),
        }
    }

    /// FIN の観測を終端状態へ反映する
    ///
    /// リセットを観測済みの場合は上書きしない。`Other` (接続断・内部エラー・
    /// 明示的な STOP_SENDING) の後に FIN を観測した場合は `Fin` へ進める。
    /// transport は FIN 受信後の STOP_SENDING を受理するため、STOP_SENDING の
    /// 後にデータを読み切って FIN を観測する経路がある。
    fn observe_fin(&mut self, fin: bool) {
        if fin && matches!(self.terminal, TerminalState::Open | TerminalState::Other) {
            self.terminal = TerminalState::Fin;
        }
    }

    /// 受信エラーを終端状態へ反映する
    ///
    /// リセット受信は同じ `StreamError::Reset` を繰り返し返せるよう保持する。
    /// それ以外のエラーは `Other` とし、既に FIN / リセットを観測している
    /// 場合はその状態を優先する。
    fn observe_error(&mut self, error: Error) -> Error {
        if let Error::Stream(stream_error @ StreamError::Reset { .. }) = &error {
            self.terminal = TerminalState::Reset(stream_error.clone());
        } else if !self.terminal.is_terminal() {
            self.terminal = TerminalState::Other;
        }
        error
    }

    /// 受信 future の完了結果を検証し、持ち越し領域へ移す
    ///
    /// `data` は要求容量で確保されたバッファであり、`n` より後ろは未受信の
    /// 領域であるため切り詰める。`n == 0` かつ `fin == false` の結果は実装
    /// 不整合として扱う。
    fn complete_read(&mut self, mut data: Vec<u8>, n: usize, fin: bool) -> Result<(), Error> {
        if n == 0 && !fin {
            // driver は n > 0 または fin を返す契約である。ここへ来た場合、
            // 読み取りが進んでいない結果を EOF (0 バイト) として通知すると
            // データの有無を取り違えるため、実装不整合として終端する。
            return Err(self.observe_error(Error::Internal(
                "stream receive returned empty data without fin".into(),
            )));
        }
        self.observe_fin(fin);
        data.truncate(n);
        self.pending_recv = Some(PendingRecv {
            data,
            offset: 0,
            fin,
        });
        Ok(())
    }

    /// 持ち越した受信データをバッファ群へ返す
    ///
    /// 持ち越しが無い場合は `None` を返す。返し切れなかった分は再び保持し、
    /// そのときの `fin` は偽になる。FIN を含むデータを返し切った場合に `fin` が
    /// 真になる。FIN の終端判定は [`Self::complete_read`] が完了時に行う。
    fn take_pending(&mut self, bufs: &mut [&mut [u8]]) -> Option<StreamRead> {
        let (copied, drained, pending_fin) = {
            let pending = self.pending_recv.as_mut()?;
            let copied = pending.copy_to(bufs);
            (copied, pending.is_drained(), pending.fin)
        };
        let fin = drained && pending_fin;
        if drained {
            self.pending_recv = None;
        }
        Some(StreamRead { len: copied, fin })
    }

    /// `AsyncRead::poll_read` の実装
    ///
    /// `receive` / `receive_vectored` と同じ `recv_future` と `pending_recv` を
    /// 使う。キャンセル後に別の容量の `ReadBuf` で再開しても、返し切れなかった
    /// 分は `pending_recv` へ持ち越すため、`ReadBuf` の容量を超えて書き込まない。
    ///
    /// 0 長の `ReadBuf` では FIN の有無を呼び出し側へ伝えられないため、FIN を
    /// 観測しないまま `Ready(Ok(()))` で 0 バイトを返す。EOF の判定は非 0 長の
    /// 読み取りに委ねる。
    fn poll_read(
        &mut self,
        conn: &SharedConnection,
        stream_id: u64,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        // キャンセルされた読み取りが持ち越したデータを先に返す。0 長の
        // `ReadBuf` ではコピーしないが、データは保持したまま 0 バイトを返す。
        if self.pending_recv.is_some() {
            self.take_pending_read(buf);
            return Poll::Ready(Ok(()));
        }
        if buf.remaining() == 0 {
            // 0 長の読み取りはデータを消費せず、FIN も参照しない。新しい
            // 読み取りも開始せず、進行中の future は破棄せずに次の非 0 長の
            // 読み取りで回収する。
            return Poll::Ready(Ok(()));
        }
        // 終端状態を観測済みなら driver を呼ばずに同じ結果を返す。
        match &self.terminal {
            TerminalState::Fin => return Poll::Ready(Ok(())),
            TerminalState::Reset(error) => {
                return Poll::Ready(Err(io::Error::other(Error::Stream(error.clone()))));
            }
            TerminalState::Open | TerminalState::Other => {}
        }
        if self.recv_future.is_none() {
            // 現在の `ReadBuf` の残量を容量として読み取りを開始する。キャンセル
            // された読み取りの future が残っている場合は、その future をそのまま
            // 進める。返ってきたデータが現在の `ReadBuf` より大きくても、
            // `pending_recv` 経由で容量までしかコピーしない。
            self.recv_future = Some(start_read(conn.clone(), stream_id, buf.remaining()));
        }
        let future = self
            .recv_future
            .as_mut()
            .expect("recv future must exist after initialization");
        match future.as_mut().poll(cx) {
            Poll::Ready(Ok((data, n, fin))) => {
                self.recv_future = None;
                // 結果を検証して保持領域へ移してから、現在の `ReadBuf` の
                // 残量までコピーする。コピーしきれない分は次の呼び出しへ
                // 持ち越す。
                match self.complete_read(data, n, fin) {
                    Ok(()) => {
                        self.take_pending_read(buf);
                        Poll::Ready(Ok(()))
                    }
                    Err(error) => Poll::Ready(Err(io::Error::other(error))),
                }
            }
            Poll::Ready(Err(error)) => {
                self.recv_future = None;
                let error = self.observe_error(error);
                Poll::Ready(Err(io::Error::other(error)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// 持ち越した受信データを `ReadBuf` へ返す
    ///
    /// FIN を含むデータを返し切った場合の終端判定は [`Self::complete_read`] が
    /// 完了時に行う。
    fn take_pending_read(&mut self, buf: &mut ReadBuf<'_>) {
        let Some(pending) = self.pending_recv.as_mut() else {
            return;
        };
        pending.copy_to_read_buf(buf);
        if pending.is_drained() {
            self.pending_recv = None;
        }
    }
}

/// ストリーム受信結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamRead {
    /// 読み取ったバイト数
    pub len: usize,
    /// 最終サイズまで到達済みで未読データが無いか (リセット済みなら偽)
    pub fin: bool,
}

/// 所有データを返す受信結果
///
/// [`ReceiveStream::receive_vec`] と [`BidirectionalStream::receive_vec`] が返す。
/// `data` は受信したデータを所有する `Vec` であり、`fin` は最終サイズまで
/// 到達済みで未読データが無いことを表す。`data` が空でも `fin` が真なら
/// ストリームは正常終端している。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamChunk {
    /// 受信したデータ
    ///
    /// `receive_vec` に渡した `max_len` を超えない。`Vec` の容量は `max_len` を
    /// 超え得る。
    pub data: Vec<u8>,
    /// 最終サイズまで到達済みで未読データが無いか (リセット済みなら偽)
    pub fin: bool,
}

/// 送信 future を開始する
///
/// 入力は [`Arc`] で受け取り、通知ごとの再試行で複製しない。`AsyncWrite` の
/// 入力照合にも同じ [`Arc`] を使うため、書き込み開始時のコピーは 1 回で済む。
fn start_write(conn: SharedConnection, stream_id: u64, data: Arc<[u8]>, fin: bool) -> WriteFuture {
    // 実際の送信可否判定は connection driver 側で一元化する。
    Box::pin(async move {
        wait_for_command(&conn, |reply, on_block| Command::StreamSend {
            stream_id,
            data: Arc::clone(&data),
            fin,
            reply,
            on_block,
            accepted: None,
        })
        .await
        .map_err(into_stream_error)
    })
}

/// 呼び出し側の future から独立して完了できる送信操作
///
/// この操作を所有するタスクが [`Future`] を完了させる限り、呼び出し側の
/// `send` future をキャンセルしても driver はコマンドを処理し続ける。
/// 受理済みバイト数は [`Self::accepted_handle`] で取得した [`AtomicUsize`] に、
/// フロー制御の待機や UDP 出力の処理より前に記録される。
pub struct SendOperation {
    conn: SharedConnection,
    stream_id: u64,
    data: Arc<[u8]>,
    accepted: Arc<AtomicUsize>,
    future: Option<SendOperationFuture>,
}

impl std::fmt::Debug for SendOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendOperation")
            .field("stream_id", &self.stream_id)
            .field("accepted", &self.accepted())
            .finish_non_exhaustive()
    }
}

impl SendOperation {
    fn new(conn: SharedConnection, stream_id: u64, data: Arc<[u8]>) -> Self {
        Self {
            conn,
            stream_id,
            data,
            accepted: Arc::new(AtomicUsize::new(0)),
            future: None,
        }
    }

    /// 受理済みバイト数を共有するハンドルを返す
    ///
    /// 操作 future を待たずに、driver が記録した受理量を読み取れる。
    pub fn accepted_handle(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.accepted)
    }

    /// 現在記録されている受理済みバイト数を返す
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::Acquire)
    }
}

impl Future for SendOperation {
    type Output = Result<usize, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // 初回の poll でコマンドを送る。操作 future 自体をキャンセルしても
        // コマンドは driver に残るため、受理量は共有カウンタから回収できる。
        if self.future.is_none() {
            let conn = self.conn.clone();
            let stream_id = self.stream_id;
            let data = Arc::clone(&self.data);
            let accepted = Arc::clone(&self.accepted);
            self.future = Some(Box::pin(async move {
                wait_for_command(&conn, move |reply, on_block| Command::StreamSend {
                    stream_id,
                    data: Arc::clone(&data),
                    fin: false,
                    reply,
                    on_block,
                    accepted: Some(Arc::clone(&accepted)),
                })
                .await
                .map_err(into_stream_error)
            }));
        }
        self.future
            .as_mut()
            .expect("send future must exist after initialization")
            .as_mut()
            .poll(cx)
    }
}

fn start_shutdown(conn: SharedConnection, stream_id: u64) -> ShutdownFuture {
    // QUIC の FIN は空 payload + fin=true として扱う。
    Box::pin(async move {
        start_write(conn, stream_id, Arc::from(Vec::new()), true).await?;
        Ok(())
    })
}

fn start_read(conn: SharedConnection, stream_id: u64, capacity: usize) -> ReadFuture {
    // 空の確認と readable 待ちを同じ命令で登録し、受信進捗を取り逃さない。
    Box::pin(async move {
        wait_for_command(&conn, |reply, on_block| Command::StreamRecv {
            stream_id,
            len: capacity,
            reply,
            on_block,
        })
        .await
        .map_err(into_stream_error)
    })
}

/// 接続全体の終了通知をストリーム API の型付きエラーへ変換する。
fn into_stream_error(error: Error) -> Error {
    match error {
        Error::Connection(reason) => Error::Stream(StreamError::ConnectionLost(reason)),
        error => error,
    }
}

/// RESET_STREAM を送信する
///
/// 接続断は [`into_stream_error`] で、他のストリーム API と同じ
/// `StreamError::ConnectionLost` に揃える。
async fn send_reset(conn: SharedConnection, stream_id: u64, error_code: u64) -> Result<(), Error> {
    let (reply_tx, reply_rx) = oneshot::channel();
    conn.send(Command::ResetStream {
        stream_id,
        error_code,
        reply: reply_tx,
    })
    .await
    .map_err(|_| conn.send_failure_error())
    .map_err(into_stream_error)?;
    reply_rx
        .await
        .map_err(|_| conn.reply_dropped_error())
        .map_err(into_stream_error)?
}

/// RESET_STREAM_AT を送信する
///
/// draft-ietf-quic-reliable-stream-reset-11 Section 5。
/// 接続断は [`into_stream_error`] で、他のストリーム API と同じ
/// `StreamError::ConnectionLost` に揃える。
async fn send_reset_at(
    conn: SharedConnection,
    stream_id: u64,
    error_code: u64,
    reliable_size: u64,
) -> Result<(), Error> {
    let (reply_tx, reply_rx) = oneshot::channel();
    conn.send(Command::ResetStreamAt {
        stream_id,
        error_code,
        reliable_size,
        reply: reply_tx,
    })
    .await
    .map_err(|_| conn.send_failure_error())
    .map_err(into_stream_error)?;
    reply_rx
        .await
        .map_err(|_| conn.reply_dropped_error())
        .map_err(into_stream_error)?
}

/// STOP_SENDING を送信する
///
/// 接続断は [`into_stream_error`] で、他のストリーム API と同じ
/// `StreamError::ConnectionLost` に揃える。
async fn send_stop_sending(
    conn: SharedConnection,
    stream_id: u64,
    error_code: u64,
) -> Result<(), Error> {
    let (reply_tx, reply_rx) = oneshot::channel();
    conn.send(Command::StopSending {
        stream_id,
        error_code,
        reply: reply_tx,
    })
    .await
    .map_err(|_| conn.send_failure_error())
    .map_err(into_stream_error)?;
    reply_rx
        .await
        .map_err(|_| conn.reply_dropped_error())
        .map_err(into_stream_error)?
}

/// 送信ストリーム
///
/// `SendStream` は `Send + Sync` である。`&SendStream` をタスク間で共有でき、
/// async ブロック越しに保持できる。変更操作は `&mut self` を要求し、`&self`
/// で呼べるのは [`Self::id`] などの読み取り専用メソッドに限る。
///
/// `Debug` を実装しており、`stream_id` と `finished` などの安定した値だけを
/// 出力する。内部の future や channel は含まない。出力の形式は内部表現に
/// 依存せず、将来変わり得る。
///
/// # AsyncWrite
///
/// `AsyncWrite::poll_write` は、外側の `write` future がキャンセルされても
/// 内部の送信 future を破棄せず、次の `poll_write` で結果を回収する。保持中の
/// future と入力の対応は次の規則で扱う。
///
/// - 保持している future がある間、同じ入力で再び `poll_write` すると、その
///   future をそのまま再開する。送信は 1 回だけ行われる。
/// - 別の入力で `poll_write` すると、古い future を完了まで poll して結果を
///   破棄し、新しい入力用の future を作成してから poll する。古い入力の
///   `Ok(n)` やエラーを新しい入力の結果として返さない。
/// - 破棄した古い入力のデータは、既に driver へ渡って送信済みになっている
///   ことがある。future のキャンセルは送信自体を取り消さない。
/// - 空の入力は送信を開始せず `Ok(0)` を返す。進行中の future は保持し、
///   次の非 0 長の書き込みで回収する。
/// - 入力の同一性は内容で比較する。同じ内容を新規の書き込み意図で渡しても
///   「同じ入力の再開」とみなされるため、保持中の future がある間は新しい
///   意図の分を重ねて送らず、1 回分の結果だけを返すことがある。改めて
///   送信したい場合は、進行中の書き込みが完了してから呼ぶこと。
///
/// `send` / `send_all` / `send_fin` / `send_vectored` / `finish` /
/// `reset_stream` / `reset_stream_at` は `AsyncWrite` が保持する future を
/// 参照しない。これらの
/// ネイティブ API と `AsyncWrite` を同じストリームで混在させる場合、
/// `AsyncWrite` の future が進行中の間は混在させないこと。進行中の future が
/// ある状態でネイティブ API を呼ぶと、送信順序は driver がコマンドを受け取った
/// 順になり、`AsyncWrite` の結果とネイティブ API の結果の対応が保証されない。
/// `finish` / `send_fin` / `reset_stream` / `reset_stream_at` で送信側を終端
/// した後に `AsyncWrite` で書き込みを開始すると、終端済みのエラーが返る。
/// 終端前に開始して保持中の書き込みは、その完了結果を返し得る。
/// `AsyncWrite::poll_shutdown` も `poll_write` の future を参照しないため、
/// 進行中の書き込みがある間の混在は避けること。
pub struct SendStream {
    conn: SharedConnection,
    stream_id: u64,
    drop_error_code: u64,
    /// `AsyncWrite` が保持する進行中の送信
    ///
    /// 外側の `write` future がキャンセルされても破棄せず、次の書き込みで
    /// 完了結果を回収する。完了時は `None` にして入力と future の領域を解放する。
    write_in_flight: Option<WriteInFlight>,
    shutdown_future: Option<ShutdownFuture>,
    /// 送信側が終端したか (FIN・RESET_STREAM・RESET_STREAM_AT 送信済み)
    ///
    /// 終端後の drop で RESET_STREAM を送ると、ピアが FIN 済みの
    /// ストリームで RESET_STREAM を先に処理して受信データを読めなくなる。
    /// そのため終端済みの場合は drop 時の RESET_STREAM を送らない。
    ///
    /// このフラグは送信終端操作 (`send_fin` / `finish` / `reset_stream` /
    /// `reset_stream_at`) の完了を待ってから立てる。driver が終端フレームを
    /// 送信した後、完了応答を受け取る前に future をキャンセルした場合は
    /// 偽のまま残り、drop が RESET_STREAM を送ることがある。送信側の
    /// キャンセル安全性は別の課題として追跡する。
    finished: bool,
}

impl std::fmt::Debug for SendStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendStream")
            .field("stream_id", &self.stream_id)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl SendStream {
    pub(crate) fn new(conn: SharedConnection, stream_id: u64) -> Self {
        Self::with_finished(conn, stream_id, false)
    }

    /// 送信終端状態を引き継いでストリームを作る
    ///
    /// 送信側を FIN・RESET_STREAM・RESET_STREAM_AT のいずれかで終端した
    /// [`BidirectionalStream`] を [`BidirectionalStream::split`] するときに使う。
    /// 終端済みの状態を引き継がないと、drop 時に改めて RESET_STREAM を送ってしまう。
    /// 引き継ぐ状態は送信終端操作の完了時点の値であり、完了前に future を
    /// キャンセルした場合は終端状態が確定しないことがある。
    pub(crate) fn with_finished(conn: SharedConnection, stream_id: u64, finished: bool) -> Self {
        Self {
            conn,
            stream_id,
            drop_error_code: 0,
            write_in_flight: None,
            shutdown_future: None,
            finished,
        }
    }

    pub fn id(&self) -> u64 {
        self.stream_id
    }

    pub fn set_drop_error_code(&mut self, error_code: u64) {
        self.drop_error_code = error_code;
    }

    /// 呼び出し側から独立して完了できる送信操作を開始する
    ///
    /// 戻り値の [`SendOperation`] を所有するタスクが結果を回収する限り、
    /// 呼び出し側の future をキャンセルしても送信は継続する。受理済み
    /// バイト数は [`SendOperation::accepted_handle`] で参照できる。
    ///
    /// 送信順序は driver がコマンドを受け取った順になる。先行する操作の
    /// 完了を待たずに次の操作を開始すると、入力と結果の対応が保証されない。
    pub fn start_send(&mut self, data: &[u8]) -> SendOperation {
        SendOperation::new(self.conn.clone(), self.stream_id, Arc::from(data))
    }

    /// データを送信し、受理されたバイト数を返す
    ///
    /// フロー制御の制約で `data` の一部だけが受理されることがある。全量を
    /// 送るには [`Self::send_all`] を使う。非空の `data` に対して `Ok(0)` を
    /// 返すことはなく、送信可能になるまで driver が待って再試行する。
    pub async fn send(&mut self, data: &[u8]) -> Result<usize, Error> {
        start_write(self.conn.clone(), self.stream_id, Arc::from(data), false).await
    }

    /// データを全量送信する
    ///
    /// [`Self::send`] の部分受理を吸収し、`data` をすべて受理させるまで
    /// 繰り返す。フロー制御で一度に受理できない場合は、driver が送信可能に
    /// なるまで待って再試行する。空の `data` を渡した場合は何も送らずに
    /// `Ok(())` を返す。
    ///
    /// このメソッドは FIN を送らない。送信側を終端するには [`Self::finish`] か
    /// [`Self::send_fin`] を呼ぶ。`SendStream` は終端せずに drop すると
    /// RESET_STREAM を送る。`BidirectionalStream` には `Drop` が無いため、
    /// 送信側を終端するには `finish` か `reset_stream` を明示的に呼ぶ。
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルすると、それまでに受理されたバイト数は
    /// 呼び出し側へ返らない。再試行すると先頭から送り直すことになり、重複が
    /// 生じ得る。キャンセル後も残りを正確に送りたい場合は
    /// [`Self::start_send`] を使う。`SendOperation` をタスクに所有させ、
    /// [`SendOperation::accepted_handle`] で受理量を回収して残りを送る。
    /// `BidirectionalStream` には `start_send` が無いため、
    /// [`BidirectionalStream::split`] で `SendStream` を得る。
    pub async fn send_all(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut sent = 0;
        while sent < data.len() {
            let n = self.send(&data[sent..]).await?;
            if n == 0 {
                // `send` は非空データで Ok(0) を返さない契約だが、進捗のない
                // ループを避けるための防御的不変条件として扱う。
                return Err(Error::Internal("stream send returned zero progress".into()));
            }
            sent += n;
        }
        Ok(())
    }

    /// データを送信し、全データが受理された場合のみ FIN を送る
    ///
    /// 戻り値は受理されたバイト数である。フロー制御の制約で `data` の一部しか
    /// 受理されなかった場合、FIN は送られない。`data` が空の場合は FIN のみを
    /// 送る。部分的に受理された場合は、残りのデータを改めて送信する必要がある。
    ///
    /// 終端操作が成功したときだけ送信側の終端状態が確定する。完了応答を
    /// 受け取る前にこの future をキャンセルすると終端状態は確定せず、その後に
    /// drop すると RESET_STREAM を送ることがある。
    pub async fn send_fin(&mut self, data: &[u8]) -> Result<usize, Error> {
        let n = start_write(self.conn.clone(), self.stream_id, Arc::from(data), true).await?;
        // 全データを送り切ったときだけ FIN が送信されている
        if n == data.len() {
            self.finished = true;
        }
        Ok(n)
    }

    /// 複数バッファからデータを送信する (Vectored I/O)
    ///
    /// 全バッファを連結した先頭から受理されたバイト数を返す。フロー制御の
    /// 制約で一部だけが受理されることがある。全量を送るには [`Self::send_all`]
    /// を使うか、戻り値の分だけ先頭を進めて残りを送る。
    pub async fn send_vectored(&mut self, bufs: &[&[u8]]) -> Result<usize, Error> {
        let mut combined = Vec::new();
        for buf in bufs {
            combined.extend_from_slice(buf);
        }
        start_write(
            self.conn.clone(),
            self.stream_id,
            Arc::from(combined),
            false,
        )
        .await
    }

    /// FIN を送り、送信側を終端する
    ///
    /// FIN は現在の書き込みオフセットに記録する。未送信データが残っていれば
    /// 最後のデータフレームに FIN が載り、全データが送信済みのときだけ空
    /// payload の STREAM フレーム (fin=true) が別フレームになる。。終端操作が成功した
    /// ときだけ送信側の終端状態が確定する。完了応答を受け取る前にこの future を
    /// キャンセルすると終端状態は確定せず、その後に drop すると RESET_STREAM を
    /// 送ることがある。
    pub async fn finish(&mut self) -> Result<(), Error> {
        start_shutdown(self.conn.clone(), self.stream_id).await?;
        // FIN を送信したため送信側は終端した
        self.finished = true;
        Ok(())
    }

    /// ストリームをリセットする (RESET_STREAM フレームを送信する)
    ///
    /// 確定した peer transport parameter のフロー制御上限 (ストリーム上限・
    /// 接続上限) を Final Size が超える場合は `Err` を返す
    /// (RFC 9000 Section 19.9, 19.10)。
    ///
    /// 終端操作が成功したときだけ送信側の終端状態が確定する。完了応答を
    /// 受け取る前にこの future をキャンセルすると終端状態は確定せず、その後に
    /// drop すると RESET_STREAM を送ることがある。
    pub async fn reset_stream(&mut self, error_code: u64) -> Result<(), Error> {
        send_reset(self.conn.clone(), self.stream_id, error_code).await?;
        // RESET_STREAM を送信したため送信側は終端した
        self.finished = true;
        Ok(())
    }

    /// `reliable_size` までのデータ配信を保証してストリームをリセットする
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 5。ピアが
    /// `reset_stream_at` transport parameter を提示していない場合や、
    /// 既存の `final_size` を超える `reliable_size` を渡した場合は `Err` を返す。
    /// 既にリセットを送信済みで `error_code` が異なる場合も `Err` を返す
    /// (draft-ietf-quic-reliable-stream-reset-11 Section 5.2 MUST NOT)。
    /// 確定した peer transport parameter のフロー制御上限 (ストリーム上限・
    /// 接続上限) を Final Size が超える場合も `Err` を返す (同 Section 4 /
    /// RFC 9000 Section 19.9, 19.10)。0-RTT 拒否後に上限が縮小した場合などに
    /// 発生する。
    ///
    /// 終端操作が成功したときだけ送信側の終端状態が確定する。完了応答を
    /// 受け取る前にこの future をキャンセルすると終端状態は確定せず、その後に
    /// drop すると RESET_STREAM を送ることがある。
    pub async fn reset_stream_at(
        &mut self,
        error_code: u64,
        reliable_size: u64,
    ) -> Result<(), Error> {
        send_reset_at(self.conn.clone(), self.stream_id, error_code, reliable_size).await?;
        // RESET_STREAM_AT を送信したため送信側は終端した
        self.finished = true;
        Ok(())
    }
}

impl AsyncWrite for SendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        if buf.is_empty() {
            // 空の入力では送信を開始しない。進行中の送信 future は破棄せず、
            // 次の非 0 長の書き込みで結果を回収する。
            return Poll::Ready(Ok(0));
        }
        // キャンセル後に別の入力で再開した場合、保持中の future は古い入力の
        // 送信を追跡している。古い future を完了まで進めて結果を破棄しないと、
        // 古い入力の `Ok(n)` / `Err` を現在の入力の結果として返してしまう。
        if this
            .write_in_flight
            .as_ref()
            .is_some_and(|in_flight| in_flight.input.as_ref() != buf)
        {
            let in_flight = this
                .write_in_flight
                .as_mut()
                .expect("write in-flight must exist");
            match in_flight.future.as_mut().poll(cx) {
                Poll::Ready(_) => {
                    // 古い入力の送信結果は現在の入力に対応しないため破棄する。
                    // 中断した送信が既に driver に渡っている場合は、そのデータが
                    // 送信され得る。新しい入力は古い送信の後に送信される。
                    this.write_in_flight = None;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        if this.write_in_flight.is_none() {
            // 現在の入力で future を生成し、作成に使った入力を対応付けて保持する。
            // 入力は 1 回だけ複製し、future と照合用の `Arc` で共有する。
            let input: Arc<[u8]> = Arc::from(buf);
            let future = start_write(this.conn.clone(), this.stream_id, Arc::clone(&input), false);
            this.write_in_flight = Some(WriteInFlight { input, future });
        }

        let in_flight = this
            .write_in_flight
            .as_mut()
            .expect("write in-flight must exist after initialization");
        match in_flight.future.as_mut().poll(cx) {
            Poll::Ready(Ok(n)) => {
                // 完了した入力と future を解放する。`Option` を `None` にして
                // `Arc` の入力と future を drop し、その領域を返す。
                this.write_in_flight = None;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => {
                this.write_in_flight = None;
                Poll::Ready(Err(io::Error::other(e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        if this.shutdown_future.is_none() {
            this.shutdown_future = Some(start_shutdown(this.conn.clone(), this.stream_id));
        }

        let future = this
            .shutdown_future
            .as_mut()
            .expect("shutdown future must exist");
        match future.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                this.shutdown_future = None;
                // FIN を送信したため送信側は終端した
                this.finished = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                this.shutdown_future = None;
                Poll::Ready(Err(io::Error::other(e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for SendStream {
    fn drop(&mut self) {
        // FIN・RESET_STREAM・RESET_STREAM_AT で送信側が終端済みの場合、
        // 改めて RESET_STREAM を送る必要はない。送るとピアが受信データを読む前に
        // RESET_STREAM を処理してしまう競合を生む。
        //
        // 送信終端操作の future が完了前にキャンセルされると finished が偽の
        // まま残り、ここで RESET_STREAM を送る。送信側のキャンセル安全性は
        // 別の課題として追跡する。
        if self.finished {
            return;
        }
        let conn = self.conn.clone();
        let stream_id = self.stream_id;
        let error_code = self.drop_error_code;
        // `SendStream` drop は RESET_STREAM に対応づける。
        // drop をブロックしないため fire-and-forget で通知する。
        tokio::spawn(async move {
            let _ = send_reset(conn, stream_id, error_code).await;
        });
    }
}

/// 受信ストリーム
///
/// `ReceiveStream` は `Send + Sync` である。`&ReceiveStream` をタスク間で
/// 共有でき、async ブロック越しに保持できる。変更操作は `&mut self` を要求し、
/// `&self` で呼べるのは [`Self::id`] などの読み取り専用メソッドに限る。
///
/// # AsyncRead
///
/// `AsyncRead::poll_read` は `receive` / `receive_vectored` と同じ受信状態を
/// 共有する。同じストリームで両者を混在させても、読み取り順序を保ち、
/// データを失わない。
///
/// - キャンセル後に別の容量の [`ReadBuf`] で再開しても、保持済みの受信結果を
///   現在の `ReadBuf::remaining()` までコピーし、収まらない分は次の読み取りへ
///   持ち越す。最初の読み取りで確保した容量が現在の `ReadBuf` より大きくても、
///   容量を超えて書き込まない。
/// - `ReadBuf::remaining()` が 0 の読み取りは、新しい読み取りを開始せず
///   `Ready(Ok(()))` を 0 バイトで返す。進行中の読み取り future は保持し、
///   データも消費しない。0 長の `ReadBuf` では FIN の有無を観測できず、受信側
///   の終端状態も更新しない。EOF の確認には [`Self::receive`] に 0 長バッファを
///   渡す。
/// - FIN を観測した読み取りは、返せるデータがあればそれを返し、無ければ
///   0 バイトの `Ready(Ok(()))` で EOF を通知する。空のストリームでは、非 0 長
///   の読み取りが 0 バイトで完了して EOF になる。データを返し切った後の非 0 長
///   の読み取りも 0 バイトの `Ready(Ok(()))` を返し続ける。リセットを観測した
///   後の非 0 長の読み取りは、同じ `StreamError::Reset` を `io::Error` で
///   返し続ける。接続が終了しても、終端状態を観測済みならその状態を優先する。
/// - FIN が到着済みでも、0 長の読み取りだけでは終端状態を更新しないため、
///   そのままストリームを drop すると STOP_SENDING を送ることがある。
/// - ピアのリセットや接続終了は `io::Error` で返る。`io::Error::get_ref()` から
///   [`Error`] を取り出し、[`StreamError`] の variant を型で判定できる。
///
/// 読み取り結果の持ち越しとキャンセルの扱いは [`Self::receive`] と同じである。
pub struct ReceiveStream {
    conn: SharedConnection,
    stream_id: u64,
    drop_error_code: u64,
    /// `receive` / `receive_vectored` / `AsyncRead` が共有する受信状態
    ///
    /// 保持中の読み取り future と持ち越しデータを保持する。
    /// `AsyncRead::poll_read` と `receive` / `receive_vectored` を混在させても、
    /// 同じ状態を使うため読み取り順序が保たれる。
    recv: RecvState,
}

impl std::fmt::Debug for ReceiveStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiveStream")
            .field("stream_id", &self.stream_id)
            .field("terminal", &self.recv.terminal)
            .finish_non_exhaustive()
    }
}

impl ReceiveStream {
    pub(crate) fn new(conn: SharedConnection, stream_id: u64) -> Self {
        Self {
            conn,
            stream_id,
            drop_error_code: 0,
            recv: RecvState::new(),
        }
    }

    pub fn id(&self) -> u64 {
        self.stream_id
    }

    pub fn set_drop_error_code(&mut self, error_code: u64) {
        self.drop_error_code = error_code;
    }

    /// ストリームからデータを受信する
    ///
    /// データが届くまでは待つ。`buf` より短い読み取りになることがある。
    ///
    /// ピアが RESET_STREAM を送った場合でも、リセット前に受信してバッファ済みの
    /// 連続データは読み出せる。RFC 9000 Section 3.2 は受信済みデータの配信を
    /// 中断してよいとするため、バッファ済みデータを返し切るのは本実装の方針で
    /// ある。バッファ済みデータを読み切った後に
    /// `Error::Stream(StreamError::Reset)` が返り、リセットのエラーコード、
    /// 最終サイズ、Reliable Size を観測できる。ピアが RESET_STREAM_AT を送った
    /// 場合、Reliable Size までのデータを読み切った後に同じエラーが返り、
    /// `StreamError::Reset::reliable_size` が `Some(n)` になる。RESET_STREAM の
    /// 場合は `None` になる
    /// (draft-ietf-quic-reliable-stream-reset-11 Section 1 / Section 5)。
    ///
    /// FIN を観測した後の非 0 長受信は、data を伴わない
    /// `StreamRead { len: 0, fin: true }` を繰り返し返す。リセットを観測した
    /// 場合は、観測した `StreamError::Reset` を保持し、以後の非 0 長受信は
    /// driver を呼ばずに同じ `Error::Stream(StreamError::Reset)` を返す。
    /// 接続が終了しても、終端状態を観測済みならその状態を優先し、
    /// `ConnectionLost` で上書きしない。終端済みのストリームを drop しても
    /// STOP_SENDING は送らない。0 長受信は終端状態より優先し、リセット済みでも
    /// `(0, false)` を返す。
    ///
    /// `buf` の長さが 0 のときは読み取りを行わない。FIN まで到達済みで未読
    /// データが無ければ [`StreamRead::fin`] が真、それ以外は偽で返る。リセット
    /// 済みのストリームでは常に偽になる。この経路はパケット受信を行わないため、
    /// FIN の到着を観測するには呼び出し側で `drive()` を回す必要がある。
    /// キャンセルした読み取りが結果を保持している間は、その結果を追い越さない
    /// よう `fin` を返さず偽を返す。
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルしても、既に driver へ送信した受信要求の結果は
    /// 失われない。次に同じストリームへ `receive` を呼ぶと、キャンセル前に
    /// 到着していたデータから順に返す。キャンセルした呼び出しが確保していた
    /// 受信容量が次の `buf` より大きい場合、収まらない分は次の呼び出しへ
    /// 持ち越し、そのときの `fin` は偽になる。エラーで終了した場合は観測した
    /// エラーを保持し、以後の非 0 長受信は同じエラーを返す。0 長受信は終端状態
    /// より優先する。
    ///
    /// 同一ストリームで `AsyncRead` (`poll_read`) と `receive` /
    /// `receive_vectored` を混在させてもよい。両者は同じ受信状態を共有するため、
    /// 読み取り順序を保証し、データは失われない。
    ///
    /// キャンセルされた受信 future を保持したまま `stop_sending` した場合でも、
    /// 保持済みの受信結果は次の `receive` / `poll_read` で返る。
    ///
    /// 接続が終了した場合は `Error::Stream(StreamError::ConnectionLost)` を返す。
    /// driver が接続終了理由を残さずに停止した場合だけ `Error::Internal` になる。
    /// ただし、終端状態 (FIN / リセット) を観測済みならその状態を優先する。
    /// ただし、終端状態 (FIN / リセット) を観測済みならその状態を優先する。
    pub async fn receive(&mut self, buf: &mut [u8]) -> Result<StreamRead, Error> {
        self.recv.receive(&self.conn, self.stream_id, buf).await
    }

    /// 所有 `Vec` でデータを受信する
    ///
    /// `max_len` は 1 回の呼び出しで返すデータ長の上限であり、driver が確保する
    /// 受信バッファの大きさでもある。`data.len()` は `max_len` を超えない。
    /// 返る `Vec` の容量は、キャンセルされた読み取りが前回の容量で受信を再開した
    /// 場合に `max_len` を超え得る。持ち越しデータから取り出した場合は `max_len`
    /// 以下になる。
    ///
    /// データを返し切った後は `fin = true` の空の `StreamChunk` を返す。
    /// リセットを観測した場合は、[`Self::receive`] と同じ
    /// `Error::Stream(StreamError::Reset)` を返す。接続が終了した場合は
    /// [`StreamError::ConnectionLost`] を返すが、終端状態を観測済みならそれを
    /// 優先する。`max_len = 0` の扱いは [`Self::receive`] の 0 長受信と同じで、
    /// 終端状態より優先し、リセット済みでも `Ok` で `fin = false` を返す。
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルしても、保持している読み取り future の結果は
    /// 失われない。次の `receive` / `receive_vec` / `poll_read` で回収できる。
    pub async fn receive_vec(&mut self, max_len: usize) -> Result<StreamChunk, Error> {
        self.recv
            .receive_vec(&self.conn, self.stream_id, max_len)
            .await
    }

    /// 複数バッファにデータを受信する (Vectored I/O)
    ///
    /// 受信したデータは先頭のバッファから順に埋め、合計長を超える分は次の
    /// 呼び出しへ持ち越す。バッファ単位の区切りは保証しない。
    ///
    /// 合計長が 0 のときの挙動は [`ReceiveStream::receive`] と同じである。
    /// キャンセルした読み取りが結果を保持している間は `fin` を返さない。
    /// RESET_STREAM / RESET_STREAM_AT の扱いとエラー終端も
    /// [`ReceiveStream::receive`] と同じである。
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルしても受信データは失われない。次に同じストリームへ
    /// `receive_vectored` を呼ぶと、キャンセル前に到着していたデータから順に返す。
    /// キャンセルした呼び出しが確保していた受信容量が次のバッファの合計長より
    /// 大きい場合、収まらない分は次の呼び出しへ持ち越し、そのときの `fin` は
    /// 偽になる。エラーで終了した場合は観測したエラーを保持し、以後の非 0 長
    /// 受信は同じエラーを返す。0 長受信は終端状態より優先する。
    ///
    /// 同一ストリームで `AsyncRead` (`poll_read`) と `receive` /
    /// `receive_vectored` を混在させてもよい。両者は同じ受信状態を共有するため、
    /// 読み取り順序を保証し、データは失われない。
    ///
    /// キャンセルされた受信 future を保持したまま `stop_sending` した場合でも、
    /// 保持済みの受信結果は次の `receive_vectored` / `poll_read` で返る。
    ///
    /// 接続が終了した場合は `Error::Stream(StreamError::ConnectionLost)` を返す。
    /// driver が接続終了理由を残さずに停止した場合だけ `Error::Internal` になる。
    /// ただし、終端状態 (FIN / リセット) を観測済みならその状態を優先する。
    pub async fn receive_vectored(&mut self, bufs: &mut [&mut [u8]]) -> Result<StreamRead, Error> {
        self.recv
            .receive_vectored(&self.conn, self.stream_id, bufs)
            .await
    }

    /// ピアに STOP_SENDING を送り、受信側を終端する
    ///
    /// STOP_SENDING はピアの送信側にデータ送信の中止を要求する
    /// (RFC 9000 Section 3.5, Section 19.5)。送信の中止を要求しても、受信
    /// バッファに溜まっているデータは引き続き `receive` / `receive_vectored` /
    /// `poll_read` で読み出せる。STOP_SENDING は受信データの無視を保証しないため
    /// (同 Section 3.5)、本実装は受信済みデータの配信を中断しない方針を採る
    /// (同 Section 3.2 は中断してよいとする)。終端済みの受信側で drop しても、
    /// 改めて STOP_SENDING を送らない。キャンセルされた受信の結果を保持して
    /// いる場合は、次の `receive` / `receive_vectored` / `poll_read` で回収できる。
    /// ピアから受信した STOP_SENDING の観測は
    /// [`crate::connection::Connection::accept_stop_sending`] を使う。
    ///
    /// 終端状態を観測済みの場合、このメソッドは終端理由を上書きしない。
    /// リセットを観測済みなら transport が `ResetRead` のためエラーを返す
    /// ことがあるが、その場合も受信側の `StreamError::Reset` は失われない。
    /// エラーは無視してよい。
    pub async fn stop_sending(&mut self, error_code: u64) -> Result<(), Error> {
        send_stop_sending(self.conn.clone(), self.stream_id, error_code).await?;
        // 明示的に STOP_SENDING を送ったため受信側は終端した。既に FIN /
        // リセットを観測している場合は、その終端理由を失わせない。
        if !self.recv.terminal.is_terminal() {
            self.recv.terminal = TerminalState::Other;
        }
        Ok(())
    }
}

impl AsyncRead for ReceiveStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        // receive / receive_vectored と同じ受信状態を使い、混在時も順序を保つ。
        this.recv.poll_read(&this.conn, this.stream_id, cx, buf)
    }
}

impl Drop for ReceiveStream {
    fn drop(&mut self) {
        // FIN 到達済み・リセット受信済み・明示的な STOP_SENDING 済みの場合、
        // 改めて STOP_SENDING を送る必要はない。送るとピアが RESET_STREAM を
        // 返して不要な競合を生む。
        if self.recv.terminal.is_terminal() {
            return;
        }
        let conn = self.conn.clone();
        let stream_id = self.stream_id;
        let error_code = self.drop_error_code;
        // 受信を途中で捨てたことを peer に伝えるため STOP_SENDING を送る。
        tokio::spawn(async move {
            let _ = send_stop_sending(conn, stream_id, error_code).await;
        });
    }
}

/// 双方向ストリーム
///
/// `BidirectionalStream` は `Send + Sync` である。`&BidirectionalStream` を
/// タスク間で共有でき、async ブロック越しに保持できる。変更操作は `&mut self`
/// を要求し、`&self` で呼べるのは [`Self::id`] などの読み取り専用メソッドに
/// 限る。
pub struct BidirectionalStream {
    conn: SharedConnection,
    stream_id: u64,
    /// `receive` / `receive_vectored` の受信状態
    ///
    /// [`Self::split`] ではこの状態を丸ごと [`ReceiveStream`] へ移し、
    /// 受信の終端判定も引き継ぐ。
    recv: RecvState,
    /// 送信側が終端したか (FIN・RESET_STREAM・RESET_STREAM_AT 送信済み)
    ///
    /// [`Self::split`] で [`SendStream`] へ引き継ぐ。引き継がないと、分割後の
    /// drop で RESET_STREAM を送り、ピアが FIN 済みの受信データを読めなくなる。
    ///
    /// このフラグは送信終端操作 (`send_fin` / `finish` / `reset` /
    /// `reset_stream_at`) の完了を待ってから立てる。driver が終端フレームを
    /// 送信した後、完了応答を受け取る前に future をキャンセルした場合は
    /// 偽のまま残り、分割後の drop が RESET_STREAM を送ることがある。送信側の
    /// キャンセル安全性は別の課題として追跡する。
    finished: bool,
}

impl std::fmt::Debug for BidirectionalStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BidirectionalStream")
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}

impl BidirectionalStream {
    pub(crate) fn new(conn: SharedConnection, stream_id: u64) -> Self {
        Self {
            conn,
            stream_id,
            recv: RecvState::new(),
            finished: false,
        }
    }

    pub fn id(&self) -> u64 {
        self.stream_id
    }

    /// 送信側と受信側に分割する
    ///
    /// キャンセルされた受信の進行状態も受信側へ引き継ぐ。分割前に受信 future を
    /// キャンセルしていても、分割後の [`ReceiveStream::receive`] でデータを
    /// 回収できる。受信側が終端していれば、その終端状態も引き継ぐため、分割後の
    /// drop で不要な STOP_SENDING を送らない。
    ///
    /// 送信側の終端状態も引き継ぐ。分割前に FIN・RESET_STREAM・RESET_STREAM_AT を
    /// 送っていれば、分割後の [`SendStream`] を drop しても RESET_STREAM を送らない。
    /// ただし送信終端操作の future を完了前にキャンセルした場合は終端状態が
    /// 確定しないことがあり、分割後の drop が RESET_STREAM を送ることがある。
    pub fn split(self) -> (SendStream, ReceiveStream) {
        // split 後も同一 stream ID を共有し、状態管理は driver task が担う。
        let Self {
            conn,
            stream_id,
            recv,
            finished,
        } = self;
        let send = SendStream::with_finished(conn.clone(), stream_id, finished);
        let mut receiver = ReceiveStream::new(conn, stream_id);
        receiver.recv = recv;
        (send, receiver)
    }

    /// データを送信し、受理されたバイト数を返す
    ///
    /// フロー制御の制約で `data` の一部だけが受理されることがある。全量を
    /// 送るには [`Self::send_all`] を使う。非空の `data` に対して `Ok(0)` を
    /// 返すことはなく、送信可能になるまで driver が待って再試行する。
    pub async fn send(&mut self, data: &[u8]) -> Result<usize, Error> {
        start_write(self.conn.clone(), self.stream_id, Arc::from(data), false).await
    }

    /// データを全量送信する
    ///
    /// [`Self::send`] の部分受理を吸収し、`data` をすべて受理させるまで
    /// 繰り返す。フロー制御で一度に受理できない場合は、driver が送信可能に
    /// なるまで待って再試行する。空の `data` を渡した場合は何も送らずに
    /// `Ok(())` を返す。
    ///
    /// このメソッドは FIN を送らない。送信側を終端するには [`Self::finish`] か
    /// [`Self::send_fin`] を呼ぶ。`SendStream` は終端せずに drop すると
    /// RESET_STREAM を送る。`BidirectionalStream` には `Drop` が無いため、
    /// 送信側を終端するには `finish` か `reset_stream` を明示的に呼ぶ。
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルすると、それまでに受理されたバイト数は
    /// 呼び出し側へ返らない。再試行すると先頭から送り直すことになり、重複が
    /// 生じ得る。キャンセル後も残りを正確に送りたい場合は
    /// [`SendStream::start_send`] を使う。`SendOperation` をタスクに所有させ、
    /// [`SendOperation::accepted_handle`] で受理量を回収して残りを送る。
    /// `BidirectionalStream` には `start_send` が無いため、
    /// [`BidirectionalStream::split`] で `SendStream` を得る。
    pub async fn send_all(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut sent = 0;
        while sent < data.len() {
            let n = self.send(&data[sent..]).await?;
            if n == 0 {
                // `send` は非空データで Ok(0) を返さない契約だが、進捗のない
                // ループを避けるための防御的不変条件として扱う。
                return Err(Error::Internal("stream send returned zero progress".into()));
            }
            sent += n;
        }
        Ok(())
    }

    /// データを送信し、全データが受理された場合のみ FIN を送る
    ///
    /// 戻り値は受理されたバイト数である。フロー制御の制約で `data` の一部しか
    /// 受理されなかった場合、FIN は送られない。`data` が空の場合は FIN のみを
    /// 送る。部分的に受理された場合は、残りのデータを改めて送信する必要がある。
    ///
    /// 終端操作が成功したときだけ送信側の終端状態が確定する。完了応答を
    /// 受け取る前にこの future をキャンセルすると終端状態は確定せず、その後に
    /// drop すると RESET_STREAM を送ることがある。
    pub async fn send_fin(&mut self, data: &[u8]) -> Result<usize, Error> {
        let n = start_write(self.conn.clone(), self.stream_id, Arc::from(data), true).await?;
        // 全データを送り切ったときだけ FIN が送信されている
        if n == data.len() {
            self.finished = true;
        }
        Ok(n)
    }

    /// 複数バッファからデータを送信する (Vectored I/O)
    ///
    /// 全バッファを連結した先頭から受理されたバイト数を返す。フロー制御の
    /// 制約で一部だけが受理されることがある。全量を送るには [`Self::send_all`]
    /// を使うか、戻り値の分だけ先頭を進めて残りを送る。
    pub async fn send_vectored(&mut self, bufs: &[&[u8]]) -> Result<usize, Error> {
        let mut combined = Vec::new();
        for buf in bufs {
            combined.extend_from_slice(buf);
        }
        start_write(
            self.conn.clone(),
            self.stream_id,
            Arc::from(combined),
            false,
        )
        .await
    }

    /// FIN を送り、送信側を終端する
    ///
    /// FIN は現在の書き込みオフセットに記録する。未送信データが残っていれば
    /// 最後のデータフレームに FIN が載り、全データが送信済みのときだけ空
    /// payload の STREAM フレーム (fin=true) が別フレームになる。。終端操作が成功した
    /// ときだけ送信側の終端状態が確定する。完了応答を受け取る前にこの future を
    /// キャンセルすると終端状態は確定せず、その後に drop すると RESET_STREAM を
    /// 送ることがある。
    pub async fn finish(&mut self) -> Result<(), Error> {
        start_shutdown(self.conn.clone(), self.stream_id).await?;
        // FIN を送信したため送信側は終端した
        self.finished = true;
        Ok(())
    }

    /// ストリームからデータを受信する
    ///
    /// データが届くまでは待つ。`buf` より短い読み取りになることがある。
    ///
    /// ピアが RESET_STREAM を送った場合でも、リセット前に受信してバッファ済みの
    /// 連続データは読み出せる。RFC 9000 Section 3.2 は受信済みデータの配信を
    /// 中断してよいとするため、バッファ済みデータを返し切るのは本実装の方針で
    /// ある。バッファ済みデータを読み切った後に
    /// `Error::Stream(StreamError::Reset)` が返り、リセットのエラーコード、
    /// 最終サイズ、Reliable Size を観測できる。ピアが RESET_STREAM_AT を送った
    /// 場合、Reliable Size までのデータを読み切った後に同じエラーが返り、
    /// `StreamError::Reset::reliable_size` が `Some(n)` になる。RESET_STREAM の
    /// 場合は `None` になる
    /// (draft-ietf-quic-reliable-stream-reset-11 Section 1 / Section 5)。
    ///
    /// 受信側はエラーを観測した時点で終端し、観測した `StreamError::Reset` を
    /// 保持する。以後の非 0 長受信は driver を呼ばずに同じ
    /// `Error::Stream(StreamError::Reset)` を返す。接続が終了しても、終端状態を
    /// 観測済みならその状態を優先し、`ConnectionLost` で上書きしない。0 長受信は
    /// 終端状態より優先し、リセット済みでも `(0, false)` を返す。
    ///
    /// `buf` の長さが 0 のときは読み取りを行わない。FIN まで到達済みで未読
    /// データが無ければ [`StreamRead::fin`] が真、それ以外は偽で返る。リセット
    /// 済みのストリームでは常に偽になる。この経路はパケット受信を行わないため、
    /// FIN の到着を観測するには呼び出し側で `drive()` を回す必要がある。
    /// キャンセルした読み取りが結果を保持している間は、その結果を追い越さない
    /// よう `fin` を返さず偽を返す。
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルしても、既に driver へ送信した受信要求の結果は
    /// 失われない。次に同じストリームへ `receive` を呼ぶと、キャンセル前に
    /// 到着していたデータから順に返す。キャンセルした呼び出しが確保していた
    /// 受信容量が次の `buf` より大きい場合、収まらない分は次の呼び出しへ
    /// 持ち越し、そのときの `fin` は偽になる。エラーで終了した場合は観測した
    /// エラーを保持し、以後の非 0 長受信は同じエラーを返す。0 長受信は終端状態
    /// より優先する。
    ///
    /// キャンセルされた受信 future を保持したまま `stop_sending` した場合でも、
    /// 保持済みの受信結果は次の `receive` で返る。
    ///
    /// 接続が終了した場合は `Error::Stream(StreamError::ConnectionLost)` を返す。
    /// driver が接続終了理由を残さずに停止した場合だけ `Error::Internal` になる。
    /// ただし、終端状態 (FIN / リセット) を観測済みならその状態を優先する。
    pub async fn receive(&mut self, buf: &mut [u8]) -> Result<StreamRead, Error> {
        self.recv.receive(&self.conn, self.stream_id, buf).await
    }

    /// 所有 `Vec` でデータを受信する
    ///
    /// `max_len` は 1 回の呼び出しで返すデータ長の上限であり、driver が確保する
    /// 受信バッファの大きさでもある。`data.len()` は `max_len` を超えない。
    /// 返る `Vec` の容量は、キャンセルされた読み取りが前回の容量で受信を再開した
    /// 場合に `max_len` を超え得る。持ち越しデータから取り出した場合は `max_len`
    /// 以下になる。
    ///
    /// データを返し切った後は `fin = true` の空の `StreamChunk` を返す。
    /// リセットを観測した場合は、[`Self::receive`] と同じ
    /// `Error::Stream(StreamError::Reset)` を返す。接続が終了した場合は
    /// [`StreamError::ConnectionLost`] を返すが、終端状態を観測済みならそれを
    /// 優先する。`max_len = 0` の扱いは [`Self::receive`] の 0 長受信と同じで、
    /// 終端状態より優先し、リセット済みでも `Ok` で `fin = false` を返す。
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルしても、保持している読み取り future の結果は
    /// 失われない。次の `receive` / `receive_vec` / `poll_read` で回収できる。
    pub async fn receive_vec(&mut self, max_len: usize) -> Result<StreamChunk, Error> {
        self.recv
            .receive_vec(&self.conn, self.stream_id, max_len)
            .await
    }

    /// 複数バッファにデータを受信する (Vectored I/O)
    ///
    /// 受信したデータは先頭のバッファから順に埋め、合計長を超える分は次の
    /// 呼び出しへ持ち越す。バッファ単位の区切りは保証しない。
    ///
    /// 合計長が 0 のときの挙動は [`BidirectionalStream::receive`] と同じである。
    /// キャンセルした読み取りが結果を保持している間は `fin` を返さない。
    /// RESET_STREAM / RESET_STREAM_AT の扱いとエラー終端も
    /// [`BidirectionalStream::receive`] と同じである。
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルしても受信データは失われない。次に同じストリームへ
    /// `receive_vectored` を呼ぶと、キャンセル前に到着していたデータから順に返す。
    /// キャンセルした呼び出しが確保していた受信容量が次のバッファの合計長より
    /// 大きい場合、収まらない分は次の呼び出しへ持ち越し、そのときの `fin` は
    /// 偽になる。エラーで終了した場合は観測したエラーを保持し、以後の非 0 長
    /// 受信は同じエラーを返す。0 長受信は終端状態より優先する。
    ///
    /// キャンセルされた受信 future を保持したまま `stop_sending` した場合でも、
    /// 保持済みの受信結果は次の `receive_vectored` で返る。
    ///
    /// 接続が終了した場合は `Error::Stream(StreamError::ConnectionLost)` を返す。
    /// driver が接続終了理由を残さずに停止した場合だけ `Error::Internal` になる。
    /// ただし、終端状態 (FIN / リセット) を観測済みならその状態を優先する。
    pub async fn receive_vectored(&mut self, bufs: &mut [&mut [u8]]) -> Result<StreamRead, Error> {
        self.recv
            .receive_vectored(&self.conn, self.stream_id, bufs)
            .await
    }

    /// ストリームをリセットする (RESET_STREAM フレームを送信する)
    ///
    /// 確定した peer transport parameter のフロー制御上限 (ストリーム上限・
    /// 接続上限) を Final Size が超える場合は `Err` を返す
    /// (RFC 9000 Section 19.9, 19.10)。成功すると送信側は終端する。
    pub async fn reset(&mut self, error_code: u64) -> Result<(), Error> {
        send_reset(self.conn.clone(), self.stream_id, error_code).await?;
        // RESET_STREAM を送信したため送信側は終端した
        self.finished = true;
        Ok(())
    }

    /// ストリームをリセットする (RESET_STREAM フレームを送信する)
    ///
    /// [`Self::reset`] と同じ。確定した peer transport parameter のフロー制御
    /// 上限 (ストリーム上限・接続上限) を Final Size が超える場合は `Err` を返す
    /// (RFC 9000 Section 19.9, 19.10)。
    ///
    /// 終端操作が成功したときだけ送信側の終端状態が確定する。完了応答を
    /// 受け取る前にこの future をキャンセルすると終端状態は確定せず、その後に
    /// drop すると RESET_STREAM を送ることがある。
    pub async fn reset_stream(&mut self, error_code: u64) -> Result<(), Error> {
        self.reset(error_code).await
    }

    /// `reliable_size` までのデータ配信を保証してストリームをリセットする
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 5。
    /// ピアが `reset_stream_at` transport parameter を提示していない場合や、
    /// 既存の `final_size` を超える `reliable_size` を渡した場合は `Err` を返す。
    /// 既にリセットを送信済みで `error_code` が異なる場合も `Err` を返す
    /// (draft-ietf-quic-reliable-stream-reset-11 Section 5.2 MUST NOT)。
    /// 確定した peer transport parameter のフロー制御上限 (ストリーム上限・
    /// 接続上限) を Final Size が超える場合も `Err` を返す (同 Section 4 /
    /// RFC 9000 Section 19.9, 19.10)。0-RTT 拒否後に上限が縮小した場合などに
    /// 発生する。`reliable_size` が以前の値より大きい場合は仕様 Section 5.2 に
    /// 従い無視される (戻り値は `Ok`)。成功すると送信側は終端する。
    ///
    /// 終端操作が成功したときだけ送信側の終端状態が確定する。完了応答を
    /// 受け取る前にこの future をキャンセルすると終端状態は確定せず、その後に
    /// drop すると RESET_STREAM を送ることがある。
    pub async fn reset_stream_at(
        &mut self,
        error_code: u64,
        reliable_size: u64,
    ) -> Result<(), Error> {
        send_reset_at(self.conn.clone(), self.stream_id, error_code, reliable_size).await?;
        // RESET_STREAM_AT を送信したため送信側は終端した
        self.finished = true;
        Ok(())
    }

    /// ピアに STOP_SENDING を送り、受信側を終端する
    ///
    /// STOP_SENDING はピアの送信側にデータ送信の中止を要求する
    /// (RFC 9000 Section 3.5, Section 19.5)。送信側の終端状態は変化しない。
    /// 送信の中止を要求しても、受信バッファに溜まっているデータは引き続き
    /// `receive` / `receive_vectored` で読み出せる。STOP_SENDING は受信データの
    /// 無視を保証しないため (同 Section 3.5)、本実装は受信済みデータの配信を
    /// 中断しない方針を採る (同 Section 3.2 は中断してよいとする)。終端済みの
    /// 受信側で drop しても、改めて STOP_SENDING を送らない。キャンセルされた
    /// 受信の結果を保持している場合は、次の `receive` / `receive_vectored` で
    /// 回収できる。ピアから受信した STOP_SENDING の観測は
    /// [`crate::connection::Connection::accept_stop_sending`] を使う。
    pub async fn stop_sending(&mut self, error_code: u64) -> Result<(), Error> {
        send_stop_sending(self.conn.clone(), self.stream_id, error_code).await?;
        // 明示的に STOP_SENDING を送ったため受信側は終端した。分割後の
        // ReceiveStream の drop で STOP_SENDING を二重に送らない。既に FIN /
        // リセットを観測している場合は、その終端理由を失わせない。
        if !self.recv.terminal.is_terminal() {
            self.recv.terminal = TerminalState::Other;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
