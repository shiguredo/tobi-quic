// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! HTTP/3 と拡張プロトコルが共有する制御ストリームと QUIC I/O。

use shiguredo_http3::{ClientConnection, H3InitData, Settings};
use tobi_quic::{ReceiveStream, SendStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::Error;

/// QUIC 受信ストリームで観測したイベント。
#[derive(Debug)]
pub enum ReadEvent {
    /// データを受信した。
    Data {
        /// QUIC ストリーム ID。
        stream_id: u64,
        /// 受信したバイト列。
        data: Vec<u8>,
    },
    /// FIN を受信した。
    Fin {
        /// QUIC ストリーム ID。
        stream_id: u64,
    },
    /// RESET_STREAM を受信した。
    Reset {
        /// QUIC ストリーム ID。
        stream_id: u64,
        /// ピアが通知したアプリケーションエラーコード。
        error_code: u64,
        /// ピアが通知した最終サイズ。
        final_size: u64,
    },
    /// QUIC 接続が終了した。正常終了と障害の種別を保持する。
    ConnectionClosed {
        /// 終了したストリーム ID。
        stream_id: u64,
        /// QUIC の終了理由。
        reason: tobi_quic::ConnectionError,
    },
    /// ストリームの読み取りが失敗した。
    Failed {
        /// QUIC ストリーム ID。
        stream_id: u64,
        /// QUIC のエラー内容。
        message: String,
    },
}

/// HTTP/3 の制御、QPACK encoder、QPACK decoder の送信ストリーム。
pub struct ControlStreams {
    control: SendStream,
    encoder: SendStream,
    decoder: SendStream,
}

impl ControlStreams {
    /// QUIC がストリームの開設を許可するまで待ち、3 本を順に開く。
    pub async fn open(connection: &tobi_quic::Connection) -> Result<Self, Error> {
        Ok(Self {
            control: connection.open_send_stream_wait().await?,
            encoder: connection.open_send_stream_wait().await?,
            decoder: connection.open_send_stream_wait().await?,
        })
    }

    /// 制御、encoder、decoder の順でストリーム ID を返す。
    pub fn ids(&self) -> [u64; 3] {
        [self.control.id(), self.encoder.id(), self.decoder.id()]
    }

    /// クライアントの HTTP/3 状態機械を初期化し、SETTINGS と QPACK の初期データを送る。
    pub async fn client(
        connection: &tobi_quic::Connection,
        settings: Settings,
    ) -> Result<(ClientConnection, Self), Error> {
        if connection.application_protocol().await.as_deref() != Some(b"h3") {
            return Err(Error::InvalidAlpn);
        }
        let mut streams = Self::open(connection).await?;
        let ids = streams.ids();
        let mut state = ClientConnection::new(settings);
        let init = state.init_h3_streams(ids[0], ids[1], ids[2])?;
        streams.send_initial(&init).await?;
        Ok((state, streams))
    }

    /// 初期化データを全バイト送る。QUIC の部分書き込みを内部で扱う。
    pub async fn send_initial(&mut self, init: &H3InitData) -> Result<(), Error> {
        write_all(&mut self.control, &init.control_data).await?;
        write_all(&mut self.encoder, &init.encoder_data).await?;
        write_all(&mut self.decoder, &init.decoder_data).await
    }

    /// 制御と QPACK の送信待ちデータを QUIC へ流す。
    pub async fn flush_client(&mut self, state: &mut ClientConnection) -> Result<(), Error> {
        for stream in [&mut self.control, &mut self.encoder, &mut self.decoder] {
            flush_client_stream(state, stream).await?;
        }
        Ok(())
    }

    /// 汎用の接続ドライバーへ 3 本の所有権を渡す。
    pub fn into_streams(self) -> [SendStream; 3] {
        [self.control, self.encoder, self.decoder]
    }
}

/// HTTP/3 が生成したストリームのデータと FIN を送る。
pub async fn flush_client_stream(
    state: &mut ClientConnection,
    stream: &mut SendStream,
) -> Result<(), Error> {
    while let Some((data, fin)) = state.take_stream_data(stream.id()) {
        if fin {
            write_all_fin(stream, &data).await?;
            break;
        }
        write_all(stream, &data).await?;
    }
    Ok(())
}

/// キャンセルせずに呼び出し、バイト列全体を書き終えるまで待つ。
pub async fn write_all(stream: &mut SendStream, mut data: &[u8]) -> Result<(), Error> {
    while !data.is_empty() {
        let length = stream.send(data).await?;
        if length == 0 {
            return Err(Error::Closed("stream accepted zero bytes".into()));
        }
        data = &data[length..];
    }
    Ok(())
}

/// 全バイトを送り、最後に受理されるデータと同じ送信操作で FIN を確定する。
///
/// 部分書き込みでは未送信分を再試行する。空のデータでは FIN だけを送る。
/// 終端状態の確定まで、キャンセルせずに完了を待つこと。
pub async fn write_all_fin(stream: &mut SendStream, mut data: &[u8]) -> Result<(), Error> {
    loop {
        let length = stream.send_fin(data).await?;
        if length == data.len() {
            return Ok(());
        }
        if length == 0 {
            return Err(Error::Closed("stream accepted zero bytes".into()));
        }
        data = &data[length..];
    }
}

/// 受信ストリームを読み、上限付きチャネルへイベントを送るタスクを起動する。
///
/// 呼び出し側が JoinHandle を所有し、中断時は abort する。drop_error_code は
/// 読み取り中断時に送る STOP_SENDING のアプリケーションエラーコードである。
pub fn spawn_reader(
    mut recv: ReceiveStream,
    sender: mpsc::Sender<ReadEvent>,
    drop_error_code: u64,
) -> JoinHandle<()> {
    recv.set_drop_error_code(drop_error_code);
    tokio::spawn(async move {
        let stream_id = recv.id();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            match recv.receive(&mut buffer).await {
                Ok(read) => {
                    if read.len > 0
                        && sender
                            .send(ReadEvent::Data {
                                stream_id,
                                data: buffer[..read.len].to_vec(),
                            })
                            .await
                            .is_err()
                    {
                        return;
                    }
                    if read.fin {
                        let _ = sender.send(ReadEvent::Fin { stream_id }).await;
                        return;
                    }
                }
                // HTTP/3 と WebTransport は Reliable Size を使わないため、
                // `reliable_size: _` で受け取り、フィールド追加を網羅的に検出する。
                Err(tobi_quic::Error::Stream(tobi_quic::StreamError::Reset {
                    error_code,
                    final_size,
                    reliable_size: _,
                })) => {
                    let _ = sender
                        .send(ReadEvent::Reset {
                            stream_id,
                            error_code,
                            final_size,
                        })
                        .await;
                    return;
                }
                Err(tobi_quic::Error::Connection(reason))
                | Err(tobi_quic::Error::Stream(tobi_quic::StreamError::ConnectionLost(reason))) => {
                    let _ = sender
                        .send(ReadEvent::ConnectionClosed { stream_id, reason })
                        .await;
                    return;
                }
                Err(error) => {
                    let _ = sender
                        .send(ReadEvent::Failed {
                            stream_id,
                            message: error.to_string(),
                        })
                        .await;
                    return;
                }
            }
        }
    })
}
