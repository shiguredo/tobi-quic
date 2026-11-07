// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! tobi-webtransport — tobi-http3 を使った WebTransport over HTTP/3 の結線
//!
//! tobi-http3 の制御ストリーム、QPACK、QUIC I/O を使い、WebTransport over
//! HTTP/3 のクライアントとサーバーを提供する。
//! draft-ietf-webtrans-http3 の draft-02 / 07 / 14 / 15 に対応する。
//!
//! # 前提
//!
//! QUIC 層は次の前提を満たす必要がある。ALPN 以外は
//! [`client::Client::builder`] を使うと自動的に設定される。
//!
//! - ALPN が `h3`
//!   ([`client::ClientBuilder::with_tls_config`] は自動設定する。
//!   [`client::ClientBuilder::with_tls`] を使う場合は呼び出し側で設定する)
//! - `max_datagram_frame_size > 0` を広告する
//! - draft-14 / 15 では `reset_stream_at` transport parameter を広告する
//!
//! # 使い方
//!
//! ```no_run
//! use tobi_quic::{Connect, IoConfig};
//! use tobi_webtransport::client::{Client, ClientConfig};
//!
//! # async fn example(tls: std::sync::Arc<rustls::ClientConfig>) -> Result<(), Box<dyn std::error::Error>> {
//! let client = Client::builder()
//!     .with_tls_config(tls)
//!     .with_io(IoConfig::new("0.0.0.0:0".parse()?))
//!     .start()?;
//!
//! let mut session = client
//!     .connect(
//!         Connect::new("127.0.0.1:4443".parse()?, "localhost"),
//!         ClientConfig::new("localhost", "/"),
//!     )
//!     .await?;
//!
//! let mut stream = session.open_bidirectional_stream().await?;
//! stream.send(b"hello").await?;
//! stream.finish().await?;
//! while let Some(data) = stream.recv().await? {
//!     println!("received {} bytes", data.len());
//! }
//!
//! session.close(0, "done").await?;
//! let _ = session.wait_closed().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # セッションの終了
//!
//! [`session::Session::close`] は WT_CLOSE_SESSION を送って CONNECT ストリームを FIN で
//! 閉じ、ピアの CONNECT ストリーム終了を待ってから QUIC 接続を閉じる。
//! セッションをドロップしただけでも、ドライバーがクローズコード 0 で同じ処理を
//! 行う。[`session::Session::wait_closed`] は、RESET_STREAM やセッションエラーで
//! 異常終了した場合は [`error::Error::SessionAborted`] を返す。

pub mod client;
pub mod error;
pub mod server;
pub mod session;
pub mod stream;

mod driver;
