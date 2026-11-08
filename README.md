# tobi-quic

[![crates.io](https://img.shields.io/crates/v/tobi_quic.svg)](https://crates.io/crates/tobi_quic)
[![docs.rs](https://docs.rs/tobi_quic/badge.svg)](https://docs.rs/tobi_quic)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?logo=discord&logoColor=white)](https://discord.gg/shiguredo)

## 概要

tobi-quic は、Multipath QUIC (RFC 10069) に対応した Rust 製の QUIC ライブラリです。クライアントとしての利用を主な用途としています。プロトコルエンジンは Sans I/O で実装し、ネットワーク I/O には [Tokio](https://tokio.rs/) を利用します。

## 特徴

- [QUIC](https://www.rfc-editor.org/rfc/rfc9000) のクライアントとサーバーに対応し、双方向ストリーム、単方向ストリーム、[DATAGRAM 拡張](https://www.rfc-editor.org/rfc/rfc9221) を利用可能
- [Multipath QUIC](https://www.rfc-editor.org/rfc/rfc10069) により 1 つの接続で複数のネットワークパスを利用
  - 経路を切り替えて接続を維持し、複数のパスで同時に送信することも可能
  - 送信パスの選択に MinRtt、MinCompletionTime、BlestLike、RoundRobin、RateAware、WeightedRoundRobin、Redundant の[スケジューラー](https://www.rfc-editor.org/rfc/rfc10069.html#section-5.5)を利用可能
  - ネットワークインターフェースの変化に応じたパスの管理に対応
  - パスごとに輻輳制御、損失検出、往復時間の推定を実施
- [セッション再開と 0-RTT](https://www.rfc-editor.org/rfc/rfc9001) により、再接続時にハンドシェイクの完了を待たずにデータを送信可能
- 輻輳制御に [NewReno](https://www.rfc-editor.org/rfc/rfc9002)、[CUBIC](https://www.rfc-editor.org/rfc/rfc9438)、[BBRv2](https://datatracker.ietf.org/doc/draft-cardwell-iccrg-bbr-congestion-control/)、[BBRv3](https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/)、[LIA](https://www.rfc-editor.org/rfc/rfc6356) を選択可能
- [qlog](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/) の出力と接続ごと、パスごとの統計の取得に対応

### 相互接続試験

QUIC と HTTP/3 と WebTransport の相互接続試験を [Interop Test Runner](https://github.com/quic-interop/quic-interop-runner) で実施しています。対向実装と TESTCASE ごとの最新の結果は [tobi-quic の相互接続試験結果](https://tobi-quic-interop.shiguredo.app/) に掲載しています。

## crate 一覧

| crate | 説明 |
| --- | --- |
| `tobi_quic` | QUIC の公開 API |
| `tobi_http3` | HTTP/3 のクライアント / サーバー結線と共通 I/O |
| `tobi_webtransport` | WebTransport over HTTP/3 のクライアント結線 |
| `tobi_platform` | Tokio によるネットワーク I/O |
| `tobi_transport` | Sans I/O の QUIC プロトコルエンジン |
| `tobi_core` | Sans I/O のフレーム、パケット、輻輳制御など |
| `tobi_crypto` | パケット保護とトークンの処理 |
| `tobi_rustls` | rustls による TLS 統合 |
| `tobi_qlog` | Sans I/O の qlog 型とシリアライズ |

tobi-webtransport は tobi-http3 に依存し、HTTP/3 の制御ストリーム、QPACK ストリーム、QUIC I/O を共有します。どちらも Sans I/O の HTTP/3 / QPACK 実装である [shiguredo/http3-rs](https://github.com/shiguredo/http3-rs) を利用しています。

## 使い方

次の例では、接続先と証明書に合わせた TLS 設定を用意してください。

### クライアント

クライアントを起動し、接続先と双方向ストリームで通信します。

```rust
use tobi_quic::{Client, Connect, IoConfig};

// ALPN を設定した rustls の設定から client_tls を用意する
let client = Client::builder()
    .with_tls(client_tls)
    .with_io(IoConfig::new("0.0.0.0:0".parse()?))
    .start()?;

// 接続先アドレスと証明書の検証に使うサーバー名を指定する
let connect = Connect::new("127.0.0.1:4433".parse()?, "localhost");
let conn = client.connect(connect).await?;

// 双方向ストリームを開き、データを送信して送信側を終了する
let (mut send, mut recv) = conn.open_bidirectional_stream_split().await?;
tokio::io::AsyncWriteExt::write_all(&mut send, b"hello").await?;
send.finish().await?;

// 受信結果の len は読み取ったバイト数、fin は受信の終了を表す
let mut buf = [0u8; 1024];
let read = recv.receive(&mut buf).await?;
```

既定では接続の操作中に受信とタイマーを処理します。操作していない間も接続を進める場合は、バックグラウンドでの処理を有効にします。

```rust
// アプリケーションが接続を操作していない間も受信とタイマーを処理する
conn.enable_background_driver().await?;
```

### サーバー

サーバーを起動し、接続と双方向ストリームを受け入れます。

```rust
use tobi_quic::{IoConfig, Server};

// 証明書と ALPN を設定した rustls の設定から server_tls を用意する
let mut server = Server::builder()
    .with_tls(server_tls)
    .with_io(IoConfig::new("127.0.0.1:4433".parse()?))
    .start()?;

// 接続ごとにタスクを起動してストリームを受け入れる
loop {
    let conn = server.accept().await?;
    tokio::spawn(async move {
        if let Ok((mut send, mut recv)) = conn.accept_bidirectional_stream_split().await {
            // ストリームの読み書き
        }
    });
}
```

### Reliable Stream Reset

Reliable Stream Reset は、ストリームの先頭から指定した範囲の配送を保証して送信をリセットする拡張です。受信側が対応を通知している必要があります。

```rust
use tokio::io::AsyncWriteExt;

// 受信側で ConnectionConfig の transport_params.reset_stream_at を有効にする
// 送信側はピアの対応を確認してからストリームを開く
if conn.peer_supports_reset_stream_at().await {
    let mut send = conn.open_send_stream().await?;
    send.write_all(b"header").await?;
    send.write_all(b"body").await?;
    // 先頭の 6 バイトの配送を保証してエラーコード 0x42 でリセットする
    send.reset_stream_at(0x42, 6).await?;
}
```

受信側は保証されたデータを読み切った後にリセットを受け取ります。

### Multipath

Multipath QUIC (RFC 10069) は、1 つの接続で複数のネットワークパスを利用する拡張です。既定で有効になり、両端が対応している場合はクライアントから追加パスを開けます。

```rust
use tobi_quic::NewPath;

// ローカルアドレスと接続先を指定して追加パスの検証を開始する
let path = conn
    .open_path(NewPath::with_addrs(local_addr, remote_addr))
    .await?;
// accept_path_event で PathEvent::Validated または ValidationFailed を確認する
```

追加パスの検証は非同期に行われます。既定では最良のパスを使い、設定によって複数のパスを同時に利用できます。

### 0-RTT

0-RTT は、以前の接続で受け取ったセッションチケットを使い、再接続時にハンドシェイクの完了を待たずにデータを送る機能です。送信する操作は、繰り返し実行されても問題のないものにしてください。

```rust
use tobi_quic::Connect;
use tokio::io::AsyncWriteExt;

// クライアントの rustls 設定で enable_early_data を有効にする
// 初回接続でチケットを受け取り、peer_transport_params でピアの設定を保存する
// 再接続でも同じセッションチケットストアを使う
let connect = Connect::new(remote_addr, "localhost")
    .with_early_peer_params(previous_peer_params);
let conn = client.connect_early(connect).await?;

// ハンドシェイク中にストリームを開いてデータを送る
let mut send = conn.open_send_stream().await?;
send.write_all(b"request").await?;
send.finish().await?;
```

0-RTT の受理にはサーバー側の設定も必要です。tobi-quic のサーバーでは、TLS の早期データ、リプレイフィルター、部分的なストリームリセットを有効にします。

## 対応仕様

| 仕様 | 内容 |
| --- | --- |
| [RFC 6356](https://www.rfc-editor.org/rfc/rfc6356) | LIA によるマルチパス結合輻輳制御 |
| [RFC 7464](https://www.rfc-editor.org/rfc/rfc7464) | JSON-SEQ (qlog の出力形式) |
| [RFC 8899](https://www.rfc-editor.org/rfc/rfc8899) | DPLPMTUD |
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC トランスポートプロトコル |
| [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) | QUIC の TLS 1.3 統合 |
| [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) | 損失検出と輻輳制御 |
| [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) | QUIC DATAGRAM 拡張 |
| [RFC 9287](https://www.rfc-editor.org/rfc/rfc9287) | Greasing the QUIC Bit |
| [RFC 9368](https://www.rfc-editor.org/rfc/rfc9368) | Compatible Version Negotiation for QUIC |
| [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369) | QUIC Version 2 |
| [RFC 9406](https://www.rfc-editor.org/rfc/rfc9406) | HyStart++ |
| [RFC 9438](https://www.rfc-editor.org/rfc/rfc9438) | CUBIC |
| [RFC 10069](https://www.rfc-editor.org/rfc/rfc10069) | Multipath QUIC 拡張 |
| [draft-ietf-quic-ack-frequency-14](https://datatracker.ietf.org/doc/draft-ietf-quic-ack-frequency/) | ACK Frequency 拡張 |
| [draft-ietf-quic-reliable-stream-reset-11](https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/) | 部分信頼性付きストリームリセット |
| [draft-ietf-quic-receive-ts-03](https://datatracker.ietf.org/doc/draft-ietf-quic-receive-ts/) | Receive Timestamps 拡張 |
| [draft-ietf-quic-address-discovery-01](https://datatracker.ietf.org/doc/draft-ietf-quic-address-discovery/) | Address Discovery 拡張 |
| [draft-ietf-quic-qlog-main-schema-14](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/) | qlog メインスキーマ |
| [draft-ietf-quic-qlog-quic-events-13](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-quic-events/) | qlog QUIC イベント定義 |
| [draft-cardwell-iccrg-bbr-congestion-control-02](https://datatracker.ietf.org/doc/draft-cardwell-iccrg-bbr-congestion-control/) | BBRv2 |
| [draft-ietf-ccwg-bbr-06](https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/) | BBRv3 |

## テストコードについて

ユニットテスト、プロパティベースドテスト、ファジング、相互接続テストのコードは公開していません。これらのコードは有償で提供しています。購入をご検討の場合は、[時雨堂](https://shiguredo.jp) のウェブサイトに記載のメールアドレスまでお問い合わせください。

## ライセンス

Apache License 2.0

```text
Copyright 2026 Shiguredo Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
