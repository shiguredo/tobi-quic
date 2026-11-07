// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 低水準 API のオプション設定
//!
//! `QuicServer::bind_with_config` / `QuicConnection::connect_with_config_and_bind`
//! のような低水準の入口は、任意の設定 (トレイトオブジェクトやオプション値) が
//! 増え続ける。位置引数で受けると追加のたびに全呼び出し元がコンパイル修正を
//! 強いられるため、`#[derive(Default)]` した構造体に集約する。
//!
//! 必須引数 (アドレス / TLS 設定 / `ConnectionConfig`) は位置引数のまま残す。
//! これらは接続の確立に不可欠で、`Option` 化すると必須性が読み取りにくくなる。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tobi_core::connection::ConnectionIdGenerator;
use tobi_core::connection::StatelessResetTokenGenerator;
use tobi_core::connection::{ConnectionCloseFormatter, EndpointLimits};
use tobi_core::transport_params::TransportParams;
use tobi_qlog::QlogWriterFactory;

use crate::RetryConfig;

/// ハンドシェイク完了までの既定のタイムアウト
///
/// クライアントとサーバーの両方で使う。応答しないピアに対して接続処理が
/// 永遠に待ち続けないようにするための安全側の既定値である。
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// UDP のバッチ I/O とオフロードの設定
///
/// Linux / Android では 1 回のシステムコールで複数データグラムを送受信する
/// `sendmmsg` / `recvmmsg` と、カーネルにデータグラムの分割と結合を任せる
/// GSO / GRO (`UDP_SEGMENT` / `UDP_GRO`) が使える。macOS / iOS には同等の
/// 機能がないため、ここで有効にしても従来の 1 データグラム 1 システムコールで
/// 動作する。
///
/// 性能より堅牢性を優先し、既定では無効にする。有効化した場合の効果は実ソケットの
/// ベンチマークで確認する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpBatchConfig {
    /// `sendmmsg` / `recvmmsg` で複数データグラムをまとめて送受信する
    pub syscalls: bool,
    /// GSO / GRO を使う (送信の `UDP_SEGMENT` と受信の `UDP_GRO`)
    pub offload: bool,
    /// 1 回の `sendmmsg` / `recvmmsg` でまとめるデータグラム数の上限
    ///
    /// GSO で連結するセグメント数の上限にもなる。
    /// `recvmmsg` はこの数だけ受信バッファを保持する。単発受信用のバッファも
    /// 1 つ持つため、受信タスク 1 本あたりのメモリ使用量は
    /// `(max_datagrams + 1) × 64 KiB` になる。
    pub max_datagrams: usize,
    /// GSO で 1 回の送信にまとめる最大バイト数
    ///
    /// カーネルが `EMSGSIZE` を返さない範囲に収める。
    pub max_gso_bytes: usize,
}

impl Default for UdpBatchConfig {
    /// 無効かつ控えめな上限を既定値にする
    fn default() -> Self {
        Self {
            syscalls: false,
            offload: false,
            max_datagrams: 8,
            max_gso_bytes: 16 * 1024,
        }
    }
}

impl UdpBatchConfig {
    /// いずれかの機能を有効にしているか
    pub fn is_enabled(&self) -> bool {
        self.syscalls || self.offload
    }

    /// 設定値を検証する
    ///
    /// `max_datagrams` は受信バッファの保持数とまとめる件数の上限、
    /// `max_gso_bytes` は GSO で 1 回の送信に連結する合計バイト数の上限になる。
    /// どちらも 0 を許すと送受信が成立しない。
    /// 上限は GSO のセグメント数 (古いカーネルの `UDP_MAX_SEGMENTS` = 64 に合わせた
    /// 保守的な値) と、UDP ペイロードの最大長 (IPv4 で 65507 バイト) に合わせる。
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=64).contains(&self.max_datagrams) {
            return Err(format!(
                "max_datagrams must be in 1..=64, got {}",
                self.max_datagrams
            ));
        }
        if !(1..=65507).contains(&self.max_gso_bytes) {
            return Err(format!(
                "max_gso_bytes must be in 1..=65507, got {}",
                self.max_gso_bytes
            ));
        }
        Ok(())
    }
}

/// サーバーが広告する preferred_address の設定 (RFC 9000 Section 18.2)
///
/// サーバーはハンドシェイク応答の transport parameter で、クライアントに
/// 移行先のアドレスを通知できる。設定しない (BindOptions で `None`) 場合、
/// サーバーは preferred_address を広告しない。
///
/// アドレスファミリごとに広告するかどうかを選べる。広告しないファミリは
/// アドレス長 0 のフィールドとして送信される (RFC 9000 Section 18.2)。
/// ポートに 0 を指定した場合は、サーバーが実際にバインドしたポートを使う。
/// 初期ポートと異なる非ゼロポートを指定した場合、そのローカルアドレスにも
/// バインドして同じ接続ルーターで受信する。バインドに失敗すると起動は失敗する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreferredAddressConfig {
    /// IPv4 で広告するアドレス
    pub ipv4: Option<SocketAddr>,
    /// IPv6 で広告するアドレス
    pub ipv6: Option<SocketAddr>,
}

impl PreferredAddressConfig {
    /// 新しい設定を作成する
    pub fn new(ipv4: Option<SocketAddr>, ipv6: Option<SocketAddr>) -> Self {
        Self { ipv4, ipv6 }
    }

    /// 設定値を検証する
    ///
    /// 両方 `None` の場合は広告するアドレスが無いためエラーにする。
    /// IPv4 のフィールドには IPv4、IPv6 のフィールドには IPv6 の
    /// `SocketAddr` を指定する必要がある。
    pub fn validate(&self) -> Result<(), String> {
        if self.ipv4.is_none() && self.ipv6.is_none() {
            return Err("preferred_address requires at least one address".into());
        }
        if let Some(addr) = self.ipv4
            && addr.is_ipv6()
        {
            return Err(format!("preferred_address IPv4 slot must be IPv4: {addr}"));
        }
        if let Some(addr) = self.ipv6
            && addr.is_ipv4()
        {
            return Err(format!("preferred_address IPv6 slot must be IPv6: {addr}"));
        }
        // RFC 9000 Section 18.2: port 0 は「そのアドレスファミリを使わない」を
        // 意味する。非ゼロ port で unspecified アドレスを広告すると、クライアントが
        // 0.0.0.0 / :: を接続先として解釈し、意図しないローカルサービスへ
        // 接続する可能性がある。
        for addr in [self.ipv4, self.ipv6].into_iter().flatten() {
            if addr.port() != 0 && addr.ip().is_unspecified() {
                return Err(format!(
                    "preferred_address must not use an unspecified address: {addr}"
                ));
            }
        }
        Ok(())
    }

    /// `bind_port` を未指定 (port 0) のアドレスへ適用する
    ///
    /// unspecified アドレス (`0.0.0.0` / `::`) の port 0 は「そのアドレス
    /// ファミリを使わない」を意味するため、バインドポートで埋めない。
    /// 埋めてしまうと「非ゼロ port と unspecified アドレス」の組み合わせに
    /// なり、クライアントが `preferred_address` を拒否してハンドシェイクが
    /// 失敗する (RFC 9000 Section 18.2)。
    pub(crate) fn with_bind_port(self, bind_port: u16) -> Self {
        let fill = |addr: Option<SocketAddr>| {
            addr.map(|mut addr| {
                if addr.port() == 0 && !addr.ip().is_unspecified() {
                    addr.set_port(bind_port);
                }
                addr
            })
        };
        Self {
            ipv4: fill(self.ipv4),
            ipv6: fill(self.ipv6),
        }
    }
}

/// `QuicServer::bind_with_config` のオプション設定
///
/// 基本的に `Default` で「未設定」を表す。ただし `handshake_timeout` は
/// 停滞したハンドシェイクで `accept()` が永遠に待たないよう、既定で
/// [`DEFAULT_HANDSHAKE_TIMEOUT`] を持つ。必要な設定だけを代入して渡す:
///
/// ```ignore
/// let options = BindOptions {
///     qlog_factory: Some(factory),
///     ..Default::default()
/// };
/// ```
#[derive(Clone)]
pub struct BindOptions {
    /// QUIC バージョンごとの rustls サーバー設定
    ///
    /// RFC 9369 Section 5: TLS セッションチケットは発行した QUIC バージョンに
    /// 固有であり、サーバーは別バージョンのチケットを受け入れてはならない
    /// (MUST)。バージョンごとに別のチケット鍵を持つ `ServerConfig` を渡すことで、
    /// 別バージョンで発行されたチケットの再開を TLS 層で拒否できる。
    /// `None` の場合は `tls_config` を全バージョンで共有する。
    pub versioned_tls_configs: Option<
        std::sync::Arc<std::collections::HashMap<u32, std::sync::Arc<rustls::ServerConfig>>>,
    >,
    /// UDP のバッチ I/O の設定。`None` なら無効
    pub udp_batch: Option<UdpBatchConfig>,
    /// 特定アドレスへ bind した場合も別アドレスファミリの wildcard で待ち受ける
    ///
    /// 既定は `false` で、`0.0.0.0` / `::` を指定した場合だけデュアルスタックに
    /// なる。loopback や特定インターフェースを指定したサーバーの公開範囲を
    /// 意図せず広げないための opt-in。
    pub allow_dual_stack: bool,
    /// 初期ソケットと追加ソケットに `SO_REUSEPORT` を設定する
    ///
    /// 既定は `true`。無効にすると `SO_REUSEPORT` によるポート共有を防げる。
    /// Linux では `SO_REUSEADDR` も常に設定しているため、別プロセスが
    /// `SO_REUSEADDR` を設定していれば同じ UDP ポートに bind できる点に注意する
    /// (socket(7) の NOTES)。`SO_REUSEPORT` を無効にすると、同じ UID の
    /// 別プロセスが `SO_REUSEPORT` でポートを共有することは防げる。
    pub reuse_port: bool,
    /// 0-RTT のリプレイ検出フィルター (RFC 9001 Section 4.1.3)
    pub replay_filter: Option<Arc<dyn tobi_core::token::ReplayFilter>>,
    /// qlog writer のファクトリ。`None` なら qlog を出力しない
    ///
    /// qlog には接続 ID、アドレス、トランスポートパラメータ、CONNECTION_CLOSE の
    /// reason phrase が含まれる。reason phrase には `close_formatter` を適用した
    /// 値だけを記録する。出力先とローテーションは利用者が管理し、本番環境では
    /// 必要な期間だけ有効にする。書き込み失敗は接続処理に影響させない
    /// (`JsonSeqQlogWriter` は書き込みエラーを無視する)。
    pub qlog_factory: Option<Arc<dyn QlogWriterFactory>>,
    /// CONNECTION_CLOSE の reason phrase フォーマッタ。`None` なら reason をそのまま送る
    pub close_formatter: Option<Arc<dyn ConnectionCloseFormatter>>,
    /// Stateless Reset Token の生成器。`None` なら乱数で生成する (RFC 9000 Section 10.3.2)
    pub stateless_reset_generator: Option<Arc<dyn StatelessResetTokenGenerator>>,
    /// サーバー CID の生成器。`None` なら 8 バイトの乱数を生成する
    pub cid_generator: Option<Arc<dyn ConnectionIdGenerator>>,
    /// Retry によるアドレス検証の設定 (RFC 9000 Section 8.1.2)
    pub retry_config: Option<RetryConfig>,
    /// エンドポイントの接続数・ハンドシェイク数の上限
    pub endpoint_limits: EndpointLimits,
    /// accept キューの容量。`None` なら [`crate::DEFAULT_ACCEPT_QUEUE_CAPACITY`]
    pub accept_queue_capacity: Option<usize>,
    /// サーバーが広告する preferred_address (RFC 9000 Section 18.2)
    pub preferred_address: Option<PreferredAddressConfig>,
    /// NEW_TOKEN のトークン生成・検証に使うプロバイダ (RFC 9000 Section 8.1.3)
    ///
    /// 設定した場合、各接続で Initial のトークン検証とパス検証成功後の
    /// NEW_TOKEN 自動発行が有効になる。サーバー全体で同一のプロバイダを
    /// 共有するため `Arc` で渡す。
    pub token_provider: Option<Arc<dyn tobi_core::token::TokenProvider>>,
    /// ハンドシェイク完了までのタイムアウト。
    ///
    /// `None` ならタイムアウトしない。既定は [`DEFAULT_HANDSHAKE_TIMEOUT`]。
    /// 停滞したハンドシェイクで `accept()` が永久に待ち続けるのを防ぐ。
    /// 0 は起動時に拒否する。
    pub handshake_timeout: Option<Duration>,
}

impl Default for BindOptions {
    fn default() -> Self {
        Self {
            versioned_tls_configs: None,
            udp_batch: None,
            allow_dual_stack: false,
            reuse_port: true,
            replay_filter: None,
            qlog_factory: None,
            close_formatter: None,
            stateless_reset_generator: None,
            cid_generator: None,
            retry_config: None,
            endpoint_limits: EndpointLimits::default(),
            accept_queue_capacity: None,
            preferred_address: None,
            token_provider: None,
            handshake_timeout: Some(DEFAULT_HANDSHAKE_TIMEOUT),
        }
    }
}

/// `QuicConnection::connect_with_config_and_bind` のオプション設定
///
/// 基本的に `Default` で「未設定」を表す。ただし `handshake_timeout` は
/// 応答しないサーバーで永遠に待たないよう、既定で 10 秒を持つ。
#[derive(Clone)]
pub struct ConnectOptions {
    /// 前回セッションで取得したピアの transport parameter。
    /// `Some` なら 0-RTT パケットを送信できる (RFC 9001 Section 4.6.1)
    pub early_peer_params: Option<TransportParams>,
    /// qlog writer のファクトリ。`None` なら qlog を出力しない
    pub qlog_factory: Option<Arc<dyn QlogWriterFactory>>,
    /// CONNECTION_CLOSE の reason phrase フォーマッタ。`None` なら reason をそのまま送る
    pub close_formatter: Option<Arc<dyn ConnectionCloseFormatter>>,
    /// クライアント自身の SCID の生成器。`None` なら 8 バイトの乱数を生成する
    pub cid_generator: Option<Arc<dyn ConnectionIdGenerator>>,
    /// UDP のバッチ I/O の設定。`None` なら無効
    pub udp_batch: Option<UdpBatchConfig>,
    /// 前回接続で受信した NEW_TOKEN を Initial に載せるためのアドレストークン
    /// (RFC 9000 Section 8.1.3)
    ///
    /// `Some` の場合、Initial 送信前に transport の `set_address_token` を呼ぶ。
    /// サーバーがトークンを検証できればアドレス検証済みとして受理される。
    pub address_token: Option<Vec<u8>>,
    /// 特定アドレスへ bind した場合も別アドレスファミリの wildcard ソケットを
    /// 追加してよいか。既定は `false`。
    pub allow_dual_stack: bool,
    /// ハンドシェイク完了までのタイムアウト。
    ///
    /// `None` ならタイムアウトしない。既定は 10 秒で、応答しないサーバーに
    /// 対して接続処理が永遠に待ち続けるのを防ぐ。
    pub handshake_timeout: Option<Duration>,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            early_peer_params: None,
            qlog_factory: None,
            close_formatter: None,
            cid_generator: None,
            udp_batch: None,
            address_token: None,
            allow_dual_stack: false,
            handshake_timeout: Some(DEFAULT_HANDSHAKE_TIMEOUT),
        }
    }
}

#[cfg(test)]
mod tests;
