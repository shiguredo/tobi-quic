// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

use alloc::format;
use alloc::vec::Vec;

use crate::error::Error;
use crate::packet::{QUIC_VERSION_2, is_supported_version};
use crate::path::policy::MultipathPolicy;
use crate::role::Role;
use crate::transport_params::{TransportParams, VersionInformation};

/// エンドポイントの接続制限設定
///
/// DoS 対策として同時ハンドシェイク数や同時接続数を制限する。
/// RFC 9000 Section 21.2 は、未検証の Initial を破棄することで
/// リソース枯渇を防ぐことを勧めている。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointLimits {
    /// 同時ハンドシェイク数の上限
    ///
    /// ハンドシェイクが完了していない接続の数。上限に達している間は
    /// 新規 Initial を破棄する。
    pub max_inflight_handshakes: usize,
    /// 同時接続数の上限 (None = 無制限)
    ///
    /// ハンドシェイク中と確立済みを合わせた接続の数。上限に達している間は
    /// 新規 Initial を破棄する。既定は 1000 で、明示的に `None` を指定した
    /// 場合だけ無制限になる。無制限にすると確立済み接続を増やし続けて
    /// メモリとファイルディスクリプタを枯渇させられるため、運用に合わせて
    /// 明示的に設定すること。
    pub max_connections: Option<usize>,
}

impl Default for EndpointLimits {
    fn default() -> Self {
        Self {
            max_inflight_handshakes: 100,
            // 既定で上限を設け、無制限を明示的な選択にする。
            max_connections: Some(1000),
        }
    }
}

/// 接続設定
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    pub transport_params: TransportParams,
    /// Multipath ポリシー設定
    pub multipath_policy: MultipathPolicy,
    /// DPLPMTUD の MTU 設定 (RFC 8899 / RFC 9000 Section 14)
    pub mtu: MtuConfig,
    /// 輻輳制御アルゴリズムの選択 (RFC 9002 Section 7)
    ///
    /// 既定は NewReno。CUBIC / BBRv2 / BBRv3 も選択できる。
    pub congestion_control: crate::recovery::CongestionControlAlgorithm,
    /// パス単位 keep-alive の送信間隔
    ///
    /// `None` の場合、アイドルタイムアウトの 3/4 を間隔として使う。
    /// 明示した場合、アイドルタイムアウトが無効 (`max_idle_timeout` が 0) な
    /// 接続でも keep-alive が動作する。middlebox のタイムアウトはパスごとに
    /// 異なるため、アプリケーションが間隔を指定できる必要がある
    /// (RFC 10069 Section 5.9 / RFC 9000 Section 10.1.2)。
    ///
    /// `Duration::ZERO` は無効として扱う。
    pub keep_alive_interval: Option<crate::time::Duration>,
    /// 遅延 ACK (RFC 9000 Section 13.2.2) を有効にする
    ///
    /// `true` の場合、ACK_FREQUENCY 未交渉時に ack-eliciting パケットを 2 個
    /// 受信するまで ACK を遅延し、max_ack_delay 以内に必ず送る。再順序・
    /// ギャップ・CE では即時 ACK する (Section 13.2.1)。
    ///
    /// `false` の場合、従来どおり ack-eliciting パケットごとに即時 ACK する。
    /// Interop Test Runner の rebind テストで転送が停止する事象が確認されているため、
    /// 既定では無効にしている。
    pub delayed_ack: bool,
    /// スケジューラーの構成 (データ送信 / ACK 返送 / 再送)
    ///
    /// 既定は `DefaultSchedulerFactory` と同じ組み合わせであり、既存の挙動を
    /// 変えない。接続ごとに選択した実装が使われる。
    pub scheduler: crate::scheduler::SchedulerConfig,
    /// 同時に実行するパス検証の上限
    ///
    /// 未検証の追加パスを大量に作らせるリソース枯渇攻撃を抑えるための上限。
    /// RFC 10069 Section 7.1 の同時検証数制限に対応する。
    /// 既定は 4 で、0 は設定エラーではなく 1 として扱う。
    pub max_concurrent_path_validations: usize,
    /// DATAGRAM の送信キューの上限 (件数)
    ///
    /// RFC 9221 Section 5.4 の DATAGRAM を、輻輳制御が送信を許すまで保持する
    /// キューの上限である。上限に達した状態で破棄方針の送信 API を呼ぶと、
    /// 最も古い DATAGRAM を破棄して新しいものを積む。既定は 256 で、0 は
    /// 設定エラーとして扱う。メモリ使用量の目安は「上限 ×
    /// `max_datagram_frame_size`」である。
    pub datagram_send_queue_max: usize,
    /// DATAGRAM の受信キューの上限 (件数)
    ///
    /// アプリケーションが取り出すまで受信済み DATAGRAM を保持するキューの
    /// 上限である。`tobi-transport` が受信キューの容量として使い、上限に達した
    /// 状態で新しい DATAGRAM を受信すると最も古いものを破棄する。この値は
    /// ピアが接続に保持させられる量の上限になる。既定は 1024 で、0 は設定
    /// エラーとして扱う。メモリ使用量の目安は「上限 ×
    /// `max_datagram_frame_size`」である。
    pub datagram_recv_queue_max: usize,
    /// この接続で使用する QUIC バージョン (RFC 9000 Section 15 / RFC 9369 Section 3.1)
    ///
    /// クライアントは最初の接続試行でこのバージョンを使う。サーバーは
    /// 受理した Initial のバージョン、または互換バージョン交渉で選択した
    /// バージョンをルーターが設定する。
    pub version: u32,
    /// 対応する QUIC バージョンの一覧 (優先順)
    ///
    /// クライアントは Version Negotiation 後の再試行候補として使い、
    /// サーバーは受理するバージョンの判定と Version Negotiation 応答の
    /// 一覧に使う。空の一覧は設定エラーとする。
    pub supported_versions: Vec<u32>,
    /// Version Negotiation に反応して開始した接続試行か (RFC 9368 Section 4)
    ///
    /// 真の場合、この接続試行中に受信した Version Negotiation パケットは
    /// ダウングレード攻撃対策のため無視する (MUST)。クライアントの再試行
    /// 経路だけが真に設定する。
    pub vn_retry: bool,
    /// 互換バージョン交渉でクライアントが最初の flight に使ったバージョン
    ///
    /// RFC 9368 Section 2.3 の互換バージョン交渉で、サーバーがクライアントの
    /// Chosen Version と異なるバージョンを選んだ場合に、ルーターが
    /// クライアントの Chosen Version を設定する。サーバーは Chosen Version の
    /// Initial を受信してハンドシェイクを開始し、ネゴシエート済みバージョンで
    /// 応答するため、受信鍵を両方のバージョンで用意する必要がある。
    /// それ以外の接続では `None`。
    pub compatible_client_version: Option<u32>,
    /// ピアが `grease_quic_bit` を広告した場合に、送信パケットの QUIC Bit を
    /// 0 にして送るか (RFC 9287 Section 3.1)
    ///
    /// 受信許容は [`TransportParams::grease_quic_bit`] (自分が TP を広告するか)
    /// で決まる。送信側は、ピアが TP を広告したことを確認した後だけ QUIC Bit を
    /// 0 にできる。既定は false (常に 1) で、true にすると該当パケットを
    /// すべて 0 にする。
    pub send_zero_quic_bit: bool,
}

/// DPLPMTUD の MTU 設定
///
/// `MtuController` の初期値・下限・上限として使う。既定値は
/// `MtuController` の既定値と一致させている (`max_mtu = DEFAULT_MAX_MTU`)。
/// `max_mtu` は RFC 9000 Section 18.2 の最大 UDP ペイロード 65,527 以下で
/// なければならない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtuConfig {
    /// 初期 MTU (探索開始時点の確認済み MTU)
    pub initial_mtu: u16,
    /// DPLPMTUD が下回らない最小 MTU (RFC 9000 Section 14 により 1200 以上)
    pub base_mtu: u16,
    /// 探索上限 MTU
    ///
    /// RFC 9000 Section 18.2 の最大 UDP ペイロードである 65,527 以下で
    /// なければならない。
    pub max_mtu: u16,
}

impl Default for MtuConfig {
    fn default() -> Self {
        Self {
            initial_mtu: crate::path::mtu::BASE_MTU,
            base_mtu: crate::path::mtu::BASE_MTU,
            max_mtu: crate::path::mtu::DEFAULT_MAX_MTU,
        }
    }
}

impl MtuConfig {
    /// 設定値を検証する
    ///
    /// RFC 9000 Section 14: `base_mtu` は 1200 以上。
    /// `initial_mtu` は `base_mtu` 以上 `max_mtu` 以下。
    /// RFC 9000 Section 18.2: `max_mtu` は 65,527 以下。
    pub fn validate(&self) -> Result<(), Error> {
        if self.base_mtu < crate::path::mtu::BASE_MTU {
            return Err(Error::InvalidData(format!(
                "base_mtu {} is below the QUIC minimum MTU {}",
                self.base_mtu,
                crate::path::mtu::BASE_MTU
            )));
        }
        if self.initial_mtu < self.base_mtu {
            return Err(Error::InvalidData(format!(
                "initial_mtu {} is below base_mtu {}",
                self.initial_mtu, self.base_mtu
            )));
        }
        if self.max_mtu < self.initial_mtu {
            return Err(Error::InvalidData(format!(
                "max_mtu {} is below initial_mtu {}",
                self.max_mtu, self.initial_mtu
            )));
        }
        // RFC 9000 Section 18.2: UDP payload の最大値は 65,527 バイト。
        // これを超える MTU を設定すると sendto が EMSGSIZE になったり、
        // 不要な IP 断片化を招く。
        if self.max_mtu > crate::path::mtu::MAX_UDP_PAYLOAD {
            return Err(Error::InvalidData(format!(
                "max_mtu {} exceeds the maximum UDP payload {}",
                self.max_mtu,
                crate::path::mtu::MAX_UDP_PAYLOAD
            )));
        }
        Ok(())
    }

    /// `MtuController` を作成する
    pub fn build_controller(&self) -> Result<crate::path::mtu::MtuController, Error> {
        self.validate()?;
        crate::path::mtu::MtuController::new_with_config(
            self.initial_mtu,
            self.base_mtu,
            self.max_mtu,
        )
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            transport_params: TransportParams {
                initial_max_data: 1_048_576,
                initial_max_stream_data_bidi_local: 65536,
                initial_max_stream_data_bidi_remote: 65536,
                initial_max_stream_data_uni: 65536,
                initial_max_streams_bidi: 100,
                initial_max_streams_uni: 100,
                initial_max_path_id: Some(4),
                // RFC 9287 Section 3: 既定で広告し、ピアからの QUIC Bit 0 を
                // 受け入れる。送信側は `send_zero_quic_bit` が false の間は
                // 従来どおり 1 を送る。
                grease_quic_bit: true,
                ..Default::default()
            },
            multipath_policy: MultipathPolicy::default(),
            mtu: MtuConfig::default(),
            congestion_control: crate::recovery::CongestionControlAlgorithm::default(),
            keep_alive_interval: None,
            delayed_ack: false,
            max_concurrent_path_validations: 4,
            datagram_send_queue_max: 256,
            datagram_recv_queue_max: 1024,
            scheduler: crate::scheduler::SchedulerConfig::default(),
            version: crate::packet::QUIC_VERSION_1,
            supported_versions: alloc::vec![crate::packet::QUIC_VERSION_1],
            vn_retry: false,
            compatible_client_version: None,
            send_zero_quic_bit: false,
        }
    }
}

impl ConnectionConfig {
    /// ローカルのトランスポートパラメータへ version_information を設定する
    ///
    /// RFC 9369 Section 4 は v2 endpoint に version_information の送信・処理・
    /// 検証を MUST とする。RFC 9368 Section 3 のとおり、Chosen Version は
    /// Available Versions に含めなければならない。
    ///
    /// クライアントは対応バージョン一覧を Available Versions として送り、
    /// 互換バージョン交渉を有効にする (RFC 9368 Section 2.3)。本実装では
    /// rustls の QUIC セッションがバージョンに束縛されるため接続内でバージョンを
    /// 切り替えられず、サーバーが Chosen Version と異なる互換バージョンを
    /// 選んだ場合は上位層がそのバージョンで新しい接続試行を開始する
    /// (tobi-quic の `Client::connect` を参照)。サーバーは Fully Deployed
    /// Versions として対応バージョン一覧を送る。
    ///
    /// 既に `transport_params.version_information` が設定済みの場合は上書きしない
    /// (検証用に明示設定する場合があるため)。
    pub fn apply_version_information(&mut self, role: Role) {
        if self.transport_params.version_information.is_some() {
            return;
        }
        let version = self.version;
        // クライアントは v2 対応時のみ送信する (RFC 9369 Section 4 MUST)。
        // サーバーは常に送信し、v1 のみの endpoint でもピアの v2 対応と
        // バージョンダウングレード検証を成立させる。
        let is_v2_capable =
            version == QUIC_VERSION_2 || self.supported_versions.contains(&QUIC_VERSION_2);
        if role == Role::Client && !is_v2_capable {
            return;
        }
        let mut available_versions = if self.supported_versions.is_empty() {
            alloc::vec![version]
        } else {
            // クライアントは対応バージョン一覧をそのまま広告して互換バージョン
            // 交渉を有効にし、サーバーは Fully Deployed Versions として広告する。
            self.supported_versions.clone()
        };
        // Chosen Version を Available Versions に含める。サーバーは含めなくても
        // よいが、包含しておけば v2 未対応の検証実装とも齟齬が出にくい。
        if !available_versions.contains(&version) {
            available_versions.push(version);
        }
        // 重複を除去する (先勝ち)。`with_versions` を経由しない直接設定でも
        // Available Versions に同じバージョンを並べない。
        let mut deduped = Vec::new();
        for version in available_versions {
            if !deduped.contains(&version) {
                deduped.push(version);
            }
        }
        let mut available_versions = deduped;
        // 0 と本実装が対応しないバージョンは送らない (予約バージョンを
        // Available Versions に含めるのは試験用途のみで、ここでは含めない)。
        available_versions.retain(|v| is_supported_version(*v));
        self.transport_params.version_information = Some(VersionInformation {
            chosen_version: version,
            available_versions,
        });
    }
}

/// CONNECTION_CLOSE フレームの reason phrase をフォーマットするトレイト
///
/// 本番環境では内部情報を含む reason phrase を抑制するために使用する。
/// `Connection::set_close_formatter` で設定されたときのみ介在し、整形は
/// クローズ 1 回につき 1 回だけ行われる。整形結果の主な適用先は次のとおり:
///
/// - transport close (`Connection::close`): 保持している全レベル
///   (Initial / Handshake / 1-RTT。確定後は 1-RTT のみ) の reason phrase。
/// - application close (`Connection::close_application`): 1-RTT の 0x1d と qlog。
///   Initial / Handshake へ 0x1c 変換して送るときは、RFC 9000 Section 10.2.3 の
///   MUST により reason phrase を空にするため整形結果は載らない。
///
/// 実装への期待:
///
/// - 純関数として実装すること。同じ引数に対して結果が変わったり、外部状態を
///   変更する副作用は避ける。
/// - 戻り値は SHOULD で UTF-8 エンコード文字列であること (RFC 9000 Section 19.19)。
/// - 戻り値のサイズはパケット MTU に収まる必要がある (RFC 9000 Section 19.19)。
///   フォーマッタ側で上限を意識せず巨大な値を返すと `emit_1rtt_single_frame` が
///   失敗する。
pub trait ConnectionCloseFormatter: Send + Sync {
    /// CONNECTION_CLOSE の reason phrase を整形する
    ///
    /// `error_code` は transport-level (type 0x1c) の場合は RFC 9000 Section 20.1 の
    /// transport error code、application-level (type 0x1d) の場合は
    /// RFC 9000 Section 20.2 の application code space の値である。どちらの code
    /// space の値も同じ `u64` として渡されるため、フォーマッタは code space を
    /// 区別せずに整形する。
    fn format(&self, error_code: u64, reason: &[u8]) -> Vec<u8>;
}

/// 本番向けの CONNECTION_CLOSE フォーマッタ (reason phrase を空にする)
pub struct SilentConnectionCloseFormatter;

impl ConnectionCloseFormatter for SilentConnectionCloseFormatter {
    fn format(&self, _error_code: u64, _reason: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

/// Stateless Reset Token の生成をカスタマイズするトレイト
///
/// 設定すると、CID 発行時に `generate(connection_id)` の戻り値を
/// Stateless Reset Token として使用する。同じ Connection ID に対して常に
/// 同じ Token を返す決定的な実装 (HMAC-SHA256 等) を渡すことで、状態を失った
/// サーバーでも再起動前と同じ Token を再計算できる (RFC 9000 Section 10.3.2)。
///
/// 実装への期待:
///
/// - Token は 16 バイトであること (RFC 9000 Section 10.3)。
/// - ピアから推測できない値であること (RFC 9000 Section 10.3.1 の MUST)。
/// - 純関数として実装すること。同じ Connection ID に対して同じ Token を返し、
///   外部状態を変更する副作用は避ける (再起動をまたいだ再計算の前提)。
pub trait StatelessResetTokenGenerator: Send + Sync {
    /// Connection ID に対応する Stateless Reset Token を生成する
    fn generate(&self, connection_id: &[u8]) -> [u8; 16];
}

/// Connection ID の生成をカスタマイズするトレイト (RFC 9000 Section 5.1)
///
/// RFC 9000 Section 5.1 は Connection ID を endpoint が implementation-specific に
/// 選択するものとし、その選び方を endpoint に委ねている。draft-ietf-quic-load-balancers-21
/// や RFC 9312 Section 4.4 が前提とする「CID に Server ID を埋め込む」運用を
/// アプリケーションから実装するためのフックである。
///
/// 実装への期待:
///
/// - `generate()` の戻り値長は `cid_len()` と一致すること。
/// - `cid_len()` は 1..=20 の範囲であること (RFC 9000 Section 17.2)。
/// - 生成する CID はピアから推測できない値であること (RFC 9000 Section 5.1)。
pub trait ConnectionIdGenerator: Send + Sync {
    /// 新しい Connection ID を生成する
    fn generate(&self) -> Vec<u8>;
    /// Connection ID の長さを返す
    fn cid_len(&self) -> usize;
}
