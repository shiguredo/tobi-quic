// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! QUIC 接続の Sans I/O 状態マシン
//!
//! Multipath First: 初期パス (Path ID 0) から始まり、
//! 追加パスは open_path() で作成する。

use std::collections::VecDeque;
use std::sync::Arc;

use tobi_core::connection::{ConnectionCloseFormatter, StatelessResetTokenGenerator};
use tobi_core::connection_id::ConnectionId;
use tobi_core::error::Error;
use tobi_core::frame;
use tobi_core::frame::Frame;
use tobi_core::nonce;
use tobi_core::packet::header::{self, LongHeader, ShortHeader};
use tobi_core::packet::number;
use tobi_core::packet::{self, LongPacketType};
use tobi_core::path::controller::default::DefaultPathControllerFactory;
use tobi_core::path::controller::{
    PathAction, PathControlCtx, PathControlEvent, PathController, PathControllerFactory,
};
use tobi_core::path::mtu::MAX_UDP_PAYLOAD;
use tobi_core::path::policy::MultipathPolicy;
use tobi_core::path::state::PathState;
use tobi_core::path::{EcnValidationState, Path, PathId, PathManager, PathStatus};
use tobi_core::recovery::ack_tracker::AckTracker;
use tobi_core::recovery::sent_packets::{
    LostResetFrame, LostStreamFrame, SentFrameInfo, SentPacket, SentPackets,
};
use tobi_core::recovery::{
    AckedPacketInfo, CongestionControl, CongestionControlFactory, CongestionStateKind, IdleReason,
    LossDetector, LostPacketInfo, NewRenoFactory, PacketNumberSpace,
};
use tobi_core::scheduler::{
    AckCtx, AckPathPolicy, DataScheduler, DefaultSchedulerFactory, FrameClass, LossReason,
    MultipathScheduler, PathMetrics, RetransmissionPolicy, RetxCtx, RetxDecision, ScheduleCtx,
    SchedulerFactory,
};
use tobi_core::stats::ConnectionStats;
use tobi_core::time::{Duration, Timestamp};
use tobi_core::transport_params::{MAX_PATH_ID, TransportParams};
use tobi_core::varint::VarInt;
use tobi_crypto::aws_lc_rs;
use tobi_crypto::keys as crypto;
use tobi_crypto::protection;
use tobi_qlog as qlog;
use tobi_rustls::rustls;

use crate::stream::buffer::RetxMeta;
use crate::stream::{RetxTarget, StreamEvent, StreamFrameOut, StreamManager};
use crate::tls;

mod output;
use output::{MAX_ONE_RTT_OVERHEAD, OneRttPurpose, PendingOneRtt};

pub use tobi_core::connection::{
    ConnectionCloseKind, ConnectionConfig, ConnectionEvent, ConnectionObservationEvent,
    ConnectionOutput, ConnectionState, EcnCodepoint, TimerId,
};
pub use tobi_core::role::Role;

/// アプリケーションイベントのキューに保持する最大件数
///
/// ピアは 1 つのパケットに多数の NEW_TOKEN / DATAGRAM / STREAM フレームを詰められる。
/// アプリケーションの消費が遅い場合に備えて上限を設け、上限超過時は新しい
/// イベントを破棄する。`StreamReadable` はストリーム単位で合流させる。
/// DPLPMTUD の PROBE_TIMER の下限
///
/// RFC 8899 Section 5.1.1: "This value MUST NOT be smaller than 1 second"。
/// 同節は 15 秒より大きくすることを SHOULD とするが、本実装は最小実装方針に
/// 従い MUST の下限だけを満たす。
const PMTU_PROBE_TIMER_MIN: Duration = Duration::from_secs(1);

const MAX_EVENT_QUEUE_EVENTS: usize = 1024;

/// 観測イベントのキューに保持する最大件数
///
/// 購読者が遅い場合でも接続処理をブロックしないため、溢れた分は破棄する。
const MAX_OBSERVATION_QUEUE_EVENTS: usize = 1024;

/// ピアが広告する `active_connection_id_limit` の実用上限
///
/// RFC 9000 Section 18.2 は 2 以上を要求するが、上限は 2^62-1 まで許される。
/// そのまま使うと、ピアが `PATH_CIDS_BLOCKED` を送るたびにこちらの CID が
/// 無制限に増えるため、実装側で実用的な値に clamp する。
/// ピアの広告値より少ない CID しか発行しないことは仕様上問題ない。
const MAX_PEER_ACTIVE_CID_LIMIT: u64 = 64;

/// パスごとにローカルで保持する CID の実用上限
///
/// ピアが `retire_prior_to` で退役させた CID でも、ピアから
/// RETIRE_CONNECTION_ID が届くまでは受信パケットのルーティングに必要になる。
/// ピアが RETIRE を送らずに `PATH_CIDS_BLOCKED` を繰り返す場合でも、
/// ここで発行を止めてメモリと CID 発行コストを抑える。
const MAX_LOCAL_CIDS_PER_PATH: usize = 64;

/// RETIRE 送信待ちの重複抑止として保持するピア CID の履歴上限
///
/// RFC 9000 Section 5.1.2 は未 ACK の退役 CID 数を抑える SHOULD と、少なくとも
/// 2 × `active_connection_id_limit` の RETIRE を送受信できるようにする SHOULD を
/// 定める。本実装は 2 × `active_connection_id_limit` を上限として扱い、超過を
/// CONNECTION_ID_LIMIT_ERROR にする (MAY)。履歴は固定上限で抑える。既定値
/// (`active_connection_id_limit = 2`) では 2 × limit = 4 件であり、この上限より
/// 十分小さい。ただしローカルの `active_connection_id_limit` は接続生成時に任意の
/// 値を設定できるため、大きな値では履歴上限が 2 × limit を下回り、未 ACK 数を
/// 過小評価し得る。上限を超えた履歴は古いものから捨てるため、同じシーケンス番号
/// の CID を再通知されたときに RETIRE を重ねて送る可能性がある。これは許容される
/// (RFC 9000 Section 19.16 が禁じるのは DCID との一致と、発行済み最大を超える
/// シーケンス番号であり、同じシーケンス番号の RETIRE 再送を禁じる規定は無い)。
const MAX_RETIRED_PEER_CID_HISTORY: usize = 1024;

/// PathController のアクション実行で、ポリシーから導出した上限に加える余裕
///
/// `MultipathPolicy::max_paths` は上限が無く、Aggregate モードの
/// `aggregate_actions` は劣化パス 1 本につき 2 アクション (`SetStatus` と
/// `SetKeepAlive`) を返す。そのため上限は `2 * max_paths` を基礎にする。
/// 公開 API から `max_paths` を超えるパスを開けるため、実際のアクティブパス数も
/// 基礎に含める。同じイベントで開設や状態変更が加わっても正当なアクションを
/// 切り捨てないよう、固定の余裕を足す。
const PATH_ACTION_LIMIT_MARGIN: usize = 8;

/// PathController のアクション実行を再入できる深度の上限
///
/// `AbandonPath` の実行は `PathAbandoned` の通知から
/// `execute_path_actions` を再入させる。正当な実装では 1 回のイベントに
/// つき高々数段しか再入しないため、これを超える連鎖は実装の誤りとみなす。
/// 再入が連鎖し続けてもスタックを消費し尽くさないよう上限を設ける。
const MAX_PATH_ACTION_REENTRANCY_DEPTH: usize = 8;

/// パス廃棄時に PathController へ `PathAbandoned` を通知するか
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbandonNotification {
    /// 通知し、返されたアクションを実行する
    Notify,
    /// 通知しない (開設処理の途中で失敗したパスの後始末)
    Skip,
}

/// 開設処理で `PathOpened` を I/O 層へ発行済みか
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathOpenedState {
    /// 発行済み。`PATH_ABANDON` の実出力時または `PathCleanup` 時に
    /// `PathClosed` を発行する
    Emitted,
    /// 未発行。`PathClosed` を発行しない
    NotEmitted,
}

/// 暗号化レベル
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EncryptionLevel {
    Initial,
    Handshake,
    /// 0-RTT パケット
    ///
    /// RFC 9000 Section 12.4 Table 3 のフレーム制限を 1-RTT とは別に適用する。
    ZeroRtt,
    OneRtt,
}

// --- 暗号化レベルごとの鍵管理 ---

/// Initial レベルの鍵 (aws-lc-rs ベース)
///
/// 送信鍵はネゴシエート済みバージョンで導出する。受信鍵はパケットの
/// バージョンごとに保持する。RFC 9368 Section 2.3 の互換バージョン交渉では、
/// サーバーがクライアントの Chosen Version と異なるバージョンで応答するため、
/// クライアントの最初の flight は Chosen Version、以降のパケットは
/// ネゴシエート済みバージョンで届く。
struct InitialKeys {
    /// 送信に使う鍵 (ネゴシエート済みバージョン)
    send: crypto::DirectionalKeys,
    /// 受信に使う鍵 (バージョン, 鍵) の組
    recv: Vec<(u32, crypto::DirectionalKeys)>,
}

impl InitialKeys {
    /// ネゴシエート済みバージョンの送受信鍵を生成する
    fn new(send_version: u32, dcid: &ConnectionId, role: Role) -> Result<Self, Error> {
        let keys = crypto::derive_initial_keys(send_version, dcid, role)?;
        Ok(Self {
            send: keys.local,
            recv: vec![(send_version, keys.remote)],
        })
    }

    /// 指定バージョンの受信鍵を追加する
    ///
    /// 互換バージョン交渉でサーバーが Chosen Version の Initial を受信するために
    /// 使う。同じバージョンを既に持つ場合は何もしない。
    fn add_recv_version(
        &mut self,
        version: u32,
        dcid: &ConnectionId,
        role: Role,
    ) -> Result<(), Error> {
        if self.recv.iter().any(|(known, _)| *known == version) {
            return Ok(());
        }
        let keys = crypto::derive_initial_keys(version, dcid, role)?;
        self.recv.push((version, keys.remote));
        Ok(())
    }

    /// 指定バージョンの受信鍵を返す
    fn recv_for(&self, version: u32) -> Option<&crypto::DirectionalKeys> {
        self.recv
            .iter()
            .find(|(known, _)| *known == version)
            .map(|(_, keys)| keys)
    }
}

/// Handshake / 1-RTT レベルの鍵 (rustls ベース)
struct RustlsLevelKeys {
    local_packet: Box<dyn rustls::quic::PacketKey>,
    local_header: Box<dyn rustls::quic::HeaderProtectionKey>,
    /// remote パケット鍵
    ///
    /// 鍵更新では旧世代へ移してから新しい鍵を設定するため一時的に `None` になる。
    /// 更新処理の外では常に `Some` である。
    remote_packet: Option<Box<dyn rustls::quic::PacketKey>>,
    remote_header: Box<dyn rustls::quic::HeaderProtectionKey>,
}

/// 鍵更新前の 1-RTT 受信鍵の世代 (RFC 9001 Section 6.5)
///
/// 鍵更新後に再順序で到着した旧 Key Phase のパケットを復号するために保持する。
/// HP 鍵は鍵更新で変わらないため、保持するのは remote のパケット鍵だけでよい
/// (RFC 9001 Section 6)。
struct PreviousOneRttKeys {
    /// 更新前の remote パケット鍵
    remote_packet: Box<dyn rustls::quic::PacketKey>,
    /// 更新前の Key Phase bit
    key_phase: bool,
    /// 旧鍵の保持期限
    ///
    /// RFC 9001 Section 6.1: 更新後の鍵で保護されたパケットの保護解除に成功する
    /// まで旧鍵を保持しなければならない (MUST)。`None` はその成功前を表し、
    /// 期限を設けずに保持する。`Some(t)` は `t` まで保持することを表し、経過後は
    /// 破棄する (RFC 9001 Section 6.5)。値は更新後の鍵で最初に受信した時刻 +
    /// 全パスの最大 PTO の 3 倍 (3 × max(PTO)) である。
    expires_at: Option<Timestamp>,
}

/// CRYPTO 受信バッファの pending 蓄積上限 (Initial 用バイト数)
///
/// RFC 9000 Section 7.5 は out-of-order CRYPTO データを最低 4096 バイトまで
/// バッファリングすることを MUST とする。Initial の ClientHello / ServerHello は
/// 小さいため 16 KiB とする。
const CRYPTO_RECV_INITIAL_MAX_BYTES: usize = 16 * 1024;
/// CRYPTO 受信バッファの pending 蓄積上限 (Handshake / 1-RTT 用バイト数)
///
/// 証明書チェーンで大きくなるため 64 KiB とする。
const CRYPTO_RECV_HANDSHAKE_MAX_BYTES: usize = 64 * 1024;
/// 1-RTT CRYPTO 受信バッファの上限 (ポストハンドシェイクメッセージ用)
///
/// 1-RTT の CRYPTO は NewSessionTicket などのポストハンドシェイク
/// メッセージだけを運ぶため、Handshake と同じ 64 KiB とする。
const CRYPTO_RECV_1RTT_MAX_BYTES: usize = 64 * 1024;
/// CRYPTO 受信バッファの pending フラグメント数上限
///
/// `drain_pending` の最悪計算量 O(件数^2) による CPU 増幅を抑える。
const CRYPTO_RECV_MAX_PENDING_COUNT: usize = 256;

/// サーバーが Initial パケットを処理するために必要な最小データグラム長
///
/// RFC 9000 Section 14.1: サーバーは smallest allowed maximum datagram size である
/// 1200 バイト未満の UDP データグラムで運ばれた Initial パケットを破棄しなければ
/// ならない (MUST)。
const MIN_INITIAL_DATAGRAM_SIZE: usize = 1200;

/// Initial パケットの AEAD 認証タグ長
///
/// Initial パケットは AEAD_AES_128_GCM を使い、認証タグは 16 バイトである
/// (RFC 9001 Section 5 / Section 5.3)。Handshake / 1-RTT は交渉した暗号
/// スイートの `PacketKey::tag_len` を使う。
const INITIAL_AEAD_TAG_LEN: usize = 16;

/// Header Protection のサンプル長
///
/// RFC 9001 Section 5.4.2: サンプルは暗号スイートに依らず 16 バイトである。
/// AEAD の認証タグ長 (`INITIAL_AEAD_TAG_LEN` や `tag_len`) とは別の概念のため
/// 独立した定数にする。
const HP_SAMPLE_LEN: usize = 16;

/// CRYPTO フレームの受信バッファ
///
/// RFC 9000 Section 7.5: CRYPTO フレームは順不同で到着する可能性がある。
/// Chrome は 1 つの Initial パケット内でも CRYPTO フレームを断片化し、
/// offset が前後する順序で送信する。gap を許容して再組立する。
struct CryptoRecvBuffer {
    /// 連続データ (offset 0 から next_offset まで)
    data: Vec<u8>,
    /// 次に期待する連続オフセット
    next_offset: u64,
    /// gap のあるフラグメント (offset, data) を一時保持する
    pending: Vec<(u64, Vec<u8>)>,
    /// pending に蓄積できる最大バイト数
    max_buffer_bytes: usize,
    /// pending に蓄積できる最大フラグメント数
    max_pending_count: usize,
}

impl CryptoRecvBuffer {
    fn new(max_buffer_bytes: usize, max_pending_count: usize) -> Self {
        Self {
            data: Vec::new(),
            next_offset: 0,
            pending: Vec::new(),
            max_buffer_bytes,
            max_pending_count,
        }
    }

    fn receive(&mut self, offset: u64, data: &[u8]) -> Result<(), Error> {
        if data.is_empty() {
            return Ok(());
        }

        let end = offset + data.len() as u64;

        if offset <= self.next_offset {
            // 連続部分に追加できる (重複部分はスキップする)
            if end > self.next_offset {
                let skip = (self.next_offset - offset) as usize;
                self.data.extend_from_slice(&data[skip..]);
                self.next_offset = end;
                // pending から連続化できるフラグメントを取り込む
                self.drain_pending();
            }
        } else {
            // gap がある: pending に保存する前に蓄積量の上限を検査する
            // (RFC 9000 Section 7.5 / 20.1: CRYPTO_BUFFER_EXCEEDED)。
            // 上限ちょうどは許容する。
            let pending_bytes: usize = self.pending.iter().map(|(_, d)| d.len()).sum();
            if pending_bytes.saturating_add(data.len()) > self.max_buffer_bytes {
                return Err(Error::Protocol {
                    code: tobi_core::error::TransportErrorCode::CRYPTO_BUFFER_EXCEEDED,
                    reason: format!(
                        "CRYPTO buffer exceeded: {} + {} > {} bytes",
                        pending_bytes,
                        data.len(),
                        self.max_buffer_bytes
                    ),
                });
            }
            if self.pending.len() >= self.max_pending_count {
                return Err(Error::Protocol {
                    code: tobi_core::error::TransportErrorCode::CRYPTO_BUFFER_EXCEEDED,
                    reason: format!(
                        "CRYPTO pending fragments exceeded: {} >= {}",
                        self.pending.len(),
                        self.max_pending_count
                    ),
                });
            }
            self.pending.push((offset, data.to_vec()));
        }
        Ok(())
    }

    /// pending のフラグメントを連続データに取り込む
    fn drain_pending(&mut self) {
        loop {
            let mut merged = false;
            // next_offset に接続可能なフラグメントを探す
            let mut i = 0;
            while i < self.pending.len() {
                let (off, ref frag) = self.pending[i];
                let frag_end = off + frag.len() as u64;
                if off <= self.next_offset && frag_end > self.next_offset {
                    let skip = (self.next_offset - off) as usize;
                    self.data.extend_from_slice(&frag[skip..]);
                    self.next_offset = frag_end;
                    self.pending.swap_remove(i);
                    merged = true;
                } else if frag_end <= self.next_offset {
                    // 完全に重複しているフラグメントは除去する
                    self.pending.swap_remove(i);
                    merged = true;
                } else {
                    i += 1;
                }
            }
            if !merged {
                break;
            }
        }
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }

    /// 未消費の CRYPTO データ (連続データまたは未充填のギャップ) が無いか
    ///
    /// RFC 9001 Section 4.1.3: 低い暗号化レベルのデータを TLS が消費し切る前に
    /// 高い暗号化レベルのデータを渡してはならない。順序制御の判定に使う。
    fn is_empty(&self) -> bool {
        self.data.is_empty() && self.pending.is_empty()
    }
}

/// TLS セッションの保持
enum TlsSessionHolder {
    Client(tls::ClientTlsSession),
    Server(tls::ServerTlsSession),
}

/// データグラム内の 1 パケットを処理した結果
///
/// RFC 9000 Section 12.2 は、連結されたパケットの 1 つが復号できなくても、
/// 残りのパケットの処理を試みることを MUST とする。復号失敗はパケットだけを
/// 破棄し、Long Header の Length フィールドから求めた次のパケット位置へ進める。
enum PacketOutcome {
    /// パケットを処理した。値はデータグラム内で消費したバイト数。
    Processed(usize),
    /// パケットだけを破棄した。残りのパケットの処理は継続する。
    Dropped { consumed: usize, error: Error },
}

impl PacketOutcome {
    /// データグラム内で消費したバイト数を返す
    #[cfg(test)]
    fn consumed(&self) -> usize {
        match self {
            Self::Processed(consumed) | Self::Dropped { consumed, .. } => *consumed,
        }
    }
}

// --- Connection 本体 ---

/// Multipath QUIC 接続 (Sans I/O 状態マシン)
pub struct Connection<
    F: CongestionControlFactory = NewRenoFactory,
    S: SchedulerFactory = DefaultSchedulerFactory,
    P: PathControllerFactory = DefaultPathControllerFactory,
> {
    role: Role,
    state: ConnectionState,
    local_params: TransportParams,
    peer_params: Option<TransportParams>,
    /// 0-RTT 用に保存していたピアトランスポートパラメータ
    ///
    /// `set_early_peer_params()` で設定された値を保持し、ハンドシェイク完了後の
    /// `max_datagram_frame_size` バリデーション (RFC 9221 Section 3) に使用する。
    early_peer_params: Option<TransportParams>,
    /// ピアが広告した Receive Timestamps 拡張の設定
    ///
    /// None はピアが拡張を広告していない (max_receive_timestamps_per_ack が
    /// 存在しない、または 0) ことを表す。0-RTT で記憶した値は使わず、今回の
    /// ハンドシェイクで確定した値だけを入れる。
    peer_receive_timestamps: Option<PeerReceiveTimestamps>,
    /// ハンドシェイクで受信した実ピアトランスポートパラメータが適用済みか
    ///
    /// `set_early_peer_params()` で `peer_params` を先に埋めても、ハンドシェイクで
    /// サーバーが送信した実値を必ず再処理して検証を行うために必要なフラグ。
    peer_params_finalized: bool,
    paths: PathManager<F>,
    /// ハンドシェイクで使用したローカルアドレス (RFC 9000 Section 9)
    ///
    /// `disable_active_migration` の判定で「ハンドシェイクアドレス」を特定するために保持する。
    handshake_local_addr: std::net::SocketAddr,
    /// ハンドシェイクで使用したピアアドレス (RFC 9000 Section 9)
    handshake_remote_addr: std::net::SocketAddr,
    /// preferred_address に従って移行したことがあるか
    ///
    /// `disable_active_migration` は preferred_address に従った移行後の
    /// アクティブマイグレーションを禁止しない (RFC 9000 Section 9.6)。
    acted_on_preferred_address: bool,

    stats: ConnectionStats,
    /// 最初の送受信を観測した時刻 (経過時間の起点)
    started_at: Option<Timestamp>,
    /// 直近で復号に成功したパケットが属するパス
    ///
    /// 受信統計を UDP データグラム単位でパスへ帰属させるために使う。
    /// `process_short_header` などで復号に成功した時点で設定される。
    last_valid_recv_path: Option<PathId>,
    local_cid: ConnectionId,
    peer_cid: ConnectionId,
    initial_dcid: ConnectionId,
    /// この接続で使用する QUIC バージョン (RFC 9000 Section 15 / RFC 9369 Section 3.1)
    version: u32,
    /// 対応する QUIC バージョンの一覧 (Version Negotiation 再試行の候補)
    supported_versions: Vec<u32>,
    /// 受信した Version Negotiation が提示したバージョン一覧
    ///
    /// クライアントは接続を中止したうえで、上位層がこの一覧を使って
    /// 別バージョンで再試行する (RFC 9000 Section 6.2)。
    version_negotiation_versions: Option<Vec<u32>>,
    /// Version Negotiation に反応して開始した接続試行か (RFC 9368 Section 4)
    ///
    /// 真の場合、この接続試行中に受信した Version Negotiation は
    /// ダウングレード攻撃対策のため無視する (MUST)。
    vn_retry: bool,
    /// ピアが現在の接続で QUIC Bit の greasing を広告したか (RFC 9287 Section 3)
    ///
    /// None = ピアのトランスポートパラメータ未確定。0-RTT 用に記憶した値は
    /// 使わない (Section 3.1: サーバーは過去の接続の広告を記憶してはならない)。
    peer_grease_quic_bit: Option<bool>,
    /// ピアが広告した場合に QUIC Bit 0 を送るか
    ///
    /// `ConnectionConfig::send_zero_quic_bit` の値。既定は false (常に 1)。
    send_zero_quic_bit: bool,
    /// ピアが最初の Initial パケットで使った SCID (RFC 9000 Section 7.3)
    ///
    /// サーバーがクライアントの initial_source_connection_id を検証するために記録する。
    peer_initial_scid: Option<ConnectionId>,
    /// サーバーが最初の Initial パケットで使った SCID (RFC 9000 Section 7.2)
    ///
    /// クライアントがサーバーの initial_source_connection_id を検証し、
    /// 2 通目以降で異なる SCID を持つ Initial を破棄するために記録する。
    server_initial_scid: Option<ConnectionId>,
    /// 互換バージョン交渉でクライアントが最初の flight に使ったバージョン
    ///
    /// RFC 9368 Section 2.3: サーバーがクライアントの Chosen Version と
    /// 異なるバージョンを選んだ場合、ルーターがここに Chosen Version を
    /// 設定する。サーバーはこのバージョンの Initial も受信してハンドシェイクを
    /// 開始し、ネゴシエート済みバージョンで応答する。
    compatible_client_version: Option<u32>,
    /// クライアントがサーバーの Initial で検出した互換バージョン
    ///
    /// RFC 9368 Section 2.3: サーバーがクライアントの Chosen Version と
    /// 異なる互換バージョンで応答した場合、クライアントはそのバージョンを
    /// 記録して接続を閉じる。rustls の QUIC セッションがバージョンに
    /// 束縛され、接続内でバージョンを切り替えられないため、上位層が
    /// このバージョンで新しい接続試行を開始する。
    compatible_version_switch: Option<u32>,

    // ストリーム管理
    streams: StreamManager,

    // 鍵
    initial_keys: Option<InitialKeys>,
    /// Initial 鍵を破棄済みか
    ///
    /// RFC 9001 Section 4.9.1 に基づき一度破棄した Initial 鍵は再導出しない。
    /// ハンドシェイク完了後に Initial パケットを受信しても、復号・フレーム処理を
    /// 行わずに silent discard するために使う。
    initial_keys_discarded: bool,
    /// サーバーが最初の Handshake パケットを正常に処理したか
    ///
    /// サーバーはこの時点で Initial 鍵を破棄する (RFC 9001 Section 4.9.1)。
    /// Handshake 鍵の導出直後 (ServerHello 送信時) に破棄すると、ServerHello の
    /// ロストでハンドシェイクが停止する。
    initial_handshake_processed: bool,
    handshake_keys: Option<RustlsLevelKeys>,
    one_rtt_keys: Option<RustlsLevelKeys>,

    // TLS
    tls_session: TlsSessionHolder,
    /// ネゴシエートされた ALPN プロトコル
    alpn_protocol: Option<Vec<u8>>,

    // CRYPTO バッファ
    crypto_send_initial: Vec<u8>,
    /// Initial CRYPTO の再送待ち (元の offset を保持する)
    ///
    /// RFC 9001 Section 4.1.3: 再送は最初に送ったときと同じ offset で行う。
    /// 新規送信データの末尾へ追加すると offset がずれ、ピアが同じ
    /// ClientHello を別メッセージとして処理してしまう。
    crypto_retransmit_initial: VecDeque<(u64, Vec<u8>)>,
    crypto_send_handshake: Vec<u8>,
    /// 1-RTT CRYPTO 送信バッファ (ポストハンドシェイクメッセージ: NewSessionTicket 等)
    crypto_send_1rtt: Vec<u8>,
    crypto_send_initial_offset: u64,
    crypto_send_handshake_offset: u64,
    crypto_send_1rtt_offset: u64,
    crypto_recv_initial: CryptoRecvBuffer,
    crypto_recv_handshake: CryptoRecvBuffer,
    /// 1-RTT CRYPTO の受信バッファ
    ///
    /// RFC 9001 Section 4.1.3: 暗号化レベルごとに CRYPTO データのバイト列
    /// (オフセット空間) は独立している。Handshake と 1-RTT を同じバッファに
    /// 流すと、どちらも offset 0 から始まるためオフセットが衝突する。
    crypto_recv_1rtt: CryptoRecvBuffer,

    // パケット番号空間 (RFC 9000 Section 12.3)
    // Initial / Handshake / Application (1-RTT) は独立したパケット番号空間を持つ。
    // Application 空間は Path ごとに管理する。Initial / Handshake は初期パスのみ。
    /// Initial パケット番号空間: 送信 PN
    initial_send_pn: u64,
    /// Initial パケット番号空間: 受信 PN 最大値
    initial_recv_pn_largest: Option<u64>,
    /// Initial パケット番号空間: ACK 追跡
    initial_ack_tracker: AckTracker,
    /// Initial パケット番号空間: 送信済みパケット
    initial_sent_packets: SentPackets,
    /// Handshake パケット番号空間: 送信 PN
    handshake_send_pn: u64,
    /// Handshake パケット番号空間: 受信 PN 最大値
    handshake_recv_pn_largest: Option<u64>,
    /// Handshake パケット番号空間: ACK 追跡
    handshake_ack_tracker: AckTracker,
    /// Handshake パケット番号空間: 送信済みパケット
    handshake_sent_packets: SentPackets,
    /// DPLPMTUD プローブとして送信した 1-RTT パケットの (path, PN)
    ///
    /// RFC 8899 Section 5.7: プローブのロストは輻輳の兆候として扱わない。
    /// Application Data 空間の通常のロスト検出から区別するために記録する。
    pmtu_probe_pns: Vec<(PathId, u64)>,
    /// `emit_packets` 中のパス使用記録を有効にするか
    emit_tracking: bool,
    /// 今回の送信機会で 1-RTT パケットを出力したパス
    emit_used_paths: Vec<PathId>,
    /// DPLPMTUD プローブタイムアウトの連続回数 (path ごと)
    ///
    /// RFC 9002 Section 6.2.1 の PTO バックオフと同様に、連続タイムアウトでは
    /// 再プローブ間隔を指数的に増やす。ACK を受けたらリセットする。
    pmtu_probe_backoff: std::collections::HashMap<PathId, u32>,

    // 出力 / イベント
    output_queue: VecDeque<ConnectionOutput>,
    /// 暗号化前に保持する 1-RTT の未送信内容
    one_rtt_outputs: VecDeque<PendingOneRtt>,
    /// 実出力の完了まで CID と I/O を保持するパス
    pending_abandon_completion: std::collections::HashSet<PathId>,
    /// PathController のアクション実行の再入深度
    ///
    /// `AbandonPath` の実行が `PathAbandoned` の通知からアクション実行へ
    /// 再入するため、実装の誤りで連鎖し続けた場合の防御に使う。
    path_action_depth: usize,
    /// 同じ pacing 期限を出力し続けないための armed 状態
    pacing_deadlines: std::collections::HashMap<PathId, Timestamp>,
    /// 現在時刻の実出力バースト量
    one_rtt_bursts: std::collections::HashMap<PathId, (Timestamp, u64)>,
    event_queue: VecDeque<ConnectionEvent>,

    // 観測イベント (購読者がある場合のみ有効化する)
    /// 観測イベントを記録するか
    ///
    /// アプリケーションが購読した接続でのみ true。未購読時はイベント生成の
    /// コストを払わない。
    observation_enabled: bool,
    /// 観測イベントのキュー
    ///
    /// driver が 1 処理ステップごとに取り出す。取り出しが遅れて溢れた場合は
    /// 古いイベントから破棄する (接続処理をブロックしない)。
    observation_queue: VecDeque<ConnectionObservationEvent>,
    /// パスごとに最後に観測した輻輳制御の状態
    ///
    /// 状態が変化したときだけ `CongestionStateChanged` を発行するために使う。
    observed_congestion_states: std::collections::HashMap<PathId, CongestionStateKind>,

    // ハンドシェイク状態
    handshake_done_sent: bool,
    handshake_done_received: bool,
    /// ハンドシェイクが一度確認されたか
    ///
    /// `is_handshake_confirmed` は Connected の間だけ true を返すため、
    /// Closing / Draining へ遷移した後も実効 ACK delay を PTO に含められる
    /// よう、確認済みであることを保持する (RFC 9002 Section 6.2.1)。
    handshake_confirmed_once: bool,

    // 鍵更新 (RFC 10069 Section 2.5)
    /// 次の鍵更新用シークレット
    next_secrets: Option<rustls::quic::Secrets>,
    /// 現在の Key Phase (false = 0, true = 1)
    key_phase: bool,
    /// 鍵更新前の 1-RTT 受信鍵 (RFC 9001 Section 6.5)
    ///
    /// 鍵更新の直後に再順序で到着した旧 Key Phase のパケットを復号するために
    /// 保持する。更新後の鍵で保護されたパケットの保護解除に成功するまでは
    /// 破棄しない (RFC 9001 Section 6.1)。
    previous_one_rtt_keys: Option<PreviousOneRttKeys>,

    /// 現行の Key Phase で受信した、パスごとの最小パケット番号
    ///
    /// RFC 9001 Section 6.5: 前世代と次世代の鍵は同じ Key Phase bit を持つため、
    /// どちらの鍵かをパケット番号で判定する。旧鍵で復号できたパケットの
    /// パケット番号がこの値以上なら、そのパケット番号以下で新しい鍵が使われた
    /// ことになり、KEY_UPDATE_ERROR とする (RFC 9001 Section 6.4)。
    /// エントリが無いパスは、現行の Key Phase のパケットをまだ受信していない。
    current_key_phase_lowest_recv_pns: std::collections::HashMap<PathId, u64>,

    /// 次の鍵更新が許可される時刻
    ///
    /// 鍵更新を実行した時点ではなく、現行の Key Phase で送ったパケットを確認した
    /// 最初の ACK を受信した時点から、全パスの最大 PTO の 3 倍
    /// (3 × max(PTO)) だけ待つ (RFC 9001 Section 6.5、
    /// RFC 10069 Section 2.5)。確認 ACK を受けるまでは
    /// None のままとする。TLS が最初に提供した 1-RTT 鍵のフェーズでは設定しない。
    key_update_allowed_at: Option<Timestamp>,

    /// 現行の Key Phase を開始した時点の、パスごとの次回送信パケット番号
    ///
    /// RFC 9001 Section 6.1: 現行鍵フェーズで送ったパケットの ACK を受けるまで
    /// 次の鍵更新を開始してはならない (MUST NOT)。送信時刻の比較では同一時刻に
    /// 送った旧フェーズのパケットと区別できないため、フェーズ開始時の次回送信
    /// パケット番号を記録し、ACK されたパケット番号と比較する。
    /// 記録が無いパス (フェーズ開始後に作られたパス) は全パケットが現行フェーズ
    /// なので 0 として扱う。
    one_rtt_phase_start_pns: std::collections::HashMap<PathId, u64>,
    /// 現行の Key Phase で送ったパケットの ACK を 1 つ以上受けたか
    /// (RFC 9001 Section 6.1)
    current_phase_acked: bool,
    /// 現行の Key Phase が鍵更新で開始されたか
    ///
    /// TLS が最初に提供した 1-RTT 鍵のフェーズでは false のままにする。
    /// 確認 ACK による再更新の待機時間は、鍵更新後のフェーズだけに課す。
    /// 一度 true になったら接続中は true のままとする。
    key_phase_established_by_update: bool,

    // AEAD 制限 (RFC 9001 Appendix B / RFC 10069 Section 7.3)
    /// 現在の 1-RTT 鍵で送信した全パス合計パケット数
    /// confidentiality limit に達したら鍵更新をトリガーする
    one_rtt_packets_sent: u64,
    /// AEAD 認証に失敗した受信パケット数
    /// 接続生涯で across all keys 累積し、integrity limit を超えたら
    /// AEAD_LIMIT_REACHED で接続を閉じる (RFC 9001 Section 6.6)
    /// AEAD 認証に失敗した回数 (integrity limit の判定用)
    ///
    /// ピア起点の Key Phase trial の失敗も含む。trial が後続の鍵で成功すると
    /// パケットは破棄されないため、`ConnectionStats::packet_dropped_decryption_failure`
    /// とは一致しない。パケット破棄の観測には統計の破棄カウンタを使う。
    aead_auth_failures: u64,

    // RETRY (RFC 9000 Section 17.2.5)
    /// サーバーから受信した Retry トークン
    retry_token: Vec<u8>,
    /// Retry で受信したサーバー SCID (RFC 9000 Section 7.3 の検証用)
    retry_scid: Option<ConnectionId>,
    /// Retry パケット受信済みフラグ (2 回目を拒否するため)
    retry_received: bool,
    /// 元の Initial DCID (Retry Integrity Tag 検証用)
    original_dcid: ConnectionId,

    // 0-RTT (RFC 9001 Section 4.6)
    /// 0-RTT 鍵 (クライアント: 送信用、サーバー: 受信用)
    zero_rtt_keys: Option<tls::ZeroRttKeys>,
    /// 0-RTT パケットの受信に成功したか (サーバー側の追跡用)
    zero_rtt_accepted: bool,
    /// セッションチケット受信済みフラグ (重複イベント防止)
    session_ticket_received: bool,
    /// クライアントが 0-RTT パケットを送信したか (拒否時フォールバック用)
    zero_rtt_sent: bool,
    /// クライアントが 0-RTT で送信したパケット番号の範囲 (最小, 最大)
    ///
    /// 0-RTT 拒否後に 0-RTT パケットへの ACK を受信した場合の違反検出に使う
    /// (RFC 9001 Section 4.6.2)。
    zero_rtt_sent_pn_range: Option<(u64, u64)>,
    /// クライアントが 0-RTT 拒否を検出したか
    zero_rtt_rejected: bool,
    /// サーバーが受信した 0-RTT のセッションチケットのハッシュ (リプレイ検出用)
    zero_rtt_ticket_hash: Option<Vec<u8>>,
    /// サーバーが 1-RTT パケットを初めて復号した時刻
    ///
    /// この時刻から 3 × PTO 経過後に 0-RTT 鍵を破棄する (RFC 9001 Section 4.9.3)。
    zero_rtt_keys_discard_at: Option<Timestamp>,

    // NEW_TOKEN (RFC 9000 Section 8.1)
    /// アドレス検証トークン (NEW_TOKEN フレームまたは Retry で受信)
    /// 次回接続の Initial パケットに含める
    address_token: Vec<u8>,
    /// トークンプロバイダ (サーバー側のトークン生成・検証)
    ///
    /// サーバー全体で同一のインスタンスを共有して参照するため `Arc` とする。
    token_provider: Option<std::sync::Arc<dyn tobi_core::token::TokenProvider>>,
    /// Initial で受信したアドレストークンが検証できたか
    ///
    /// ハンドシェイク完了時にアドレス検証済みになるため、`address_validated`
    /// だけではトークンによる検証と区別できない。トークンの受理可否を
    /// 観測するために別途記録する。
    initial_token_validated: bool,
    /// 0-RTT リプレイフィルター (サーバー側)
    ///
    /// 複数接続から同一フィルターを共有して参照するため `Arc` とする。
    replay_filter: Option<std::sync::Arc<dyn tobi_core::token::ReplayFilter>>,

    // PTO プローブ
    /// PTO 発火でプローブ送信が必要なパス
    pto_probe_paths: Vec<PathId>,
    /// Handshake 空間の PTO で送信を待つプローブ数
    ///
    /// RFC 9002 Section 6.2.4: PTO で送る probe は ack-eliciting でなければ
    /// ならない (MUST)。同 Section 6.2.2.1: クライアントは Handshake 鍵を持つが
    /// ack-eliciting な Handshake パケットを in-flight に持たない場合、PTO で
    /// Handshake パケットを送らなければならない (MUST)。未確認 CRYPTO が
    /// ある場合は最大 2 個を使い、先のプローブが失われても ACK の機会を作る。
    /// データが無い場合は同節の SHOULD に従い PING を 1 個だけ送る。
    /// 仕様改訂時には個数と送信条件を見直す。
    handshake_pto_probes_pending: u8,
    /// Initial 空間の PTO で送信を待つプローブ数
    ///
    /// RFC 9002 Section 6.2.4: PTO では ack-eliciting パケットを最低 1 つ
    /// 送る (MUST)。同節は最大 2 つの full-sized datagram を許可しており
    /// (MAY)、1 つのプローブが失われた場合も次の PTO まで待たずに回復できる。
    /// 30% 損失 / 破損の multiconnect 試験では、ハンドシェイク中の Initial
    /// プローブが続けて失われると接続の期限までに完了しないことがあるため、
    /// 2 個送る。
    initial_pto_probes_pending: u8,
    /// ハンドシェイク確認前の PTO で、経路検証用の CID を先に送るか
    ///
    /// クライアントが 1-RTT 鍵を持つが HANDSHAKE_DONE 未受信のとき、対向は
    /// 新しい経路の検証に未使用の CID を必要とする (RFC 9000 Section 9.5)。
    pre_confirmation_cids_pending: bool,

    // アイドルタイムアウト
    /// ネゴシエート済みのアイドルタイムアウト (ミリ秒、0 = 無効)
    idle_timeout_ms: u64,
    /// Keep-Alive の既定値 (RFC 9000 Section 10.1.2)
    ///
    /// パス作成時に各パスへ継承される。`Connection::set_keep_alive` は
    /// この既定値と既存の全パスの設定を同時に変更する。
    keep_alive_enabled: bool,
    /// 設定で明示された keep-alive の送信間隔
    ///
    /// `None` の場合はアイドルタイムアウトの 3/4 を使う。明示された場合は
    /// アイドルタイムアウトが無効でも keep-alive を動作させる
    /// (RFC 10069 Section 5.9)。
    keep_alive_interval: Option<Duration>,
    /// 遅延 ACK (RFC 9000 Section 13.2.2) を有効にするか
    ///
    /// 既定は false (ack-eliciting パケットごとに即時 ACK)。
    delayed_ack: bool,
    /// 到達性確認中 (PATH_CHALLENGE 送信済み) のパス
    ///
    /// 昇格前の確認に使う。PATH_RESPONSE を受信するか、検証のリトライ上限を
    /// 超えてパスを廃棄するまで保持する。
    pending_path_probes: std::collections::HashSet<PathId>,
    /// 損失検出タイマーを armed 済みのパスとパケット番号空間
    ///
    /// タイマーが armed されていないパスに対して ClearTimer を出力しないために
    /// 保持する。ARM していないタイマーの破棄で余計な出力を出すと、silent に
    /// 破棄すべきパケット (1200 バイト未満の Initial など) で出力が生じてしまう。
    /// タイマーは 1 パスにつき 1 つで、期限が最も早い空間を記録する
    /// (RFC 9002 Section 6.2 / Appendix A.8)。
    loss_detection_timers_armed: std::collections::HashMap<PathId, PacketNumberSpace>,

    // アンチアンプリフィケーション (RFC 9000 Section 8.1)
    /// アドレス検証が完了したか
    address_validated: bool,
    /// ハンドシェイク完了前の受信バイト数 (サーバーのみ)
    ///
    /// 増幅予算は送信先アドレスごとに評価する (RFC 9000 Section 8.1)。
    /// `amplification_addr` が変わった時点でこの値と送信バイト数を 0 に戻す。
    recv_bytes_before_validated: u64,
    /// ハンドシェイク完了前の送信バイト数 (サーバーのみ)
    sent_bytes_before_validated: u64,
    /// 現在の増幅予算が紐づく 4-tuple
    ///
    /// 未検証アドレスから受信したバイト数の 3 倍だけを送信できる。
    /// 別アドレスから受信した分を現在の送信先の予算へ流用しない。
    amplification_addr: Option<(std::net::SocketAddr, std::net::SocketAddr)>,
    /// 処理中の UDP payload 長。増幅予算へ一度加算したら None にする。
    ///
    /// コアレシングされたパケットごとの Length では、UDP の余白を計上できない。
    current_recv_datagram_len: Option<usize>,
    /// ハンドシェイク中のリバインディングで、PATH_CHALLENGE を先に送るための保留
    ///
    /// 対向のアドレス変更を検出した直後は、新しい 4-tuple への最初のサーバー
    /// パケットに PATH_CHALLENGE を含める必要がある。Initial / Handshake の
    /// 再送より先に 1-RTT の PATH_CHALLENGE を送れるよう、保留中は初期パス宛ての
    /// 暗号化済みデータグラムを取り出さない。PATH_CHALLENGE の送信で解除する。
    defer_initial_datagrams_until_challenge: bool,
    /// 4-tuple の変更直後に PATH_CHALLENGE 以外の 1-RTT 出力を保留するパス
    ///
    /// アドレス変更の検出時は、最初のサーバー パケットを PATH_CHALLENGE にする。
    /// ACK だけの 1-RTT 出力が先に送られるのを防ぐため、PATH_CHALLENGE を
    /// 送信できるまで対象パスの他の出力を取り出さない。送信で解除する。
    defer_path_datagrams_until_challenge: Option<PathId>,

    // CRYPTO 再送
    /// Initial レベルの送信済み CRYPTO データ (再送用に保持)
    crypto_sent_initial: Vec<u8>,
    /// Handshake レベルの送信済み CRYPTO データ (再送用に保持)
    crypto_sent_handshake: Vec<u8>,
    /// Handshake レベルの CRYPTO 再送待ちフレーム (元のオフセット, データ)
    ///
    /// 新規送信データ (`crypto_send_handshake`) とは別に持つ。新規データは
    /// `crypto_send_handshake_offset` の位置へ順に送るのに対し、再送は最初に
    /// 送ったときと同じ暗号化レベル・同じオフセットで送る (RFC 9001
    /// Section 4.9、RFC 9000 Section 19.6)。PTO や部分損失で未送信の新規
    /// データが残っていても、このキューが新規データのオフセットを
    /// 巻き戻さない。
    crypto_retransmit_handshake: VecDeque<(u64, Vec<u8>)>,
    /// 1-RTT レベルの送信済み CRYPTO データ (再送用に保持)
    ///
    /// 再送は元の暗号化レベルと元のオフセットで行う (RFC 9001 Section 4.9、
    /// RFC 9000 Section 19.6)。NewSessionTicket などのポストハンドシェイク
    /// メッセージのロストを回復するために保持する。
    crypto_sent_1rtt: Vec<u8>,
    /// 1-RTT レベルの CRYPTO 再送待ちフレーム (元のオフセット, データ)
    ///
    /// 新規送信データ (`crypto_send_1rtt`) とは別に持つ。新規データは
    /// 末尾のオフセットで送るのに対し、再送は元のオフセットで送る必要がある。
    crypto_retransmit_1rtt: VecDeque<(u64, Vec<u8>)>,

    // CID 管理
    /// 発行済みローカル CID テーブル ((path_id, sequence_number) → ConnectionId)
    /// パスごとに独立したシーケンス番号空間を使用する
    /// (RFC 10069 Section 4)
    local_cid_table: std::collections::HashMap<(u32, u64), ConnectionId>,
    /// 自分が退役を要求済みの CID の境界。RETIRE の到着待ちを
    /// アクティブな CID と数えると、補充のたびに退役要求が連鎖する。
    local_cid_retire_prior_to: std::collections::HashMap<u32, u64>,
    /// ローカル CID の長さ (バイト)
    local_cid_len: usize,

    /// ピアの initial_max_path_id (MAX_PATH_ID バリデーション用)
    /// RFC 10069 Section 4.6:
    /// MAX_PATH_ID は initial_max_path_id 未満の値を通知してはならない
    peer_initial_max_path_id: u32,

    /// Closing 状態で再送する CONNECTION_CLOSE パケット (RFC 9000 Section 10.2.1)
    closing_packet: Option<Vec<u8>>,
    /// Closing 状態での最後の CONNECTION_CLOSE 再送時刻 (レート制限用)
    closing_last_resend: Option<Timestamp>,
    /// `closing_packet` を再送するパス
    ///
    /// 1-RTT の CONNECTION_CLOSE は、そのとき Active なパスの 4-tuple へ出す
    /// (RFC 10069 Section 2.6)。
    closing_path_id: PathId,

    /// ピアから受信した CID の追跡テーブル
    ///
    /// NEW_CONNECTION_ID / PATH_NEW_CONNECTION_ID で有効化したピア CID と、
    /// ハンドシェイクで受領した初期 CID (シーケンス番号 0) および
    /// preferred_address の CID (シーケンス番号 1) を保持する。用途は次の通り。
    ///
    /// - Stateless Reset の検出 (RFC 9000 Section 10.3)
    /// - 送信先 CID の能動回転と、退役後の送信先 CID の選び直し
    /// - migration の候補 CID の選択
    /// - PATH_ABANDON 時の CID 退役
    /// - `active_connection_id_limit` の会計
    ///
    /// 初期 CID と preferred_address の CID も含むため、ピアが発行した
    /// 追加 CID だけを数える用途には使わないこと。
    ///
    /// 有効なピア CID の集合を兼ねる。同じ CID の重複登録は、このベクタを
    /// 線形走査して判定する。ピア CID は 1 パスあたり
    /// `active_connection_id_limit` 程度しか登録されないため、走査コストは
    /// 無視できる。`PathManager::lookup_by_cid` が参照するマップは自分が発行した
    /// ローカル CID 専用である。ピア CID を同じマップへ登録すると、平文で
    /// 観測できるピア CID を DCID にした Short Header がローカル接続へ誤って
    /// 紐づき、AEAD 復号を試みられる。また、ピアがローカル CID と同じ値を
    /// 発行した場合にローカル CID のルーティングを上書きし得る。そのため
    /// ピア CID は独立した本ベクタで管理し、ローカル CID との衝突は
    /// `PathManager::contains_cid` で別に判定する。
    ///
    /// `used` は送信先への採用状況、`stateless_reset_token` は Stateless Reset
    /// の検出に使う。
    peer_cid_entries: Vec<PeerCidEntry>,
    /// パスごとに受信したピア CID の最大シーケンス番号
    ///
    /// RFC 10069 Section 4.7 の PATH_CIDS_BLOCKED が通知する
    /// Next Sequence Number (次に発行されると期待するシーケンス番号) を求めるため、
    /// CID 退役後も peer_cid_entries から消えた最大値だけ保持する。
    /// 初期 CID (シーケンス番号 0) と preferred_address の CID (シーケンス番号 1)
    /// も受信済みとして数える。
    ///
    /// 不変条件: 有効化したピア CID の最大シーケンス番号は、そのパスの
    /// 最大 Retire Prior To 以上になる。Retire Prior To を増加させるフレームは
    /// 必ず `retire_prior_to <= sequence_number` を満たし、その CID を有効化する
    /// ため (RFC 9000 Section 19.15)。
    peer_cid_max_seq: std::collections::HashMap<u32, u64>,
    /// パスごとに受信した Retire Prior To の最大値
    ///
    /// NEW_CONNECTION_ID / PATH_NEW_CONNECTION_ID で受信した Retire Prior To の
    /// パスごとの最大値。CID 退役後も保持し、後着した古い CID を有効化しない
    /// ために使う。RFC 9000 Section 19.15: 最大値を増加させない Retire Prior To は
    /// 無視しなければならない (MUST)。path ID 0 では NEW_CONNECTION_ID と
    /// PATH_NEW_CONNECTION_ID が同じ最大値を共有する
    /// (RFC 10069 Section 3.2 / Section 4.4)。
    /// 未受信のパスは 0 として扱う。
    peer_cid_retire_prior_to: std::collections::HashMap<u32, u64>,
    /// RETIRE_CONNECTION_ID / PATH_RETIRE_CONNECTION_ID を送信待ちに積んだ
    /// (パス ID, シーケンス番号) の履歴
    ///
    /// 同じシーケンス番号の退役フレームを二重に積まないための重複抑止と、
    /// 未 ACK の退役 CID 数の会計に使う。パス ID ごとに独立したシーケンス番号
    /// 空間を持つ (RFC 10069 Section 3.2 / Section 4.4)。
    /// 履歴の上限と、上限超過時に同じシーケンス番号の RETIRE を重ねて送る扱いは
    /// MAX_RETIRED_PEER_CID_HISTORY を参照。ACK で確認された記録は削除する。
    retired_peer_cid_seq: std::collections::HashSet<(u32, u64)>,
    /// `retired_peer_cid_seq` の挿入順 (古い記録から捨てるため)
    ///
    /// 集合と同じ要素を持ち、上限超過時に先頭から取り除く。ACK で削除する
    /// 場合も同じ要素を取り除く。
    retired_peer_cid_order: VecDeque<(u32, u64)>,
    /// 退役したピア CID の値から (パス ID, シーケンス番号) を引く対応表
    ///
    /// `peer_cid_entries` は退役した CID を保持しないため、退役済み CID を
    /// パケットの DCID に使っていないかを送信前に検査するには、CID の値から
    /// シーケンス番号を引く必要がある (RFC 9000 Section 19.16)。
    /// `retired_peer_cid_seq` と同じ履歴を上限とし、ACK で確認された記録は
    /// 集合と同時に削除する。退役済み CID を使うパケットは通常の送信経路では
    /// 作られないため、参照は防御的な検査に限られる。
    retired_peer_cid_identities: std::collections::HashMap<(u32, u64), ConnectionId>,
    /// CID 枯渇による PATH_CIDS_BLOCKED を送信済みのパス
    ///
    /// RFC 10069 Section 4.7 の通知はピアの行動を要求しない
    /// ため、同一の枯渇状態で繰り返し送らない。新しいピア CID を受信したら
    /// 解除する。
    cid_blocked_notified: std::collections::HashSet<u32>,

    // qlog (draft-ietf-quic-qlog-main-schema-14)
    /// qlog ライター (None の場合はログ無効)
    qlog_writer: Option<Box<dyn qlog::QlogWriter>>,
    /// qlog 用の基準時刻
    qlog_start: Option<std::time::Instant>,

    /// CONNECTION_CLOSE フレームの reason phrase フォーマッタ
    ///
    /// `Connection::close` が送る全ての鍵レベル (Initial / Handshake / 1-RTT) の
    /// reason phrase に適用する。None の場合は元の reason バイト列をそのまま送信する。
    close_formatter: Option<Arc<dyn ConnectionCloseFormatter>>,

    /// Stateless Reset Token 生成器
    ///
    /// 設定すると `generate_new_cid` / `issue_proactive_cids` が発行する CID の
    /// Token を `generator.generate(cid.as_bytes())` から得る。None の場合は
    /// 乱数で生成する。設定時は同一 CID から決定的に Token を再生成できるため、
    /// 再起動 / マルチインスタンスをまたいだ Stateless Reset に使用できる
    /// (RFC 9000 Section 10.3.2)。
    stateless_reset_generator: Option<Arc<dyn StatelessResetTokenGenerator>>,

    /// 現在処理中のデータグラムの ECN コードポイント
    ///
    /// `receive_with_ecn` が設定し、`receive` の終了時に `NotEct` へ戻す。
    /// パケット処理の内部関数へ引数を増やさずに ECN を伝えるための一時状態で、
    /// Sans I/O の接続は受信処理を並行に走らせないため安全に使える。
    current_recv_ecn: EcnCodepoint,

    /// ACK Frequency 拡張で送信した要求値のうち、まだ ACK されていないもの
    ///
    /// (Sequence Number, Requested Max Ack Delay (マイクロ秒))。
    /// draft-ietf-quic-ack-frequency-14 Section 7: ACK されるまでの間は現在の
    /// max_ack_delay とこれらの最大値を PTO 計算に使わなければならない (MUST)。
    ack_frequency_in_flight: Vec<(u64, u64)>,
    /// ACK_FREQUENCY が ACK された最新の要求値 (Sequence Number, 要求値)
    ///
    /// in-flight が無い場合の PTO 計算の基準として使う。未 ACK なら
    /// ピアの transport parameter の max_ack_delay を使う。
    ack_frequency_last_acked: Option<(u64, u64)>,
    /// 次に送信する ACK_FREQUENCY のシーケンス番号
    ack_frequency_next_sequence_number: u64,

    /// 現在の受信処理で認証に成功したパケットがあるか
    ///
    /// RFC 9000 Section 10.1 のアイドルタイマーのリスタートは「パケットを正常に
    /// 受信・処理した」場合に限られる。復号に失敗したパケットでリスタートすると、
    /// 攻撃者が任意のデータグラムを送るだけで接続の寿命を延ばせてしまうため、
    /// AEAD 復号に成功したパケットだけを対象に判定する。
    received_valid_packet: bool,

    /// 最後に open_path() を呼び出した時刻 (レート制限用)
    /// (RFC 10069 Section 7.2)
    last_path_open_time: Option<Timestamp>,

    /// プロアクティブ CID 発行済みパスの次の seq 番号
    /// パスがまだ存在しない時に CID を先行発行した場合、
    /// パス作成時に next_local_cid_seq を正しく初期化するために使用する。
    proactive_cid_next_seq: std::collections::HashMap<u32, u64>,

    /// 廃棄済みパス ID の tombstone セット
    ///
    /// RFC 10069 Section 4:
    /// "処理できなくなった path ID の multipath frame は MUST silently ignore"
    ///
    /// 3 PTO 後に remove_path() でパス状態を物理削除した後も、
    /// 遅延した multipath frame を正しく無視するために保持する。

    /// Multipath スケジューラー (Data / ACK / Retransmission)
    scheduler: MultipathScheduler<S::Data, S::Ack, S::Retx>,

    /// パス自動管理コントローラー
    path_controller: P::Controller,
    /// Multipath ポリシー設定
    multipath_policy: MultipathPolicy,

    /// 各パスの最後の ACK 送信パスを追跡する
    /// (acked_path_id → last_ack_send_path_id)
    /// ACK パス変更時に Path::ack_path_changed を設定する
    last_ack_send_path: std::collections::HashMap<PathId, PathId>,

    // DATAGRAM 拡張 (RFC 9221)
    /// 送信待ちデータグラムキュー
    datagram_send_queue: VecDeque<Vec<u8>>,
    /// 送信キューの最大サイズ
    datagram_send_queue_max: usize,
    /// 受信済みデータグラムキュー
    datagram_recv_queue: VecDeque<Vec<u8>>,
    /// 受信キューの最大サイズ
    datagram_recv_queue_max: usize,

    // Address Discovery 拡張 (draft-ietf-quic-address-discovery-01)
    /// OBSERVED_ADDRESS の送信シーケンス番号 (接続内で単調増加)
    observed_address_seq_send: u64,
    /// パスごとに最後に受信した OBSERVED_ADDRESS のシーケンス番号
    observed_address_seq_recv: std::collections::HashMap<PathId, u64>,

    // 4-tuple 移行の検証 (RFC 9000 Section 9.5 / Section 9.6.1)
    /// 検証中の 4-tuple 移行 (path_id → 文脈)
    ///
    /// 現在は初期パス (path 0) だけを対象とする。
    pending_migrations: std::collections::HashMap<PathId, PendingMigration>,
}

/// 検証中の 4-tuple 移行の文脈 (RFC 9000 Section 9.5 / Section 9.6.1)
///
/// 検証が成功するまでパスの 4-tuple と送信先 CID は変更しない。
/// 成功時に新しいアドレスと CID を確定し、失敗時は元の値を維持する。
#[derive(Debug, Clone)]
struct PendingMigration {
    /// 検証対象のリモートアドレス
    candidate_remote_addr: std::net::SocketAddr,
    /// 検証対象のローカルアドレス
    ///
    /// `None` の場合は現在のローカルアドレスを維持する
    /// (preferred_address への移行ではリモートだけが変わる)。
    candidate_local_addr: Option<std::net::SocketAddr>,
    /// 検証パケットの送信先 CID
    ///
    /// RFC 9000 Section 9.5: 複数の宛先アドレスへの送信で同じ CID を再利用しては
    /// ならない (MUST NOT)。そのため移行の検証パケット (PATH_CHALLENGE /
    /// PATH_RESPONSE) は、この候補 CID を DCID に使う。候補は送信先に使う予約と
    /// して `used` を立てて選ぶが、一度も送信せずに取り消した場合は解放する。
    ///
    /// 検証中に Retire Prior To の増加で退役した場合は、
    /// `Connection::reconcile_pending_migrations_after_cid_retire` が
    /// 未使用の CID へ置き換える。
    candidate_peer_cid: ConnectionId,
    /// 候補 CID を使った検証パケットを 1 度でも送信したか
    ///
    /// 送信前に取り消した場合は候補 CID を未使用へ戻せるが、送信済みの CID を
    /// 別の宛先アドレスへ再利用することはできない (RFC 9000 Section 9.5)。
    /// abort / パス破棄の時点でこの値を見て解放の可否を決める。
    /// 退役で候補を置き換えた場合は、置き換え後の候補をまだ送っていないため
    /// `false` に戻す。
    candidate_probe_sent: bool,
    /// 検証前のリモートアドレス (失敗時に維持する)
    original_remote_addr: std::net::SocketAddr,
    /// 検証前のローカルアドレス (失敗時に維持する)
    original_local_addr: std::net::SocketAddr,
    /// 検証前のピア CID (失敗時に維持する)
    ///
    /// 検証中に退役した場合は、abort の時点で現在のパスが有効な CID を
    /// 保持していればそれを維持する。保存値は、現在のパスが有効な CID を
    /// 失っている場合の復元先としてだけ使う。
    original_peer_cid: Option<ConnectionId>,
    /// preferred_address に従った移行かどうか
    ///
    /// `disable_active_migration` は preferred_address に従った移行後の
    /// アクティブマイグレーションを禁止しない (RFC 9000 Section 9.6)。
    from_preferred_address: bool,
}

/// 1-RTT パケットの送信先をパスの 4-tuple から上書きする
///
/// 4-tuple 移行の検証では、パスの 4-tuple と送信先 CID を確定する前に、
/// 候補アドレスと候補 CID を使ってパケットを送る。検証以外の用途では
/// すべて `None` にし、パスの現在の値を使う。
#[derive(Debug, Clone, Default)]
struct OneRttSendOverride {
    /// 送信先のリモートアドレス (None ならパスの値)
    remote_addr: Option<std::net::SocketAddr>,
    /// 送信元のローカルアドレス (None ならパスの値)
    local_addr: Option<std::net::SocketAddr>,
    /// DCID (None ならパスの送信先 CID)
    dcid: Option<ConnectionId>,
}

/// 1-RTT データパケットの送信パス選択結果
///
/// 再送パス選択ポリシーの判断結果を、実際のパケット構築へ渡すための情報。
#[derive(Debug, Clone)]
struct DataSendPath {
    /// パケットを送信するパス
    path_id: PathId,
    /// このパケットで送る再送対象 (None なら新規データのみ)
    retx: Option<RetxTarget>,
    /// `RetxDecision::Duplicate` で複製送信する追加パス
    duplicate_path: Option<PathId>,
    /// 冗長スケジューラーが新規データの複製送信先として選んだ追加パス
    ///
    /// 再送の `duplicate_path` とは独立して扱う。STREAM フレームだけを
    /// 選ばれた各パスへ複製する。
    duplicate_paths: Vec<PathId>,
}

/// ピアが広告した Receive Timestamps 拡張の設定
///
/// draft-ietf-quic-receive-ts-03 Section 6 のトランスポートパラメータを
/// ACK 生成で使いやすい形にしたもの。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerReceiveTimestamps {
    /// ACK に載せてよい受信タイムスタンプの最大数 (1 以上)
    max_per_ack: u64,
    /// タイムスタンプ差分のエンコードに使う指数 (ピアが広告した値)
    exponent: u32,
}

/// ピアから受信した CID のエントリ
///
/// 有効なピア CID をパス ID とシーケンス番号で追跡し、次の用途で参照する。
///
/// - Stateless Reset の検出 (RFC 9000 Section 10.3)
/// - 能動回転と移行候補の選択 (未使用の CID を選ぶ。RFC 9000 Section 9.5)
/// - Retire Prior To による退役 (RFC 9000 Section 5.1.2)
/// - PATH_ABANDON 時の当該パス CID の一括退役
#[derive(Debug, Clone)]
struct PeerCidEntry {
    path_id: PathId,
    sequence_number: u64,
    connection_id: ConnectionId,
    /// 送信先 CID として使用済みか
    ///
    /// RFC 9000 Section 9.5: エンドポイントは複数のローカルアドレスから送信する
    /// ときに同じ CID を再利用してはならず (MUST NOT)、複数の宛先アドレスへ
    /// 送信するときも同じ CID を再利用してはならない (MUST NOT)。
    /// 能動回転や migration の候補には未使用の CID だけを選ぶため、
    /// 送信先に採用した時点で真にする。初期 CID (シーケンス番号 0) は
    /// ハンドシェイクで使用済みのため真で登録する。
    used: bool,
    /// CID を送信先に使った 4-tuple (リモートアドレス, ローカルアドレス)
    ///
    /// RFC 9000 Section 9.5 が禁じるのは複数の宛先アドレスへの再利用であり、
    /// 同じ 4-tuple への再送は禁じていない。検証に失敗した migration を同じ
    /// 4-tuple へ再試行するときだけ、この値で再利用の可否を判定する。
    /// `used` が真で `used_for` が `None` の場合は送信先を特定できないため
    /// 再利用しない (ハンドシェイクで使った初期 CID など)。
    used_for: Option<(std::net::SocketAddr, std::net::SocketAddr)>,
    /// Stateless Reset Token (RFC 9000 Section 10.3)
    ///
    /// NEW_CONNECTION_ID / PATH_NEW_CONNECTION_ID で受信したトークン。
    /// 初期 CID (シーケンス番号 0) は、サーバーが stateless_reset_token
    /// トランスポートパラメータを通知した場合だけトークンを持つ
    /// (RFC 9000 Section 18.2)。クライアントはこのパラメータを送信できない。
    /// トークンを持たない CID も退役追跡のためエントリ自体は保持する。
    stateless_reset_token: Option<[u8; 16]>,
}

/// ピア CID の登録結果
///
/// NEW_CONNECTION_ID / PATH_NEW_CONNECTION_ID の共通処理が、呼び出し側に
/// 後続処理 (送信先 CID の選び直しや上限検査) を行うかどうかを伝える。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerCidRegistration {
    /// 有効なピア CID として登録されている状態にした
    ///
    /// 新規登録のほか、同じ CID の再送で Stateless Reset Token を補完した場合も
    /// 含む。再送は冪等に扱う (RFC 9000 Section 13.3)。
    Registered,
    /// Retire Prior To 未満のため有効化せず、RETIRE を送信待ちに積んだ
    Retired,
    /// 既存の CID (ローカル CID または別のピア CID) と衝突した
    ///
    /// 同じ CID を別のシーケンス番号・別のパスで通知した場合に加え、
    /// 同じパス・同じシーケンス番号へ異なる CID を割り当てた場合も含む
    /// (RFC 9000 Section 19.15 の MAY)。
    Reused,
}

/// ピア CID を通知するフレームの種別
///
/// 両者は同じ処理を共有するが、エラーメッセージと、パスへの送信先 CID の
/// 初期設定を行うかどうかが異なる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerCidFrameKind {
    /// RFC 9000 Section 19.15 の NEW_CONNECTION_ID (path ID 0 専用)
    NewConnectionId,
    /// RFC 10069 Section 4.4 の PATH_NEW_CONNECTION_ID
    PathNewConnectionId,
}

impl PeerCidFrameKind {
    /// エラーメッセージに使うフレーム名を返す
    fn name(self) -> &'static str {
        match self {
            Self::NewConnectionId => "NEW_CONNECTION_ID",
            Self::PathNewConnectionId => "PATH_NEW_CONNECTION_ID",
        }
    }
}

impl<F: CongestionControlFactory, S: SchedulerFactory, P: PathControllerFactory>
    Connection<F, S, P>
{
    /// link-local アドレスの scope ID を学習する
    ///
    /// 保存済みのローカルアドレスが scope なしの link-local で、観測した
    /// アドレスが同じ IP とポートで scope だけを持つ場合に補完する。4-tuple の
    /// 変更ではないため、migration の判定より前に呼ぶ。
    fn learn_link_local_scope(&mut self, path_id: PathId, observed: std::net::SocketAddr) {
        let Some(path) = self.paths.get_mut(path_id) else {
            return;
        };
        if let Some(scoped) = fill_link_local_scope(path.local_addr, observed) {
            path.local_addr = scoped;
        }
    }
}

/// 保存済みのローカルアドレスに scope ID が無ければ、観測した scope ID で補完する
///
/// link-local アドレスは scope ID でインターフェースを識別する (RFC 4007
/// Section 6)。ユーザーが scope なしの link-local アドレスを指定した場合、
/// 初回受信の pktinfo で scope が判明する。同じ IP とポートで scope だけが
/// 異なる場合は 4-tuple の変更ではなく学習として扱う。
fn fill_link_local_scope(
    current: std::net::SocketAddr,
    observed: std::net::SocketAddr,
) -> Option<std::net::SocketAddr> {
    let (std::net::SocketAddr::V6(current), std::net::SocketAddr::V6(observed)) =
        (current, observed)
    else {
        return None;
    };
    if !current.ip().is_unicast_link_local()
        || current.scope_id() != 0
        || observed.scope_id() == 0
        || current.ip() != observed.ip()
        || current.port() != observed.port()
    {
        return None;
    }
    // flowinfo は `LocalIp::to_socket_addr` が常に 0 で構築するため、4-tuple を
    // 一致させる目的では 0 に揃える。
    Some(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
        *current.ip(),
        current.port(),
        0,
        observed.scope_id(),
    )))
}

/// 観測したローカルアドレスを、既存のパスアドレスに反映する
///
/// `0.0.0.0` / `::` はソケットのバインド先であり、通信に使ったアドレスではない。
/// 観測側が未確定なら無視し、パス側が未確定なら観測値で埋める。両方とも
/// 具体アドレスなら観測値を採用する (呼び出し側が migration かどうかを判断する)。
///
/// IPv6 の link-local アドレスは scope ID を保持する。パス側が未確定で
/// 観測値に scope がある場合は `SocketAddrV6` で再構築し、観測した
/// インターフェース識別を落とさない。scope が無いアドレスでは
/// `SocketAddr::new` と同じ結果になる。
fn resolve_observed_local(
    current: std::net::SocketAddr,
    observed: std::net::SocketAddr,
) -> std::net::SocketAddr {
    if observed.ip().is_unspecified() {
        return current;
    }
    if current.ip().is_unspecified() {
        let port = if observed.port() == 0 {
            current.port()
        } else {
            observed.port()
        };
        return match observed {
            std::net::SocketAddr::V6(observed) => {
                std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                    *observed.ip(),
                    port,
                    observed.flowinfo(),
                    observed.scope_id(),
                ))
            }
            observed => std::net::SocketAddr::new(observed.ip(), port),
        };
    }
    observed
}

/// multipath を広告する接続ではゼロ長 CID を使えないため、必要なら TP を無効化する
///
/// RFC 10069 Section 2.1: initial_max_path_id を広告する
/// エンドポイントは Source / Destination Connection ID に非ゼロ長の CID を
/// 使わなければならない (MUST)。ローカル / ピアの CID がゼロ長の構成では
/// 広告すると違反になるため、initial_max_path_id を広告しない。
fn normalize_multipath_params_for_cids(
    config: &mut ConnectionConfig,
    local_cid: &ConnectionId,
    peer_cid: &ConnectionId,
) {
    if config.transport_params.initial_max_path_id.is_some()
        && (local_cid.is_empty() || peer_cid.is_empty())
    {
        config.transport_params.initial_max_path_id = None;
        tracing::debug!(
            "multipath disabled: initial_max_path_id requires non-zero-length connection IDs"
        );
    }
}

/// 接続設定の妥当性を検証する
///
/// Sans I/O の `Connection` は上位層 (tobi-quic / tobi-platform) が検証済みの
/// 設定を受け取る前提だったが、直接利用する場合にトランスポートパラメータの
/// 実用上限が効かない。実用上限を超えるストリーム数や Path ID を広告すると、
/// ピアの 1 フレームで大量のストリームや CID を生成してしまうため、
/// 生成時にも検証する。MTU 設定も同じ入口で検証する。
/// DATAGRAM のキュー上限は 0 を許さない。0 のキューは DATAGRAM を 1 件も
/// 保持できず、受信側は常に破棄、送信側は常に最古破棄になるため、設定ミスとして
/// 拒否する。DATAGRAM を使わない場合は `max_datagram_frame_size` を 0 にする。
fn validate_config(config: &ConnectionConfig) -> Result<(), Error> {
    config.transport_params.validate_local()?;
    config.mtu.validate()?;
    if config.datagram_send_queue_max == 0 {
        return Err(Error::InvalidData(
            "datagram_send_queue_max must be greater than zero".to_string(),
        ));
    }
    if config.datagram_recv_queue_max == 0 {
        return Err(Error::InvalidData(
            "datagram_recv_queue_max must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

/// 送信する CONNECTION_CLOSE の種別
///
/// `close` / `close_application` の共通実装で、1-RTT に載せるフレーム種別、
/// 確定前に Initial / Handshake へ載せる early frame の選択、qlog の trigger を
/// 切り替えるために使う。受信した CONNECTION_CLOSE のイベント種別を表す
/// [`tobi_core::connection::ConnectionCloseKind`] とは別の、送信側の種別である。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutgoingCloseKind {
    /// transport-level の CONNECTION_CLOSE (type 0x1c) を送る
    Transport,
    /// application-level の CONNECTION_CLOSE (type 0x1d) を送る
    Application,
}

/// ACK されたパケットから、再送が不要になったフレーム情報を収集する
///
/// ACK 範囲の列挙は largest_acknowledged / first_ack_range / 追加 ACK 範囲の
/// 3 経路に分かれるが、収集する内容は同じである。経路ごとに同じ match を
/// 書かず、この構造体へ集約する。ロスト判定済みパケットが後から ACK された
/// 場合 (spurious loss) の STREAM フレームとリセットフレームは、ロスト判定時の
/// 退避情報から復元したものとして `lost_stream_frames` / `lost_reset_frames` に
/// 分けて収集する。
/// STREAM フレームの範囲は [`tobi_core::recovery::sent_packets::LostStreamFrame`]
/// で統一し、ロスト判定時の退避情報と同じ型で扱う。
#[derive(Debug, Default)]
struct AckedFrameCollector {
    /// ACK された STREAM フレームの範囲
    stream_frames: Vec<LostStreamFrame>,
    /// ロスト判定済みパケットが後から ACK された STREAM フレームの範囲
    ///
    /// 通常の ACK で受け取る `stream_frames` と発生経路が異なるため、
    /// 区別して保持する。
    lost_stream_frames: Vec<LostStreamFrame>,
    /// ACK された RESET_STREAM の stream_id
    reset_stream_ids: Vec<u64>,
    /// ACK された RESET_STREAM_AT の (stream_id, reliable_size)
    ///
    /// Data Recvd への遷移条件が Reliable Size に依存するため、単なる
    /// stream_id ではなく ACK されたフレームの Reliable Size も保持する
    /// (draft-ietf-quic-reliable-stream-reset-11 Section 5.3)。
    reset_stream_at: Vec<(u64, u64)>,
    /// ロスト判定済みパケットが後から ACK されたリセットフレーム
    ///
    /// 通常の ACK で受け取る `reset_stream_ids` / `reset_stream_at` と
    /// 発生経路が異なるため、区別して保持する。
    lost_reset_frames: Vec<LostResetFrame>,
    /// ACK された ACK_FREQUENCY の (Sequence Number, 要求値)
    ///
    /// draft-ietf-quic-ack-frequency-14 Section 7 の in-flight 追跡に使う。
    ack_frequencies: Vec<(u64, u64)>,
    /// ACK された RETIRE_CONNECTION_ID の (パス ID, シーケンス番号)
    ///
    /// RFC 9000 Section 5.1.2: ACK 済みの退役 CID は履歴から削除できる。
    retired_cids: Vec<(u32, u64)>,
}

impl AckedFrameCollector {
    /// ACK されたパケットに含まれるフレーム情報を収集する
    fn collect(&mut self, packet: &SentPacket) {
        for frame in &packet.frames {
            // STREAM フレームの範囲は ACK 済み範囲の解放に使う
            if let Some(stream_frame) = frame.stream_frame() {
                self.stream_frames.push(stream_frame);
            }
            match frame {
                SentFrameInfo::ResetStream { stream_id, .. } => {
                    self.reset_stream_ids.push(*stream_id);
                }
                SentFrameInfo::ResetStreamAt {
                    stream_id,
                    reliable_size,
                    ..
                } => {
                    self.reset_stream_at.push((*stream_id, *reliable_size));
                }
                SentFrameInfo::AckFrequency {
                    sequence_number,
                    requested_max_ack_delay,
                } => {
                    self.ack_frequencies
                        .push((*sequence_number, *requested_max_ack_delay));
                }
                SentFrameInfo::RetireConnectionId {
                    path_id,
                    sequence_number,
                } => {
                    self.retired_cids.push((*path_id, *sequence_number));
                }
                _ => {}
            }
        }
    }
}

/// 出力キューへ積む直前に構築した 0-RTT パケット
///
/// フレームの書き込みでストリームの送信位置は構築時点で進むため、構築した
/// パケットを破棄するとデータだけが失われる。一方、輻輳制御・損失検出・
/// パケット番号は実際に出力キューへ積んだ後でなければ確定できない。
/// この二段階を型で表し、構築したパケットは必ず 1 回だけ
/// [`Connection::queue_zero_rtt_datagram`] で出力キューへ積んで送信会計を
/// 確定する。
#[must_use = "0-RTT パケットは queue_zero_rtt_datagram で出力キューへ積まないとデータを失う"]
struct PendingZeroRttPacket {
    /// ヘッダー保護まで適用したパケット全体
    bytes: Vec<u8>,
    /// Application Data 空間のパケット番号
    pn: u64,
    /// パケットに含めたフレーム (再送と損失検出用)
    frames: Vec<SentFrameInfo>,
}

impl<F: CongestionControlFactory, S: SchedulerFactory, P: PathControllerFactory>
    Connection<F, S, P>
{
    /// クライアント接続を作成する
    ///
    /// `config.mtu` と `config.transport_params` を検証してから、パスや
    /// 輻輳制御などの接続状態を構築する。不正な設定は [`Error::InvalidData`]
    /// として返し、既定値へ置き換えない (RFC 9000 Section 14 / RFC 8899)。
    /// `transport_params` は実用上限 (ストリーム数・Path ID・CID 数など) も
    /// 含めて検証する。
    #[allow(clippy::too_many_arguments)]
    pub fn client(
        config: ConnectionConfig,
        tls_session: tls::ClientTlsSession,
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
        cc_factory: F,
        scheduler_factory: S,
        path_controller_factory: P,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) -> Result<Self, Error> {
        let mut config = config;
        normalize_multipath_params_for_cids(&mut config, &local_cid, &peer_cid);
        validate_config(&config)?;
        let initial_dcid = peer_cid.clone();
        let max_path_id = config.transport_params.initial_max_path_id.unwrap_or(0);
        Self::new_inner(
            Role::Client,
            config,
            TlsSessionHolder::Client(tls_session),
            local_cid,
            peer_cid,
            initial_dcid,
            max_path_id,
            cc_factory,
            scheduler_factory,
            path_controller_factory,
            remote_addr,
            local_addr,
        )
    }

    /// サーバー接続を作成する
    ///
    /// `config.mtu` と `config.transport_params` を検証してから、パスや
    /// 輻輳制御などの接続状態を構築する。不正な設定は [`Error::InvalidData`]
    /// として返し、既定値へ置き換えない (RFC 9000 Section 14 / RFC 8899)。
    /// `transport_params` は実用上限 (ストリーム数・Path ID・CID 数など) も
    /// 含めて検証する。
    #[allow(clippy::too_many_arguments)]
    pub fn server(
        config: ConnectionConfig,
        tls_session: tls::ServerTlsSession,
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
        initial_dcid: ConnectionId,
        cc_factory: F,
        scheduler_factory: S,
        path_controller_factory: P,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) -> Result<Self, Error> {
        let mut config = config;
        normalize_multipath_params_for_cids(&mut config, &local_cid, &peer_cid);
        validate_config(&config)?;
        let max_path_id = config.transport_params.initial_max_path_id.unwrap_or(0);
        Self::new_inner(
            Role::Server,
            config,
            TlsSessionHolder::Server(tls_session),
            local_cid,
            peer_cid,
            initial_dcid,
            max_path_id,
            cc_factory,
            scheduler_factory,
            path_controller_factory,
            remote_addr,
            local_addr,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        role: Role,
        config: ConnectionConfig,
        tls_session: TlsSessionHolder,
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
        initial_dcid: ConnectionId,
        max_path_id: u32,
        cc_factory: F,
        scheduler_factory: S,
        path_controller_factory: P,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) -> Result<Self, Error> {
        // RFC 9000 Section 14 / RFC 8899: 不正な MTU 設定を既定値へ置き換えず、
        // パスなどの接続状態を構築する前に拒否する。
        config.mtu.validate()?;
        // この接続で使うバージョンと対応バージョン一覧を取り出す。
        // 空の一覧は「この接続のバージョンのみ対応」として扱う。
        let version = config.version;
        let vn_retry = config.vn_retry;
        let send_zero_quic_bit = config.send_zero_quic_bit;
        let supported_versions = if config.supported_versions.is_empty() {
            vec![version]
        } else {
            config.supported_versions.clone()
        };
        let multipath_policy = config.multipath_policy.clone();
        let path_controller = path_controller_factory.create(multipath_policy.clone());
        // 明示された keep-alive 間隔を保持する。`Duration::ZERO` は無効として扱う
        // (0 間隔のタイマーは常に発火し続けてしまう)。
        let config_keep_alive_interval = config
            .keep_alive_interval
            .filter(|interval| *interval != Duration::ZERO);
        let delayed_ack = config.delayed_ack;
        let streams = StreamManager::new(role, &config.transport_params);
        let local_cid_len = local_cid.len();
        let mut local_cid_table = std::collections::HashMap::new();
        // 初期パス (path_id=0) の seq=0 として初期 CID を登録する
        local_cid_table.insert((0u32, 0u64), local_cid.clone());

        let mut paths =
            PathManager::new(max_path_id, cc_factory, remote_addr, local_addr, config.mtu)
                .with_max_concurrent_validations(config.max_concurrent_path_validations);
        // keep-alive の既定値 (無効) を初期パスにも適用する。追加パスは
        // 作成時に `Connection::keep_alive_enabled` を継承するが、初期パスは
        // `Path::new` の既定値のままになるため、ここで揃える。
        paths.initial_path_mut().set_keep_alive_enabled(false);
        // 初期パスの送信先 peer CID を設定する
        paths.initial_path_mut().peer_cid = Some(peer_cid.clone());
        // 初期パスのローカル CID を CID→Path マッピングに登録する
        paths.register_cid(local_cid.clone(), PathId::INITIAL);

        Ok(Self {
            role,
            state: ConnectionState::Idle,
            local_params: config.transport_params,
            peer_params: None,
            early_peer_params: None,
            peer_receive_timestamps: None,
            peer_params_finalized: false,
            paths,
            handshake_local_addr: local_addr,
            handshake_remote_addr: remote_addr,
            acted_on_preferred_address: false,
            stats: ConnectionStats::default(),
            started_at: None,
            last_valid_recv_path: None,
            local_cid,
            peer_cid: peer_cid.clone(),
            initial_dcid: initial_dcid.clone(),
            peer_initial_scid: None,
            server_initial_scid: None,
            compatible_client_version: config.compatible_client_version,
            compatible_version_switch: None,
            retry_scid: None,
            retry_token: Vec::new(),
            retry_received: false,
            original_dcid: initial_dcid,
            version,
            supported_versions,
            version_negotiation_versions: None,
            vn_retry,
            peer_grease_quic_bit: None,
            send_zero_quic_bit,
            zero_rtt_keys: None,
            zero_rtt_accepted: false,
            session_ticket_received: false,
            zero_rtt_sent: false,
            zero_rtt_sent_pn_range: None,
            zero_rtt_rejected: false,
            zero_rtt_ticket_hash: None,
            zero_rtt_keys_discard_at: None,
            address_token: Vec::new(),
            token_provider: None,
            initial_token_validated: false,
            replay_filter: None,
            streams,
            initial_keys: None,
            initial_keys_discarded: false,
            initial_handshake_processed: false,
            handshake_keys: None,
            one_rtt_keys: None,
            tls_session,
            alpn_protocol: None,
            crypto_send_initial: Vec::new(),
            crypto_retransmit_initial: VecDeque::new(),
            crypto_send_handshake: Vec::new(),
            crypto_send_1rtt: Vec::new(),
            crypto_send_initial_offset: 0,
            crypto_send_handshake_offset: 0,
            crypto_send_1rtt_offset: 0,
            crypto_recv_initial: CryptoRecvBuffer::new(
                CRYPTO_RECV_INITIAL_MAX_BYTES,
                CRYPTO_RECV_MAX_PENDING_COUNT,
            ),
            crypto_recv_handshake: CryptoRecvBuffer::new(
                CRYPTO_RECV_HANDSHAKE_MAX_BYTES,
                CRYPTO_RECV_MAX_PENDING_COUNT,
            ),
            crypto_recv_1rtt: CryptoRecvBuffer::new(
                CRYPTO_RECV_1RTT_MAX_BYTES,
                CRYPTO_RECV_MAX_PENDING_COUNT,
            ),
            initial_send_pn: 0,
            initial_recv_pn_largest: None,
            initial_ack_tracker: AckTracker::new(),
            initial_sent_packets: SentPackets::new(),
            handshake_send_pn: 0,
            handshake_recv_pn_largest: None,
            handshake_ack_tracker: AckTracker::new(),
            handshake_sent_packets: SentPackets::new(),
            pmtu_probe_pns: Vec::new(),
            emit_tracking: false,
            emit_used_paths: Vec::new(),
            pmtu_probe_backoff: std::collections::HashMap::new(),
            output_queue: VecDeque::new(),
            one_rtt_outputs: VecDeque::new(),
            pending_abandon_completion: std::collections::HashSet::new(),
            path_action_depth: 0,
            pacing_deadlines: std::collections::HashMap::new(),
            one_rtt_bursts: std::collections::HashMap::new(),
            event_queue: VecDeque::new(),
            observation_enabled: false,
            observation_queue: VecDeque::new(),
            observed_congestion_states: std::collections::HashMap::new(),
            handshake_done_sent: false,
            handshake_done_received: false,
            handshake_confirmed_once: false,
            next_secrets: None,
            key_phase: false,
            previous_one_rtt_keys: None,
            key_update_allowed_at: None,
            key_phase_established_by_update: false,
            one_rtt_phase_start_pns: std::collections::HashMap::new(),
            current_key_phase_lowest_recv_pns: std::collections::HashMap::new(),
            current_phase_acked: false,
            one_rtt_packets_sent: 0,
            aead_auth_failures: 0,
            pto_probe_paths: Vec::new(),
            idle_timeout_ms: 0,
            current_recv_ecn: EcnCodepoint::NotEct,
            ack_frequency_in_flight: Vec::new(),
            ack_frequency_last_acked: None,
            ack_frequency_next_sequence_number: 0,
            received_valid_packet: false,
            // keep-alive は既定で無効。`set_keep_alive` で明示的に有効化する
            // (無効のままアイドルタイムアウトを有効にできるようにするため)。
            keep_alive_enabled: false,
            keep_alive_interval: config_keep_alive_interval,
            delayed_ack,
            pending_path_probes: std::collections::HashSet::new(),
            loss_detection_timers_armed: std::collections::HashMap::new(),
            // クライアントはアドレス検証済み (サーバーが応答した時点で検証)
            address_validated: role == Role::Client,
            recv_bytes_before_validated: 0,
            sent_bytes_before_validated: 0,
            amplification_addr: None,
            current_recv_datagram_len: None,
            defer_initial_datagrams_until_challenge: false,
            defer_path_datagrams_until_challenge: None,
            crypto_sent_initial: Vec::new(),
            crypto_sent_handshake: Vec::new(),
            crypto_retransmit_handshake: VecDeque::new(),
            handshake_pto_probes_pending: 0,
            initial_pto_probes_pending: 0,
            pre_confirmation_cids_pending: false,
            crypto_sent_1rtt: Vec::new(),
            crypto_retransmit_1rtt: VecDeque::new(),
            local_cid_table,
            local_cid_retire_prior_to: std::collections::HashMap::new(),
            local_cid_len,
            peer_initial_max_path_id: 0,
            closing_packet: None,
            closing_last_resend: None,
            closing_path_id: PathId::INITIAL,
            peer_cid_entries: Vec::new(),
            peer_cid_max_seq: std::collections::HashMap::new(),
            peer_cid_retire_prior_to: std::collections::HashMap::new(),
            retired_peer_cid_seq: std::collections::HashSet::new(),
            retired_peer_cid_order: VecDeque::new(),
            retired_peer_cid_identities: std::collections::HashMap::new(),
            cid_blocked_notified: std::collections::HashSet::new(),
            qlog_writer: None,
            qlog_start: None,
            close_formatter: None,
            stateless_reset_generator: None,
            last_path_open_time: None,
            proactive_cid_next_seq: std::collections::HashMap::new(),
            scheduler: scheduler_factory.create(),
            path_controller,
            multipath_policy,
            last_ack_send_path: std::collections::HashMap::new(),
            datagram_send_queue: VecDeque::new(),
            datagram_send_queue_max: config.datagram_send_queue_max,
            datagram_recv_queue: VecDeque::new(),
            datagram_recv_queue_max: config.datagram_recv_queue_max,
            observed_address_seq_send: 0,
            observed_address_seq_recv: std::collections::HashMap::new(),
            pending_migrations: std::collections::HashMap::new(),
        })
    }

    /// 現在の 1-RTT Key Phase bit を返す (RFC 9001 Section 6.1)
    ///
    /// 送信パケットの Key Phase bit と一致する。鍵更新のたびに反転する。
    pub fn key_phase(&self) -> bool {
        self.key_phase
    }

    /// ネゴシエート済みのピアトランスポートパラメータを取得する
    ///
    /// ハンドシェイク完了後に利用可能。0-RTT 用にパラメータを保存する際に使用する。
    pub fn peer_transport_params(&self) -> Option<&TransportParams> {
        self.peer_params.as_ref()
    }

    /// 送信パケットの QUIC Bit を 0 にするか (RFC 9287 Section 3.1)
    ///
    /// 設定で有効化されており、かつ現在の接続でピアが `grease_quic_bit` を
    /// 広告した場合のみ true。0-RTT 用の記憶値では true にならない。
    fn send_quic_bit_zero(&self) -> bool {
        self.send_zero_quic_bit && self.peer_grease_quic_bit == Some(true)
    }

    /// 0-RTT 用のピアトランスポートパラメータを設定する (クライアント側)
    ///
    /// 前回のセッションで取得したピアのトランスポートパラメータを設定する。
    /// これにより、ハンドシェイク完了前に `open_stream_bidi()` や `stream_send()` が
    /// 使用可能になり、0-RTT パケットで送信される。
    ///
    /// RFC 9001 Section 4.6.1: クライアントは前回のセッションで使用されたサーバーの
    /// トランスポートパラメータを記憶し、0-RTT 時に使用しなければならない。
    ///
    /// RFC 9221 Section 3: ここで設定された `max_datagram_frame_size` は、
    /// ハンドシェイク完了時にサーバーが新たに通知する値が同値以上であることを
    /// 検証するための基準値として保存される。検証に失敗した場合、接続は
    /// PROTOCOL_VIOLATION で終了する。
    pub fn set_early_peer_params(&mut self, mut params: TransportParams) {
        // draft-ietf-quic-ack-frequency-14 Section 3:
        // min_ack_delay の値を次回接続 (0-RTT) に記憶してはならない (MUST NOT)。
        // 記憶すると 0-RTT 中に ACK_FREQUENCY を送れると誤認するため、
        // 0-RTT 用のパラメータでは常に未広告として扱う。
        params.min_ack_delay = None;
        // RFC 9287 Section 3.1: 過去の接続で受け取った grease_quic_bit を
        // 記憶して 0-RTT に使ってはならない。0-RTT 用のパラメータでは
        // 未広告として扱い、ハンドシェイクで実際の値を受け取った後に更新する。
        params.grease_quic_bit = false;
        // RFC 10069 Section 2.1: initial_max_path_id は
        // 次回接続 (0-RTT) に記憶してはならない。記憶すると 0-RTT 中に
        // multipath がネゴシエート済みと誤認するため、未広告として扱い、
        // ハンドシェイクで実際の値を受け取った後に更新する。
        params.initial_max_path_id = None;
        self.streams.apply_peer_params(&params);
        self.early_peer_params = Some(params.clone());
        self.peer_params = Some(params);
    }

    /// トークンプロバイダを設定する (サーバー側)
    ///
    /// NEW_TOKEN のトークン生成・検証に使用する。
    /// 設定すると、Initial パケットのトークンを自動検証し、
    /// `send_new_token_auto()` でトークンを自動生成できる。
    /// 複数の接続で同一のトークン形式を共有するため `Arc` で渡す。
    pub fn set_token_provider(
        &mut self,
        provider: std::sync::Arc<dyn tobi_core::token::TokenProvider>,
    ) {
        self.token_provider = Some(provider);
    }

    /// トークンプロバイダを使ってクライアントに NEW_TOKEN を送信する
    ///
    /// `client_addr` は現在のクライアントのアドレス。
    /// トークンプロバイダが設定されていない場合はエラーを返す。
    pub fn send_new_token_auto(
        &mut self,
        client_addr: &std::net::SocketAddr,
        now: tobi_core::time::Timestamp,
    ) -> Result<(), Error> {
        let provider = self
            .token_provider
            .as_ref()
            .ok_or_else(|| Error::InvalidData("token provider is not set".into()))?;
        let token = provider.generate_token(client_addr, self.version);
        self.send_new_token(token, now)
    }

    /// 複数の検証済みアドレスを含む NEW_TOKEN をクライアントに送信する
    ///
    /// RFC 10069 Section 3.1.3: Multipath 環境で各パスの
    /// 検証済みアドレスをまとめてトークンに格納することで、クライアントが次回
    /// 接続時にどのアドレスから接続しても 0-RTT を利用できるようになる。
    ///
    /// `client_addrs` は検証済みアドレスのリスト (古い順 → 新しい順)。
    /// プロバイダが上限に達した場合は新しい側から `HmacTokenProvider::MAX_ADDRS`
    /// (デフォルト 8) 個が残るように切り詰められる。
    /// トークンプロバイダが設定されていない場合はエラーを返す。
    pub fn send_new_token_auto_multi(
        &mut self,
        client_addrs: &[std::net::SocketAddr],
        now: tobi_core::time::Timestamp,
    ) -> Result<(), Error> {
        if client_addrs.is_empty() {
            return Err(Error::InvalidData(
                "at least one client address is required".into(),
            ));
        }
        let provider = self
            .token_provider
            .as_ref()
            .ok_or_else(|| Error::InvalidData("token provider is not set".into()))?;
        let token = provider.generate_token_multi(client_addrs, self.version);
        self.send_new_token(token, now)
    }

    /// 0-RTT リプレイフィルターを設定する (サーバー側)
    ///
    /// RFC 9001 Section 9.2 に基づき、サーバーは 0-RTT のリプレイを検出する
    /// 必要がある。フィルターが未設定の場合、サーバーは 0-RTT パケットを
    /// 受理しない (安全側の既定)。0-RTT を利用する接続では必ず設定すること。
    /// 複数接続間で同一フィルター (チケットハッシュの共有辞書) を共有するため
    /// `Arc` で渡す。
    pub fn set_replay_filter(
        &mut self,
        filter: std::sync::Arc<dyn tobi_core::token::ReplayFilter>,
    ) {
        self.replay_filter = Some(filter);
    }

    /// 0-RTT 鍵が利用可能かどうかを返す
    ///
    /// クライアント: セッション再開時に送信鍵として利用可能 (1-RTT 鍵導出後に廃棄される)
    /// サーバー: ClientHello 処理後に受信鍵として利用可能
    pub fn has_zero_rtt_keys(&self) -> bool {
        self.zero_rtt_keys.is_some()
    }

    /// サーバーが 0-RTT パケットを受理したかを返す
    pub fn zero_rtt_accepted(&self) -> bool {
        self.zero_rtt_accepted
    }

    // --- パブリック API ---

    /// qlog ライターを設定する
    ///
    /// 設定すると、パケット送受信やロス検出等のイベントが
    /// QlogWriter に通知される。
    pub fn set_qlog(&mut self, writer: Box<dyn qlog::QlogWriter>) {
        self.qlog_start = Some(std::time::Instant::now());
        self.qlog_writer = Some(writer);
    }

    /// CONNECTION_CLOSE の reason phrase フォーマッタを設定する
    ///
    /// 設定すると、[`Self::close`] / [`Self::close_application`] は
    /// `formatter.format(error_code, reason)` を 1 回だけ呼び、その戻り値を
    /// reason phrase として使う。
    ///
    /// - transport close ([`Self::close`]): 整形結果を保持している全レベル
    ///   (Initial / Handshake / 1-RTT。確定後は 1-RTT のみ) に載せる。
    /// - application close ([`Self::close_application`]): 整形結果は 1-RTT の
    ///   0x1d と qlog にだけ載せる。Initial / Handshake へ 0x1c 変換して送るときは
    ///   RFC 9000 Section 10.2.3 の MUST により Reason Phrase を空にする。
    pub fn set_close_formatter(&mut self, formatter: Arc<dyn ConnectionCloseFormatter>) {
        self.close_formatter = Some(formatter);
    }

    /// Stateless Reset Token 生成器を設定する
    ///
    /// 設定すると、CID 発行時に `generator.generate(cid.as_bytes())` の戻り値を
    /// Stateless Reset Token として使用する。同一 CID から決定的に Token を
    /// 再生成できるため、マルチインスタンス / 再起動をまたいだ Stateless Reset に
    /// 使用できる (RFC 9000 Section 10.3.2)。未設定の場合は従来どおり乱数で
    /// 生成する。
    pub fn set_stateless_reset_generator(
        &mut self,
        generator: Arc<dyn StatelessResetTokenGenerator>,
    ) {
        self.stateless_reset_generator = Some(generator);
    }

    /// qlog 用の経過時間 (ミリ秒) を計算する
    ///
    /// packet_sent の記録では qlog writer を可変借用したままこのメソッドを
    /// 呼べない (`&self` の借用が衝突する) ため、呼び出し側は writer を
    /// 借りる前にこの値を求める。
    fn qlog_time_ms(&self) -> f64 {
        self.qlog_start
            .map(|start| {
                let elapsed = start.elapsed();
                elapsed.as_secs_f64() * 1000.0
            })
            .unwrap_or(0.0)
    }

    /// 受信した ACK / PATH_ACK の ACK Delay 指数
    ///
    /// RFC 9000 Section 19.3: ACK Delay は ACK を送信したピアの
    /// `ack_delay_exponent` でスケールされている。受信 ACK の RTT サンプル
    /// (RFC 9002 Section 5.3) と、受信 ACK を qlog へ記録するときの ms 換算で
    /// 共通に使う。ピアのパラメータをまだ受け取っていない場合は既定値 3 を
    /// 使い、RFC 9000 Section 18.2 の上限 20 で制限する。
    fn peer_ack_delay_exponent(&self) -> u32 {
        peer_ack_delay_exponent(self.peer_params.as_ref())
    }

    /// 送信する ACK / PATH_ACK の ACK Delay 指数
    ///
    /// RFC 9000 Section 19.3: 送信する ACK Delay はローカルの
    /// `ack_delay_exponent` で `delay_micros >> exponent` としてエンコードする。
    /// ACK 生成時と、送信 ACK を qlog へ記録するときの ms 換算で共通に使う。
    /// 上限は ACK 生成時のエンコードと同じく RFC 9000 Section 18.2 の 20。
    ///
    /// qlog writer を可変借用したままこのメソッドを呼ぶことはできないため、
    /// packet_sent の記録では writer を借りる前に求める。
    fn local_ack_delay_exponent(&self) -> u32 {
        self.local_params.ack_delay_exponent.min(20) as u32
    }

    /// 接続を開始する (クライアントのみ)
    pub fn connect(&mut self, now: Timestamp) -> Result<(), Error> {
        if self.role != Role::Client {
            return Err(Error::InvalidData("connect() is only for client".into()));
        }
        self.initial_keys = Some(InitialKeys::new(
            self.version,
            &self.initial_dcid,
            Role::Client,
        )?);
        // qlog: parameters_set (ローカル) + 状態遷移 Idle → Handshaking
        if self.qlog_writer.is_some() {
            let time_ms = self.qlog_time_ms();
            let qlog_params = qlog::TransportParametersSet {
                max_idle_timeout: self.local_params.max_idle_timeout,
                max_udp_payload_size: self.local_params.max_udp_payload_size,
                initial_max_data: self.local_params.initial_max_data,
                initial_max_stream_data_bidi_local: self
                    .local_params
                    .initial_max_stream_data_bidi_local,
                initial_max_stream_data_bidi_remote: self
                    .local_params
                    .initial_max_stream_data_bidi_remote,
                initial_max_stream_data_uni: self.local_params.initial_max_stream_data_uni,
                initial_max_streams_bidi: self.local_params.initial_max_streams_bidi,
                initial_max_streams_uni: self.local_params.initial_max_streams_uni,
                active_connection_id_limit: self.local_params.active_connection_id_limit,
                initial_max_path_id: self.local_params.initial_max_path_id,
            };
            if let Some(ref mut w) = self.qlog_writer {
                w.on_parameters_set(time_ms, "local", &qlog_params);
                w.on_connection_state_updated(time_ms, "idle", "handshaking");
            }
        }
        self.state = ConnectionState::Handshaking;
        // qlog: クライアントが Initial を送る時点のバージョン情報
        // (qlog-quic-events-13 Section 5.1)
        if self.qlog_writer.is_some() {
            let time_ms = self.qlog_time_ms();
            let client_versions = self.supported_versions.clone();
            if let Some(ref mut w) = self.qlog_writer {
                w.on_version_information(time_ms, &client_versions, &[], Some(self.version));
            }
        }
        // ハンドシェイク中もアイドルタイマーを張れるよう、ローカルの
        // max_idle_timeout を暫定値として使う。ピアの値はハンドシェイク完了後に
        // `maybe_apply_peer_params` が min(local, peer) で確定する。
        self.idle_timeout_ms = self.local_params.max_idle_timeout;
        // 最初の flight を送った時点でタイマーを開始する。ピアが沈黙したまま
        // 応答しない場合、このタイマーで接続を閉じる。
        self.reset_idle_timer(now);
        self.advance_tls(now)?;
        self.emit_packets(now)?;
        Ok(())
    }

    /// 受信データをフィードする
    ///
    /// `remote_addr` と `local_addr` はパケットの送信元/受信先の 4-tuple。
    /// RFC 10069 Section 3.1 に基づき、PATH_RESPONSE は
    /// PATH_CHALLENGE を受けた同じ network path で送信する。
    ///
    /// ECN は [`EcnCodepoint::NotEct`] として扱う。戻り値の契約は
    /// [`Self::receive_with_ecn`] と同じである。
    pub fn receive(
        &mut self,
        data: &[u8],
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
        now: Timestamp,
    ) -> Result<(), Error> {
        self.receive_with_ecn(data, remote_addr, local_addr, now, EcnCodepoint::NotEct)
    }

    /// 受信データをフィードする (受信パケットの ECN コードポイント付き)
    ///
    /// `ecn` は `IP_RECVTOS` / `IPV6_RECVTCLASS` の cmsg から取得した値。
    /// ACK_ECN のカウントに使う (RFC 9000 Section 13.4.2)。
    ///
    /// # 戻り値
    ///
    /// 正常受信、Draining / Closing / Closed 中の破棄、`process_packet` が返す
    /// 非 Protocol エラー (復号前のヘッダ / Length 不足、復号失敗、内部エラーなど)
    /// によるパケット破棄は `Ok(())` を返す。
    /// `Error::Protocol` (フレーム不正や予約ビット違反など) は、接続がまだ閉じて
    /// いなければ内部で CONNECTION_CLOSE を送って接続を Closing へ遷移させるため、
    /// 呼び出し元へはやはり `Ok(())` を返す。`Err` を返すのは、パケット送信
    /// (`emit_packets`。内部でピアの transport parameter の適用
    /// `maybe_apply_peer_params` も行う) が返す非 Protocol のエラーだけである。
    ///
    /// そのため、戻り値だけではパケット破棄と正常受信を区別できない。破棄理由は
    /// qlog の packet_dropped、接続エラーは接続状態と送信した CONNECTION_CLOSE で
    /// 確認すること。
    pub fn receive_with_ecn(
        &mut self,
        data: &[u8],
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
        now: Timestamp,
        ecn: EcnCodepoint,
    ) -> Result<(), Error> {
        self.current_recv_ecn = ecn;
        self.record_activity(now);
        // Draining 状態ではパケットを送信しない (RFC 9000 Section 10.2.2)
        if self.state == ConnectionState::Draining || self.state == ConnectionState::Closed {
            return Ok(());
        }
        // Closing 状態: CONNECTION_CLOSE をレート制限付きで再送する (RFC 9000 Section 10.2.1)
        if self.state == ConnectionState::Closing {
            if let Some(ref pkt) = self.closing_packet {
                // レート制限: smoothed_rtt ごとに最大 1 回
                let rtt_interval = self.paths.initial_path().rtt.smoothed_rtt;
                let should_resend = match self.closing_last_resend {
                    Some(last) => now.has_elapsed(last.add(rtt_interval)),
                    None => true,
                };
                if should_resend {
                    // 初回送信と同じパスへ出す。Active なパスが無い閉鎖では
                    // closing_packet 自体を保存しない。
                    self.output_queue
                        .push_back(self.make_send_datagram(pkt.clone(), self.closing_path_id));
                    self.closing_last_resend = Some(now);
                }
            }
            return Ok(());
        }
        // サーバーの増幅予算は、AEAD 復号で帰属を確認したデータグラムの
        // UDP payload 全体を一度だけ加算する (RFC 9000 Section 8.1)。
        // パケットの Length だけでは、暗号文の外側の余白を計上できない。
        // 4-tuple は Long Header では初期パスへ、Short Header では DCID の path_id へ反映する
        // (RFC 9000 Section 9.3 / RFC 10069 Section 3.1.2)
        self.current_recv_datagram_len = Some(data.len());

        // このデータグラムで AEAD 復号に成功したパケットがあるかを記録する
        // (アイドルタイマーのリスタート判定に使う。RFC 9000 Section 10.1)。
        self.received_valid_packet = false;
        let mut offset = 0;
        while offset < data.len() {
            // データグラム長は Initial の最小長検査 (RFC 9000 Section 14.1) に使う。
            // コアレシングされた後続パケットの位置に依らずデータグラム全体の長さを渡す。
            match self.process_packet(&data[offset..], data.len(), now, remote_addr, local_addr) {
                Ok(PacketOutcome::Processed(consumed)) => {
                    if consumed == 0 {
                        break;
                    }
                    offset += consumed;
                }
                Ok(PacketOutcome::Dropped { consumed, error }) => {
                    // 復号に失敗したパケットだけを破棄し、同じデータグラムに
                    // 連結された残りのパケットの処理を続ける
                    // (RFC 9000 Section 12.2 MUST)。
                    //
                    // 最初のパケットで失敗した場合は Stateless Reset の
                    // 可能性をチェックする (RFC 9000 Section 10.3)。
                    if offset == 0 {
                        self.check_stateless_reset(data, now);
                        // Stateless Reset を検出した場合は、データグラムの残りは
                        // 別の接続向けの可能性があるため処理しない
                        // (RFC 9000 Section 10.3.1)。
                        if self.state == ConnectionState::Draining {
                            break;
                        }
                    }
                    // 破棄理由を統計と qlog に残す
                    // (qlog-quic-events-13 Section 5.7 の QUICPacketDropped)
                    self.record_dropped_packet(&error);
                    if consumed == 0 {
                        break;
                    }
                    offset += consumed;
                }
                Err(Error::Protocol { code, reason }) => {
                    // プロトコルエラー: CONNECTION_CLOSE を送信して接続を閉じる
                    // (RFC 9000 Section 10.2)
                    let _ = self.close(code.as_u64(), reason.as_bytes(), now);
                    break;
                }
                Err(err) => {
                    // ヘッダ / Length の解析失敗は次のパケット位置を特定できない
                    // ため、データグラムの残りを破棄する。
                    //
                    // ただし最初のパケットで失敗した場合は
                    // Stateless Reset の可能性をチェックする (RFC 9000 Section 10.3)
                    if offset == 0 {
                        self.check_stateless_reset(data, now);
                    }
                    // 破棄理由を統計と qlog に残す
                    // (qlog-quic-events-13 Section 5.7 の QUICPacketDropped)
                    self.record_dropped_packet(&err);
                    break;
                }
            }
        }
        // RFC 9000 Section 13.4.1: 1 つのデータグラムに coalesced された各 QUIC
        // パケットへ同じ IP ヘッダの ECN を適用するため、データグラム全体の
        // 処理が終わってから次の受信に備えて初期化する。
        self.current_recv_ecn = EcnCodepoint::NotEct;
        self.current_recv_datagram_len = None;
        // 受信統計は「有効なパケットを 1 つ以上含むデータグラム」を 1 と数える。
        // パスへの帰属は直近で復号に成功したパケットのパスを使う。
        if self.received_valid_packet {
            let len = data.len() as u64;
            self.stats.record_received(len);
            let path_id = self.last_valid_recv_path.take().unwrap_or(PathId::INITIAL);
            if let Some(path) = self.paths.get_mut(path_id) {
                path.record_received_packet(len);
            }
        }

        // パケット受信でアイドルタイマーをリセットする (RFC 9000 Section 10.1)
        //
        // ハンドシェイク中も対象にする。ハンドシェイク中にピアが沈黙すると
        // PTO は再送するだけで接続を閉じないため、アイドルタイマーが無いと
        // 接続がどのタイマーでも閉じられず残り続ける。
        // リセットするのは AEAD 復号に成功したパケットを受信した場合だけである。
        // 復号に失敗したパケットでリセットすると、攻撃者が任意のデータグラムを
        // 送り続けるだけで接続の寿命を延ばせてしまう。
        if (self.state == ConnectionState::Connected || self.state == ConnectionState::Handshaking)
            && self.received_valid_packet
        {
            self.reset_idle_timer(now);
        }
        // パケット送信はデータグラム内の全パケット処理後に 1 回だけ実行する
        // 各パケット処理後に emit_packets を呼ぶと ACK-only Initial が
        // Handshake レスポンスより先に送信されてピアが Initial space 廃棄後に受信する問題を防ぐ
        // ハンドシェイク完了と同じ receive で 1-RTT データや PMTU プローブを
        // 送る場合に備え、パケット送信の前にピアの transport parameter を確定する
        // (RFC 9000 Section 18.2)。不正な transport parameter は Protocol
        // エラーで返ってくるため、接続クローズ扱いにする。
        match self.maybe_apply_peer_params() {
            Ok(()) => {}
            Err(Error::Protocol { code, reason }) => {
                let _ = self.close(code.as_u64(), reason.as_bytes(), now);
                return Ok(());
            }
            Err(e) => return Err(e),
        }
        // AEAD 使用制限の検査は emit_packets の先頭で行う。integrity /
        // confidentiality limit 超過は Protocol エラーで返ってくるため、
        // 同じく接続クローズ扱いにする。
        match self.emit_packets(now) {
            Ok(()) => Ok(()),
            Err(Error::Protocol { code, reason }) => {
                let _ = self.close(code.as_u64(), reason.as_bytes(), now);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// パケット番号空間単位の損失検出タイマー発火を処理する
    ///
    /// RFC 9002 Section 6.1.2 / 6.2 / Appendix A.9 に従い、時間閾値のロスト
    /// タイマーならその空間のパケットをロスト判定し、PTO なら対象空間の
    /// プローブ送信をスケジュールする。パケット番号空間ごとに独立した
    /// `loss_time` / `time_of_last_ack_eliciting_packet` を使う。
    fn handle_loss_detection_timeout(
        &mut self,
        path_id: PathId,
        space: PacketNumberSpace,
        now: Timestamp,
    ) -> Result<(), Error> {
        // Initial / Handshake の SentPackets は Connection 直下にあるため、
        // 処理中だけ一時的に借用する (RFC 9000 Section 12.3)。
        let mut temp_sent_packets = match space {
            PacketNumberSpace::Initial => std::mem::take(&mut self.initial_sent_packets),
            PacketNumberSpace::Handshake => std::mem::take(&mut self.handshake_sent_packets),
            PacketNumberSpace::ApplicationData => SentPackets::new(),
        };
        // ECN 検証状態の遷移を qlog に出すための時刻を path の借用前に控える
        let qlog_time_ms = self.qlog_time_ms();
        let path = self
            .paths
            .get_mut(path_id)
            .ok_or_else(|| Error::InvalidData(format!("path {path_id} not found")))?;
        let sent_packets = match space {
            PacketNumberSpace::Initial | PacketNumberSpace::Handshake => &mut temp_sent_packets,
            PacketNumberSpace::ApplicationData => &mut path.sent_packets,
        };

        // 再送対象フレーム (path の借用が終わった後で self 側の再送キューへ戻す)
        let mut lost_streams: Vec<(u64, u64, usize, bool, u32)> = Vec::new();
        let mut lost_cryptos: Vec<(u64, usize, LossReason)> = Vec::new();
        let mut lost_control_frames: Vec<SentFrameInfo> = Vec::new();
        // ACK 駆動のロスト経路と同じ分類で multipath 制御フレームを再送する
        // (RFC 9000 Section 13.3 / RFC 10069 Section 4.2 /
        // 4.3 / 4.6)。
        // PATH_STATUS は再送条件 (最後に送った状態か) の判定を
        // `retransmit_lost_control_frames` に一本化するため、制御フレームとして
        // 同じキューに積む。
        let mut lost_path_abandons: Vec<(u32, u64)> = Vec::new();
        let mut lost_max_path_id = false;
        let mut pto_streams: Vec<(u64, u64, usize, bool, u32)> = Vec::new();
        let mut pto_cryptos: Vec<(u64, usize)> = Vec::new();
        // Handshake 空間の PTO で再送する CRYPTO 範囲 (元の offset, 長さ)。
        // 新規送信データとは別の再送待ちキューへ積むため、Initial の全体再送
        // (`resend_crypto`) とは扱いを分ける。
        let mut pto_handshake_cryptos: Vec<(u64, usize)> = Vec::new();
        let mut pto_control_frames: Vec<SentFrameInfo> = Vec::new();
        // ロスト・破棄したフレームに紐づくストリーム ID (終端遷移の再判定対象)。
        // ACK 駆動ロスト経路と対称にする。
        let mut lost_frame_stream_ids: Vec<u64> = Vec::new();
        let mut resend_crypto = false;
        let mut pto_fired = false;
        let mut probe_application_data = false;
        // 統計更新用: path 借用中に数え、借用終了後に Connection 全体へ反映する
        let mut lost_in_flight_count: u64 = 0;
        let mut retransmitted_count: u64 = 0;
        // PTO プローブによる再送のパス統計を path 借用終了後に更新するためのフラグ
        let mut pto_probe_retransmitted = false;

        if path.loss_detectors.get(space).loss_time().is_some() {
            // 時間閾値のロスト判定 (RFC 9002 Section 6.1.2 / Appendix A.9)
            let lost_packets = path.loss_detectors.get_mut(space).detect_lost_packets(
                sent_packets,
                &path.rtt,
                now,
            );
            // RFC 9002 Section 6.1.2: ロストした in-flight パケットを輻輳制御へ通知する。
            // RFC 8899 Section 5.7: DPLPMTUD プローブのロストは輻輳の兆候として
            // 扱わない。プローブ分は cwnd を減らさず bytes_in_flight からだけ除去する。
            // DPLPMTUD プローブは通常の損失検出から除外されているため、
            // ここに来るロストはすべて通常パケットである。輻輳制御へ通常の
            // ロストとして通知する。
            let mut congestion_lost_bytes: u64 = 0;
            let mut lost_packet_infos: Vec<LostPacketInfo> = Vec::new();
            for packet in lost_packets.iter().filter(|packet| packet.in_flight) {
                congestion_lost_bytes = congestion_lost_bytes.saturating_add(packet.sent_bytes);
                lost_packet_infos.push(LostPacketInfo {
                    space,
                    pn: packet.pn,
                    time_sent: packet.time_sent,
                    sent_bytes: packet.sent_bytes,
                });
            }
            if congestion_lost_bytes > 0 {
                path.congestion.on_packets_lost(congestion_lost_bytes, now);
            }
            // DPLPMTUD: 時間閾値で確定したロストも ACK 駆動と同じ入力として
            // MTU へ通知する (RFC 8899 Section 4.3。共通化は実装方針)。
            // ACK 経路と同じく、損失詳細を CC へ渡す前に MTU を反映する。
            if space == PacketNumberSpace::ApplicationData {
                let before_mtu_state = path.mtu_controller.state();
                if let Some((old_mtu, new_mtu, done)) =
                    apply_pmtu_loss_feedback(path, &lost_packets, now)
                    && let Some(ref mut w) = self.qlog_writer
                {
                    w.on_mtu_updated(qlog_time_ms, u32::from(old_mtu), u32::from(new_mtu), done);
                }
                // BASE フェーズへ遷移したときだけ、旧探索の未送信プローブを破棄する。
                if before_mtu_state != path.mtu_controller.state()
                    && path.mtu_controller.state() == tobi_core::path::mtu::MtuState::BaseRequested
                {
                    discard_pending_old_probe(path_id, &mut self.one_rtt_outputs);
                    discard_sent_pmtu_probes(path, path_id, &mut self.pmtu_probe_pns);
                }
            }
            if !lost_packet_infos.is_empty() {
                // ACK 受信時と同じ損失詳細を渡す。バイト数だけでは、BBR の
                // 損失率の更新と送信時スナップショットの削除が行われない
                // (draft-ietf-ccwg-bbr-06 Section 5.5.10.2)。draft 改訂で変わり得る。
                path.congestion.on_packets_lost_cc(&lost_packet_infos, now);
            }
            for lost_pkt in &lost_packets {
                for frame_info in &lost_pkt.frames {
                    match frame_info {
                        SentFrameInfo::Stream {
                            stream_id,
                            offset,
                            length,
                            fin,
                            retransmission_count,
                        } => {
                            lost_frame_stream_ids.push(*stream_id);
                            lost_streams.push((
                                *stream_id,
                                *offset,
                                *length,
                                *fin,
                                *retransmission_count,
                            ));
                        }
                        SentFrameInfo::Crypto { offset, length } => {
                            lost_cryptos.push((*offset, *length, LossReason::TimeThreshold));
                        }
                        // RFC 10069 Section 4.2:
                        // PATH_ABANDON は別パスで同じ内容を再送する (SHOULD)。
                        SentFrameInfo::PathAbandon {
                            path_id: pa_path_id,
                            error_code,
                        } => {
                            lost_path_abandons.push((*pa_path_id, *error_code));
                        }
                        // RFC 10069 Section 4.3:
                        // PATH_STATUS はそのパスについて最後に送った状態だけを再送する
                        // (SHOULD)。再送条件とシーケンス番号の扱いを ACK 駆動経路と
                        // 揃えるため、制御フレームの再送キューへ戻す。
                        SentFrameInfo::PathStatus { .. } => {
                            lost_control_frames.push(frame_info.clone());
                        }
                        // RFC 10069 Section 4.6:
                        // MAX_PATH_ID は最新の値のみ再送する (SHOULD)。
                        SentFrameInfo::MaxPathId { .. } => {
                            lost_max_path_id = true;
                        }
                        // RFC 9000 Section 13.3: 制御フレームの再送
                        // RETIRE_CONNECTION_ID / PATH_RETIRE_CONNECTION_ID は、
                        // ロストしたパケットに含まれていたら同じ内容で再送する。
                        // RFC 9000 Section 5.1.2 は CID を退役させずに忘れることを
                        // 禁じており、この再送は退役履歴による重複抑止の対象外と
                        // する (履歴は通常の再通知の重複を抑止するためのもの)。
                        SentFrameInfo::MaxData
                        | SentFrameInfo::MaxStreamData { .. }
                        | SentFrameInfo::MaxStreams { .. }
                        | SentFrameInfo::DataBlocked
                        | SentFrameInfo::StreamDataBlocked { .. }
                        | SentFrameInfo::StreamsBlocked { .. }
                        | SentFrameInfo::ResetStream { .. }
                        | SentFrameInfo::ResetStreamAt { .. }
                        | SentFrameInfo::StopSending { .. }
                        | SentFrameInfo::NewConnectionId { .. }
                        | SentFrameInfo::RetireConnectionId { .. }
                        | SentFrameInfo::PathsBlocked { .. }
                        | SentFrameInfo::PathCidsBlocked { .. }
                        | SentFrameInfo::ObservedAddress { .. }
                        | SentFrameInfo::HandshakeDone => {
                            if let Some(stream_id) = sent_frame_stream_id(frame_info) {
                                lost_frame_stream_ids.push(stream_id);
                            }
                            lost_control_frames.push(frame_info.clone());
                        }
                        // RFC 9000 Section 13.3: NEW_TOKEN は同一内容で再送する。
                        SentFrameInfo::NewToken { .. } => {
                            lost_control_frames.push(frame_info.clone());
                        }
                        // draft-ietf-quic-ack-frequency-14 Section 4 / Section 7:
                        // ACK_FREQUENCY はロストしても再送しない。PTO 計算用の
                        // in-flight からも除去する。
                        SentFrameInfo::AckFrequency {
                            sequence_number, ..
                        } => {
                            self.ack_frequency_in_flight
                                .retain(|(in_flight, _)| in_flight != sequence_number);
                        }
                        // ACK / PATH_ACK は再送不要。PING / PADDING などの
                        // 情報を持たないフレームも `Other` として再送しない。
                        SentFrameInfo::Ack { .. }
                        | SentFrameInfo::PathAck
                        | SentFrameInfo::Other => {}
                    }
                }
            }
            // ロスト統計を更新する (RFC 9002 Section 2: in-flight のみ対象)
            for lost_pkt in &lost_packets {
                if !lost_pkt.in_flight {
                    continue;
                }
                lost_in_flight_count = lost_in_flight_count.saturating_add(1);
                path.record_lost_packet();
                if has_retransmittable_frame(&lost_pkt.frames) {
                    retransmitted_count = retransmitted_count.saturating_add(1);
                    path.record_retransmitted_packet();
                }
            }
            // RFC 9000 Section 13.4.2: ECT(0) 付きで送信したパケットがすべて
            // ロストした場合は ECN 検証失敗とみなし、以降の ECT 付与を止める (SHOULD)。
            let lost_ect0_count = lost_packets
                .iter()
                .filter(|packet| matches!(packet.ecn, EcnCodepoint::Ect0))
                .count() as u64;
            if lost_ect0_count > 0 {
                let mut all_lost = false;
                for _ in 0..lost_ect0_count {
                    all_lost = path.record_ecn_ect0_lost();
                }
                if all_lost {
                    let state_before = path.ecn_state;
                    path.ecn_state = EcnValidationState::Failed;
                    if self.qlog_writer.is_some()
                        && let Some(ref mut w) = self.qlog_writer
                    {
                        w.on_ecn_state_updated(
                            qlog_time_ms,
                            ecn_state_name(state_before),
                            ecn_state_name(path.ecn_state),
                        );
                    }
                }
            }
        } else {
            // PTO 発火: RFC 9002 Section 6.2.1 のとおり空間横断でバックオフを進める
            pto_fired = true;
            path.loss_detectors.on_pto_expired();
            match space {
                PacketNumberSpace::Initial => {
                    // RFC 9002 Section 6.2.4: 対象空間の未確認 CRYPTO データを再送する。
                    // クライアントの anti-deadlock PTO もこの経路で Initial パケットを
                    // 送る (RFC 9002 Section 6.2.1 MUST)。
                    // PTO による再送も再送統計に含める。
                    resend_crypto = true;
                    retransmitted_count = retransmitted_count.saturating_add(1);
                    path.record_retransmitted_packet();
                    // RFC 9002 Section 6.2.4 の MAY に従い、未確認 CRYPTO の
                    // 再送に加えて 2 個目のプローブを送る。1 個目の Interval の
                    // パケットが損失や破損で届かない場合も、次の PTO を待たずに
                    // ハンドシェイクを進められる。
                    self.initial_pto_probes_pending = 2;
                }
                PacketNumberSpace::Handshake => {
                    // RFC 9002 Section 6.2.4: PTO では ack-eliciting パケットを
                    // 最低 1 つ送る (MUST)。未確認の Handshake CRYPTO データを
                    // 元の offset のまま再送待ちキューへ積む。
                    //
                    // 同節は probe を最大 2 つの full-sized datagram まで送る
                    // ことを許可する (MAY) とし、新規データを probe に含める
                    // ことを SHOULD とする。本実装は、CRYPTO が順序付きの
                    // バイト列であり欠けた offset を再送しないとピアの TLS が
                    // 先へ進めないこと、および分割送信した範囲を元の offset で
                    // 回復することを優先し、未確認範囲を先に再送する (送信量は
                    // 1 回の pacing バーストまでに制限され、残りは通常の送信
                    // 機会と損失検出に委ねる)。新規送信データは上書きせず、
                    // offset も巻き戻さない。
                    if self.handshake_keys.is_some() {
                        for packet in sent_packets.iter() {
                            for frame in &packet.frames {
                                if let SentFrameInfo::Crypto { offset, length } = frame {
                                    pto_handshake_cryptos.push((*offset, *length));
                                }
                            }
                        }
                        // RFC 9002 Section 6.2.4 の最大 2 個のプローブを使う。
                        // 未確認の CRYPTO は両方の probe に含め、片方の損失だけで
                        // Finished の到着が次の PTO まで遅れないようにする。
                        self.handshake_pto_probes_pending = if pto_handshake_cryptos.is_empty() {
                            1
                        } else {
                            2
                        };
                    }
                    // 再送統計は実際に再送する CRYPTO 範囲がある場合だけ加算する。
                    // PING だけの probe は「再送したパケット」ではない。
                    if !pto_handshake_cryptos.is_empty() {
                        retransmitted_count = retransmitted_count.saturating_add(1);
                        path.record_retransmitted_packet();
                    }
                }
                PacketNumberSpace::ApplicationData => {
                    // ACK 誘発パケットが in-flight の場合のみプローブを送信する
                    // (RFC 9002 Section 6.2.4)
                    if sent_packets.has_ack_eliciting_in_flight() {
                        probe_application_data = true;
                        // 最も古い ack-eliciting in-flight パケット 1 つからフレームを
                        // 再送キューへ戻す。新しく送った再送パケットはより大きい
                        // パケット番号を持つため、PTO を重ねても再送対象は増えない。
                        if let Some(pkt) = sent_packets
                            .iter()
                            .find(|pkt| pkt.ack_eliciting && has_retransmittable_frame(&pkt.frames))
                        {
                            // PTO プローブとして 1 パケット分を再送する
                            retransmitted_count = retransmitted_count.saturating_add(1);
                            pto_probe_retransmitted = true;
                            for frame_info in &pkt.frames {
                                match frame_info {
                                    SentFrameInfo::Stream {
                                        stream_id,
                                        offset,
                                        length,
                                        fin,
                                        retransmission_count,
                                    } => {
                                        // PTO はロスト確定ではないが、再送の
                                        // ために再送キューへ戻す。後から元
                                        // パケットが ACK された場合は ACK 済み
                                        // 範囲の記録で再送待ちが取り除かれる
                                        // (RFC 9002 Section 6.2)。
                                        pto_streams.push((
                                            *stream_id,
                                            *offset,
                                            *length,
                                            *fin,
                                            *retransmission_count,
                                        ));
                                    }
                                    SentFrameInfo::Crypto { offset, length } => {
                                        pto_cryptos.push((*offset, *length));
                                    }
                                    // 制御フレームは通常のロスト時と同じ再送経路へ戻す。
                                    // PATH_STATUS は最後に送った状態のみを
                                    // 同じシーケンス番号で再送するため、プローブに
                                    // 重複して載ってもピアの状態を変えない
                                    // (RFC 10069 Section 4.3)。
                                    SentFrameInfo::MaxData
                                    | SentFrameInfo::MaxStreamData { .. }
                                    | SentFrameInfo::MaxStreams { .. }
                                    | SentFrameInfo::DataBlocked
                                    | SentFrameInfo::StreamDataBlocked { .. }
                                    | SentFrameInfo::StreamsBlocked { .. }
                                    | SentFrameInfo::ResetStream { .. }
                                    | SentFrameInfo::ResetStreamAt { .. }
                                    | SentFrameInfo::StopSending { .. }
                                    | SentFrameInfo::NewConnectionId { .. }
                                    | SentFrameInfo::RetireConnectionId { .. }
                                    | SentFrameInfo::PathStatus { .. }
                                    | SentFrameInfo::PathsBlocked { .. }
                                    | SentFrameInfo::PathCidsBlocked { .. }
                                    | SentFrameInfo::ObservedAddress { .. }
                                    | SentFrameInfo::HandshakeDone => {
                                        pto_control_frames.push(frame_info.clone())
                                    }
                                    // RFC 9002 Section 6.2: PTO はパケットのロストを
                                    // 示さない。RFC 9000 Section 8.1.3 は NEW_TOKEN を
                                    // 全クライアントで一意にすることを MUST とし、
                                    // 例外は「以前送った NEW_TOKEN のロスト修復」に
                                    // 限る。PTO はロスト確定ではないため再送せず、
                                    // ロスト判定後の再送 (Section 13.3) に委ねる。
                                    // これにより同一トークンが pending_frames へ
                                    // 重複して積まれることもない。
                                    SentFrameInfo::NewToken { .. } => {}
                                    // RFC 10069 Section 4.2:
                                    // PATH_ABANDON の再送はパケットがロストと
                                    // 判定された場合の SHOULD であり、PTO はロストを
                                    // 示さない。また PATH_ABANDON を送ったパスは
                                    // 以後送信に使えないため、再送はロスト判定後に行う。
                                    SentFrameInfo::PathAbandon { .. } => {}
                                    // RFC 10069 Section 4.6:
                                    // MAX_PATH_ID の再送は「ロストし、かつより新しい
                                    // MAX_PATH_ID を送っていない」場合の SHOULD。
                                    // PTO はロストを示さないため再送せず、ロスト判定後に
                                    // 最新値を送る経路へ委ねる。
                                    SentFrameInfo::MaxPathId { .. } => {}
                                    // ACK / PATH_ACK と再送不要フレームは対象外
                                    SentFrameInfo::Ack { .. }
                                    | SentFrameInfo::PathAck
                                    | SentFrameInfo::AckFrequency { .. }
                                    | SentFrameInfo::Other => {}
                                }
                            }
                        }
                    }
                }
            }
        }

        // クライアントがハンドシェイク確認前でも 1-RTT 鍵を持つ場合、Handshake
        // 空間の PTO に加えて 1-RTT の PING もプローブとして送る。対向が
        // HANDSHAKE_DONE を送った直後に NAT リバインディングが起きると、対向は
        // Handshake 鍵を破棄済みのためクライアントの Handshake probe を復号できず、
        // 新しい 4-tuple を学習できない。1-RTT の PING は復号できるため、対向が
        // 移行して HANDSHAKE_DONE を新しい 4-tuple へ送り直せる。
        if space == PacketNumberSpace::Handshake
            && self.role == Role::Client
            && self.one_rtt_keys.is_some()
            && !self.is_handshake_confirmed()
        {
            // 新しい経路の検証には未使用の CID が必要である (RFC 9000 Section 9.5)。
            // 確認前でも 1-RTT で送れるため、probe より先に CID を発行して送る。
            self.issue_initial_cids();
            self.pre_confirmation_cids_pending = true;
            self.pto_probe_paths.push(path_id);
        }

        // SentPackets を元に戻す (path の借用はここまで)
        match space {
            PacketNumberSpace::Initial => self.initial_sent_packets = temp_sent_packets,
            PacketNumberSpace::Handshake => self.handshake_sent_packets = temp_sent_packets,
            PacketNumberSpace::ApplicationData => {}
        }

        // RFC 9002 Section 6.2.4: 他の空間にも未確認データがあれば併送する
        // (SHOULD)。ServerHello が失われた相手へ Handshake だけを再送しても
        // 復号できないため、Initial と Handshake を emit_packets で連結する。
        if pto_fired
            && path_id == PathId::INITIAL
            && self.initial_keys.is_some()
            && self.handshake_keys.is_some()
        {
            let mut other_crypto = false;
            if space == PacketNumberSpace::Handshake
                && self.initial_sent_packets.has_ack_eliciting_in_flight()
                && !self.crypto_sent_initial.is_empty()
            {
                resend_crypto = true;
                other_crypto = true;
            } else if space == PacketNumberSpace::Initial
                && self.handshake_sent_packets.has_ack_eliciting_in_flight()
            {
                for packet in self.handshake_sent_packets.iter() {
                    for frame in &packet.frames {
                        if let SentFrameInfo::Crypto { offset, length } = frame {
                            pto_handshake_cryptos.push((*offset, *length));
                        }
                    }
                }
                other_crypto = !pto_handshake_cryptos.is_empty();
                self.handshake_pto_probes_pending = if other_crypto { 2 } else { 1 };
            }
            if other_crypto {
                retransmitted_count = retransmitted_count.saturating_add(1);
                self.paths.initial_path_mut().record_retransmitted_packet();
            }
        }

        if pto_probe_retransmitted && let Some(path) = self.paths.get_mut(path_id) {
            path.record_retransmitted_packet();
        }

        // path 借用中に数えたロスト・再送統計を Connection 全体へ反映する
        self.stats.lost_packets = self.stats.lost_packets.saturating_add(lost_in_flight_count);
        self.stats.retransmitted_packets = self
            .stats
            .retransmitted_packets
            .saturating_add(retransmitted_count);

        // RFC 9002 Section 6.2.4: 対象空間の CRYPTO データを再送キューへ戻す
        if resend_crypto && self.initial_keys.is_some() && !self.crypto_sent_initial.is_empty() {
            self.crypto_send_initial = self.crypto_sent_initial.clone();
            self.crypto_send_initial_offset = 0;
            self.crypto_retransmit_initial.clear();
        }
        // Handshake は元の offset のまま再送し、新規データの位置を巻き戻さない。
        for (offset, length) in pto_handshake_cryptos {
            self.retransmit_crypto(
                EncryptionLevel::Handshake,
                offset,
                length,
                RetxMeta {
                    original_path: path_id,
                    loss_reason: LossReason::Pto,
                    retransmission_count: 0,
                },
                now,
            );
        }
        if probe_application_data {
            // RFC 9002 Section 6.2.4: アプリケーションデータ空間のプローブを送る
            self.pto_probe_paths.push(path_id);
        }

        // 時間閾値タイマー経由のロストフレームを再送キューへ戻す
        for (stream_id, offset, length, fin, retransmission_count) in lost_streams {
            self.streams.mark_lost(
                stream_id,
                offset,
                length,
                fin,
                RetxMeta {
                    original_path: path_id,
                    loss_reason: LossReason::TimeThreshold,
                    retransmission_count,
                },
            );
        }
        for (offset, length, loss_reason) in lost_cryptos {
            // ロストしたパケットが属していた空間の暗号化レベルで再送する
            // (RFC 9001 Section 4.1.3)。
            self.retransmit_crypto(
                Self::encryption_level(space),
                offset,
                length,
                RetxMeta {
                    original_path: path_id,
                    loss_reason,
                    retransmission_count: 0,
                },
                now,
            );
        }
        // 時間閾値経路でも ACK 駆動経路と同じ分類で multipath 制御フレームを
        // 再送する (RFC 9000 Section 13.3)。
        self.retransmit_lost_multipath_frames(lost_path_abandons, lost_max_path_id, now)?;
        self.retransmit_lost_control_frames(lost_control_frames, now);

        // PTO 発火で被疑パスから戻したフレームを再送キューへ積む
        for (stream_id, offset, length, fin, retransmission_count) in pto_streams {
            self.streams.mark_lost(
                stream_id,
                offset,
                length,
                fin,
                RetxMeta {
                    original_path: path_id,
                    loss_reason: LossReason::Pto,
                    retransmission_count,
                },
            );
        }
        for (offset, length) in pto_cryptos {
            // Application Data 空間の再送は 1-RTT レベルで行う
            self.retransmit_crypto(
                EncryptionLevel::OneRtt,
                offset,
                length,
                RetxMeta {
                    original_path: path_id,
                    loss_reason: LossReason::Pto,
                    retransmission_count: 0,
                },
                now,
            );
        }
        self.retransmit_lost_control_frames(pto_control_frames, now);

        // 再送キューへの復元が終わったストリームは、ACK 済み範囲しか
        // 残っていない場合に終端状態へ遷移できる
        // (RFC 9000 Section 3.1, Section 13.3)。
        for stream_id in lost_frame_stream_ids {
            self.streams.try_transition_send_terminal(stream_id);
        }

        Ok(())
    }

    /// タイマー発火通知
    pub fn handle_timer(&mut self, timer_id: TimerId, now: Timestamp) -> Result<(), Error> {
        match timer_id {
            TimerId::LossDetection { path_id, space } => {
                // RFC 9002 Section 6.2.2.1: サーバーがアンチアンプリフィケーション
                // 制限で送信できない間は PTO を armed してはならない (MUST NOT)。
                // 時間閾値の損失タイマーは送信を伴わないため、その処理だけは行う。
                let has_loss_time = self
                    .paths
                    .get(path_id)
                    .is_some_and(|path| path.loss_detectors.get(space).loss_time().is_some());
                if self.server_pto_blocked_by_anti_amplification() && !has_loss_time {
                    self.clear_loss_detection_timer_for_space(path_id, space);
                    return Ok(());
                }
                // 発火したタイマーは Sans I/O 層側で破棄済みのため、armed 記録を消す
                if self.loss_detection_timers_armed.get(&path_id) == Some(&space) {
                    self.loss_detection_timers_armed.remove(&path_id);
                }
                self.handle_loss_detection_timeout(path_id, space, now)?;
                // LossDetection タイマーの再設定/破棄は emit_packets が一元管理する
                self.emit_packets(now)?;
            }
            TimerId::AckDelay { path_id } => {
                // ACK 遅延タイマー発火: 遅延していた ACK を送信する。
                // draft-ietf-quic-ack-frequency-14 Section 6: 拡張有効時は
                // 閾値未満でもタイマー発火で ACK を送る。
                if self.one_rtt_keys.is_some()
                    && matches!(
                        self.state,
                        ConnectionState::Handshaking | ConnectionState::Connected
                    )
                {
                    // 未 ACK の ack-eliciting パケットがある場合のみ強制する。
                    // 古いタイマーが残っていて ACK 済みの場合は空 ACK を送らない。
                    if let Some(path) = self.paths.get_mut(path_id)
                        && path.ack_tracker.first_ack_eliciting_time().is_some()
                    {
                        path.ack_tracker.request_immediate_ack();
                    }
                    self.emit_1rtt_path_acks(now)?;
                }
                // Initial / Handshake 空間の ACK は各暗号化レベルの送信で処理済み。
                let _ = path_id;
            }
            TimerId::ClosingDraining => {
                // Closing/Draining 猶予期間終了: Closed に遷移する
                if self.state == ConnectionState::Closing || self.state == ConnectionState::Draining
                {
                    self.state = ConnectionState::Closed;
                }
            }
            TimerId::Idle => {
                // アイドルタイムアウト: 接続を静かに閉じる (RFC 9000 Section 10.1)
                if self.state == ConnectionState::Connected
                    || self.state == ConnectionState::Handshaking
                {
                    self.state = ConnectionState::Closed;
                    // qlog: アイドルタイムアウトによるクローズ
                    // (qlog-quic-events-13 Section 4.3 の trigger "idle_timeout")
                    if self.qlog_writer.is_some() {
                        let time_ms = self.qlog_time_ms();
                        if let Some(ref mut w) = self.qlog_writer {
                            w.on_connection_closed(
                                time_ms,
                                None,
                                Some("idle timeout"),
                                "idle_timeout",
                            );
                        }
                    }
                    self.push_event(ConnectionEvent::ConnectionClosed {
                        error_code: 0,
                        reason: "idle timeout".into(),
                        kind: ConnectionCloseKind::IdleTimeout,
                    });
                }
            }
            TimerId::PathValidation { path_id } => {
                // パス検証タイムアウト (RFC 9000 Section 8.2.4)
                //
                // 閉じ始めた接続では検証を進めない。close 時に移行と到達性確認は
                // 取り消し済みだが、発火済みのタイマーが遅れて届いても、
                // PATH_CHALLENGE のリトライ・タイマー再設定・終了後の
                // PathValidationFailed 通知を行わないよう、状態で防御する。
                if self.state != ConnectionState::Connected {
                    return Ok(());
                }
                let Some(path) = self.paths.get_mut(path_id) else {
                    return Ok(());
                };

                // preferred_address への移行検証中はパスが Active のままだが
                // 検証タイマーは動作させる必要がある (RFC 9000 Section 9.6.1)。
                let migration_pending = self.pending_migrations.contains_key(&path_id);
                // 昇格前の到達性確認中もパスは Active のままだが、
                // PATH_RESPONSE が来ないときのためにリトライする。
                let probing = self.pending_path_probes.contains(&path_id);
                // 検証完了または廃棄済みのパスでは何もしない
                if path.state != PathState::Validating && !migration_pending && !probing {
                    return Ok(());
                }

                // ピア CID が未通知のまま検証タイムアウトしたか
                // (RFC 10069 Section 4.2.1 の
                //  NO_CID_AVAILABLE_FOR_PATH で廃棄する判断に使う)
                let no_peer_cid = path_id != PathId::INITIAL && path.peer_cid.is_none();

                // リトライ上限チェック
                if path.validation.increment_retry() {
                    // 初期パスは唯一の経路であることが多く、廃棄すると接続
                    // そのものが閉じる。検証に失敗した場合は最後に検証済みの
                    // 4-tuple へ戻し、戻せない場合は現在の 4-tuple を認めて
                    // 接続を維持する (RFC 9000 Section 9.3.2)。初期パス以外は
                    // 従来どおり廃棄する。
                    if path_id == PathId::INITIAL && !migration_pending {
                        let hint = self
                            .paths
                            .get_mut(path_id)
                            .expect("path exists")
                            .migration_hint;
                        let path = self.paths.get_mut(path_id).expect("path exists");
                        if let Some(hint) = hint {
                            path.remote_addr = hint.previous_remote_addr;
                            path.local_addr = hint.previous_local_addr;
                        }
                        path.state = PathState::Active;
                        path.address_validated = true;
                        path.migration_reset_pending = false;
                        path.validation.restart();
                        self.pending_path_probes.remove(&path_id);
                        if self.defer_path_datagrams_until_challenge == Some(path_id) {
                            self.defer_path_datagrams_until_challenge = None;
                        }
                        if self.defer_initial_datagrams_until_challenge {
                            self.defer_initial_datagrams_until_challenge = false;
                        }
                        self.output_queue.push_back(ConnectionOutput::ClearTimer {
                            id: TimerId::PathValidation { path_id },
                        });
                        self.push_event(ConnectionEvent::PathValidationFailed { path_id });
                        tracing::warn!(
                            "initial path validation failed; keeping the connection alive path={path_id:?}"
                        );
                        return Ok(());
                    }
                    // 上限超過: preferred_address への移行検証中であれば元の
                    // アドレスと CID へ戻す (RFC 9000 Section 9.6.1 MUST)。
                    // それ以外はパスを廃棄する。廃棄する前に検証失敗を
                    // アプリへ通知する (RFC 9000 Section 8.2.4)。
                    self.pending_path_probes.remove(&path_id);
                    if !self.abort_pending_migration(path_id) {
                        self.push_event(ConnectionEvent::PathValidationFailed { path_id });
                        // ピアが対象 path ID の CID を発行しないまま検証が
                        // タイムアウトした場合は NO_CID_AVAILABLE_FOR_PATH で
                        // 廃棄する (RFC 10069 Section 4.2.1)。
                        let error_code = if no_peer_cid {
                            frame::path_abandon::error_code::NO_CID_AVAILABLE_FOR_PATH
                        } else {
                            0
                        };
                        self.abandon_path_inner(path_id, error_code, now)?;
                    }
                } else {
                    // リトライ: 新しい PATH_CHALLENGE を送信する
                    let mut challenge_data = [0u8; 8];
                    aws_lc_rs::rand::fill(&mut challenge_data).map_err(|_| {
                        Error::InvalidData("failed to generate random bytes".into())
                    })?;

                    // 移行検証中は候補アドレス宛てに送り続ける
                    let candidate_addrs = self
                        .pending_migrations
                        .get(&path_id)
                        .map(|m| (m.candidate_remote_addr, m.candidate_local_addr));

                    let path = self.paths.get_mut(path_id).expect("path must exist");
                    path.validation.request_challenge(challenge_data);
                    // ピア CID が未通知のパスでは送信を保留する。DCID に使える
                    // CID が無く、送ってもピアがルーティングできない。
                    let has_peer_cid = path.peer_cid.is_some();

                    if has_peer_cid {
                        let (candidate_remote_addr, candidate_local_addr) = match candidate_addrs {
                            Some((remote, local)) => (Some(remote), local),
                            None => (None, None),
                        };
                        self.emit_1rtt_path_challenge_to(
                            path_id,
                            challenge_data,
                            candidate_remote_addr,
                            candidate_local_addr,
                            now,
                        )?;
                    }

                    // PTO バックオフ付きでタイマーを再設定する
                    let retry_count = self
                        .paths
                        .get(path_id)
                        .expect("path must exist")
                        .validation
                        .retry_count();
                    let base_pto = self.path_validation_pto(path_id);
                    let backoff_pto = tobi_core::time::Duration::from_micros(
                        base_pto
                            .as_micros()
                            .saturating_mul(1u64 << retry_count.min(62)),
                    );
                    self.output_queue.push_back(ConnectionOutput::SetTimer {
                        id: TimerId::PathValidation { path_id },
                        deadline: now + backoff_pto,
                    });
                }
            }
            TimerId::PathCleanup { path_id } => {
                self.cancel_one_rtt_path(path_id)?;
                self.pacing_deadlines.remove(&path_id);
                self.one_rtt_bursts.remove(&path_id);
                if self.pending_abandon_completion.remove(&path_id) {
                    self.retire_peer_cids_for_path(path_id, now)?;
                    self.output_queue
                        .push_back(ConnectionOutput::PathClosed { path_id });
                }
                // PATH_ABANDON 後の 3 PTO クリーンアップ
                // (RFC 10069 Section 3.4)
                // パス状態と関連リソースを完全に削除する
                // 退役済みのピア CID をパスに保持し続けない
                // (RFC 10069 Section 3.4)。初期パスは削除
                // しないため、ここでクリアしないと CID が残り続ける。
                if let Some(path) = self.paths.get_mut(path_id) {
                    path.peer_cid = None;
                }
                if path_id != PathId::INITIAL {
                    self.paths.remove_path(path_id);
                }
                // 削除したパス宛ての未送信データグラムを送信キューから除去する。
                // 残すと、存在しないパス向けの PATH_CHALLENGE などが古い宛先へ
                // 送信され、認証前に積まれた出力が反射に使われる。
                self.remove_queued_datagrams_for_path(path_id);
            }
            TimerId::ZeroRttKeys => {
                // RFC 9001 Section 4.9.3: 1-RTT パケット受信から 3 × PTO 経過後、
                // 順序が入れ替わって届いた 0-RTT パケットを復号する必要はない。
                self.zero_rtt_keys = None;
                self.zero_rtt_keys_discard_at = None;
            }
            TimerId::KeepAlive { path_id } => {
                // パス単位の keep-alive: 対象パスにだけ PING を送信する
                // (RFC 9000 Section 10.1.2 / RFC 10069 Section 5.9)
                if self.state != ConnectionState::Connected || self.one_rtt_keys.is_none() {
                    return Ok(());
                }
                let Some(interval) = self.effective_keep_alive_interval() else {
                    return Ok(());
                };
                let Some(path) = self.paths.get(path_id) else {
                    return Ok(());
                };
                if !path.keep_alive_enabled() || !path.is_usable() {
                    return Ok(());
                }
                // 直近に送受信がある場合は PING を送らず、最終活動 + 間隔の
                // 時点まで再度待つ。データ送信が続いているパスに不要な PING を
                // 重ねない。
                if let Some(last_activity) = path.last_activity_at() {
                    let deadline = last_activity.add(interval);
                    if now < deadline {
                        self.output_queue.push_back(ConnectionOutput::SetTimer {
                            id: TimerId::KeepAlive { path_id },
                            deadline,
                        });
                        return Ok(());
                    }
                }
                // 送信に失敗してもタイマーは再設定し、keep-alive を止めない
                if let Err(e) = self.send_ping(path_id, now) {
                    tracing::debug!("keep-alive PING failed on path {path_id}: {e}");
                }
                self.output_queue.push_back(ConnectionOutput::SetTimer {
                    id: TimerId::KeepAlive { path_id },
                    deadline: now.add(interval),
                });
            }
            TimerId::Pacing { path_id } => {
                self.pacing_deadlines.remove(&path_id);
                // Pacing の departure time に達したので送信を再開する。
                // (Sans I/O ではアプリケーションが handle_timer を呼んだ後に
                // poll_output() で送信データグラムを取り出す)
                if self.one_rtt_keys.is_some() && self.state == ConnectionState::Connected {
                    self.emit_packets(now)?;
                }
            }
            TimerId::PmtuProbe { path_id } => {
                // 連続タイムアウトでは次回の再プローブ間隔を倍加する
                let backoff = self.pmtu_probe_backoff.entry(path_id).or_insert(0);
                *backoff = backoff.saturating_add(1).min(6);
                // DPLPMTUD プローブタイムアウト (RFC 8899)
                // ACK/Loss が時間内に来なかった場合、ロストとみなす
                let mut timed_out_probe_pn: Option<u64> = None;
                if let Some(path) = self.paths.get_mut(path_id)
                    && let probe_pn = match path.mtu_controller.state() {
                        tobi_core::path::mtu::MtuState::Searching { probe_pn, .. }
                        | tobi_core::path::mtu::MtuState::BaseSearching { probe_pn, .. } => {
                            Some(probe_pn)
                        }
                        _ => None,
                    }
                    && let Some(probe_pn) = probe_pn
                {
                    timed_out_probe_pn = Some(probe_pn);
                    // タイムアウトしたプローブはロストとして扱う。プローブの
                    // ロストは輻輳の兆候ではないため cwnd を減らさず、
                    // bytes_in_flight からだけ除去する (RFC 8899 Section 5.7)。
                    // 同時に飛ぶプローブを 1 個に抑え、プローブが cwnd を
                    // 使い切って STREAM データを送れなくなるのを防ぐ。
                    if let Some(packet) = path.sent_packets.remove_packet(probe_pn)
                        && packet.in_flight
                    {
                        // PROBE_TIMER 満了は ACK ではないため、largest_acked を
                        // 進めない削除 API を使う。
                        path.congestion.on_packet_discarded_bytes(packet.sent_bytes);
                    }
                    // CC の per-packet 状態も通常のロスト経路と同じく破棄する
                    path.congestion
                        .on_packets_discarded_cc(PacketNumberSpace::ApplicationData, &[probe_pn]);
                    path.mtu_controller.on_probe_lost(probe_pn, now);
                }
                if let Some(probe_pn) = timed_out_probe_pn {
                    self.pmtu_probe_pns
                        .retain(|&(probe_path, pn)| probe_path != path_id || pn != probe_pn);
                }
                // 必要ならば再プローブを送信する
                self.emit_pmtu_probes(now)?;
            }
            TimerId::PmtuRaise { path_id } => {
                // DPLPMTUD 再プローブタイマー発火 (RFC 8899)
                // MTU 増加の余地がないか再探索する
                if let Some(path) = self.paths.get_mut(path_id) {
                    path.mtu_controller.check_reprobe(now);
                }
                self.emit_pmtu_probes(now)?;
            }
        }
        Ok(())
    }

    /// 指定パスの SendDatagram を生成する (Initial / Handshake レベル)
    ///
    /// Initial / Handshake パケットは ECN 検証の対象外とし、常に `NotEct` を設定する。
    /// RFC 9000 Section 13.4.2 の ECN 検証は 1-RTT パケットのみで行う。
    fn make_send_datagram(&self, data: Vec<u8>, path_id: PathId) -> ConnectionOutput {
        self.make_send_datagram_with_ecn(data, path_id, EcnCodepoint::NotEct)
    }

    /// 明示的な ECN コードポイントで SendDatagram を生成する
    fn make_send_datagram_with_ecn(
        &self,
        data: Vec<u8>,
        path_id: PathId,
        ecn: EcnCodepoint,
    ) -> ConnectionOutput {
        let (remote_addr, local_addr) = self
            .paths
            .get(path_id)
            .map(|p| (p.remote_addr, p.local_addr))
            .unwrap_or_else(|| {
                let initial = self.paths.initial_path();
                (initial.remote_addr, initial.local_addr)
            });
        ConnectionOutput::SendDatagram {
            data,
            path_id,
            remote_addr,
            local_addr,
            ecn,
        }
    }

    /// パスの ECN 検証状態に応じた送信用 ECN コードポイントを返す
    ///
    /// RFC 9000 Section 13.4.2: Testing / Capable の間は ECT(0) を設定し、
    /// Failed に遷移した後は NotEct にフォールバックする。
    fn path_ecn_codepoint(&self, path_id: PathId) -> EcnCodepoint {
        let Some(path) = self.paths.get(path_id) else {
            return EcnCodepoint::NotEct;
        };
        if path.ecn_state.should_mark_ect0() {
            EcnCodepoint::Ect0
        } else {
            EcnCodepoint::NotEct
        }
    }

    /// 認証したデータグラム全体を、その 4-tuple の増幅予算へ一度だけ加算する
    ///
    /// RFC 9000 Section 8.1 の増幅制限は、送信先アドレスごとに
    /// 「そのアドレスから受信した量の 3 倍」で評価する。受信元の 4-tuple が
    /// 変わったら旧アドレスの予算を新アドレスへ引き継がない。
    /// RFC 9000 Section 8.1 の計上単位は UDP payload 全体である。
    /// 呼び出し側は AEAD 復号に成功したパケットでのみ呼ぶこと。
    fn record_authenticated_received_datagram(
        &mut self,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) {
        // クライアントはサーバーのアドレスを検証済みとして扱う
        // (RFC 9000 Section 8.1: 制限はサーバー側のみ)。
        if self.address_validated {
            return;
        }
        let Some(len) = self.current_recv_datagram_len.take() else {
            return;
        };
        let tuple = (remote_addr, local_addr);
        if self.amplification_addr != Some(tuple) {
            // アドレスが変わったら、旧アドレスで積んだ予算を新アドレスへ
            // 引き継がない。このデータグラムのバイト数だけが新しい予算になる。
            self.recv_bytes_before_validated = 0;
            self.sent_bytes_before_validated = 0;
            self.amplification_addr = Some(tuple);
        }
        self.recv_bytes_before_validated =
            self.recv_bytes_before_validated.saturating_add(len as u64);
    }

    /// アンチアンプリフィケーションにより `SendDatagram` を今すぐ出せないか（参照のみ）
    fn send_datagram_blocked(&self, len: u64, path_id: PathId) -> bool {
        if !self.address_validated {
            let limit = self.recv_bytes_before_validated.saturating_mul(3);
            let new_total = self.sent_bytes_before_validated.saturating_add(len);
            if new_total > limit {
                return true;
            }
        }
        if let Some(path) = self.paths.get(path_id)
            && !path.can_send_bytes(len)
        {
            return true;
        }
        false
    }

    /// 現在時刻で送信可能な出力を 1 件取り出す。
    ///
    /// 通常の 1-RTT 出力は、この時点で PN、CID、鍵を確定して暗号化する。
    /// 準備に失敗した場合はエラーを返す。接続終了時の暗号化済み出力は、
    /// 従来どおり出力キューから取り出す。
    pub fn poll_output(&mut self, now: Timestamp) -> Result<Option<ConnectionOutput>, Error> {
        self.observe_congestion_changes();
        if matches!(
            self.state,
            ConnectionState::Draining | ConnectionState::Closed
        ) {
            self.output_queue
                .retain(|output| !matches!(output, ConnectionOutput::SendDatagram { .. }));
            self.discard_one_rtt_outputs(false);
        }
        // ハンドシェイク中のリバインディングでは、新しい 4-tuple への最初の
        // サーバー パケットに PATH_CHALLENGE を含める。PATH_CHALLENGE の 1-RTT
        // 出力が準備できるまでの間は、初期パス宛ての Initial / Handshake の
        // 暗号化済みデータグラムを後回しにする。保留出力が消えた場合は、
        // 再送を止め続けないよう保留も解除する。
        if self.defer_initial_datagrams_until_challenge
            && !self.one_rtt_outputs.iter().any(|pending| {
                pending.path_id == PathId::INITIAL
                    && matches!(pending.purpose, OneRttPurpose::PathChallenge { .. })
            })
        {
            self.defer_initial_datagrams_until_challenge = false;
        }
        let defer_initial = self.defer_initial_datagrams_until_challenge;
        // ソケット作成・CID 登録・タイマーを先に渡す。Initial / Handshake /
        // 0-RTT の暗号化済み出力も、共有する PN 空間の順序を保つため先に渡す。
        let mut seen_raw_datagram = false;
        let raw_index = self.output_queue.iter().position(|output| match output {
            ConnectionOutput::SendDatagram { data, path_id, .. } => {
                if defer_initial && *path_id == PathId::INITIAL {
                    seen_raw_datagram = true;
                    return false;
                }
                // 暗号化済みの Initial / Handshake も PN 空間の順序を保つ。
                // 先頭が止まっている間は、後続の小さい暗号文で追い越さない。
                let first = !seen_raw_datagram;
                seen_raw_datagram = true;
                first && !self.send_datagram_blocked(data.len() as u64, *path_id)
            }
            _ => true,
        });
        let output = if let Some(index) = raw_index {
            self.output_queue.remove(index)
        } else if !defer_initial
            && self.output_queue.iter().any(|output| {
                matches!(output, ConnectionOutput::SendDatagram { data, .. }
                    if output::has_application_data(data))
            })
        {
            None
        } else {
            match self.poll_one_rtt_output(now) {
                Ok(output) => output,
                Err(error) => {
                    self.close_on_output_error(&error);
                    return Err(error);
                }
            }
        };
        // 出力選択中に pacing タイマーを設定した場合も、同じ poll で渡す。
        // None の背後へタイマーを残すと I/O 層が待機を開始できない。
        let output = output.or_else(|| {
            let index = self
                .output_queue
                .iter()
                .position(|output| !matches!(output, ConnectionOutput::SendDatagram { .. }))?;
            self.output_queue.remove(index)
        });
        let Some(output) = output else {
            return Ok(None);
        };
        if self.defer_initial_datagrams_until_challenge
            && matches!(&output, ConnectionOutput::SendDatagram { path_id, .. } if *path_id == PathId::INITIAL)
        {
            // PATH_CHALLENGE が先に出たため、保留していた再送を再開する。
            self.defer_initial_datagrams_until_challenge = false;
        }
        if let ConnectionOutput::SendDatagram { data, path_id, .. } = &output {
            let len = data.len() as u64;
            if !self.address_validated {
                self.sent_bytes_before_validated =
                    self.sent_bytes_before_validated.saturating_add(len);
            }
            self.stats.record_sent(len);
            if let Some(path) = self.paths.get_mut(*path_id) {
                path.on_bytes_sent(len);
                path.record_sent_packet(len);
            }
            if let Some((space, deadline)) = self.loss_detection_timer(*path_id, now) {
                self.set_loss_detection_timer(*path_id, space, deadline);
            }
            if self.state == ConnectionState::Connected {
                self.notify_app_limited_if_idle();
            }
        }
        Ok(Some(output))
    }

    /// アプリケーションイベントをキューへ追加する
    ///
    /// `StreamReadable` は同じストリームの未読イベントが既にあれば合流させる。
    /// キューが上限に達している場合は新しいイベントを破棄する。接続の終了通知
    /// だけは状態を確定するために優先し、古いイベントを 1 件捨てて追加する。
    fn push_event(&mut self, event: ConnectionEvent) {
        if let ConnectionEvent::StreamReadable { stream_id } = event {
            let already_notified = self.event_queue.iter().any(|queued| {
                matches!(
                    queued,
                    ConnectionEvent::StreamReadable { stream_id: queued_id }
                        if *queued_id == stream_id
                )
            });
            if already_notified {
                return;
            }
        }
        if self.event_queue.len() >= MAX_EVENT_QUEUE_EVENTS {
            if matches!(
                event,
                ConnectionEvent::ConnectionClosed { .. } | ConnectionEvent::Connected
            ) {
                // 接続の開始と終了はアプリケーションが状態を確定するために
                // 必要な制御通知であり、失うと接続確立や終了を観測できない。
                // 最も古いイベントを捨ててでも追加する。
                self.event_queue.pop_front();
            } else {
                return;
            }
        }
        self.event_queue.push_back(event);
    }

    /// アプリケーションイベントを 1 件取り出す
    ///
    /// イベントを消費した時点で、終端済みストリームの GC を試みる。未消費の
    /// イベントが残っているストリームは GC されない。
    pub fn poll_event(&mut self) -> Option<ConnectionEvent> {
        let event_queue = &self.event_queue;
        self.streams.gc_finished_streams(|stream_id| {
            event_queue
                .iter()
                .any(|event| connection_event_stream_id(event) == Some(stream_id))
        });
        self.event_queue.pop_front()
    }

    /// 観測イベントの記録を有効化・無効化する
    ///
    /// アプリケーションがイベントを購読したときだけ有効化する。無効化すると
    /// キューに残っているイベントも破棄する。
    pub fn set_observation_enabled(&mut self, enabled: bool) {
        self.observation_enabled = enabled;
        if !enabled {
            self.observation_queue.clear();
            self.observed_congestion_states.clear();
        }
    }

    /// 観測イベントを 1 件取り出す
    pub fn poll_observation_event(&mut self) -> Option<ConnectionObservationEvent> {
        self.observation_queue.pop_front()
    }

    /// 観測イベントをキューに積む
    ///
    /// 未購読時は何もしない。キューが満杯の場合は古いイベントを破棄する。
    /// 観測は接続処理をブロックしてはならないため、待機は行わない。
    fn observe(&mut self, event: ConnectionObservationEvent) {
        if !self.observation_enabled {
            return;
        }
        if self.observation_queue.len() >= MAX_OBSERVATION_QUEUE_EVENTS {
            self.observation_queue.pop_front();
        }
        self.observation_queue.push_back(event);
    }

    /// パスごとの輻輳制御状態の変化を観測イベントとして記録する
    ///
    /// ACK 処理やロスト検出で状態が変わるため、データグラム処理と損失検出の
    /// 末尾で呼ぶ。未購読時は何もしない。
    fn observe_congestion_changes(&mut self) {
        if !self.observation_enabled {
            return;
        }
        // paths を借用したまま observe() を呼べないため、変化を先に集める。
        let mut changes: Vec<(PathId, CongestionStateKind)> = Vec::new();
        for path in self.paths.all_paths() {
            let state = path.congestion.state_kind();
            if self.observed_congestion_states.get(&path.id) != Some(&state) {
                changes.push((path.id, state));
            }
        }
        for (path_id, state) in changes {
            let is_initial_observation = self
                .observed_congestion_states
                .insert(path_id, state)
                .is_some();
            if is_initial_observation {
                self.observe(ConnectionObservationEvent::CongestionStateChanged { path_id, state });
            }
        }
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// この接続で使用している QUIC バージョンを返す
    ///
    /// クライアントは最初の接続試行で設定したバージョン、サーバーは
    /// 受信した Initial のバージョンとなる (RFC 9000 Section 15)。
    pub fn version(&self) -> u32 {
        self.version
    }

    /// 互換バージョン交渉でサーバーが選んだバージョンを返す (クライアントのみ)
    ///
    /// RFC 9368 Section 2.3: サーバーがクライアントの Chosen Version と
    /// 異なる互換バージョンで応答した場合に、そのバージョンを返す。
    /// rustls の QUIC セッションがバージョンに束縛されるため接続内では
    /// 切り替えられず、上位層がこのバージョンで新しい接続試行を開始する。
    pub fn compatible_version_switch(&self) -> Option<u32> {
        self.compatible_version_switch
    }

    /// 受信した Version Negotiation が提示したバージョン一覧を返す
    ///
    /// `None` は VN を受信していないことを表す。クライアントは接続中止後に
    /// この一覧から未試行の対応バージョンを選んで再試行する
    /// (RFC 9000 Section 6.2)。
    pub fn version_negotiation_versions(&self) -> Option<&[u32]> {
        self.version_negotiation_versions.as_deref()
    }

    /// 全パスのメトリクススナップショットを返す
    pub fn path_metrics(&self) -> Vec<tobi_core::scheduler::PathMetrics> {
        self.paths.collect_metrics()
    }

    /// 接続全体の累積統計を返す
    ///
    /// 経過時間は最初の送受信を観測した時点からの値で、`now` を使って求める。
    /// まだ送受信していない接続では経過時間は 0 になる。
    pub fn stats(&self, now: Timestamp) -> ConnectionStats {
        let mut stats = self.stats;
        stats.datagram_send_queue_len = self.datagram_send_queue.len();
        stats.datagram_recv_queue_len = self.datagram_recv_queue.len();
        stats.elapsed = self
            .started_at
            .map_or(Duration::ZERO, |start| now.saturating_duration_since(start));
        stats
    }

    /// ロストした in-flight パケットの統計を更新する
    fn record_lost_packet(&mut self, path_id: PathId) {
        self.stats.record_lost();
        if let Some(path) = self.paths.get_mut(path_id) {
            path.record_lost_packet();
        }
    }

    /// 再送した in-flight パケットの統計を更新する
    fn record_retransmitted_packet(&mut self, path_id: PathId) {
        self.stats.record_retransmitted();
        if let Some(path) = self.paths.get_mut(path_id) {
            path.record_retransmitted_packet();
        }
    }

    /// 指定パスの 4-tuple を返す (`(local_addr, remote_addr)`)
    ///
    /// パスが存在しない場合は `None`。
    pub fn path_addrs(
        &self,
        path_id: PathId,
    ) -> Option<(std::net::SocketAddr, std::net::SocketAddr)> {
        self.paths
            .get(path_id)
            .map(|p| (p.local_addr, p.remote_addr))
    }

    /// 指定パスで送信に使うピアの Connection ID を返す
    ///
    /// パスが存在しない場合や、ピアの CID がまだ確定していない場合は `None`。
    /// preferred_address への移行が確定すると、初期パスの宛先 CID は
    /// ピアが通知した CID に置き換わる (RFC 9000 Section 9.6.1)。
    pub fn path_peer_cid(&self, path_id: PathId) -> Option<&ConnectionId> {
        self.paths.get(path_id).and_then(|p| p.peer_cid.as_ref())
    }

    /// Initial で受信したアドレストークンが検証できたかを返す
    /// (RFC 9000 Section 8.1.3)
    ///
    /// サーバー側では、クライアントが Initial に有効なアドレストークンを
    /// 含めていた場合に `true` になる。トークンが無い、または検証に失敗した
    /// 場合は `false` のままである。クライアント側は常に `false`。
    pub fn initial_token_validated(&self) -> bool {
        self.initial_token_validated
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// ネゴシエートされた ALPN プロトコルを取得する
    ///
    /// ハンドシェイク完了前は None を返す。
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_protocol.as_deref()
    }

    /// 初期パスのローカルアドレスを返す
    ///
    /// `0.0.0.0` / `::` のままなら、まだ受信パケットの宛先で確定していない。
    pub fn initial_local_addr(&self) -> std::net::SocketAddr {
        self.paths.initial_path().local_addr
    }

    // --- ストリーム API ---

    /// ストリームの送信系 API を利用できる状態かを検証する
    ///
    /// 閉鎖中の接続では、ピアパラメータの再評価より先に接続終了を表す
    /// `InvalidData` を返す。閉鎖中は新しいストリームを開いたりデータを
    /// 書き込んだりしても送信されないため、成功を返してはならない。
    /// [`Self::send_datagram`] と同じ契約に揃えている。
    fn ensure_stream_send_allowed(&self) -> Result<(), Error> {
        if matches!(
            self.state,
            ConnectionState::Closing | ConnectionState::Draining | ConnectionState::Closed
        ) {
            return Err(Error::InvalidData("connection is closed".to_string()));
        }
        Ok(())
    }

    /// 双方向ストリームを開く
    ///
    /// # エラー
    ///
    /// - 接続が閉鎖中 (Closing / Draining / Closed) の場合は
    ///   `Error::InvalidData`
    /// - ピアが許可した上限に達している場合は `Error::StreamLimitReached`。
    ///   STREAMS_BLOCKED を送信待ちに積み、接続は閉じない。MAX_STREAMS の
    ///   受信後に再試行できる
    /// - ピアの transport parameter を適用できない場合は `Error::Protocol` など
    pub fn open_stream_bidi(&mut self) -> Result<u64, Error> {
        self.ensure_stream_send_allowed()?;
        self.maybe_apply_peer_params()?;
        let stream_id = self.streams.open_bidi()?;
        self.stats.record_stream_opened();
        Ok(stream_id)
    }

    /// 単方向ストリームを開く
    ///
    /// # エラー
    ///
    /// - 接続が閉鎖中 (Closing / Draining / Closed) の場合は
    ///   `Error::InvalidData`
    /// - ピアが許可した上限に達している場合は `Error::StreamLimitReached`。
    ///   STREAMS_BLOCKED を送信待ちに積み、接続は閉じない。MAX_STREAMS の
    ///   受信後に再試行できる
    /// - ピアの transport parameter を適用できない場合は `Error::Protocol` など
    pub fn open_stream_uni(&mut self) -> Result<u64, Error> {
        self.ensure_stream_send_allowed()?;
        self.maybe_apply_peer_params()?;
        let stream_id = self.streams.open_uni()?;
        self.stats.record_stream_opened();
        Ok(stream_id)
    }

    /// ピアが許可した双方向ストリームの残枠を返す
    ///
    /// ピアの累積許可数から、ローカルが既に開いた数を引いた値。許可数は接続の
    /// 生存期間における累積値であり、ストリームを閉じても残枠は戻らない
    /// (RFC 9000 Section 19.11)。ピアから MAX_STREAMS を受信すると増える。
    ///
    /// 返り値は参照時点の値であり、後続の [`Self::open_stream_bidi`] に対する
    /// 予約ではない。ハンドシェイク完了まではピアの許可数が未確定のため 0 を
    /// 返し得る。
    pub fn remaining_bidi_streams(&self) -> u64 {
        self.streams.remaining_bidi_streams()
    }

    /// ピアが許可した単方向ストリームの残枠を返す
    ///
    /// [`Self::remaining_bidi_streams`] の単方向版。残枠の意味と、返り値が
    /// 参照時点の値であることは同じ。
    pub fn remaining_uni_streams(&self) -> u64 {
        self.streams.remaining_uni_streams()
    }

    /// ピアが起動できる双方向ストリームの累積上限を引き上げ、MAX_STREAMS を送る
    ///
    /// RFC 9000 Section 19.11: MAX_STREAMS はピアが接続の生存期間に開ける
    /// 累積数を通知する。現在の上限以下の値は無視し、フレームを送らずに `Ok(())`
    /// を返す (同 Section 4.6 / Section 19.11)。[`Self`] には現在広告している
    /// 上限を取得する API がないため、値が適用されたかを呼び出し側で確認
    /// できない。現在の上限は [`StreamManager::local_max_streams_bidi`] が保持
    /// しており、[`Self`] の公開 API では観測できない。現在値と同じ値や小さい
    /// 値を渡してもエラーにせず、何も送らない (silent no-op)。
    ///
    /// # エラー
    ///
    /// - 2^60 を超える値は `Error::InvalidData` (RFC 9000 Section 19.11)
    /// - 接続が確立していない場合も `Error::InvalidData`
    pub fn set_max_streams_bidi(
        &mut self,
        maximum_streams: u64,
        now: Timestamp,
    ) -> Result<(), Error> {
        self.set_max_streams(maximum_streams, now, true)
    }

    /// ピアが起動できる単方向ストリームの累積上限を引き上げ、MAX_STREAMS を送る
    ///
    /// [`Self::set_max_streams_bidi`] の単方向版。現在の上限以下の値を無視して
    /// `Ok(())` を返す点、現在値を取得する API がない点、エラーの条件も同じ。
    /// 現在の上限は [`StreamManager::local_max_streams_uni`] が保持している。
    pub fn set_max_streams_uni(
        &mut self,
        maximum_streams: u64,
        now: Timestamp,
    ) -> Result<(), Error> {
        self.set_max_streams(maximum_streams, now, false)
    }

    /// ピアが起動できるストリームの累積上限を引き上げる
    ///
    /// 双方向と単方向で処理が同じため、公開ラッパーから共通化している。
    /// `bidirectional` は引き上げる上限の種別を表す。
    fn set_max_streams(
        &mut self,
        maximum_streams: u64,
        now: Timestamp,
        bidirectional: bool,
    ) -> Result<(), Error> {
        if self.state != ConnectionState::Connected {
            return Err(Error::InvalidData("connection must be established".into()));
        }
        if bidirectional {
            self.streams.set_local_max_streams_bidi(maximum_streams)?;
        } else {
            self.streams.set_local_max_streams_uni(maximum_streams)?;
        }
        self.flush(now)
    }

    /// ストリームにデータを書き込む
    ///
    /// 接続が閉鎖中 (Closing / Draining / Closed) の場合は
    /// `Error::InvalidData` を返す。
    pub fn stream_send(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<usize, Error> {
        self.ensure_stream_send_allowed()?;
        self.maybe_apply_peer_params()?;
        self.streams.send(stream_id, data, fin)
    }

    /// ピアが RESET_STREAM で通知したエラーコードを返す
    ///
    /// ピアがストリームをリセットしていない場合は `None` を返す。
    pub fn stream_recv_reset_error_code(&self, stream_id: u64) -> Option<u64> {
        self.streams.recv_reset_error_code(stream_id)
    }

    /// 受信側ストリームが RESET_STREAM で通知された最終サイズを返す
    ///
    /// リセットを受けていないストリームでは `None` を返す。アプリへ
    /// `StreamError::Reset` を返す際に最終サイズを併せて報告するために使う。
    pub fn stream_recv_final_size(&self, stream_id: u64) -> Option<u64> {
        self.streams.recv_final_size(stream_id)
    }

    /// 受信側ストリームが RESET_STREAM_AT で通知された Reliable Size を返す
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 4 / Section 5。
    /// RESET_STREAM によるリセットや未リセットのストリームでは `None` を返す。
    /// アプリへ `StreamError::Reset` を返す際に Reliable Size を併せて報告する
    /// ために使う。`None` は未リセットと RESET_STREAM の両方を表すため、
    /// 呼び出し側は [`Self::stream_recv_reset_error_code`] が `Some` のときだけ
    /// この値を使う。
    pub fn stream_recv_reset_at_reliable_size(&self, stream_id: u64) -> Option<u64> {
        self.streams.recv_reset_at_reliable_size(stream_id)
    }

    /// ストリームの送信側がアプリからの書き込みを受け付けない状態かを返す
    ///
    /// FIN を送信済み、リセット済み、または GC 済みの場合に `true` を返す。
    pub fn stream_send_finished(&self, stream_id: u64) -> bool {
        self.streams.send_finished(stream_id)
    }

    /// ピアが STOP_SENDING で通知したエラーコードを返す
    ///
    /// ピアが送信停止を要求していない場合は `None` を返す。
    pub fn stream_send_stopped_error_code(&self, stream_id: u64) -> Option<u64> {
        self.streams.send_stopped_error_code(stream_id)
    }

    /// ストリームからデータを読み取る
    pub fn stream_recv(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        self.streams.recv(stream_id, buf)
    }

    /// ストリームをリセットする
    pub fn stream_reset(&mut self, stream_id: u64, error_code: u64) -> Result<(), Error> {
        self.streams.reset_stream(stream_id, error_code)
    }

    /// `reliable_size` までのデータ配信を保証してストリームをリセットする
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 5。ピアが `reset_stream_at`
    /// transport parameter を提示していない場合や、`reliable_size > final_size` の
    /// 場合は `Err(Error::InvalidData)` を返す。
    pub fn stream_reset_at(
        &mut self,
        stream_id: u64,
        error_code: u64,
        reliable_size: u64,
    ) -> Result<(), Error> {
        self.streams
            .reset_stream_at(stream_id, error_code, reliable_size)
    }

    /// ピアに送信停止を要求する
    pub fn stream_stop_sending(&mut self, stream_id: u64, error_code: u64) -> Result<(), Error> {
        self.streams.stop_sending(stream_id, error_code)
    }

    /// データグラムを送信キューに追加する (RFC 9221)
    ///
    /// ピアが `max_datagram_frame_size` を通知していない場合はエラーを返す。
    /// エンコード後のフレームサイズ (フレームタイプ + Length + payload) が
    /// ピアの `max_datagram_frame_size` を超える場合もエラーを返す
    /// (RFC 9221 Section 3)。payload 単体の上限は [`Self::max_datagram_size`]
    /// で取得でき、PMTU から求めたペイロード上限を超える場合もエラーを返す
    /// (RFC 9000 Section 14.2)。
    /// RFC 9221 Section 5.4 は、輻輳制御が送信を許すまで DATAGRAM を遅延させるか、
    /// 送信せずに破棄するかのいずれかを実装に求めている。このメソッドは破棄を
    /// 選ぶ。送信キューが満杯の場合は最も古いデータグラムをドロップして新しい
    /// ものを追加する。この暗黙の破棄回数は [`Self::stats`] が返す
    /// [`ConnectionStats::datagram_send_dropped`] で観測できる。送信キューの
    /// 上限は [`ConnectionConfig::datagram_send_queue_max`] で設定する。
    /// 破棄を避けたい場合は [`Self::datagram_send_queue_has_space`] で空きを
    /// 確認してから追加し、空きが無い間は呼び出し側で待機する。
    /// 送信キューに積んだ後、PMTU の縮小により現在のサイズ上限へ収まらなく
    /// なった DATAGRAM は再送しないため破棄する (RFC 9221 Section 5.2、
    /// RFC 9000 Section 14.2)。この破棄は `datagram_send_dropped` には数えない。
    /// 実際の送信は `flush()` 後に `poll_output()` で取得する。
    ///
    /// 接続が終了している (Closing / Draining / Closed) 場合は
    /// `Error::InvalidData` を返し、送信キューは変更しない。
    pub fn send_datagram(&mut self, data: Vec<u8>) -> Result<(), Error> {
        if matches!(
            self.state,
            ConnectionState::Closing | ConnectionState::Draining | ConnectionState::Closed
        ) {
            return Err(Error::InvalidData("connection is closed".to_string()));
        }
        self.maybe_apply_peer_params()?;
        self.validate_datagram(&data)?;
        // キューが満杯の場合は古いものをドロップする。破棄した事実を
        // 利用側が観測できるよう、統計に記録する。
        if !self.datagram_send_queue_has_space() {
            self.stats.record_datagram_send_dropped();
            self.datagram_send_queue.pop_front();
        }
        self.datagram_send_queue.push_back(data);
        Ok(())
    }

    /// データグラムを送信キューに追加できるかを検証する (RFC 9221)
    ///
    /// 現在保持している `peer_params` を使い、`maybe_apply_peer_params` に
    /// よる確定は行わない。ピアが `max_datagram_frame_size` を通知していない
    /// 場合、エンコード後のフレームサイズ (フレームタイプ + Length + payload) が
    /// ピアの `max_datagram_frame_size` を超える場合 (RFC 9221 Section 3)、
    /// payload が PMTU から求めたペイロード上限を超える場合 (RFC 9000
    /// Section 14.2) はエラーを返す。payload 単体の上限は
    /// [`Self::max_datagram_size`] で取得できる。サイズ検査の規則は
    /// [`Self::send_datagram`] と同じである。送信キューの状態は変更しない。
    pub fn validate_datagram(&self, data: &[u8]) -> Result<(), Error> {
        let peer_max = self
            .peer_params
            .as_ref()
            .and_then(|p| p.max_datagram_frame_size);
        let max = match peer_max {
            None | Some(0) => {
                return Err(Error::InvalidData(
                    "peer does not support DATAGRAM frames".to_string(),
                ));
            }
            Some(max) => max,
        };
        // エンコード後のフレームサイズを検証する
        let frame_size = frame::datagram::Datagram::encoded_size_for(data.len()) as u64;
        if frame_size > max {
            return Err(Error::InvalidData(format!(
                "datagram frame size {} exceeds peer max_datagram_frame_size {}",
                frame_size, max
            )));
        }
        // RFC 9000 Section 14.2: PMTU を超えるとパケットが分割または破棄され得る。
        // 送信パスはデータスケジューラーが選ぶため、利用可能なパスのうち
        // 最小の PMTU から求めたペイロード上限で保守的に検査する。
        let path_limit = self.max_datagram_size().unwrap_or(0);
        if data.len() > path_limit {
            return Err(Error::InvalidData(format!(
                "datagram payload {} exceeds the limit {} allowed by the path MTU",
                data.len(),
                path_limit
            )));
        }
        Ok(())
    }

    /// DATAGRAM の送信キューに空きがあるかを返す
    ///
    /// [`Self::send_datagram`] は満杯のときに最も古い DATAGRAM を破棄する。
    /// 破棄を避けたい呼び出し側は、このメソッドが `true` を返す間だけ
    /// 送信キューへ追加すればよい。待機するかどうかは利用側が決める。
    pub fn datagram_send_queue_has_space(&self) -> bool {
        self.datagram_send_queue.len() < self.datagram_send_queue_max
    }

    /// 受信済みの DATAGRAM を 1 件取り出す (RFC 9221)
    ///
    /// 受信キューが空の場合は `None` を返す。受信キューが満杯の状態で新しい
    /// DATAGRAM を受信した場合は、最も古い DATAGRAM が破棄されている。
    /// 破棄件数は [`Self::stats`] が返す
    /// [`ConnectionStats::datagram_recv_dropped`] で観測できる。
    pub fn recv_datagram_now(&mut self) -> Option<Vec<u8>> {
        self.datagram_recv_queue.pop_front()
    }

    /// DATAGRAM の受信キューに空きがあるかを返す
    ///
    /// 受信キューが満杯の状態で新しい DATAGRAM を受信すると、最も古い
    /// DATAGRAM を破棄して新しいものを積む。
    pub fn datagram_recv_queue_has_space(&self) -> bool {
        self.datagram_recv_queue.len() < self.datagram_recv_queue_max
    }

    /// DATAGRAM の受信キューに保持している件数を返す
    pub fn datagram_recv_queue_len(&self) -> usize {
        self.datagram_recv_queue.len()
    }

    /// 受信した DATAGRAM を受信キューへ積む
    ///
    /// キューが上限に達している場合は最も古い DATAGRAM を破棄する。破棄件数は
    /// [`ConnectionStats::datagram_recv_dropped`] に加算する。
    fn push_datagram_recv(&mut self, data: Vec<u8>) {
        if self.datagram_recv_queue.len() >= self.datagram_recv_queue_max {
            self.datagram_recv_queue.pop_front();
            self.stats.record_datagram_recv_dropped();
        }
        self.datagram_recv_queue.push_back(data);
    }

    /// 送信可能な最大データグラムペイロードサイズを返す (RFC 9221)
    ///
    /// ピアが `max_datagram_frame_size` を通知していない場合は `None` を返す。
    /// 返される値はフレームヘッダ (タイプ + Length) を除いたペイロード部分の
    /// 最大サイズであり、ピアの `max_datagram_frame_size` から求めた上限と、
    /// PMTU から求めたペイロード上限の小さい方である。
    ///
    /// RFC 9000 Section 14.2 により経路の最大データグラムサイズも上限になる。
    /// 送信パスはデータスケジューラーが選ぶため、利用可能なパスのうち最小の
    /// PMTU から求めたペイロード上限で保守的に検査する。
    pub fn max_datagram_size(&self) -> Option<usize> {
        let peer_max = self
            .peer_params
            .as_ref()
            .and_then(|p| p.max_datagram_frame_size)?;
        if peer_max == 0 {
            return None;
        }
        let mut limit = datagram_payload_limit(peer_max as usize);

        for path in self.paths.all_paths().filter(|p| p.is_usable()) {
            // 待機中の CID 変更も含め、生成時と同じヘッダー予算を使う。
            let Some(frame_max) = (path.pmtu as usize).checked_sub(MAX_ONE_RTT_OVERHEAD) else {
                continue;
            };
            limit = limit.min(datagram_payload_limit(frame_max));
        }

        Some(limit)
    }

    /// 経過時間の起点を記録する
    ///
    /// 最初の送信または受信を観測した時刻を接続の開始時刻として記録する。
    fn record_activity(&mut self, now: Timestamp) {
        if self.started_at.is_none() {
            self.started_at = Some(now);
        }
    }

    /// 送信待ちデータをパケット化する
    ///
    /// stream_send() 等でバッファに書き込んだデータを即座にパケット化して
    /// poll_output() で取得可能にする。
    /// Sans I/O 設計のため、receive() や handle_timer() を待たずに
    /// 明示的に送信をトリガーする場合に使用する。
    ///
    /// 接続が閉鎖中 (Closing / Draining / Closed) の場合は何も送信せず
    /// `Ok(())` を返す。CONNECTION_CLOSE の再送は `receive` が行う。
    pub fn flush(&mut self, now: Timestamp) -> Result<(), Error> {
        self.record_activity(now);
        // 閉鎖中はピアパラメータを再評価しない。不正なピアパラメータで閉じた
        // 接続でも、閉鎖猶予中のフラッシュがアプリへエラーを返さないようにする。
        // CONNECTION_CLOSE の再送は `receive` が行う。
        if matches!(
            self.state,
            ConnectionState::Closing | ConnectionState::Draining | ConnectionState::Closed
        ) {
            return Ok(());
        }
        self.maybe_apply_peer_params()?;
        if self.state == ConnectionState::Connected || self.state == ConnectionState::Handshaking {
            self.emit_packets(now)?;
        }
        Ok(())
    }

    // --- 接続のクローズ ---

    /// transport-level の CONNECTION_CLOSE (type 0x1c) を送って接続を閉じる
    ///
    /// RFC 9000 Section 10.2.1 / Section 10.2.3 に基づき、transport-level の
    /// CONNECTION_CLOSE (type 0x1c) を送信して Closing 状態に遷移する。
    /// `error_code` に 0 を渡すと NO_ERROR (RFC 9000 Section 20.1) による
    /// 正常クローズになる。アプリケーションのエラーコードを通知する場合は
    /// [`Self::close_application`] を使う。
    ///
    /// 送信する鍵レベルは実際に保持している鍵で決める:
    ///
    /// - ハンドシェイク確定前 (`state != Connected`): Initial / Handshake / 1-RTT のうち
    ///   保持している全空間に載せてコアレスする (RFC 9000 Section 10.2.3 の SHOULD)。
    ///   1-RTT 鍵があれば Handshake と 1-RTT の両方で送る SHOULD を満たす。
    /// - ハンドシェイク確定後 (`state == Connected`): 1-RTT のみで送る (同節 MUST)。
    ///   確定後は Initial / Handshake 鍵が破棄済みという非局所な順序不変条件に
    ///   依存しないよう、明示的に 1-RTT へ限定するセーフガードを置く。
    ///
    /// 接続が既に閉じ始めている (Closing / Draining / Closed) 場合は何も送らずに
    /// `Ok(())` を返す。`error_code` が 62 ビット varint に収まらない場合は
    /// `Error::InvalidData` を返す。この検証は接続状態より先に行うため、
    /// 閉じ始めた接続に対しても範囲外の値はエラーになる。
    ///
    /// 1-RTT の閉鎖パケットの DCID には、接続が現在送信先に使っているピア CID を
    /// 使う。その CID が退役済みの場合は、現在の 4-tuple へ送信できる有効な CID を
    /// 選び直す。それも無い場合に限り、最後の送信先 CID (退役済み) を例外的に
    /// 使う。退役済み CID でも閉鎖パケットが届く根拠は RFC 9000 Section 5.1.1 で
    /// あり、CID を発行したエンドポイントは RETIRE_CONNECTION_ID を受けるまで
    /// その CID を運ぶパケットを受け付けなければならない (MUST)。
    ///
    /// 閉鎖パケットには CONNECTION_CLOSE だけを載せ、同じ DCID を指す
    /// RETIRE_CONNECTION_ID を含めない。これは RFC の要求ではなく実装ポリシーで
    /// ある。RFC 9000 Section 19.16 で関係するのは、RETIRE のシーケンス番号が
    /// そのパケットの DCID を指してはならない MUST NOT だけである。
    ///
    /// 検証中の移行と到達性確認は close 時に取り消し、それらの PathValidation
    /// タイマーを解除する。
    ///
    /// 再送用に閉鎖データグラムの暗号化済みバイト列を `closing_packet` へ保存する。
    /// 同一バイト列を再送するため、Initial 鍵が途中で破棄されても再暗号化は不要
    /// (RFC 9000 Section 10.2.1)。
    pub fn close(&mut self, error_code: u64, reason: &[u8], now: Timestamp) -> Result<(), Error> {
        self.close_inner(OutgoingCloseKind::Transport, error_code, reason, now)
    }

    /// アプリケーションエラーで接続を閉じる
    ///
    /// RFC 9000 Section 19.19 の application-level CONNECTION_CLOSE (type 0x1d) を
    /// 送信して Closing 状態に遷移する。`error_code` は MOQT / HTTP/3 などの
    /// アプリケーションプロトコルが定義する code space の値であり、
    /// transport error の code space (RFC 9000 Section 20.1) とは区別される。
    ///
    /// 送信する鍵レベルは [`Self::close`] と同じ規則に従う:
    ///
    /// - ハンドシェイク確定後: 1-RTT にだけ 0x1d を送る (RFC 9000 Section 10.2.3 の MUST)。
    /// - ハンドシェイク確定前: 1-RTT 鍵を保持していれば 1-RTT に 0x1d を載せる。
    ///   加えて、保持している Initial / Handshake 鍵の各空間には同節に従い 0x1c へ
    ///   変換したフレーム (Error Code は APPLICATION_ERROR、Frame Type は 0、
    ///   Reason Phrase は空) を載せる。0x1d と 0x1c は 1 つのデータグラムに
    ///   コアレスする (RFC 9000 Section 12.2)。
    ///
    /// reason phrase は `close_formatter` で 1 回だけ整形し、1-RTT と qlog にだけ
    /// 反映する。Initial / Handshake へ変換するときは整形結果を破棄して空にする
    /// (RFC 9000 Section 10.2.3 の MUST)。
    ///
    /// 接続が既に閉じ始めている (Closing / Draining / Closed) 場合は何も送らずに
    /// `Ok(())` を返す。`error_code` が 62 ビット varint に収まらない場合は
    /// `Error::InvalidData` を返す。この検証は接続状態より先に行うため、
    /// 閉じ始めた接続に対しても範囲外の値はエラーになる。
    ///
    /// 閉鎖パケットの DCID の扱いは [`Self::close`] と同じである。
    pub fn close_application(
        &mut self,
        error_code: u64,
        reason: &[u8],
        now: Timestamp,
    ) -> Result<(), Error> {
        self.close_inner(OutgoingCloseKind::Application, error_code, reason, now)
    }

    /// `close` / `close_application` の共通実装
    ///
    /// [`OutgoingCloseKind::Application`] の場合は 1-RTT に 0x1d を送り、確定前に
    /// 保持している Initial / Handshake には 0x1c へ変換したフレームを送る
    /// (RFC 9000 Section 10.2.3)。[`OutgoingCloseKind::Transport`] の場合は保持している
    /// 全レベル (確定後は 1-RTT のみ) に 0x1c を送る。
    ///
    /// 1-RTT の閉鎖パケットの DCID には、閉じる時点でパスが送信先に使っている
    /// ピア CID を使う。その CID が退役済みの場合は、現在の 4-tuple へ送信できる
    /// 有効な CID を選び直し、それも無い場合だけ退役済みの最後の送信先 CID を
    /// 例外的に使う。退役済み CID でも閉鎖パケットが届くのは、CID を発行した
    /// エンドポイントが RETIRE_CONNECTION_ID を受けるまでその CID を運ぶパケットを
    /// 受け付けなければならないためである (RFC 9000 Section 5.1.1 の MUST)。
    /// RFC 9000 Section 10.2.3 は、ピアが処理できる最も高い暗号化レベルで
    /// CONNECTION_CLOSE を届けることを目的としている。
    ///
    /// 閉鎖パケットに CONNECTION_CLOSE だけを載せ、同じ DCID を指す
    /// RETIRE_CONNECTION_ID を含めないのは実装ポリシーである。RFC 9000
    /// Section 19.16 で関係するのは、RETIRE のシーケンス番号がそのパケットの
    /// DCID を指してはならない MUST NOT だけである。
    ///
    /// close 時には検証中の移行と到達性確認を取り消し、それらの PathValidation
    /// タイマーを解除する。取り消しは検証失敗として扱わず、
    /// `PathValidationFailed` を通知しない。
    fn close_inner(
        &mut self,
        kind: OutgoingCloseKind,
        error_code: u64,
        reason: &[u8],
        now: Timestamp,
    ) -> Result<(), Error> {
        // RFC 9000 Section 16: CONNECTION_CLOSE の Error Code は 62 ビット
        // varint に収まる必要がある。アプリケーション由来の値を構築前に検証し、
        // encode 時の panic ではなく Result のエラーとして返す。入力の妥当性は
        // 接続状態に依存しないため、閉鎖済みの早期 return より前に検証する。
        let error_code_varint = VarInt::try_from(error_code)
            .map_err(|e| Error::InvalidData(format!("invalid connection error code: {e}")))?;

        // 既に閉じ始めている接続へ再度 close しても、フレームを送らず状態も変えない。
        if self.state == ConnectionState::Closing
            || self.state == ConnectionState::Draining
            || self.state == ConnectionState::Closed
        {
            return Ok(());
        }

        // 確定判定は state を Closing へ変える前に取得する。Connected 遷移で
        // 設定される `handshake_confirmed_once` を使い、ライフサイクル期限と
        // 同じ真実源にする。
        let handshake_confirmed = self.handshake_confirmed_once;

        // qlog: 状態遷移 → Closing
        if self.qlog_writer.is_some() {
            let time_ms = self.qlog_time_ms();
            let old = match self.state {
                ConnectionState::Connected => "connected",
                ConnectionState::Handshaking => "handshaking",
                _ => "unknown",
            };
            if let Some(ref mut w) = self.qlog_writer {
                w.on_connection_state_updated(time_ms, old, "closing");
            }
        }

        self.state = ConnectionState::Closing;
        self.discard_one_rtt_outputs(self.paths.active_path_count() == 0);
        // 閉じた接続では検証を進めない。検証中の移行と到達性確認をここで
        // 取り消し、PathValidation タイマーを解除する。残したままにすると、
        // Closing / Closed 中にタイマーが発火してリトライとタイマー再設定を
        // 繰り返し、リトライ上限では終了後に PathValidationFailed を通知する。
        self.discard_path_validation_on_close();
        // 閉鎖を復号するための ServerHello などは先に渡す。
        // Application Data の古い出力は閉鎖後に流さない。
        self.output_queue.retain(|output| match output {
            ConnectionOutput::SendDatagram { data, .. } => !output::has_application_data(data),
            _ => true,
        });

        // reason phrase の整形は送信レベルに関わらず 1 回だけ行う。
        // 1-RTT 送信の内側で整形すると Initial / Handshake の経路で整形が迂回され、
        // `SilentConnectionCloseFormatter` 等の抑制が効かず reason phrase が漏れる。
        // transport close は整形結果を保持している全レベルに載せる。application close
        // は 1-RTT にだけ載せ、Initial / Handshake への 0x1c 変換では空にする
        // (RFC 9000 Section 10.2.3 の MUST)。
        // qlog にも同じ整形後の値だけを記録し、内部のエラーメッセージや機密情報が
        // qlog へ漏れないようにする。
        let reason_phrase = self
            .close_formatter
            .as_ref()
            .map(|f| f.format(error_code, reason))
            .unwrap_or_else(|| reason.to_vec());

        // qlog: 接続クローズイベント (qlog-quic-events-13 Section 4.3)。
        // 同節は「ロガーは導出できる限り最も説明的な trigger を使うべき
        // (SHOULD)」と定めるため、application close は "application"、
        // transport close は "error" を渡す。
        // error_code は呼び出し元が渡した値 (application close なら application
        // code) を記録する。Initial / Handshake 向けに 0x1c へ変換したときの
        // APPLICATION_ERROR (0x0c) ではない。
        // reason phrase は 1-RTT に送る値と同じ整形後のものを使う。
        let trigger = match kind {
            OutgoingCloseKind::Transport => "error",
            OutgoingCloseKind::Application => "application",
        };
        if self.qlog_writer.is_some() {
            let time_ms = self.qlog_time_ms();
            let reason_text = if reason_phrase.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&reason_phrase).into_owned())
            };
            if let Some(ref mut w) = self.qlog_writer {
                w.on_connection_closed(time_ms, Some(error_code), reason_text.as_deref(), trigger);
            }
        }

        // 1-RTT 用の CONNECTION_CLOSE を組み立てる。
        // application close は type 0x1d であり、Frame Type フィールドを持たない
        // (RFC 9000 Section 19.19)。transport close は type 0x1c で、エラーを
        // 引き起こしたフレーム種別が不明なため Frame Type 0 を載せる。
        // Frame Type 0 は「フレーム種別が不明な場合に使う」と RFC 9000
        // Section 19.19 が定めている値である。
        let application = kind == OutgoingCloseKind::Application;
        let frame = Frame::ConnectionClose(frame::connection_close::ConnectionClose {
            application,
            error_code: error_code_varint,
            frame_type: match kind {
                OutgoingCloseKind::Application => None,
                OutgoingCloseKind::Transport => Some(VarInt::from(0u8)),
            },
            reason_phrase,
        });

        // RFC 9000 Section 10.2.3: 確定前に送る application close は 0x1d と
        // 変換後の 0x1c が別物になるため、コアレス時は両方を組み立てる。
        // transport close は Initial / Handshake でも 0x1c のままでよいため、
        // 1-RTT と同じフレームを使い回す。
        let early_frame = if handshake_confirmed {
            None
        } else {
            Some(match kind {
                OutgoingCloseKind::Transport => frame.clone(),
                OutgoingCloseKind::Application => Self::early_application_close_frame(),
            })
        };

        // RFC 9000 Section 12.2: コアレス順序は increasing encryption levels
        // (Initial → Handshake → 1-RTT)。1-RTT は Length を持たない Short Header のため
        // 必ず最後に置く。確定後は 1-RTT のみで送る (RFC 9000 Section 10.2.3 MUST)。
        // Initial 送信は `handshake_keys` ではなく `initial_keys.is_some()` で判定する
        // (Initial 鍵は Handshake 鍵の取得後に破棄され得るため)。
        let mut datagram = Vec::new();
        if let Some(ref early_frame) = early_frame {
            if self.initial_keys.is_some() {
                datagram.extend(self.build_initial_close_bytes(early_frame)?);
            }
            if self.handshake_keys.is_some() {
                datagram.extend(self.build_handshake_close_bytes(early_frame)?);
            }
        }
        // 確定後の 1-RTT は、そのとき Active なパスの CID と nonce で組む。
        // Active なパスが無いときは廃棄済みパスへ出さない。
        // 未確定時のコアレスは初期パスの 1-RTT を載せる (パスは初期パスだけ)。
        let open_path = self.paths.select_open_path();
        let close_path = if handshake_confirmed {
            open_path
        } else {
            Some(PathId::INITIAL)
        };
        // 1-RTT の閉鎖パケットを組む前に DCID を点検する。現在の送信先 CID が
        // 退役済みなら、現在の 4-tuple へ送信できる有効な CID を選び直す。
        // 選び直せない場合だけ、退役済みの最後の送信先 CID を例外的に使う。
        if let Some(path_id) = close_path {
            self.reselect_peer_cid_for_close(path_id);
        }
        if self.one_rtt_keys.is_some()
            && let Some(path_id) = close_path
        {
            datagram.extend(self.build_1rtt_close_bytes(&frame, path_id)?);
        }

        // 閉鎖データグラムを 1 件だけキューへ積み、Closing 中の再送用に保存する
        // (RFC 9000 Section 10.2.1)。Initial / Handshake を含むコアレスは ECN 対象外
        // のため NotEct で送る。確定後の 1-RTT だけのデータグラムも NotEct のまま
        // 同じ経路で出す。送信先は、未確定なら初期パス、確定後なら Active なパス。
        if !datagram.is_empty() {
            let send_path = if handshake_confirmed {
                open_path.expect("1-RTT close datagram requires an open path")
            } else {
                PathId::INITIAL
            };
            let closing = datagram.clone();
            self.output_queue
                .push_back(self.make_send_datagram(datagram, send_path));
            self.closing_packet = Some(closing);
            self.closing_last_resend = Some(now);
            self.closing_path_id = send_path;
        }

        // 3×PTO 猶予期間タイマーを設定する (RFC 9000 Section 10.2)
        self.set_closing_draining_timer(now);

        Ok(())
    }

    /// close 時に検証中の移行と到達性確認を取り消し、タイマーを解除する
    ///
    /// Closing / Closed 中は `handle_timer` の PathValidation 処理が状態を見て
    /// 何もしないが、タイマー自体を残すと I/O 層が不要な待機を続ける。また、
    /// 検証の記録を残すと終了後にイベントが増える余地を残す。ここで移行と
    /// 到達性確認を破棄し、対象パスのタイマー解除を出力へ積む。
    ///
    /// `PathValidationFailed` は通知しない。close はアプリケーションが明示的に
    /// 開始した終了であり、検証失敗として扱わないため、通知を行う
    /// `cancel_pending_migration` ではなく `discard_pending_migration` を使う。
    fn discard_path_validation_on_close(&mut self) {
        let mut cleared = Vec::new();
        let migration_paths: Vec<PathId> = self.pending_migrations.keys().copied().collect();
        for path_id in migration_paths {
            if self.discard_pending_migration(path_id) {
                cleared.push(path_id);
            }
        }
        let probe_paths: Vec<PathId> = self.pending_path_probes.drain().collect();
        for path_id in probe_paths {
            // 移行の取り消しで同じパスの解除を積んでいる場合は重ねない。
            if cleared.contains(&path_id) {
                continue;
            }
            self.output_queue.push_back(ConnectionOutput::ClearTimer {
                id: TimerId::PathValidation { path_id },
            });
        }
    }

    /// 閉鎖パケットの DCID に使うピア CID を点検し、必要なら選び直す
    ///
    /// 現在の送信先 CID が有効な集合に無い場合、現在の 4-tuple へ送信できる
    /// 有効な CID を取り直す。取れない場合は何もしない。呼び出し元は退役済みの
    /// 最後の送信先 CID を例外的に使う (RFC 9000 Section 5.1.1)。
    ///
    /// 移行候補として予約していた CID は、close が先に移行を取り消しているため
    /// 予約が解除されており、選び直しの対象になる。
    fn reselect_peer_cid_for_close(&mut self, path_id: PathId) {
        let current = self
            .paths
            .get(path_id)
            .and_then(|path| path.peer_cid.clone())
            .or_else(|| (path_id == PathId::INITIAL).then(|| self.peer_cid.clone()));
        if current
            .as_ref()
            .is_some_and(|connection_id| self.is_active_peer_cid(path_id, connection_id))
        {
            return;
        }
        if let Some(connection_id) = self.take_peer_cid_for_path(path_id) {
            self.assign_path_peer_cid(path_id, connection_id);
        }
    }

    /// 確定前に Initial / Handshake へ載せる application close の変換フレームを組み立てる
    ///
    /// RFC 9000 Section 10.2.3: ハンドシェイク確定前に application-level の
    /// CONNECTION_CLOSE (type 0x1d) を Initial / Handshake で送ることはできず、
    /// type 0x1c へ変換しなければならない (MUST)。変換時は Reason Phrase を
    /// 空にし (MUST)、Error Code に APPLICATION_ERROR を使う (SHOULD)。
    /// Frame Type は、エラーを引き起こしたフレーム種別が不明なため 0 にする
    /// (RFC 9000 Section 19.19)。
    fn early_application_close_frame() -> Frame {
        Frame::ConnectionClose(frame::connection_close::ConnectionClose {
            application: false,
            error_code: VarInt::try_from(
                tobi_core::error::TransportErrorCode::APPLICATION_ERROR.as_u64(),
            )
            .expect("APPLICATION_ERROR fits in 62-bit varint"),
            frame_type: Some(VarInt::from(0u8)),
            reason_phrase: Vec::new(),
        })
    }

    /// 送信パケット番号が上限 (2^62-1) に達したため接続を閉じる
    ///
    /// RFC 9000 Section 12.3: 送信に使用するパケット番号が 2^62-1 に達した場合、
    /// エンドポイントは CONNECTION_CLOSE フレームを送信せず、以降のパケットも
    /// 送信せずに接続を閉じなければならない (MUST)。Closing/Draining の猶予期間を
    /// 設けず、その場で Closed へ遷移して以降の送信をすべて止める。
    /// ピアからの追加パケットに対しては Stateless Reset (RFC 9000 Section 10.3) を
    /// 送信できる余地を残す。
    fn close_on_send_pn_limit(&mut self) {
        // 状態変化とイベント通知は 1 回だけ行う
        if self.state == ConnectionState::Closed {
            return;
        }
        self.state = ConnectionState::Closed;
        self.discard_one_rtt_outputs(false);
        self.push_event(ConnectionEvent::ConnectionClosed {
            error_code: 0,
            reason: "send packet number limit reached".into(),
            kind: ConnectionCloseKind::Internal,
        });
    }

    /// 新しいパスを開始する (クライアントのみ)
    ///
    /// 指定パスに PING フレームを送信する
    ///
    /// RFC 9000 Section 19.2: PING は ack-eliciting パケットの生成に使用する。
    /// キープアライブやパスの活性確認に使用する。
    pub fn send_ping(&mut self, path_id: PathId, now: Timestamp) -> Result<(), Error> {
        if self.state != ConnectionState::Connected {
            return Err(Error::InvalidData(
                "connection must be established to send PING".into(),
            ));
        }
        if self.one_rtt_keys.is_none() {
            return Err(Error::InvalidData("no 1-RTT keys available".into()));
        }
        self.emit_1rtt_single_frame(path_id, Frame::Ping(frame::ping::Ping), now)
            .map(|_| ())
    }

    /// ピアに ACK の送信頻度と遅延を要求する (ACK_FREQUENCY)
    ///
    /// draft-ietf-quic-ack-frequency-14 Section 4:
    /// - `ack_eliciting_threshold`: ACK を送らずに受け取れる ack-eliciting
    ///   パケットの最大数
    /// - `requested_max_ack_delay_us`: ピアに要求する max_ack_delay (マイクロ秒)
    /// - `reordering_threshold`: 再順序で即時 ACK を出す閾値
    ///
    /// ピアが `min_ack_delay` を広告していない場合は拡張を利用できないため
    /// エラーを返す。Requested Max Ack Delay が 2^14 ミリ秒以上、またはピアの
    /// `min_ack_delay` 未満の場合もエラーにする (Section 4)。
    /// 可変長整数フィールドが varint の範囲を超える場合もエラーにする。
    ///
    /// `path_id` はフレームを送信するパスを指定する。ACK_FREQUENCY 自体は
    /// 接続全体の ACK 戦略に対する要求であり、受信側はフレームを受信した
    /// パスの ACK 制御に適用する。
    ///
    /// 1-RTT 鍵を確立した接続 (Connected) でのみ送信できる。0-RTT では
    /// 拡張のパラメータを記憶してはならないため送信しない (Section 3)。
    pub fn send_ack_frequency(
        &mut self,
        path_id: PathId,
        ack_eliciting_threshold: u64,
        requested_max_ack_delay_us: u64,
        reordering_threshold: u64,
        now: Timestamp,
    ) -> Result<(), Error> {
        if self.state != ConnectionState::Connected {
            return Err(Error::InvalidData(
                "connection must be established to send ACK_FREQUENCY".into(),
            ));
        }
        if self.one_rtt_keys.is_none() {
            return Err(Error::InvalidData("no 1-RTT keys available".into()));
        }
        if self.paths.get(path_id).is_none() {
            return Err(Error::InvalidData(format!("path {path_id} not found")));
        }
        // 可変長整数フィールドは varint の範囲内でなければエンコードできない。
        if ack_eliciting_threshold > tobi_core::varint::MAX_VALUE {
            return Err(Error::InvalidData(format!(
                "ack_eliciting_threshold {ack_eliciting_threshold} exceeds the varint maximum"
            )));
        }
        if reordering_threshold > tobi_core::varint::MAX_VALUE {
            return Err(Error::InvalidData(format!(
                "reordering_threshold {reordering_threshold} exceeds the varint maximum"
            )));
        }
        // draft-ietf-quic-ack-frequency-14 Section 3:
        // ピアが min_ack_delay を広告している場合のみ ACK_FREQUENCY を送れる。
        let peer_min_ack_delay_us = self
            .peer_params
            .as_ref()
            .and_then(|params| params.min_ack_delay)
            .ok_or_else(|| Error::InvalidData("peer does not advertise min_ack_delay".into()))?;
        // draft-ietf-quic-ack-frequency-14 Section 4:
        // Requested Max Ack Delay は 2^14 ミリ秒 (16_384_000 マイクロ秒) 以上、
        // またはピアの min_ack_delay 未満の値は不正である。
        const MAX_REQUESTED_MAX_ACK_DELAY_US: u64 = 16_384_000;
        if requested_max_ack_delay_us >= MAX_REQUESTED_MAX_ACK_DELAY_US {
            return Err(Error::InvalidData(format!(
                "requested max ack delay {requested_max_ack_delay_us}us must be below 2^14 ms"
            )));
        }
        if requested_max_ack_delay_us < peer_min_ack_delay_us {
            return Err(Error::InvalidData(format!(
                "requested max ack delay {requested_max_ack_delay_us}us is below peer min_ack_delay {peer_min_ack_delay_us}us"
            )));
        }

        let sequence_number = next_varint_sequence(&mut self.ack_frequency_next_sequence_number);
        // ACK_FREQUENCY は ack-eliciting かつ輻輳制御対象のフレームである
        // (draft-ietf-quic-ack-frequency-14 Section 4)。
        // pending_frames に積んで送信経路 (pacing / 輻輳制御) を共通化する。
        // PTO 用の in-flight 記録は実際にパケットを送信した時点で行う
        // (フレームが送れなかった場合に実効値を更新しない)。
        self.streams.pending_frames.push_back(Frame::AckFrequency(
            frame::ack_frequency::AckFrequency {
                sequence_number,
                ack_eliciting_threshold: VarInt::new(ack_eliciting_threshold)
                    .expect("value fits in 62-bit varint"),
                requested_max_ack_delay: VarInt::new(requested_max_ack_delay_us)
                    .expect("value fits in 62-bit varint"),
                reordering_threshold: VarInt::new(reordering_threshold)
                    .expect("value fits in 62-bit varint"),
            },
        ));
        self.emit_packets(now)
    }

    /// ピアに即時 ACK を要求する (IMMEDIATE_ACK)
    ///
    /// draft-ietf-quic-ack-frequency-14 Section 5:
    /// ピアが `min_ack_delay` を広告している場合に送信できる。
    /// ピアは受信後、即座に ACK を返す (SHOULD)。
    pub fn send_immediate_ack(&mut self, path_id: PathId, now: Timestamp) -> Result<(), Error> {
        if self.state != ConnectionState::Connected {
            return Err(Error::InvalidData(
                "connection must be established to send IMMEDIATE_ACK".into(),
            ));
        }
        if self.one_rtt_keys.is_none() {
            return Err(Error::InvalidData("no 1-RTT keys available".into()));
        }
        if self
            .peer_params
            .as_ref()
            .and_then(|params| params.min_ack_delay)
            .is_none()
        {
            return Err(Error::InvalidData(
                "peer does not advertise min_ack_delay".into(),
            ));
        }
        // IMMEDIATE_ACK も ack-eliciting かつ輻輳制御対象である
        // (draft-ietf-quic-ack-frequency-14 Section 5)。
        self.emit_1rtt_single_frame(
            path_id,
            Frame::ImmediateAck(frame::immediate_ack::ImmediateAck),
            now,
        )
        .map(|_| ())
    }

    /// サーバーが NEW_TOKEN フレームをクライアントに送信する (RFC 9000 Section 19.7)
    ///
    /// トークンはクライアントが次回接続の Initial パケットに含めて使用する。
    /// アドレス検証のスキップに使用される。
    pub fn send_new_token(&mut self, token: Vec<u8>, now: Timestamp) -> Result<(), Error> {
        if self.role != Role::Server {
            return Err(Error::InvalidData("only server can send NEW_TOKEN".into()));
        }
        if self.state != ConnectionState::Connected {
            return Err(Error::InvalidData(
                "connection must be established to send NEW_TOKEN".into(),
            ));
        }
        if token.is_empty() {
            return Err(Error::InvalidData("token must not be empty".into()));
        }
        // NEW_TOKEN フレームをペンディングキューに追加する
        self.streams
            .pending_frames
            .push_back(Frame::NewToken(frame::new_token::NewToken { token }));
        // パケット送信をトリガーする
        self.emit_packets(now)?;
        Ok(())
    }

    /// クライアントが次回接続で使用するアドレス検証トークンを設定する (RFC 9000 Section 8.1)
    ///
    /// 前回接続で受信した NEW_TOKEN のトークンを指定する。
    /// `connect()` の前に呼び出す。
    pub fn set_address_token(&mut self, token: Vec<u8>) {
        self.address_token = token;
    }

    /// Keep-Alive の有効/無効を接続の既定値として設定する (RFC 9000 Section 10.1.2)
    ///
    /// 既存の全パスに適用し、以降に作成されるパスにも継承される。有効時は
    /// パスごとの最終送受信時刻から keep-alive 間隔が経過した時点で、その
    /// パスにだけ PING を送信する。
    ///
    /// 送信間隔は [`ConnectionConfig::keep_alive_interval`] で指定する。
    /// 未設定の場合はアイドルタイムアウトの 3/4 を使うため、アイドルタイムアウトが
    /// 無効な接続では動作しない。
    pub fn set_keep_alive(&mut self, enabled: bool, now: Timestamp) {
        self.keep_alive_enabled = enabled;
        let path_ids: Vec<PathId> = self.paths.all_paths().map(|path| path.id).collect();
        for path_id in path_ids {
            if let Some(path) = self.paths.get_mut(path_id) {
                path.set_keep_alive_enabled(enabled);
            }
            if enabled {
                self.arm_keep_alive_timer(path_id, now);
            } else {
                self.clear_keep_alive_timer(path_id);
            }
        }
    }

    /// パス単位の Keep-Alive の有効/無効を設定する (RFC 9000 Section 10.1.2)
    ///
    /// [`Self::set_keep_alive`] の既定値より優先される。使用されない待機パスを
    /// middlebox のタイムアウトで失わないよう、パスごとに有効化できる
    /// (RFC 10069 Section 5.9)。
    pub fn set_path_keep_alive(
        &mut self,
        path_id: PathId,
        enabled: bool,
        now: Timestamp,
    ) -> Result<(), Error> {
        let Some(path) = self.paths.get_mut(path_id) else {
            return Err(Error::InvalidData(format!("path {path_id} not found")));
        };
        path.set_keep_alive_enabled(enabled);
        if enabled {
            self.arm_keep_alive_timer(path_id, now);
        } else {
            self.clear_keep_alive_timer(path_id);
        }
        Ok(())
    }

    /// パス単位 keep-alive の実効間隔を返す
    ///
    /// 明示設定があればそれを優先し、無ければ
    /// `max(アイドルタイムアウト, 3 × 初期パスの実効 PTO)` の 3/4 を使う。
    /// どちらも無効な場合は `None`。
    fn effective_keep_alive_interval(&self) -> Option<Duration> {
        if let Some(interval) = self.keep_alive_interval {
            return Some(interval);
        }
        if self.idle_timeout_ms == 0 {
            return None;
        }
        let idle_duration = Duration::from_millis(self.idle_timeout_ms);
        // 従来の動作に合わせ、アイドルタイムアウトと 3 × PTO の大きい方の
        // 3/4 を間隔にする。Idle / keep-alive は初期パスの PTO を基準にする。
        // Closing / Draining と鍵関連期限は接続全体の最大 PTO
        // (RFC 10069 Section 2.6)、PathCleanup は当該パスの
        // PTO (同 Section 3.4) を使う。
        let three_pto = self.lifecycle_pto_for_path(PathId::INITIAL).mul(3);
        let timeout = if idle_duration > three_pto {
            idle_duration
        } else {
            three_pto
        };
        Some(Duration::from_micros(timeout.as_micros() * 3 / 4))
    }

    /// パスの keep-alive タイマーを設定する
    ///
    /// タイマーの期限は最終送受信時刻 + 間隔とする。送受信があるたびに
    /// 設定し直す代わりに、タイマー発火時に直近の活動を見て再設定する。
    fn arm_keep_alive_timer(&mut self, path_id: PathId, now: Timestamp) {
        let Some(interval) = self.effective_keep_alive_interval() else {
            return;
        };
        let Some(path) = self.paths.get(path_id) else {
            return;
        };
        if !path.keep_alive_enabled() {
            return;
        }
        // Pending / Validating / Abandoning のパスには送らない。検証が完了して
        // Active になった時点で改めて設定する。
        if !path.is_usable() {
            return;
        }
        let last_activity = path.last_activity_at().unwrap_or(now);
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::KeepAlive { path_id },
            deadline: last_activity.add(interval),
        });
    }

    /// keep-alive が有効な全パスのタイマーを設定する
    ///
    /// ハンドシェイク完了時と keep-alive の設定変更時に呼ぶ。
    fn arm_all_keep_alive_timers(&mut self, now: Timestamp) {
        let path_ids = self.paths.keep_alive_path_ids();
        for path_id in path_ids {
            self.arm_keep_alive_timer(path_id, now);
        }
    }

    /// パスの keep-alive タイマーを取り消す
    fn clear_keep_alive_timer(&mut self, path_id: PathId) {
        self.output_queue.push_back(ConnectionOutput::ClearTimer {
            id: TimerId::KeepAlive { path_id },
        });
    }

    /// パスの到達性確認を開始する (RFC 10069 Section 5.9)
    ///
    /// 未使用のパスを能動利用へ切り替える前に PATH_CHALLENGE を送り、
    /// PATH_RESPONSE の受信を待つ。パス自体は Active のまま維持し、状態を
    /// Validating に戻さない (待機パスの到達性を確認するだけであり、
    /// 切り替えの可否は PathController が PATH_RESPONSE 受信後に判断する)。
    fn start_path_probe(&mut self, path_id: PathId, now: Timestamp) -> Result<(), Error> {
        let Some(path) = self.paths.get(path_id) else {
            return Ok(());
        };
        // PATH_CHALLENGE はパスに紐づくピア CID で送る必要がある
        // (RFC 10069 Section 3.1)。CID が未確定なら送れない。
        if !matches!(path.state, PathState::Active) || path.peer_cid.is_none() {
            return Ok(());
        }
        let mut challenge_data = [0u8; 8];
        aws_lc_rs::rand::fill(&mut challenge_data)
            .map_err(|_| Error::InvalidData("failed to generate random bytes".into()))?;
        let path = self.paths.get_mut(path_id).expect("path existence checked");
        path.validation.restart();
        path.validation.request_challenge(challenge_data);
        self.pending_path_probes.insert(path_id);
        self.emit_1rtt_path_challenge(path_id, challenge_data, now)?;
        let pto = self.path_validation_pto(path_id);
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::PathValidation { path_id },
            deadline: now + pto,
        });
        Ok(())
    }

    // --- PathController API ---

    /// ネットワークイベントを受け取り、PathController に渡す
    ///
    /// I/O 層 (tobi_platform) から NetworkMonitor のイベントを受け取り、
    /// PathController が判断したアクションを実行する。
    ///
    /// I/O 層が渡すのは
    /// [`PathControlEvent::NetworkInterfaceUp`] /
    /// [`PathControlEvent::NetworkInterfaceDown`] /
    /// [`PathControlEvent::NetworkAddressChanged`] の 3 種類である。
    ///
    /// 内部イベント ([`PathControlEvent::ObservedAddressReceived`] など) も
    /// 渡せる。`Connection` の内部状態を変えるイベントを、I/O 層を持たない
    /// 統合テストなどから注入するために使う。
    ///
    /// [`PathControlEvent::PathOpenSucceeded`] /
    /// [`PathControlEvent::PathOpenFailed`] は `PathAction::OpenPath` の実行結果を
    /// 伝える `Connection` 内部専用のイベントであり、外部から渡してはならない。
    /// 誤って渡された場合は PathController へ通知するが、返されたアクションは
    /// 実行せず、警告ログを出して破棄する。
    pub fn on_network_event(&mut self, event: PathControlEvent, now: Timestamp) {
        if self.state != ConnectionState::Connected {
            return;
        }
        // PathOpenSucceeded / PathOpenFailed は Connection 内部専用である。
        // 外部から渡された場合にアクションまで実行すると、開設失敗を受けて
        // 同じ OpenPath を返す実装で開設と失敗が繰り返される。対応付けの
        // 更新だけを行い、アクションは破棄する。
        if matches!(
            &event,
            PathControlEvent::PathOpenSucceeded { .. } | PathControlEvent::PathOpenFailed { .. }
        ) {
            tracing::warn!(
                event = ?event,
                "path open result event passed to on_network_event; discarding its actions"
            );
            let actions = self.invoke_path_controller(&event, now);
            Self::discard_result_event_actions(&event, actions);
            return;
        }
        let actions = self.invoke_path_controller(&event, now);
        self.execute_path_actions(actions, now);
    }

    /// パスメトリクスの更新を PathController に通知する
    ///
    /// RTT 推定が動いた時点で `PathControlEvent::PathMetricsUpdated` を発行し、
    /// 返されたアクションを既存経路 (`Connection::execute_path_actions`) で
    /// 適用する。`DefaultPathController` はこのイベントで閾値判定を行い、
    /// 劣化したパスの降格や Handover の切り替えを行う。パケット受信ごとに
    /// 発行せず、推定値が動いたときに限る。
    fn notify_metrics_updated_if_changed(
        &mut self,
        path_id: PathId,
        before_smoothed_rtt: Option<tobi_core::time::Duration>,
        now: Timestamp,
    ) {
        if self.state != ConnectionState::Connected {
            return;
        }
        let after_smoothed_rtt = self.paths.get(path_id).map(|p| p.rtt.smoothed_rtt);
        if after_smoothed_rtt.is_none() || after_smoothed_rtt == before_smoothed_rtt {
            return;
        }
        let event = PathControlEvent::PathMetricsUpdated { path_id };
        let actions = self.invoke_path_controller(&event, now);
        self.execute_path_actions(actions, now);
    }

    /// PathController を呼び出してアクションを取得する
    fn invoke_path_controller(
        &mut self,
        event: &PathControlEvent,
        now: Timestamp,
    ) -> Vec<PathAction> {
        let metrics = self.paths.collect_metrics();
        let ctx = PathControlCtx {
            path_metrics: &metrics,
            current_path_count: self.paths.active_path_count(),
            policy: &self.multipath_policy,
            now,
            keep_alive_interval: self.effective_keep_alive_interval(),
        };
        self.path_controller.on_event(event, &ctx)
    }

    /// PathController が返したアクションを実行する
    ///
    /// アクションは渡された順に実行する。`OpenPath` を実行したときだけ
    /// PathController へ結果を通知し、成功時は
    /// [`PathControlEvent::PathOpenSucceeded`]、失敗時は
    /// [`PathControlEvent::PathOpenFailed`] を渡す。公開 API から開いたパスは
    /// この経路を通らないため通知しない。
    ///
    /// 結果通知で返されたアクションは実行せず、警告ログを出して破棄する
    /// (イベントの契約は [`PathControlEvent::PathOpenSucceeded`] を参照)。
    ///
    /// 1 回の呼び出しで処理するアクション数は
    /// `2 * max(max_paths, 現在のアクティブパス数) + 余裕` を上限とし、
    /// 超えた分は警告ログを出して破棄する。`AbandonPath` の実行は
    /// `abandon_path_inner` 経由でこの関数を再入させるため、再入深度にも
    /// 上限を設け、超えた場合は警告ログを出して何もしない。
    fn execute_path_actions(&mut self, actions: Vec<PathAction>, now: Timestamp) {
        if self.path_action_depth >= MAX_PATH_ACTION_REENTRANCY_DEPTH {
            tracing::warn!(
                depth = self.path_action_depth,
                limit = MAX_PATH_ACTION_REENTRANCY_DEPTH,
                actions = actions.len(),
                "path action reentrancy limit reached; dropping the actions"
            );
            return;
        }
        self.path_action_depth += 1;
        self.execute_path_actions_inner(actions, now);
        self.path_action_depth -= 1;
    }

    /// アクション実行の本体
    ///
    /// 再入深度の管理を 1 箇所に閉じ込めるため、[`Self::execute_path_actions`]
    /// からだけ呼ぶ。
    fn execute_path_actions_inner(&mut self, actions: Vec<PathAction>, now: Timestamp) {
        let limit = self.max_path_actions_per_execution();
        let total = actions.len();
        for (processed, action) in actions.into_iter().enumerate() {
            if processed >= limit {
                tracing::warn!(
                    limit,
                    dropped_actions = total - processed,
                    "path action execution limit reached; dropping the remaining actions"
                );
                break;
            }
            match action {
                PathAction::OpenPath {
                    local_addr,
                    remote_addr,
                } => {
                    // PathController が指定したアドレスで新パスを開く
                    // remote_addr がダミー (port == 0) の場合は初期パスから継承する
                    let ra = if remote_addr.port() != 0 {
                        Some(remote_addr)
                    } else {
                        None
                    };
                    match self.open_path_with_addrs(now, Some(local_addr), ra) {
                        Ok(path_id) => {
                            let event = PathControlEvent::PathOpenSucceeded {
                                path_id,
                                local_addr,
                            };
                            let returned = self.invoke_path_controller(&event, now);
                            Self::discard_result_event_actions(&event, returned);
                        }
                        Err(e) => {
                            tracing::debug!("PathController OpenPath failed: {e}");
                            let event = PathControlEvent::PathOpenFailed { local_addr };
                            let returned = self.invoke_path_controller(&event, now);
                            Self::discard_result_event_actions(&event, returned);
                        }
                    }
                }
                PathAction::AbandonPath {
                    path_id,
                    error_code,
                } => {
                    // 通知は `Connection::abandon_path_inner` が行う
                    if let Err(e) = self.abandon_path_inner(path_id, error_code, now) {
                        tracing::debug!("PathController AbandonPath failed: {e}");
                    }
                }
                PathAction::SetStatus { path_id, status } => {
                    if let Some(path) = self.paths.get_mut(path_id) {
                        path.status = status;
                        // PATH_STATUS フレームを送信する
                        let seq = next_varint_sequence(&mut path.status_seq_send);
                        let frame = match status {
                            PathStatus::Available => Frame::PathStatusAvailable(
                                frame::path_status::PathStatusAvailable {
                                    path_id: path_id.0,
                                    path_status_sequence_number: seq,
                                },
                            ),
                            PathStatus::Backup => {
                                Frame::PathStatusBackup(frame::path_status::PathStatusBackup {
                                    path_id: path_id.0,
                                    path_status_sequence_number: seq,
                                })
                            }
                        };
                        self.streams.pending_frames.push_back(frame);
                        // ローカル状態の変更をアプリへ通知する
                        self.push_event(ConnectionEvent::PathStatusChanged { path_id, status });
                    }
                }
                PathAction::SetKeepAlive { path_id, enabled } => {
                    if self.paths.get(path_id).is_none() {
                        tracing::debug!("PathController SetKeepAlive: path {path_id} not found");
                        continue;
                    }
                    if let Some(path) = self.paths.get_mut(path_id) {
                        path.set_keep_alive_enabled(enabled);
                    }
                    if enabled {
                        self.arm_keep_alive_timer(path_id, now);
                    } else {
                        self.clear_keep_alive_timer(path_id);
                    }
                }
                PathAction::ProbePath { path_id } => {
                    // 昇格前の到達性確認: PATH_CHALLENGE を送り、PATH_RESPONSE を
                    // 待ってから PathController が状態を切り替える
                    // (RFC 10069 Section 5.9)。
                    if let Err(e) = self.start_path_probe(path_id, now) {
                        tracing::debug!("PathController ProbePath failed: {e}");
                    }
                }
            }
        }
    }

    /// 1 回のアクション実行で処理する数の上限を返す
    ///
    /// `MultipathPolicy::max_paths` の値には上限が無い。Aggregate モードの
    /// `aggregate_actions` は劣化パス 1 本につき 2 アクション (`SetStatus` と
    /// `SetKeepAlive`) を返すため、固定値では `max_paths` を大きくする構成で
    /// 正当なアクションを切り捨てる。ポリシーから導出し、余裕を足した値を
    /// 上限にする。
    ///
    /// 公開 API の [`Self::open_path`] / [`Self::open_path_with_addrs`] は
    /// `max_paths` を検査しないため、`max_paths` を超えるパスを開ける。
    /// その場合も実際のアクティブパス数を考慮する。Aggregate の判定は
    /// 劣化・回復したパス 1 本につき最大 2 アクション (`SetStatus` と
    /// `SetKeepAlive`) を返し、到達性確認では `ProbePath` 1 アクションを
    /// 返すため、パス 1 本につき 2 アクションを見込めば正当なアクションを
    /// 切り捨てない。
    fn max_path_actions_per_execution(&self) -> usize {
        let path_count = self
            .multipath_policy
            .max_paths
            .max(self.paths.active_path_count());
        path_count
            .saturating_mul(2)
            .saturating_add(PATH_ACTION_LIMIT_MARGIN)
    }

    /// パス開設結果の通知で返されたアクションを破棄する
    ///
    /// このアクションを実行すると、開設失敗を受けて同じ `OpenPath` を返す
    /// 実装では失敗と再試行が繰り返され、接続の駆動処理が戻らなくなる。
    /// そのため警告ログを出して破棄する。
    fn discard_result_event_actions(event: &PathControlEvent, actions: Vec<PathAction>) {
        if actions.is_empty() {
            return;
        }
        tracing::warn!(
            event = ?event,
            actions = ?actions,
            "PathController returned actions for a path open result; discarding them"
        );
    }

    // --- パス管理 API ---

    /// RFC 10069 Section 3.1 に基づき、
    /// 新しいパスを作成し PATH_CHALLENGE を送信キューに追加する。
    /// PathValidated イベントで検証完了が通知される。
    ///
    /// ピアが `disable_active_migration` を通知している場合でも、同じローカル
    /// アドレスからのパス追加と、ハンドシェイクアドレス以外へのパス追加は許可する。
    /// 禁止されるのはハンドシェイクで使ったピアアドレスへ新しいローカルアドレスから
    /// 送信するパスだけである (RFC 9000 Section 18.2)。
    ///
    /// このメソッドは初期パスのアドレスをそのまま新パスに継承する。
    /// 独自のローカル / リモートアドレスを指定する場合は [`Self::open_path_with_addrs`]
    /// を使用する。
    ///
    /// この API は PathController の `OpenPath` アクションを経由しないため、
    /// 開設結果の [`PathControlEvent::PathOpenSucceeded`] /
    /// [`PathControlEvent::PathOpenFailed`] は通知しない。
    pub fn open_path(&mut self, now: Timestamp) -> Result<PathId, Error> {
        self.open_path_inner(now, None, None)
    }

    /// アドレスを明示指定して新しいパスを作成する
    ///
    /// `local_addr` / `remote_addr` のいずれかが `Some` の場合、その値が新パスに
    /// 設定される。`None` の場合は初期パスの値を継承する。Multipath の 4-tuple を
    /// 変更しないシングルソケット構成では両方 `None` を指定する。
    ///
    /// この API は PathController の `OpenPath` アクションを経由しないため、
    /// 開設結果の [`PathControlEvent::PathOpenSucceeded`] /
    /// [`PathControlEvent::PathOpenFailed`] は通知しない。
    pub fn open_path_with_addrs(
        &mut self,
        now: Timestamp,
        local_addr: Option<std::net::SocketAddr>,
        remote_addr: Option<std::net::SocketAddr>,
    ) -> Result<PathId, Error> {
        self.open_path_inner(now, local_addr, remote_addr)
    }

    /// ピアが通知したパスの preference を返す
    ///
    /// RFC 10069 Section 3.3 は両端点の preference が独立で
    /// あると定める。ピアの通知はローカルのパス状態を変更しないため、参照用に
    /// この API で取得する。通知が無い場合は `None` を返す。
    pub fn peer_path_status(&self, path_id: PathId) -> Option<PathStatus> {
        self.paths.get(path_id).and_then(|p| p.peer_status)
    }

    /// ピアが通知した preferred_address を返す (RFC 9000 Section 18.2)
    ///
    /// ピアが通知していない場合やハンドシェイク未完了の場合は `None` を返す。
    pub fn peer_preferred_address(&self) -> Option<&tobi_core::transport_params::PreferredAddress> {
        self.peer_params
            .as_ref()
            .and_then(|p| p.preferred_address.as_ref())
    }

    /// ピアが `disable_active_migration` を通知したかを返す (RFC 9000 Section 18.2)
    pub fn peer_disable_active_migration(&self) -> bool {
        self.peer_params
            .as_ref()
            .is_some_and(|p| p.disable_active_migration)
    }

    /// 指定の 4-tuple への送信が `disable_active_migration` で禁止されるかを判定する
    ///
    /// RFC 9000 Section 18.2: `disable_active_migration` は「ハンドシェイクで
    /// 使ったピアアドレスへ、新しいローカルアドレスから送信すること」を禁止する。
    /// それ以外 (同じローカルアドレスからの送信、preferred_address など
    /// 別のピアアドレスへの送信) は禁止しない。preferred_address に従って
    /// 移行した後も禁止しない (RFC 9000 Section 9.6)。
    fn active_migration_forbidden(
        &self,
        candidate_local: std::net::SocketAddr,
        candidate_remote: std::net::SocketAddr,
    ) -> bool {
        self.role == Role::Client
            && self.peer_disable_active_migration()
            && !self.acted_on_preferred_address
            && candidate_remote == self.handshake_remote_addr
            && candidate_local != self.handshake_local_addr
    }

    /// 初期パス (Path ID 0) を新しい 4-tuple へ移行する (クライアントのみ)
    ///
    /// RFC 9000 Section 9: ハンドシェイク確定後、クライアントはローカルと
    /// リモートのアドレスを変更して接続を移行できる。このメソッドはパスの
    /// 4-tuple をすぐには変更せず、候補アドレスへ PATH_CHALLENGE を送って
    /// 検証を開始する。検証に成功したら 4-tuple と送信先 CID を新しい値に
    /// 確定し、[`ConnectionEvent::PathValidated`] (path_id = 0) を通知する。
    /// 検証に失敗した場合は元の 4-tuple と CID を維持したまま
    /// [`ConnectionEvent::PathValidationFailed`] を通知する
    /// (RFC 9000 Section 9.3 / 9.6.1 と同じ扱い)。
    ///
    /// `local_addr` が `None` の場合は現在のローカルアドレスを維持する。
    /// `remote_addr` が `None` の場合は現在のリモートアドレスを維持する。
    /// 両方が現在の値と同じ場合はエラーを返す。
    ///
    /// ピアが `disable_active_migration` を通知している場合、ハンドシェイク
    /// アドレス (リモート) へ新しいローカルアドレスから送信することはできない。
    /// preferred_address に従って移行済みの場合はこの制限を受けない。
    ///
    /// 移行の検証が完了するまでの間、元の 4-tuple での送受信は継続できる。
    ///
    /// 送信先 CID には、そのパスで未使用の最小シーケンス番号の CID を予約して
    /// 使う (RFC 9000 Section 9.5)。検証パケットの DCID にはこの候補 CID を使い、
    /// 元の 4-tuple で使っている CID を移行先の宛先アドレスへ再利用しない。
    /// 検証中に Retire Prior To の増加で候補が退役した場合は、未使用の CID へ
    /// 置き換える。
    ///
    /// # エラー
    ///
    /// 次の場合は [`Error::InvalidData`] を返し、移行を開始しない。
    ///
    /// - 接続が確立していない、ハンドシェイクが確定していない、クライアント以外
    /// - 同じ初期パスの移行がすでに検証中
    /// - `local_addr` と `remote_addr` の両方が現在の値と同じ
    /// - ピアが `disable_active_migration` でハンドシェイクアドレスへの移行を
    ///   禁止している
    /// - 移行先に使える未使用のピア CID が無い
    pub fn migrate(
        &mut self,
        now: Timestamp,
        local_addr: Option<std::net::SocketAddr>,
        remote_addr: Option<std::net::SocketAddr>,
    ) -> Result<(), Error> {
        if self.role != Role::Client {
            return Err(Error::InvalidData(
                "only client can initiate migration".into(),
            ));
        }
        if self.state != ConnectionState::Connected {
            return Err(Error::InvalidData(
                "connection must be established before migrating".into(),
            ));
        }
        if !self.is_handshake_confirmed() {
            // RFC 9000 Section 9: ハンドシェイク確定前に移行を開始してはならない
            return Err(Error::InvalidData(
                "connection migration requires a confirmed handshake".into(),
            ));
        }
        if self.pending_migrations.contains_key(&PathId::INITIAL) {
            return Err(Error::InvalidData("migration already in progress".into()));
        }

        let current_local = self.paths.initial_path().local_addr;
        let current_remote = self.paths.initial_path().remote_addr;
        let candidate_local = local_addr.unwrap_or(current_local);
        let candidate_remote = remote_addr.unwrap_or(current_remote);
        if candidate_local == current_local && candidate_remote == current_remote {
            return Err(Error::InvalidData(
                "migration target equals current 4-tuple".into(),
            ));
        }
        if self.active_migration_forbidden(candidate_local, candidate_remote) {
            return Err(Error::InvalidData(
                "peer has set disable_active_migration for the handshake address".into(),
            ));
        }

        // 移行先の宛先アドレスには、まだどの宛先アドレスにも使っていないピア CID を
        // 使う (RFC 9000 Section 9.5 の MUST NOT)。未使用の CID が無い場合は現在の
        // CID で移行を続けず、エラーを返す。ピアは移行に備えて未使用の CID を
        // 用意することが SHOULD であり (RFC 9000 Section 5.1.1 / Section 9.5)、
        // 同じ CID を複数の宛先アドレスへ使うと linkability が生じるため。
        let Some(candidate_peer_cid) = self.select_peer_cid_for_migration() else {
            return Err(Error::InvalidData(
                "no unused peer connection ID available for migration".into(),
            ));
        };
        let original_remote_addr = current_remote;
        let original_local_addr = current_local;
        let original_peer_cid = self.paths.initial_path().peer_cid.clone();

        // 候補 CID を予約した後に失敗した場合は、送信前であれば未使用へ戻す。
        // ここからの失敗は乱数生成と出力キューの準備に限られ、検証パケットは
        // まだ送信されていない。
        let mut challenge_data = [0u8; 8];
        if aws_lc_rs::rand::fill(&mut challenge_data).is_err() {
            self.release_peer_cid_reservation(PathId::INITIAL, &candidate_peer_cid);
            return Err(Error::InvalidData("failed to generate random bytes".into()));
        }
        // RFC 9000 Section 9.4: IP アドレスが変わる移行では CC と RTT をリセットする。
        // ポートだけの変更 (NAT リバインディング相当) ではリセットしない。
        let ip_changed = candidate_local.ip() != current_local.ip()
            || candidate_remote.ip() != current_remote.ip();
        self.paths.initial_path_mut().migration_reset_pending = ip_changed;
        self.paths.initial_path_mut().validation.restart();
        self.paths
            .initial_path_mut()
            .validation
            .request_challenge(challenge_data);

        self.pending_migrations.insert(
            PathId::INITIAL,
            PendingMigration {
                candidate_remote_addr: candidate_remote,
                candidate_local_addr: Some(candidate_local),
                candidate_peer_cid,
                candidate_probe_sent: false,
                original_remote_addr,
                original_local_addr,
                original_peer_cid,
                from_preferred_address: false,
            },
        );

        // パスの 4-tuple は変更せず候補アドレスへ PATH_CHALLENGE を送る。
        // ローカルアドレスの上書きにより I/O 層は移行先ソケットを選ぶ。
        if let Err(error) = self.emit_1rtt_path_challenge_to(
            PathId::INITIAL,
            challenge_data,
            Some(candidate_remote),
            Some(candidate_local),
            now,
        ) {
            // 検証パケットは送信していないため、予約した CID を解放して取り消す。
            self.discard_pending_migration(PathId::INITIAL);
            return Err(error);
        }

        let pto = self.path_validation_pto(PathId::INITIAL);
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::PathValidation {
                path_id: PathId::INITIAL,
            },
            deadline: now + pto,
        });
        Ok(())
    }

    /// 移行後の送信先に使える未使用のピア CID を予約する
    ///
    /// Path ID 0 用に発行済みで、まだどの宛先アドレスにも送信していない CID のうち
    /// 最小のシーケンス番号のものを予約し、使用済みとして記録する。返した CID は
    /// `Connection::pending_migrations` の候補として保持し、検証パケットの DCID に
    /// 使う。
    ///
    /// RFC 9000 Section 9.5: 複数のローカル / 宛先アドレスへの送信で同じ CID を
    /// 再利用してはならない (MUST NOT)。未使用の CID が無い場合は `None` を返し、
    /// 呼び出し側は移行を失敗させる。送信前に取り消した場合は
    /// `Connection::release_peer_cid_reservation` で未使用へ戻す。
    fn select_peer_cid_for_migration(&mut self) -> Option<ConnectionId> {
        self.take_unused_peer_cid_for_path(PathId::INITIAL)
    }

    /// 自身が通知する preferred_address を返す (RFC 9000 Section 18.2)
    ///
    /// [`Self::set_preferred_address`] で設定した値を返す。サーバーは
    /// ハンドシェイク応答の transport parameter をエンコードする前にこの値を
    /// 参照し、`preferred_address` を含める必要がある。
    pub fn preferred_address(&self) -> Option<&tobi_core::transport_params::PreferredAddress> {
        self.local_params.preferred_address.as_ref()
    }

    /// サーバーの preferred_address を設定し、その CID を経路解決に登録する
    ///
    /// RFC 9000 Section 18.2: サーバーはハンドシェイク応答で preferred_address を
    /// 通知する。クライアントは通知された CID を移行後の送信先 CID として使うため、
    /// サーバー側はその CID を自身のローカル CID として解決できる必要がある。
    ///
    /// このメソッドは、まだ通知していない接続に対して
    /// *path 0* 用の CID と Stateless Reset Token を新規発行し、
    /// `preferred_address` トランスポートパラメータとして設定する。
    /// ハンドシェイク開始前 (サーバー接続の生成直後) に呼び出すこと。
    ///
    /// 戻り値は設定した preferred_address。
    pub fn set_preferred_address(
        &mut self,
        ipv4_addr: std::net::Ipv4Addr,
        ipv4_port: u16,
        ipv6_addr: std::net::Ipv6Addr,
        ipv6_port: u16,
    ) -> Result<tobi_core::transport_params::PreferredAddress, Error> {
        // path 0 用の CID を発行する
        let (_, connection_id, stateless_reset_token) = self.generate_new_cid(PathId::INITIAL)?;
        self.set_preferred_address_with_cid(
            ipv4_addr,
            ipv4_port,
            ipv6_addr,
            ipv6_port,
            connection_id,
            stateless_reset_token,
        )
    }

    /// サーバーの preferred_address を CID と Stateless Reset Token を指定して設定する
    ///
    /// 呼び出し側が CID を事前に生成している場合に使う。CID は path 0 の
    /// ローカル CID として経路解決に登録されるため、クライアントが移行後に
    /// その CID を宛先に使ってもサーバーはパケットを復号できる。
    ///
    /// ハンドシェイク開始前 (サーバー接続の生成直後) に呼び出すこと。
    pub fn set_preferred_address_with_cid(
        &mut self,
        ipv4_addr: std::net::Ipv4Addr,
        ipv4_port: u16,
        ipv6_addr: std::net::Ipv6Addr,
        ipv6_port: u16,
        connection_id: ConnectionId,
        stateless_reset_token: [u8; 16],
    ) -> Result<tobi_core::transport_params::PreferredAddress, Error> {
        if self.role != Role::Server {
            return Err(Error::InvalidData(
                "only server can set preferred_address".into(),
            ));
        }
        if self.state != ConnectionState::Handshaking && self.state != ConnectionState::Idle {
            return Err(Error::InvalidData(
                "preferred_address must be set before the handshake completes".into(),
            ));
        }

        let preferred = tobi_core::transport_params::PreferredAddress {
            ipv4_address: ipv4_addr.octets(),
            ipv4_port,
            ipv6_address: ipv6_addr.octets(),
            ipv6_port,
            connection_id,
            stateless_reset_token,
        };
        // path 0 のローカル CID として登録し、受信パケットの経路解決に使えるようにする
        let seq = self
            .paths
            .get(PathId::INITIAL)
            .map_or(0, |p| p.next_local_cid_seq);
        if let Some(path) = self.paths.get_mut(PathId::INITIAL) {
            path.next_local_cid_seq = seq.saturating_add(1);
        }
        self.local_cid_table
            .insert((PathId::INITIAL.0, seq), preferred.connection_id.clone());
        self.paths
            .register_cid(preferred.connection_id.clone(), PathId::INITIAL);
        self.output_queue
            .push_back(ConnectionOutput::RegisterLocalCid {
                cid: preferred.connection_id.clone(),
                path_id: PathId::INITIAL,
            });
        self.local_params.preferred_address = Some(preferred.clone());
        Ok(preferred)
    }

    /// サーバーの preferred_address へ移行する (クライアントのみ)
    ///
    /// RFC 9000 Section 9.6.1: ハンドシェイク確定後、クライアントは
    /// preferred_address のアドレスを選びパス検証を開始する。検証に成功したら
    /// 以降のパケットを新しいアドレスと CID で送信し、元のアドレスの使用を
    /// 止める (SHOULD)。検証に失敗した場合は元のアドレスを使い続ける (MUST)。
    ///
    /// RFC 10069 Section 2.2: preferred_address の使用は
    /// パス ID を変更しない migration として扱うため、対象は常に初期パス (path 0)。
    /// 検証が完了するまでパスの 4-tuple と送信先 CID は変更せず、
    /// PATH_CHALLENGE だけを候補アドレスへ送る。検証成功時に新しいアドレスと
    /// CID を確定し [`ConnectionEvent::PathValidated`] を通知する。
    ///
    /// 検証がタイムアウトした場合は元のアドレスと CID を維持したまま
    /// [`ConnectionEvent::PathValidationFailed`] を通知する。
    ///
    /// 通知されたアドレスのうち、初期パスのリモートアドレスと同じアドレス
    /// ファミリのものを選ぶ。同じファミリのアドレスが通知されていない場合は
    /// port が 0 でない側を使う。
    ///
    /// preferred_address の CID は、未使用であるか、同じ preferred_address への
    /// 検証パケットでだけ使用済みでなければならない (RFC 9000 Section 9.5)。
    /// 移行の検証パケットはこの CID を DCID に使う。同じ 4-tuple への再試行では
    /// 再利用でき、検証の開始前に送信せずに取り消した場合は未使用へ戻る。
    ///
    /// # エラー
    ///
    /// 次の場合は [`Error::InvalidData`] を返し、移行を開始しない。
    ///
    /// - 接続が確立していない、クライアント以外
    /// - 同じ初期パスの移行がすでに検証中
    /// - ピアが preferred_address を広告していない、または使用可能なアドレスが無い
    /// - preferred_address の CID が退役済み (RFC 9000 Section 5.1.2)
    /// - preferred_address の CID を別の 4-tuple への送信で使用済み
    pub fn migrate_to_preferred_address(&mut self, now: Timestamp) -> Result<(), Error> {
        if self.role != Role::Client {
            return Err(Error::InvalidData(
                "only client can migrate to preferred_address".into(),
            ));
        }
        if self.state != ConnectionState::Connected {
            return Err(Error::InvalidData(
                "connection must be established before migrating".into(),
            ));
        }
        // 同一パスで二重に移行を開始しない
        if self.pending_migrations.contains_key(&PathId::INITIAL) {
            return Err(Error::InvalidData(
                "preferred_address migration already in progress".into(),
            ));
        }

        let (candidate_remote_addr, candidate_cid) = {
            let pa = self
                .peer_params
                .as_ref()
                .and_then(|p| p.preferred_address.as_ref())
                .ok_or_else(|| {
                    Error::InvalidData("peer did not advertise preferred_address".into())
                })?;
            let reference = self.paths.initial_path().remote_addr;
            (
                resolve_preferred_addr(pa, reference),
                pa.connection_id.clone(),
            )
        };
        if candidate_remote_addr.port() == 0 {
            return Err(Error::InvalidData(
                "preferred_address has no usable address".into(),
            ));
        }
        // RFC 9000 Section 5.1.2: 退役した CID を使い続けてはならない。
        // Retire Prior To で preferred_address の CID が退役している場合は、
        // その CID を移行先に使わない。
        if !self.is_active_peer_cid(PathId::INITIAL, &candidate_cid) {
            return Err(Error::InvalidData(
                "preferred_address connection ID has been retired".into(),
            ));
        }
        // RFC 9000 Section 9.5: 既にほかの宛先アドレスへ送信した CID は、移行先の
        // DCID に再利用してはならない (MUST NOT)。同じ preferred_address への
        // 再試行では、前回の検証パケットを送った 4-tuple と同じ 4-tuple に限って
        // 再利用を許可する。同じ宛先アドレスへの再送は禁止されていない。
        let candidate_local_addr = self.paths.initial_path().local_addr;
        if !self.is_peer_cid_available_for(
            PathId::INITIAL,
            &candidate_cid,
            candidate_remote_addr,
            candidate_local_addr,
        ) {
            return Err(Error::InvalidData(
                "preferred_address connection ID has already been used".into(),
            ));
        }
        // preferred_address の CID はこの移行で送信先に使うため予約として
        // 使用済みにする (RFC 9000 Section 9.5)。検証パケットを一度も送らずに
        // 取り消した場合は未使用へ戻す。
        self.mark_peer_cid_used(PathId::INITIAL, &candidate_cid);

        let original_remote_addr = self.paths.initial_path().remote_addr;
        let original_local_addr = self.paths.initial_path().local_addr;
        let original_peer_cid = self.paths.initial_path().peer_cid.clone();

        // 検証用の PATH_CHALLENGE を生成する。失敗した場合は検証パケットを
        // 送っていないため、予約した CID を解放してから戻す。
        let mut challenge_data = [0u8; 8];
        if aws_lc_rs::rand::fill(&mut challenge_data).is_err() {
            self.release_peer_cid_reservation(PathId::INITIAL, &candidate_cid);
            return Err(Error::InvalidData("failed to generate random bytes".into()));
        }
        self.paths.initial_path_mut().validation.restart();
        self.paths
            .initial_path_mut()
            .validation
            .request_challenge(challenge_data);

        self.pending_migrations.insert(
            PathId::INITIAL,
            PendingMigration {
                candidate_remote_addr,
                candidate_local_addr: None,
                candidate_peer_cid: candidate_cid,
                candidate_probe_sent: false,
                original_remote_addr,
                original_local_addr,
                original_peer_cid,
                from_preferred_address: true,
            },
        );

        // パスの 4-tuple を変更せず候補アドレスへ PATH_CHALLENGE を送る
        if let Err(error) = self.emit_1rtt_path_challenge_to(
            PathId::INITIAL,
            challenge_data,
            Some(candidate_remote_addr),
            None,
            now,
        ) {
            // 検証パケットは送信していないため、予約した CID を解放して取り消す。
            self.discard_pending_migration(PathId::INITIAL);
            return Err(error);
        }

        // 検証タイマーを設定する (PTO ベース)
        let pto = self.path_validation_pto(PathId::INITIAL);
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::PathValidation {
                path_id: PathId::INITIAL,
            },
            deadline: now + pto,
        });
        Ok(())
    }

    /// 未開設の間に受信したピアの PATH_STATUS を、生成したパスへ反映する
    ///
    /// RFC 10069 Section 4.3: 未使用の path ID に対する
    /// PATH_STATUS を受け付け、パスを開いた時点で反映する。同じ path ID に
    /// ついて受信済み以下の Path Status Sequence Number は無視されるため
    /// (`record_pending_peer_status` と `process_path_status` の比較)、
    /// 開設前後をまたぐ古い通知で新しい状態を上書きしない。
    ///
    /// クライアントの `open_path_inner` とサーバーの認証済みパケット受信に
    /// よる `create_path_for_peer` の両経路から、パス生成直後に呼ぶ。
    /// ピアの希望はローカルの状態 (`Path::status`) を上書きしない
    /// (RFC 10069 Section 3.3)。
    fn apply_pending_peer_path_status(&mut self, path_id: PathId) {
        if let Some((seq, status)) = self.paths.take_pending_peer_status(path_id) {
            // `process_path_status` はパス存在時に反映し、不在時に保持し直す。
            self.process_path_status(path_id, seq, status);
        }
    }

    /// `open_path` の内部実装
    ///
    /// `PathManager::open_path()` が成功した後に失敗した場合は、作成したパスを
    /// 内部で廃棄してからエラーを返す。このとき PathController へ
    /// `PathAbandoned` は通知しない。PathController 経由の開設では、開設結果を
    /// 呼び出し側 (`execute_path_actions`) が
    /// [`PathControlEvent::PathOpenFailed`] で通知する。公開 API から開いた場合は
    /// 通知しない。
    ///
    /// `PathOpened` の出力は、パス固有のデータグラムを積む直前に発行する。
    /// それより前の失敗では `PathOpened` も `PathClosed` も通知しない。
    /// `PathOpened` の発行後に失敗した場合は、I/O 層には `PathOpened` の後に
    /// `PathClosed` が届く。呼び出し元へのエラーと I/O 層のパスライフサイクルは
    /// 独立に扱う。
    fn open_path_inner(
        &mut self,
        now: Timestamp,
        local_addr: Option<std::net::SocketAddr>,
        remote_addr: Option<std::net::SocketAddr>,
    ) -> Result<PathId, Error> {
        if self.role != Role::Client {
            return Err(Error::InvalidData(
                "only client can initiate new paths".into(),
            ));
        }
        if self.state != ConnectionState::Connected {
            return Err(Error::InvalidData(
                "connection must be established before opening paths".into(),
            ));
        }
        // パス起動のレート制限 (RFC 10069 Section 7.2)
        // 前回のパス起動から PTO 未満の間隔での起動を拒否する
        if let Some(last_open) = self.last_path_open_time {
            let pto = self.paths.initial_path().rtt.pto();
            if now.saturating_duration_since(last_open) < pto {
                return Err(Error::InvalidData(
                    "path open rate limited: wait at least one PTO".into(),
                ));
            }
        }

        // disable_active_migration が設定されている場合、ハンドシェイクアドレスへの
        // 新しいローカルアドレスからのパス追加だけを禁止する (RFC 9000 Section 18.2)。
        // 同じローカルアドレスからのパス追加や、preferred_address など別アドレスへの
        // パス追加は許可される。指定が無い側は初期パスから継承する。
        let inherited_local = self.paths.initial_path().local_addr;
        let inherited_remote = self.paths.initial_path().remote_addr;
        let effective_local = local_addr.unwrap_or(inherited_local);
        let effective_remote = remote_addr.unwrap_or(inherited_remote);
        if self.active_migration_forbidden(effective_local, effective_remote) {
            return Err(Error::InvalidData(
                "peer has set disable_active_migration for the handshake address".into(),
            ));
        }

        // 自分の `initial_max_path_id` を超えるパスは維持する意思が無いため
        // 作成しない (RFC 10069 Section 2.1 / Section 7.1)。
        // 自分の上限が理由なので PATHS_BLOCKED は送らない。
        if self.paths.next_path_id_blocked_by_local_limit() {
            return Err(Error::InvalidData(format!(
                "path ID exceeds local max path ID {}",
                self.paths.local_max_path_id
            )));
        }

        // RFC 10069 Section 3.2.1 / 4.7: 未使用 path ID がないとき PATHS_BLOCKED を送る
        if self.paths.next_path_id_blocked_by_peer_limit() {
            self.streams.pending_frames.push_back(Frame::PathsBlocked(
                frame::paths_blocked::PathsBlocked {
                    maximum_path_id: self.paths.remote_max_path_id,
                },
            ));
        }

        let path_id = self.paths.open_path()?;

        // 接続の既定値 (keep-alive の有効/無効) を新しいパスへ継承する
        if let Some(path) = self.paths.get_mut(path_id) {
            path.set_keep_alive_enabled(self.keep_alive_enabled);
        }

        // 未開設の間に受信したピアの PATH_STATUS を反映する
        self.apply_pending_peer_path_status(path_id);

        // プロアクティブ CID 発行で使用した seq 番号を反映する
        // (issue_proactive_cids でパス存在前に CID を発行した場合)
        if let Some(next_seq) = self.proactive_cid_next_seq.remove(&path_id.0) {
            let path = self.paths.get_mut(path_id).expect("path just created");
            path.next_local_cid_seq = next_seq;
        }

        // ピアからプロアクティブに発行された CID を新パスの送信先 CID として設定する
        // (open_path 前に PATH_NEW_CONNECTION_ID を受信済みの場合)。
        // 送信先に採用した CID は使用済みにする (RFC 9000 Section 9.5)。
        if let Some(entry) = self.peer_cid_entries.iter().find(|e| e.path_id == path_id) {
            let cid = entry.connection_id.clone();
            self.assign_path_peer_cid(path_id, cid);
        }

        // 新パスに CID を発行する (RFC 10069 Section 4.3)
        if let Ok((seq, cid, token)) = self.generate_new_cid(path_id) {
            self.streams
                .pending_frames
                .push_back(Frame::PathNewConnectionId(
                    frame::path_new_connection_id::PathNewConnectionId {
                        path_id: path_id.0,
                        sequence_number: VarInt::new(seq).expect("value fits in 62-bit varint"),
                        retire_prior_to: VarInt::new(0).expect("value fits in 62-bit varint"),
                        connection_id: cid,
                        stateless_reset_token: token,
                    },
                ));
        }

        // PATH_CHALLENGE データを生成 (暗号論的ランダム)
        let mut challenge_data = [0u8; 8];
        if aws_lc_rs::rand::fill(&mut challenge_data).is_err() {
            // パス作成後の失敗は作成済みのパスを廃棄してから返す。残すと
            // PathManager に孤立パスが残り、PathController の対応付けとも
            // 食い違う。PathOpened はまだ発行していない。
            self.abandon_created_path(path_id, now, PathOpenedState::NotEmitted);
            return Err(Error::InvalidData("failed to generate random bytes".into()));
        }

        let path = self.paths.get_mut(path_id).expect("path just created");
        path.validation.request_challenge(challenge_data);
        path.state = PathState::Validating;
        // クライアントが開いたパスはアンチアンプリフィケーション制限の対象外
        // (RFC 9000 Section 8.1: 制限はサーバー側のみ)
        path.address_validated = true;
        // このパスで使うピア CID が既に判明しているか
        let has_peer_cid = path.peer_cid.is_some();

        // 呼び出し側が指定したアドレスで新パスの 4-tuple を上書きする
        // (指定されなかった側は初期パスから継承した値をそのまま使用する)。
        if (local_addr.is_some() || remote_addr.is_some())
            && let Some(path) = self.paths.get_mut(path_id)
        {
            if let Some(la) = local_addr {
                path.local_addr = la;
            }
            if let Some(ra) = remote_addr {
                path.remote_addr = ra;
            }
        }

        // 新パスの CID を先に通知してから PATH_CHALLENGE を送る。ピアが CID を
        // ルーティングに登録する前に PATH_CHALLENGE が届くと、ピアはその
        // パケットを宛先不明として破棄する。`emit_1rtt_data` は利用可能なパス
        // (この時点では初期パス) で `pending_frames` を送る。
        if let Err(error) = self.emit_1rtt_data(now) {
            // パス作成後の失敗は作成済みのパスを廃棄してから返す。
            // PathOpened はまだ発行していない。
            self.abandon_created_path(path_id, now, PathOpenedState::NotEmitted);
            return Err(error);
        }

        // I/O 層にパス作成を通知する (RFC 10069 Section 3.1)。
        // パス固有のデータグラム (PATH_CHALLENGE) を積むより前に発行し、
        // I/O 層が新しいパスのソケットを用意できるようにする。失敗しうる処理を
        // この出力より前に済ませ、開設に失敗したパスを I/O 層へ通知しない。
        // PathController 経由の open (execute_path_actions) と同じ扱いとする。
        let path = self.paths.get(path_id).expect("path just created");
        self.output_queue.push_back(ConnectionOutput::PathOpened {
            path_id,
            local_addr: path.local_addr,
            remote_addr: path.remote_addr,
        });

        if has_peer_cid
            && let Err(error) = self.emit_1rtt_path_challenge(path_id, challenge_data, now)
        {
            // パス作成後の失敗は作成済みのパスを廃棄してから返す。ここまでで
            // PathOpened を発行済みのため、I/O 層には PathClosed も届く。
            self.abandon_created_path(path_id, now, PathOpenedState::Emitted);
            return Err(error);
        }
        // ピアがこのパスの CID をまだ通知していない場合は PATH_CHALLENGE の送信を
        // 保留する。DCID に使える CID が無く、送ってもピアがルーティングできない。
        // CID を受信して `peer_cid` が設定された時点で
        // `emit_1rtt_path_challenges` が送信する。

        // パス検証タイマーを設定する (PTO ベース)
        let pto = self.path_validation_pto(path_id);
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::PathValidation { path_id },
            deadline: now + pto,
        });

        // レート制限用にパス起動時刻を記録する
        self.last_path_open_time = Some(now);

        Ok(path_id)
    }

    /// 開設処理の途中で失敗したパスを廃棄する
    ///
    /// `PathManager::open_path()` が成功した後にエラーを返す経路で呼ぶ。
    /// 作成済みのパスを残すと、PathManager と PathController の対応付けが
    /// 食い違ったまま孤立パスが送信対象に残る。廃棄自体に失敗しても元の
    /// エラーは呼び出し元へ返す必要があるため、ここではログだけ残す。
    ///
    /// PathController へは `PathAbandoned` を通知しない。PathController 経由の
    /// 開設では、開設結果が [`PathControlEvent::PathOpenFailed`] で伝わり、
    /// 未関連付けのエントリはそれで削除されるため通知は不要である。重ねて
    /// 通知すると、`PathAbandoned` から `OpenPath` を返す実装で開設と失敗が
    /// 繰り返される。公開 API から開いたパスは PathController に関連付けが
    /// 無いため、いずれのイベントも通知しない。
    ///
    /// `path_opened` が [`PathOpenedState::NotEmitted`] の場合、I/O 層へ
    /// `PathOpened` を発行していないため `PathClosed` も発行しない。
    /// `PathClosed` だけを受け取った I/O 層が、開いていないパスの終了として
    /// 扱うことになるためである。
    ///
    /// 廃棄に失敗した場合は作成済みのパスが PathManager に残り得る。検証
    /// タイマーを設定する前の失敗では、パスを回収する別の経路も無い。
    /// 呼び出し元は元のエラーだけを受け取るため、孤立パスの存在を観測できない。
    fn abandon_created_path(
        &mut self,
        path_id: PathId,
        now: Timestamp,
        path_opened: PathOpenedState,
    ) {
        if let Err(e) = self.abandon_path_with_notification(
            path_id,
            frame::path_abandon::error_code::NO_ERROR,
            now,
            AbandonNotification::Skip,
        ) {
            tracing::warn!(
                path_id = %path_id,
                "failed to abandon the path created by open_path: {e}"
            );
        }
        if let PathOpenedState::NotEmitted = path_opened
            && self.pending_abandon_completion.remove(&path_id)
        {
            // `PathOpened` を発行していないため `PathClosed` も抑止する。
            // ピア CID の退役は本来 `PathClosed` を発行する経路で行うが、
            // ここでその経路を通らなくなるため先に済ませる。
            if let Err(e) = self.retire_peer_cids_for_path(path_id, now) {
                tracing::warn!(
                    path_id = %path_id,
                    "failed to retire peer CIDs for the path created by open_path: {e}"
                );
            }
            if let Some(path) = self.paths.get_mut(path_id) {
                path.peer_cid = None;
            }
        }
    }

    /// PATH_ABANDON の初回送信先を返す
    ///
    /// 別の Active なパスがあればそこへ送る (Section 3.4 の RECOMMENDED)。
    /// 無ければ、閉じようとしているパス自身を返す。廃棄済みの別パスへは落とさない。
    fn path_abandon_send_path(&self, abandon_path_id: PathId) -> PathId {
        self.paths
            .select_alt_path(abandon_path_id)
            .unwrap_or(abandon_path_id)
    }

    /// 送信に使う DCID を返す
    ///
    /// RFC 10069 Section 3.1 は、パケットを送るときに受信
    /// パケットと同じ path ID に紐づく Connection ID を使うことを MUST と
    /// している。追加パスで `Path::peer_cid` が未確定の間は初期パスの
    /// `Connection::peer_cid` へフォールバックせず、送信しない。
    fn path_dcid(&self, path_id: PathId) -> Option<ConnectionId> {
        let path = self.paths.get(path_id)?;
        if path.state == PathState::Abandoned
            || (path.state == PathState::Abandoning
                && !self.pending_abandon_completion.contains(&path_id))
        {
            return None;
        }
        if let Some(cid) = &path.peer_cid {
            return Some(cid.clone());
        }
        // 初期パスは接続のピア CID がそのままそのパスの CID になる
        if path_id == PathId::INITIAL {
            return Some(self.peer_cid.clone());
        }
        None
    }

    /// 送信先アドレスが移行の候補 4-tuple と一致する場合に、候補のピア CID を返す
    ///
    /// RFC 9000 Section 9.5: エンドポイントは複数の宛先アドレスへ送信するときに
    /// 同じ CID を再利用してはならない (MUST NOT)。移行の検証中は、候補 4-tuple へ
    /// 送る PATH_RESPONSE などの検証パケットに限り、パスが現在使っている CID では
    /// なく候補 CID を使う。候補 4-tuple 以外 (移行前の 4-tuple) へ送る場合は
    /// `None` を返し、パスの送信先 CID をそのまま使う。
    fn migration_candidate_dcid_for(
        &self,
        path_id: PathId,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) -> Option<ConnectionId> {
        let migration = self.pending_migrations.get(&path_id)?;
        let candidate_local = match migration.candidate_local_addr {
            Some(local_addr) => local_addr,
            // preferred_address への移行ではローカルアドレスを変更しないため、
            // パスの現在のローカルアドレスが候補のローカルアドレスになる。
            None => self.paths.get(path_id)?.local_addr,
        };
        if remote_addr != migration.candidate_remote_addr || local_addr != candidate_local {
            return None;
        }
        Some(migration.candidate_peer_cid.clone())
    }

    /// transport-level の CONNECTION_CLOSE フレームを作る
    fn connection_close_frame(&self, error_code: VarInt, reason: &[u8]) -> Frame {
        let reason_phrase = self
            .close_formatter
            .as_ref()
            .map(|formatter| formatter.format(error_code.as_u64(), reason))
            .unwrap_or_else(|| reason.to_vec());
        Frame::ConnectionClose(frame::connection_close::ConnectionClose {
            application: false,
            error_code,
            frame_type: Some(VarInt::from(0u8)),
            reason_phrase,
        })
    }

    /// 唯一のオープンパスで PATH_ABANDON を受けたときの最後のパケットを送る
    ///
    /// PATH_ABANDON を CONNECTION_CLOSE より前に載せ、そのパスの最後のパケットにする。
    /// Closing 中の再送はスケジュールしない (Section 3.4: そのパスでは以後送れない)。
    fn emit_final_path_abandon(&mut self, path_id: PathId, now: Timestamp) -> Result<(), Error> {
        // PATH_ABANDON は multipath 拡張のフレームである。ネゴシエートして
        // いないピアへ送ると、未知のフレームとして PROTOCOL_VIOLATION に
        // なる (RFC 10069 Section 2)。その場合は
        // CONNECTION_CLOSE だけで接続を閉じる。
        let mut frames = Vec::new();
        if self.multipath_negotiated() {
            frames.push(Frame::PathAbandon(frame::path_abandon::PathAbandon {
                path_id: path_id.0,
                error_code: VarInt::new(frame::path_abandon::error_code::NO_ERROR)
                    .expect("value fits in 62-bit varint"),
            }));
        }
        frames.push(self.connection_close_frame(VarInt::from(0u8), b"all paths abandoned"));
        self.cancel_one_rtt_path(path_id)?;
        self.emit_1rtt_frames(path_id, &frames, now)?;
        if let Some(index) = self.one_rtt_outputs.len().checked_sub(1) {
            // 受信処理で CID を即時退役する前に、最後の閉鎖パケットを確定する。
            // 通常の未送信内容は取り消してあるため、共有 PN 空間も逆転しない。
            // このパケットは PATH_ABANDON と CONNECTION_CLOSE だけで最小 MTU に
            // 収まるため、poll_one_rtt_output の PMTU 点検を経由しない。
            let size = self.one_rtt_outputs[index].payload.len() + MAX_ONE_RTT_OVERHEAD;
            match self.prepare_one_rtt_output(index, size, now) {
                Ok(Some(output)) => self.output_queue.push_back(output),
                Ok(None) => {}
                Err(error) => {
                    self.close_on_output_error(&error);
                    return Err(error);
                }
            }
        }

        if self.state == ConnectionState::Closing
            || self.state == ConnectionState::Draining
            || self.state == ConnectionState::Closed
        {
            return Ok(());
        }
        if self.qlog_writer.is_some() {
            let time_ms = self.qlog_time_ms();
            let old = match self.state {
                ConnectionState::Connected => "connected",
                ConnectionState::Handshaking => "handshaking",
                _ => "unknown",
            };
            if let Some(ref mut writer) = self.qlog_writer {
                writer.on_connection_state_updated(time_ms, old, "closing");
            }
        }
        self.state = ConnectionState::Closing;
        // このパケットのあと同じパスへ再送しない。
        self.closing_packet = None;
        self.set_closing_draining_timer(now);
        Ok(())
    }

    /// パスを廃棄する
    ///
    /// RFC 10069 Section 3.4 に基づき、
    /// 指定パスの状態を Abandoning に遷移し、PATH_ABANDON を送信する。
    ///
    /// multipath がネゴシエートされていない接続では PATH_ABANDON を送っては
    /// ならないため、エラーを返してフレームを送らない。
    ///
    /// `error_code` が 62 ビット varint の範囲外の場合は、接続状態やパスの
    /// 状態に関わらず [`Error::InvalidData`] を返す。
    pub fn abandon_path(
        &mut self,
        path_id: PathId,
        error_code: u64,
        now: Timestamp,
    ) -> Result<(), Error> {
        // RFC 9000 Section 16: PATH_ABANDON の Error Code は 62 ビット varint
        // に収まる必要がある。接続状態やパスの状態による早期 return より前に
        // 検証し、既に Abandoning のパスへ範囲外の値を渡した場合もエラーに
        // する (以前の実装の挙動を維持する)。
        VarInt::try_from(error_code)
            .map_err(|e| Error::InvalidData(format!("invalid PATH_ABANDON error code: {e}")))?;
        if self.state != ConnectionState::Connected {
            return Err(Error::InvalidData("connection must be established".into()));
        }
        self.check_multipath_negotiated()?;

        self.abandon_path_inner(path_id, error_code, now)
    }

    /// パスを廃棄する (multipath のネゴシエーション検査なし)
    ///
    /// パス検証の失敗・衝突解消・自動パス管理など、接続内部のパス管理から呼ぶ。
    /// これらは multipath のネゴシエーション結果に関わらず必要になるため、
    /// 送信側 API の検査を経由させない。
    ///
    /// 処理の順序:
    ///
    /// 1. パスの状態を `Abandoning` にし、3 PTO 後のクリーンアップタイマーを
    ///    設定する。
    /// 2. PathController へ [`PathControlEvent::PathAbandoned`] を通知し、返された
    ///    アクションを [`Self::execute_path_actions`] で実行する。
    /// 3. `PATH_ABANDON` フレームを送信する。
    ///
    /// `PathAbandoned` の通知時点では `PATH_ABANDON` はまだ送信されていない。
    /// この順序は将来変わりうるため、実装は送信完了を前提にしてはならない。
    /// アクションの実行はこの関数への再入であり、同じパスは既に `Abandoning`
    /// のため何もしない。別のパスを対象にした場合はそのパスについて同じ手順を
    /// 再帰的に実行する。
    ///
    /// ピア起点の廃棄は [`Self::process_path_abandon`] が通知するため、この
    /// 関数は呼ばない (二重通知を避ける)。
    fn abandon_path_inner(
        &mut self,
        path_id: PathId,
        error_code: u64,
        now: Timestamp,
    ) -> Result<(), Error> {
        self.abandon_path_with_notification(path_id, error_code, now, AbandonNotification::Notify)
    }

    /// 通知の有無を指定してパスを廃棄する
    ///
    /// 処理の順序は [`Self::abandon_path_inner`] と同じ。
    /// [`AbandonNotification::Skip`] の場合は `PathAbandoned` を通知せず、
    /// 返されたアクションも実行しない。開設処理の途中で失敗したパスの後始末に
    /// 使う。開設結果は [`PathControlEvent::PathOpenFailed`] で伝わり、
    /// 未関連付けのエントリはそれで削除されるため、`PathAbandoned` を重ねて
    /// 通知すると、その通知から `OpenPath` を返す実装で開設と失敗が
    /// 繰り返される。
    fn abandon_path_with_notification(
        &mut self,
        path_id: PathId,
        error_code: u64,
        now: Timestamp,
        notification: AbandonNotification,
    ) -> Result<(), Error> {
        let path = self
            .paths
            .get_mut(path_id)
            .ok_or_else(|| Error::InvalidData(format!("path {path_id} not found")))?;

        // 既に廃棄済み/廃棄中なら何もしない
        if path.state == PathState::Abandoning || path.state == PathState::Abandoned {
            return Ok(());
        }

        // アプリケーション由来のエラーコードは varint 範囲を超えうるため、
        // 状態を Abandoning に変える前に検証する。状態を変えた後に失敗すると、
        // 廃棄中として残る一方で PathController へ通知できない。
        // RFC 9000 Section 16: PATH_ABANDON の Error Code は 62 ビット varint
        // に収まる必要がある。
        let error_code = VarInt::try_from(error_code)
            .map_err(|e| Error::InvalidData(format!("invalid path abandon error code: {e}")))?;

        // 廃棄対象のパスで migration を検証中なら、完了できないため取り消す。
        // パス廃棄は PathAbandoned 相当の出力で利用者へ伝わるため、
        // PathValidationFailed は重ねて通知しない。
        self.discard_pending_migration(path_id);
        self.cancel_one_rtt_path(path_id)?;
        // ピアが PATH_ABANDON を返さない場合でも保持期間の経過後にパス状態を
        // 解放できるよう、受信側 (`Connection::process_path_abandon`) と同じ
        // 3 PTO のタイマーを設定する。算出式を揃えて送信側と受信側で
        // 保持期間を一致させる。
        let pto_3x = self.lifecycle_pto_for_path(path_id).mul(3);
        let path = self.paths.get_mut(path_id).expect("path exists");
        path.state = PathState::Abandoning;
        // 3 PTO クリーンアップ用のタイムスタンプを記録する
        // (RFC 10069 Section 3.4)
        path.abandoned_at = Some(now);
        // tombstone を登録する (remove_path() 後も遅延フレームを無視するため)
        self.paths.abandon_path_id(path_id);
        // 最終出力を I/O へ渡してから CID を退役し、ソケットを閉じる。
        self.pending_abandon_completion.insert(path_id);
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::PathCleanup { path_id },
            deadline: now.add(pto_3x),
        });

        // 通知とアクションの実行は PATH_ABANDON の送信より前に行う。
        // 実行はこの関数へ再入しうるが、同じパスは Abandoning のため
        // 再通知されない。
        if let AbandonNotification::Notify = notification {
            let pc_event = PathControlEvent::PathAbandoned {
                path_id,
                error_code: error_code.as_u64(),
            };
            let actions = self.invoke_path_controller(&pc_event, now);
            self.execute_path_actions(actions, now);
        }

        // PATH_ABANDON は別の Active なパスへ送る (RECOMMENDED)。
        // 無ければ、閉じようとしているパス自身でこの 1 パケットを送る。
        // RFC 10069 Section 3.4。廃棄済みの初期パスへは落とさない。
        let send_path = self.path_abandon_send_path(path_id);
        self.emit_1rtt_single_frame(
            send_path,
            Frame::PathAbandon(frame::path_abandon::PathAbandon {
                path_id: path_id.0,
                error_code,
            }),
            now,
        )?;

        // 廃棄パスの未確認パケットを lost として扱う
        // 送信側も受信側と同様にパケットを整理する必要がある
        // 統計更新用: path 借用中に数え、借用終了後に Connection 全体へ反映する
        let mut abandoned_lost_count: u64 = 0;
        let mut abandoned_retransmitted_count: u64 = 0;
        // 廃棄したパスの per-packet 状態も破棄する。パスは 3 PTO 後に削除される
        // まで保持されるため、その間 BBR の Delivery Rate Sampling 用の状態を
        // 残さないよう明示的に削除する (RFC 9002 Section 6.4)。
        let mut abandoned_pns: Vec<u64> = Vec::new();
        let lost_packets_for_recovery = {
            let path = self.paths.get_mut(path_id).expect("path exists");
            let lost_packets = path.sent_packets.drain_all();
            let discarded_bytes = lost_packets
                .iter()
                .filter(|packet| packet.in_flight)
                .fold(0u64, |total, packet| {
                    total.saturating_add(packet.sent_bytes)
                });
            path.congestion.on_packet_discarded_bytes(discarded_bytes);
            abandoned_pns.extend(lost_packets.iter().map(|packet| packet.pn));
            for packet in &lost_packets {
                if !packet.in_flight {
                    continue;
                }
                abandoned_lost_count = abandoned_lost_count.saturating_add(1);
                path.record_lost_packet();
                if has_retransmittable_frame(&packet.frames) {
                    abandoned_retransmitted_count = abandoned_retransmitted_count.saturating_add(1);
                    path.record_retransmitted_packet();
                }
            }
            lost_packets
        };
        self.recover_lost_frames_on_abandoned_path(lost_packets_for_recovery, path_id, now);

        // 廃棄したパスの per-packet 状態を削除する。送信済みパケットは
        // Application Data 空間に属する (0-RTT / 1-RTT)。
        if !abandoned_pns.is_empty()
            && let Some(path) = self.paths.get_mut(path_id)
        {
            path.congestion
                .on_packets_discarded_cc(PacketNumberSpace::ApplicationData, &abandoned_pns);
        }

        // path 借用中に数えたロスト・再送統計を Connection 全体へ反映する
        self.stats.lost_packets = self.stats.lost_packets.saturating_add(abandoned_lost_count);
        self.stats.retransmitted_packets = self
            .stats
            .retransmitted_packets
            .saturating_add(abandoned_retransmitted_count);

        // PTO プローブキューから当該パスを除去する
        self.pto_probe_paths.retain(|&pid| pid != path_id);

        // 最後のアクティブパスが廃棄された場合は接続を閉じる (SHOULD)
        // (RFC 10069 Section 3.4)
        if self.paths.active_path_count() == 0 && self.state == ConnectionState::Connected {
            self.close(0, b"all paths abandoned", now)?;
        }

        Ok(())
    }

    /// 指定パス宛ての未送信データグラムを送信キューから除去する
    ///
    /// パスを削除した後も `output_queue` に残った `SendDatagram` を送ると、
    /// 存在しないパスの古い宛先へパケットを送ってしまう。パス削除時に呼ぶ。
    fn remove_queued_datagrams_for_path(&mut self, path_id: PathId) {
        self.output_queue.retain(|output| match output {
            ConnectionOutput::SendDatagram {
                path_id: queued_path_id,
                ..
            } => *queued_path_id != path_id,
            _ => true,
        });
    }

    /// パスのステータスを設定し、ピアに通知する
    ///
    /// RFC 10069 Section 3.3 に基づき、
    /// PATH_STATUS_AVAILABLE / PATH_STATUS_BACKUP フレームを送信する。
    pub fn set_path_status(
        &mut self,
        path_id: PathId,
        status: PathStatus,
        now: Timestamp,
    ) -> Result<(), Error> {
        if self.state != ConnectionState::Connected {
            return Err(Error::InvalidData("connection must be established".into()));
        }
        self.check_multipath_negotiated()?;

        if self.paths.get(path_id).is_none() {
            return Err(Error::InvalidData(format!("path {path_id} not found")));
        }
        // 送信先が無いときは状態を変えない。対象 path ID は送信先の制約ではない。
        let Some(send_path) = self.paths.select_open_path() else {
            return Err(Error::InvalidData("no open path".into()));
        };
        let path = self.paths.get_mut(path_id).expect("path exists");
        path.status = status;
        let seq = next_varint_sequence(&mut path.status_seq_send);

        // ローカル状態の変更をアプリへ通知する
        self.push_event(ConnectionEvent::PathStatusChanged { path_id, status });

        let frame = match status {
            PathStatus::Available => {
                Frame::PathStatusAvailable(frame::path_status::PathStatusAvailable {
                    path_id: path_id.0,
                    path_status_sequence_number: seq,
                })
            }
            PathStatus::Backup => Frame::PathStatusBackup(frame::path_status::PathStatusBackup {
                path_id: path_id.0,
                path_status_sequence_number: seq,
            }),
        };

        self.emit_1rtt_single_frame(send_path, frame, now)
            .map(|_| ())
    }

    /// 鍵更新に伴い 1-RTT 鍵を次世代へ進め、旧世代の受信鍵を保持する
    ///
    /// RFC 9001 Section 6.1: 更新前の受信鍵は、更新後の鍵で保護されたパケットの
    /// 保護解除に成功するまで保持しなければならない (MUST)。成功後は全パスの
    /// 最大 PTO の 3 倍 (3 × max(PTO)) の間だけ保持し、その後破棄する
    /// (RFC 9001 Section 6.5)。HP 鍵は鍵更新で変わらないため、旧世代として
    /// 保持するのは remote パケット鍵だけ。
    ///
    /// `next` は `update_keys` または `apply_peer_initiated_key_update` が
    /// `Secrets::next_packet_keys()` で導出した次世代の鍵ペア。
    ///
    /// 旧鍵の保持期限はここでは設定しない。期限は更新後の鍵で最初にパケットを
    /// 受信したときに `record_current_key_phase_packet` が設定する
    /// (RFC 9001 Section 6.1)。
    fn advance_one_rtt_keys(&mut self, next: rustls::quic::PacketKeySet) {
        let Some(keys) = self.one_rtt_keys.as_mut() else {
            return;
        };
        // 現在の remote パケット鍵を旧世代へ移す (必ず Some である)
        let previous_remote = keys
            .remote_packet
            .take()
            .expect("1-RTT remote packet key must exist outside of a key update");
        self.previous_one_rtt_keys = Some(PreviousOneRttKeys {
            remote_packet: previous_remote,
            key_phase: self.key_phase,
            // 更新後の鍵で保護されたパケットの保護解除に成功するまでは期限を
            // 設けない (RFC 9001 Section 6.1)。
            expires_at: None,
        });
        keys.local_packet = next.local;
        keys.remote_packet = Some(next.remote);
        // 現行鍵フェーズの受信境界は鍵フェーズごとに独立している。鍵更新で
        // 全パスの境界を消し、次世代のパケットを受信するまで境界が無い状態に
        // する (RFC 9001 Section 6.5)。
        self.current_key_phase_lowest_recv_pns.clear();
    }

    /// 現行の 1-RTT 鍵フェーズで受信したパケットを記録する
    ///
    /// RFC 9001 Section 6.5: 現行の Key Phase で受信した最小パケット番号を
    /// パスごとの境界として更新する。旧鍵で保護されたパケットは、この境界より
    /// 小さいパケット番号の場合だけ再順序として受理する。
    ///
    /// RFC 9001 Section 6.1: 更新後の鍵で保護されたパケットの保護解除に成功した
    /// ことを記録し、旧鍵の保持期限が未設定なら全パスの最大 PTO の 3 倍
    /// (3 × max(PTO)) を設定する。期限の計算は未設定の場合だけ行い、2 回目以降の
    /// 受信で上書きしない。
    fn record_current_key_phase_packet(&mut self, path_id: PathId, full_pn: u64, now: Timestamp) {
        // 境界は最小値で固定する。受信順に依存せず、後から小さいパケット番号が
        // 届いても境界を下げる (RFC 9001 Section 6.5)。
        let boundary = self
            .current_key_phase_lowest_recv_pns
            .entry(path_id)
            .or_insert(full_pn);
        *boundary = (*boundary).min(full_pn);

        // 保持期限が未設定のときだけ最大 PTO を計算する
        let needs_expiry = self
            .previous_one_rtt_keys
            .as_ref()
            .is_some_and(|previous| previous.expires_at.is_none());
        if needs_expiry {
            let retention = self.lifecycle_max_pto().mul(3);
            if let Some(previous) = self.previous_one_rtt_keys.as_mut() {
                previous.expires_at = Some(now.add(retention));
            }
        }
    }

    /// 保持期限を過ぎた旧 1-RTT 受信鍵を破棄する (RFC 9001 Section 6.5)
    ///
    /// `expires_at` が `None` の間は、更新後の鍵での受信に成功していないため
    /// 破棄しない (RFC 9001 Section 6.1)。
    fn discard_expired_previous_one_rtt_keys(&mut self, now: Timestamp) {
        if let Some(previous) = self.previous_one_rtt_keys.as_ref()
            && let Some(expires_at) = previous.expires_at
            && now.has_elapsed(expires_at)
        {
            self.previous_one_rtt_keys = None;
        }
    }

    /// 現在の 1-RTT 鍵で復号する
    fn decrypt_one_rtt_with_current_key(
        &self,
        path_id: PathId,
        full_pn: u64,
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<Vec<u8>, Error> {
        let rk = self
            .one_rtt_keys
            .as_ref()
            .ok_or_else(|| Error::InvalidData("no 1-RTT keys".into()))?;
        let key = rk
            .remote_packet
            .as_ref()
            .ok_or_else(|| Error::InvalidData("no 1-RTT remote packet key".into()))?;
        key.decrypt_in_place_for_path(path_id.0, full_pn, aad, ciphertext)
            .map(|plaintext| plaintext.to_vec())
            .map_err(|_| Error::InvalidData("1-RTT decryption failed".into()))
    }

    /// 鍵更新前の旧世代の鍵で復号を試みる (RFC 9001 Section 6.5)
    ///
    /// 受信パケットの Key Phase が旧世代のものと一致し、保持期限内である場合のみ
    /// trial 復号する。保持期限が設定されていない (`None`) 間は、更新後の鍵での
    /// 受信に成功していないため無期限に保持する (RFC 9001 Section 6.1)。
    /// 復号できた場合は平文を返し、鍵更新は行わない。
    /// 復号できなかった場合は `None` を返す (呼び出し側がピア起動の鍵更新を試す)。
    fn try_decrypt_with_previous_keys(
        &mut self,
        recv_key_phase: bool,
        path_id: PathId,
        full_pn: u64,
        aad: &[u8],
        ciphertext: &[u8],
        now: Timestamp,
    ) -> Option<Vec<u8>> {
        let previous = self.previous_one_rtt_keys.as_ref()?;
        // 保持期限切れの鍵では復号しない (RFC 9001 Section 6.5)。呼び出し元は
        // 直前に discard_expired_previous_one_rtt_keys を呼ぶため通常は到達しない。
        // 破棄済みの鍵で復号する事故を防ぐための防衛的な検査である。
        if let Some(expires_at) = previous.expires_at
            && now.has_elapsed(expires_at)
        {
            self.previous_one_rtt_keys = None;
            return None;
        }
        // Key Phase が旧世代のものと一致する場合のみ試す。呼び出し元は現行の
        // Key Phase と異なるパケットだけを渡すため通常は一致するが、鍵更新を
        // 挟んだ場合に古い Key Phase のパケットを旧鍵で復号しないよう、
        // 防衛的に検査する。
        if recv_key_phase != previous.key_phase {
            return None;
        }
        // AEAD の in-place 復号は、認証失敗時にも入力を書き換え得る。
        // RFC 9001 Section 6.5 の旧鍵と次鍵の trial は、同じ元の暗号文で
        // 試す必要があるため、旧鍵には専用の作業バッファを渡す。
        let mut trial_ciphertext = ciphertext.to_vec();
        match previous.remote_packet.decrypt_in_place_for_path(
            path_id.0,
            full_pn,
            aad,
            &mut trial_ciphertext,
        ) {
            Ok(plaintext) => Some(plaintext.to_vec()),
            Err(_) => {
                // 旧鍵でも復号できない場合は認証失敗として数える (RFC 9001 Section 6.6)
                self.record_aead_auth_failure();
                None
            }
        }
    }

    /// ピア起動の鍵更新を受信側で処理する (RFC 9001 Section 6.1 / 6.3)
    ///
    /// HP 解除後に Key Phase bit が自分の key_phase と異なる場合に呼び出される。
    /// next_secrets を clone して次鍵を導出し、trial 復号に成功したときのみ
    /// 自身の鍵と next_secrets をコミットする。
    ///
    /// RFC 10069 Section 7.3: AEAD 制限は全パス合計で管理されるため、
    /// 鍵更新に成功したら送受信カウンタをリセットする。
    ///
    /// 従来は Key Phase bit を無視していたため、ピア起動の鍵更新後は
    /// 現行鍵で復号を試み続けて失敗していた。
    fn apply_peer_initiated_key_update(
        &mut self,
        path_id: PathId,
        full_pn: u64,
        aad: &[u8],
        ciphertext: &mut [u8],
        now: Timestamp,
    ) -> Result<Vec<u8>, Error> {
        // next_secrets を消費せず clone する。trial 復号に失敗しても self.next_secrets を
        // 破壊しないため (RFC 9001 Section 6.3: 生成済みの next 鍵はパケットを破棄した場合も
        // 保持すべき)。rustls::quic::Secrets は Clone を実装している (rustls 0.23.39 時点。
        // 将来の rustls 更新で derive が外れる可能性がある)。
        let mut trial = self.next_secrets.clone().ok_or_else(|| {
            Error::InvalidData("no next secrets for peer-initiated key update".into())
        })?;
        let next = trial.next_packet_keys();
        // 次鍵で復号を試みる。失敗時は self.next_secrets を一切変更せず早期 return する。
        let decrypt_result = next
            .remote
            .decrypt_in_place_for_path(path_id.0, full_pn, aad, ciphertext);
        let trial_plaintext = match decrypt_result {
            Ok(plaintext) => plaintext.to_vec(),
            Err(_) => {
                // RFC 9001 Section 6.6: 認証失敗数を integrity limit 用に数える
                // (trial 復号の失敗も across all keys の累積対象)
                self.record_aead_auth_failure();
                return Err(Error::InvalidData(
                    "1-RTT decryption failed (peer key update trial)".into(),
                ));
            }
        };

        // 復号成功: 鍵更新をコミットする
        // HP 鍵は変わらないため引き継ぎ、旧世代の remote 鍵は更新後の鍵での
        // 受信に成功するまで保持し、成功後は全パスの最大 PTO の 3 倍
        // (3 × max(PTO)) 保持する (RFC 9001 Section 6.1 / 6.5)
        if self.one_rtt_keys.is_none() {
            return Err(Error::InvalidData("no existing 1-RTT keys".into()));
        }
        self.advance_one_rtt_keys(next);

        self.key_phase = !self.key_phase;
        self.next_secrets = Some(trial);

        // RFC 9001 Section 6.5: トリガーパケットはコミット後の現行鍵フェーズで
        // 受信した最初のパケットである。このパケット番号をそのパスの受信境界と
        // して記録し、以降に旧鍵で届いた境界以上の番号のパケットを検出する。
        // RFC 9001 Section 6.1: 更新後の鍵での受信に成功したため、ここで旧鍵の
        // 保持期限も設定される。
        self.record_current_key_phase_packet(path_id, full_pn, now);

        // 観測イベント: 1-RTT 鍵更新
        self.observe(ConnectionObservationEvent::KeyUpdated {
            key_phase: u8::from(self.key_phase),
        });
        // qlog: ピア起点の 1-RTT 鍵更新 (qlog-quic-events-13 Section 6.1)
        if self.qlog_writer.is_some() {
            let time_ms = self.qlog_time_ms();
            let key_phase = u64::from(self.key_phase);
            if let Some(ref mut w) = self.qlog_writer {
                w.on_key_updated(time_ms, "1rtt", Some(key_phase), "remote_update");
            }
        }

        // 鍵更新のクールダウンは、更新後のフェーズで送ったパケットを確認した
        // 最初の ACK を受信した時点から開始する (process_ack)。
        // 実行時点の古い期限は破棄し、フェーズ開始状態を初期化する。
        self.begin_key_phase(true);

        // 送信カウンタのみリセットする (confidentiality limit は鍵ごと)
        // 認証失敗カウンタは across all keys 累積のためリセットしない (RFC 9001 Section 6.6)
        self.one_rtt_packets_sent = 0;

        Ok(trial_plaintext)
    }

    /// 自発的に鍵更新を実行する
    ///
    /// RFC 10069 Section 2.5 に基づき、Key Phase を切り替えて
    /// 新しいパケット鍵を生成する。HP 鍵は鍵更新で変わらない (RFC 9001 Section 6)。
    /// 更新後のフェーズで送ったパケットを確認した最初の ACK を受信してから
    /// 3 × PTO の間は次の鍵更新を開始しない (SHOULD、RFC 9001 Section 6.5)。
    /// マルチパスでは全パスの最大 PTO を使う (RFC 10069
    /// Section 2.5)。
    pub fn update_keys(&mut self, now: Timestamp) -> Result<(), Error> {
        // RFC 9001 Section 6.1: ハンドシェイクを確認する前に鍵更新を開始しては
        // ならない (MUST NOT)。
        if !self.is_handshake_confirmed() {
            return Err(Error::InvalidData(
                "handshake must be confirmed before initiating a key update".into(),
            ));
        }
        // RFC 9001 Section 6.1: 現行鍵フェーズで送ったパケットの ACK を 1 つ以上
        // 受ける前に、次の鍵更新を開始してはならない (MUST NOT)。
        if !self.current_phase_acked {
            return Err(Error::InvalidData(
                "current key phase packet has not been acknowledged".into(),
            ));
        }
        // 鍵更新クールダウンチェック (RFC 9001 Section 6.5、
        // RFC 10069 Section 2.5)
        if let Some(allowed_at) = self.key_update_allowed_at
            && !now.has_elapsed(allowed_at)
        {
            return Err(Error::InvalidData(
                "key update cooldown period has not elapsed".into(),
            ));
        }

        let mut secrets = self
            .next_secrets
            .take()
            .ok_or_else(|| Error::InvalidData("no next secrets available for key update".into()))?;

        let next = secrets.next_packet_keys();

        // HP 鍵は変わらないため引き継ぎ、旧世代の remote 鍵は更新後の鍵での
        // 受信に成功するまで保持する (RFC 9001 Section 6.1)
        if self.one_rtt_keys.is_none() {
            // 鍵が無い状態では next_secrets を消費しない
            self.next_secrets = Some(secrets);
            return Err(Error::InvalidData("no existing 1-RTT keys".into()));
        }
        self.advance_one_rtt_keys(next);

        self.key_phase = !self.key_phase;
        self.next_secrets = Some(secrets);

        // 観測イベント: 1-RTT 鍵更新
        self.observe(ConnectionObservationEvent::KeyUpdated {
            key_phase: u8::from(self.key_phase),
        });
        // qlog: ローカル起点の 1-RTT 鍵更新 (qlog-quic-events-13 Section 6.1)
        if self.qlog_writer.is_some() {
            let time_ms = self.qlog_time_ms();
            let key_phase = u64::from(self.key_phase);
            if let Some(ref mut w) = self.qlog_writer {
                w.on_key_updated(time_ms, "1rtt", Some(key_phase), "local_update");
            }
        }

        // 鍵更新のクールダウンは、更新後のフェーズで送ったパケットを確認した
        // 最初の ACK を受信した時点から開始する (process_ack)。
        // 実行時点の古い期限は破棄し、フェーズ開始状態を初期化する。
        self.begin_key_phase(true);

        // 送信カウンタのみリセットする
        // (RFC 9001 Appendix B / RFC 10069 Section 7.3)
        // confidentiality limit は鍵ごとに再集計する。
        // 認証失敗カウンタは across all keys 累積のためリセットしない (RFC 9001 Section 6.6)。
        self.one_rtt_packets_sent = 0;

        Ok(())
    }

    /// 許容する最大 Path ID を拡張し、ピアに通知する
    ///
    /// RFC 10069 Section 4.6 に基づく。
    /// 実装が同時に保持するパス数を制限するため、`MAX_PATH_ID` (64) を
    /// 超える値は `InvalidData` として拒否する。
    pub fn set_max_path_id(&mut self, max_path_id: u32, now: Timestamp) -> Result<(), Error> {
        if self.state != ConnectionState::Connected {
            return Err(Error::InvalidData("connection must be established".into()));
        }
        self.check_multipath_negotiated()?;

        if max_path_id > MAX_PATH_ID {
            return Err(Error::InvalidData(format!(
                "max_path_id {max_path_id} exceeds the practical maximum {MAX_PATH_ID}"
            )));
        }
        if max_path_id <= self.paths.local_max_path_id {
            return Ok(()); // 減少は許可されない
        }
        let Some(send_path) = self.paths.select_open_path() else {
            return Err(Error::InvalidData("no open path".into()));
        };
        self.paths.local_max_path_id = max_path_id;
        self.emit_1rtt_single_frame(
            send_path,
            Frame::MaxPathId(frame::max_path_id::MaxPathId {
                maximum_path_id: max_path_id,
            }),
            now,
        )?;
        // 新しい Path ID に対して CID を先行発行する
        self.issue_proactive_cids();
        Ok(())
    }

    /// 指定パスのピア CID が不足している場合に PATH_CIDS_BLOCKED を送信する
    ///
    /// RFC 10069 Section 4:
    /// CID ローテーション等で新しいピア CID が必要だが active_connection_id_limit
    /// に達している場合に送信する。アプリケーションが明示的に呼ぶ API であり、
    /// 呼ぶたびに送信する。
    pub fn notify_path_cids_blocked(
        &mut self,
        path_id: PathId,
        now: Timestamp,
    ) -> Result<(), Error> {
        if self.state != ConnectionState::Connected {
            return Err(Error::InvalidData("connection must be established".into()));
        }
        self.check_multipath_negotiated()?;

        let Some(send_path) = self.paths.select_open_path() else {
            return Err(Error::InvalidData("no open path".into()));
        };
        let next_sequence_number = self.next_peer_cid_sequence_number(path_id);
        self.emit_1rtt_single_frame(
            send_path,
            Frame::PathCidsBlocked(frame::path_cids_blocked::PathCidsBlocked {
                path_id: path_id.0,
                next_sequence_number: VarInt::new(next_sequence_number)
                    .expect("value fits in 62-bit varint"),
            }),
            now,
        )?;
        self.cid_blocked_notified.insert(path_id.0);
        self.stats.record_path_cids_blocked_sent();
        tracing::debug!(
            "sent PATH_CIDS_BLOCKED path={:?} next_sequence_number={}",
            path_id,
            next_sequence_number
        );
        Ok(())
    }

    /// 指定パスで次に発行されると期待するピア CID のシーケンス番号を返す
    ///
    /// RFC 10069 Section 4.7:
    /// Next Sequence Number は「このパスの CID についてピアが次に発行すると
    /// 期待されるシーケンス番号」である。受信済みの最大シーケンス番号 + 1 とし、
    /// まだ 1 つも受信していない場合は 0 とする。退役でエントリが消えても
    /// `peer_cid_max_seq` に最大値を残すため、全 CID が退役済みでも正しく求まる。
    fn next_peer_cid_sequence_number(&self, path_id: PathId) -> u64 {
        self.peer_cid_max_seq.get(&path_id.0).map_or(0, |max_seq| {
            max_seq.saturating_add(1).min(tobi_core::varint::MAX_VALUE)
        })
    }

    /// 指定パスで使用するピア CID を未使用のものへ能動的に切り替える
    ///
    /// RFC 9000 Section 5.1.2: エンドポイントは接続中いつでも、ピアから発行された
    /// 利用可能な CID へ切り替えてよい。RFC 9000 Section 9.5: 複数のローカル /
    /// 宛先アドレスへの送信で同じ CID を再利用してはならない (MUST NOT)。
    /// そのため、送信先に使ったことのある CID は候補にせず、未使用の CID のうち
    /// 最小シーケンス番号のものだけを選ぶ。RFC 10069
    /// Section 3.2.2: multipath 拡張では、同じ path ID に紐づく CID にだけ
    /// 切り替えなければならない (MUST)。別の path ID の CID は新しいパスを
    /// 開く試みとみなされる。
    ///
    /// 戻り値は切り替えたかどうか。未使用の CID が無い場合は false を返し、
    /// multipath がネゴシエーション済みなら PATH_CIDS_BLOCKED を送ってピアへ
    /// 通知する (同じ枯渇状態では 1 回だけ)。接続は閉じない。
    ///
    /// 切り替えの副作用は送信先 CID の変更だけであり、輻輳制御・RTT 推定・
    /// パケット番号空間は維持する (RFC 10069 Section 5.3)。
    pub fn rotate_path_cid(&mut self, path_id: PathId, now: Timestamp) -> Result<bool, Error> {
        if self.state != ConnectionState::Connected {
            return Err(Error::InvalidData("connection must be established".into()));
        }
        let path = self
            .paths
            .get(path_id)
            .ok_or_else(|| Error::InvalidData(format!("path {path_id} not found")))?;
        if path.state == PathState::Abandoning || path.state == PathState::Abandoned {
            return Err(Error::InvalidData(format!("path {path_id} is abandoned")));
        }
        // 同じ path ID の未使用 CID を 1 つ選び、使用済みにする。現在使用中の
        // CID も送信先に使った時点で used になっているため、ここで除外する
        // 必要はない。初期 CID (seq 0) はハンドシェイクで used になっている。
        let next = self.take_unused_peer_cid_for_path(path_id);

        let Some(next) = next else {
            // 未使用 CID が無い: multipath 有効時のみ PATH_CIDS_BLOCKED を送る。
            // 単一パス接続には PATH_CIDS_BLOCKED が存在しないため通知しない。
            if self.multipath_negotiated()
                && !self.cid_blocked_notified.contains(&path_id.0)
                && let Some(send_path) = self.paths.select_open_path()
            {
                let next_sequence_number = self.next_peer_cid_sequence_number(path_id);
                let frame = Frame::PathCidsBlocked(frame::path_cids_blocked::PathCidsBlocked {
                    path_id: path_id.0,
                    next_sequence_number: VarInt::new(next_sequence_number)
                        .expect("value fits in 62-bit varint"),
                });
                if self.emit_1rtt_single_frame(send_path, frame, now).is_ok() {
                    self.cid_blocked_notified.insert(path_id.0);
                    self.stats.record_path_cids_blocked_sent();
                    tracing::debug!(
                        "sent PATH_CIDS_BLOCKED path={:?} next_sequence_number={}",
                        path_id,
                        next_sequence_number
                    );
                }
            }
            return Ok(false);
        };

        // 送信先 CID だけを差し替える (輻輳制御・RTT・PN 空間は維持)
        self.assign_path_peer_cid(path_id, next);
        self.cid_blocked_notified.remove(&path_id.0);
        self.stats.record_cid_rotation();
        tracing::debug!("rotated path connection id path={:?}", path_id);
        Ok(true)
    }

    // --- パケット処理 ---

    /// パケットを 1 つ処理する
    ///
    /// `datagram_len` は `data` を先頭に含むデータグラムの全長。Initial の
    /// 最小データグラム長検査 (RFC 9000 Section 14.1) に使用する。
    fn process_packet(
        &mut self,
        data: &[u8],
        datagram_len: usize,
        now: Timestamp,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) -> Result<PacketOutcome, Error> {
        if data.is_empty() {
            return Ok(PacketOutcome::Processed(0));
        }
        if header::is_long_header(data[0]) {
            self.process_long_header(data, datagram_len, now, remote_addr, local_addr)
        } else {
            self.process_short_header(data, now, remote_addr, local_addr)
                .map(PacketOutcome::Processed)
        }
    }

    /// Long Header パケットを処理する
    ///
    /// `datagram_len` はデータグラム全体の長さ (Initial の最小長検査用)。
    fn process_long_header(
        &mut self,
        data: &[u8],
        datagram_len: usize,
        now: Timestamp,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) -> Result<PacketOutcome, Error> {
        // Long Header の 4-tuple は AEAD 復号に成功した後でだけ初期パスへ反映する
        // (RFC 9000 Section 9.3)。ここで復号前に書き換えると、CID を知るだけで
        // 未認証の Long Header を送った攻撃者に以後の送信先を汚染される。
        // 復号成功後の反映は `commit_long_header_address()` が行う。

        // RFC 9287 Section 3: 自分が grease_quic_bit を広告している場合のみ
        // QUIC Bit 0 のパケットを受け入れる。
        let hdr = if self.local_params.grease_quic_bit {
            LongHeader::decode_allow_zero_quic_bit(data)?
        } else {
            LongHeader::decode(data)?
        };

        // Version Negotiation パケット (version == 0) を処理する (RFC 9000 Section 6.2)
        if hdr.version == 0 {
            return self
                .process_version_negotiation(data, &hdr)
                .map(PacketOutcome::Processed);
        }

        // RFC 9000 Section 5.2.1: 接続で使用しているバージョンと異なる Long Header は
        // 破棄する。サーバーは受理しないバージョンの Initial をルーター側で
        // Version Negotiation 応答に変換するため、ここでは接続を確立しない。
        //
        // ただし RFC 9368 Section 2.3 の互換バージョン交渉では次の 2 つの例外がある。
        // - サーバー: クライアントの最初の flight は Chosen Version で届くため、
        //   互換バージョン交渉で選んだバージョン (self.version) と異なる
        //   Chosen Version の Initial を受理する
        // - クライアント: サーバーが Chosen Version と異なる互換バージョンで
        //   応答した場合は、そのバージョンを記録して接続を中止する
        if hdr.version != self.version {
            // サーバー: 互換バージョン交渉で最初の flight を受信する
            if self.role == Role::Server
                && hdr.packet_type == LongPacketType::Initial
                && self.compatible_client_version == Some(hdr.version)
            {
                return self.process_initial(
                    data,
                    &hdr,
                    datagram_len,
                    now,
                    remote_addr,
                    local_addr,
                );
            }
            // クライアント: サーバーが互換バージョンで応答した
            if self.role == Role::Client
                && hdr.packet_type == LongPacketType::Initial
                && hdr.dcid == self.local_cid
                && self.handshake_keys.is_none()
                && self.initial_recv_pn_largest.is_none()
                && !self.retry_received
                && self.version_negotiation_versions.is_none()
                && self.supported_versions.contains(&hdr.version)
                && tobi_core::connection::is_compatible_version(self.version, hdr.version)
            {
                tracing::info!(
                    "server selected compatible version {:#010x} instead of chosen version {:#010x}",
                    hdr.version,
                    self.version
                );
                // サーバーはクライアントの最初の接続が中止されたことを
                // CONNECTION_CLOSE で知る必要がある。送らないとサーバーは
                // ハンドシェイク完了を待ち続け、次の接続を受け付けられない。
                // この時点ではまだ Handshake 鍵が無いため Initial で送る。
                let _ = self.close(0, b"compatible version negotiation", now);
                // rustls の QUIC セッションはバージョンに束縛されるため、
                // 接続内でバージョンを切り替えられない。上位層が新しい接続
                // 試行を開始できるよう、選択されたバージョンを記録する。
                self.compatible_version_switch = Some(hdr.version);
                return Ok(PacketOutcome::Processed(data.len()));
            }
            tracing::debug!(
                "dropping long header with mismatched version: expected={:#010x} got={:#010x}",
                self.version,
                hdr.version
            );
            return Ok(PacketOutcome::Processed(data.len()));
        }

        match hdr.packet_type {
            LongPacketType::Initial => {
                self.process_initial(data, &hdr, datagram_len, now, remote_addr, local_addr)
            }
            LongPacketType::Handshake => {
                self.process_handshake(data, &hdr, now, remote_addr, local_addr)
            }
            LongPacketType::Retry => self
                .process_retry(data, &hdr, now, remote_addr, local_addr)
                .map(PacketOutcome::Processed),
            LongPacketType::ZeroRtt => {
                self.process_zero_rtt(data, &hdr, now, remote_addr, local_addr)
            }
        }
    }

    /// ハンドシェイク完了後に、ハンドシェイク中に送った経路検証を再送する
    ///
    /// ハンドシェイク中に送った PATH_CHALLENGE は、ピアが 1-RTT 鍵を持たない
    /// ため処理されないことがある。完了後に同じデータで再送し、応答を照合する。
    fn resend_initial_challenge_after_handshake(&mut self, now: Timestamp) {
        if self
            .paths
            .get(PathId::INITIAL)
            .is_none_or(|path| path.state != PathState::Validating)
        {
            return;
        }
        let Some(data) = self.paths.initial_path_mut().validation.resend_challenge() else {
            return;
        };
        let _ = self.emit_1rtt_path_challenge(PathId::INITIAL, data, now);
        let pto = self.path_validation_pto(PathId::INITIAL);
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::PathValidation {
                path_id: PathId::INITIAL,
            },
            deadline: now + pto,
        });
    }

    /// 認証に成功した Long Header の 4-tuple を初期パスへ反映する
    ///
    /// RFC 9000 Section 9.3 に基づき、送信先アドレスを変えてよいのは AEAD 復号に
    /// 成功したパケットだけである。さらに DCID が接続のローカル CID と一致する
    /// ことを確認し、別接続向けのパケットで初期パスを書き換えないようにする。
    /// 0.0.0.0 / :: は待ち受けソケットのバインド先でありパスのアドレスではないため、
    /// 受信パケットの宛先 (IP_PKTINFO) が具体アドレスなら未確定のローカルを埋める。
    fn commit_long_header_address(
        &mut self,
        dcid: &ConnectionId,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
        now: Timestamp,
    ) {
        // ハンドシェイク中のクライアントは NAT リバインディングで送信元ポートが
        // 変わることがある。サーバーの Initial を受け取る前は、クライアントの
        // Initial はサーバーがまだ知らない元の DCID を指したままなので、
        // ローカル CID との一致だけを要求すると 4-tuple を更新できない。
        // 更新しないとサーバーは古いポートへ再送し続け、ハンドシェイクが
        // タイムアウトする。増幅制限 (RFC 9000 Section 8.1) が適用される
        // ハンドシェイク中に限り、元の DCID を受けた場合も更新を許す。
        let matches_original_dcid = self.role == Role::Server
            && self.state == ConnectionState::Handshaking
            && dcid == &self.original_dcid;
        if dcid != &self.local_cid && !matches_original_dcid {
            return;
        }
        let initial = self.paths.initial_path_mut();
        let new_local = resolve_observed_local(initial.local_addr, local_addr);
        let changed = initial.remote_addr != remote_addr || initial.local_addr != new_local;
        initial.remote_addr = remote_addr;
        initial.local_addr = new_local;
        if !changed {
            return;
        }
        // 4-tuple の変更前に準備した Initial / Handshake のデータグラムは、
        // 古い宛先へ送るとピアに届かない。パケットの内容は 4-tuple に依存しない
        // ため、初期パス宛ての送信待ちデータグラムの宛先を新しい 4-tuple へ
        // 更新する。増幅制限は poll_output が送信時点で再評価する。
        for output in &mut self.output_queue {
            if let ConnectionOutput::SendDatagram {
                path_id,
                remote_addr: queued_remote,
                local_addr: queued_local,
                ..
            } = output
                && *path_id == PathId::INITIAL
            {
                *queued_remote = remote_addr;
                *queued_local = new_local;
            }
        }
        // ハンドシェイク中にクライアントのアドレスが変わった場合、サーバーは
        // 新しいアドレスの所有確認を開始する (RFC 9000 Section 9.3)。1-RTT 鍵が
        // あれば PATH_CHALLENGE を送れる。鍵が無い場合はアドレス更新だけを行い、
        // 鍵の導出後に届く Initial の再送で開始する。
        if self.role == Role::Server && self.state == ConnectionState::Handshaking {
            self.begin_handshake_rebind_validation(now);
        }
    }

    /// ハンドシェイク中のクライアント リバインディングでパス検証を開始する
    ///
    /// 新しい 4-tuple への最初のサーバー パケットに PATH_CHALLENGE を含めるため、
    /// PATH_CHALLENGE を 1-RTT の予約出力として積み、送信できるまでの間は
    /// 初期パス宛ての Initial / Handshake データグラムを保留する。
    fn begin_handshake_rebind_validation(&mut self, now: Timestamp) {
        if self.one_rtt_keys.is_none() {
            return;
        }
        let mut challenge = [0u8; 8];
        if aws_lc_rs::rand::fill(&mut challenge).is_err() {
            return;
        }
        {
            // 新しい 4-tuple の増幅予算を旧アドレスから引き継がない
            // (RFC 9000 Section 8.1 / Section 9.3.1)。このパケット自身の
            // 受信量はリセット後に加算する。初期パスは接続開始時に検証済みと
            // みなしているため、検証をやり直すと予算が 0 のままになる。
            // 加算しないと PATH_CHALLENGE も再送も送れない。
            let datagram_len = self.current_recv_datagram_len.unwrap_or_default() as u64;
            let path = self.paths.initial_path_mut();
            path.restart_address_validation();
            path.on_bytes_received(datagram_len);
            path.validation.restart();
            path.validation.request_challenge(challenge);
        }
        let _ = self.emit_1rtt_path_challenge(PathId::INITIAL, challenge, now);
        if self
            .paths
            .initial_path()
            .validation
            .unsent_challenge()
            .is_none()
        {
            // PATH_CHALLENGE を送信待ちへ積めた。Initial / Handshake の再送や
            // ACK だけの 1-RTT 出力より先に出すため、送信できるまで初期パス宛ての
            // 出力を保留する。
            self.defer_initial_datagrams_until_challenge = true;
            self.defer_path_datagrams_until_challenge = Some(PathId::INITIAL);
            let pto = self.path_validation_pto(PathId::INITIAL);
            self.output_queue.push_back(ConnectionOutput::SetTimer {
                id: TimerId::PathValidation {
                    path_id: PathId::INITIAL,
                },
                deadline: now + pto,
            });
        }
    }

    /// Version Negotiation パケットを処理する (RFC 9000 Section 6.2)
    ///
    /// クライアントのみが処理する。接続を中止し、提示されたバージョン一覧を
    /// `version_negotiation_versions` に記録する。上位層はこの一覧から
    /// 未試行の対応バージョンを選び、新しい接続試行を開始する。
    /// 以下の場合は破棄する:
    ///
    /// - サーバーが受信した場合 (VN はクライアントのみ処理)
    /// - 既に他のパケットを正常に処理済みの場合 (RFC 9000 Section 6.2 MUST)
    /// - VN の DCID / SCID が最初の Initial の SCID / DCID と一致しない場合
    ///   (スプーフィング対策。RFC 9000 Section 17.2.1 はサーバーに両方の
    ///   Connection ID のエコーを要求している)
    /// - VN が選択したバージョンを含む場合 (RFC 9000 Section 6.2 MUST)
    fn process_version_negotiation(
        &mut self,
        data: &[u8],
        _hdr: &LongHeader,
    ) -> Result<usize, Error> {
        // サーバーは VN パケットを処理しない
        if self.role != Role::Client {
            return Ok(data.len());
        }

        // RFC 9368 Section 4 MUST: VN に反応して開始した接続試行で受信した VN は
        // ダウングレード攻撃対策のため無視する。ログだけ残して接続を継続する。
        if self.vn_retry {
            tracing::info!("ignoring version negotiation received during vn retry attempt");
            return Ok(data.len());
        }

        // 既に他のパケットを正常に処理済みなら破棄する (RFC 9000 Section 6.2)
        // Retry も「処理したパケット」に含まれる。
        if self.handshake_keys.is_some()
            || self.initial_recv_pn_largest.is_some()
            || self.retry_received
            || self.version_negotiation_versions.is_some()
        {
            return Ok(data.len());
        }

        let Ok(vn) = packet::version_negotiation::VersionNegotiation::decode(data) else {
            return Ok(data.len());
        };

        // スプーフィング対策: サーバーは VN の DCID にクライアントの SCID を、
        // SCID にクライアントの DCID をコピーしなければならない
        // (RFC 9000 Section 17.2.1 MUST)。一致しない VN は破棄する。
        if vn.dcid != self.local_cid.as_bytes() || vn.scid != self.initial_dcid.as_bytes() {
            tracing::debug!("discarding version negotiation with mismatched connection IDs");
            return Ok(data.len());
        }

        // 自分の選択したバージョンを含む VN は破棄する (RFC 9000 Section 6.2 MUST)
        if vn.versions.contains(&self.version) {
            return Ok(data.len());
        }

        // qlog: Version Negotiation を受信した (qlog-quic-events-13 Section 5.1)
        // 互換バージョンが無い場合も chosen_version は付けない。
        if self.qlog_writer.is_some() {
            let time_ms = self.qlog_time_ms();
            let client_versions = self.supported_versions.clone();
            if let Some(ref mut w) = self.qlog_writer {
                w.on_version_information(time_ms, &client_versions, &vn.versions, None);
            }
        }

        // RFC 9000 Section 6.3: 予約バージョン (0x?a?a?a?a) は対応一覧に
        // 含まれないため、互換バージョンの選択では自然に無視される。
        let compatible = packet::version_negotiation::select_compatible_version(
            &vn.versions,
            &self.supported_versions,
        );
        let offered_names: Vec<&str> = vn
            .versions
            .iter()
            .map(|version| packet::version_name(*version))
            .collect();
        tracing::info!(
            "Version Negotiation received: server_versions={:?} ({:?}) compatible={:?}",
            vn.versions,
            offered_names,
            compatible
        );

        // RFC 9000 Section 6.2: 現在の接続試行を中止する。互換バージョンが
        // ある場合も transport は接続を再利用せず、上位層が新しい試行を開始する。
        self.version_negotiation_versions = Some(vn.versions);
        self.state = ConnectionState::Closed;
        if compatible.is_none() {
            self.push_event(ConnectionEvent::ConnectionClosed {
                error_code: 0,
                reason: "no compatible QUIC version in Version Negotiation".into(),
                kind: ConnectionCloseKind::Internal,
            });
        }
        Ok(data.len())
    }

    /// Retry パケットを処理する (RFC 9000 Section 17.2.5)
    ///
    /// クライアントのみ。Retry Integrity Tag を検証し、トークンを保存して
    /// Initial 鍵を再導出し、ClientHello を再送する。
    fn process_retry(
        &mut self,
        data: &[u8],
        hdr: &LongHeader,
        now: Timestamp,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) -> Result<usize, Error> {
        // クライアントのみ処理する
        if self.role != Role::Client {
            return Ok(data.len());
        }

        // 既に Retry を受信済みの場合は無視する (RFC 9000 Section 17.2.5.2)
        if self.retry_received {
            return Ok(data.len());
        }

        // 既に Initial または Retry を処理済みの場合は以後の Retry を破棄する
        // (RFC 9000 Section 17.2.5.2 MUST)。`handshake_keys` は Initial を復号した
        // だけの状態 (ServerHello 処理前で Handshake 鍵が未導出) を検出できないため、
        // Initial の受信記録とサーバー SCID の記録で判定する。
        if self.initial_recv_pn_largest.is_some() || self.server_initial_scid.is_some() {
            return Ok(data.len());
        }

        // SCID が元の DCID と同じ場合は無視する (RFC 9000 Section 17.2.5.1)
        if hdr.scid == self.original_dcid {
            return Ok(data.len());
        }

        // RFC 9000 Section 17.2.5.2: Retry の DCID はクライアントの SCID で
        // なければならない。Retry Integrity Tag は公開鍵から計算できるため、
        // DCID を検証しないとオフパス攻撃者が偽造 Retry で接続を妨害できる。
        if hdr.dcid != self.local_cid {
            tracing::debug!("ignoring retry with mismatched destination connection id");
            return Ok(data.len());
        }

        // 接続と異なるバージョンの Retry は無視する (RFC 9369 Section 4.1)。
        // バージョンは Initial と同じ値を使わなければならない。
        if hdr.version != self.version {
            tracing::debug!(
                "ignoring retry with mismatched version: expected={:#010x} got={:#010x}",
                self.version,
                hdr.version
            );
            return Ok(data.len());
        }

        // Retry Integrity Tag を検証する (RFC 9001 Section 5.8 / RFC 9369 Section 3.3.3)
        crypto::verify_retry_integrity_tag(hdr.version, data, &self.original_dcid)?;
        // Retry Integrity Tag の検証に成功したため、この 4-tuple を初期パスへ
        // 反映する。ただし DCID の一致は上で確認済みである。
        self.commit_long_header_address(&hdr.dcid, remote_addr, local_addr, now);
        // Retry は認証に成功して処理したパケットであり、アイドルタイマーの
        // リスタート対象になる (RFC 9000 Section 10.1)。
        self.received_valid_packet = true;
        self.last_valid_recv_path = Some(PathId::INITIAL);

        // Retry パケットからトークンを抽出する
        // Retry パケットのレイアウト:
        //   First Byte (1) || Version (4) || DCID Len (1) || DCID || SCID Len (1) || SCID
        //   || Retry Token (variable) || Retry Integrity Tag (16)
        let token_start = hdr.header_len;
        let token_end = data.len() - 16; // 末尾 16 バイトは Integrity Tag
        if token_start >= token_end {
            return Err(Error::InvalidData("Retry packet has empty token".into()));
        }
        let token = data[token_start..token_end].to_vec();

        // qlog: Retry を受信した (qlog-quic-events-13 Section 5.1)
        // client_versions は本実装が提示する v1 のみ、chosen_version は
        // Retry パケットのバージョン。
        if self.qlog_writer.is_some() {
            let time_ms = self.qlog_time_ms();
            let client_versions = self.supported_versions.clone();
            let server_versions = [hdr.version];
            if let Some(ref mut w) = self.qlog_writer {
                w.on_version_information(
                    time_ms,
                    &client_versions,
                    &server_versions,
                    Some(hdr.version),
                );
            }
        }

        // 状態を更新する
        self.retry_received = true;
        self.retry_token = token;
        // RFC 9000 Section 7.3: サーバーは retry_source_connection_id で
        // Retry の SCID を通知する。受信時の検証に備えて保持する。
        self.retry_scid = Some(hdr.scid.clone());

        // DCID を Retry の SCID に更新する
        self.peer_cid = hdr.scid.clone();
        if let Some(path) = self.paths.get_mut(PathId::INITIAL) {
            path.peer_cid = Some(hdr.scid.clone());
        }

        // Initial 鍵を新しい DCID で再導出する (RFC 9001 Section 5.2)
        self.initial_dcid = hdr.scid.clone();
        self.initial_keys = Some(InitialKeys::new(
            self.version,
            &self.initial_dcid,
            Role::Client,
        )?);

        // CRYPTO ストリームをリセットして ClientHello を再送する
        // crypto_sent_initial に保存されたデータを crypto_send_initial に戻す
        let crypto_data = self.crypto_sent_initial.clone();
        self.crypto_send_initial = crypto_data;
        self.crypto_send_initial_offset = 0;
        self.crypto_retransmit_initial.clear();

        // パケット番号は Initial / 0-RTT を含む全空間で維持する。
        // RFC 9000 Section 17.2.5.3 は Retry 後の番号リセットを禁止する
        // (MUST NOT)。回復状態と CRYPTO offset のリセットとは区別する。

        // RFC 9002 Section 6.3: Retry を受信したクライアントは輻輳制御と
        // 損失回復の状態をリセットし、保留中のタイマーも破棄する。
        // 破棄したパケットの bytes_in_flight は、直後に輻輳制御を作り直すため
        // 新しい CC の初期値 (0) に含まれる。旧 CC への通知は不要。
        self.initial_sent_packets = SentPackets::new();

        // Application Data 空間 (0-RTT) で送信済みのパケットも回復状態の対象から
        // 外れる。STREAM フレームは 1-RTT で送り直せるようロスト扱いにし、
        // 制御フレームは再送キューへ戻す。
        let mut retry_lost_streams: Vec<(u64, u64, usize, bool, u32)> = Vec::new();
        let mut retry_lost_control_frames: Vec<SentFrameInfo> = Vec::new();
        if let Some(path) = self.paths.get_mut(PathId::INITIAL) {
            let drained = path.sent_packets.drain_all();
            for packet in drained {
                for frame in packet.frames {
                    match frame {
                        SentFrameInfo::Stream {
                            stream_id,
                            offset,
                            length,
                            fin,
                            retransmission_count,
                        } => retry_lost_streams.push((
                            stream_id,
                            offset,
                            length,
                            fin,
                            retransmission_count,
                        )),
                        SentFrameInfo::Ack { .. }
                        | SentFrameInfo::PathAck
                        | SentFrameInfo::Other => {}
                        other => retry_lost_control_frames.push(other),
                    }
                }
            }
        }
        // 輻輳制御・RTT 推定・損失検出器を作り直す (RFC 9002 Section 6.3)
        self.paths.reset_recovery_for_retry(PathId::INITIAL)?;
        // 保留中のタイマーを破棄する (RFC 9002 Section 6.3)
        self.clear_loss_detection_timer(PathId::INITIAL);
        self.output_queue.push_back(ConnectionOutput::ClearTimer {
            id: TimerId::Pacing {
                path_id: PathId::INITIAL,
            },
        });
        self.pto_probe_paths.clear();

        for (stream_id, offset, length, fin, retransmission_count) in retry_lost_streams {
            // Retry はパケットロスではないが、0-RTT で送ったデータは 1-RTT で
            // 送り直す必要がある。時間閾値ロストとして再送キューへ戻す。
            //
            // ここでは終端遷移を試みない。Retry を受けた時点でクライアントは
            // 0-RTT パケットの ACK をまだ受け取っておらず、サーバーが 0-RTT を
            // 受理したかも確定していない。Retry より前に 0-RTT の ACK は成立
            // しないため、この再キューで ACK 済みになる範囲は無く、終端遷移の
            // 判定材料が変わらない。再送したデータの ACK またはロスト判定の
            // 経路で終端遷移を試みる。
            self.streams.mark_lost(
                stream_id,
                offset,
                length,
                fin,
                RetxMeta {
                    original_path: PathId::INITIAL,
                    loss_reason: LossReason::TimeThreshold,
                    retransmission_count,
                },
            );
        }
        self.retransmit_lost_control_frames(retry_lost_control_frames, now);

        // 新しい Initial パケットを送信する
        self.emit_packets(now)?;

        Ok(data.len())
    }

    /// 0-RTT パケットを処理する (RFC 9001 Section 4.6)
    ///
    /// サーバーのみ。0-RTT 鍵で復号し、アプリケーションデータフレームを処理する。
    fn process_zero_rtt(
        &mut self,
        data: &[u8],
        hdr: &LongHeader,
        now: Timestamp,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) -> Result<PacketOutcome, Error> {
        // Length フィールドをパースしてパケットの終端を求める。鍵が無い場合でも
        // 連結された後続パケットを処理できるよう、先に終端を確定する
        // (RFC 9000 Section 12.2)。
        let (pn_offset, packet_end) = long_header_packet_end(data, hdr.header_len)?;

        // クライアントは 0-RTT パケットを受信しない
        if self.role == Role::Client {
            return Ok(PacketOutcome::Processed(packet_end));
        }

        // 0-RTT 鍵がなければ、このパケットだけをスキップする
        let zk = match self.zero_rtt_keys.as_ref() {
            Some(k) => k,
            None => {
                return Ok(PacketOutcome::Processed(packet_end));
            }
        };

        // RFC 9001 Section 4.6.2: サーバーが 0-RTT を拒否した場合、0-RTT
        // パケットを処理してはならない (MUST NOT)。0-RTT 鍵は TLS が early_data を
        // 受理した場合にだけ `advance_tls` で設定されるため、鍵の存在が受理の
        // 判定になっている。

        // draft-ietf-quic-reliable-stream-reset-11 Section 3:
        // "When the server accepts 0-RTT data, the server MUST NOT disable this
        //  extension on the resumed connection."
        //
        // サーバーは自身の設定でこの拡張を広告するかを決める。0-RTT ではクライアントは
        // 前回セッションでサーバーが広告したかどうかの記憶に基づいて RESET_STREAM_AT を
        // 送るため (-11 Section 3)、サーバーが今回この拡張を広告しない
        // (local_params.reset_stream_at = false) 構成のまま 0-RTT データを受理すると
        // 上記 MUST に反する。本実装はその構成では 0-RTT パケットを silent に discard
        // して 0-RTT データを受理しないことで MUST を守る (0-RTT を受理しない選択自体は
        // MUST 違反ではない)。本パケット (packet_end まで) のみを破棄し、同一データグラム
        // 内にコアレスされた 1-RTT 等の後続パケットは処理を継続する。
        //
        // (アプリケーション設定で TLS 側の max_early_data_size > 0 と QUIC 側の
        //  reset_stream_at = false が同居している状態が根本原因。tobi-platform の
        //  QuicServer::bind_with_config が起動時にこの組み合わせを拒否するため、
        //  通常の高レベル API 経由では到達しない。transport を直接使う場合の
        //  防御としてここで破棄する。)
        if !self.local_params.reset_stream_at {
            return Ok(PacketOutcome::Processed(packet_end));
        }

        // RFC 9001 Section 9.2: 0-RTT のリプレイ防御はサーバーの責務である。
        // `replay_filter` が未設定のまま受理すると、同じセッションチケットを
        // 使った再送を検出できない。安全側に倒し、フィルターが無い場合は
        // 0-RTT を受理しない。受理しなくても 0-RTT の STREAM データは
        // 1-RTT で再送されるため、データは失われない。
        if self.replay_filter.is_none() {
            return Ok(PacketOutcome::Processed(packet_end));
        }

        // Header Protection 除去 (rustls)
        let mut pkt = data[..packet_end].to_vec();
        let sample_offset = pn_offset + 4;
        if pkt.len() < sample_offset + zk.header.sample_len() {
            // このパケットだけをスキップし、連結された後続パケットは処理する
            return Ok(PacketOutcome::Processed(packet_end));
        }
        let sample = pkt[sample_offset..sample_offset + zk.header.sample_len()].to_vec();
        // rustls の decrypt_in_place は first byte と PN bytes を同時に処理する
        // 借用の分割が必要
        let pn_max_len = 4.min(pkt.len() - pn_offset);
        let (first_part, rest) = pkt.split_at_mut(pn_offset);
        if let Err(error) =
            zk.header
                .decrypt_in_place(&sample, &mut first_part[0], &mut rest[..pn_max_len])
        {
            // Header Protection の解除に失敗したパケットだけを破棄し、
            // 連結された後続パケットの処理を続ける (RFC 9000 Section 12.2)。
            return Ok(PacketOutcome::Dropped {
                consumed: packet_end,
                error: Error::InvalidData(format!("0-RTT header protection failed: {error:?}")),
            });
        }
        let pn_len = (pkt[0] & 0x03) + 1;

        // パケット番号復元 (Application PN 空間を共有、初期パスで処理)
        let (truncated, _) = match number::decode_truncated(&pkt[pn_offset..], pn_len) {
            Ok(decoded) => decoded,
            Err(error) => {
                return Ok(PacketOutcome::Dropped {
                    consumed: packet_end,
                    error,
                });
            }
        };
        let path = self.paths.initial_path();
        let largest = path.recv_pn_largest;
        let full_pn = number::decode_full(largest, u64::from(truncated), u32::from(pn_len) * 8);

        // RFC 9000 Section 12.3: パケット番号は 0 から 2^62-1。復元結果が範囲外の
        // パケットは上限を守らないピアからの入力なので、復号前に破棄する。
        if full_pn > number::MAX_PACKET_NUMBER {
            return Ok(PacketOutcome::Processed(packet_end));
        }

        let header_end = pn_offset + pn_len as usize;
        let aad = &pkt[..header_end];

        // AEAD 復号 (rustls)
        let mut payload = pkt[header_end..].to_vec();
        let decrypt_result = zk.packet.decrypt_in_place(full_pn, aad, &mut payload);
        let plaintext_len = match decrypt_result {
            Ok(plaintext) => plaintext.len(),
            Err(_) => {
                // RFC 9001 Section 6.6: 認証失敗数を integrity limit 用に数える
                self.record_aead_auth_failure();
                // 復号に失敗したパケットだけを破棄し、連結された後続パケットの
                // 処理を続ける (RFC 9000 Section 12.2 MUST)。
                return Ok(PacketOutcome::Dropped {
                    consumed: packet_end,
                    error: Error::InvalidData("0-RTT decryption failed".into()),
                });
            }
        };

        // RFC 9000 Section 17.2: パケット保護とヘッダ保護の両方を除去した後、
        // Reserved Bits (0x0c) が非ゼロなら PROTOCOL_VIOLATION とする (MUST)。
        // AEAD 復号に成功した 0-RTT だけが初期パスの 4-tuple を更新できる
        // (RFC 9000 Section 9.3)。
        self.commit_long_header_address(&hdr.dcid, remote_addr, local_addr, now);
        self.record_authenticated_received_datagram(remote_addr, local_addr);

        header::check_long_header_reserved_bits(pkt[0])?;

        // 重複パケット検出
        let path = self.paths.initial_path();
        if path.ack_tracker.is_already_received(full_pn) {
            return Ok(PacketOutcome::Processed(packet_end));
        }

        // リプレイフィルターチェック (RFC 9001 Section 9.2)
        // 最初の 0-RTT パケットでフィルターを適用する (以降は同一接続として許可)
        if !self.zero_rtt_accepted {
            // 上の検査で `replay_filter` が `Some` であることは保証済みである。
            let Some(filter) = self.replay_filter.as_ref() else {
                return Ok(PacketOutcome::Processed(packet_end));
            };
            // リプレイ識別子には ClientHello の PSK identity (セッションチケット)
            // のハッシュを使う (RFC 9001 Section 9.2)。同じチケットを再利用した
            // 別接続では同じ識別子になるため、接続をまたいだリプレイを検出できる。
            // チケットを特定できない場合は、リプレイ検出を行えないため 0-RTT を
            // 受理しない (安全側に倒す)。
            let Some(ticket_hash) = self.zero_rtt_ticket_hash.as_deref() else {
                return Ok(PacketOutcome::Processed(packet_end));
            };
            if !filter.check(ticket_hash) {
                // リプレイ検出: 0-RTT パケットを無視する
                return Ok(PacketOutcome::Processed(packet_end));
            }
        }

        // パケット番号を記録する
        let path = self.paths.initial_path_mut();
        path.update_recv_pn(full_pn);
        path.ack_tracker.record_received(full_pn, true, now);

        self.zero_rtt_accepted = true;

        // フレーム処理 (0-RTT で許可されるフレームのみ)
        // RFC 9000 Section 12.4: 0-RTT では ACK, CRYPTO, HANDSHAKE_DONE,
        // NEW_TOKEN, PATH_RESPONSE, RETIRE_CONNECTION_ID フレームは送信不可
        let plaintext_data = payload[..plaintext_len].to_vec();
        self.process_frames(
            &plaintext_data,
            EncryptionLevel::ZeroRtt,
            PathId::INITIAL,
            None,
            now,
        )?;
        // フレームをすべて正常に処理できたパケットだけがアイドルタイマーの
        // リスタート対象になる (RFC 9000 Section 10.1)
        self.received_valid_packet = true;
        self.last_valid_recv_path = Some(PathId::INITIAL);

        Ok(PacketOutcome::Processed(packet_end))
    }

    /// Initial パケットを処理する (aws-lc-rs ベースの鍵で復号)
    ///
    /// `datagram_len` はデータグラム全体の長さ。サーバーは 1200 バイト未満の
    /// データグラムで運ばれた Initial を復号せずに破棄する (RFC 9000 Section 14.1)。
    fn process_initial(
        &mut self,
        data: &[u8],
        hdr: &LongHeader,
        datagram_len: usize,
        now: Timestamp,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) -> Result<PacketOutcome, Error> {
        // 破棄するパケット自身の長さを確定してから以降の処理を行うため、Token と
        // Length を先にパースする (どちらも Header Protection の対象外で平文のまま読める)

        // Token と Length をパース
        let mut pos = hdr.header_len;
        let (token_len, n) = VarInt::decode(&data[pos..])?;
        pos += n;
        let token_start = pos;
        let tlen = usize::try_from(token_len.as_u64())
            .map_err(|_| Error::InvalidData("Initial token length exceeds usize".into()))?;
        // Token Length がデータグラム残長を超える場合は不完全パケットとして破棄する。
        // Token Length は可変長整数で攻撃者が任意に符号化できる (RFC 9000 Section 17.2.2)。
        // 不正な Initial の破棄は許容される (RFC 9000 Section 11.1)。
        // この時点で pos <= data.len() が保証されるため data.len() - pos は underflow しない。
        if tlen > data.len() - pos {
            return Err(Error::Incomplete {
                needed: tlen - (data.len() - pos),
            });
        }
        pos += tlen;

        let (payload_length, n) = VarInt::decode(&data[pos..])?;
        pos += n;
        let pn_offset = pos;
        let payload_len = usize::try_from(payload_length.as_u64())
            .map_err(|_| Error::InvalidData("Initial payload length exceeds usize".into()))?;
        let packet_end = pos
            .checked_add(payload_len)
            .ok_or_else(|| Error::InvalidData("Initial packet length overflow".into()))?;

        if data.len() < packet_end {
            return Err(Error::Incomplete {
                needed: packet_end - data.len(),
            });
        }

        // クライアントはサーバーが送信した Initial の非ゼロ Token Length を
        // 受理してはならない (RFC 9000 Section 17.2.2 MUST)。仕様は破棄を
        // 求めており、接続を閉じる必要はない。破棄はこのパケットに留め、
        // 同一データグラム内に連結された後続パケットの処理は継続する。
        if self.role == Role::Client && tlen > 0 {
            return Ok(PacketOutcome::Dropped {
                consumed: packet_end,
                error: Error::InvalidData(
                    "client dropped Initial packet with non-zero token length".into(),
                ),
            });
        }

        // RFC 9001 Section 4.9.1: Initial 鍵を破棄した後の Initial パケットは
        // 復号もフレーム処理もせずに silent discard する。再導出すると、
        // 公開鍵から Initial 鍵を計算できる攻撃者が確立済み接続へ
        // CONNECTION_CLOSE や CRYPTO を注入できてしまう。
        if self.initial_keys_discarded {
            return Ok(PacketOutcome::Processed(packet_end));
        }

        // RFC 9000 Section 7.2: クライアントは最初に受理したサーバー Initial の
        // Source Connection ID を記録し、以後に受信する Initial の SCID が
        // それと異なる場合は破棄する (MUST)。サーバーも同様に、最初に受理した
        // クライアント Initial と異なる SCID の Initial を破棄する。
        // 受理の成否 (復号成功) に関わらず状態を変えないよう、復号より前に判定する。
        match self.role {
            Role::Client => {
                if let Some(ref server_scid) = self.server_initial_scid
                    && hdr.scid != *server_scid
                {
                    return Ok(PacketOutcome::Processed(packet_end));
                }
            }
            Role::Server => {
                if let Some(ref peer_scid) = self.peer_initial_scid
                    && hdr.scid != *peer_scid
                {
                    return Ok(PacketOutcome::Processed(packet_end));
                }
            }
        }

        // サーバーは 1200 バイト未満のデータグラムで運ばれた Initial を破棄する
        // (RFC 9000 Section 14.1 MUST)。CONNECTION_CLOSE は送らず silent に破棄し、
        // 不正パケットへの応答で増幅攻撃に加担しない。破棄はこの Initial に留め、
        // 同一データグラム内にコアレスされた後続パケットの処理は継続する。
        // 鍵導出や状態遷移より前に判定し、破棄した Initial が接続状態へ影響しないようにする。
        if self.role == Role::Server && datagram_len < MIN_INITIAL_DATAGRAM_SIZE {
            return Ok(PacketOutcome::Processed(packet_end));
        }

        // サーバー側: トークンプロバイダが設定されている場合にトークンを検証する
        // (RFC 9000 Section 8.1.3)
        if self.role == Role::Server
            && tlen > 0
            && let Some(ref provider) = self.token_provider
        {
            let token_data = &data[token_start..token_start + tlen];
            // RFC 9369 Section 5: トークンの発行バージョンと接続のバージョンが
            // 一致する場合のみアドレス検証済みとして扱う (MUST)。
            if provider.validate_token(token_data, &remote_addr, hdr.version) {
                self.address_validated = true;
                self.initial_token_validated = true;
            }
        }

        // サーバー側で初めて受信した場合に Initial 鍵を導出する。
        // 送信鍵はネゴシエート済みバージョン、受信鍵はこのパケットのバージョンで
        // 導出する。RFC 9368 Section 2.3 の互換バージョン交渉では、最初の flight が
        // クライアントの Chosen Version で届くため両方の受信鍵を持つ。
        if self.initial_keys.is_none() && self.role == Role::Server {
            let mut keys = match InitialKeys::new(self.version, &self.initial_dcid, Role::Server) {
                Ok(keys) => keys,
                Err(error) => {
                    // Initial 鍵の導出に失敗したパケットだけを破棄し、
                    // 連結された後続パケットの処理を続ける
                    // (RFC 9000 Section 12.2 MUST)。
                    return Ok(PacketOutcome::Dropped {
                        consumed: packet_end,
                        error,
                    });
                }
            };
            if hdr.version != self.version
                && let Err(error) =
                    keys.add_recv_version(hdr.version, &self.initial_dcid, Role::Server)
            {
                return Ok(PacketOutcome::Dropped {
                    consumed: packet_end,
                    error,
                });
            }
            self.initial_keys = Some(keys);
            // qlog: 状態遷移 Idle → Handshaking (サーバー)
            if self.state == ConnectionState::Idle && self.qlog_writer.is_some() {
                let time_ms = self.qlog_time_ms();
                if let Some(ref mut w) = self.qlog_writer {
                    w.on_connection_state_updated(time_ms, "idle", "handshaking");
                }
            }
            if self.state == ConnectionState::Idle {
                self.state = ConnectionState::Handshaking;
                // ハンドシェイク中もアイドルタイマーを張れるよう、ローカルの
                // max_idle_timeout を暫定値として使う。クライアントと同様、
                // ピアの値は `maybe_apply_peer_params` で確定する。
                // タイマーの開始は `receive` 末尾の受信処理に任せる。
                self.idle_timeout_ms = self.local_params.max_idle_timeout;
            }
        }

        let ik = match self.initial_keys.as_ref() {
            Some(keys) => keys,
            None => {
                return Ok(PacketOutcome::Dropped {
                    consumed: packet_end,
                    error: Error::InvalidData("no initial keys".into()),
                });
            }
        };
        // 受信鍵はパケットのバージョンで選ぶ。互換バージョン交渉では
        // クライアントの最初の flight が Chosen Version で届く。
        // 想定外のバージョンは受信鍵が無いため破棄する。
        let Some(recv_keys) = ik.recv_for(hdr.version) else {
            return Ok(PacketOutcome::Processed(packet_end));
        };

        // Header Protection 除去 (aws-lc-rs)
        let mut pkt = data[..packet_end].to_vec();
        let pn_len = match protection::remove_header_protection(&mut pkt, pn_offset, &recv_keys.hp)
        {
            Ok(pn_len) => pn_len,
            Err(error) => {
                return Ok(PacketOutcome::Dropped {
                    consumed: packet_end,
                    error,
                });
            }
        };

        // パケット番号復元 (Initial PN 空間 - RFC 9000 Section 12.3)
        let (truncated, _) = match number::decode_truncated(&pkt[pn_offset..], pn_len) {
            Ok(decoded) => decoded,
            Err(error) => {
                return Ok(PacketOutcome::Dropped {
                    consumed: packet_end,
                    error,
                });
            }
        };
        let largest = self.initial_recv_pn_largest;
        let full_pn = number::decode_full(largest, u64::from(truncated), u32::from(pn_len) * 8);

        // RFC 9000 Section 12.3: パケット番号は 0 から 2^62-1。復元結果が範囲外の
        // パケットは上限を守らないピアからの入力なので、復号前に破棄する。
        if full_pn > number::MAX_PACKET_NUMBER {
            return Ok(PacketOutcome::Processed(packet_end));
        }

        let header_end = pn_offset + pn_len as usize;
        let aad = pkt[..header_end].to_vec();

        // AEAD 復号 (aws-lc-rs)
        let pn_nonce = nonce::compute_nonce(recv_keys.aead.iv(), full_pn);
        let mut payload = pkt[header_end..].to_vec();
        let decrypt_result =
            protection::decrypt_payload(&recv_keys.aead, &pn_nonce, &aad, &mut payload);
        let plaintext_len = match decrypt_result {
            Ok(len) => len,
            Err(e) => {
                // RFC 9001 Section 6.6: 認証失敗数を integrity limit 用に数える
                self.record_aead_auth_failure();
                // 復号に失敗したパケットだけを破棄し、連結された後続パケットの
                // 処理を続ける (RFC 9000 Section 12.2 MUST)。
                return Ok(PacketOutcome::Dropped {
                    consumed: packet_end,
                    error: e,
                });
            }
        };

        // RFC 9000 Section 17.2: パケット保護とヘッダ保護の両方を除去した後、
        // Reserved Bits (0x0c) が非ゼロなら PROTOCOL_VIOLATION とする (MUST)。
        // 復号に成功したヘッダ (pkt[0]) だけを検査する (RFC 9001 Section 9.5)。
        // AEAD 復号に成功した Initial だけが初期パスの 4-tuple を更新できる
        // (RFC 9000 Section 9.3)。Reserved Bits の検査より前に記録するのは、
        // 認証済みパケットの受信バイトを増幅予算へ確実に反映するためである。
        self.commit_long_header_address(&hdr.dcid, remote_addr, local_addr, now);
        self.record_authenticated_received_datagram(remote_addr, local_addr);

        header::check_long_header_reserved_bits(pkt[0])?;

        // 重複パケット検出 (RFC 9000 Section 13.2.3)
        if self.initial_ack_tracker.is_already_received(full_pn) {
            return Ok(PacketOutcome::Processed(packet_end));
        }

        // qlog: packet_received (Initial)
        //
        // この記録は下の `process_frames` より前に出すため、このパケットの
        // CRYPTO フレームで初めて受け取るピアの `ack_delay_exponent` はまだ
        // `peer_params` に反映されていない。その場合は既定値 3 で ms 換算する。
        // qlog の ACK Delay は診断用の値であり、RTT 計算に使う ACK Delay は
        // `process_ack` が改めて変換するため、この制約は qlog 出力だけに限られる。
        if self.qlog_writer.is_some() {
            let time_ms = self.qlog_time_ms();
            let qlog_frames =
                decode_frames_for_qlog(&payload[..plaintext_len], self.peer_ack_delay_exponent());
            let qlog_header = qlog::PacketHeader {
                packet_type: qlog::PacketType::Initial,
                packet_number: full_pn,
                dcid: qlog::cid_to_hex(&hdr.dcid),
                scid: Some(qlog::cid_to_hex(&hdr.scid)),
                version: Some(format!("{:08x}", hdr.version)),
                length: Some(packet_end),
            };
            if let Some(ref mut w) = self.qlog_writer {
                w.on_packet_received(time_ms, &qlog_header, &qlog_frames, packet_end);
            }
        }
        // 観測イベント: パケット受信
        self.observe(ConnectionObservationEvent::PacketReceived {
            path_id: PathId::INITIAL,
            packet_number: full_pn,
            size: packet_end,
        });

        // 最初の Initial の SCID をロールごとに記録する (RFC 9000 Section 7.2 / 7.3)。
        //
        // - クライアント: サーバーの SCID を peer_cid として採用し、
        //   initial_source_connection_id の検証に使う。2 通目以降で異なる SCID を
        //   持つ Initial は復号前に破棄済みである。
        // - サーバー: クライアントの SCID を記録し、クライアントの
        //   initial_source_connection_id の検証に使う。
        match self.role {
            Role::Client => {
                if self.server_initial_scid.is_none() {
                    self.server_initial_scid = Some(hdr.scid.clone());
                    self.peer_cid = hdr.scid.clone();
                    if let Some(path) = self.paths.get_mut(PathId::INITIAL) {
                        path.peer_cid = Some(hdr.scid.clone());
                    }
                }
            }
            Role::Server => {
                if self.peer_initial_scid.is_none() {
                    self.peer_initial_scid = Some(hdr.scid.clone());
                }
            }
        }

        // フレーム処理
        let outcome = self.process_frames(
            &payload[..plaintext_len],
            EncryptionLevel::Initial,
            PathId::INITIAL,
            None,
            now,
        )?;
        let ack_eliciting = outcome.ack_eliciting;
        // フレームをすべて正常に処理できたパケットだけがアイドルタイマーの
        // リスタート対象になる (RFC 9000 Section 10.1)
        self.received_valid_packet = true;
        self.last_valid_recv_path = Some(PathId::INITIAL);

        // 受信記録 (Initial PN 空間 - RFC 9000 Section 12.3)
        match self.initial_recv_pn_largest {
            Some(largest) if full_pn > largest => self.initial_recv_pn_largest = Some(full_pn),
            None => self.initial_recv_pn_largest = Some(full_pn),
            _ => {}
        }
        self.initial_ack_tracker
            .record_received(full_pn, ack_eliciting, now);
        if ack_eliciting {
            // RFC 9000 Section 13.2.1: Initial / Handshake 空間の ACK は即時に返す。
            // Application Data 空間の 2 パケット閾値を流用しない。
            self.initial_ack_tracker.request_immediate_ack();
        }

        // TLS 状態を進めて次レベルの鍵を導出する
        // (コアレシングされた Handshake/1-RTT パケットの復号に必要)
        self.advance_tls(now)?;

        Ok(PacketOutcome::Processed(packet_end))
    }

    /// Handshake パケットを処理する (rustls ベースの鍵で復号)
    fn process_handshake(
        &mut self,
        data: &[u8],
        hdr: &LongHeader,
        now: Timestamp,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) -> Result<PacketOutcome, Error> {
        // Length をパースしてパケットの終端を求める。鍵が無い場合でも
        // 連結された後続パケットを処理できるよう、先に終端を確定する
        // (RFC 9000 Section 12.2)。
        let (pn_offset, packet_end) = long_header_packet_end(data, hdr.header_len)?;
        if self.handshake_keys.is_none() {
            // 鍵がまだない場合は、このパケットだけをスキップする
            return Ok(PacketOutcome::Processed(packet_end));
        }

        let mut pkt = data[..packet_end].to_vec();

        // Header Protection 除去 (rustls)
        let hk = match self.handshake_keys.as_ref() {
            Some(keys) => keys,
            None => {
                return Ok(PacketOutcome::Dropped {
                    consumed: packet_end,
                    error: Error::InvalidData("no handshake keys".into()),
                });
            }
        };
        let pn_len = match remove_hp_rustls(&mut pkt, pn_offset, &*hk.remote_header, true) {
            Ok(pn_len) => pn_len,
            Err(error) => {
                return Ok(PacketOutcome::Dropped {
                    consumed: packet_end,
                    error,
                });
            }
        };

        // パケット番号復元 (Handshake PN 空間 - RFC 9000 Section 12.3)
        let (truncated, _) = match number::decode_truncated(&pkt[pn_offset..], pn_len) {
            Ok(decoded) => decoded,
            Err(error) => {
                return Ok(PacketOutcome::Dropped {
                    consumed: packet_end,
                    error,
                });
            }
        };
        let largest = self.handshake_recv_pn_largest;
        let full_pn = number::decode_full(largest, u64::from(truncated), u32::from(pn_len) * 8);

        // RFC 9000 Section 12.3: パケット番号は 0 から 2^62-1。復元結果が範囲外の
        // パケットは上限を守らないピアからの入力なので、復号前に破棄する。
        if full_pn > number::MAX_PACKET_NUMBER {
            return Ok(PacketOutcome::Processed(packet_end));
        }

        let header_end = pn_offset + pn_len as usize;
        let aad = pkt[..header_end].to_vec();

        // AEAD 復号 (rustls)
        let hk = match self.handshake_keys.as_ref() {
            Some(keys) => keys,
            None => {
                return Ok(PacketOutcome::Dropped {
                    consumed: packet_end,
                    error: Error::InvalidData("no handshake keys".into()),
                });
            }
        };
        let mut ciphertext = pkt[header_end..].to_vec();
        let decrypt_result = match hk.remote_packet.as_ref() {
            Some(remote_packet) => remote_packet.decrypt_in_place(full_pn, &aad, &mut ciphertext),
            None => {
                return Ok(PacketOutcome::Dropped {
                    consumed: packet_end,
                    error: Error::InvalidData("no handshake remote packet key".into()),
                });
            }
        };
        let plaintext = match decrypt_result {
            Ok(plaintext) => plaintext.to_vec(),
            Err(_) => {
                // RFC 9001 Section 6.6: 認証失敗数を integrity limit 用に数える
                self.record_aead_auth_failure();
                // 復号に失敗したパケットだけを破棄し、連結された後続パケットの
                // 処理を続ける (RFC 9000 Section 12.2 MUST)。
                return Ok(PacketOutcome::Dropped {
                    consumed: packet_end,
                    error: Error::InvalidData("handshake decryption failed".into()),
                });
            }
        };

        // RFC 9000 Section 17.2: パケット保護とヘッダ保護の両方を除去した後、
        // Reserved Bits (0x0c) が非ゼロなら PROTOCOL_VIOLATION とする (MUST)。
        // AEAD 復号に成功した Handshake だけが初期パスの 4-tuple を更新できる
        // (RFC 9000 Section 9.3)。NAT リバインディング中の Handshake も
        // 認証済みであれば受け入れる。
        self.commit_long_header_address(&hdr.dcid, remote_addr, local_addr, now);
        self.record_authenticated_received_datagram(remote_addr, local_addr);

        header::check_long_header_reserved_bits(pkt[0])?;

        // 重複パケット検出 (RFC 9000 Section 13.2.3)
        if self.handshake_ack_tracker.is_already_received(full_pn) {
            return Ok(PacketOutcome::Processed(packet_end));
        }

        // qlog: packet_received (Handshake)
        if self.qlog_writer.is_some() {
            let time_ms = self.qlog_time_ms();
            let qlog_frames = decode_frames_for_qlog(&plaintext, self.peer_ack_delay_exponent());
            let qlog_header = qlog::PacketHeader {
                packet_type: qlog::PacketType::Handshake,
                packet_number: full_pn,
                dcid: qlog::cid_to_hex(&hdr.dcid),
                scid: Some(qlog::cid_to_hex(&hdr.scid)),
                version: Some(format!("{:08x}", hdr.version)),
                length: Some(packet_end),
            };
            if let Some(ref mut w) = self.qlog_writer {
                w.on_packet_received(time_ms, &qlog_header, &qlog_frames, packet_end);
            }
        }
        // 観測イベント: パケット受信
        self.observe(ConnectionObservationEvent::PacketReceived {
            path_id: PathId::INITIAL,
            packet_number: full_pn,
            size: packet_end,
        });

        // フレーム処理
        let outcome = self.process_frames(
            &plaintext,
            EncryptionLevel::Handshake,
            PathId::INITIAL,
            None,
            now,
        )?;
        let ack_eliciting = outcome.ack_eliciting;
        // フレームをすべて正常に処理できたパケットだけがアイドルタイマーの
        // リスタート対象になる (RFC 9000 Section 10.1)
        self.received_valid_packet = true;
        self.last_valid_recv_path = Some(PathId::INITIAL);

        // RFC 9000 Section 8.1: Handshake 鍵で保護されたパケットの正常な処理で
        // ピアが ServerHello を受信したと分かる。Finished を待つと、大きな
        // 証明書チェーンの途中で増幅予算を使い切った接続が進行できない。
        if self.role == Role::Server {
            self.address_validated = true;
        }

        // 受信記録 (Handshake PN 空間 - RFC 9000 Section 12.3)
        match self.handshake_recv_pn_largest {
            Some(largest) if full_pn > largest => self.handshake_recv_pn_largest = Some(full_pn),
            None => self.handshake_recv_pn_largest = Some(full_pn),
            _ => {}
        }
        self.handshake_ack_tracker
            .record_received(full_pn, ack_eliciting, now);

        // RFC 9001 Section 4.9.1: サーバーは最初の Handshake パケットを正常に
        // 処理した時点で Initial 鍵を破棄する。実際の破棄は emit_packets の
        // 末尾で行い、このフラグで「処理済み」を記録する。
        self.initial_handshake_processed = true;

        // TLS 状態を進めて次レベルの鍵を導出する
        // (コアレシングされた 1-RTT パケットの復号に必要)
        self.advance_tls(now)?;

        Ok(PacketOutcome::Processed(packet_end))
    }

    /// Short Header (1-RTT) パケットを処理する (rustls ベース)
    ///
    /// DCID からパスを特定し、Multipath PPN nonce で復号する
    /// (RFC 10069 Section 2.4)。
    fn process_short_header(
        &mut self,
        data: &[u8],
        now: Timestamp,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) -> Result<usize, Error> {
        // RFC 9001 Section 5.7: サーバーは TLS 完了前に 1-RTT を処理しては
        // ならない。ACK するとクライアントが Handshake 鍵を廃棄できるため、
        // Finished の損失を回復できなくなる。同節の保存は任意なので破棄し、
        // ハンドシェイク後の再送を待つ。仕様変更時には受理条件を見直す。
        if self.role == Role::Server && self.state == ConnectionState::Handshaking {
            return Err(Error::InvalidData("TLS handshake is not complete".into()));
        }
        if self.one_rtt_keys.is_none() {
            return Err(Error::InvalidData("no 1-RTT keys".into()));
        }

        let dcid_len = self.local_cid.len();
        // RFC 9287 Section 3: 自分が grease_quic_bit を広告している場合のみ
        // QUIC Bit 0 のパケットを受け入れる。
        let sh = if self.local_params.grease_quic_bit {
            ShortHeader::decode_allow_zero_quic_bit(data, dcid_len)?
        } else {
            ShortHeader::decode(data, dcid_len)?
        };
        let pn_offset = sh.header_len;

        // DCID からパスを特定する。未登録の CID は接続に紐づかないため破棄する。
        // 初期パスへフォールバックすると、CID を知らない第三者のパケットが
        // path 0 の状態を動かせてしまう。Err を返すことで
        // Connection::check_stateless_reset の経路 (RFC 9000 Section 10.3.1) を保つ。
        let Some(path_id) = self.paths.lookup_by_cid(&sh.dcid) else {
            return Err(Error::InvalidData(
                "unknown destination connection id".to_string(),
            ));
        };

        // パスが存在しない場合、サーバーはクライアントが開設した新パスを受け入れて
        // 検証する (RFC 10069 Section 3.1)。パスを開設するのは
        // クライアントだけであり、クライアントが未使用 path ID の CID 宛パケットで
        // パスを作ってはならない。作成しても PATH_CHALLENGE を送らない Pending の
        // パスが残り、同時検証数の上限を消費して以後の open_path が失敗する。
        // 復号前のパス作成は取り消せないため、クライアントではここで破棄する。
        // CID が解決できても Path が無いパケットは未認証であり、接続状態を
        // 変えてはならない (RFC 9000 Section 9.3)。
        if self.role == Role::Client && self.paths.get(path_id).is_none() {
            return Err(Error::InvalidData(format!(
                "path {path_id} is not established on client"
            )));
        }

        // クライアントで Pending のパスが残っている場合、ピアが先にパスを開設しようと
        // したことになる。放置すると同時検証数の枠を占有し続けるため、PATH_ABANDON で
        // 明示的に閉じる (RFC 10069 Section 3.1)。
        // ただし PATH_ABANDON の生成は AEAD 復号に成功した後に行う。未認証の
        // Short Header でパス状態を変えられないようにするため、ここでは判定だけする。
        let received_on_pending_path = self.role == Role::Client
            && self
                .paths
                .get(path_id)
                .is_some_and(|p| p.state == PathState::Pending);

        // パスが存在しない場合は、AEAD 復号に成功した後に自動作成する
        // (RFC 10069 Section 3.1)。復号前に作成すると、
        // 未認証の Short Header で検証枠とメモリを消費される。
        let path_created_for_peer = self.paths.get(path_id).is_none();

        let mut pkt = data.to_vec();

        // Header Protection 除去 (rustls)
        let rk = self
            .one_rtt_keys
            .as_ref()
            .ok_or_else(|| Error::InvalidData("no 1-RTT keys".into()))?;
        let pn_len = remove_hp_rustls(&mut pkt, pn_offset, &*rk.remote_header, false)?;

        // RFC 9001 Section 6.1: HP 解除後に Key Phase bit (0x04) を参照し、
        // 自身の key_phase と異なる場合はピアが鍵更新を開始したものとして次鍵で復号を試みる。
        let recv_key_phase = (pkt[0] & 0x04) != 0;

        // パケット番号復元 (パスごとの受信パケット番号を使用)
        // 未作成のパスでは受信履歴が無いため largest は None になる。
        let (truncated, _) = number::decode_truncated(&pkt[pn_offset..], pn_len)?;
        let largest = self
            .paths
            .get(path_id)
            .and_then(|path| path.recv_pn_largest);
        let full_pn = number::decode_full(largest, u64::from(truncated), u32::from(pn_len) * 8);

        // RFC 9000 Section 12.3: パケット番号は 0 から 2^62-1。復元結果が範囲外の
        // パケットは上限を守らないピアからの入力なので、復号前に破棄する。
        if full_pn > number::MAX_PACKET_NUMBER {
            return Ok(data.len());
        }

        let header_end = pn_offset + pn_len as usize;
        let aad = pkt[..header_end].to_vec();

        // 保持期限を過ぎた旧世代の鍵はここで破棄する (RFC 9001 Section 6.5)
        self.discard_expired_previous_one_rtt_keys(now);

        // 受信パケットが現在の Key Phase のものかを復号前に判定して保持する。
        // ピア起動の鍵更新をコミットすると `self.key_phase` が反転し、トリガー
        // パケットも現在の Key Phase のものとして扱う必要がある一方、旧鍵で
        // 復号したパケットはコミット後も旧世代のままである。
        let is_current_key_phase = recv_key_phase == self.key_phase;

        // Multipath AEAD 復号 (rustls, RFC 10069 Section 2.4)
        let mut ciphertext = pkt[header_end..].to_vec();
        // 旧鍵で復号できたかどうか。復号に成功したパケットだけが Reserved Bits の
        // 検査と鍵更新境界の判定に進む。
        let (plaintext, decrypted_with_previous_key) = if is_current_key_phase {
            // 現鍵で復号する
            match self.decrypt_one_rtt_with_current_key(path_id, full_pn, &aad, &mut ciphertext) {
                Ok(plaintext) => (plaintext, false),
                Err(_) => {
                    // RFC 9001 Section 6.6: 認証失敗数を integrity limit 用に数える
                    self.record_aead_auth_failure();
                    return Err(Error::InvalidData("1-RTT decryption failed".into()));
                }
            }
        } else if let Some(plaintext) = self.try_decrypt_with_previous_keys(
            recv_key_phase,
            path_id,
            full_pn,
            &aad,
            &ciphertext,
            now,
        ) {
            (plaintext, true)
        } else {
            // RFC 9001 Section 6.1/6.3: ピア起動の鍵更新を検出した。
            // next_secrets から次鍵を導出して復号を試みる。成功したら自身も鍵を
            // コミットする (update_keys 相当の処理)。復号に失敗した場合は
            // パケットを破棄する (接続は閉じない)。
            match self.apply_peer_initiated_key_update(path_id, full_pn, &aad, &mut ciphertext, now)
            {
                Ok(plaintext) => (plaintext, false),
                // RFC 9001 Section 6.6: 次鍵でも復号できないパケットは破棄する
                Err(Error::InvalidData(_)) => return Ok(data.len()),
                // 復号失敗以外のエラー (Protocol など) は握り潰さずに伝播する。
                // 将来この経路が Protocol を返すようになっても、接続を閉じずに
                // パケットを捨てる事故を防ぐ。
                Err(err) => return Err(err),
            }
        };

        // RFC 9000 Section 17.3: パケット保護とヘッダ保護の両方を除去した後、
        // Reserved Bits (0x18) が非ゼロなら PROTOCOL_VIOLATION とする (MUST)。
        // 復号に成功したすべての経路 (現鍵・旧鍵・次鍵) がここを通る。旧鍵で
        // 復号できたパケットでも、鍵更新境界の判定より先にこの検査を行う。
        header::check_short_header_reserved_bits(pkt[0])?;

        if decrypted_with_previous_key {
            // RFC 9001 Section 6.4 / 6.5: 旧鍵で復号できたパケットのパケット番号が
            // 現行の Key Phase で受信済みの最小パケット番号以上なら、そのパケット
            // 番号以下で新しい鍵が使われている。これは接続エラー KEY_UPDATE_ERROR
            // とする (MUST)。境界より小さければ、鍵更新前に送信された再順序
            // パケットとして鍵更新を行わずに受理する。
            //
            // Section 6.4 の MUST が対象とするのは「より低いパケット番号のパケットに
            // 新しい鍵が使われた場合」であり、境界と同値のパケット番号は MUST の
            // 範囲外である。同値は同じパケット番号の再利用になるため、本実装では
            // 同一 PN の再利用として KEY_UPDATE_ERROR にする実装判断を取る。
            if let Some(boundary) = self
                .current_key_phase_lowest_recv_pns
                .get(&path_id)
                .copied()
                && full_pn >= boundary
            {
                return Err(Error::Protocol {
                    code: tobi_core::error::TransportErrorCode::KEY_UPDATE_ERROR,
                    reason: format!(
                        "packet number {full_pn} is not lower than the current key phase boundary {boundary} but was protected with the previous key"
                    ),
                });
            }
        }

        if is_current_key_phase {
            // RFC 9001 Section 6.5: 現行の Key Phase で受信した最小パケット番号を
            // そのパスの境界として記録する。旧鍵で復号できたパケットは、この値より
            // 小さい場合だけ再順序として受理する。
            //
            // RFC 9001 Section 6.1: 更新後の鍵で保護されたパケットの保護解除に
            // 成功したので、旧鍵の保持期限もここで設定する。ローカル起点の鍵更新
            // では期限を設定せず、この時点まで旧鍵を保持している。
            self.record_current_key_phase_packet(path_id, full_pn, now);
        }

        // ここから先は AEAD 復号に成功した認証済みパケットだけが到達する。
        // パス状態・検証枠・通知の変更はすべてこの地点より後で行う。

        // クライアントの Pending パスへピアが先に送ってきた場合は、ここで
        // パスを閉じる。復号に失敗したパケットでは到達しない。
        if received_on_pending_path {
            self.abandon_path_inner(
                path_id,
                frame::path_abandon::error_code::APPLICATION_ABANDON_PATH,
                now,
            )?;
            // パスを閉じただけであり、このパケットでパス状態は動かさない。
            return Ok(data.len());
        }

        // サーバーは認証済みパケットを受信した時点で、未登録の path ID のパスを
        // 作成し、アドレス検証を開始する (RFC 10069 Section 3.1)。
        // 生成直後のパスが既存パスと同じ 4-tuple を持つ場合の冗長パス判定も行う
        // (RFC 10069 Section 5.2)。
        let mut created_path_collision = false;
        if path_created_for_peer {
            if self.paths.create_path_for_peer(path_id).is_err() {
                // 検証枠の上限などで作成できない場合は、未認証パケットのときと
                // 同様に接続状態を変えずにこのパケットを破棄する。
                return Ok(data.len());
            }
            // 接続の既定値 (keep-alive の有効/無効) を新しいパスへ継承する
            if let Some(path) = self.paths.get_mut(path_id) {
                path.set_keep_alive_enabled(self.keep_alive_enabled);
            }
            // 未開設の間に受信したピアの PATH_STATUS を反映する
            self.apply_pending_peer_path_status(path_id);
            // 生成直後のパスは初期パスの 4-tuple を引き継いでいる。受信パケットの
            // 4-tuple がそれと異なる場合だけ「migration 相当」とみなし、
            // 既存パスと同じ 4-tuple なら冗長パスとして扱う。
            let inherited_tuple_differs = self
                .paths
                .get(path_id)
                .is_some_and(|p| p.remote_addr != remote_addr || p.local_addr != local_addr);
            // 受信パケットの 4-tuple をこのパスの 4-tuple として確定する。
            if let Some(path) = self.paths.get_mut(path_id) {
                path.remote_addr = remote_addr;
                path.local_addr = local_addr;
            }
            created_path_collision = inherited_tuple_differs
                && self.paths.all_paths().any(|p| {
                    p.id != path_id
                        && matches!(p.state, PathState::Active | PathState::Validating)
                        && p.remote_addr == remote_addr
                        && p.local_addr == local_addr
                });
            // プロアクティブ CID 発行で使用した seq 番号を反映する
            if let Some(next_seq) = self.proactive_cid_next_seq.remove(&path_id.0)
                && let Some(path) = self.paths.get_mut(path_id)
            {
                path.next_local_cid_seq = next_seq;
            }
            // ピアから既に受信済みの CID があればパスの peer_cid として設定する。
            // 送信先に採用した CID は使用済みにする (RFC 9000 Section 9.5)。
            if let Some(entry) = self.peer_cid_entries.iter().find(|e| e.path_id == path_id) {
                let cid = entry.connection_id.clone();
                self.assign_path_peer_cid(path_id, cid);
            }

            // サーバーはピアのアドレスを検証するため PATH_CHALLENGE を送信する
            // (RFC 10069 Section 3.1, RFC 9000 Section 8.2)
            // PATH_RESPONSE とバンドルして返す (Figure 4)
            if self.role == Role::Server {
                let mut challenge_data = [0u8; 8];
                aws_lc_rs::rand::fill(&mut challenge_data)
                    .map_err(|_| Error::InvalidData("failed to generate random bytes".into()))?;

                let path = self.paths.get_mut(path_id).expect("path just created");
                path.validation.request_challenge(challenge_data);
                path.state = PathState::Validating;

                // PATH_CHALLENGE を 1200 byte パディング付きで送信する (RFC 9000 Section 8.2.1)
                self.emit_1rtt_path_challenge(path_id, challenge_data, now)?;

                // パス検証タイマーを設定する (PTO ベース)
                let pto = self.path_validation_pto(path_id);
                self.output_queue.push_back(ConnectionOutput::SetTimer {
                    id: TimerId::PathValidation { path_id },
                    deadline: now + pto,
                });
            }

            // ピアのパケットで自動生成したパスを I/O 層へ通知する。この通知で
            // パス用のソケットが解決され、初期パスとアドレスファミリが異なる場合に
            // そのソケットの受信タスクが起動する。通知しないと、あとから追加された
            // ファミリのパスで受信したパケットを I/O 層が配送できない。
            // 4-tuple の反映後に通知することで、実アドレスを購読側へ渡せる。
            if let Some(path) = self.paths.get(path_id) {
                self.output_queue.push_back(ConnectionOutput::PathOpened {
                    path_id,
                    local_addr: path.local_addr,
                    remote_addr: path.remote_addr,
                });
            }
        }

        // link-local アドレスの scope ID だけが新たに判明した場合は、4-tuple の
        // 変更ではなく学習として扱う。ユーザーが scope なしの link-local アドレス
        // (`[fe80::1]:443` など) を指定した場合、初回受信までは pktinfo の
        // `ipi6_ifindex` が分からない。scope を保存済みのアドレスへ補完しないと、
        // 以降の受信が 4-tuple の変更と誤判定され、通常の受信で migration が走る。
        // 保存済みのポートが 0 の場合はポートの学習が別途必要なため対象外である。
        self.learn_link_local_scope(path_id, local_addr);

        // 4-tuple の差分を記録する。migration の確定は AEAD 復号の成功後に行う
        // (RFC 9000 Section 9.3 / RFC 10069 Section 3.1.2)。
        // 復号前にパス状態を書き換えると、認証に失敗するパケットで送信パスを
        // 失わせられる。生成直後のパスは上で 4-tuple を確定済みなので false。
        let migration_tuple_changed = !path_created_for_peer
            && self
                .paths
                .get(path_id)
                .is_some_and(|p| p.remote_addr != remote_addr || p.local_addr != local_addr);

        // RFC 9001 Section 4.9.3: サーバーは 1-RTT パケットを初めて受信した時点から
        // 3 × PTO 経過後に 0-RTT 鍵を破棄しなければならない (MUST)。
        if self.role == Role::Server {
            self.schedule_zero_rtt_keys_discard(now);
        }

        // 重複パケット検出 (RFC 9000 Section 13.2.3)
        if self
            .paths
            .get(path_id)
            .is_some_and(|path| path.ack_tracker.is_already_received(full_pn))
        {
            return Ok(data.len());
        }

        // qlog: packet_received (1-RTT)
        if self.qlog_writer.is_some() {
            let time_ms = self.qlog_time_ms();
            let qlog_frames = decode_frames_for_qlog(&plaintext, self.peer_ack_delay_exponent());
            let qlog_header = qlog::PacketHeader {
                packet_type: qlog::PacketType::OneRtt,
                packet_number: full_pn,
                dcid: qlog::cid_to_hex(&sh.dcid),
                scid: None,
                version: None,
                length: Some(data.len()),
            };
            if let Some(ref mut w) = self.qlog_writer {
                w.on_packet_received(time_ms, &qlog_header, &qlog_frames, data.len());
            }
        }
        // 観測イベント: パケット受信
        self.observe(ConnectionObservationEvent::PacketReceived {
            path_id,
            packet_number: full_pn,
            size: data.len(),
        });

        // フレーム処理
        let outcome = self.process_frames(
            &plaintext,
            EncryptionLevel::OneRtt,
            path_id,
            Some((remote_addr, local_addr)),
            now,
        )?;
        // フレームをすべて正常に処理できたパケットだけがアイドルタイマーの
        // リスタート対象になる (RFC 9000 Section 10.1)
        self.received_valid_packet = true;
        self.last_valid_recv_path = Some(path_id);

        // 認証済みの新しい CID への切り替えを確認してから、次の移行用を補充する。
        // 復号前のヘッダーや古い CID の再到着では新しい CID を発行しない。
        self.refill_local_cids_after_rotation(path_id, &sh.dcid);

        // ポストハンドシェイク TLS メッセージ (NewSessionTicket 等) を処理する
        // 1-RTT CRYPTO フレームで受信したデータを rustls にフィードする
        self.advance_tls(now)?;

        // migration の確定 (RFC 9000 Section 9.3)
        //
        // 送信先アドレスを変えてよいのは、復号に成功した non-probing パケットの
        // うち、そのパスで受信した non-probing パケットの最大パケット番号を
        // 持つものだけである。最大値の記録は 4-tuple の差分の有無にかかわらず
        // 行い、記録したうえで差分がある場合にだけ migration を適用する。
        // 復号に失敗したパケットはここに到達しないため、未認証のパケットが
        // パス状態を変えることはない。
        let is_new_largest_non_probing = outcome.non_probing
            && self
                .paths
                .get_mut(path_id)
                .is_some_and(|p| p.update_recv_pn_non_probing(full_pn));
        if is_new_largest_non_probing {
            if migration_tuple_changed {
                // 送信すべきアプリケーションデータも未確認の送信も無い場合は、
                // ACK だけのパケットで 4-tuple を切り替えない。転送終了直前に
                // NAT リバインディングが起きると、経路検証を始めた直後にピアが
                // 接続を閉じ、PATH_CHALLENGE への応答が返らないためである。
                // 次に送信すべきデータが生じた時点で改めて移行する。
                let quiescent = !outcome.ack_eliciting
                    && self.state == ConnectionState::Connected
                    && self
                        .paths
                        .get(path_id)
                        .is_some_and(|path| path.congestion.bytes_in_flight() == 0)
                    && !self.streams.has_unsent_data();
                if !quiescent {
                    self.apply_path_migration(path_id, remote_addr, local_addr, now)?;
                }
            } else if created_path_collision {
                // 生成直後のパスが既存パスと同じ 4-tuple を持つ場合は冗長なので
                // PATH_RESOURCE_LIMIT_REACHED で廃棄する
                // (RFC 10069 Section 5.2)
                self.abandon_path_inner(
                    path_id,
                    frame::path_abandon::error_code::PATH_RESOURCE_LIMIT_REACHED,
                    now,
                )?;
            }
        }

        // 対応するパスの受信状態を更新 (ack-eliciting 判定をフレーム処理結果から取得)
        let Some(path) = self.paths.get_mut(path_id) else {
            // フレーム処理中にパスが廃棄された場合は受信状態を更新しない
            return Ok(data.len());
        };
        path.update_recv_pn(full_pn);
        // keep-alive と昇格前の到達性確認で使う最終受信時刻を更新する。
        // 復号に成功したパケットだけを活動とみなす。
        path.record_received(now);
        // パスごとのアンチアンプリフィケーション: 受信バイト数を記録する
        path.on_bytes_received(data.len() as u64);
        // Receive Timestamps 拡張は post-handshake の 1-RTT パケットだけを
        // 対象とする (draft-ietf-quic-receive-ts-03 Section 4)。0-RTT や
        // ハンドシェイク中のパケットの受信時刻は記録しない。
        path.ack_tracker
            .record_received_with_timestamp(full_pn, outcome.ack_eliciting, now);

        // 遅延 ACK を無効にしている場合は、ACK_FREQUENCY 未交渉に限り
        // 従来どおり ack-eliciting パケットごとに即時 ACK する (設定の既定値)。
        // ACK_FREQUENCY 交渉済みの場合はピアの要求 (閾値) を優先する。
        if !self.delayed_ack && outcome.ack_eliciting && !path.ack_tracker.is_ack_frequency_active()
        {
            path.ack_tracker.request_immediate_ack();
        }
        // ACK タイミング判定 (RFC 9000 Section 13.2.1, 13.2.2 と
        // draft-ietf-quic-ack-frequency-14 Section 6)
        let local_max_ack_delay =
            tobi_core::time::Duration::from_millis(self.local_params.max_ack_delay);
        let effective_max_ack_delay = path
            .ack_tracker
            .requested_max_ack_delay_micros()
            .map_or(local_max_ack_delay, tobi_core::time::Duration::from_micros);
        // Section 6.3: CE への遷移では即時 ACK を強制する (閾値 > 1 のみ)
        if path.ack_tracker.take_ecn_transition_ack() {
            path.ack_tracker.request_immediate_ack();
        }
        // Section 6.2: 再順序ウィンドウ外のパケットを受信したら即時 ACK を強制する。
        // 条件には「受信パケットが再順序であること」だけでなく、ギャップにより
        // 送信側がロスト判定できる場合も含まれるため、全 ack-eliciting パケットで
        // 判定する。
        if outcome.ack_eliciting && path.ack_tracker.should_ack_for_reordering(full_pn) {
            path.ack_tracker.request_immediate_ack();
        }
        // ACK 送信タイミング (RFC 9000 Section 13.2.1 / 13.2.2)。
        // 拡張未使用時は 2 個以上の ack-eliciting パケットを受信するまで ACK を
        // 遅延するため、1 個目を受信した時点で AckDelay タイマーを張り、
        // max_ack_delay 以内に必ず ACK を送る。再順序・ギャップ・CE は
        // request_immediate_ack で即時 ACK する。
        // ACK Frequency 拡張が有効な場合は閾値ベースのタイマー判定にする。
        let arm_ack_delay_timer = if path.ack_tracker.is_ack_frequency_active() {
            !path.ack_tracker.should_send_ack_now()
        } else {
            !path.ack_tracker.should_send_ack_immediately()
        };
        if arm_ack_delay_timer
            && let Some(deadline) = path.ack_tracker.ack_delay_deadline(effective_max_ack_delay)
        {
            self.output_queue.push_back(ConnectionOutput::SetTimer {
                id: TimerId::AckDelay { path_id },
                deadline,
            });
        }

        self.emit_packets(now)?;

        Ok(data.len())
    }

    /// 認証に成功した non-probing パケットに基づいて 4-tuple を更新する
    ///
    /// RFC 9000 Section 9.3: 送信先アドレスの変更は、受信した non-probing
    /// パケットのうち最大のパケット番号を持つものへの応答としてのみ行う。
    /// 呼び出し側は AEAD 復号に成功したパケットでのみこの関数を呼ぶ。
    ///
    /// IP 変更を伴う migration は PATH_RESPONSE 受信時に CC/RTT をリセットする
    /// (RFC 9000 Section 9.4)。port-only 変更はリセットしない。
    fn apply_path_migration(
        &mut self,
        path_id: PathId,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
        now: Timestamp,
    ) -> Result<(), Error> {
        // preferred_address への移行検証中は、検証完了までパスの 4-tuple を
        // 変更しない (RFC 9000 Section 9.6.1)。検証中のパスでは migration を
        // 適用せず、進行中の検証をそのまま継続する。
        if self.pending_migrations.contains_key(&path_id) {
            return Ok(());
        }

        // 移行確定直後の猶予期間 (3 × PTO) は、旧 4-tuple から遅延して届いた
        // パケットを再移行のトリガーにしない。RFC 9000 Section 9.3 は再順序された
        // パケットで旧アドレスへ送らないことを要求しており、Section 9.3.3 は
        // ヒューリスティックによる検出を許容している。
        // パケット自体の処理 (ACK 処理など) は呼び出し側が通常どおり行っており、
        // ここでは送信先アドレスの変更だけを見送る。
        let grace = self.path_validation_pto(path_id).mul(3);
        if self
            .paths
            .get(path_id)
            .is_some_and(|path| path.is_delayed_previous_tuple(remote_addr, local_addr, now, grace))
        {
            tracing::debug!(
                "ignore delayed packet from previous 4-tuple path={:?} remote={} local={}",
                path_id,
                remote_addr,
                local_addr
            );
            return Ok(());
        }

        // ワイルドカード待ち受け (0.0.0.0 / ::) から、受信パケットの宛先 IP が
        // 初めて分かっただけの更新は migration ではない。検証のやり直しや
        // 輻輳制御のリセットを起こさない。
        if let Some(path) = self.paths.get(path_id)
            && path.remote_addr == remote_addr
            && path.local_addr.ip().is_unspecified()
            && !local_addr.ip().is_unspecified()
        {
            let learned = resolve_observed_local(path.local_addr, local_addr);
            if let Some(path) = self.paths.get_mut(path_id) {
                path.local_addr = learned;
            }
            return Ok(());
        }

        // 宛先 IP が取れなかった受信で、確定済みのローカルアドレスを 0.0.0.0 に戻さない。
        let local_addr = if local_addr.ip().is_unspecified() {
            self.paths
                .get(path_id)
                .map(|p| p.local_addr)
                .unwrap_or(local_addr)
        } else {
            local_addr
        };

        // フレーム処理の中で 4-tuple が既に更新されている場合
        // (preferred_address の移行確定など) は migration ではない。
        // 検証成功直後のパスを Validating に戻さないための確認。
        let tuple_changed = self
            .paths
            .get(path_id)
            .is_some_and(|p| p.remote_addr != remote_addr || p.local_addr != local_addr);
        if !tuple_changed {
            return Ok(());
        }

        let mut migration_challenge: Option<[u8; 8]> = None;
        {
            let Some(path) = self.paths.get_mut(path_id) else {
                return Ok(());
            };
            let old_remote = path.remote_addr;
            let old_local = path.local_addr;
            let remote_changed = old_remote != remote_addr;
            let local_changed = old_local != local_addr;

            // port-only かを判定: IP が一致し port のみ差分 (両側)
            let remote_port_only =
                old_remote.ip() == remote_addr.ip() && old_remote.port() != remote_addr.port();
            let local_port_only =
                old_local.ip() == local_addr.ip() && old_local.port() != local_addr.port();
            let only_port_changes =
                (!remote_changed || remote_port_only) && (!local_changed || local_port_only);

            // 遅延パケット抑止のため、アドレスを書き換える前に確定を記録する
            path.note_migration_committed(now);
            path.remote_addr = remote_addr;
            path.local_addr = local_addr;

            // 検証中に新しい 4-tuple を検出した場合は進行中の検証を破棄して
            // やり直す (RFC 9000 Section 9.3.2)。廃棄中・廃棄済みのパスでは
            // 検証を起動しない。
            if matches!(path.state, PathState::Active | PathState::Validating) {
                // 旧アドレスの増幅枠を新しい 4-tuple へ持ち越さない
                // (RFC 9000 Section 8 / Section 9.3.1)。
                // このパケット自身の長さは、呼び出し元の on_bytes_received が
                // リセット後に新しい受信量として加算する。
                // 未検証の peer アドレスへの応答は role に関係なく制限する
                // (RFC 9000 Section 8 / Section 21.1.1.1)。
                path.restart_address_validation();
                path.migration_reset_pending = !only_port_changes;
                // 以前の 4-tuple 向けの PATH_CHALLENGE を破棄し、
                // リトライ回数も新しい 4-tuple 向けにリセットする
                path.validation.restart();

                // PATH_CHALLENGE を生成する
                let mut challenge = [0u8; 8];
                if aws_lc_rs::rand::fill(&mut challenge).is_ok() {
                    path.validation.request_challenge(challenge);
                    migration_challenge = Some(challenge);
                }
            }
        }

        // Migration に伴い 4-tuple が他の Active / Validating パスと重複したか判定する
        // (RFC 10069 Section 5.2)。
        // 意図的な同一 4-tuple 並走 (DiffServ 用途等) は migration を伴わないので
        // ここでは検出されない。migration の副作用として発生した冗長パスのみ
        // 対象となる。重複が検出された場合は後発 (migration した) パスを
        // PATH_ABANDON でクローズする。
        let collision_with_other_path = self.paths.all_paths().any(|p| {
            p.id != path_id
                && matches!(p.state, PathState::Active | PathState::Validating)
                && p.remote_addr == remote_addr
                && p.local_addr == local_addr
        });

        if !collision_with_other_path && let Some(challenge) = migration_challenge {
            self.emit_1rtt_path_challenge(path_id, challenge, now)?;
            // 新しい 4-tuple への最初のサーバー パケットを PATH_CHALLENGE に
            // するため、送信できるまで他の 1-RTT 出力を保留する。ACK だけの
            // 出力が先に届くと上流の rebind 判定が失敗する。
            if self
                .paths
                .get(path_id)
                .is_some_and(|path| path.validation.unsent_challenge().is_none())
            {
                self.defer_path_datagrams_until_challenge = Some(path_id);
            }
            // パス検証タイマーを設定する (PTO ベース)
            let pto = self.path_validation_pto(path_id);
            self.output_queue.push_back(ConnectionOutput::SetTimer {
                id: TimerId::PathValidation { path_id },
                deadline: now + pto,
            });
        }

        if collision_with_other_path {
            // 後発パスを PATH_RESOURCE_LIMIT_REACHED で abandon する
            // (RFC 10069 Section 5.2)
            self.abandon_path_inner(
                path_id,
                frame::path_abandon::error_code::PATH_RESOURCE_LIMIT_REACHED,
                now,
            )?;
        }

        Ok(())
    }

    // --- フレーム処理 ---

    /// 復号に成功したペイロードのフレームデコードエラーを接続エラーへ変換する
    ///
    /// `process_frames` に渡るデータは AEAD 復号に成功した認証済みのペイロードで
    /// あり、RFC 9000 Section 12.4 はその中身が完全なフレームの列であることを
    /// 要求している。そのため、フレームの構文エラー (`Error::InvalidData`) だけで
    /// なく、フレームの可変長 varint・固定長フィールド・宣言された Length が
    /// 途中で切れている (不足している) `Error::Incomplete` も
    /// FRAME_ENCODING_ERROR として接続を閉じる (RFC 9000 Section 20.1)。
    /// `Error::Incomplete` には、宣言された Length が残りのペイロード長を超える
    /// 場合も含まれる (LEN あり DATAGRAM など)。
    ///
    /// `Frame::decode` が返す `Error::Protocol` は、非最短の Frame Type など
    /// `Frame::decode` 自身が適切な Error Code を決めたエラーである。これを
    /// FRAME_ENCODING_ERROR に潰さず、そのまま呼び出し元へ通す。
    ///
    /// この変換はフレームデコードにだけ適用する。パケットヘッダやパケット Length の
    /// 不足は復号前の検査で発生する `Error::Incomplete` であり、RFC 9000
    /// Section 5.2 / Section 10.2.3 に従ってパケット破棄のまま扱う。その経路は
    /// この関数を通らない。
    fn map_frame_decode_error(err: Error) -> Error {
        match err {
            Error::InvalidData(reason) => Error::Protocol {
                code: tobi_core::error::TransportErrorCode::FRAME_ENCODING_ERROR,
                reason,
            },
            // 認証済みペイロード内でフレームのフィールドが切れている場合は、
            // パケットの不足ではなくフレームの不正として扱う。
            Error::Incomplete { needed } => Error::Protocol {
                code: tobi_core::error::TransportErrorCode::FRAME_ENCODING_ERROR,
                reason: format!("truncated frame in authenticated payload: missing {needed} bytes"),
            },
            other => other,
        }
    }

    /// フレームを処理し、ack-eliciting フレームと non-probing フレームの有無を返す
    ///
    /// RFC 9000 Section 13.2.1: ACK フレームと PADDING フレームのみで
    /// 構成されるパケットは ack-eliciting ではない。
    ///
    /// RFC 9000 Section 12.4: フレームを 1 つも含まないパケットは
    /// PROTOCOL_VIOLATION として接続を閉じる (MUST)。
    ///
    /// `packet_addrs` は受信パケットの 4-tuple。PATH_CHALLENGE を受信したときに
    /// PATH_RESPONSE の送信先として記録する (RFC 9000 Section 8.2.2 の MUST)。
    fn process_frames(
        &mut self,
        mut data: &[u8],
        level: EncryptionLevel,
        path_id: PathId,
        packet_addrs: Option<(std::net::SocketAddr, std::net::SocketAddr)>,
        now: Timestamp,
    ) -> Result<FrameProcessOutcome, Error> {
        // RFC 9000 Section 13.4.1: ECN カウントはパケット番号空間ごとに独立して
        // 集計する。Coalesced された各 QUIC パケットは同じ IP ヘッダの ECN を
        // 1 回ずつ加算する。空間ごとの AckTracker に記録し、ACK_ECN 生成時に
        // 対応する空間の累計のみを報告する。
        match level {
            EncryptionLevel::Initial => self.initial_ack_tracker.record_ecn(self.current_recv_ecn),
            EncryptionLevel::Handshake => {
                self.handshake_ack_tracker.record_ecn(self.current_recv_ecn)
            }
            EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt => {
                if let Some(path) = self.paths.get_mut(path_id) {
                    path.ack_tracker.record_ecn(self.current_recv_ecn);
                }
            }
        }
        let mut ack_eliciting = false;
        // RFC 9000 Section 9.1: probing フレームのみで構成されるパケットは
        // probing パケットであり、それ以外のフレームを含む場合は non-probing
        // パケットである。送信先アドレスの変更は non-probing パケットでのみ行う。
        let mut non_probing = false;
        // デコードに成功したフレーム数。復号後のペイロードが 0 バイトだと
        // ループが一度も回らず 0 のままになる (RFC 9000 Section 12.4 の空検出用)
        let mut frame_count: usize = 0;
        let mut responses_requeued = false;
        while !data.is_empty() {
            // フレームデコード失敗は FRAME_ENCODING_ERROR (RFC 9000 Section 12.4)。
            // `Error::Protocol` だけは `Frame::decode` が決めた Error Code を
            // そのまま使う (非最短 Frame Type など)。復号前のパケットヘッダ /
            // Length の不足はこの変換の対象外であり、呼び出し元
            // (`receive_with_ecn`) がパケット破棄として扱う。
            let (frm, consumed) = Frame::decode(data).map_err(Self::map_frame_decode_error)?;
            data = &data[consumed..];
            frame_count += 1;
            // ack-eliciting 判定 (RFC 9000 Section 13.2.1)
            match frm {
                Frame::Padding(_) => {}
                Frame::Ack(_)
                | Frame::PathAck(_)
                | Frame::AckReceiveTimestamps(_)
                | Frame::PathAckReceiveTimestamps(_) => {}
                _ => {
                    ack_eliciting = true;
                }
            }
            // probing 判定 (RFC 9000 Section 9.1)
            if !is_probing_frame(&frm) {
                non_probing = true;
            }

            // 暗号化レベル検証 (RFC 9000 Section 12.4 Table 3)
            if !is_frame_allowed_in_level(&frm, level) {
                return Err(Error::Protocol {
                    code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                    reason: format!(
                        "frame type {:?} not allowed in {:?} packet",
                        std::mem::discriminant(&frm),
                        level
                    ),
                });
            }

            // multipath 拡張のネゴシエーション検証 (RFC 10069 Section 2)
            // 両端点が initial_max_path_id を advertise していない場合、
            // multipath 専用フレームの使用は MUST NOT である。
            // 未合意のまま path 状態や CID が操作されるのを防ぐため PROTOCOL_VIOLATION で閉じる。
            if is_multipath_only_frame(&frm) && !self.multipath_negotiated() {
                return Err(Error::Protocol {
                    code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                    reason: "multipath frame received without multipath negotiation".into(),
                });
            }

            match frm {
                Frame::Padding(_) | Frame::Ping(_) => {}
                Frame::Crypto(cf) => match level {
                    EncryptionLevel::Initial => {
                        self.crypto_recv_initial
                            .receive(cf.offset.as_u64(), &cf.data)?;
                    }
                    // 0-RTT の CRYPTO は is_frame_allowed_in_level が
                    // PROTOCOL_VIOLATION として拒否するため到達しない
                    // (RFC 9000 Section 12.4 Table 3)。
                    EncryptionLevel::Handshake => {
                        self.crypto_recv_handshake
                            .receive(cf.offset.as_u64(), &cf.data)?;
                    }
                    // RFC 9001 Section 4.1.3: 1-RTT の CRYPTO は Handshake とは
                    // 独立したオフセット空間を持つため専用バッファへ入れる。
                    EncryptionLevel::OneRtt => {
                        self.crypto_recv_1rtt
                            .receive(cf.offset.as_u64(), &cf.data)?;
                    }
                    EncryptionLevel::ZeroRtt => {}
                },
                Frame::Ack(ref ack) => {
                    // 1-RTT / 0-RTT で受信した ACK は path 0 に対する確認応答として
                    // 処理する。0-RTT のパケット番号空間も path 0 に属する。
                    // ハンドシェイク中 (Initial / Handshake) の ACK は暗号化レベル
                    // ごとのパケット番号空間で処理する従来の挙動を維持する。
                    // (RFC 9000 Section 12.3)
                    let acked_path_id = match level {
                        EncryptionLevel::OneRtt | EncryptionLevel::ZeroRtt => PathId::INITIAL,
                        EncryptionLevel::Initial | EncryptionLevel::Handshake => path_id,
                    };
                    // path 0 が既に廃棄されている場合など、対象のパスに送信済み
                    // パケットが無いときは `Connection::process_ack` が何もせず
                    // 無視する。
                    let before_smoothed_rtt =
                        self.paths.get(acked_path_id).map(|p| p.rtt.smoothed_rtt);
                    self.process_ack(ack, acked_path_id, path_id, level, now)?;
                    self.notify_metrics_updated_if_changed(acked_path_id, before_smoothed_rtt, now);
                }
                Frame::PathAck(ref path_ack) => {
                    // RFC 10069 Section 4: announced Maximum Paths を
                    // 超える path_id は PROTOCOL_VIOLATION として接続を閉じる (MUST)。
                    self.validate_frame_path_id(path_ack.path_id)?;
                    // PATH_ACK は指定された Path ID のパスに対して処理する
                    let ack_path_id = PathId(path_ack.path_id);
                    // 廃棄中 (`Abandoning`) と廃棄済み (`Abandoned` / tombstone) の
                    // パス宛 PATH_ACK は黙って無視する
                    // (RFC 10069 Section 3.4.3 / Section 4)。
                    // 他のフレームと同じ `Connection::is_path_abandoned` で判定し、
                    // フレームごとに abandoned の扱いがばらつかないようにする。
                    // パスが既に削除されている場合も処理しない (従来どおり)。
                    if self.paths.get(ack_path_id).is_some() && !self.is_path_abandoned(ack_path_id)
                    {
                        let ack = frame::ack::Ack {
                            largest_acknowledged: path_ack.largest_acknowledged,
                            ack_delay: path_ack.ack_delay,
                            first_ack_range: path_ack.first_ack_range,
                            ack_ranges: path_ack.ack_ranges.clone(),
                            ecn_counts: path_ack.ecn_counts,
                        };
                        // ack_path_id はデータ送信パス、path_id は ACK 受信パス
                        // PATH_ACK は常に 1-RTT レベルで受信される
                        let before_smoothed_rtt =
                            self.paths.get(ack_path_id).map(|p| p.rtt.smoothed_rtt);
                        self.process_ack(&ack, ack_path_id, path_id, EncryptionLevel::OneRtt, now)?;
                        self.notify_metrics_updated_if_changed(
                            ack_path_id,
                            before_smoothed_rtt,
                            now,
                        );
                    }
                }
                Frame::AckReceiveTimestamps(ref receive_ts) => {
                    // draft-ietf-quic-receive-ts-03 Section 4:
                    // ACK と同じく 1-RTT パケットでだけ受信する
                    // (is_frame_allowed_in_level が担保する)。
                    self.validate_receive_timestamps(&receive_ts.ack, &receive_ts.timestamps)?;
                    // 1-RTT の ACK は path 0 のパケット番号空間を確認応答する
                    // (0-RTT と 1-RTT は Application Data 空間を共有する)。
                    let acked_path_id = PathId::INITIAL;
                    let before_smoothed_rtt =
                        self.paths.get(acked_path_id).map(|p| p.rtt.smoothed_rtt);
                    self.process_ack(
                        &receive_ts.ack,
                        acked_path_id,
                        path_id,
                        EncryptionLevel::OneRtt,
                        now,
                    )?;
                    self.notify_metrics_updated_if_changed(acked_path_id, before_smoothed_rtt, now);
                }
                Frame::PathAckReceiveTimestamps(ref receive_ts) => {
                    // RFC 10069 Section 4 と同じく、
                    // announced Maximum Paths を超える path_id は閉じる (MUST)。
                    self.validate_frame_path_id(receive_ts.path_id)?;
                    let ack_path_id = PathId(receive_ts.path_id);
                    if self.paths.get(ack_path_id).is_some() && !self.is_path_abandoned(ack_path_id)
                    {
                        self.validate_receive_timestamps(&receive_ts.ack, &receive_ts.timestamps)?;
                        let before_smoothed_rtt =
                            self.paths.get(ack_path_id).map(|p| p.rtt.smoothed_rtt);
                        self.process_ack(
                            &receive_ts.ack,
                            ack_path_id,
                            path_id,
                            EncryptionLevel::OneRtt,
                            now,
                        )?;
                        self.notify_metrics_updated_if_changed(
                            ack_path_id,
                            before_smoothed_rtt,
                            now,
                        );
                    }
                }
                Frame::Stream(ref sf) => {
                    self.streams.on_stream_frame(sf)?;
                    self.drain_stream_events();
                }
                Frame::ResetStream(ref rf) => {
                    self.streams.on_reset_stream(rf)?;
                    self.drain_stream_events();
                }
                Frame::ResetStreamAt(ref rf) => {
                    self.streams.on_reset_stream_at(rf)?;
                    self.drain_stream_events();
                }
                Frame::StopSending(ref sf) => {
                    self.streams.on_stop_sending(sf)?;
                    self.drain_stream_events();
                }
                Frame::MaxData(ref md) => {
                    self.streams.on_max_data(md.maximum_data.as_u64());
                }
                Frame::MaxStreamData(ref msd) => {
                    self.streams.on_max_stream_data(msd)?;
                    self.drain_stream_events();
                }
                Frame::MaxStreams(ref ms) => {
                    self.streams.on_max_streams(ms)?;
                }
                Frame::DataBlocked(_) => { /* 情報提供のみ */ }
                Frame::StreamDataBlocked(ref sdb) => {
                    self.streams.on_stream_data_blocked(sdb)?;
                }
                Frame::StreamsBlocked(ref sb) => {
                    self.streams.on_streams_blocked(sb)?;
                }
                Frame::HandshakeDone(_) => {
                    // RFC 9000 Section 19.20: サーバーが HANDSHAKE_DONE を受信した場合、
                    // PROTOCOL_VIOLATION として接続を閉じる MUST。
                    if self.role == Role::Server {
                        return Err(Error::Protocol {
                            code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                            reason: "server received HANDSHAKE_DONE frame".into(),
                        });
                    }
                    if self.role == Role::Client {
                        self.handshake_done_received = true;
                        if self.state == ConnectionState::Handshaking {
                            // qlog: 状態遷移 Handshaking → Connected
                            if self.qlog_writer.is_some() {
                                let time_ms = self.qlog_time_ms();
                                if let Some(ref mut w) = self.qlog_writer {
                                    w.on_connection_state_updated(
                                        time_ms,
                                        "handshaking",
                                        "connected",
                                    );
                                }
                            }
                            self.state = ConnectionState::Connected;
                            self.push_event(ConnectionEvent::Connected);
                            self.handshake_confirmed_once = true;
                            self.reset_idle_timer(now);
                            // keep-alive が有効なパスのタイマーを開始する
                            self.arm_all_keep_alive_timers(now);
                            self.issue_initial_cids();
                            // Handshake 鍵を廃棄する (RFC 9001 Section 4.9.2)
                            self.discard_handshake_keys();
                            // DPLPMTUD を有効化する (RFC 8899)
                            self.enable_dplpmtud();
                            // ハンドシェイク完了後の初期パスで観測アドレスを通知する
                            // (draft-ietf-quic-address-discovery-01 Section 5)
                            self.send_observed_address(PathId::INITIAL, now)?;

                            // 0-RTT 受理の反映 (RFC 9001 Section 4.6.2)
                            //
                            // クライアントはサーバーの early_data 拡張の有無で受理を判断する。
                            // サーバー側は 0-RTT パケットを受信した時点で
                            // `process_zero_rtt` が同じフィールドを立てる。
                            if self.role == Role::Client
                                && let TlsSessionHolder::Client(c) = &self.tls_session
                            {
                                self.zero_rtt_accepted = c.is_early_data_accepted();
                            }

                            // 0-RTT 拒否チェック (RFC 9001 Section 4.6.2)
                            // クライアントが 0-RTT を送信していた場合、サーバーの受理を確認する
                            if self.zero_rtt_sent {
                                let accepted = match &self.tls_session {
                                    TlsSessionHolder::Client(c) => c.is_early_data_accepted(),
                                    TlsSessionHolder::Server(_) => false,
                                };
                                if !accepted {
                                    // 0-RTT が拒否された: 0-RTT で送信済みのパケットを
                                    // 破棄し、bytes_in_flight を回収して 1-RTT で再送させる
                                    // (RFC 9001 Section 4.6.2 / RFC 9002 Section 6.4)。
                                    self.discard_sent_packets_for_zero_rtt_rejection(now);
                                    self.zero_rtt_rejected = true;
                                    self.push_event(ConnectionEvent::ZeroRttRejected);
                                }
                            }
                        }
                    }
                }
                Frame::PathChallenge(ref pc) => {
                    // PATH_CHALLENGE を受信: PATH_RESPONSE を返す必要がある。
                    // PATH_RESPONSE は PATH_CHALLENGE を受信した 4-tuple へ返すため
                    // (RFC 9000 Section 8.2.2 の MUST)、受信 4-tuple を記録する。
                    // 4-tuple が渡されない経路 (Initial / Handshake / 0-RTT と
                    // テストヘルパ) ではパスの 4-tuple を使う。
                    // 廃棄中 / 廃棄済み / tombstone のパスでは PATH_RESPONSE を返さない
                    // (RFC 10069 Section 3.4)。同節は PATH_ABANDON を
                    // 送った端点に対し、その path ID の Connection ID を即座に退役させ、
                    // 以後そのパスでパケットを送れないとする。PATH_RESPONSE は
                    // PATH_CHALLENGE と同じパス・同じ path ID の Connection ID で返す
                    // 必要があるため (Section 3.1)、廃棄済みパスでは返せない。
                    if !self.is_path_abandoned(path_id) {
                        if !responses_requeued {
                            self.requeue_unsent_path_responses(path_id);
                            responses_requeued = true;
                        }
                        let response_addrs = packet_addrs.or_else(|| {
                            self.paths
                                .get(path_id)
                                .map(|p| (p.remote_addr, p.local_addr))
                        });
                        if let (Some(path), Some((remote_addr, local_addr))) =
                            (self.paths.get_mut(path_id), response_addrs)
                        {
                            // チャレンジを運んだデータグラムの UDP payload 長を
                            // 覚えておく。応答先がパスの現在の 4-tuple と異なる
                            // 場合 (移行の probe への応答など) の拡張判定で、その
                            // アドレスの増幅予算として使う
                            // (RFC 9000 Section 8.2.2 / Section 8.1)。
                            let datagram_len = self.current_recv_datagram_len.unwrap_or_default();
                            path.validation.challenge_received(
                                pc.data,
                                remote_addr,
                                local_addr,
                                datagram_len,
                            );
                        }
                        // 新しい 4-tuple からの probe には、PATH_RESPONSE より先に
                        // 自前の PATH_CHALLENGE を送る (RFC 9000 Section 8.2)。
                        if let Some((remote_addr, local_addr)) = response_addrs {
                            self.maybe_start_validation_for_probe(
                                path_id,
                                remote_addr,
                                local_addr,
                                now,
                            )?;
                        }
                    }
                }
                Frame::PathResponse(ref pr) => {
                    // multipath-21 Section 3.4: 同じパケットの先行フレームで
                    // 廃棄したパスも、後続の応答で再検証してはならない。
                    if self.is_path_abandoned(path_id) {
                        continue;
                    }
                    // PATH_RESPONSE を受信: 対応する PATH_CHALLENGE を解決する
                    let mut should_reset_cc_rtt = false;
                    let mut newly_validated = false;
                    let mut needs_mtu_validation = false;
                    if let Some(path) = self.paths.get_mut(path_id)
                        && let Some(datagram_size) = path.validation.response_received(&pr.data)
                    {
                        // アドレス検証完了: アンチアンプリフィケーション制限を解除する
                        path.address_validated = true;
                        // RFC 9000 Section 9.4: アドレスの所有を確認した時点で
                        // CC / RTT をリセットする。MTU 検証の完了までは待たない。
                        if path.migration_reset_pending {
                            should_reset_cc_rtt = true;
                        }
                        if datagram_size >= 1200 {
                            path.state = PathState::Active;
                            newly_validated = true;
                            self.pending_path_probes.remove(&path_id);
                            self.output_queue.push_back(ConnectionOutput::ClearTimer {
                                id: TimerId::PathValidation { path_id },
                            });
                        } else {
                            // RFC 9000 Section 8.2.1: 小さいプローブでは最小 MTU を
                            // 確認できない。増幅制限を解除して新しいデータで再検証する。
                            path.state = PathState::Validating;
                            path.validation.restart();
                            needs_mtu_validation = true;
                        }
                    }
                    if newly_validated {
                        // 観測イベント: パス検証完了
                        self.observe(ConnectionObservationEvent::PathValidated { path_id });
                        // イベントはパスの借用を切った後に追加する
                        self.push_event(ConnectionEvent::PathValidated { path_id });
                    }
                    // 借用を切った後で reset を実行する (PathManager 経由で CC を再生成)
                    if should_reset_cc_rtt {
                        // 旧 4-tuple へ送ったプローブのタイマーとバックオフを
                        // 清算する。タイマーが残っていると reset 直後の
                        // 探索状態へ旧プローブのタイムアウトが作用する。
                        // PMTU のプローブタイマーと再探索タイマーはパスごとの
                        // 概念である (RFC 8899 Section 5.1.1 / Section 5.2)。
                        self.output_queue.push_back(ConnectionOutput::ClearTimer {
                            id: TimerId::PmtuProbe { path_id },
                        });
                        self.output_queue.push_back(ConnectionOutput::ClearTimer {
                            id: TimerId::PmtuRaise { path_id },
                        });
                        self.pmtu_probe_backoff.remove(&path_id);
                        // 旧 4-tuple 向けに生成済みの PMTU probe を破棄する。
                        // 残すと旧探索のプローブサイズで新探索に計上され、
                        // 確認済み MTU が実サイズより小さくなる。
                        self.one_rtt_outputs.retain(|pending| {
                            !(pending.path_id == path_id && pending.purpose == OneRttPurpose::Pmtu)
                        });
                        // 旧 4-tuple へ送った送信済みプローブを、CC を
                        // 差し替える前に回収する。新 CC の状態に旧探索の
                        // 破棄副作用を及ぼさないためである。
                        if let Some(path) = self.paths.get_mut(path_id) {
                            discard_sent_pmtu_probes(path, path_id, &mut self.pmtu_probe_pns);
                        }
                        let old_pmtu = self.paths.get(path_id).map(|p| p.pmtu);
                        if self.paths.reset_cc_and_rtt_for_migration(path_id).is_ok() {
                            // 移行で PMTU を保守的な値へ戻す場合も、探索完了の
                            // 状態を含めて qlog に 1 回だけ出力する
                            // (qlog-quic-events-13 Section 4.8)。
                            let new_pmtu = self.paths.get(path_id).map(|p| p.pmtu);
                            let done = self
                                .paths
                                .get(path_id)
                                .map(|p| !p.mtu_controller.needs_probe());
                            if let (Some(old), Some(new), Some(done)) = (old_pmtu, new_pmtu, done)
                                && old != new
                                && self.qlog_writer.is_some()
                            {
                                let time_ms = self.qlog_time_ms();
                                if let Some(ref mut w) = self.qlog_writer {
                                    w.on_mtu_updated(time_ms, u32::from(old), u32::from(new), done);
                                }
                            }
                        }
                    }
                    if needs_mtu_validation {
                        let mut challenge = [0u8; 8];
                        aws_lc_rs::rand::fill(&mut challenge).map_err(|_| {
                            Error::InvalidData("failed to generate random bytes".into())
                        })?;
                        self.paths
                            .get_mut(path_id)
                            .expect("validated path exists")
                            .validation
                            .request_challenge(challenge);
                        self.emit_1rtt_path_challenge(path_id, challenge, now)?;
                        let pto = self.path_validation_pto(path_id);
                        self.output_queue.push_back(ConnectionOutput::SetTimer {
                            id: TimerId::PathValidation { path_id },
                            deadline: now + pto,
                        });
                    }
                    // preferred_address への移行検証が成功した場合は、検証前から
                    // 保持していた 4-tuple と CID を新しい値で確定する。
                    // ここで確定するまでパスの 4-tuple は元のままであるため、
                    // 検証中も通常のパケットは元のアドレスで送受信できる。
                    if newly_validated {
                        self.commit_pending_migration(path_id, now);
                    }
                    // 新しいパスが検証できたら OBSERVED_ADDRESS を送る
                    // (draft-ietf-quic-address-discovery-01 Section 5 MUST)
                    if newly_validated {
                        self.send_observed_address(path_id, now)?;
                    }
                    // 検証済みで keep-alive が有効なパスは、ここからタイマーを
                    // 設定して到達性を維持する。
                    if newly_validated {
                        self.arm_keep_alive_timer(path_id, now);
                    }
                    // PathController にパス検証成功を通知する (reset 後)
                    if newly_validated
                        && let Some(path) = self.paths.get(path_id)
                        && path.state == PathState::Active
                        && path.validation.validated
                    {
                        let pc_event = PathControlEvent::PathValidated { path_id };
                        let actions = self.invoke_path_controller(&pc_event, now);
                        self.execute_path_actions(actions, now);
                    }
                    // RFC 10069 Section 3.1.3 / RFC 9000 Section 9.3:
                    // 新しいクライアントアドレスのパス検証成功後、サーバーは NEW_TOKEN を
                    // 発行して次回接続時のアドレス検証をスキップ可能にする。
                    // `newly_validated` はサーバー自身が送った PATH_CHALLENGE に
                    // 対する PATH_RESPONSE が一致した場合にだけ真になる。ハンドシェイク
                    // 中の初期パス検証は PATH_CHALLENGE / PATH_RESPONSE を経由しない
                    // ため、初期パスも対象に含めても NEW_TOKEN が増えることはない。
                    //
                    // Multipath 環境では、過去に検証済みの全アドレスをトークンに含めて
                    // クライアントに渡す (Section 3.1.3): これによりクライアントが
                    // どのアドレスから再接続しても同じトークンで検証できる。
                    if newly_validated && self.role == Role::Server && self.token_provider.is_some()
                    {
                        let validated_addrs: Vec<std::net::SocketAddr> = self
                            .paths
                            .all_paths()
                            .filter(|p| p.address_validated)
                            .map(|p| p.remote_addr)
                            .collect();
                        if !validated_addrs.is_empty() {
                            // 失敗 (プロバイダ未設定等) は無視: 上の is_some() で
                            // プロバイダは存在済みなので実質的には成功する想定。
                            let _ = self.send_new_token_auto_multi(&validated_addrs, now);
                        }
                    }
                }
                Frame::PathStatusAvailable(ref ps) => {
                    self.validate_frame_path_id(ps.path_id)?;
                    self.process_path_status(
                        PathId(ps.path_id),
                        ps.path_status_sequence_number.as_u64(),
                        PathStatus::Available,
                    );
                }
                Frame::PathStatusBackup(ref ps) => {
                    self.validate_frame_path_id(ps.path_id)?;
                    self.process_path_status(
                        PathId(ps.path_id),
                        ps.path_status_sequence_number.as_u64(),
                        PathStatus::Backup,
                    );
                }
                Frame::NewConnectionId(ref ncid) => {
                    // NEW_CONNECTION_ID は Path ID 0 に対する CID 発行 (RFC 9000 Section 19.15)
                    //
                    // RFC 9000 Section 19.15: zero-length DCID で送信しているエンドポイントは
                    // NEW_CONNECTION_ID の受信を PROTOCOL_VIOLATION として扱わなければ
                    // ならない (MUST)。受信自体が違反のため、sequence_number /
                    // retire_prior_to / connection_id の値に関わらず他の検証より
                    // 前に弾く (順序ポリシー)。
                    if self.peer_cid.is_empty() {
                        return Err(Error::Protocol {
                            code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                            reason: "received NEW_CONNECTION_ID but local endpoint is sending packets with zero-length DCID".into(),
                        });
                    }
                    // Retire Prior To の検証、abandon 済みパスの無視、CID 登録、
                    // 送信先 CID の選び直し、上限検査は PATH_NEW_CONNECTION_ID と
                    // 共通の処理にまとめる。
                    self.handle_peer_cid_frame(
                        PeerCidFrameKind::NewConnectionId,
                        PathId::INITIAL,
                        ncid.sequence_number.as_u64(),
                        ncid.retire_prior_to.as_u64(),
                        ncid.connection_id.clone(),
                        Some(ncid.stateless_reset_token),
                    )?;
                }
                Frame::RetireConnectionId(ref rcid) => {
                    // RETIRE_CONNECTION_ID: Path ID 0 の CID をリタイアする
                    // (RFC 9000 Section 19.16)
                    //
                    // RFC 9000 Section 19.16: zero-length CID を提供したエンドポイントは
                    // RETIRE_CONNECTION_ID の受信を PROTOCOL_VIOLATION として扱わなければ
                    // ならない (MUST)。受信自体が違反のため、sequence_number の値に関わらず
                    // 発行済み範囲検証より前に弾く (順序ポリシー)。
                    if self.local_cid.is_empty() {
                        return Err(Error::Protocol {
                            code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                            reason: "received RETIRE_CONNECTION_ID but local endpoint provided zero-length CID".into(),
                        });
                    }
                    // RFC 9000 Section 19.16: 発行済み最大より大きいシーケンス番号を
                    // 含む RETIRE_CONNECTION_ID の受信は PROTOCOL_VIOLATION として
                    // 扱わなければならない (MUST)。next_local_cid_seq は「発行済み最大
                    // + 1」なので、seq >= 次回発行予定を未発行として拒否する。
                    let expected_next_seq = self.expected_next_local_cid_seq(PathId::INITIAL);
                    if rcid.sequence_number >= expected_next_seq {
                        return Err(Error::Protocol {
                            code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                            reason: format!(
                                "RETIRE_CONNECTION_ID sequence_number {} exceeds issued range (next {})",
                                rcid.sequence_number, expected_next_seq
                            ),
                        });
                    }
                    if let Some(retired_cid) = self
                        .local_cid_table
                        .remove(&(0, rcid.sequence_number.as_u64()))
                    {
                        self.paths.unregister_cid(&retired_cid);
                        // I/O 層のルーティングテーブルからも削除する
                        self.output_queue
                            .push_back(ConnectionOutput::UnregisterLocalCid { cid: retired_cid });
                        // 実際にリタイアが発生したときのみ新しい CID を再発行する。
                        // 除去対象が存在しない RETIRE で再発行すると、攻撃者が無効な
                        // RETIRE を大量送信するだけで CID 生成とテーブル肥大を強制でき
                        // 増幅型 DoS になるため、再発行は remove が成功した場合に限定する。
                        // generate_new_cid_with_rotation で retire_prior_to を計算し、
                        // Path 0 の active_connection_id_limit を超えないよう回転する。
                        if self.active_local_cid_count(PathId::INITIAL)
                            < self.peer_active_cid_limit()
                            && let Ok((seq, cid, token, retire_prior_to)) =
                                self.generate_new_cid_with_rotation(PathId::INITIAL)
                        {
                            self.streams
                                .pending_frames
                                .push_back(Frame::NewConnectionId(
                                    frame::new_connection_id::NewConnectionId {
                                        sequence_number: VarInt::new(seq)
                                            .expect("value fits in 62-bit varint"),
                                        retire_prior_to: VarInt::new(retire_prior_to)
                                            .expect("value fits in 62-bit varint"),
                                        connection_id: cid,
                                        stateless_reset_token: token,
                                    },
                                ));
                        }
                    }
                }
                Frame::PathNewConnectionId(ref pncid) => {
                    // RFC 10069 Section 4:
                    // path ID > max_path_id は PROTOCOL_VIOLATION
                    self.validate_frame_path_id(pncid.path_id)?;
                    // Retire Prior To の検証、abandon 済みパスの無視、CID 登録、
                    // 送信先 CID の選び直し、上限検査は NEW_CONNECTION_ID と
                    // 共通の処理にまとめる。abandon 判定は共通処理の中で
                    // Retire Prior To の検証後に行う。
                    self.handle_peer_cid_frame(
                        PeerCidFrameKind::PathNewConnectionId,
                        PathId(pncid.path_id),
                        pncid.sequence_number.as_u64(),
                        pncid.retire_prior_to.as_u64(),
                        pncid.connection_id.clone(),
                        Some(pncid.stateless_reset_token),
                    )?;
                }
                Frame::PathRetireConnectionId(ref prcid) => {
                    // RFC 10069 Section 4:
                    // path ID > max_path_id は PROTOCOL_VIOLATION
                    self.validate_frame_path_id(prcid.path_id)?;
                    // RFC 10069 Section 4:
                    // abandoned path ID のフレームは無視する (MUST)
                    if self.is_path_abandoned(PathId(prcid.path_id)) {
                        continue;
                    }
                    // RFC 10069 Section 4.5: PATH_RETIRE_CONNECTION_ID は
                    // RFC 9000 Section 19.16 と同じ処理をパスごとに適用する。発行済み最大
                    // より大きいシーケンス番号は未発行であり PROTOCOL_VIOLATION として
                    // 扱う。abandoned パス宛ての遅延フレームは上の無視処理を優先するため、
                    // この検証は path_id 検証・abandoned チェックの後に置く。
                    let expected_next_seq = self.expected_next_local_cid_seq(PathId(prcid.path_id));
                    if prcid.sequence_number >= expected_next_seq {
                        return Err(Error::Protocol {
                            code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                            reason: format!(
                                "PATH_RETIRE_CONNECTION_ID sequence_number {} exceeds issued range (next {})",
                                prcid.sequence_number, expected_next_seq
                            ),
                        });
                    }
                    // PATH_RETIRE_CONNECTION_ID: 指定パスの CID をリタイアする
                    let retire_path_id = prcid.path_id;
                    if let Some(retired_cid) = self
                        .local_cid_table
                        .remove(&(prcid.path_id, prcid.sequence_number.as_u64()))
                    {
                        self.paths.unregister_cid(&retired_cid);
                        // I/O 層のルーティングテーブルからも削除する
                        self.output_queue
                            .push_back(ConnectionOutput::UnregisterLocalCid { cid: retired_cid });
                        // 実際にリタイアが発生したときのみ再発行する (増幅 DoS 対策)。
                        // generate_new_cid_with_rotation で retire_prior_to を計算し、連続した
                        // retire → 再発行サイクルでもピアの active_connection_id_limit を
                        // 超えないように回転する。
                        if self.active_local_cid_count(PathId(retire_path_id))
                            < self.peer_active_cid_limit()
                            && let Ok((seq, cid, token, retire_prior_to)) =
                                self.generate_new_cid_with_rotation(PathId(retire_path_id))
                        {
                            self.streams
                                .pending_frames
                                .push_back(Frame::PathNewConnectionId(
                                    frame::path_new_connection_id::PathNewConnectionId {
                                        path_id: retire_path_id,
                                        sequence_number: VarInt::new(seq)
                                            .expect("value fits in 62-bit varint"),
                                        retire_prior_to: VarInt::new(retire_prior_to)
                                            .expect("value fits in 62-bit varint"),
                                        connection_id: cid,
                                        stateless_reset_token: token,
                                    },
                                ));
                        }
                    }
                }
                Frame::MaxPathId(ref mp) => {
                    // MAX_PATH_ID: ピアが許容する最大 Path ID を更新する
                    // RFC 10069 Section 4.6:
                    // initial_max_path_id 未満の値は PROTOCOL_VIOLATION
                    if mp.maximum_path_id < self.peer_initial_max_path_id {
                        return Err(Error::Protocol {
                            code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                            reason: format!(
                                "MAX_PATH_ID {} is lower than initial_max_path_id {}",
                                mp.maximum_path_id, self.peer_initial_max_path_id
                            ),
                        });
                    }
                    // 以前の値より小さい場合は無視 (RFC 10069 Section 4.6)
                    if mp.maximum_path_id > self.paths.remote_max_path_id {
                        self.paths.remote_max_path_id = mp.maximum_path_id;
                        // ピアの制限拡大に伴い、新しい Path ID の CID を先行発行する
                        self.issue_proactive_cids();
                    }
                }
                Frame::PathsBlocked(ref pb) => {
                    // RFC 10069 Section 4.7:
                    // Maximum Path Identifier > local max は PROTOCOL_VIOLATION (MUST)
                    self.validate_frame_path_id(pb.maximum_path_id)?;
                    // PATHS_BLOCKED: ピアがパス数上限に達した通知
                    // アプリケーションに通知して MAX_PATH_ID の増加を委ねる
                    self.push_event(ConnectionEvent::PathsBlocked {
                        maximum_path_id: pb.maximum_path_id,
                    });
                }
                Frame::PathCidsBlocked(ref pcb) => {
                    // RFC 10069 Section 4.7:
                    // Path Identifier > local max は PROTOCOL_VIOLATION (MUST)
                    self.validate_frame_path_id(pcb.path_id)?;
                    // RFC 10069 Section 4:
                    // abandoned path ID のフレームは無視する (MUST)
                    if self.is_path_abandoned(PathId(pcb.path_id)) {
                        continue;
                    }
                    // RFC 10069 Section 4.7:
                    // Next Sequence Number がローカルの次回発行予定シーケンス番号を
                    // 超えている場合は PROTOCOL_VIOLATION (MUST)。プロアクティブ発行
                    // のみで Path オブジェクトが未生成のパスも境界を持つため、
                    // proactive_cid_next_seq を含めて計算する `expected_next_local_cid_seq`
                    // を使う (境界演算子 `>` の根拠と RETIRE 系との非対称はヘルパーの doc を参照)。
                    let expected_next_seq = self.expected_next_local_cid_seq(PathId(pcb.path_id));
                    if pcb.next_sequence_number > expected_next_seq {
                        return Err(Error::Protocol {
                            code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                            reason: format!(
                                "PATH_CIDS_BLOCKED next_sequence_number {} exceeds expected {}",
                                pcb.next_sequence_number, expected_next_seq
                            ),
                        });
                    }
                    // 既に expected_next_seq まで発行済みなら、ピアの通知は古い。
                    // RFC 10069 Section 4.7 は本フレームを
                    // informational としているため、再送で CID を発行し続けない。
                    if pcb.next_sequence_number < expected_next_seq {
                        continue;
                    }

                    // PATH_CIDS_BLOCKED: ピアが CID 不足を通知
                    // 対象パスに新しい CID を発行する。
                    //
                    // RFC 10069 Section 4.3 / RFC 9000 Section 5.1.1:
                    // ピアの active_connection_id_limit を超える CID を発行してはならない。
                    // generate_new_cid_with_rotation で retire_prior_to を計算し、
                    // 必要なら古い CID を順次リタイアさせて回転する。
                    let blocked_path_id = pcb.path_id;
                    if let Ok((seq, cid, token, retire_prior_to)) =
                        self.generate_new_cid_with_rotation(PathId(blocked_path_id))
                    {
                        self.streams
                            .pending_frames
                            .push_back(Frame::PathNewConnectionId(
                                frame::path_new_connection_id::PathNewConnectionId {
                                    path_id: blocked_path_id,
                                    sequence_number: VarInt::new(seq)
                                        .expect("value fits in 62-bit varint"),
                                    retire_prior_to: VarInt::new(retire_prior_to)
                                        .expect("value fits in 62-bit varint"),
                                    connection_id: cid,
                                    stateless_reset_token: token,
                                },
                            ));
                    }
                }
                Frame::ObservedAddress(ref oa) => {
                    // draft-ietf-quic-address-discovery-01 Section 4.1:
                    // 受信を希望していない (未送信または 0) エンドポイントが
                    // OBSERVED_ADDRESS を受信したら PROTOCOL_VIOLATION (MUST)
                    if !matches!(self.local_params.address_discovery, Some(1) | Some(2)) {
                        return Err(Error::Protocol {
                            code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                            reason:
                                "OBSERVED_ADDRESS received without requesting address discovery"
                                    .into(),
                        });
                    }
                    // 同じパスで Sequence Number が同じか小さいフレームは無視する (SHOULD)
                    if let Some(prev) = self.observed_address_seq_recv.get(&path_id)
                        && oa.sequence_number <= *prev
                    {
                        continue;
                    }
                    self.observed_address_seq_recv
                        .insert(path_id, oa.sequence_number.as_u64());
                    self.push_event(ConnectionEvent::ObservedAddress {
                        path_id,
                        addr: oa.addr,
                    });
                    // PathController に観測アドレスを通知する
                    let pc_event = PathControlEvent::ObservedAddressReceived {
                        path_id,
                        addr: oa.addr,
                    };
                    let actions = self.invoke_path_controller(&pc_event, now);
                    self.execute_path_actions(actions, now);
                }
                Frame::PathAbandon(ref pa) => {
                    self.validate_frame_path_id(pa.path_id)?;
                    self.process_path_abandon(pa, now)?;
                }
                Frame::Datagram(ref dg) => {
                    // RFC 9221 Section 3: transport parameter で DATAGRAM サポートを
                    // 示していない場合は PROTOCOL_VIOLATION。未広告と 0 はどちらも
                    // 「受信非対応」を表すが、原因を追えるよう理由を分ける。
                    let local_max = match self.local_params.max_datagram_frame_size {
                        Some(value) if value > 0 => value,
                        // 直前のガードで正の値は処理済みであるため 0 だけが到達する。
                        Some(_) => {
                            return Err(Error::Protocol {
                                code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                                reason:
                                    "received DATAGRAM frame but max_datagram_frame_size was advertised as 0"
                                        .to_string(),
                            });
                        }
                        None => {
                            return Err(Error::Protocol {
                                code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                                reason:
                                    "received DATAGRAM frame but max_datagram_frame_size was not advertised"
                                        .to_string(),
                            });
                        }
                    };
                    // RFC 9221 Section 3: 受信した DATAGRAM フレームのサイズが
                    // 自身の max_datagram_frame_size を超過する場合は PROTOCOL_VIOLATION。
                    // サイズは `Frame::decode` が返す消費バイト数 `consumed` を
                    // wire 長として判定する。再エンコード後のサイズと何が違うかは
                    // `Datagram::encoded_size` の doc を参照。
                    //
                    // 0-RTT ではピアがこの接続の transport parameter をまだ
                    // 受け取っておらず、前回のハンドシェイクで記憶した値に基づいて
                    // 送ってくる可能性がある。それでも受信側の上限はこの接続の
                    // 設定で確定しているため、同じ判定を適用する (RFC 9221 Section 3)。
                    if consumed as u64 > local_max {
                        return Err(Error::Protocol {
                            code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                            reason: format!(
                                "DATAGRAM frame wire length {consumed} exceeds max_datagram_frame_size {local_max}"
                            ),
                        });
                    }
                    // 受信データグラムを受信キューへ積む。上限に達している
                    // 場合は最も古い DATAGRAM を破棄する。
                    self.push_datagram_recv(dg.data.clone());
                }
                Frame::ConnectionClose(cc) => {
                    // qlog: 状態遷移 → Draining
                    if self.qlog_writer.is_some() {
                        let time_ms = self.qlog_time_ms();
                        let old = match self.state {
                            ConnectionState::Connected => "connected",
                            ConnectionState::Handshaking => "handshaking",
                            _ => "unknown",
                        };
                        if let Some(ref mut w) = self.qlog_writer {
                            w.on_connection_state_updated(time_ms, old, "draining");
                        }
                    }
                    self.state = ConnectionState::Draining;
                    let kind = if cc.application {
                        ConnectionCloseKind::Application
                    } else {
                        ConnectionCloseKind::Transport
                    };
                    self.push_event(ConnectionEvent::ConnectionClosed {
                        error_code: cc.error_code.as_u64(),
                        reason: cc.reason_phrase,
                        kind,
                    });
                    self.set_closing_draining_timer(now);
                }
                Frame::NewToken(ref nt) => {
                    // RFC 9000 Section 19.7: NEW_TOKEN はサーバーからクライアントのみ
                    if self.role != Role::Client {
                        return Err(Error::Protocol {
                            code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                            reason: "server received NEW_TOKEN frame".to_string(),
                        });
                    }
                    // RFC 9000 Section 19.7: 空のトークンは FRAME_ENCODING_ERROR
                    if nt.token.is_empty() {
                        return Err(Error::Protocol {
                            code: tobi_core::error::TransportErrorCode::FRAME_ENCODING_ERROR,
                            reason: "NEW_TOKEN with empty token".to_string(),
                        });
                    }
                    // トークンを保存する (次回接続の Initial パケットで使用)
                    self.address_token = nt.token.clone();
                    self.push_event(ConnectionEvent::NewToken {
                        token: nt.token.clone(),
                    });
                }
                Frame::AckFrequency(ref af) => {
                    // draft-ietf-quic-ack-frequency-14 Section 4
                    self.process_ack_frequency(af, path_id)?;
                }
                Frame::ImmediateAck(_) => {
                    // draft-ietf-quic-ack-frequency-14 Section 5:
                    // 受信したら即座に ACK を送る。拡張を広告していない場合は
                    // 受信する想定がないため無視する。
                    if self.local_params.min_ack_delay.is_some()
                        && let Some(path) = self.paths.get_mut(path_id)
                    {
                        path.ack_tracker.request_immediate_ack();
                    }
                }
            }
        }
        // RFC 9000 Section 12.4: ペイロードには最低 1 つのフレームが含まれなければ
        // ならない。復号後のペイロードが 0 バイトで 1 フレームもデコードされなかった
        // 場合は PROTOCOL_VIOLATION として接続を閉じる (MUST)。
        // 空判定はフレーム数で行う。PADDING (0x00) も ACK も 1 フレームであるため、
        // PADDING のみ / ACK のみのパケットは「フレームを含む」として許容される。
        if frame_count == 0 {
            return Err(Error::Protocol {
                code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                reason: "packet payload contains no frames".into(),
            });
        }
        Ok(FrameProcessOutcome {
            ack_eliciting,
            non_probing,
        })
    }

    /// ACK_FREQUENCY フレームを処理する
    ///
    /// draft-ietf-quic-ack-frequency-14 Section 4:
    /// - 古いシーケンス番号のフレームは無視する (MUST)
    /// - Requested Max Ack Delay が 2^14 ミリ秒以上、または自分が広告した
    ///   `min_ack_delay` 未満なら PROTOCOL_VIOLATION
    /// - 有効な値はパスごとの ACK 送信制御に反映する
    fn process_ack_frequency(
        &mut self,
        af: &frame::ack_frequency::AckFrequency,
        path_id: PathId,
    ) -> Result<(), Error> {
        let Some(local_min_ack_delay_us) = self.local_params.min_ack_delay else {
            // 拡張を広告していない場合は ACK_FREQUENCY を処理しない。
            return Ok(());
        };
        // draft-ietf-quic-ack-frequency-14 Section 4:
        // Sequence Number が最後に処理した値以下のフレームは、検証より前に
        // 無視しなければならない (MUST)。
        let Some(path) = self.paths.get_mut(path_id) else {
            return Ok(());
        };
        if !path
            .ack_tracker
            .is_new_ack_frequency_sequence(af.sequence_number.as_u64())
        {
            return Ok(());
        }
        // 適用するフレームだけ値を検証する。
        const MAX_REQUESTED_MAX_ACK_DELAY_US: u64 = 16_384_000;
        if af.requested_max_ack_delay >= MAX_REQUESTED_MAX_ACK_DELAY_US {
            return Err(Error::Protocol {
                code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                reason: format!(
                    "ACK_FREQUENCY requested max ack delay {}us must be below 2^14 ms",
                    af.requested_max_ack_delay
                ),
            });
        }
        if af.requested_max_ack_delay < local_min_ack_delay_us {
            return Err(Error::Protocol {
                code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                reason: format!(
                    "ACK_FREQUENCY requested max ack delay {}us is below advertised min_ack_delay {local_min_ack_delay_us}us",
                    af.requested_max_ack_delay
                ),
            });
        }
        // 受信した ACK_FREQUENCY は自分がデータ受信側としての ACK 送信間隔を
        // 変えるだけで、自分が送信側として使う PTO のピア max_ack_delay は
        // 変えない。PTO 側の更新は ACK_FREQUENCY を送信した接続だけが行う
        // (draft-ietf-quic-ack-frequency-14 Section 7)。
        path.ack_tracker.apply_ack_frequency(
            af.sequence_number.as_u64(),
            af.ack_eliciting_threshold.as_u64(),
            af.requested_max_ack_delay.as_u64(),
            af.reordering_threshold.as_u64(),
        );
        // 遅延中の ACK があれば、新しい Requested Max Ack Delay でタイマーを張り直す。
        let requested_delay =
            tobi_core::time::Duration::from_micros(af.requested_max_ack_delay.as_u64());
        if !path.ack_tracker.should_send_ack_now()
            && let Some(deadline) = path.ack_tracker.ack_delay_deadline(requested_delay)
        {
            self.output_queue.push_back(ConnectionOutput::SetTimer {
                id: TimerId::AckDelay { path_id },
                deadline,
            });
        }
        Ok(())
    }

    // --- ACK 処理と損失検出 ---

    /// 現在の状態でハンドシェイクが確認済みかを返す (RFC 9001 Section 4.1.2)
    ///
    /// クライアントは HANDSHAKE_DONE 受信時、サーバーはハンドシェイク完了時に
    /// `state` が `Connected` へ遷移するため、`state == Connected` が現在の
    /// 状態での確認済みを表す。RTT サンプル補正や鍵更新の前提など、現在の
    /// 状態に依存する判定にはこの関数を使う。
    ///
    /// closing / draining 中は false となるため、遷移後も確認状態を保つ必要が
    /// あるライフサイクル期限 (Closing / Draining、鍵関連期限) では
    /// `handshake_confirmed_once` を使う。
    fn is_handshake_confirmed(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    /// 損失検出タイマーを armed する
    ///
    /// パスにつき 1 つのタイマーを空間付きで管理する。空間が変わった場合は
    /// 古い空間のタイマーを破棄してから新しい空間で設定する。
    fn set_loss_detection_timer(
        &mut self,
        path_id: PathId,
        space: PacketNumberSpace,
        deadline: Timestamp,
    ) {
        if let Some(armed) = self.loss_detection_timers_armed.get(&path_id).copied()
            && armed != space
        {
            self.output_queue.push_back(ConnectionOutput::ClearTimer {
                id: TimerId::LossDetection {
                    path_id,
                    space: armed,
                },
            });
        }
        self.loss_detection_timers_armed.insert(path_id, space);
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::LossDetection { path_id, space },
            deadline,
        });
    }

    /// 損失検出タイマーを disarm する
    ///
    /// 未 armed のタイマーに対する ClearTimer は出力しない。タイマーを armed
    /// していないパスしかない場合に出力キューが空のままになり、silent に
    /// 破棄すべきパケットで出力が生じない。
    fn clear_loss_detection_timer(&mut self, path_id: PathId) {
        if let Some(space) = self.loss_detection_timers_armed.remove(&path_id) {
            self.output_queue.push_back(ConnectionOutput::ClearTimer {
                id: TimerId::LossDetection { path_id, space },
            });
        }
    }

    /// 指定空間の損失検出タイマーだけを disarm する
    ///
    /// 鍵破棄や 0-RTT 拒否では該当空間の状態だけを破棄する。他の空間の
    /// タイマーが armed 済みならそのまま維持する。
    fn clear_loss_detection_timer_for_space(&mut self, path_id: PathId, space: PacketNumberSpace) {
        if self.loss_detection_timers_armed.get(&path_id).copied() == Some(space) {
            self.loss_detection_timers_armed.remove(&path_id);
            self.output_queue.push_back(ConnectionOutput::ClearTimer {
                id: TimerId::LossDetection { path_id, space },
            });
        }
    }

    /// 新しい鍵フェーズの状態を初期化する
    ///
    /// `key_update_allowed_at` は現行フェーズを確認する最初の ACK を受けるまで
    /// None のままにし、`key_phase_established_by_update` で TLS が最初に提供した
    /// 1-RTT 鍵のフェーズと鍵更新後のフェーズを区別する。鍵を設定する前でも
    /// 呼べる。ACK 追跡とクールダウンの状態だけを初期化する。
    fn begin_key_phase(&mut self, established_by_update: bool) {
        self.key_update_allowed_at = None;
        // 一度でも鍵更新でフェーズを開始したら true のままにする
        self.key_phase_established_by_update |= established_by_update;
        self.reset_key_phase_ack_tracking();
    }

    /// Key Phase の ACK 追跡を新しいフェーズとして初期化する
    ///
    /// RFC 9001 Section 6.1: 新しい鍵フェーズを開始した時点のパスごとの次回送信
    /// パケット番号を記録し、それ以降に送ったパケットの ACK だけを現行フェーズの
    /// ACK として扱う。送信時刻の比較では同一 Timestamp で送った旧フェーズの
    /// パケットと区別できないため、パケット番号で判定する。
    fn reset_key_phase_ack_tracking(&mut self) {
        self.current_phase_acked = false;
        self.one_rtt_phase_start_pns.clear();
        let starts: Vec<(PathId, u64)> = self
            .paths
            .all_paths()
            .map(|path| (path.id, path.send_pn))
            .collect();
        for (path_id, send_pn) in starts {
            self.one_rtt_phase_start_pns.insert(path_id, send_pn);
        }
    }

    /// 暗号化レベルが属するパケット番号空間を返す
    ///
    /// 0-RTT と 1-RTT は Application Data 空間を共有する (RFC 9000 Section 12.3)。
    fn packet_number_space(level: EncryptionLevel) -> PacketNumberSpace {
        match level {
            EncryptionLevel::Initial => PacketNumberSpace::Initial,
            EncryptionLevel::Handshake => PacketNumberSpace::Handshake,
            EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt => {
                PacketNumberSpace::ApplicationData
            }
        }
    }

    /// パケット番号空間に対応する暗号化レベルを返す
    ///
    /// 再送は最初に送ったときと同じ暗号化レベルで行う (RFC 9001 Section 4.1.3)。
    /// Application Data 空間の 1-RTT 再送は OneRtt レベルで送る。
    fn encryption_level(space: PacketNumberSpace) -> EncryptionLevel {
        match space {
            PacketNumberSpace::Initial => EncryptionLevel::Initial,
            PacketNumberSpace::Handshake => EncryptionLevel::Handshake,
            PacketNumberSpace::ApplicationData => EncryptionLevel::OneRtt,
        }
    }

    /// RFC 9002 Appendix A.8 PeerCompletedAddressValidation
    ///
    /// サーバーは常に true。クライアントは Handshake ACK を受信するか
    /// ハンドシェイクが確認済みになるまで false で、その間は in-flight が
    /// 無くても anti-deadlock PTO を設定しなければならない
    /// (RFC 9002 Section 6.2.1 / 6.2.2.1 MUST)。
    fn peer_completed_address_validation(&self) -> bool {
        match self.role {
            Role::Server => true,
            Role::Client => {
                self.is_handshake_confirmed() || self.handshake_sent_packets.largest_acked.is_some()
            }
        }
    }

    /// パスの損失検出タイマー期限を RFC 9002 Appendix A.8 に従って計算する
    ///
    /// 戻り値は (対象のパケット番号空間, 期限)。タイマーを設定しない場合は None。
    ///
    /// - 空間ごとの時間閾値タイマー (`loss_time`) があれば、そのうち最も早いものを返す。
    /// - サーバーがアンチアンプリフィケーション制限で送信できない間は None。
    /// - ack-eliciting な in-flight が無い場合、クライアントのアドレス検証が
    ///   未完了なら anti-deadlock PTO (Handshake 鍵があれば Handshake、無ければ
    ///   Initial) を now + PTO 期間で返す。
    /// - それ以外は空間ごとの PTO 期限のうち最も早いものを返す。
    ///   Application Data 空間はハンドシェイク確認後だけ対象にする
    ///   (RFC 9002 Section 6.2.1 MUST NOT)。
    fn loss_detection_timer(
        &self,
        path_id: PathId,
        now: Timestamp,
    ) -> Option<(PacketNumberSpace, Timestamp)> {
        let path = self.paths.get(path_id)?;
        // Initial パスは 3 空間すべて、追加パスは Application Data 空間のみ扱う。
        let spaces: &[PacketNumberSpace] = if path_id == PathId::INITIAL {
            &PacketNumberSpace::ALL
        } else {
            &[PacketNumberSpace::ApplicationData]
        };

        // 1. 時間閾値の損失タイマー (RFC 9002 Section 6.1.2 / 6.2)。
        //    送信を伴わないためアンチアンプリフィケーション制限より優先する。
        if let Some((space, loss_time)) = path.loss_detectors.earliest_loss_time()
            && spaces.contains(&space)
        {
            return Some((space, loss_time));
        }

        // 2. サーバーがアンチアンプリフィケーション制限で送信できない間は
        //    PTO を armed してはならない (RFC 9002 Section 6.2.2.1 MUST NOT)。
        if self.server_pto_blocked_by_anti_amplification() {
            return None;
        }

        // 3. 空間ごとの ack-eliciting in-flight を判定する。
        let mut in_flight = [false; 3];
        for (index, space) in spaces.iter().enumerate() {
            in_flight[index] = match space {
                PacketNumberSpace::Initial => {
                    path_id == PathId::INITIAL
                        && self.initial_sent_packets.has_ack_eliciting_in_flight()
                }
                PacketNumberSpace::Handshake => {
                    path_id == PathId::INITIAL
                        && self.handshake_sent_packets.has_ack_eliciting_in_flight()
                }
                PacketNumberSpace::ApplicationData => {
                    self.is_handshake_confirmed() && path.sent_packets.has_ack_eliciting_in_flight()
                }
            };
        }

        if !in_flight.iter().any(|value| *value) {
            // 追加パスには anti-deadlock PTO を設定しない (Initial パスの役割)。
            if path_id != PathId::INITIAL || self.peer_completed_address_validation() {
                return None;
            }
            // RFC 9002 Section 6.2.1: クライアントは Handshake の ACK を受信するまで、
            // in-flight が無くても anti-deadlock PTO を設定しなければならない (MUST)。
            // 現在時刻から PTO 期間を足した期限を Initial / Handshake 空間に置く。
            let space = if self.handshake_keys.is_some() {
                PacketNumberSpace::Handshake
            } else {
                PacketNumberSpace::Initial
            };
            let deadline = now.add(path.loss_detectors.pto_period(
                space,
                &path.rtt,
                Duration::ZERO,
            ));
            return Some((space, deadline));
        }

        // 4. PTO 期限のうち最も早いものを選ぶ (RFC 9002 Section 6.2.1)。
        //    Initial / Handshake の両方に in-flight があれば早い方になる。
        // draft-ietf-quic-ack-frequency-14 Section 7: ACK_FREQUENCY で要求した
        // 値とピアの TP の大きい方を PTO に使う。
        let max_ack_delay = self.effective_peer_max_ack_delay();
        let mut earliest: Option<(PacketNumberSpace, Timestamp)> = None;
        for (index, space) in spaces.iter().enumerate() {
            if !in_flight[index] {
                continue;
            }
            let delay = if matches!(space, PacketNumberSpace::ApplicationData) {
                max_ack_delay
            } else {
                Duration::ZERO
            };
            if let Some(deadline) = path.loss_detectors.pto_time(*space, &path.rtt, delay)
                && earliest.is_none_or(|(_, current)| deadline < current)
            {
                earliest = Some((*space, deadline));
            }
        }
        earliest
    }

    /// サーバーがアンチアンプリフィケーション制限で PTO を armed できないか
    /// (RFC 9002 Section 6.2.2.1)
    ///
    /// 追加データを送れない間は、クライアントからデータグラムを受信するまで
    /// PTO タイマーを armed してはならない (MUST NOT)。PTO で送るパケットも
    /// アンチアンプリフィケーション制限に算入されるためである。
    fn server_pto_blocked_by_anti_amplification(&self) -> bool {
        if self.role != Role::Server || self.address_validated {
            return false;
        }
        // 最小の ack-eliciting パケット (1 バイト) すら送れない状態を
        // 「追加データを送れない」と判定する。
        self.send_datagram_blocked(1, PathId::INITIAL)
    }

    /// ACK フレームを処理し、損失検出を実行する
    ///
    /// 暗号化レベルに応じたパケット番号空間の SentPackets を使用する (RFC 9000 Section 12.3)。
    /// 輻輳制御とロス検出はパスに対して行う。
    /// 受信した Receive Timestamps 拡張フレームを検証する
    ///
    /// draft-ietf-quic-receive-ts-03 Section 6:
    /// - 自エンドポイントが max_receive_timestamps_per_ack を広告していない
    ///   (0 または未送信) 場合、このフレームを受信してはならない。
    /// - フレームに含まれるタイムスタンプの合計は広告した上限を超えてはならない。
    ///
    /// draft-ietf-quic-receive-ts-03 Section 4.1:
    /// タイムスタンプレンジが参照するパケット番号は Largest Acknowledged 以下で
    /// なければならない。タイムスタンプ値そのものの妥当性は受信側の裁量
    /// (Section 9) であり、本実装は値を使わないため検査しない。
    fn validate_receive_timestamps(
        &self,
        ack: &frame::ack::Ack,
        timestamps: &frame::receive_timestamps::ReceiveTimestamps,
    ) -> Result<(), Error> {
        let local_max = self
            .local_params
            .max_receive_timestamps_per_ack
            .unwrap_or(0);
        if local_max == 0 {
            return Err(Error::Protocol {
                code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                reason: "received receive timestamps frame without negotiation".into(),
            });
        }
        if timestamps.total_deltas() > local_max {
            return Err(Error::Protocol {
                code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                reason: format!(
                    "received {} receive timestamps, exceeding advertised maximum {local_max}",
                    timestamps.total_deltas()
                ),
            });
        }
        for range in &timestamps.timestamp_ranges {
            if range.delta_largest_acknowledged > ack.largest_acknowledged {
                return Err(Error::Protocol {
                    code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                    reason: "receive timestamp range starts above largest acknowledged".into(),
                });
            }
            let range_largest = ack.largest_acknowledged - range.delta_largest_acknowledged;
            // 降順に count 個のパケット番号を表すため、レンジの最大番号 + 1 個を超えない。
            if range.deltas.len() as u64 > range_largest.saturating_add(1) {
                return Err(Error::Protocol {
                    code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                    reason: "receive timestamp range underflows packet number space".into(),
                });
            }
        }
        Ok(())
    }

    fn process_ack(
        &mut self,
        ack: &frame::ack::Ack,
        path_id: PathId,
        ack_recv_path: PathId,
        level: EncryptionLevel,
        now: Timestamp,
    ) -> Result<(), Error> {
        // RFC 9001 Section 4.6.2: サーバーが 0-RTT を拒否した後、0-RTT パケットへの
        // ACK を受信した場合は PROTOCOL_VIOLATION とする (SHOULD)。拒否時点で
        // 送信済みパケットは破棄しているため、番号範囲を別途記録して検出する。
        if self.role == Role::Client
            && self.zero_rtt_rejected
            && level == EncryptionLevel::OneRtt
            && let Some((min, max)) = self.zero_rtt_sent_pn_range
            && ack.largest_acknowledged >= min
            && ack.largest_acknowledged <= max
        {
            return Err(Error::Protocol {
                code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                reason: "received ACK for rejected 0-RTT packet".into(),
            });
        }

        // ACK フレームはそのパケット番号空間の損失検出器で処理する
        // (RFC 9002 Section 4.1)。0-RTT と 1-RTT は Application Data 空間を共有する。
        let space = Self::packet_number_space(level);

        // Initial/Handshake の場合は Connection の PN 空間から SentPackets を一時的に借用する
        // (RFC 9000 Section 12.3: 各暗号化レベルは独立したパケット番号空間を持つ)
        // 関数終了時に戻す
        let mut temp_sent_packets = match level {
            EncryptionLevel::Initial => std::mem::take(&mut self.initial_sent_packets),
            EncryptionLevel::Handshake => std::mem::take(&mut self.handshake_sent_packets),
            // 0-RTT / 1-RTT は Application Data PN 空間を共有する (RFC 9000 Section 12.3)
            EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt => SentPackets::new(),
        };
        // RFC 9000 Section 13.1: 自身が送信していないパケット番号を確認応答する
        // ACK の受信は、検出できる場合 PROTOCOL_VIOLATION とする (SHOULD)。
        // 本実装はパケット番号を飛ばさずに送信するため、次に送信するパケット番号
        // 以上の largest_acknowledged は未送信パケットへの ACK と判定できる。
        // なお 0-RTT / 1-RTT は Application Data のパケット番号空間を共有するため、
        // パスごとの次回送信番号 (`Path::send_pn`) で比較する。
        // path の可変借用より前に解決する。
        let next_send_pn = match level {
            EncryptionLevel::Initial => self.initial_send_pn,
            EncryptionLevel::Handshake => self.handshake_send_pn,
            EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt => {
                self.paths
                    .get(path_id)
                    .expect("path for ACK must exist")
                    .send_pn
            }
        };
        // qlog の時刻も path の可変借用より前に解決する
        let qlog_time_ms = self.qlog_time_ms();
        // RTT サンプル調整と Persistent Congestion 判定に使う実効
        // max_ack_delay は path の可変借用より前に解決する。
        let effective_peer_max_ack_delay = self.effective_peer_max_ack_delay();
        let handshake_confirmed = self.is_handshake_confirmed();
        let rtt_max_ack_delay =
            effective_max_ack_delay(handshake_confirmed, Some(effective_peer_max_ack_delay));
        // spurious loss 判定用の保持期間は path の可変借用より前に解決する。
        let spurious_loss_retention = self.spurious_loss_retention(path_id, space);
        // spurious loss の MTU フィードバックに使う base MTU を借用前に解決する
        let base_mtu_for_spurious = self
            .paths
            .get(path_id)
            .map(|path| path.mtu_controller.base_mtu())
            .unwrap_or(tobi_core::path::mtu::BASE_MTU);
        let path = self.paths.get_mut(path_id).expect("path must exist");
        let sent_packets = match level {
            EncryptionLevel::Initial | EncryptionLevel::Handshake => &mut temp_sent_packets,
            EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt => &mut path.sent_packets,
        };

        // ACK で示されたパケットを確認応答する
        //
        // RFC 9002 Appendix B.5: 輻輳制御の会計は in-flight だったパケットだけを
        // 対象にする。ACK 専用パケット (in_flight == false) は bytes_in_flight に
        // 含まれていないため、減算にも cwnd 増加にも使わない。
        let mut total_acked_in_flight_bytes: u64 = 0;
        // in-flight だった ACK 済みパケットの最新送信時刻 (on_ack_received 用)
        let mut newest_acked_in_flight_time_sent: Option<Timestamp> = None;
        // largest_acknowledged が新規 ACK されたパケットの送信時刻 (RTT サンプル用)
        let mut largest_acked_time_sent: Option<Timestamp> = None;
        // 新規 ACK されたパケットに ack-eliciting が含まれるか
        // (RFC 9002 Section 5.1 の RTT サンプル生成条件)
        let mut newly_acked_ack_eliciting = false;
        let mut newly_acked_largest = false;
        // on_packets_acked_cc へ渡す in-flight パケットだけの一覧
        let mut acked_in_flight_packets: Vec<AckedPacketInfo> = Vec::new();
        let mut acked_packets: Vec<AckedPacketInfo> = Vec::new();
        // ACK された STREAM / RESET_STREAM / RESET_STREAM_AT などの情報を
        // 3 経路 (largest_acknowledged / first_ack_range / 追加 ACK 範囲) で
        // 共通に収集する。STREAM の範囲は ACK 済みデータの解放と終端遷移に、
        // RESET_STREAM は ResetSent → ResetRecvd の遷移に使う。
        let mut acked_frames = AckedFrameCollector::default();
        // 本 ACK で新規 ACK された ECT(0) パケット数 (RFC 9000 Section 13.4.2.1 の検証に使う)
        let mut newly_acked_ect0: u64 = 0;
        // spurious loss 判定で ACK 範囲を再走査するための範囲一覧
        let mut acked_ranges: Vec<(u64, u64)> = Vec::new();

        // largest_acknowledged を処理
        if let Some(pkt) = sent_packets.ack_packet(ack.largest_acknowledged.as_u64()) {
            newly_acked_largest = true;
            largest_acked_time_sent = Some(pkt.time_sent);
            if pkt.ack_eliciting {
                newly_acked_ack_eliciting = true;
            }
            // RFC 9002 Appendix B.5: 輻輳制御へ渡すのは in-flight だった
            // パケットの sent_bytes だけ。ACK-only パケットは bytes_in_flight に
            // 含まれておらず、cwnd 増加の対象でもない。
            if pkt.in_flight {
                total_acked_in_flight_bytes += pkt.sent_bytes;
                newest_acked_in_flight_time_sent = Some(pkt.time_sent);
            }
            if matches!(pkt.ecn, EcnCodepoint::Ect0) {
                newly_acked_ect0 += 1;
            }
            let packet_info = AckedPacketInfo {
                space,
                pn: ack.largest_acknowledged.as_u64(),
                time_sent: pkt.time_sent,
                sent_bytes: pkt.sent_bytes,
            };
            acked_packets.push(packet_info);
            if pkt.in_flight {
                acked_in_flight_packets.push(packet_info);
            }
            acked_frames.collect(&pkt);

            // このパスで送信したパケットが ACK された。送信パスが機能している
            // 証拠として、到達性の確認時刻を更新する。RTT サンプルの生成条件は
            // 全 ACK 範囲を処理した後に別途判定する (RFC 9002 Section 5.1)。
            path.last_acked_at = Some(now);
        }

        // ACK 範囲の処理
        //
        // RFC 9000 Section 19.3: ACK フレームは攻撃者が `first_ack_range` や `ack_range` を
        // 2^62 に近い値にすることで 10^18 回規模のループを誘発できる。ピア主張の範囲を
        // 逐次列挙する従来実装はこの攻撃に対して脆弱なため、自分が保持している
        // `sent_packets` のキーセットとの交差のみを取るアルゴリズムに変更する。
        // あわせて `first_ack_range > largest_acknowledged` などの不整合は
        // `FRAME_ENCODING_ERROR` で接続を閉じる (RFC 9000 Section 19.3.1)。
        if ack.first_ack_range > ack.largest_acknowledged {
            return Err(Error::Protocol {
                code: tobi_core::error::TransportErrorCode::FRAME_ENCODING_ERROR,
                reason: format!(
                    "ACK first_ack_range {} exceeds largest_acknowledged {}",
                    ack.first_ack_range, ack.largest_acknowledged
                ),
            });
        }

        // RFC 9000 Section 13.1: 自身が送信していないパケット番号を確認応答する
        // ACK の受信は、検出できる場合 PROTOCOL_VIOLATION とする (SHOULD)。
        // 構造的な不正 (first_ack_range など) の FRAME_ENCODING_ERROR を優先する。
        // 次に送信するパケット番号は path の可変借用より前に解決済み (`next_send_pn`)。
        if ack.largest_acknowledged >= next_send_pn {
            return Err(Error::Protocol {
                code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                reason: format!(
                    "ACK acknowledges unsent packet number {} (next send packet number is {next_send_pn})",
                    ack.largest_acknowledged
                ),
            });
        }

        // first_ack_range 内のパケットを確認応答
        let range_end = ack.largest_acknowledged;
        let range_start_first = range_end - ack.first_ack_range;
        // largest_acknowledged も ACK 済みのため範囲に含める。
        acked_ranges.push((range_start_first, range_end.as_u64()));
        let first_pns = sent_packets.pns_in_range(range_start_first, range_end.saturating_sub(1));
        for pn in first_pns {
            if let Some(pkt) = sent_packets.ack_packet(pn) {
                if pkt.ack_eliciting {
                    newly_acked_ack_eliciting = true;
                }
                if pkt.in_flight {
                    total_acked_in_flight_bytes += pkt.sent_bytes;
                    newest_acked_in_flight_time_sent =
                        Some(match newest_acked_in_flight_time_sent {
                            Some(newest) if newest >= pkt.time_sent => newest,
                            _ => pkt.time_sent,
                        });
                }
                if matches!(pkt.ecn, EcnCodepoint::Ect0) {
                    newly_acked_ect0 += 1;
                }
                let packet_info = AckedPacketInfo {
                    space,
                    pn,
                    time_sent: pkt.time_sent,
                    sent_bytes: pkt.sent_bytes,
                };
                acked_packets.push(packet_info);
                if pkt.in_flight {
                    acked_in_flight_packets.push(packet_info);
                }
                acked_frames.collect(&pkt);
            }
        }

        // 追加の ACK 範囲を処理
        let mut current = range_start_first;
        for ack_range in &ack.ack_ranges {
            // current < gap + 2 は不整合。RFC 9000 Section 19.3.1 により FRAME_ENCODING_ERROR。
            let gap_plus_two = ack_range
                .gap
                .checked_add(2)
                .ok_or_else(|| Error::Protocol {
                    code: tobi_core::error::TransportErrorCode::FRAME_ENCODING_ERROR,
                    reason: "ACK gap overflow".into(),
                })?;
            if current < gap_plus_two {
                return Err(Error::Protocol {
                    code: tobi_core::error::TransportErrorCode::FRAME_ENCODING_ERROR,
                    reason: "ACK range extends below 0".into(),
                });
            }
            current -= gap_plus_two;
            if ack_range.ack_range > current {
                return Err(Error::Protocol {
                    code: tobi_core::error::TransportErrorCode::FRAME_ENCODING_ERROR,
                    reason: "ACK range extends below 0".into(),
                });
            }
            let range_start = current - ack_range.ack_range;
            acked_ranges.push((range_start, current));
            let pns = sent_packets.pns_in_range(range_start, current);
            for pn in pns {
                if let Some(pkt) = sent_packets.ack_packet(pn) {
                    if pkt.ack_eliciting {
                        newly_acked_ack_eliciting = true;
                    }
                    if pkt.in_flight {
                        total_acked_in_flight_bytes += pkt.sent_bytes;
                        newest_acked_in_flight_time_sent =
                            Some(match newest_acked_in_flight_time_sent {
                                Some(newest) if newest >= pkt.time_sent => newest,
                                _ => pkt.time_sent,
                            });
                    }
                    if matches!(pkt.ecn, EcnCodepoint::Ect0) {
                        newly_acked_ect0 += 1;
                    }
                    let packet_info = AckedPacketInfo {
                        space,
                        pn,
                        time_sent: pkt.time_sent,
                        sent_bytes: pkt.sent_bytes,
                    };
                    acked_packets.push(packet_info);
                    if pkt.in_flight {
                        acked_in_flight_packets.push(packet_info);
                    }
                    acked_frames.collect(&pkt);
                }
            }
            current = range_start;
        }

        // RFC 9002 Section 5.1: RTT サンプルは次の 2 条件を満たす場合だけ生成する。
        //
        // - largest acknowledged packet number が新規に ACK された
        // - 新規 ACK されたパケットのうち少なくとも 1 つが ack-eliciting
        //
        // ACK 専用パケットだけの ACK は ACK Delay が任意に大きくなり得るため、
        // RTT 推定に使わない。混合 ACK では largest が ACK 専用でも、他に新規
        // ACK された ack-eliciting パケットがあれば条件を満たすため、largest の
        // 送信時刻でサンプルを作る。
        if newly_acked_largest
            && newly_acked_ack_eliciting
            && let Some(largest_acked_time_sent) = largest_acked_time_sent
        {
            let rtt_sample = now.saturating_duration_since(largest_acked_time_sent);
            // RFC 9000 Section 19.3: ACK Delay は送信者 (= ピア) の ack_delay_exponent で
            // `encoded_value << exponent` として scale されている。受信側は左シフトで
            // マイクロ秒の実値に戻す必要がある。指数の選択は受信 ACK を qlog へ
            // 記録するときと共通の `peer_ack_delay_exponent` に集約している。
            // 受信側の peer_params 適用時に範囲検証 (<= 20) が入っているが、
            // 防御的に u128 経由で計算する。
            let ack_delay_exponent = peer_ack_delay_exponent(self.peer_params.as_ref());
            let ack_delay_micros = ((u128::from(ack.ack_delay.as_u64())) << ack_delay_exponent)
                .min(u64::MAX as u128) as u64;
            let ack_delay = tobi_core::time::Duration::from_micros(ack_delay_micros);
            // RFC 9002 Section 5.3: ACK 遅延補正は Application Data 空間かつ
            // ハンドシェイク確認後にのみ適用する。Initial / Handshake 空間の
            // ACK は即時送信され (RFC 9000 Section 13.2.1)、0-RTT パケットの
            // ACK は確認前に届くため、これらの空間では報告された遅延を
            // RTT サンプルから減算しない。
            let ack_delay_for_rtt = ack_delay_for_rtt_sample(space, handshake_confirmed, ack_delay);
            // rtt_max_ack_delay は確認状態に応じた実効値
            // (RFC 9002 Section 5.3。解決は `effective_max_ack_delay` を参照)
            path.rtt.update(
                rtt_sample,
                ack_delay_for_rtt,
                rtt_max_ack_delay,
                ack_recv_path,
                now,
            );
            path.congestion.on_rtt_update(
                path.rtt.smoothed_rtt,
                path.rtt.min_rtt,
                path.rtt.latest_rtt,
            );
        }

        // spurious loss 検出 (RFC 9002 Section 6.1 /
        // draft-ietf-ccwg-bbr-06 Section 5.5.11)
        // ロスト判定済みだが ACK されたパケットを検出し、輻輳制御へ通知する。
        // ACK 範囲の再順序 (古い範囲だけを含む ACK) でも検出できるよう、
        // 送信済みパケットではなく ACK 範囲そのものを走査する。
        sent_packets.prune_recently_lost(now, spurious_loss_retention);
        let mut spurious_in_flight_count: usize = 0;
        // ECT(0) で送信したパケットが後から ACK された場合、全ロスト判定の
        // 根拠から取り消す (RFC 9000 Section 13.4.2)。
        let mut spurious_ect0_count: u64 = 0;
        // base MTU 超のパケットのうち spurious loss だった数。
        // `sent_packets` の可変借用が終わってから MTU コントローラへ通知する。
        let mut spurious_large_count: usize = 0;
        for (range_start, range_end) in &acked_ranges {
            for packet in sent_packets.spurious_losses_in_range(
                *range_start,
                *range_end,
                now,
                spurious_loss_retention,
            ) {
                if packet.in_flight {
                    spurious_in_flight_count += 1;
                }
                if matches!(packet.ecn, EcnCodepoint::Ect0) {
                    spurious_ect0_count += 1;
                }
                // DPLPMTUD: base MTU 超のパケットのロスト判定はブラックホール
                // 検出のカウンタを取り消す。プローブの spurious loss は別 issue で扱う。
                if packet.in_flight && packet.sent_bytes > u64::from(base_mtu_for_spurious) {
                    spurious_large_count += 1;
                }
                // ロスト判定時に STREAM フレームの範囲とリセットフレームの
                // ACK 情報を退避してあるため、元のパケットの ACK でも ACK
                // 済み範囲の解放と終端遷移を行える。
                acked_frames
                    .lost_stream_frames
                    .extend_from_slice(&packet.stream_frames);
                acked_frames
                    .lost_reset_frames
                    .extend_from_slice(&packet.reset_frames);
            }
        }
        // draft-ietf-quic-ack-frequency-14 Section 7:
        // ACK された ACK_FREQUENCY を in-flight から除外する。以降の PTO 計算は
        // 直近に ACK された要求値を基準にする (in-flight が無い場合)。
        if !acked_frames.ack_frequencies.is_empty() {
            let mut latest: Option<(u64, u64)> = None;
            for (sequence_number, requested) in &acked_frames.ack_frequencies {
                self.ack_frequency_in_flight
                    .retain(|(in_flight, _)| in_flight != sequence_number);
                if latest.is_none_or(|(current, _)| *sequence_number >= current) {
                    latest = Some((*sequence_number, *requested));
                }
            }
            if let Some((sequence_number, requested)) = latest
                && self
                    .ack_frequency_last_acked
                    .is_none_or(|(current, _)| sequence_number >= current)
            {
                self.ack_frequency_last_acked = Some((sequence_number, requested));
            }
        }

        // qlog: recovery_metrics_updated (path の借用前に値をコピーする)
        let qlog_rtt_data = if newly_acked_largest && self.qlog_writer.is_some() {
            Some((
                path.rtt.min_rtt.as_micros() as f64 / 1000.0,
                path.rtt.smoothed_rtt.as_micros() as f64 / 1000.0,
                path.rtt.latest_rtt.as_micros() as f64 / 1000.0,
                path.congestion.congestion_window(),
            ))
        } else {
            None
        };

        // 輻輳制御: in-flight だった ACK 済みパケットのバイト数だけを反映する
        // (RFC 9002 Appendix B.5 の OnPacketAcked)。ACK 専用パケットは
        // bytes_in_flight に含まれていないため、減算も cwnd 増加もしない。
        if let Some(newest_acked_time_sent) = newest_acked_in_flight_time_sent {
            path.congestion
                .on_packet_acked_bytes(total_acked_in_flight_bytes);
            path.congestion.on_ack_received(
                total_acked_in_flight_bytes,
                newest_acked_time_sent,
                now,
            );
        }

        // BBR 対応: in-flight だった ACK 済みパケットの詳細情報だけを CC に通知する
        // (RFC 9002 Appendix B.5)。ACK 専用パケットを渡すと配送レートと RTT
        // サンプルに影響するため含めない。
        if !acked_in_flight_packets.is_empty() {
            path.congestion
                .on_packets_acked_cc(&acked_in_flight_packets, now);
        }

        // ECN フィードバック: ACK の ECN カウントを輻輳制御に渡す (RFC 9000 Section 13.4)
        // 併せて RFC 9000 Section 13.4.2.1 の ECN 検証を行う (1-RTT のみ)
        //
        // `ecn_validated` は検証成功 (Capable へ遷移、または Capable 維持) を表す。
        // 後段の CE フィードバックと prev_ecn_counts 更新は検証成功した ACK のみで行う。
        // RFC 9000 Section 13.4.2.1 は「last successfully processed ACK frame」との比較を
        // 求めており、reorder ACK や検証失敗 ACK で基準を動かすと、次の正規 ACK の増分が
        // 未検証の基準から測られて偽 Failed になったり CE を二重計上したりする。
        let mut ecn_validated = false;
        // 検証で状態が変わったら qlog に出すため、変更前の状態を控えておく
        let ecn_state_before = path.ecn_state;
        if level == EncryptionLevel::OneRtt
            && newly_acked_largest
            && path.ecn_state != EcnValidationState::Failed
        {
            // 再順序付けされた ACK (largest_acknowledged が増えない) では検証を行わない
            // (RFC 9000 Section 13.4.2.1 MUST NOT)
            let prev = path.prev_ecn_counts;
            match ack.ecn_counts.as_ref() {
                Some(ecn) => {
                    let ect0_increase = ecn.ect0.saturating_sub(prev.ect0.as_u64());
                    let ce_increase = ecn.ecn_ce.saturating_sub(prev.ecn_ce.as_u64());
                    // 新規 ACK された ECT(0) パケット数以上の増分があること
                    // (なければネットワークが CE or 未報告マークに書き換えた可能性)
                    let increase_ok = ect0_increase + ce_increase >= newly_acked_ect0;
                    // 自分が送信した ECT(0) 合計を超える ECT(0) カウントは remarking
                    let sum_ok = ecn.ect0 <= path.ecn_ect0_sent;
                    if ecn.ect0 < prev.ect0 || ecn.ecn_ce < prev.ecn_ce {
                        // ECN カウントは累積で単調非減少 (RFC 9000 Section 13.4.1,
                        // Section 19.3)。減少は壊れた / remarking された ACK の兆候なので
                        // saturating_sub で増分を 0 に潰さず検証失敗とする。
                        path.ecn_state = EcnValidationState::Failed;
                    } else if ecn.ect1 != 0 {
                        // 本実装は ECT(1) codepoint を送らないため、非ゼロ ect1 は
                        // 適用していない codepoint のカウント報告であり検証失敗
                        // (RFC 9000 Section 13.4.2.1)。将来 ECT(1) 送信を実装する場合は
                        // ECT(0) と同じ増分検証に置き換えること。
                        path.ecn_state = EcnValidationState::Failed;
                    } else if increase_ok && sum_ok {
                        if path.ecn_state == EcnValidationState::Testing {
                            path.ecn_state = EcnValidationState::Capable;
                        }
                        ecn_validated = true;
                    } else {
                        path.ecn_state = EcnValidationState::Failed;
                    }
                }
                None => {
                    // ECN カウントが ACK に含まれていないのに ECT(0) を新規 ACK している場合、
                    // ピアが ECN を報告していないので検証失敗
                    if newly_acked_ect0 > 0 {
                        path.ecn_state = EcnValidationState::Failed;
                    }
                }
            }
        }

        // ECN 状態が変わったら qlog に出す (qlog-quic-events-13 Section 7.6)
        if path.ecn_state != ecn_state_before && self.qlog_writer.is_some() {
            let time_ms = qlog_time_ms;
            let old_state = ecn_state_name(ecn_state_before);
            let new_state = ecn_state_name(path.ecn_state);
            if let Some(ref mut w) = self.qlog_writer {
                w.on_ecn_state_updated(time_ms, old_state, new_state);
            }
        }

        if ecn_validated && let Some(ecn) = &ack.ecn_counts {
            let new_ce = ecn
                .ecn_ce
                .saturating_sub(path.prev_ecn_counts.ecn_ce.as_u64());
            if new_ce > 0 {
                path.congestion.on_ecn_ce_count(new_ce, now);
            }
            path.prev_ecn_counts = *ecn;
        }

        // DPLPMTUD: ACK されたパケットに対するフィードバック (RFC 8899)
        if level == EncryptionLevel::OneRtt {
            let base_mtu = u64::from(path.mtu_controller.base_mtu());
            // ブラックホール検出のカウントは in-flight パケットのロストだけを
            // 数えるため、リセットも in-flight だったパケットの ACK に限る。
            for ap in &acked_in_flight_packets {
                path.mtu_controller.on_probe_acked(ap.pn, now);
                if ap.sent_bytes > base_mtu {
                    path.mtu_controller.on_large_packet_acked();
                }
            }
            // MTU が更新されたら反映し、qlog に出す
            // (qlog-quic-events-13 Section 4.8)
            if let Some((old_mtu, new_mtu, done)) = apply_pmtu_from_controller(
                &mut path.mtu_controller,
                &mut path.pmtu,
                &mut path.congestion,
            ) && let Some(ref mut w) = self.qlog_writer
            {
                w.on_mtu_updated(qlog_time_ms, u32::from(old_mtu), u32::from(new_mtu), done);
            }
        }

        // 損失検出を実行
        // RFC 9002 Section 6.2.1: PTO バックオフは ACK の受信でリセットするが、
        // クライアントがサーバーのアドレス検証完了を確信するまでは、Initial
        // パケットの ACK でリセットしてはならない (MUST NOT)。サーバーが
        // クライアントの Initial を処理できたことを示す Handshake 空間の ACK は
        // リセット対象とする (RFC 9000 Section 8.1)。
        let reset_pto_backoff = !(self.role == Role::Client && level == EncryptionLevel::Initial);
        if newly_acked_largest && reset_pto_backoff {
            // RFC 9002 Section 6.2.1: PTO バックオフは空間横断で 1 つの値として
            // 扱うため、全空間のバックオフを同時にリセットする。
            path.loss_detectors.on_ack_received();
        }
        let lost_packets =
            path.loss_detectors
                .get_mut(space)
                .detect_lost_packets(sent_packets, &path.rtt, now);
        // 各パケットがパケット閾値と時間閾値のどちらでロストしたかを
        // 再送パス選択ポリシーへ伝えるため、判定基準を控えておく。
        // ACK された DPLPMTUD プローブの記録を削除する
        let acked_probe_pns: Vec<u64> = acked_packets.iter().map(|packet| packet.pn).collect();
        self.pmtu_probe_pns.retain(|&(probe_path, probe_pn)| {
            probe_path != path_id || !acked_probe_pns.contains(&probe_pn)
        });
        if !acked_probe_pns.is_empty() {
            // プローブが ACK されたら PTO バックオフをリセットする
            // (RFC 9002 Section 6.2.1: ACK 受信でバックオフを戻す)。
            self.pmtu_probe_backoff.remove(&path_id);
        }

        let largest_acked = sent_packets.largest_acked;
        // ここまでで `sent_packets` の可変借用は終わる。spurious loss と
        // 全ロスト判定で path の ECN 状態を更新する。
        // DPLPMTUD: spurious ACK は base MTU 超のパケットが通った証拠なので、
        // ブラックホール検出の連続ロストカウンタを減算ではなく 0 に戻す。減算
        // するとどのロストが取り消されたかの対応管理が必要になるため、安全側で
        // 検出をやり直す。フィードバックは 1-RTT の経路だけを対象にする。
        if level == EncryptionLevel::OneRtt && spurious_large_count > 0 {
            path.mtu_controller.on_large_packet_acked();
        }
        //
        // RFC 9000 Section 13.4.2: ECT(0) で送信したパケットが後から ACK された
        // 場合は全ロスト判定の根拠から取り消す。
        for _ in 0..spurious_ect0_count {
            path.record_ecn_ect0_spurious_ack();
        }
        // RFC 9000 Section 13.4.2: ECT(0) 付きで送信したパケットがすべてロスト
        // した場合は ECN 検証失敗とみなし、以降の ECT 付与を止める (SHOULD)。
        let lost_ect0_count = lost_packets
            .iter()
            .filter(|packet| matches!(packet.ecn, EcnCodepoint::Ect0))
            .count() as u64;
        if lost_ect0_count > 0 {
            let mut all_lost = false;
            for _ in 0..lost_ect0_count {
                all_lost = path.record_ecn_ect0_lost();
            }
            if all_lost {
                let state_before = path.ecn_state;
                path.ecn_state = EcnValidationState::Failed;
                if self.qlog_writer.is_some()
                    && let Some(ref mut w) = self.qlog_writer
                {
                    w.on_ecn_state_updated(
                        qlog_time_ms,
                        ecn_state_name(state_before),
                        ecn_state_name(path.ecn_state),
                    );
                }
            }
        }

        // spurious loss を輻輳制御へ通知する (draft-ietf-ccwg-bbr-06 Section 5.5.11.2:
        // BBR は保存した cwnd / モデルパラメータを復元し、損失回復起因の状態遷移を
        // 巻き戻す)。複数パケットをまとめて検出した場合も、パケットごとに通知する。
        // BBR 側は最初の通知で undo 状態を消すため 2 回目以降は no-op になる。
        for _ in 0..spurious_in_flight_count {
            path.congestion.on_spurious_loss_detection(now);
            self.stats.record_spurious_lost();
        }

        // ロスト PN を記録 (qlog 出力用、path の借用前にコピーする)
        let lost_pns: Vec<u64> = lost_packets.iter().map(|p| p.pn).collect();

        // ロストパケットの処理: 輻輳制御に通知し、フレーム情報を収集する
        // (self への借用を分離するため、先にフレーム情報を収集する)
        // 再送対象の STREAM データ (元パスは path_id、再送回数とロスト理由も保持する)
        let mut lost_streams: Vec<(u64, u64, usize, bool, u32, LossReason)> = Vec::new();
        let mut lost_stream_ids: Vec<u64> = Vec::new();
        let mut lost_cryptos: Vec<(u64, usize, LossReason)> = Vec::new();
        let mut lost_path_abandons: Vec<(u32, u64)> = Vec::new();
        let mut lost_max_path_id = false;
        // RFC 9000 Section 13.3: ロスト制御フレーム再送用
        let mut lost_control_frames: Vec<SentFrameInfo> = Vec::new();
        if !lost_packets.is_empty() {
            // RFC 9002 Appendix B.8: 輻輳イベントの対象は in-flight だったパケットだけ。
            // ACK / PATH_ACK 専用パケットのロストでは bytes_in_flight も
            // 輻輳ウィンドウも変えない。
            // DPLPMTUD プローブは `detect_lost_packets` が除外し、PROBE_TIMER
            // 満了で処理する。ここに来るロストは通常パケットだけである
            // (RFC 8899 Section 5.7)。
            let mut congestion_lost_bytes: u64 = 0;
            let mut congestion_lost_packets: Vec<SentPacket> = Vec::new();
            for packet in lost_packets.iter().filter(|packet| packet.in_flight) {
                congestion_lost_bytes = congestion_lost_bytes.saturating_add(packet.sent_bytes);
                congestion_lost_packets.push(packet.clone());
            }
            if congestion_lost_bytes > 0 {
                path.congestion.on_packets_lost(congestion_lost_bytes, now);
            }

            // Persistent Congestion 判定 (RFC 9002 Section 7.6)
            let max_ack_delay_for_pc = effective_peer_max_ack_delay;
            // 区間内 ACK 有無の判定に使うため、今回 newly-acked になった
            // パケットの送信時刻を集める
            let acked_times: Vec<Timestamp> = acked_packets.iter().map(|a| a.time_sent).collect();
            if tobi_core::recovery::LossDetector::is_persistent_congestion(
                &congestion_lost_packets,
                &path.rtt,
                max_ack_delay_for_pc,
                &acked_times,
            ) {
                path.congestion.on_persistent_congestion();
            }

            // DPLPMTUD: ロストパケットに対するフィードバック (RFC 8899 Section 4.3)
            // 時間閾値の経路と同じ共通処理を通す。
            if level == EncryptionLevel::OneRtt {
                let before_mtu_state = path.mtu_controller.state();
                if let Some((old_mtu, new_mtu, done)) =
                    apply_pmtu_loss_feedback(path, &lost_packets, now)
                    && let Some(ref mut w) = self.qlog_writer
                {
                    w.on_mtu_updated(qlog_time_ms, u32::from(old_mtu), u32::from(new_mtu), done);
                }
                // BASE フェーズへ遷移したときだけ、旧探索の未送信プローブを破棄する。
                if before_mtu_state != path.mtu_controller.state()
                    && path.mtu_controller.state() == tobi_core::path::mtu::MtuState::BaseRequested
                {
                    discard_pending_old_probe(path_id, &mut self.one_rtt_outputs);
                    discard_sent_pmtu_probes(path, path_id, &mut self.pmtu_probe_pns);
                }
            }

            // BBR 対応: ロスト詳細情報を CC に通知する。
            // DPLPMTUD プローブのロストは輻輳イベントではないため除外する
            // (RFC 8899 Section 5.7)。
            let lost_packet_infos: Vec<LostPacketInfo> = congestion_lost_packets
                .iter()
                .map(|p| LostPacketInfo {
                    space,
                    pn: p.pn,
                    time_sent: p.time_sent,
                    sent_bytes: p.sent_bytes,
                })
                .collect();
            if !lost_packet_infos.is_empty() {
                path.congestion.on_packets_lost_cc(&lost_packet_infos, now);
            }

            for lost_pkt in &lost_packets {
                let loss_reason = largest_acked.map_or(LossReason::TimeThreshold, |largest| {
                    LossDetector::loss_reason_for_packet(lost_pkt.pn, largest)
                });
                for frame_info in &lost_pkt.frames {
                    match frame_info {
                        SentFrameInfo::Stream {
                            stream_id,
                            offset,
                            length,
                            fin,
                            retransmission_count,
                        } => {
                            lost_streams.push((
                                *stream_id,
                                *offset,
                                *length,
                                *fin,
                                *retransmission_count,
                                loss_reason,
                            ));
                            lost_stream_ids.push(*stream_id);
                        }
                        SentFrameInfo::Crypto { offset, length } => {
                            lost_cryptos.push((*offset, *length, loss_reason));
                        }
                        // RFC 10069 Section 4.2:
                        // PATH_ABANDON は別パスで同じ内容を再送する (SHOULD)。
                        SentFrameInfo::PathAbandon {
                            path_id: pa_path_id,
                            error_code,
                        } => {
                            lost_path_abandons.push((*pa_path_id, *error_code));
                        }
                        // RFC 10069 Section 4.3:
                        // PATH_STATUS はそのパスについて最後に送った状態だけを再送する
                        // (SHOULD)。時間閾値経路と同じ再送条件・シーケンス番号の扱いに
                        // するため、制御フレームの再送キューへ戻す。
                        SentFrameInfo::PathStatus { .. } => {
                            lost_control_frames.push(frame_info.clone());
                        }
                        // RFC 10069 Section 4.6:
                        // MAX_PATH_ID は最新の値のみ再送する (SHOULD)。
                        SentFrameInfo::MaxPathId { .. } => {
                            lost_max_path_id = true;
                        }
                        // RFC 9000 Section 13.3: 制御フレームの再送
                        SentFrameInfo::ResetStream { stream_id, .. }
                        | SentFrameInfo::ResetStreamAt { stream_id, .. } => {
                            lost_stream_ids.push(*stream_id);
                            lost_control_frames.push(frame_info.clone());
                        }
                        SentFrameInfo::MaxData
                        | SentFrameInfo::MaxStreamData { .. }
                        | SentFrameInfo::MaxStreams { .. }
                        | SentFrameInfo::DataBlocked
                        | SentFrameInfo::StreamDataBlocked { .. }
                        | SentFrameInfo::StreamsBlocked { .. }
                        | SentFrameInfo::StopSending { .. }
                        | SentFrameInfo::NewConnectionId { .. }
                        | SentFrameInfo::ObservedAddress { .. }
                        | SentFrameInfo::HandshakeDone => {
                            lost_control_frames.push(frame_info.clone());
                        }
                        // RFC 9000 Section 13.3:
                        // NEW_TOKEN は同一内容で再送しなければならない。
                        SentFrameInfo::NewToken { .. } => {
                            lost_control_frames.push(frame_info.clone());
                        }
                        // RFC 9000 Section 5.1.2 / Section 13.3:
                        // RETIRE_CONNECTION_ID は同一内容で再送する。
                        // PATH_RETIRE_CONNECTION_ID も同じく再送し、
                        // RFC 10069 Section 4.5 に従う。
                        // PATHS_BLOCKED / PATH_CIDS_BLOCKED はまだブロック状態の
                        // 場合に再送する (RFC 10069 Section 4.7)。
                        SentFrameInfo::RetireConnectionId { .. }
                        | SentFrameInfo::PathsBlocked { .. }
                        | SentFrameInfo::PathCidsBlocked { .. } => {
                            lost_control_frames.push(frame_info.clone());
                        }
                        // draft-ietf-quic-ack-frequency-14 Section 4 / Section 7:
                        // ACK_FREQUENCY はロストしても再送しない。PTO 計算用の
                        // in-flight からも除去する。
                        SentFrameInfo::AckFrequency {
                            sequence_number, ..
                        } => {
                            self.ack_frequency_in_flight
                                .retain(|(in_flight, _)| in_flight != sequence_number);
                        }
                        // ACK / PATH_ACK は再送不要。PING / PADDING などの
                        // 情報を持たないフレームも `Other` として再送しない。
                        SentFrameInfo::Ack { .. }
                        | SentFrameInfo::PathAck
                        | SentFrameInfo::Other => {}
                    }
                }
            }
        }

        // Initial/Handshake の SentPackets を戻す。
        // `loss_detection_timer` は in-flight の有無を Connection 側の
        // SentPackets から判定するため、タイマー再計算より前に戻す必要がある。
        // 退避したまま再計算すると Initial/Handshake の in-flight が常に空に
        // 見え、未 ACK のパケットがあってもタイマーを誤って破棄する。
        match level {
            EncryptionLevel::Initial => self.initial_sent_packets = temp_sent_packets,
            EncryptionLevel::Handshake => self.handshake_sent_packets = temp_sent_packets,
            // path.sent_packets を直接使っているので戻す必要なし
            EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt => {}
        }

        // 損失タイマーの設定/破棄は path の借用が終わった後に行う。
        // ACK 処理で空間ごとの loss_time / in-flight / PTO バックオフが変わるため、
        // RFC 9002 Appendix A.8 に従って全空間から改めて選択する。
        let loss_timer = self.loss_detection_timer(path_id, now);
        if let Some((timer_space, deadline)) = loss_timer {
            self.set_loss_detection_timer(path_id, timer_space, deadline);
        } else {
            self.clear_loss_detection_timer(path_id);
        }

        // ロスト統計を更新する (RFC 9002 Section 2: in-flight のみ対象)
        for lost_packet in lost_packets.iter().filter(|packet| packet.in_flight) {
            self.record_lost_packet(path_id);
            if has_retransmittable_frame(&lost_packet.frames) {
                self.record_retransmitted_packet(path_id);
            }
        }

        // path の借用が終わった後にロストフレームを処理する
        for (stream_id, offset, length, fin, retransmission_count, loss_reason) in lost_streams {
            self.streams.mark_lost(
                stream_id,
                offset,
                length,
                fin,
                RetxMeta {
                    original_path: path_id,
                    loss_reason,
                    retransmission_count,
                },
            );
        }
        for (offset, length, loss_reason) in lost_cryptos {
            // ロストしたパケットが属していた暗号化レベルで再送する
            // (RFC 9001 Section 4.1.3)。
            self.retransmit_crypto(
                level,
                offset,
                length,
                RetxMeta {
                    original_path: path_id,
                    loss_reason,
                    retransmission_count: 0,
                },
                now,
            );
        }

        // Multipath 制御フレームのロスト再送 (ACK 駆動と時間閾値で共通)
        // (RFC 10069 Section 4.2, 4.3, 4.6)
        self.retransmit_lost_multipath_frames(lost_path_abandons, lost_max_path_id, now)?;

        // RFC 9000 Section 13.3: ロスト制御フレームの再送
        self.retransmit_lost_control_frames(lost_control_frames, now);

        // 送信側ストリーム状態の終端遷移 (RFC 9000 Section 3.1)
        // 再送キューへの復元はこの ACK 処理の前半で終わっているため、
        // 復元の直後に終端遷移を試みる (RFC 9000 Section 13.3)。
        for stream_id in lost_stream_ids {
            self.streams.try_transition_send_terminal(stream_id);
        }
        // ACK された STREAM フレームの ACK 範囲を記録し、終端遷移を試みる
        for frame in acked_frames.stream_frames {
            self.streams.on_stream_frame_acked(
                frame.stream_id,
                frame.offset,
                frame.length,
                frame.fin,
            );
        }
        // ロスト判定済みパケットが後から ACK された場合 (spurious loss) も、
        // 退避した STREAM フレームの ACK 済み範囲を送信バッファへ伝える
        // (RFC 9002 Section 6.1, RFC 9000 Section 13.3)。ACK 済み範囲の記録は
        // 通常の ACK と同じ処理でよいため、同じメソッドを使う。
        for frame in acked_frames.lost_stream_frames {
            self.streams.on_stream_frame_acked(
                frame.stream_id,
                frame.offset,
                frame.length,
                frame.fin,
            );
        }
        for stream_id in acked_frames.reset_stream_ids {
            self.streams.on_reset_stream_acked(stream_id);
        }
        for (stream_id, reliable_size) in acked_frames.reset_stream_at {
            self.streams
                .on_reset_stream_at_acked(stream_id, reliable_size);
        }
        // ロスト判定済みパケットが後から ACK された場合 (spurious loss) も、
        // 退避したリセットフレームの ACK を終端遷移へ反映する
        // (RFC 9000 Section 3.1, RFC 9002 Section 6.1)。ロスト判定済みパケットは
        // in-flight の会計から既に除外されているため、ここで減算し直さない。
        for frame in acked_frames.lost_reset_frames {
            match frame {
                LostResetFrame::ResetStream { stream_id } => {
                    self.streams.on_reset_stream_acked(stream_id);
                }
                LostResetFrame::ResetStreamAt {
                    stream_id,
                    reliable_size,
                } => {
                    self.streams
                        .on_reset_stream_at_acked(stream_id, reliable_size);
                }
            }
        }

        // qlog: packet_lost + recovery_metrics_updated (path の借用後に出力)
        //
        // DPLPMTUD プローブは `detect_lost_packets` の対象外であり、
        // PROBE_TIMER 満了によるロストも `PathStats::lost_packets` に含めない。
        // そのため qlog の packet_lost にもプローブを出力しない
        // (RFC 8899 Section 5.7)。
        if self.qlog_writer.is_some() {
            if !lost_pns.is_empty() {
                let time_ms = self.qlog_time_ms();
                for pn in &lost_pns {
                    let qlog_header = qlog::PacketHeader {
                        packet_type: qlog::PacketType::OneRtt,
                        packet_number: *pn,
                        dcid: String::new(),
                        scid: None,
                        version: None,
                        length: None,
                    };
                    if let Some(ref mut w) = self.qlog_writer {
                        w.on_packet_lost(time_ms, &qlog_header);
                    }
                }
            }
            if let Some((min_rtt_ms, smoothed_rtt_ms, latest_rtt_ms, cwnd)) = qlog_rtt_data {
                let time_ms = self.qlog_time_ms();
                if let Some(ref mut w) = self.qlog_writer {
                    w.on_recovery_metrics_updated(
                        time_ms,
                        min_rtt_ms,
                        smoothed_rtt_ms,
                        latest_rtt_ms,
                        cwnd,
                    );
                }
            }
        }
        // 観測イベント: パケットロスト (qlog の有無に依らず記録する)
        for pn in &lost_pns {
            self.observe(ConnectionObservationEvent::PacketLost {
                path_id,
                packet_number: *pn,
            });
        }
        // RFC 9001 Section 6.1: 現行の Key Phase で送ったパケットが ACK されたかを
        // 記録する。次の鍵更新を開始できる条件の 1 つである。ACK されたパケット
        // 番号をフェーズ開始時の次回送信パケット番号と比較する。送信時刻の比較
        // では同一 Timestamp で送った旧フェーズのパケットと区別できないため、
        // パケット番号で判定する。
        if level == EncryptionLevel::OneRtt && !self.current_phase_acked {
            let start_pn = self
                .one_rtt_phase_start_pns
                .get(&path_id)
                .copied()
                .unwrap_or(0);
            if acked_packets.iter().any(|packet| packet.pn >= start_pn) {
                self.current_phase_acked = true;
                // 鍵更新後のフェーズでは、確認 ACK を受信した時点から
                // 全パスの最大 PTO の 3 倍の待機を開始する
                // (RFC 9001 Section 6.5、RFC 10069 Section 2.5)。
                // TLS が最初に提供した 1-RTT 鍵のフェーズでは課さない。
                if self.key_phase_established_by_update {
                    let cooldown = self.lifecycle_max_pto().mul(3);
                    self.key_update_allowed_at = Some(now.add(cooldown));
                }
            }
        }

        // サーバーは HANDSHAKE_DONE を送った直後でも、Handshake flight が ACK されるまでは
        // Handshake 鍵を保持する。ここで in-flight が空になったことを確認してから破棄する。
        if self.role == Role::Server
            && self.handshake_done_sent
            && self.handshake_keys.is_some()
            && !self.handshake_sent_packets.has_in_flight()
        {
            self.discard_handshake_keys();
        }

        // RFC 9000 Section 5.1.2: ACK 済みの退役 CID は履歴から削除できる。
        // 履歴は重複 RETIRE を抑止するためだけに使うので、削除しても
        // RETIRE の再送は許容される範囲に収まる。
        for key in acked_frames.retired_cids {
            if self.retired_peer_cid_seq.remove(&key) {
                self.retired_peer_cid_order.retain(|entry| *entry != key);
                self.retired_peer_cid_identities.remove(&key);
            }
        }

        Ok(())
    }

    /// PATH_ABANDON フレームを処理する
    ///
    /// RFC 10069 Section 3.4 に基づき、
    /// パスを廃棄状態に遷移し、対応する PATH_ABANDON を返送する。
    fn process_path_abandon(
        &mut self,
        pa: &frame::path_abandon::PathAbandon,
        now: Timestamp,
    ) -> Result<(), Error> {
        let abandon_path_id = PathId(pa.path_id);

        let Some(path) = self.paths.get(abandon_path_id) else {
            // トラフィックの送受信前に PATH_ABANDON を受け取るのは正常系である
            // (RFC 10069 Section 3.4)。同節は PATH_ABANDON を
            // 受信したときに返送することを MUST としているため、Path が無くても
            // tombstone を登録して生きているパスで返送する。Path が無いので
            // クリーンアップタイマーは不要。
            self.paths.abandon_path_id(abandon_path_id);
            // Path が無くても、ピアが先に PATH_NEW_CONNECTION_ID で登録した
            // 当該パスの CID が残っていることがある。PATH_ABANDON を受けたら
            // そのパスの CID を即時退役として扱う (RFC 10069
            // Section 3.4 の MUST) ため、ここで RETIRE を送って集合から除く。
            self.retire_peer_cids_for_path(abandon_path_id, now)?;
            self.push_event(ConnectionEvent::PathAbandoned {
                path_id: abandon_path_id,
                error_code: pa.error_code.as_u64(),
            });
            let send_path = self
                .paths
                .active_paths()
                .min_by_key(|p| p.rtt.smoothed_rtt)
                .map(|p| p.id);
            if let Some(send_path) = send_path {
                self.emit_1rtt_single_frame(
                    send_path,
                    Frame::PathAbandon(frame::path_abandon::PathAbandon {
                        path_id: pa.path_id,
                        error_code: VarInt::new(frame::path_abandon::error_code::NO_ERROR)
                            .expect("value fits in 62-bit varint"),
                    }),
                    now,
                )?;
            }
            return Ok(());
        };
        let already_abandoning =
            path.state == PathState::Abandoning || path.state == PathState::Abandoned;

        // 廃棄されるパスで migration を検証中なら、完了できないため取り消す。
        // この時点で取り消しておかないと、後から別パスの Retire Prior To が
        // 増加したときの reconcile が PathValidationFailed を通知し、
        // PathAbandoned と矛盾する。パス廃棄の通知は PathAbandoned だけで行う。
        self.discard_pending_migration(abandon_path_id);

        // 唯一のオープンパスなら、Abandoned にする前に PATH_ABANDON と
        // CONNECTION_CLOSE を同じパケットで送る (Section 3.4 の SHOULD)。
        let only_open_path = !already_abandoning && self.paths.active_path_count() == 1;
        if only_open_path {
            self.emit_final_path_abandon(abandon_path_id, now)?;
        } else {
            // 受信側も未出力の検証と履歴を取り消す。同じパケットの後続に
            // PATH_RESPONSE があっても、退役した CID で再検証を始めない。
            // 信頼性が必要な未出力フレームは、残ったパスへの送信待ちに戻す。
            self.cancel_one_rtt_path(abandon_path_id)?;
        }

        // クリーンアップ期限はパスを Abandoned にする前の RTT と実効 ACK delay から決める。
        let pto_3x = self.lifecycle_pto_for_path(abandon_path_id).mul(3);
        let path = self.paths.get_mut(abandon_path_id).expect("path exists");
        // パスを Abandoned 状態に遷移
        path.state = PathState::Abandoned;
        // 3 PTO クリーンアップ用のタイムスタンプを記録する
        // (RFC 10069 Section 3.4)
        path.abandoned_at = Some(now);
        // tombstone を登録する (remove_path() 後も遅延フレームを無視するため)
        self.paths.abandon_path_id(abandon_path_id);

        // 3 PTO 後にパス状態を削除するタイマーを設定する
        let cleanup_deadline = now.add(pto_3x);
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::PathCleanup {
                path_id: abandon_path_id,
            },
            deadline: cleanup_deadline,
        });

        self.push_event(ConnectionEvent::PathAbandoned {
            path_id: abandon_path_id,
            error_code: pa.error_code.as_u64(),
        });

        // PathController にパス廃棄を通知する
        let pc_event = PathControlEvent::PathAbandoned {
            path_id: abandon_path_id,
            error_code: pa.error_code.as_u64(),
        };
        let actions = self.invoke_path_controller(&pc_event, now);
        self.execute_path_actions(actions, now);

        // まだ PATH_ABANDON を送信していない場合は返送する (MUST)。
        // 唯一のオープンパスでは、上で CONNECTION_CLOSE と一緒に送ってある。
        if !already_abandoning && !only_open_path {
            let send_path = self.path_abandon_send_path(abandon_path_id);
            self.emit_1rtt_single_frame(
                send_path,
                Frame::PathAbandon(frame::path_abandon::PathAbandon {
                    path_id: pa.path_id,
                    error_code: VarInt::new(frame::path_abandon::error_code::NO_ERROR)
                        .expect("value fits in 62-bit varint"),
                }),
                now,
            )?;
        }

        // 廃棄されたパスの未確認パケットに対して PATH_ACK を送信する (SHOULD)
        // (RFC 10069 Section 3.4.3)
        // PATH_ACK は別パスで送信する
        {
            // RFC 9000 Section 19.3: ACK Delay は送信者自身の ack_delay_exponent で
            // `delay_micros >> exponent` として scale する。送信者はこちらなので
            // ローカルの値を使う。指数の選択は ACK 生成と qlog 記録で共通の
            // `local_ack_delay_exponent` に集約している。
            let ack_delay_exponent = self.local_ack_delay_exponent();
            if let Some(path) = self.paths.get_mut(abandon_path_id) {
                let ack_delay = path
                    .ack_tracker
                    .largest_received_time()
                    .map(|t| {
                        let delay_micros = now.saturating_duration_since(t).as_micros();
                        delay_micros >> ack_delay_exponent
                    })
                    .unwrap_or(0);
                if let Some(ack) = path.ack_tracker.generate_ack(ack_delay)
                    && let Some(send_path) = self.paths.select_alt_path(abandon_path_id)
                {
                    // 最後の ACK は別パスで送る (Section 3.4.1)。別パスが無ければ出さない。
                    let path_ack = frame::path_ack::PathAck {
                        path_id: abandon_path_id.0,
                        largest_acknowledged: ack.largest_acknowledged,
                        ack_delay: ack.ack_delay,
                        first_ack_range: ack.first_ack_range,
                        ack_ranges: ack.ack_ranges,
                        ecn_counts: ack.ecn_counts,
                    };
                    self.emit_1rtt_single_frame(send_path, Frame::PathAck(path_ack), now)?;
                }
            }
        }

        // 廃棄パスの未確認パケットを lost として回復する。手順と根拠は
        // `recover_lost_frames_on_abandoned_path` の doc を参照。
        let lost_packets_for_recovery = {
            let path = self.paths.get_mut(abandon_path_id).expect("path exists");
            let lost_packets = path.sent_packets.drain_all();
            let mut lost_bytes: u64 = 0;
            for pkt in &lost_packets {
                // in-flight でないパケット (ACK / PATH_ACK 専用) は
                // 輻輳ウィンドウの対象外 (RFC 9002 Section 2)
                if pkt.in_flight {
                    lost_bytes += pkt.sent_bytes;
                }
            }
            if lost_bytes > 0 {
                path.congestion.on_packets_lost(lost_bytes, now);
            }
            // 損失検出タイマーをクリアする。
            // 未 armed のタイマーへ ClearTimer を出さないようヘルパー経由で行う。
            self.clear_loss_detection_timer(abandon_path_id);
            lost_packets
        };
        self.recover_lost_frames_on_abandoned_path(lost_packets_for_recovery, abandon_path_id, now);

        // 廃棄されたパスが ACK 受信パスだった他パスの min_rtt をリセットする
        // (RFC 10069 Section 5.4)
        for path in self.paths.all_paths_mut() {
            path.rtt.on_ack_path_abandoned(abandon_path_id);
        }

        // ピアから受信した当該パスの CID を全てリタイアする
        // (RFC 10069 Section 3.4 のパス閉鎖の処理)
        self.retire_peer_cids_for_path(abandon_path_id, now)?;

        // 最後のオープンパスは emit_final_path_abandon がすでに Closing にしている。
        // それ以外でオープンパスが残っていないときは、Active なパスが無ければ
        // 1-RTT の CONNECTION_CLOSE を出さずに Closing へ入る。
        // (RFC 10069 Section 3.4)
        if self.paths.active_path_count() == 0 && self.state == ConnectionState::Connected {
            self.close(0, b"all paths abandoned", now)?;
        }

        Ok(())
    }

    /// 指定パスのピア CID を全てリタイアする
    ///
    /// PATH_ABANDON を受信したとき (`process_path_abandon`。Path オブジェクトが
    /// 無い場合も含む) と、ローカルに廃棄したパスの `PathCleanup` タイマーが
    /// 発火したときに呼ばれる。ピアから受信した当該パスの全 CID に対して
    /// RETIRE_CONNECTION_ID / PATH_RETIRE_CONNECTION_ID を送信し、CID の集合から
    /// 削除する。1 CID ごとにパケットを作らず、最大 64 個ずつ 1 パケットに
    /// まとめる。
    /// 検証中の migration の取り消しは呼び出し側 (`abandon_path_inner` /
    /// `process_path_abandon`) が行う。
    fn retire_peer_cids_for_path(&mut self, path_id: PathId, now: Timestamp) -> Result<(), Error> {
        // 当該パスのピア CID エントリを抽出する。ピア CID はローカル CID の
        // ルーティングと分離して管理しているため、`PathManager::unregister_cid`
        // は呼ばない。
        let (to_retire, remaining): (Vec<_>, Vec<_>) = self
            .peer_cid_entries
            .drain(..)
            .partition(|entry| entry.path_id == path_id);
        self.peer_cid_entries = remaining;

        // Active なパスが無いときはフレームを出さない。本メソッドはピア CID の
        // 削除と RETIRE の送信だけを行い、ローカル CID には触れない。
        let send_path = self.paths.select_open_path();

        // パス廃棄時は全 CID の退役が必須のため、送信待ちの上限
        // (RFC 9000 Section 5.1.2 の MAY) は適用せず、直接送信する。
        // 1 CID ごとにパケットを作らず、可能な限り 1 パケットへまとめる。
        let mut frames = Vec::new();
        for entry in &to_retire {
            self.record_retired_peer_cid((path_id.0, entry.sequence_number), &entry.connection_id);
            frames.push(Frame::PathRetireConnectionId(
                frame::path_retire_connection_id::PathRetireConnectionId {
                    path_id: path_id.0,
                    sequence_number: VarInt::new(entry.sequence_number)
                        .expect("value fits in 62-bit varint"),
                },
            ));
        }
        if let Some(send_path) = send_path
            && !frames.is_empty()
        {
            // RFC 9000 Section 19.16: RETIRE のシーケンス番号は、そのパケットの
            // DCID を指してはならない。ここで退役するのは abandoned なパスの CID
            // であり、送信に使うパスの DCID とは別の CID なので満たされる。
            //
            // 1 パケットに載せる RETIRE の数を固定上限で区切る。PATH_RETIRE は
            // 最大 18 バイト (type 1 + path ID 8 + sequence number 8) と
            // 見積もっても、64 個で 1,152 バイトに収まる。Short Header と
            // AEAD タグを含めても最小 MTU 1,200 バイト未満である。上限が無いと、
            // `active_connection_id_limit` を巨大に広告した接続で 1 パケットが
            // MTU を超えて送信待ちのまま残り得る。
            const MAX_RETIRE_FRAMES_PER_PACKET: usize = 64;
            for chunk in frames.chunks(MAX_RETIRE_FRAMES_PER_PACKET) {
                self.emit_1rtt_frames(send_path, chunk, now)?;
            }
        }

        Ok(())
    }

    /// 指定パスの有効なピア CID 数が上限を超えている場合に
    /// `CONNECTION_ID_LIMIT_ERROR` を返す
    ///
    /// RFC 10069 Section 2.2:
    /// Multipath 有効時は `active_connection_id_limit` をパスごとに適用する。
    /// ピア CID を登録した後に呼び、退役済みを差し引いた有効 CID 数が
    /// 上限を超えていないか検査する。
    ///
    /// 会計にはハンドシェイクの初期 CID (シーケンス番号 0) と
    /// preferred_address の CID (シーケンス番号 1) も含む。
    /// RFC 9000 Section 5.1.1: `active_connection_id_limit` は
    /// ピアが維持する有効な CID 数の上限であり、ハンドシェイクで発行された
    /// CID も有効な CID に含まれる。
    fn enforce_peer_cid_limit(&self, path_id: PathId) -> Result<(), Error> {
        check_peer_cid_limit(
            &self.peer_cid_entries,
            path_id,
            self.local_params.active_connection_id_limit,
        )
    }

    /// NEW_CONNECTION_ID / PATH_NEW_CONNECTION_ID の共通処理
    ///
    /// path ID 0 の NEW_CONNECTION_ID は RFC 9000 Section 19.15、
    /// path ID 0 以外の PATH_NEW_CONNECTION_ID は
    /// RFC 10069 Section 4.4 に従う。処理内容は次の通り。
    ///
    /// 1. `retire_prior_to > sequence_number` を FRAME_ENCODING_ERROR にする
    ///    (RFC 9000 Section 19.15 / RFC 10069 Section 4.4)
    /// 2. abandon 済みのパスならフレームを無視する
    /// 3. 最大 Retire Prior To を更新し、増加した場合だけ古い CID を退役させる
    ///    (RFC 9000 Section 5.1.2 / RFC 10069 Section 4.4)
    /// 4. CID を登録し、CID の再利用を PROTOCOL_VIOLATION にする
    ///    (RFC 9000 Section 19.15 の MAY)
    /// 5. 退役で送信先 CID が変わった場合と、migration の検証中に候補 CID が
    ///    退役した場合に、送信先 CID を選び直し、候補の置き換えまたは移行の
    ///    取り消しを行う (original の保存値は置き換えない)
    /// 6. `active_connection_id_limit` を検査する
    ///
    /// 形式検証は abandoned 判定より先に行う。RFC 10069
    /// Section 4 が silent ignore を MUST とするのは multipath-specific frame に
    /// 限られる。NEW_CONNECTION_ID は RFC 9000 Section 19.15 のフレームであるため、
    /// abandoned なパス 0 で受信した NEW_CONNECTION_ID を無視するのは本実装の
    /// ポリシーである。退役済みのパスへ新しい CID を追加しないための判断であり、
    /// `retire_prior_to > sequence_number` の MUST 検査を免除しない
    /// (RFC 9000 Section 19.15)。
    fn handle_peer_cid_frame(
        &mut self,
        frame_kind: PeerCidFrameKind,
        path_id: PathId,
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: ConnectionId,
        stateless_reset_token: Option<[u8; 16]>,
    ) -> Result<(), Error> {
        // RFC 9000 Section 19.15 / RFC 10069 Section 4.4:
        // Retire Prior To は Sequence Number を超えてはならず、超える場合は
        // FRAME_ENCODING_ERROR とする (MUST)。検証を通らないフレームは
        // 最大値の更新と退役の対象にしない。
        if retire_prior_to > sequence_number {
            return Err(Error::Protocol {
                code: tobi_core::error::TransportErrorCode::FRAME_ENCODING_ERROR,
                reason: format!(
                    "{} retire_prior_to {} exceeds sequence_number {}",
                    frame_kind.name(),
                    retire_prior_to,
                    sequence_number
                ),
            });
        }
        // RFC 10069 Section 3.4: abandon したパスの CID は
        // 即時退役扱いになり、以後そのパスでは送信できない。処理を続けられない
        // path ID のフレームは silent ignore する。ただし上の形式検証は先に行い、
        // malformed なフレームは無視しない。
        if self.is_path_abandoned(path_id) {
            return Ok(());
        }
        // 重複・CID 再利用の判定に使う既存エントリの情報は、Retire Prior To
        // による退役で消える前に控える。同じ CID を別のシーケンス番号で
        // 通知した場合、このフレームの退役処理で旧エントリが消えても
        // CID の再利用として検出できる。
        let existing = self.lookup_peer_cid_entry(&connection_id);
        // RFC 9000 Section 19.15: 最大 Retire Prior To を増加させない値は
        // 無視しなければならない (MUST)。最大値の更新と退役は重複検査より
        // 前に行う。同一 CID の再通知でも増加した Retire Prior To を反映する
        // 必要があるため (RFC 9000 Section 5.1.2)。
        let retire_increased = self.update_peer_cid_retire_prior_to(path_id, retire_prior_to)?;
        // RFC 9000 Section 13.3 は NEW_CONNECTION_ID の再送を認めている。
        // 同じ CID・同じパス・同じシーケンス番号の再送は冪等に扱い
        // (重複として無視)、それ以外の CID の使い回しは CID の再利用として
        // PROTOCOL_VIOLATION にする (RFC 9000 Section 19.15 の MAY)。
        if let Some((existing_path_id, existing_sequence_number)) = existing {
            if existing_path_id == path_id && existing_sequence_number == sequence_number {
                // 再送された同一フレーム: CID は再登録しない。Retire Prior To が
                // 増加した場合は `retire_peer_cids_prior_to` が退役させるため、
                // 退役で候補 CID が変わっていないか点検し、必要なら送信先 CID を
                // 選び直す。original の保存値は置き換えない。
                if retire_increased {
                    self.reconcile_pending_migrations_after_cid_retire();
                }
                // Retire Prior To が増加しない再通知でも、送信先が退役済みなら
                // 有効な CID へ選び直す。新しい CID を再登録しない場合も、
                // 退役した CID を送信先に残してはならない
                // (RFC 9000 Section 5.1.2)。
                self.select_peer_cid_after_retire(path_id)?;
                return Ok(());
            }
            return Err(Self::peer_cid_reuse_error(frame_kind));
        }
        match self.register_peer_cid(
            path_id,
            sequence_number,
            connection_id.clone(),
            stateless_reset_token,
        )? {
            PeerCidRegistration::Registered => {}
            PeerCidRegistration::Retired => {
                // Retire Prior To 未満の CID は有効化せず RETIRE を積んだ。
                // この分岐は `retire_prior_to <= sequence_number` を満たすフレームで
                // `sequence_number < 最大 Retire Prior To` の場合だけ通るため、
                // このフレームが最大値を増加させることはない。つまり新たな退役は
                // 起こらず、送信先 CID の選び直しも不要である。
                return Ok(());
            }
            PeerCidRegistration::Reused => {
                return Err(Self::peer_cid_reuse_error(frame_kind));
            }
        }
        // PATH_NEW_CONNECTION_ID: このパスで最初に受信した CID を送信先にする
        // (RFC 10069 Section 4)。送信先に採用した CID は
        // 使用済みとして記録する (RFC 9000 Section 9.5)。
        if frame_kind == PeerCidFrameKind::PathNewConnectionId
            && self
                .paths
                .get(path_id)
                .is_some_and(|path| path.peer_cid.is_none())
        {
            self.assign_path_peer_cid(path_id, connection_id.clone());
        }
        // 退役処理の時点では新しい CID がまだ登録されていないため、
        // 生存 CID が無ければ送信先 CID が退役済みのまま残る。
        // 登録後に改めて有効な CID を選び直す (RFC 9000 Section 5.1.2)。
        // Retire Prior To が増加しないフレームでも、送信先が退役済みなら
        // ここで選び直す。Path オブジェクトが無いパスでは
        // `select_peer_cid_after_retire` が何もしないため、未開設のパスへ
        // 先行発行された CID を送信先に割り当てることはない。
        self.select_peer_cid_after_retire(path_id)?;
        if retire_increased {
            // 検証中の migration が保存した CID も退役していないか点検する
            self.reconcile_pending_migrations_after_cid_retire();
        }
        // RFC 9000 Section 5.1.1 / RFC 10069 Section 2.2:
        // active_connection_id_limit はパスごとに適用する。
        // 退役処理後の有効 CID 数が上限を超えた場合は
        // CONNECTION_ID_LIMIT_ERROR で接続を閉じる。
        self.enforce_peer_cid_limit(path_id)
    }

    /// CID の再利用を通知するエラーフレーム名付きの PROTOCOL_VIOLATION を作る
    fn peer_cid_reuse_error(frame_kind: PeerCidFrameKind) -> Error {
        Error::Protocol {
            code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
            reason: format!("{} reused an existing connection ID", frame_kind.name()),
        }
    }

    /// ピアから受信した CID をパスに登録する
    ///
    /// 初期 CID (シーケンス番号 0) と preferred_address の CID
    /// (シーケンス番号 1) も、stateless_reset_token の有無に関わらず
    /// このメソッドで登録する。トークンを持たない初期 CID も退役追跡の対象に
    /// するため、`PeerCidEntry` 自体は作成する。
    ///
    /// path ID 0 は RFC 9000 Section 19.15、path ID 0 以外は
    /// RFC 10069 Section 4.4 に従う。
    ///
    /// 一意性検査も本メソッドで行う。
    ///
    /// - ローカル CID と同じ値は再利用として `Reused` を返す
    ///   (RFC 10069 Section 3.2.1: CID は接続全体で一意)。
    ///   ただしゼロ長 CID は送受信で別の名前空間を使うため、この検査から除く。
    /// - 同じパス・同じシーケンス番号に異なる CID を登録しようとした場合は
    ///   `Reused` を返す (RFC 9000 Section 19.15 の MAY)。
    /// - 同じ CID を別のパス・別のシーケンス番号で登録しようとした場合も
    ///   `Reused` を返す。
    ///
    /// `Reused` を PROTOCOL_VIOLATION にするか無視するかは呼び出し側が決める。
    /// 本実装は接続エラーにする。
    fn register_peer_cid(
        &mut self,
        path_id: PathId,
        sequence_number: u64,
        connection_id: ConnectionId,
        stateless_reset_token: Option<[u8; 16]>,
    ) -> Result<PeerCidRegistration, Error> {
        // PATH_CIDS_BLOCKED の Next Sequence Number は「受信した最大 + 1」なので、
        // 退役対象の CID でも受信した事実は記録する。
        self.peer_cid_max_seq
            .entry(path_id.0)
            .and_modify(|value| *value = (*value).max(sequence_number))
            .or_insert(sequence_number);
        let max_retire = self
            .peer_cid_retire_prior_to
            .get(&path_id.0)
            .copied()
            .unwrap_or(0);
        // RFC 9000 Section 19.15 / RFC 10069 Section 4.4:
        // 以前に受信した最大 Retire Prior To より小さいシーケンス番号の CID は
        // 有効化せず、RETIRE_CONNECTION_ID / PATH_RETIRE_CONNECTION_ID を
        // 送らなければならない (MUST)。
        if sequence_number < max_retire {
            self.queue_retire_peer_cid(path_id, sequence_number, &connection_id)?;
            return Ok(PeerCidRegistration::Retired);
        }
        // 同じシーケンス番号の CID が登録済みなら再通知として扱う。
        // トークンだけ欠けている場合は補完する。CID が異なる場合は
        // RFC 9000 Section 19.15 の MAY に従い再利用として拒否する。
        if let Some(entry) = self
            .peer_cid_entries
            .iter_mut()
            .find(|entry| entry.path_id == path_id && entry.sequence_number == sequence_number)
        {
            if entry.connection_id != connection_id {
                return Ok(PeerCidRegistration::Reused);
            }
            // 同じパス・同じシーケンス番号・同じ CID の再送は冪等に扱う
            // (RFC 9000 Section 13.3)。Stateless Reset Token だけ欠けている
            // 場合は補完し、登録済みとして返す。
            if entry.stateless_reset_token.is_none() {
                entry.stateless_reset_token = stateless_reset_token;
            }
            return Ok(PeerCidRegistration::Registered);
        }
        // ピア CID の集合とローカル CID のマップは別名前空間である。
        // どちらかに登録済みの CID をピア CID として使うことはできない。
        // ピア CID の集合は `peer_cid_entries` 自体で表現し、線形走査で判定する。
        if self.lookup_peer_cid_entry(&connection_id).is_some() {
            return Ok(PeerCidRegistration::Reused);
        }
        if !connection_id.is_empty() && self.paths.contains_cid(&connection_id) {
            return Ok(PeerCidRegistration::Reused);
        }
        self.peer_cid_entries.push(PeerCidEntry {
            path_id,
            sequence_number,
            connection_id,
            used: false,
            used_for: None,
            stateless_reset_token,
        });
        // 新しい CID を受信したため、枯渇通知の抑止を解除する
        self.cid_blocked_notified.remove(&path_id.0);
        Ok(PeerCidRegistration::Registered)
    }

    /// 指定した CID がパスの有効なピア CID として登録されているかを返す
    ///
    /// Retire Prior To による退役では `peer_cid_entries` から除去されるため、
    /// 登録されていなければ退役済みとみなせる。
    fn is_active_peer_cid(&self, path_id: PathId, connection_id: &ConnectionId) -> bool {
        self.peer_cid_entries
            .iter()
            .any(|entry| entry.path_id == path_id && &entry.connection_id == connection_id)
    }

    /// 指定した CID がパスの有効なピア CID として登録され、未使用かを返す
    ///
    /// 移行の候補と preferred_address の CID は、ほかの宛先アドレスへ送信して
    /// いないものだけを使う (RFC 9000 Section 9.5 の MUST NOT)。同じ 4-tuple への
    /// 再試行の可否は `is_peer_cid_available_for` が判定する。
    #[cfg(test)]
    fn is_unused_peer_cid(&self, path_id: PathId, connection_id: &ConnectionId) -> bool {
        self.peer_cid_entries.iter().any(|entry| {
            entry.path_id == path_id && &entry.connection_id == connection_id && !entry.used
        })
    }

    /// 指定パスで未使用の最小シーケンス番号のピア CID を取り出し、使用済みにする
    ///
    /// RFC 9000 Section 9.5: 同じ CID を複数のローカル / 宛先アドレスへの送信に
    /// 再利用してはならない (MUST NOT)。能動回転と migration の候補選択は
    /// このメソッドを使い、送信先に採用した CID を `used` にする。
    fn take_unused_peer_cid_for_path(&mut self, path_id: PathId) -> Option<ConnectionId> {
        let index = self
            .peer_cid_entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.path_id == path_id && !entry.used)
            .min_by_key(|(_, entry)| entry.sequence_number)
            .map(|(index, _)| index)?;
        self.peer_cid_entries[index].used = true;
        Some(self.peer_cid_entries[index].connection_id.clone())
    }

    /// 指定パスで送信先に使えるピア CID を取り出し、使用済みにする
    ///
    /// 未使用の CID を優先し、無ければ最小シーケンス番号の有効な CID を返す。
    /// 退役後の送信先選び直し (`select_peer_cid_after_retire`) と、移行取り消し時の
    /// 送信先復元 (`abort_pending_migration`) に使う。
    ///
    /// 検証中の migration が候補として予約している CID は、移行先の宛先アドレスへ
    /// 送るために取ってある。移行前のアドレスの送信先に採用すると同じ CID を
    /// 2 つの宛先アドレスで使うことになるため (RFC 9000 Section 9.5 の MUST NOT)、
    /// 未使用へ戻す余地のある候補は除く。
    ///
    /// 使用済みの CID は、現在のパスの 4-tuple と同じ宛先でだけ使ったものを選ぶ。
    /// 別の 4-tuple で使った CID を選ぶと RFC 9000 Section 9.5 の MUST NOT に
    /// 反するため、その場合は `None` を返す。
    fn take_peer_cid_for_path(&mut self, path_id: PathId) -> Option<ConnectionId> {
        if let Some(cid) = self.take_unused_peer_cid_for_path(path_id) {
            return Some(cid);
        }
        let reserved = self
            .pending_migrations
            .get(&path_id)
            .map(|migration| migration.candidate_peer_cid.clone());
        let current_target = self
            .paths
            .get(path_id)
            .map(|path| (path.remote_addr, path.local_addr));
        let index = self
            .peer_cid_entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.path_id == path_id)
            .filter(|(_, entry)| reserved.as_ref() != Some(&entry.connection_id))
            .filter(|(_, entry)| entry.used_for.is_none() || current_target == entry.used_for)
            .min_by_key(|(_, entry)| entry.sequence_number)
            .map(|(index, _)| index)?;
        self.peer_cid_entries[index].used = true;
        Some(self.peer_cid_entries[index].connection_id.clone())
    }

    /// ピア CID を使用済みとして記録する
    ///
    /// エントリに存在しない CID (退役済みなど) を渡しても何もしない。
    /// 送信先の 4-tuple は記録しない。実際に送信した 4-tuple は
    /// `record_peer_cid_send_target` が、パスの送信先に採用した CID は
    /// `assign_path_peer_cid` が記録する。予約しただけの CID に 4-tuple を
    /// 記録すると、migration の候補を同じ 4-tuple へ再試行できなくなる。
    fn mark_peer_cid_used(&mut self, path_id: PathId, connection_id: &ConnectionId) {
        if let Some(entry) = self
            .peer_cid_entries
            .iter_mut()
            .find(|entry| entry.path_id == path_id && &entry.connection_id == connection_id)
        {
            entry.used = true;
        }
    }

    /// 実際に送信した 4-tuple を使ってピア CID を使用済みとして記録する
    ///
    /// RFC 9000 Section 9.5 は複数の宛先アドレスへの CID の再利用を禁じる。
    /// 同じ CID を別の 4-tuple へ送ろうとした場合は実装の不整合であるため、
    /// 最初に記録した 4-tuple を保持し、再利用の判定で弾く。
    fn record_peer_cid_send_target(
        &mut self,
        path_id: PathId,
        connection_id: &ConnectionId,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) {
        if let Some(entry) = self
            .peer_cid_entries
            .iter_mut()
            .find(|entry| entry.path_id == path_id && &entry.connection_id == connection_id)
        {
            if entry
                .used_for
                .is_some_and(|used| used != (remote_addr, local_addr))
            {
                tracing::debug!(
                    path_id = %path_id,
                    "connection ID is being reused for a different destination 4-tuple"
                );
            }
            entry.used = true;
            if entry.used_for.is_none() {
                entry.used_for = Some((remote_addr, local_addr));
            }
        }
    }

    /// ピア CID を使用済みとして記録し、送信先の 4-tuple を設定する
    ///
    /// `target` が `None` の場合は 4-tuple を記録しない。エントリが無い場合は
    /// 何もしない。
    fn record_peer_cid_used_at(
        &mut self,
        path_id: PathId,
        connection_id: &ConnectionId,
        target: Option<(std::net::SocketAddr, std::net::SocketAddr)>,
    ) {
        if let Some(entry) = self
            .peer_cid_entries
            .iter_mut()
            .find(|entry| entry.path_id == path_id && &entry.connection_id == connection_id)
        {
            entry.used = true;
            if entry.used_for.is_none() {
                entry.used_for = target;
            }
        }
    }

    /// 指定した 4-tuple への送信にピア CID を使えるかを返す
    ///
    /// 未使用の CID は使える。使用済みの CID は、同じ 4-tuple にだけ送信した
    /// 場合に限り再利用できる (RFC 9000 Section 9.5 は複数の宛先アドレスへの
    /// 再利用だけを禁じる)。`used_for` が無い場合は送信先を特定できないため、
    /// 再利用しない。
    fn is_peer_cid_available_for(
        &self,
        path_id: PathId,
        connection_id: &ConnectionId,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) -> bool {
        self.peer_cid_entries.iter().any(|entry| {
            entry.path_id == path_id
                && &entry.connection_id == connection_id
                && (!entry.used || entry.used_for == Some((remote_addr, local_addr)))
        })
    }

    /// 送信前に取り消した移行候補 CID の予約を解放する
    ///
    /// RFC 9000 Section 9.5: 実際に送信した CID は別の宛先アドレスへ再利用できない
    /// ため、解放してよいのは検証パケットを一度も送っていない場合だけである。
    /// 本メソッド自身は送信の有無を判定しない。呼び出し側が
    /// `PendingMigration::candidate_probe_sent` を確認し、一度も送っていない場合だけ
    /// 呼ぶ。migration を登録する前の乱数生成失敗も、候補を予約しただけで送って
    /// いないため呼び出し対象になる。
    ///
    /// 次の場合は何もしない。
    ///
    /// - 退役などでエントリが無い
    /// - その CID がパスの現在の送信先になっている
    fn release_peer_cid_reservation(&mut self, path_id: PathId, connection_id: &ConnectionId) {
        // パスの現在の送信先 CID として使っている場合は解放しない。退役処理の
        // 置き換えで同じ CID が送信先に採用されていることがある。
        let current = self
            .paths
            .get(path_id)
            .and_then(|path| path.peer_cid.clone())
            .or_else(|| (path_id == PathId::INITIAL).then(|| self.peer_cid.clone()));
        if current.as_ref() == Some(connection_id) {
            return;
        }
        if let Some(entry) = self
            .peer_cid_entries
            .iter_mut()
            .find(|entry| entry.path_id == path_id && &entry.connection_id == connection_id)
        {
            entry.used = false;
            entry.used_for = None;
        }
    }

    /// ピア CID をパスの送信先として設定し、使用済みとして記録する
    ///
    /// 初期パスでは `Connection::peer_cid` も同じ値へ更新する。
    fn assign_path_peer_cid(&mut self, path_id: PathId, connection_id: ConnectionId) {
        self.mark_peer_cid_used(path_id, &connection_id);
        let target = self
            .paths
            .get(path_id)
            .map(|path| (path.remote_addr, path.local_addr));
        self.record_peer_cid_used_at(path_id, &connection_id, target);
        if path_id == PathId::INITIAL {
            self.peer_cid = connection_id.clone();
        }
        if let Some(path) = self.paths.get_mut(path_id) {
            path.peer_cid = Some(connection_id);
        }
    }

    /// ピア CID のエントリを (パス ID, シーケンス番号) で返す
    ///
    /// RFC 9000 Section 19.15 / RFC 10069 Section 4.4:
    /// 同じ CID を別のシーケンス番号、または別のパス ID で通知した場合は
    /// CID の再利用として PROTOCOL_VIOLATION にできる (MAY)。
    /// 同じ CID・同じパス・同じシーケンス番号の再送は冪等に扱う。
    fn lookup_peer_cid_entry(&self, connection_id: &ConnectionId) -> Option<(PathId, u64)> {
        self.peer_cid_entries
            .iter()
            .find(|entry| &entry.connection_id == connection_id)
            .map(|entry| (entry.path_id, entry.sequence_number))
    }

    /// パスごとの最大 Retire Prior To を更新し、必要なら古い CID を退役させる
    ///
    /// RFC 9000 Section 19.15: 最大値を増加させない Retire Prior To は
    /// 無視しなければならない (MUST)。増加した場合だけ最大値を更新し、
    /// RFC 9000 Section 5.1.2 に従って新しい CID を有効集合へ追加する前に、
    /// 当該パスの Retire Prior To 未満の CID を退役させる (MUST)。
    /// RFC 10069 Section 4.4: この規則はパスごとに適用し、
    /// path ID 0 では NEW_CONNECTION_ID と PATH_NEW_CONNECTION_ID が
    /// 同じ最大値を共有する。
    ///
    ///
    /// 戻り値は最大値を更新したかどうか。送信先 CID の選び直しが必要かを
    /// 呼び出し側が判断するために使う。
    fn update_peer_cid_retire_prior_to(
        &mut self,
        path_id: PathId,
        retire_prior_to: u64,
    ) -> Result<bool, Error> {
        let max_retire = self
            .peer_cid_retire_prior_to
            .get(&path_id.0)
            .copied()
            .unwrap_or(0);
        if retire_prior_to <= max_retire {
            return Ok(false);
        }
        self.peer_cid_retire_prior_to
            .insert(path_id.0, retire_prior_to);
        self.retire_peer_cids_prior_to(path_id, retire_prior_to)?;
        Ok(true)
    }

    /// 指定パスの Retire Prior To 未満のピア CID を退役させる
    ///
    /// RFC 9000 Section 5.1.2: 増加した Retire Prior To を受信したら、新しい CID を
    /// 有効集合へ追加する前に、対応する CID を RETIRE_CONNECTION_ID /
    /// PATH_RETIRE_CONNECTION_ID で退役させなければならない (MUST)。
    /// RFC 10069 Section 4.4: 退役の対象は指定した path ID を
    /// 持つ CID に限る。呼び出し側はパスごとの最大 Retire Prior To を更新した
    /// 直後に呼ぶ。
    ///
    /// 未 ACK の退役 CID 数が 2 × `active_connection_id_limit` に達した場合は
    /// CONNECTION_ID_LIMIT_ERROR を返す (RFC 9000 Section 5.1.2 の MAY)。
    ///
    fn retire_peer_cids_prior_to(
        &mut self,
        path_id: PathId,
        retire_prior_to: u64,
    ) -> Result<(), Error> {
        let (to_retire, remaining): (Vec<_>, Vec<_>) = self
            .peer_cid_entries
            .drain(..)
            .partition(|entry| entry.path_id == path_id && entry.sequence_number < retire_prior_to);
        self.peer_cid_entries = remaining;

        for entry in &to_retire {
            // リタイアフレームを送信する
            // RFC 10069 Section 4.4/4.5:
            // PATH_NEW_CONNECTION_ID の retire_prior_to にも RFC 9000 Section 5.1.2 と
            // 同じ処理をパスごとに適用する
            self.queue_retire_peer_cid(path_id, entry.sequence_number, &entry.connection_id)?;
        }

        // 送信先 CID の選び直しはここでは行わない。呼び出し元の
        // `handle_peer_cid_frame` が、新しい CID を登録した後または同一 CID の
        // 再通知を処理した後に `select_peer_cid_after_retire` を呼ぶ。ここで
        // 選び直すと、この直後に登録される新しい CID を候補にできず、移行を
        // 不必要に取り消すことがある。
        Ok(())
    }

    /// 指定パスで未 ACK の退役 CID 数を返す
    ///
    /// 送信待ち (`pending_frames`) だけでなく、送信済みで未 ACK の RETIRE も
    /// 数えるため、退役履歴 (`retired_peer_cid_seq`) のうち当該パスの件数を返す。
    /// 履歴の上限による過小評価の扱いは MAX_RETIRED_PEER_CID_HISTORY を参照。
    fn unacked_retired_peer_cid_count(&self, path_id: PathId) -> usize {
        self.retired_peer_cid_seq
            .iter()
            .filter(|(retired_path_id, _)| *retired_path_id == path_id.0)
            .count()
    }

    /// 退役させるピア CID の RETIRE フレームを送信待ちに積む
    ///
    /// 呼び出し側は、このメソッドを呼ぶ前に `peer_cid_entries` へ登録せず、
    /// 登録済みなら削除しておく。本メソッドは退役履歴の記録とフレームの送信待ち
    /// への追加だけを行う。
    /// RFC 9000 Section 19.16 / RFC 10069 Section 4.5:
    /// path ID 0 では RETIRE_CONNECTION_ID、それ以外のパスでは
    /// PATH_RETIRE_CONNECTION_ID を使う。
    /// 履歴による重複抑止と未 ACK 数の上限は
    /// MAX_RETIRED_PEER_CID_HISTORY を参照。この上限は損失再送では検査しない。
    /// 損失再送は「退役させずに忘れない」ための必須の送信であり、通常の退役要求
    /// とは区別する。
    ///
    /// `connection_id` は退役する CID の値であり、退役履歴の対応表に記録する。
    /// 退役後も DCID として使われていないかを送信前に検査できるようにするため
    /// (RFC 9000 Section 19.16)。
    ///
    fn queue_retire_peer_cid(
        &mut self,
        path_id: PathId,
        sequence_number: u64,
        connection_id: &ConnectionId,
    ) -> Result<(), Error> {
        let key = (path_id.0, sequence_number);
        if self.retired_peer_cid_seq.contains(&key) {
            return Ok(());
        }
        let limit = self
            .local_params
            .active_connection_id_limit
            .saturating_mul(2);
        if self.unacked_retired_peer_cid_count(path_id) as u64 >= limit {
            return Err(Error::Protocol {
                code: tobi_core::error::TransportErrorCode::CONNECTION_ID_LIMIT_ERROR,
                reason: format!(
                    "unacknowledged RETIRE frames for path {path_id} would exceed 2 * active_connection_id_limit {limit}"
                ),
            });
        }
        self.record_retired_peer_cid(key, connection_id);
        let sequence_number = VarInt::new(sequence_number).expect("value fits in 62-bit varint");
        if path_id == PathId::INITIAL {
            self.streams
                .pending_frames
                .push_back(Frame::RetireConnectionId(
                    frame::retire_connection_id::RetireConnectionId { sequence_number },
                ));
        } else {
            self.streams
                .pending_frames
                .push_back(Frame::PathRetireConnectionId(
                    frame::path_retire_connection_id::PathRetireConnectionId {
                        path_id: path_id.0,
                        sequence_number,
                    },
                ));
        }
        Ok(())
    }

    /// 退役した (パス ID, シーケンス番号) を履歴へ記録する
    ///
    /// 履歴は MAX_RETIRED_PEER_CID_HISTORY を上限とし、超えた分は古い記録から
    /// 捨てる。同じキーが既にあれば履歴の集合には何もしないが、CID の対応表は
    /// 受け取った値で更新する。
    fn record_retired_peer_cid(&mut self, key: (u32, u64), connection_id: &ConnectionId) {
        self.retired_peer_cid_identities
            .insert(key, connection_id.clone());
        if !self.retired_peer_cid_seq.insert(key) {
            return;
        }
        self.retired_peer_cid_order.push_back(key);
        while self.retired_peer_cid_order.len() > MAX_RETIRED_PEER_CID_HISTORY {
            if let Some(oldest) = self.retired_peer_cid_order.pop_front() {
                self.retired_peer_cid_seq.remove(&oldest);
                self.retired_peer_cid_identities.remove(&oldest);
            }
        }
    }

    /// 退役後に送信先として使うピア CID を選び直す
    ///
    /// RFC 9000 Section 5.1.2: 増加した Retire Prior To を受信したピアは、
    /// 対応する CID の使用を停止し、RETIRE_CONNECTION_ID で退役させなければ
    /// ならない (MUST)。したがって、退役した CID を送信先に残してはならない。
    /// 呼び出し時点で `retire_peer_cids_prior_to` が Retire Prior To 未満の
    /// エントリを除去済みなので、残っているエントリはすべて有効である。
    ///
    /// 未使用の CID を優先し、無ければ最小シーケンス番号の CID を選ぶのは
    /// 本実装のポリシーであり、RFC が最小を要求するものではない。
    /// どの有効 CID を選んでもよいが、決定的にしてテストしやすくするために
    /// この順序にする。RFC 10069 Section 3.2.2:
    /// 同じ path ID に紐づく CID にだけ切り替える (MUST)。
    ///
    /// 現在の送信先 CID が退役していて、現在の 4-tuple へ送信できる有効な CID も
    /// 無い場合は、同じパスの検証中の migration が予約している候補 CID を解放して
    /// 送信先に選び直す。migration は取り消す。候補 CID を検証パケットで送信済みの
    /// 場合は、同じ CID を別の宛先アドレスへ再利用できないため (RFC 9000
    /// Section 9.5 の MUST NOT)、退役済み CID を使い続けずに
    /// `CONNECTION_ID_LIMIT_ERROR` で接続を閉じる。どのエラーコードで閉じるかは
    /// RFC が定めておらず、本実装が CID の管理限界として選んだものである。
    ///
    /// 送信可能な CID が 1 つも無い状態で閉じる場合、CONNECTION_CLOSE の DCID に
    /// 最後の送信先 CID (退役済み) を使うほかない。退役済み CID でも閉鎖が届くのは、
    /// CID を発行したエンドポイントが RETIRE_CONNECTION_ID を受けるまでその CID を
    /// 運ぶパケットを受け付けなければならないためである (RFC 9000 Section 5.1.1 の
    /// MUST)。閉鎖パケットには CONNECTION_CLOSE だけを載せ、同じ DCID を指す
    /// RETIRE_CONNECTION_ID を含めないのは実装ポリシーである。RFC 9000
    /// Section 19.16 で関係するのは、RETIRE のシーケンス番号がそのパケットの
    /// DCID を指してはならない MUST NOT だけである。ピアが閉鎖通知を処理できる
    /// ようにすることを優先する (RFC 9000 Section 10.2.3)。
    ///
    /// このメソッドが返す [`Error::Protocol`] は受信処理の接続クローズ経路へ
    /// 伝播する。エラーを返す前に検証中の migration を取り消し、PathValidation
    /// タイマーを解除するため、Closing 中に PATH_CHALLENGE は生成されない。
    ///
    /// Path オブジェクトがまだ無いパスでは何もしない。未開設のパスへ
    /// PATH_NEW_CONNECTION_ID が届いても CID は登録だけしておき、送信先への
    /// 割り当ては `open_path` 時に行う。ここで先に `used` を立てると、
    /// 送信先に使わない CID を消費してしまう (RFC 9000 Section 9.5)。
    fn select_peer_cid_after_retire(&mut self, path_id: PathId) -> Result<(), Error> {
        // 未開設のパスには送信先が無いため、CID の選択も使用済みの記録も行わない。
        if self.paths.get(path_id).is_none() {
            return Ok(());
        }
        // ハンドシェイクで使うピアの初期 CID は、ピアのトランスポート
        // パラメータを確定した時点で `peer_cid_entries` に登録される。
        // 確定前にここで選び直すと、まだ登録されていない初期 CID を
        // 「退役済み」と誤認し、受信済みの未使用 CID を送信先に消費して
        // しまう。パラメータ確定後は初期 CID が登録済みになるため、
        // このガードで必要な選び直しが失われることはない。
        if !self.peer_params_finalized {
            return Ok(());
        }
        // 現在の送信先 CID がまだ有効なら切り替えない。Retire Prior To の増加に
        // 現在の CID が含まれない場合に、ここで無条件に未使用 CID へ切り替えると、
        // 退役処理の直後と新しい CID の登録後で 2 回切り替わり、1 パケットも
        // 送っていない CID を使用済みにしてしまう (RFC 9000 Section 9.5)。
        let current = self
            .paths
            .get(path_id)
            .and_then(|path| path.peer_cid.clone())
            .or_else(|| (path_id == PathId::INITIAL).then(|| self.peer_cid.clone()));
        // 送信先がまだ決まっていないパスは、退役ではなく未割り当てである。
        // ここで CID を選ぶと `open_path` 前の CID を使用済みにしてしまう。
        let Some(current) = current else {
            return Ok(());
        };
        if self.is_active_peer_cid(path_id, &current) {
            return Ok(());
        }
        // 退役した現在の CID の代わりに、未使用または同じ 4-tuple で使用済みの
        // 有効な CID を選ぶ。migration 候補として予約されている CID は除かれる。
        if let Some(new_cid) = self.take_peer_cid_for_path(path_id) {
            self.assign_path_peer_cid(path_id, new_cid);
            return Ok(());
        }
        // 予約済みの候補 CID しか残っていない場合、その候補を現在の送信先に
        // 使うためには検証中の migration を取り消して予約を解放する必要がある。
        let Some(candidate_probe_sent) = self
            .pending_migrations
            .get(&path_id)
            .map(|migration| migration.candidate_probe_sent)
        else {
            // 現在の 4-tuple へ送信できる有効な CID が無い。退役済み CID を
            // 使い続けることはできない (RFC 9000 Section 5.1.2) ため、接続を閉じる。
            // 移行が無くても PathValidation タイマーが残っていれば解除する。
            return Err(self.fail_no_peer_cid_after_retire(path_id));
        };
        if candidate_probe_sent {
            // 検証パケットで送信済みの候補 CID は、別の宛先アドレスへ再利用
            // できない (RFC 9000 Section 9.5 の MUST NOT)。退役済み CID を
            // 使わず、接続を閉じる。検証中の migration とタイマーを先に破棄する。
            return Err(self.fail_no_peer_cid_after_retire(path_id));
        }
        // 候補はまだ一度も送信していないため、移行を取り消して予約を解放できる。
        // `discard_pending_migration` がタイマー解除と PathValidationFailed の
        // 通知を行う。
        self.cancel_pending_migration(path_id);
        let Some(new_cid) = self.take_peer_cid_for_path(path_id) else {
            // 候補も同時に退役しているなど、解放後にも有効な CID が無い。
            // migration とタイマーは上の取り消しで破棄済みである。
            return Err(Self::no_peer_cid_after_retire_error(path_id));
        };
        self.assign_path_peer_cid(path_id, new_cid);
        Ok(())
    }

    /// 退役後に送信先 CID を確保できないとき、migration を破棄してエラーを返す
    ///
    /// エラーを返す前に、検証中の migration を取り消す。`discard_pending_migration`
    /// は `pending_migrations` の削除、未送信の検証パケットの破棄、
    /// PathValidation タイマーの解除を行う。migration を取り消した場合は
    /// `PathValidationFailed` を 1 回だけ通知する。migration が無い場合も、
    /// パス検証タイマーが発火して PATH_CHALLENGE を生成しないよう ClearTimer を
    /// 積む。同じ migration を二重に取り消した場合は通知しない
    /// (`discard_pending_migration` が偽を返すため)。
    ///
    /// RFC 9000 Section 5.1.2: 増加した Retire Prior To を受信したピアは、対応する
    /// CID の使用を停止し、RETIRE_CONNECTION_ID で退役させなければならない (MUST)。
    /// 送信可能な CID を残さない退役要求を受けた場合に接続を閉じることは、同節は
    /// 定めていない。本実装は CID の管理限界として `CONNECTION_ID_LIMIT_ERROR` を
    /// 選ぶ。
    ///
    /// 接続を閉じる CONNECTION_CLOSE は、現在の 4-tuple へ送信できる有効な CID が
    /// 無いため最後の送信先 CID (退役済み) を DCID に使う例外的な送信になる。
    /// 退役済み CID でも閉鎖が届く根拠は、CID を発行したエンドポイントが
    /// RETIRE_CONNECTION_ID を受けるまでその CID を運ぶパケットを受け付けなければ
    /// ならないことである (RFC 9000 Section 5.1.1 の MUST)。閉鎖パケットには
    /// CONNECTION_CLOSE だけを載せ、同じ DCID を指す RETIRE_CONNECTION_ID を
    /// 含めないのは実装ポリシーである (RFC 9000 Section 19.16)。詳細は
    /// `close_inner` を参照。
    fn fail_no_peer_cid_after_retire(&mut self, path_id: PathId) -> Error {
        if self.pending_migrations.contains_key(&path_id) {
            self.cancel_pending_migration(path_id);
        } else {
            // 移行ではないパス検証 (追加パスの到達性確認など) のタイマーも、
            // Closing 中に PATH_CHALLENGE を生成しないよう解除する。
            self.output_queue.push_back(ConnectionOutput::ClearTimer {
                id: TimerId::PathValidation { path_id },
            });
        }
        Self::no_peer_cid_after_retire_error(path_id)
    }

    /// 退役後に送信先 CID を確保できないときの接続エラーを作る
    ///
    /// RFC 9000 Section 5.1.2: 増加した Retire Prior To を受信したピアは、対応する
    /// CID の使用を停止し、RETIRE_CONNECTION_ID で退役させなければならない (MUST)。
    /// 送信可能な CID を残さない退役要求を受けた場合に接続を閉じることは、同節は
    /// 定めていない。本実装は CID の管理限界として `CONNECTION_ID_LIMIT_ERROR` を
    /// 選ぶ。
    ///
    /// この関数はエラー値を作るだけで、イベント通知もタイマー解除も行わない。
    /// migration を取り消してからこのエラーを返す場合は
    /// `fail_no_peer_cid_after_retire` を使うこと。閉鎖時の DCID と RETIRE の
    /// 扱いは同メソッドと `close_inner` を参照。
    fn no_peer_cid_after_retire_error(path_id: PathId) -> Error {
        Error::Protocol {
            code: tobi_core::error::TransportErrorCode::CONNECTION_ID_LIMIT_ERROR,
            reason: format!(
                "no usable peer connection ID remains for path {path_id} after retirement"
            ),
        }
    }

    /// 退役処理の後に、検証中の migration が保持する候補 CID を点検する
    ///
    /// `migrate` / `migrate_to_preferred_address` は検証開始時点の
    /// candidate / original ピア CID を `pending_migrations` に保存する。
    /// 検証中に Retire Prior To が増加して candidate が退役した場合、
    /// そのまま commit すると退役済み CID を送信先へ確定してしまう
    /// (RFC 9000 Section 5.1.2)。
    ///
    /// 本実装のポリシー: 退役した candidate を、移行先の宛先アドレスへまだ
    /// 送っていない CID に置き換える (RFC 9000 Section 9.5 の MUST NOT)。
    /// 置き換えた候補はまだ検証パケットを送っていないため、
    /// `candidate_probe_sent` を偽に戻す。旧候補で送信済みの未出力パケットは
    /// `one_rtt_pending_valid` が候補 CID の一致を確認して破棄する。
    /// 置き換え先が無い場合は移行を継続できないため取り消す。
    ///
    /// original は commit では使わず、abort のときだけ使う。ここで置き換え先を
    /// 予約すると、未使用の CID を `used` にしたまま commit し、その CID が
    /// 二度と選ばれなくなる。そのため original の置き換えは行わない。abort は
    /// 現在のパスが有効な CID を保持していればそれを維持し、失われている場合だけ
    /// 有効な CID を選び直す (`abort_pending_migration`)。
    fn reconcile_pending_migrations_after_cid_retire(&mut self) {
        if self.pending_migrations.is_empty() {
            return;
        }
        // pending_migrations の可変借用と peer_cid_entries の参照が衝突しないよう、
        // パス ID ごとに判定と更新を分ける。
        let path_ids: Vec<PathId> = self.pending_migrations.keys().copied().collect();
        for path_id in path_ids {
            let candidate_retired = {
                let Some(migration) = self.pending_migrations.get(&path_id) else {
                    continue;
                };
                !self.is_active_peer_cid(path_id, &migration.candidate_peer_cid)
            };
            if !candidate_retired {
                continue;
            }
            // 未使用の CID が残らなければ、移行先の DCID に使う CID が無い。
            // 退役済み CID や使用済み CID で移行を続けず、取り消す。
            let Some(replacement) = self.take_unused_peer_cid_for_path(path_id) else {
                self.cancel_pending_migration(path_id);
                continue;
            };
            let Some(migration) = self.pending_migrations.get_mut(&path_id) else {
                continue;
            };
            migration.candidate_peer_cid = replacement;
            // 置き換え前の候補で送った検証パケットの有無を引き継がない。
            // 新しい候補はまだ一度も送っていないため、取り消し時に解放できる。
            migration.candidate_probe_sent = false;
        }
    }

    /// 退役した CID の置き換え先が無いため、検証中の migration を取り消す
    ///
    /// 4-tuple は検証中に変更していないため元のアドレスへ戻し、`validation.restart()`
    /// で検証状態を破棄する。再試行するかどうかは呼び出し側が判断する。
    /// ピア CID は退役済みの元値へ戻さず、現在のパス状態を維持する。
    /// 検証失敗としてアプリケーションへ通知する。
    ///
    /// `PathValidationFailed` を通知するのは、取り消した migration があった場合
    /// だけである。`discard_pending_migration` 自体は通知しないため、呼び出し側が
    /// このメソッドと `discard_pending_migration` を用途で使い分ける。
    /// 同じ migration を二重に取り消しても、2 回目は破棄に失敗するため通知しない。
    fn cancel_pending_migration(&mut self, path_id: PathId) {
        if self.discard_pending_migration(path_id) {
            self.push_event(ConnectionEvent::PathValidationFailed { path_id });
        }
    }

    /// 検証中の migration を取り消し、イベントを通知せずに破棄する
    ///
    /// このメソッドは `PathValidationFailed` を通知しない。通知の要否は呼び出し側が
    /// 決める。移行の取り消しを利用者へ伝える場合は `cancel_pending_migration` を
    /// 使う。PATH_ABANDON でパス自体を廃棄する場合は `PathAbandoned` を通知するため
    /// `PathValidationFailed` を重ねて通知しない。`commit_pending_migration` の
    /// フォールバックも、直前に `PathValidated` を通知している場合は矛盾を避ける
    /// ために通知しない。検証タイマーは必ず解除し、タイマー発火時に改めて失敗通知が
    /// 出ないようにする。
    ///
    /// 候補 CID を使った検証パケットを一度も送っていない場合は、予約として
    /// 立てた `used` を解除して未使用へ戻す。送信済みの場合は RFC 9000
    /// Section 9.5 により別の宛先アドレスへ再利用できないため、`used` のまま
    /// 残す。
    ///
    /// 戻り値は取り消した migration があったかどうか。
    fn discard_pending_migration(&mut self, path_id: PathId) -> bool {
        let Some(migration) = self.pending_migrations.remove(&path_id) else {
            return false;
        };
        // 候補 CID を DCID にした未出力の検証パケットを破棄する。残すと
        // 通常データの生成枠を塞ぎ、取り消した移行の出力が後から送られる。
        self.discard_pending_migration_outputs(path_id);
        if !migration.candidate_probe_sent {
            self.release_peer_cid_reservation(path_id, &migration.candidate_peer_cid);
        }
        if let Some(path) = self.paths.get_mut(path_id) {
            // 検証中は 4-tuple を変更していないが、abort と同じ状態へ戻す
            path.remote_addr = migration.original_remote_addr;
            path.local_addr = migration.original_local_addr;
            path.migration_reset_pending = false;
            path.validation.restart();
        }
        self.output_queue.push_back(ConnectionOutput::ClearTimer {
            id: TimerId::PathValidation { path_id },
        });
        true
    }

    /// PATH_STATUS_AVAILABLE / PATH_STATUS_BACKUP フレームを処理する
    ///
    /// RFC 10069 Section 3.3 に基づき、
    /// シーケンス番号で順序外のフレームを無視し、パスステータスを更新する。
    /// マルチパスフレームの path_id が local_max_path_id 以下であることを検証する
    ///
    /// RFC 10069 Section 4:
    /// 「path ID が MAX_PATH_ID または initial_max_path_id の値を超える場合、
    ///  PROTOCOL_VIOLATION として接続エラーとする (MUST)」
    fn validate_frame_path_id(&self, path_id: u32) -> Result<(), Error> {
        if path_id > self.paths.local_max_path_id {
            return Err(Error::Protocol {
                code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                reason: format!(
                    "frame path_id {} exceeds local max_path_id {}",
                    path_id, self.paths.local_max_path_id
                ),
            });
        }
        Ok(())
    }

    /// multipath 拡張がネゴシエート済みかどうかを判定する
    ///
    /// RFC 10069 Section 2:
    /// 両端点が `initial_max_path_id` transport parameter を advertise した場合のみ
    /// multipath 拡張を利用できる。値が `Some(0)` でも advertise されていれば
    /// ネゴシエート済みとして扱うため、値ではなく advertise の有無で判定する。
    /// peer 側が `None` の場合も安全に `false` を返す (拒否側に倒れる)。
    fn multipath_negotiated(&self) -> bool {
        self.local_params.initial_max_path_id.is_some()
            && self
                .peer_params
                .as_ref()
                .and_then(|p| p.initial_max_path_id)
                .is_some()
    }

    /// multipath がネゴシエート済みであることを検査する
    ///
    /// RFC 10069 Section 2:
    /// "If either of the endpoints does not advertise the initial_max_path_id
    /// transport parameter, then both endpoints MUST NOT use any frame or
    /// mechanism defined in this document."
    ///
    /// 受信側は PROTOCOL_VIOLATION で接続を閉じるが、送信側 API はローカルの
    /// 誤用であるため接続状態の不正と同じ `Error::InvalidData` を返す。
    fn check_multipath_negotiated(&self) -> Result<(), Error> {
        if self.multipath_negotiated() {
            return Ok(());
        }
        Err(Error::InvalidData(
            "multipath is not negotiated with the peer".into(),
        ))
    }

    /// PTO / Persistent Congestion / RTT サンプル調整 / ライフサイクル期限に使う
    /// 実効ピア max_ack_delay
    ///
    /// draft-ietf-quic-ack-frequency-14 Section 7: ACK_FREQUENCY で要求した値と
    /// ピアの transport parameter の大きい方を使う。ACK されるまでの間は
    /// in-flight の要求値との最大を取る MUST を、送信済み要求値の最大を保持する
    /// ことで満たす (値は単調増加)。
    fn effective_peer_max_ack_delay(&self) -> tobi_core::time::Duration {
        let peer_tp_us = self
            .peer_params
            .as_ref()
            .map_or(25_000, |params| params.max_ack_delay.saturating_mul(1000));
        // ACK 済みの直近要求値があればそれを、無ければピアの TP を使う。
        let current_us = self
            .ack_frequency_last_acked
            .map_or(peer_tp_us, |(_, requested)| requested);
        // ACK されるまでの間は in-flight の要求値との大きい方を使う (MUST)。
        let in_flight_max = self
            .ack_frequency_in_flight
            .iter()
            .map(|(_, requested)| *requested)
            .max();
        let effective_us = in_flight_max.map_or(current_us, |requested| current_us.max(requested));
        tobi_core::time::Duration::from_micros(effective_us)
    }

    /// ライフサイクル期限に加算する実効 ACK delay を返す
    ///
    /// RFC 9002 Section 6.2.1: Application Data 空間の PTO には
    /// max_ack_delay を加算する。Idle / keep-alive / PathCleanup /
    /// Closing / Draining / 鍵関連期限は、ハンドシェイク確認後ならこの値を使う。
    /// 確認前は Initial / Handshake 空間と同じく加算しない。
    fn lifecycle_ack_delay(&self) -> tobi_core::time::Duration {
        if self.handshake_confirmed_once {
            self.effective_peer_max_ack_delay()
        } else {
            tobi_core::time::Duration::ZERO
        }
    }

    /// 指定パスのライフサイクル期限用 PTO を返す
    ///
    /// ハンドシェイク確認後は実効 ACK delay を含む。初期パスは常に存在し、
    /// 廃棄対象のパスも呼び出し前に存在を確認しているため、パスが存在しない
    /// 場合は実装バグとしてパニックする。
    fn lifecycle_pto_for_path(&self, path_id: PathId) -> tobi_core::time::Duration {
        let base = self
            .paths
            .get(path_id)
            .expect("lifecycle PTO requires an existing path")
            .rtt
            .pto();
        base.saturating_add(self.lifecycle_ack_delay())
    }

    /// 全パスの最大ライフサイクル期限用 PTO を返す
    ///
    /// Closing / Draining、鍵関連期限など、接続全体で 1 つの期限を決める
    /// 用途で使う。最大の基準 PTO に実効 ACK delay を 1 回だけ加算する。
    fn lifecycle_max_pto(&self) -> tobi_core::time::Duration {
        self.paths
            .max_pto()
            .saturating_add(self.lifecycle_ack_delay())
    }

    /// spurious loss 判定のためにロスト判定済みパケットを保持する期間
    ///
    /// RFC 9002 Section 6.1: ロスト判定は再順序により覆り得るため、後から
    /// ACK されたパケットを spurious loss と判定するには一定期間の記録が必要。
    /// 3 × PTO を保持期間とし、その間に ACK されなければ再順序ではなく
    /// 実際のロストとみなす。PTO には Application Data 空間のみ peer の
    /// max_ack_delay を加算する (RFC 9002 Section 6.2.1)。
    fn spurious_loss_retention(
        &self,
        path_id: PathId,
        space: PacketNumberSpace,
    ) -> tobi_core::time::Duration {
        let Some(path) = self.paths.get(path_id) else {
            return tobi_core::time::Duration::ZERO;
        };
        let max_ack_delay = if space == PacketNumberSpace::ApplicationData {
            self.effective_peer_max_ack_delay()
        } else {
            tobi_core::time::Duration::ZERO
        };
        let pto = path.rtt.pto().saturating_add(max_ack_delay);
        tobi_core::time::Duration::from_micros(pto.as_micros().saturating_mul(3))
    }

    /// PathValidation タイマーの基準 PTO を返す
    ///
    /// RFC 9000 Section 8.2.4 は現在のパスと検証対象パスの PTO の大きい方を
    /// 使うことを RECOMMENDED とする。新パスの RTT が初期パスより長い場合に
    /// タイムアウトが短すぎて検証成功前に abandon する偽陰性を防ぐ。
    fn path_validation_pto(&self, path_id: PathId) -> tobi_core::time::Duration {
        // pto() は Copy の Duration を返すため借用は衝突しない
        let current = self.paths.initial_path().rtt.pto();
        let target = self
            .paths
            .get(path_id)
            .expect("path must exist for validation timer")
            .rtt
            .pto();
        current.max(target)
    }

    /// OBSERVED_ADDRESS を送信できるかどうかを判定する
    ///
    /// draft-ietf-quic-address-discovery-01 Section 3 / 5:
    /// 自分が観測アドレスを提供可能 (0 または 2) かつ
    /// ピアが受信を希望 (1 または 2) している場合のみ送信できる。
    fn can_send_observed_address(&self) -> bool {
        matches!(self.local_params.address_discovery, Some(0) | Some(2))
            && matches!(
                self.peer_params.as_ref().and_then(|p| p.address_discovery),
                Some(1) | Some(2)
            )
    }

    /// 指定パスで観測したピアアドレスを OBSERVED_ADDRESS として送信する
    ///
    /// draft-ietf-quic-address-discovery-01 Section 5:
    /// 提供可能なエンドポイントは新しいパスごとに OBSERVED_ADDRESS を送信する (MUST)。
    /// 送信できない条件では何もしない。
    fn send_observed_address(&mut self, path_id: PathId, now: Timestamp) -> Result<(), Error> {
        if !self.can_send_observed_address() {
            return Ok(());
        }
        let Some(path) = self.paths.get(path_id) else {
            return Ok(());
        };
        let addr = path.remote_addr;
        let sequence_number = self.observed_address_seq_send;
        // シーケンス番号は VarInt 範囲 (2^62-1) を超えないように飽和させる
        self.observed_address_seq_send = sequence_number.saturating_add(1).min((1u64 << 62) - 1);
        self.emit_1rtt_single_frame(
            path_id,
            Frame::ObservedAddress(frame::observed_address::ObservedAddress {
                sequence_number: VarInt::new(sequence_number).expect("value fits in 62-bit varint"),
                addr,
            }),
            now,
        )
        .map(|_| ())
    }

    /// パスが abandoned/abandoning 状態かどうかを判定する
    ///
    /// RFC 10069 Section 4:
    /// abandoned path ID のフレームは無視しなければならない (MUST)
    /// Stateless Reset パケットの検出 (RFC 9000 Section 10.3)
    ///
    /// デコード/復号に失敗したパケットの末尾 16 バイトが
    /// 既知の Stateless Reset Token と一致するか確認する。
    /// 一致した場合は Draining 状態に遷移する。
    fn check_stateless_reset(&mut self, data: &[u8], now: Timestamp) {
        // Stateless Reset は最低 21 バイト (RFC 9000 Section 10.3)
        if data.len() < 21 {
            return;
        }
        let token_bytes: [u8; 16] = data[data.len() - 16..]
            .try_into()
            .expect("stateless reset token is 16 bytes");

        // 定数時間比較で既知トークンと照合する。トークンを持たない初期 CID は
        // 比較対象から除く。
        let is_reset = self.peer_cid_entries.iter().any(|entry| {
            entry
                .stateless_reset_token
                .as_ref()
                .is_some_and(|token| crypto::constant_time_eq_pub(token, &token_bytes))
        });

        if is_reset {
            self.state = ConnectionState::Draining;
            self.push_event(ConnectionEvent::ConnectionClosed {
                error_code: 0,
                reason: b"stateless reset".to_vec(),
                kind: ConnectionCloseKind::Internal,
            });
            // Draining タイマーを設定する (Closing と同じ算出式を使う)
            self.set_closing_draining_timer(now);
        }
    }

    fn is_path_abandoned(&self, path_id: PathId) -> bool {
        // tombstone セットを確認する (remove_path() 後も有効)
        if self.paths.is_abandoned_path_id(path_id) {
            return true;
        }
        self.paths
            .get(path_id)
            .is_some_and(|p| p.state == PathState::Abandoned || p.state == PathState::Abandoning)
    }

    fn process_path_status(&mut self, status_path_id: PathId, seq: u64, status: PathStatus) {
        let Some(path) = self.paths.get_mut(status_path_id) else {
            // 廃棄済みの path ID は再作成されないため、保持しても消費されない。
            // 処理できない path ID のフレームは黙って無視する
            // (RFC 10069 Section 4)。`PathManager` 側の
            // 記録ガードと重複するが、フレーム処理の入口で早期に捨てる。
            if self.paths.is_abandoned_path_id(status_path_id) {
                return;
            }
            // 未開設の path ID への通知は保持し、そのパスを開いた時点で反映する
            // (RFC 10069 Section 4.3)
            self.paths
                .record_pending_peer_status(status_path_id, seq, status);
            return;
        };
        // RFC 10069 Section 4:
        // abandoned path ID のフレームは無視する (MUST)
        if path.state == PathState::Abandoned || path.state == PathState::Abandoning {
            return;
        }
        // シーケンス番号が古いか同じ場合は無視する
        // RFC 10069 Section 4.3:
        // 「同じ Path Identifier で等しいかより大きい Path Status Sequence Number の
        //  フレームを受信済みの場合、受信者はそのフレームを無視しなければならない (MUST)」
        // PATH_STATUS_AVAILABLE と PATH_STATUS_BACKUP は共有シーケンス番号空間
        if let Some(prev_seq) = path.status_seq_recv
            && seq <= prev_seq
        {
            return;
        }
        path.status_seq_recv = Some(seq);
        // ピアの preference はローカルの状態を上書きしない
        // (RFC 10069 Section 3.3)。
        path.peer_status = Some(status);
        // ピアの希望の変化をアプリへ通知する
        self.push_event(ConnectionEvent::PeerPathStatusChanged {
            path_id: status_path_id,
            status,
        });
    }

    // --- TLS ---

    fn advance_tls(&mut self, now: Timestamp) -> Result<(), Error> {
        // 受信 CRYPTO データを TLS に供給する。rustls が致命的なハンドシェイク
        // エラー (ALPN 不一致、証明書検証失敗など) を返した場合は、その場で
        // CRYPTO_ERROR の CONNECTION_CLOSE を送って接続を閉じる
        // (RFC 9001 Section 4.8)。ここで閉じないと状態が handshaking のまま
        // 停止し、呼び出し側の connect() が永久に完了しない。
        // RFC 9001 Section 4.1.3: 暗号化レベルごとに CRYPTO データのバイト列は
        // 独立している。低い暗号化レベルの未消費データ (未充填のギャップ) が
        // 残っている間は、高い暗号化レベルのデータを TLS に渡さない。
        let initial_data = self.crypto_recv_initial.take();
        if !initial_data.is_empty()
            && let Err(err) = self.tls_read_hs(&initial_data)
        {
            return self.close_on_tls_error(err, now);
        }

        // Initial レベルの未消費データが残っている間は Handshake を渡さない。
        if self.crypto_recv_initial.is_empty() {
            let hs_data = self.crypto_recv_handshake.take();
            if !hs_data.is_empty()
                && let Err(err) = self.tls_read_hs(&hs_data)
            {
                return self.close_on_tls_error(err, now);
            }
        }

        // Handshake レベルの未消費データが残っている間は 1-RTT を渡さない。
        if self.crypto_recv_initial.is_empty() && self.crypto_recv_handshake.is_empty() {
            let rtt_data = self.crypto_recv_1rtt.take();
            if !rtt_data.is_empty() {
                if let Err(err) = self.tls_read_hs(&rtt_data) {
                    return self.close_on_tls_error(err, now);
                }
                // RFC 9001 Section 4.5 / Section 4.1.3: NewSessionTicket は
                // 1-RTT の CRYPTO で運ばれるポストハンドシェイクメッセージである。
                // 受信バッファの残量や HANDSHAKE_DONE の到着順ではなく、
                // クライアントが 1-RTT CRYPTO を TLS に渡して処理した事実で
                // 1 回だけ通知する。
                if self.role == Role::Client && !self.session_ticket_received {
                    self.session_ticket_received = true;
                    self.push_event(ConnectionEvent::SessionTicketReceived);
                }
            }
        }

        // 0-RTT 鍵の取得 (RFC 9001 Section 4.6)
        // サーバー: ClientHello 処理後に 0-RTT 受信鍵が利用可能になる
        // クライアント: セッション復元設定後に 0-RTT 送信鍵が利用可能になる
        if self.zero_rtt_keys.is_none() {
            let zk = match &self.tls_session {
                TlsSessionHolder::Client(c) => c.zero_rtt_keys(),
                // RFC 9001 Section 4.6.2: サーバーが early_data を拒否した場合は
                // 0-RTT パケットを処理してはならない (MUST NOT)。rustls は拒否時に
                // 0-RTT 鍵を導出しないが、受理判定を明示的に確認してから設定する。
                TlsSessionHolder::Server(s) => {
                    if s.is_early_data_accepted() {
                        s.zero_rtt_keys()
                    } else {
                        None
                    }
                }
            };
            if let Some(keys) = zk {
                self.zero_rtt_keys = Some(keys);
                // サーバーはリプレイ検出用にセッションチケットのハッシュを保持する。
                // チケットは ClientHello の PSK identity から取得する。
                if self.role == Role::Server {
                    self.zero_rtt_ticket_hash = match &self.tls_session {
                        TlsSessionHolder::Server(t) => t.zero_rtt_ticket_hash().map(|h| h.to_vec()),
                        TlsSessionHolder::Client(_) => None,
                    };
                }
            }
        }

        // TLS からデータと鍵を繰り返し取得する
        // rustls の write_hs は呼び出しごとに 1 つの暗号化レベルのデータと鍵変更を返す
        loop {
            let output = self.tls_write_hs();

            if !output.handshake_data.is_empty() {
                if self.one_rtt_keys.is_some() {
                    // 1-RTT 鍵導出後のデータはポストハンドシェイクメッセージ
                    // (NewSessionTicket 等) なので 1-RTT CRYPTO で送信する
                    self.crypto_send_1rtt
                        .extend_from_slice(&output.handshake_data);
                } else if self.handshake_keys.is_some() {
                    self.crypto_send_handshake
                        .extend_from_slice(&output.handshake_data);
                } else {
                    self.crypto_send_initial
                        .extend_from_slice(&output.handshake_data);
                }
            }

            let has_key_change = output.key_change.is_some();
            if let Some(kc) = output.key_change {
                match kc {
                    tls::KeyChange::Handshake { keys } => {
                        // RFC 9001 Section 4.1.3: 高い暗号化レベルの鍵が提供された
                        // 時点で、低い暗号化レベルの CRYPTO データが未消費
                        // (未充填のギャップとして残っている) なら
                        // PROTOCOL_VIOLATION とする (MUST)。
                        if !self.crypto_recv_initial.is_empty() {
                            return Err(Error::Protocol {
                                code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                                reason: "handshake keys provided before consuming all initial CRYPTO data"
                                    .into(),
                            });
                        }
                        self.handshake_keys = Some(RustlsLevelKeys {
                            local_packet: keys.local.packet,
                            local_header: keys.local.header,
                            remote_packet: Some(keys.remote.packet),
                            remote_header: keys.remote.header,
                        });
                        // qlog: ハンドシェイク鍵の導出
                        // (qlog-quic-events-13 Section 6.1、trigger は TLS 由来)
                        if self.qlog_writer.is_some() {
                            let time_ms = self.qlog_time_ms();
                            if let Some(ref mut w) = self.qlog_writer {
                                w.on_key_updated(time_ms, "handshake", None, "tls");
                            }
                        }
                        // Initial 鍵の廃棄は emit_packets 後に行う
                        // (送信待ちの Initial CRYPTO データがある可能性がある)
                    }
                    tls::KeyChange::OneRtt { keys, next_secrets } => {
                        // RFC 9001 Section 6.1: 現行鍵フェーズの ACK 追跡を開始する。
                        // このフェーズで送ったパケットの ACK を受けるまで、次の
                        // 鍵更新を開始してはならない (MUST NOT)。
                        self.begin_key_phase(false);
                        // RFC 9001 Section 4.1.3: 1-RTT 鍵の提供時点で Handshake
                        // レベルの CRYPTO データが未消費なら PROTOCOL_VIOLATION
                        // とする (MUST)。
                        if !self.crypto_recv_initial.is_empty()
                            || !self.crypto_recv_handshake.is_empty()
                        {
                            return Err(Error::Protocol {
                                code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                                reason:
                                    "1-RTT keys provided before consuming all handshake CRYPTO data"
                                        .into(),
                            });
                        }
                        self.next_secrets = Some(next_secrets);
                        self.one_rtt_keys = Some(RustlsLevelKeys {
                            local_packet: keys.local.packet,
                            local_header: keys.local.header,
                            remote_packet: Some(keys.remote.packet),
                            remote_header: keys.remote.header,
                        });
                        // qlog: 1-RTT 鍵の導出 (qlog-quic-events-13 Section 6.1)
                        if self.qlog_writer.is_some() {
                            let time_ms = self.qlog_time_ms();
                            if let Some(ref mut w) = self.qlog_writer {
                                w.on_key_updated(time_ms, "1rtt", Some(0), "tls");
                            }
                        }
                        // RFC 9001 Section 4.9.3: クライアントは 1-RTT 鍵導出後に
                        // 0-RTT 鍵を廃棄する (以降は 1-RTT で送信する)
                        if self.role == Role::Client {
                            self.zero_rtt_keys = None;
                        }
                        // サーバーの Connected 遷移はここでは行わない
                        // RFC 9001 Section 4.1.2: サーバーのハンドシェイクは
                        // クライアントの Finished を受信・検証した時点で完了する
                        // 1-RTT 鍵は ServerHello 生成後に利用可能になるが、
                        // HANDSHAKE_DONE 送信はハンドシェイク完了まで待つ必要がある
                        // (RFC 9000 Section 19.20)
                    }
                }
            }

            // データも鍵変更もなければ終了
            if output.handshake_data.is_empty() && !has_key_change {
                break;
            }
        }

        // サーバー: ハンドシェイク完了チェック (RFC 9001 Section 4.1.2)
        // 1-RTT 鍵が利用可能かつ TLS ハンドシェイクが完了した場合に Connected に遷移する
        // クライアントの Handshake Finished を受信・検証するまでは遷移しない
        if self.role == Role::Server
            && self.one_rtt_keys.is_some()
            && self.state == ConnectionState::Handshaking
        {
            let is_handshaking = match &self.tls_session {
                TlsSessionHolder::Client(_) => true,
                TlsSessionHolder::Server(t) => t.is_handshaking(),
            };
            if !is_handshaking {
                // qlog: 状態遷移 Handshaking → Connected
                if self.qlog_writer.is_some() {
                    let time_ms = self.qlog_time_ms();
                    if let Some(ref mut w) = self.qlog_writer {
                        w.on_connection_state_updated(time_ms, "handshaking", "connected");
                    }
                }
                self.state = ConnectionState::Connected;
                self.push_event(ConnectionEvent::Connected);
                self.handshake_confirmed_once = true;
                // アドレス検証完了: アンプリフィケーション制限を解除する
                self.address_validated = true;
                // ハンドシェイク中に送った PATH_CHALLENGE はピアが 1-RTT 鍵を
                // 持たず処理されないことがある。完了後に同じデータで再送する。
                self.resend_initial_challenge_after_handshake(now);
                // 移行や CID ローテーションに備えて初期パスの追加 CID を発行する
                // (RFC 9000 Section 5.1.1)
                self.issue_initial_cids();
                // Handshake 鍵を廃棄する (RFC 9001 Section 4.9.2)
                // サーバーのハンドシェイクはクライアントの Finished 受信で確認される
                // 確認後は Handshake パケットの送受信を行わない
                self.discard_handshake_keys();
                // DPLPMTUD を有効化する (RFC 8899)
                self.enable_dplpmtud();
                // keep-alive が有効なパスのタイマーを開始する
                self.arm_all_keep_alive_timers(now);
                // アイドルタイマーは次の receive() でリセットされる
            }
        }

        // ALPN プロトコルの保存
        if self.alpn_protocol.is_none() {
            let alpn = match &self.tls_session {
                TlsSessionHolder::Client(t) => t.alpn_protocol(),
                TlsSessionHolder::Server(t) => t.alpn_protocol(),
            };
            self.alpn_protocol = alpn.map(|a| a.to_vec());
        }

        // ピアのトランスポートパラメータ検証は receive() の末尾で行う。
        // advance_tls() は connect() からも呼ばれるが、その時点では
        // サーバーの SCID がまだ不明なため initial_source_connection_id の
        // 検証ができない (セッション再開時に rustls が前回のパラメータを返す場合)。
        Ok(())
    }

    /// ピアのトランスポートパラメータが今回の接続の実値として確定しているかを返す
    ///
    /// サーバーはクライアントの最初の Initial (ClientHello) を受信した時点で
    /// 実値が確定している。クライアントはセッション再開時に rustls が前回
    /// セッションで記憶した値を返すため、サーバーの EncryptedExtensions を
    /// 処理して 1-RTT 鍵が利用可能になるまで実値は確定しない。
    fn peer_transport_params_ready(&self) -> bool {
        match self.role {
            Role::Server => self.initial_recv_pn_largest.is_some(),
            Role::Client => self.one_rtt_keys.is_some() || self.state == ConnectionState::Connected,
        }
    }

    fn maybe_apply_peer_params(&mut self) -> Result<(), Error> {
        // 閉鎖中はピアパラメータを再評価しない。不正なピアパラメータで閉じた
        // 接続は確定に失敗したままなので、閉鎖猶予中の `flush` やストリーム系
        // API、タイマー処理から呼ばれるたびに同じ `Error::Protocol` を返すと、
        // CONNECTION_CLOSE の再送やアプリの後処理が打ち切られてしまう。
        // 閉鎖中はピアパラメータの適用自体が不要である。
        if matches!(
            self.state,
            ConnectionState::Closing | ConnectionState::Draining | ConnectionState::Closed
        ) {
            return Ok(());
        }
        // ハンドシェイクで受信した実ピアパラメータを既に確定済みなら何もしない。
        // `set_early_peer_params()` で `peer_params` を埋めただけの場合は、
        // この時点では未確定のため、TLS から実値が取得でき次第ここで処理する。
        if self.peer_params_finalized {
            return Ok(());
        }
        let tp = match &self.tls_session {
            TlsSessionHolder::Client(t) => t.peer_transport_params(),
            TlsSessionHolder::Server(t) => t.peer_transport_params(),
        };
        let Some(bytes) = tp else {
            return Ok(());
        };

        let params = TransportParams::decode(bytes)?;

        // RFC 9368 Section 4 / RFC 9369 Section 4: version_information を検証する。
        // 不整合は VERSION_NEGOTIATION_ERROR (0x11) で接続を閉じる。
        // サーバーはクライアントの最初の flight を Chosen Version で解析するため、
        // サーバー側の検証対象は接続バージョンではなく Chosen Version になる
        // (RFC 9368 Section 4: Chosen Version と最初の flight のバージョンの一致)。
        let first_flight_version = match self.role {
            Role::Server => self.compatible_client_version.unwrap_or(self.version),
            Role::Client => self.version,
        };
        tobi_core::connection::validate_peer_version_information(
            self.role,
            first_flight_version,
            self.vn_retry,
            self.local_params.version_information.as_ref(),
            params.version_information.as_ref(),
            &self.supported_versions,
        )?;

        // RFC 9368 Section 2.3: 互換バージョン交渉の選択はサーバーのルーターが
        // 最初の Initial を復号して決定論的に行い、接続はネゴシエート済み
        // バージョンで作られる。選択規則との齟齬があれば記録する。
        if self.role == Role::Server
            && let Some(version_information) = params.version_information.as_ref()
            && let Some(selected) = tobi_core::connection::select_server_negotiated_version(
                version_information,
                &self.supported_versions,
                &self.supported_versions,
            )
            && selected != self.version
        {
            tracing::warn!(
                "compatible version negotiation selected {:#010x} but connection uses {:#010x}",
                selected,
                self.version
            );
        }

        // クライアントはセッション再開時、rustls が EncryptedExtensions を処理する
        // 前に前回セッションで記憶したピアトランスポートパラメータを返す。
        // 記憶値は今回の接続の CID と一致しないため、実ハンドシェイクの値が
        // 確定するまで検証と適用を先送りする。Initial と Handshake の受信後に
        // receive() から再度呼ばれ、その時点で下の検証がまとめて実行される。
        if !self.peer_transport_params_ready() {
            return Ok(());
        }

        // RFC 9221 Section 3: 0-RTT で保存していた `max_datagram_frame_size` を
        // 新ハンドシェイクでサーバーが通知する値が下回ってはならない。
        // 違反時は PROTOCOL_VIOLATION で接続を終了しなければならない。
        if let Some(ref early) = self.early_peer_params {
            let early_mdfs = early.max_datagram_frame_size.unwrap_or(0);
            let new_mdfs = params.max_datagram_frame_size.unwrap_or(0);
            if new_mdfs < early_mdfs {
                return Err(Error::Protocol {
                    code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                    reason: format!(
                        "server reduced max_datagram_frame_size from {early_mdfs} (0-RTT saved) to {new_mdfs}"
                    ),
                });
            }
        }

        // draft-ietf-quic-address-discovery-01 Section 3: 0-RTT を受理した場合、
        // サーバーは address_discovery を無効化・値変更してはならない (MUST NOT)
        if let Some(ref early) = self.early_peer_params {
            let zero_rtt_accepted = matches!(
                &self.tls_session,
                TlsSessionHolder::Client(c) if c.is_early_data_accepted()
            );
            validate_address_discovery_unchanged(
                early.address_discovery,
                params.address_discovery,
                zero_rtt_accepted,
            )?;
        }

        // Multipath ネゴシエーション制約チェック
        // (RFC 10069 Section 2.1)
        if let Some(mp) = params.initial_max_path_id {
            // 非ゼロ長の CID が必須 (RFC 10069 Section 2.1)
            // "If an initial_max_path_id transport parameter is received and the
            //  carrying packet contains a zero-length connection ID, the receiver MUST
            //  treat this as a connection error of type PROTOCOL_VIOLATION"
            // DCID (= self.local_cid) と SCID (= self.peer_cid) の両方を検査する。
            if self.local_cid.is_empty() {
                return Err(Error::Protocol {
                    code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                    reason: "initial_max_path_id requires non-zero-length local CID".into(),
                });
            }
            if self.peer_cid.is_empty() {
                return Err(Error::Protocol {
                    code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                    reason: "initial_max_path_id requires non-zero-length peer CID".into(),
                });
            }
            // initial_source_connection_id が送られている場合、それが空 CID なら
            // 同様に PROTOCOL_VIOLATION。multipath 有効下で空 CID は禁止される。
            if let Some(ref peer_scid) = params.initial_source_connection_id
                && peer_scid.is_empty()
            {
                return Err(Error::Protocol {
                    code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                    reason: "initial_max_path_id forbids empty initial_source_connection_id".into(),
                });
            }
            self.paths.remote_max_path_id = mp;
            self.peer_initial_max_path_id = mp;
        }

        // Multipath は両端が提示した場合のみ有効
        let multipath_enabled =
            params.initial_max_path_id.is_some() && self.local_params.initial_max_path_id.is_some();
        if !multipath_enabled {
            // Multipath 無効: パス制限をリセット
            self.paths.remote_max_path_id = 0;
            self.paths.local_max_path_id = 0;
        }

        // RFC 10069 Section 2.1:
        // nonce が 12 バイト未満の cipher suite が選択され、かつ multipath 拡張が
        // 使用される場合、エンドポイントは TRANSPORT_PARAMETER_ERROR でハンドシェイクを
        // 中断しなければならない (MUST)。
        if multipath_enabled {
            let nonce_len = match &self.tls_session {
                TlsSessionHolder::Client(t) => t.aead_nonce_len(),
                TlsSessionHolder::Server(t) => t.aead_nonce_len(),
            };
            // Some(len) が 12 以上なら OK。None (未知の suite) または Some(len<12) は拒否する。
            let ok = nonce_len.is_some_and(|len| len >= 12);
            if !ok {
                return Err(Error::Protocol {
                    code: tobi_core::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                    reason: format!(
                        "cipher suite AEAD nonce length {:?} < 12 is incompatible with multipath extension",
                        nonce_len
                    ),
                });
            }
        }

        // 接続 ID の認証とロール固有のトランスポートパラメータ検証
        // (RFC 9000 Section 7.3 / Section 18.2)
        //
        // - クライアント: サーバーの original_destination_connection_id /
        //   initial_source_connection_id / retry_source_connection_id を検証する。
        // - サーバー: クライアントの initial_source_connection_id を検証し、
        //   サーバー専用パラメータの送信を拒否する。
        match self.role {
            Role::Client => {
                let server_initial_scid = self.server_initial_scid.as_ref().ok_or_else(|| {
                    // 到達しない想定 (クライアントの TP 確定は 1-RTT 鍵導出後で、
                    // その時点でサーバーの Initial は受信済み)。到達した場合は
                    // 接続を閉じるべきエラーとして扱う。
                    Error::Protocol {
                        code: tobi_core::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                        reason: "server initial packet must be received before validating transport parameters"
                            .into(),
                    }
                })?;
                validate_server_transport_params(
                    &params,
                    &self.original_dcid,
                    server_initial_scid,
                    self.retry_scid.as_ref(),
                )?;
            }
            Role::Server => {
                let peer_initial_scid = self.peer_initial_scid.as_ref().ok_or_else(|| {
                    // 到達しない想定 (サーバーの TP 確定は最初の Initial 受信後)。
                    // 到達した場合は接続を閉じるべきエラーとして扱う。
                    Error::Protocol {
                        code: tobi_core::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                        reason: "client initial packet must be received before validating transport parameters"
                            .into(),
                    }
                })?;
                validate_client_transport_params(&params, peer_initial_scid)?;
            }
        }

        self.streams.apply_peer_params(&params);

        // draft-ietf-quic-reliable-stream-reset-11 Section 3:
        // ピアが広告していない場合は RESET_STREAM_AT を送ってはならない (MUST NOT)。
        // 0-RTT では前回セッションの広告を記憶してキューするため、確定した
        // 今回の transport parameter に合わせて RESET_STREAM へ降格する。
        if !params.reset_stream_at {
            let demoted = self.streams.demote_unsupported_reset_stream_at();
            if demoted > 0 {
                tracing::warn!(
                    "peer did not advertise reset_stream_at; downgraded {demoted} pending RESET_STREAM_AT frame(s) to RESET_STREAM"
                );
            }
        }

        // RFC 9000 Section 5.1.1: ピアの初期 CID のシーケンス番号は 0 である。
        // stateless_reset_token を持たない場合も、Retire Prior To による退役を
        // 追跡できるように登録する。トークンはサーバーが
        // stateless_reset_token トランスポートパラメータを通知した場合だけ存在し、
        // クライアントはこのパラメータを送信できない (RFC 9000 Section 18.2)。
        //
        // 1-RTT の NEW_CONNECTION_ID が coalesced packet で先に処理された場合、
        // この時点で既に最大 Retire Prior To が確定していることがある。
        // その場合 `register_peer_cid` は CID を有効化せず RETIRE_CONNECTION_ID を
        // 積むため、ここで最大値と比較してから登録する必要がある。
        let peer_initial_cid = match self.role {
            Role::Client => self.server_initial_scid.clone(),
            Role::Server => self.peer_initial_scid.clone(),
        };
        if let Some(handshake_cid) = peer_initial_cid {
            let token = match self.role {
                Role::Client => params.stateless_reset_token,
                // クライアントは stateless_reset_token を送信できない
                Role::Server => None,
            };
            match self.register_peer_cid(PathId::INITIAL, 0, handshake_cid.clone(), token)? {
                PeerCidRegistration::Registered => {
                    // RFC 9000 Section 9.5: 初期 CID はハンドシェイクで使用済みである。
                    // migration の候補に初期 CID を選ばないよう使用済みにする。
                    let target = self
                        .paths
                        .get(PathId::INITIAL)
                        .map(|path| (path.remote_addr, path.local_addr));
                    self.record_peer_cid_used_at(PathId::INITIAL, &handshake_cid, target);
                }
                PeerCidRegistration::Retired => {}
                PeerCidRegistration::Reused => {
                    return Err(Error::Protocol {
                        code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                        reason: "initial connection ID collides with an existing connection ID"
                            .into(),
                    });
                }
            }
        }

        // RFC 9000 Section 5.1.1 / 18.2: サーバーが preferred_address を
        // advertise した場合、その CID は sequence number 1 の利用可能 CID として
        // 登録しなければならない。
        // RFC 10069 Section 2.2 により Multipath 有効時も
        // preferred_address の CID は path ID 0 に属する (追加パスではない)。
        //
        // クライアントだけがこの処理を行う (サーバーは advertise 側)。
        if self.role == Role::Client
            && let Some(ref pa) = params.preferred_address
        {
            match self.register_peer_cid(
                PathId::INITIAL,
                1,
                pa.connection_id.clone(),
                Some(pa.stateless_reset_token),
            )? {
                // preferred_address の CID は移行に使うまで未使用のままにする
                PeerCidRegistration::Registered | PeerCidRegistration::Retired => {}
                PeerCidRegistration::Reused => {
                    return Err(Error::Protocol {
                        code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                        reason:
                            "preferred_address connection ID collides with an existing connection ID"
                                .into(),
                    });
                }
            }
        }

        // RFC 9000 Section 5.1.1 / 18.2: active_connection_id_limit は
        // ハンドシェイクの CID と preferred_address の CID も数に含める。
        // 初期 CID の登録後に上限を検査する。
        self.enforce_peer_cid_limit(PathId::INITIAL)?;

        // アイドルタイムアウトのネゴシエーション (RFC 9000 Section 10.1)
        // 両者の max_idle_timeout の小さい方を使用する (0 は無効)
        let local_idle = self.local_params.max_idle_timeout;
        let peer_idle = params.max_idle_timeout;
        self.idle_timeout_ms = match (local_idle, peer_idle) {
            (0, 0) => 0,
            (0, p) => p,
            (l, 0) => l,
            (l, p) => l.min(p),
        };

        // qlog: parameters_set (ピア)
        if self.qlog_writer.is_some() {
            let time_ms = self.qlog_time_ms();
            let qlog_params = qlog::TransportParametersSet {
                max_idle_timeout: params.max_idle_timeout,
                max_udp_payload_size: params.max_udp_payload_size,
                initial_max_data: params.initial_max_data,
                initial_max_stream_data_bidi_local: params.initial_max_stream_data_bidi_local,
                initial_max_stream_data_bidi_remote: params.initial_max_stream_data_bidi_remote,
                initial_max_stream_data_uni: params.initial_max_stream_data_uni,
                initial_max_streams_bidi: params.initial_max_streams_bidi,
                initial_max_streams_uni: params.initial_max_streams_uni,
                active_connection_id_limit: params.active_connection_id_limit,
                initial_max_path_id: params.initial_max_path_id,
            };
            if let Some(ref mut w) = self.qlog_writer {
                w.on_parameters_set(time_ms, "remote", &qlog_params);
            }
        }

        // RFC 9287 Section 3.1: 現在の接続でピアが広告した場合のみ
        // QUIC Bit 0 の送信を許可する。
        self.peer_grease_quic_bit = Some(params.grease_quic_bit);

        // draft-ietf-quic-receive-ts-03 Section 6:
        // max_receive_timestamps_per_ack が存在しない、または 0 の場合は
        // 拡張非サポートとして扱う。0-RTT で記憶した値は使わず、今回の
        // ハンドシェイクで確定したパラメータだけを反映する。
        self.peer_receive_timestamps = match params.max_receive_timestamps_per_ack.unwrap_or(0) {
            0 => None,
            max_per_ack => Some(PeerReceiveTimestamps {
                max_per_ack,
                exponent: params.receive_timestamps_exponent.unwrap_or(0).min(20) as u32,
            }),
        };
        // RFC 9000 Section 18.2: ピアの max_udp_payload_size を超える
        // データグラムを送らないよう、DPLPMTUD と現在の MTU を制限する。
        let peer_max_udp_payload_size = params.max_udp_payload_size;
        self.peer_params = Some(params);
        self.peer_params_finalized = true;
        self.apply_peer_max_udp_payload_size(peer_max_udp_payload_size);

        // coalesced packet で 1-RTT の NEW_CONNECTION_ID が先に処理され、
        // 初期 CID が Retire Prior To の対象になっている場合は、確定後の
        // 時点で送信先 CID を選び直す。確定前は初期 CID が未登録のため
        // 選び直しを保留している。
        self.select_peer_cid_after_retire(PathId::INITIAL)?;

        // remote_max_path_id が確定したのでプロアクティブ CID を発行する
        // (RFC 10069 Section 3.2.1 RECOMMENDED)
        self.issue_proactive_cids();
        Ok(())
    }

    fn tls_read_hs(&mut self, data: &[u8]) -> Result<(), Error> {
        match &mut self.tls_session {
            TlsSessionHolder::Client(t) => t.read_handshake(data),
            TlsSessionHolder::Server(t) => t.read_handshake(data),
        }
    }

    /// TLS セッションの致命的エラーを CRYPTO_ERROR で接続クローズする
    ///
    /// RFC 9001 Section 4.8: TLS アラートは `0x100 + AlertDescription` の
    /// CRYPTO_ERROR として CONNECTION_CLOSE に載せる。rustls がアラートを
    /// 記録していない場合 (fatal alert を伴わないエラー) は、同節が許容する
    /// handshake_failure (0x28) を使う。
    fn close_on_tls_error(&mut self, err: Error, now: Timestamp) -> Result<(), Error> {
        let alert = match &self.tls_session {
            TlsSessionHolder::Client(t) => t.alert(),
            TlsSessionHolder::Server(s) => s.alert(),
        };
        let alert_code =
            u8::from(alert.unwrap_or(tobi_rustls::rustls::AlertDescription::HandshakeFailure));
        let error_code = tobi_core::error::TransportErrorCode::crypto_error(alert_code).as_u64();
        let reason = format!("TLS handshake failed: {err}");
        self.close(error_code, reason.as_bytes(), now)
    }

    /// 復号済みのパケットを処理できずに破棄した理由を統計と qlog に記録する
    ///
    /// qlog-quic-events-13 Section 5.7 の QUICPacketDropped に対応する。
    /// パケットのヘッダは解析に失敗している可能性があるため記録せず、
    /// 破棄理由のカテゴリとエラー内容だけを残す。無言で捨てると、双方が
    /// 停止したときの原因を追えなくなる。
    ///
    /// qlog writer の有無に関係なく `ConnectionStats` のカウンタを更新する。
    /// qlog への記録は writer がある場合だけ行う。
    fn record_dropped_packet(&mut self, err: &Error) {
        let trigger = match err {
            Error::InvalidData(message) if message.contains("decryption") => "decryption_failure",
            Error::InvalidData(_) | Error::Incomplete { .. } => "invalid",
            // StreamLimitReached はアプリケーションが open を呼んだときにだけ
            // 返り、パケット処理では発生しない。この関数はパケット処理の
            // エラーだけを記録するため、この腕は到達しない。それでも
            // 「一般エラー」の腕に含めるのは、`Error` に variant が増えたときに
            // コンパイルエラーとして気づけるよう網羅性を保つためである。
            Error::Protocol { .. } | Error::StreamLimitReached { .. } => "general",
        };
        match trigger {
            "decryption_failure" => self.stats.record_packet_dropped_decryption_failure(),
            "invalid" => self.stats.record_packet_dropped_invalid(),
            _ => self.stats.record_packet_dropped_general(),
        }
        if self.qlog_writer.is_none() {
            return;
        }
        let time_ms = self.qlog_time_ms();
        let details = format!("{err}");
        if let Some(ref mut w) = self.qlog_writer {
            w.on_packet_dropped(time_ms, trigger, Some(&details));
        }
    }

    fn tls_write_hs(&mut self) -> tls::TlsOutput {
        match &mut self.tls_session {
            TlsSessionHolder::Client(t) => t.write_handshake(),
            TlsSessionHolder::Server(t) => t.write_handshake(),
        }
    }

    /// StreamManager のイベントを ConnectionEvent に変換してキューに入れる
    fn drain_stream_events(&mut self) {
        while let Some(evt) = self.streams.poll_event() {
            let conn_evt = match evt {
                StreamEvent::NewStream { stream_id } => ConnectionEvent::NewStream { stream_id },
                StreamEvent::StreamReadable { stream_id } => {
                    ConnectionEvent::StreamReadable { stream_id }
                }
                StreamEvent::StreamWritable { stream_id } => {
                    ConnectionEvent::StreamWritable { stream_id }
                }
                StreamEvent::StreamReset {
                    stream_id,
                    error_code,
                } => ConnectionEvent::StreamReset {
                    stream_id,
                    error_code,
                },
                StreamEvent::StreamStopSending {
                    stream_id,
                    error_code,
                } => ConnectionEvent::StreamStopSending {
                    stream_id,
                    error_code,
                },
            };
            self.push_event(conn_evt);
        }
    }

    /// アイドルタイマーをリセットする (RFC 9000 Section 10.1)
    ///
    /// タイムアウト値は max(アイドルタイムアウト, 3 × 初期パスの実効 PTO) を
    /// 使用する。
    fn reset_idle_timer(&mut self, now: Timestamp) {
        if self.idle_timeout_ms == 0 {
            return;
        }
        let idle_duration = tobi_core::time::Duration::from_millis(self.idle_timeout_ms);
        // 3 * PTO を計算する。RFC 9000 Section 10.1 は current PTO とだけ規定し、
        // multipath でのパスの選び方は指定しない。既存実装に合わせて初期パスの
        // RTT を基準にする。別パスにより大きい PTO がある場合、この Idle 期限は
        // そのパスの 3 PTO を下回り得る。Closing / Draining と鍵関連期限は
        // 接続全体の最大 PTO を使う (RFC 10069 Section 2.6) が、
        // Idle は RFC 10069 でもパスの選び方を規定していない。
        let three_pto = self.lifecycle_pto_for_path(PathId::INITIAL).mul(3);
        let timeout = if idle_duration > three_pto {
            idle_duration
        } else {
            three_pto
        };
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::Idle,
            deadline: now + timeout,
        });
        // keep-alive はパス単位の `TimerId::KeepAlive` が担当するため、
        // ここでは設定しない。ハンドシェイク完了時と設定変更時に
        // `Connection::arm_all_keep_alive_timers` が設定する。
    }

    /// ロストした CRYPTO データを元の暗号化レベルで再送キューに追加する
    ///
    /// 1-RTT では再送ポリシーへ `FrameClass::Crypto` で問い合わせ、`Duplicate`
    /// が選ばれた場合は代替パスへ複製を通常送信待ちとして積む。複製は再送追跡
    /// の対象にしない (冗長コピーの損失で再送を繰り返さない)。
    ///
    /// RFC 9001 Section 4.9: CRYPTO データを再送するフレームは、最初に送信
    /// したときと同じ暗号化レベルで送らなければならない。呼び出し元はロスト
    /// したパケットが属していた暗号化レベルを渡す。オフセットだけでレベルを
    /// 推測すると、各レベルのオフセット空間は独立しているため取り違える。
    ///
    /// すべての暗号化レベルで元のオフセットを保つ。Initial は専用の再送待ち
    /// キューへ積み、PTO の全体再送では初回フライトを先頭から送り直すため
    /// キューを破棄する。
    fn retransmit_crypto(
        &mut self,
        level: EncryptionLevel,
        offset: u64,
        length: usize,
        retx_meta: RetxMeta,
        now: Timestamp,
    ) {
        let Ok(off) = usize::try_from(offset) else {
            return;
        };
        let Some(end) = off.checked_add(length) else {
            return;
        };

        match level {
            EncryptionLevel::Initial => {
                // Initial レベルの CRYPTO データを元のオフセットで再送する。
                // 新規データの送信バッファとは別の再送待ちキューに入れ、
                // 同じ offset と長さの範囲を重ねて積まない (RFC 9001 Section 4.9)。
                if end <= self.crypto_sent_initial.len() && self.initial_keys.is_some() {
                    let already_queued = self.crypto_retransmit_initial.iter().any(
                        |(queued_offset, queued_data)| {
                            *queued_offset == offset && queued_data.len() == length
                        },
                    );
                    if !already_queued {
                        let data = self.crypto_sent_initial[off..end].to_vec();
                        self.crypto_retransmit_initial.push_back((offset, data));
                    }
                }
            }
            EncryptionLevel::Handshake => {
                // Handshake レベルの CRYPTO データを再送する。新規送信データの
                // 末尾へ追加すると offset がずれてしまうため、元の offset を
                // 持つ再送待ちキューへ積む (RFC 9001 Section 4.9)。
                if end <= self.crypto_sent_handshake.len() && self.handshake_keys.is_some() {
                    let data = self.crypto_sent_handshake[off..end].to_vec();
                    self.queue_handshake_crypto_retransmit(offset, data);
                }
            }
            EncryptionLevel::OneRtt => {
                // 1-RTT レベルの CRYPTO データを元のオフセットで再送する。
                // 新規データの送信バッファとは別の再送待ちキューに入れる。
                // 同じ範囲が PTO と ACK 由来の損失検出で重ねて報告されても
                // 二重に送らないよう、キュー内の同一範囲は追加しない。
                // Handshake の再送キューは包含関係で重複排除しており
                // (`queue_handshake_crypto_retransmit`)、ここは完全一致のみの
                // 抑止である。重複 CRYPTO はプロトコル上許容される。
                if end <= self.crypto_sent_1rtt.len() && self.one_rtt_keys.is_some() {
                    let already_queued =
                        self.crypto_retransmit_1rtt
                            .iter()
                            .any(|(queued_offset, queued_data)| {
                                *queued_offset == offset && queued_data.len() == length
                            });
                    if !already_queued {
                        let data = self.crypto_sent_1rtt[off..end].to_vec();
                        // Duplicate の複製は通常の送信待ちとして代替パスへ積む。
                        // 元の再送は通常の再送キューで管理し、パス選択に任せる。
                        if let Some(duplicate_path) = self.crypto_duplicate_path(
                            retx_meta.original_path,
                            retx_meta.loss_reason,
                            retx_meta.retransmission_count,
                        ) {
                            let duplicate = Frame::Crypto(frame::crypto::Crypto {
                                offset: VarInt::new(offset).expect("value fits in 62-bit varint"),
                                data: data.clone(),
                            });
                            let _ = self.emit_1rtt_single_frame(duplicate_path, duplicate, now);
                        }
                        self.crypto_retransmit_1rtt.push_back((offset, data));
                    }
                }
            }
            // 0-RTT の CRYPTO は存在しない (RFC 9000 Section 12.4 Table 3)。
            EncryptionLevel::ZeroRtt => {}
        }
    }

    /// 1-RTT CRYPTO の複製再送先を再送ポリシーで決める
    ///
    /// ロストした CRYPTO の元パスと再送候補パスを `FrameClass::Crypto` で
    /// ポリシーへ渡す。`Duplicate` のときだけ代替パスを返す。それ以外は
    /// 通常の送信パス選択に任せる (CRYPTO の再送を失わないことを優先する)。
    /// 損失理由は呼び出し元から受け取る。
    fn crypto_duplicate_path(
        &mut self,
        original_path: PathId,
        loss_reason: LossReason,
        retransmission_count: u32,
    ) -> Option<PathId> {
        let metrics = self.paths.collect_metrics();
        let candidates: Vec<PathId> = metrics
            .iter()
            .filter(|path| path.is_usable)
            .map(|path| path.path_id)
            .collect();
        let ctx = RetxCtx {
            paths: &metrics,
            loss_reason,
            frame_class: FrameClass::Crypto,
            retransmission_count,
        };
        match self
            .scheduler
            .retx
            .decide_retx(&ctx, original_path, &candidates)
        {
            RetxDecision::Duplicate(path_id) => Some(path_id),
            RetxDecision::SamePath | RetxDecision::CrossPath(_) | RetxDecision::Defer => None,
        }
    }

    /// Handshake レベルの CRYPTO 再送範囲を再送待ちキューへ追加する
    ///
    /// 同じ範囲を重ねて積まない。既にキューの範囲に完全に含まれる場合は
    /// 追加せず、新しい範囲がキューの範囲を完全に含む場合は置き換える。
    /// PTO と ACK 駆動の損失検出が同じ範囲を重ねて報告しても、再送データが
    /// 無制限に増えないようにするためである。部分的に重なる範囲は、再送
    /// データの重複を許容してそのまま積む (重複した CRYPTO データは
    /// プロトコル上問題ない)。
    fn queue_handshake_crypto_retransmit(&mut self, offset: u64, data: Vec<u8>) {
        let end = offset.saturating_add(data.len() as u64);
        // 既存の範囲に完全に含まれるなら追加不要
        if self
            .crypto_retransmit_handshake
            .iter()
            .any(|(queued_offset, queued_data)| {
                let queued_end = queued_offset.saturating_add(queued_data.len() as u64);
                *queued_offset <= offset && end <= queued_end
            })
        {
            return;
        }
        // 新しい範囲が完全に含む既存の範囲は取り除く
        self.crypto_retransmit_handshake
            .retain(|(queued_offset, queued_data)| {
                let queued_end = queued_offset.saturating_add(queued_data.len() as u64);
                !(offset <= *queued_offset && queued_end <= end)
            });
        self.crypto_retransmit_handshake.push_back((offset, data));
    }

    /// 廃棄パスで失われたパケットのフレームを既存の再送経路へ振り分ける
    ///
    /// RFC 10069 Section 3.4.3: パス状態を削除した時点で
    /// 未確認のパケットは lost とみなさなければならない (MUST)。本実装は
    /// Abandoning / Abandoned へ遷移した時点で `sent_packets` を drain し、
    /// 種別ごとの再送判断にかける (MUST の時点より早い処理であり、仕様に
    /// 反しない)。
    ///
    /// 呼び出し時点で `original_path` は既に Abandoning / Abandoned へ遷移し、
    /// tombstone が登録されていること。この前提により、フレームが指すパスの
    /// 再送抑止 (`is_path_abandoned`) と、PATH_ABANDON の再送先選択
    /// (`select_alt_path`) が廃棄対象のパスを避ける。
    ///
    /// 再送内容は RFC 9000 Section 13.3 と multipath 拡張の各節に従う。
    ///
    /// - STREAM は `StreamManager::mark_lost` に渡す。
    /// - RESET_STREAM / RESET_STREAM_AT / MAX_DATA / MAX_STREAM_DATA /
    ///   MAX_STREAMS / DATA_BLOCKED / STREAM_DATA_BLOCKED / STREAMS_BLOCKED /
    ///   STOP_SENDING / NEW_CONNECTION_ID / NEW_TOKEN /
    ///   HANDSHAKE_DONE / RETIRE_CONNECTION_ID / PATH_STATUS / PATHS_BLOCKED /
    ///   PATH_CIDS_BLOCKED / OBSERVED_ADDRESS は
    ///   `retransmit_lost_control_frames` に渡し、既存の再送判断を再利用する。
    ///   BLOCKED 系は送信時の値ではなく、再送時点の現在値を含む新しいフレームを
    ///   まだブロック中の場合だけ送る (RFC 9000 Section 13.3)。
    /// - PATH_ABANDON / MAX_PATH_ID は `retransmit_lost_multipath_frames` に渡す。
    /// - ACK / PATH_ACK / ACK_FREQUENCY / DATAGRAM / PING / PADDING /
    ///   PATH_CHALLENGE / PATH_RESPONSE / CONNECTION_CLOSE と 1-RTT CRYPTO は
    ///   再送しない。
    ///
    /// フレームが指すパスが廃棄済みの場合は、制御フレーム側の再送判断
    /// (`retransmit_lost_control_frames`) が送信を見送る。
    fn recover_lost_frames_on_abandoned_path(
        &mut self,
        lost_packets: Vec<SentPacket>,
        original_path: PathId,
        now: Timestamp,
    ) {
        debug_assert!(
            self.is_path_abandoned(original_path),
            "the abandoned path must be marked before recovering its frames"
        );
        // パス廃棄で強制的にロスト扱いにする。元パスは利用できなくなるため、
        // 再送パス選択ポリシーは別パスを選ぶことになる。
        // ロスト理由はパケット閾値・時間閾値のどちらでもないが、再送パス選択
        // では元パスの可用性が支配的なため TimeThreshold として渡す。
        let meta = RetxMeta {
            original_path,
            loss_reason: LossReason::TimeThreshold,
            retransmission_count: 0,
        };
        let mut control_frames: Vec<SentFrameInfo> = Vec::new();
        let mut lost_path_abandons: Vec<(u32, u64)> = Vec::new();
        let mut lost_max_path_id = false;
        let mut stream_ids: Vec<u64> = Vec::new();
        for packet in lost_packets {
            for frame in packet.frames {
                match frame {
                    SentFrameInfo::Stream {
                        stream_id,
                        offset,
                        length,
                        fin,
                        retransmission_count,
                    } => {
                        stream_ids.push(stream_id);
                        self.streams.mark_lost(
                            stream_id,
                            offset,
                            length,
                            fin,
                            RetxMeta {
                                retransmission_count,
                                ..meta
                            },
                        );
                    }
                    SentFrameInfo::PathAbandon {
                        path_id,
                        error_code,
                    } => {
                        lost_path_abandons.push((path_id, error_code));
                    }
                    SentFrameInfo::MaxPathId { .. } => {
                        lost_max_path_id = true;
                    }
                    SentFrameInfo::ResetStream { stream_id, .. }
                    | SentFrameInfo::ResetStreamAt { stream_id, .. } => {
                        stream_ids.push(stream_id);
                        control_frames.push(frame);
                    }
                    // ACK_FREQUENCY は再送しないが、ACK が返らないパケットの
                    // 要求値を PTO 計算へ残さないよう in-flight から除く。
                    SentFrameInfo::AckFrequency {
                        sequence_number, ..
                    } => {
                        self.ack_frequency_in_flight
                            .retain(|(seq, _)| *seq != sequence_number);
                    }
                    SentFrameInfo::MaxData
                    | SentFrameInfo::MaxStreamData { .. }
                    | SentFrameInfo::MaxStreams { .. }
                    | SentFrameInfo::DataBlocked
                    | SentFrameInfo::StreamDataBlocked { .. }
                    | SentFrameInfo::StreamsBlocked { .. }
                    | SentFrameInfo::StopSending { .. }
                    | SentFrameInfo::NewConnectionId { .. }
                    | SentFrameInfo::NewToken { .. }
                    | SentFrameInfo::HandshakeDone
                    | SentFrameInfo::RetireConnectionId { .. }
                    | SentFrameInfo::PathStatus { .. }
                    | SentFrameInfo::PathsBlocked { .. }
                    | SentFrameInfo::PathCidsBlocked { .. }
                    | SentFrameInfo::ObservedAddress { .. } => {
                        control_frames.push(frame);
                    }
                    // 再送しないフレーム。DATAGRAM / PING / PADDING /
                    // PATH_CHALLENGE / PATH_RESPONSE / CONNECTION_CLOSE は
                    // Other に、1-RTT CRYPTO は Crypto に入る。
                    SentFrameInfo::Ack { .. }
                    | SentFrameInfo::PathAck
                    | SentFrameInfo::Crypto { .. }
                    | SentFrameInfo::Other => {}
                }
            }
        }
        self.retransmit_lost_control_frames(control_frames, now);
        // 回復は best-effort である。再送先の emit に失敗しても、呼び出し元の
        // 統計・輻輳・タイマー・close の後始末は続行する。
        if let Err(error) =
            self.retransmit_lost_multipath_frames(lost_path_abandons, lost_max_path_id, now)
        {
            tracing::debug!(
                path_id = original_path.0,
                "failed to retransmit multipath frames from abandoned path: {error}"
            );
        }
        // 再送キューへの復元が終わったストリームは、ACK 済み範囲しか
        // 残っていない場合に終端状態へ遷移できる
        // (RFC 9000 Section 3.1, Section 13.3)。
        for stream_id in stream_ids {
            self.streams.try_transition_send_terminal(stream_id);
        }
    }

    /// ロストした multipath 制御フレームを再送キューへ戻す
    ///
    /// ACK 駆動のロスト判定と時間閾値のロスト判定で共通に使う。両経路で
    /// 再送条件がずれないよう、分類済みの値を受け取って再送だけを行う。
    /// PATH_STATUS は再送条件の判定を `retransmit_lost_control_frames` と
    /// 共通にするため、この関数では扱わない。
    ///
    /// - PATH_ABANDON: 別の使用可能なパスがある場合だけ、同じ内容を再送する
    ///   (RFC 10069 Section 4.2 の SHOULD)。廃棄対象の
    ///   パスでは、PATH_ABANDON を送ったあとに送信できないため、そのパスを
    ///   送信先にしない。使用可能な別パスが無ければ再送しない
    ///   (同 Section 3.4)。
    /// - MAX_PATH_ID: ロストを検出した時点の `local_max_path_id` を再送する
    ///   (同 Section 4.6 の SHOULD)。同節は「より新しい MAX_PATH_ID を送って
    ///   いない場合」に限るが、本実装は送信済みの最新値の追跡を持たないため、
    ///   ロスト検出時に現在値を送る。値が増えない MAX_PATH_ID はピアが無視する
    ///   ため、仕様に反する状態にはならない。
    fn retransmit_lost_multipath_frames(
        &mut self,
        lost_path_abandons: Vec<(u32, u64)>,
        lost_max_path_id: bool,
        now: Timestamp,
    ) -> Result<(), Error> {
        for (pa_path_id, error_code) in lost_path_abandons {
            // 廃棄対象パスでは再送しない。対象 path ID は送信先の制約ではないため、
            // 廃棄対象以外の使用可能なパスから送る。
            let Some(send_path) = self.paths.select_alt_path(PathId(pa_path_id)) else {
                continue;
            };
            self.emit_1rtt_single_frame(
                send_path,
                Frame::PathAbandon(frame::path_abandon::PathAbandon {
                    path_id: pa_path_id,
                    error_code: VarInt::new(error_code).expect("value fits in 62-bit varint"),
                }),
                now,
            )?;
        }
        // MAX_PATH_ID はロスト検出時点の最新値を再送する (RFC 10069 Section 4.6)。
        if lost_max_path_id && let Some(send_path) = self.paths.select_open_path() {
            let current = self.paths.local_max_path_id;
            self.emit_1rtt_single_frame(
                send_path,
                Frame::MaxPathId(frame::max_path_id::MaxPathId {
                    maximum_path_id: current,
                }),
                now,
            )?;
        }
        Ok(())
    }

    /// ロスト制御フレームを pending_frames に再キューする
    ///
    /// RFC 9000 Section 13.3 と multipath 拡張に基づき、フレームタイプごとに
    /// 再送方式が異なる:
    /// - MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS: 最新の値で再送
    /// - DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED: まだブロック中なら
    ///   再送時点の現在値で再送 (RFC 9000 Section 13.3)
    /// - RESET_STREAM, STOP_SENDING, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID,
    ///   NEW_TOKEN, HANDSHAKE_DONE: 同一値で再送
    /// - RESET_STREAM_AT: 現在の最小 Reliable Size で再送
    /// - PATH_STATUS: そのパスについて最後に送った状態のみ、同じシーケンス番号で
    ///   再送 (RFC 10069 Section 4.3)
    /// - PATHS_BLOCKED, PATH_CIDS_BLOCKED: まだブロック中なら再送
    ///   (RFC 10069 Section 4.7)
    /// - OBSERVED_ADDRESS: 元のパスへ同一内容で再送
    ///   (draft-ietf-quic-address-discovery-01 Section 4.1)
    /// - NEW_CONNECTION_ID / PATH_NEW_CONNECTION_ID / PATH_CIDS_BLOCKED /
    ///   OBSERVED_ADDRESS は、フレームが指すパスが廃棄済み・廃棄中の場合は
    ///   再送しない。NEW_CONNECTION_ID は初期パス専用であるため、初期パスを
    ///   廃棄した場合も再送しない (RFC 10069 Section 3.4)。
    ///   OBSERVED_ADDRESS は別パスへ移さない。
    fn retransmit_lost_control_frames(&mut self, lost_frames: Vec<SentFrameInfo>, now: Timestamp) {
        for fi in lost_frames {
            match fi {
                SentFrameInfo::MaxData => {
                    let max_data = self.streams.recv_max_data();
                    self.streams.pending_frames.push_back(Frame::MaxData(
                        frame::max_data::MaxData {
                            maximum_data: VarInt::new(max_data)
                                .expect("value fits in 62-bit varint"),
                        },
                    ));
                }
                SentFrameInfo::MaxStreamData { stream_id } => {
                    if let Some(max_data) = self.streams.recv_max_stream_data(stream_id) {
                        self.streams.pending_frames.push_back(Frame::MaxStreamData(
                            frame::max_stream_data::MaxStreamData {
                                stream_id: VarInt::new(stream_id)
                                    .expect("value fits in 62-bit varint"),
                                maximum_stream_data: VarInt::new(max_data)
                                    .expect("value fits in 62-bit varint"),
                            },
                        ));
                    }
                }
                SentFrameInfo::MaxStreams { is_bidi } => {
                    let max_streams = if is_bidi {
                        self.streams.local_max_streams_bidi()
                    } else {
                        self.streams.local_max_streams_uni()
                    };
                    self.streams.pending_frames.push_back(Frame::MaxStreams(
                        frame::max_streams::MaxStreams {
                            bidirectional: is_bidi,
                            maximum_streams: VarInt::new(max_streams)
                                .expect("value fits in 62-bit varint"),
                        },
                    ));
                }
                SentFrameInfo::DataBlocked => {
                    // RFC 9000 Section 13.3: まだブロック中なら現在の上限で再送する
                    self.streams.requeue_data_blocked();
                }
                SentFrameInfo::StreamDataBlocked { stream_id } => {
                    // RFC 9000 Section 13.3: 対象ストリームがまだブロック中なら
                    // 現在の上限で再送する
                    self.streams.requeue_stream_data_blocked(stream_id);
                }
                SentFrameInfo::StreamsBlocked { bidirectional } => {
                    // RFC 9000 Section 13.3: 残枠が無ければ現在の許可数で再送する
                    self.streams.requeue_streams_blocked(bidirectional);
                }
                SentFrameInfo::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                } => {
                    // RFC 9000 Section 3.3: 終端状態 (Data Recvd / Reset Recvd)
                    // からは RESET_STREAM を送信してはならない (MUST NOT)。
                    // 複製の ACK で先に終端した後、元パケットのロスト判定が
                    // 遅れて届く場合があるため、状態を確認してから再キューする。
                    if !self.streams.is_send_terminal(stream_id) {
                        self.streams.pending_frames.push_back(Frame::ResetStream(
                            frame::reset_stream::ResetStream {
                                stream_id: VarInt::new(stream_id)
                                    .expect("value fits in 62-bit varint"),
                                application_protocol_error_code: VarInt::new(error_code)
                                    .expect("value fits in 62-bit varint"),
                                final_size: VarInt::new(final_size)
                                    .expect("value fits in 62-bit varint"),
                            },
                        ));
                    }
                }
                SentFrameInfo::ResetStreamAt { stream_id, .. } => {
                    // draft-ietf-quic-reliable-stream-reset-11 Section 4 /
                    // Section 5.2: ロストした RESET_STREAM_AT は送信時の値では
                    // なく、現在の最小 Reliable Size を持つフレームの情報を
                    // 再送しなければならない (MUST)。終端状態では再送しない。
                    // 確定した peer transport parameter が未広告の場合は
                    // Section 3 の MUST NOT に従い RESET_STREAM へ降格する。
                    if !self.streams.peer_supports_reset_stream_at() {
                        self.streams.demote_unsupported_reset_stream_at();
                    } else if let Some(rsa) = self.streams.requeue_reset_stream_at(stream_id) {
                        self.streams
                            .pending_frames
                            .push_back(Frame::ResetStreamAt(rsa));
                    }
                }
                SentFrameInfo::StopSending {
                    stream_id,
                    error_code,
                } => {
                    self.streams.pending_frames.push_back(Frame::StopSending(
                        frame::stop_sending::StopSending {
                            stream_id: VarInt::new(stream_id).expect("value fits in 62-bit varint"),
                            application_protocol_error_code: VarInt::new(error_code)
                                .expect("value fits in 62-bit varint"),
                        },
                    ));
                }
                SentFrameInfo::NewConnectionId {
                    path_id: cid_path_id,
                    sequence_number,
                    retire_prior_to,
                    connection_id,
                    stateless_reset_token,
                } => {
                    // NEW_CONNECTION_ID は path ID 0 (初期パス) 専用のフレームで
                    // あり (RFC 10069 Section 4.4)、
                    // PATH_NEW_CONNECTION_ID は path ID に対応する。フレームが
                    // 指すパスが廃棄済み・廃棄中の場合は再送しない。CID の
                    // ローテーションは同じ path ID の CID に限られ
                    // (Section 3.2.2)、パス廃棄時は当該パスの受信 CID を即時
                    // 退役扱いにする (Section 3.4)。
                    // path ID 0 は初期パス (PathId::INITIAL) を表す。
                    if self.is_path_abandoned(PathId(cid_path_id)) {
                        continue;
                    }
                    if cid_path_id == 0 {
                        self.streams
                            .pending_frames
                            .push_back(Frame::NewConnectionId(
                                frame::new_connection_id::NewConnectionId {
                                    sequence_number: VarInt::new(sequence_number)
                                        .expect("value fits in 62-bit varint"),
                                    retire_prior_to: VarInt::new(retire_prior_to)
                                        .expect("value fits in 62-bit varint"),
                                    connection_id,
                                    stateless_reset_token,
                                },
                            ));
                    } else {
                        self.streams
                            .pending_frames
                            .push_back(Frame::PathNewConnectionId(
                                frame::path_new_connection_id::PathNewConnectionId {
                                    path_id: cid_path_id,
                                    sequence_number: VarInt::new(sequence_number)
                                        .expect("value fits in 62-bit varint"),
                                    retire_prior_to: VarInt::new(retire_prior_to)
                                        .expect("value fits in 62-bit varint"),
                                    connection_id,
                                    stateless_reset_token,
                                },
                            ));
                    }
                }
                SentFrameInfo::HandshakeDone => {
                    self.streams
                        .pending_frames
                        .push_back(Frame::HandshakeDone(frame::handshake_done::HandshakeDone));
                }
                // RFC 9000 Section 13.3: NEW_TOKEN は同一内容で再送する。
                SentFrameInfo::NewToken { token } => {
                    self.streams
                        .pending_frames
                        .push_back(Frame::NewToken(frame::new_token::NewToken { token }));
                }
                // RFC 9000 Section 5.1.2 / Section 13.3:
                // ロストした RETIRE_CONNECTION_ID は再送しなければならない。
                // PATH_RETIRE_CONNECTION_ID の再送は
                // RFC 10069 Section 4.5 に従う。
                // 廃棄パスで未 ACK の RETIRE も、別パスで再送する
                // (RFC 9000 Section 5.1.2 / Section 13.3: 退役させずに忘れては
                // ならない)。廃棄パス自身の CID 向けの RETIRE も対象に含める。
                // `retire_peer_cids_for_path` はまだ `peer_cid_entries` に残って
                // いる CID だけを退役させるため、飛行中の RETIRE が指す除去済み
                // CID はそこで再送されない。同じシーケンス番号の RETIRE を重ねて
                // 送ることは RFC 9000 Section 19.16 で禁止されていない。
                SentFrameInfo::RetireConnectionId {
                    path_id: rcid_path_id,
                    sequence_number,
                } => {
                    // `queue_retire_peer_cid` を通さず直接積み、退役履歴による
                    // 重複抑止をバイパスする。履歴は通常の再通知 (同じ CID の
                    // 再受信) の重複を抑止するためのものであり、ACK されていない
                    // 再送まで抑止してはならない。path_id == 0 は
                    // RETIRE_CONNECTION_ID、それ以外は PATH_RETIRE_CONNECTION_ID。
                    if rcid_path_id == 0 {
                        self.streams
                            .pending_frames
                            .push_back(Frame::RetireConnectionId(
                                frame::retire_connection_id::RetireConnectionId {
                                    sequence_number: VarInt::new(sequence_number)
                                        .expect("value fits in 62-bit varint"),
                                },
                            ));
                    } else {
                        self.streams
                            .pending_frames
                            .push_back(Frame::PathRetireConnectionId(
                                frame::path_retire_connection_id::PathRetireConnectionId {
                                    path_id: rcid_path_id,
                                    sequence_number: VarInt::new(sequence_number)
                                        .expect("value fits in 62-bit varint"),
                                },
                            ));
                    }
                }
                SentFrameInfo::PathStatus {
                    path_id,
                    status,
                    sequence_number,
                } => {
                    self.requeue_lost_path_status(path_id, status, sequence_number);
                }
                SentFrameInfo::PathsBlocked { .. } => {
                    // 現在の remote_max_path_id を引き続き超過している場合のみ
                    // 再送する (path_id が増えてブロックが解消していれば再送不要)。
                    // match のガードにすると全 variant を網羅したことにならず、
                    // 将来 variant を追加したときにコンパイルエラーで気づけない。
                    if self.paths.next_path_id_blocked_by_peer_limit() {
                        self.streams.pending_frames.push_back(Frame::PathsBlocked(
                            frame::paths_blocked::PathsBlocked {
                                maximum_path_id: self.paths.remote_max_path_id,
                            },
                        ));
                    }
                }
                SentFrameInfo::PathCidsBlocked {
                    path_id: pcb_path_id,
                    ..
                } => {
                    // PATH_CIDS_BLOCKED が指すパスが廃棄済み・廃棄中の場合は
                    // 再送しない。同節 (Section 4.7) はブロックが継続している間の
                    // 再送を MAY とするだけであり、廃棄したパスでは CID を追加
                    // しないためブロック状態を再通知する意味がない。
                    if self.is_path_abandoned(PathId(pcb_path_id)) {
                        continue;
                    }
                    // ブロック状態がまだ継続しているか (残存 CID 数 < ローカル
                    // active_connection_id_limit) を確認して再送する。RFC 9000
                    // Section 5.1.1: CID を発行するエンドポイントは受信側が広告
                    // する上限を超えてはならないため、ピアが我々へ発行できる数の
                    // 上限はローカル TP の値である。Next Sequence Number は初回送信
                    // notify_path_cids_blocked と同じく「次に発行されると期待する
                    // ピア CID のシーケンス番号」を使う
                    // (RFC 10069 Section 4.7)。
                    // 退役で peer_cid_entries から消えた CID や飛びのあるシーケンス
                    // では残存個数が期待する次番号と一致しないため、受信済みの最大
                    // シーケンス番号を残す peer_cid_max_seq から求める。受信済み
                    // 最大はピアの発行済み最大以下 (RFC 9000 Section 5.1.1) なので、
                    // その +1 はピアの次回発行予定以下となり、受信側の strict `>`
                    // 検証 (同節) で接続エラーにならない。
                    let peer_cid_count = self
                        .peer_cid_entries
                        .iter()
                        .filter(|e| e.path_id == PathId(pcb_path_id))
                        .count() as u64;
                    let local_limit = self.local_params.active_connection_id_limit;
                    if peer_cid_count < local_limit {
                        let next_sequence_number =
                            self.next_peer_cid_sequence_number(PathId(pcb_path_id));
                        self.streams
                            .pending_frames
                            .push_back(Frame::PathCidsBlocked(
                                frame::path_cids_blocked::PathCidsBlocked {
                                    path_id: pcb_path_id,
                                    next_sequence_number: VarInt::new(next_sequence_number)
                                        .expect("value fits in 62-bit varint"),
                                },
                            ));
                    }
                }
                SentFrameInfo::ObservedAddress {
                    path_id,
                    sequence_number,
                    addr,
                } => {
                    // draft-ietf-quic-address-discovery-01 Section 4.1:
                    // 再送は元のフレームを送信したパスと同じパスで行う (MUST)。
                    // そのパスが廃棄済み・削除済みの場合は別パスへ移さない。
                    if !self.is_path_abandoned(PathId(path_id))
                        && let Err(e) = self.emit_1rtt_single_frame(
                            PathId(path_id),
                            Frame::ObservedAddress(frame::observed_address::ObservedAddress {
                                sequence_number: VarInt::new(sequence_number)
                                    .expect("value fits in 62-bit varint"),
                                addr,
                            }),
                            now,
                        )
                    {
                        tracing::debug!("OBSERVED_ADDRESS retransmission failed: {e}");
                    }
                }
                // 以下は呼び出し元で別の再送経路 (STREAM / CRYPTO / multipath)
                // に分類されるか、再送不要として除外される。制御フレームの
                // 再送キューには積まれないため、ここでは何もしない。
                SentFrameInfo::Ack { .. }
                | SentFrameInfo::Crypto { .. }
                | SentFrameInfo::Stream { .. }
                | SentFrameInfo::PathAbandon { .. }
                | SentFrameInfo::MaxPathId { .. }
                | SentFrameInfo::PathAck
                | SentFrameInfo::AckFrequency { .. }
                | SentFrameInfo::Other => {}
            }
        }
    }

    /// ロストした PATH_STATUS を、そのパスについて最後に送った状態に限り再送する
    ///
    /// RFC 10069 Section 4.3: ロストした PATH_STATUS は、
    /// そのパスについて最後に送った状態を含む場合に限り再送する (SHOULD)。
    /// 判定はフレームが持つ Path Status Sequence Number が、そのパスの最後の
    /// 採番値 (`status_seq_send - 1`) と一致するかで行う。状態そのものも現在値と
    /// 一致することを確認し、状態変更後に古い通知が再送されないようにする。
    ///
    /// 再送では新しいシーケンス番号を採番せず、ロストしたフレームと同じ値を
    /// 使う。採番し直すと同じロストが ACK 駆動経路と時間閾値経路で別の通知に
    /// なり、「最後に送った状態」の判定が経路によって変わってしまう。受信側は
    /// 同じ値以下のシーケンス番号を無視するため (同 Section 4.3)、重複した
    /// 再送が状態を変えることはない。
    fn requeue_lost_path_status(&mut self, path_id: u32, status: PathStatus, sequence_number: u64) {
        let Some(path) = self.paths.get_mut(PathId(path_id)) else {
            return;
        };
        // 廃棄済み・廃棄中のパスへは再送しない (RFC 10069 Section 4)。
        if path.state == PathState::Abandoned || path.state == PathState::Abandoning {
            return;
        }
        // 最後に送った状態か (ロストしたフレームの採番値が最後の採番値と一致するか)
        if path.status_seq_send.checked_sub(1) != Some(sequence_number) {
            return;
        }
        // 状態が変わっている場合は、より新しい通知を送っているため再送しない
        if path.status != status {
            return;
        }
        // 採番値は VarInt で復号した値か内部カウンタ由来であり、通常は必ず
        // 収まる。防御的に収まらない場合は再送しない。
        let Some(seq) = VarInt::new(sequence_number) else {
            return;
        };
        let frame = match status {
            PathStatus::Available => {
                Frame::PathStatusAvailable(frame::path_status::PathStatusAvailable {
                    path_id,
                    path_status_sequence_number: seq,
                })
            }
            PathStatus::Backup => Frame::PathStatusBackup(frame::path_status::PathStatusBackup {
                path_id,
                path_status_sequence_number: seq,
            }),
        };
        self.streams.pending_frames.push_back(frame);
    }

    /// ピアの active_connection_id_limit まで CID を発行する
    ///
    /// ハンドシェイク完了後に呼び出す。
    /// 初期 CID (seq=0) は既に発行済みなので、残りを NEW_CONNECTION_ID で送信する。
    fn issue_initial_cids(&mut self) {
        // ピアの active_connection_id_limit は 2^62-1 まで広告できるため、
        // そのまま使うとハンドシェイク直後に大量の CID を発行してしまう。
        // 実用上限に clamp する (ピアの広告値より少なくても仕様上問題ない)。
        let limit = self.peer_params.as_ref().map_or(2, |p| {
            p.active_connection_id_limit.min(MAX_PEER_ACTIVE_CID_LIMIT)
        });
        // Path 0 の CID 数を数える
        let current_count = self
            .local_cid_table
            .keys()
            .filter(|(pid, _)| *pid == 0)
            .count() as u64;
        for _ in current_count..limit {
            if let Ok((seq, cid, token)) = self.generate_new_cid(PathId::INITIAL) {
                self.streams
                    .pending_frames
                    .push_back(Frame::NewConnectionId(
                        frame::new_connection_id::NewConnectionId {
                            sequence_number: VarInt::new(seq).expect("value fits in 62-bit varint"),
                            retire_prior_to: VarInt::new(0).expect("value fits in 62-bit varint"),
                            connection_id: cid,
                            stateless_reset_token: token,
                        },
                    ));
            }
        }

        // Proactive CID は peer_params 設定後に別途呼び出す
        // (remote_max_path_id が確定するまで発行できない)
    }

    /// 指定パスの次回発行予定 CID シーケンス番号を返す
    ///
    /// Path オブジェクトが存在すればその `next_local_cid_seq` を、まだ Path が
    /// 生成されておらずプロアクティブ発行のみ行ったパスでは
    /// `proactive_cid_next_seq` に退避した値を返す。どちらもなければ 0。
    /// パス生成時に `proactive_cid_next_seq` の値は `next_local_cid_seq` へ
    /// 移されるため、両者は排他で二重計上は起きない。
    /// `next_local_cid_seq` は「発行済み最大シーケンス番号 + 1」に保たれる。
    ///
    /// 用途と境界演算子は非対称:
    /// - RETIRE_CONNECTION_ID / PATH_RETIRE_CONNECTION_ID:
    ///   `sequence_number >= expected` を「未発行シーケンス番号のリタイア要求」
    ///   として PROTOCOL_VIOLATION (RFC 9000 Section 19.16、
    ///   RFC 10069 Section 4.5 が同処理を継承)
    /// - PATH_CIDS_BLOCKED:
    ///   `next_sequence_number > expected` を「次回発行予定シーケンス番号を超過」
    ///   として PROTOCOL_VIOLATION (RFC 10069 Section 4.7)
    ///   なお RFC 10069 の Next Sequence Number は「フレーム受信側 (= CID 発行側)
    ///   が次に発行することをフレーム送信側が期待している seq」を通知する
    ///   フィールドなので、`==` は「まさに次に発行予定の seq」を指し正常。
    ///   RETIRE 系の `>=` に揃えないこと。
    ///
    /// 境界演算子と MUST 文言は RFC 10069 Section 4.5 / Section 4.7 に基づく。
    fn expected_next_local_cid_seq(&self, path_id: PathId) -> u64 {
        self.paths
            .get(path_id)
            .map(|p| p.next_local_cid_seq)
            .or_else(|| self.proactive_cid_next_seq.get(&path_id.0).copied())
            .unwrap_or(0)
    }

    /// 未使用 Path ID に対して CID を先行発行する
    ///
    /// RFC 10069 Section 3.2.1:
    /// "It is RECOMMENDED that endpoints proactively issue connection IDs
    ///  for at least one unused Path ID."
    ///
    /// 発行数の上限はネゴシエート済みの maximum path identifier とする。
    /// 未使用の path ID ごとに 1 つずつ出す。「少なくとも 1 つ」を満たし、
    /// maximum を超える path ID の CID は出さない。ネゴシエート済みの上限を
    /// さらに 1 個へ縮めることはしない。
    fn issue_proactive_cids(&mut self) {
        // CID 発行の上限: ピアの local_max_path_id (= 自分の remote_max_path_id) 以下。
        // ピアがまだ MAX_PATH_ID で拡大していない場合は peer_initial_max_path_id が上限。
        // RFC 10069 Section 3.2.1:
        // > Endpoints MUST NOT issue new connection IDs with path IDs greater than
        // > the Maximum Path Identifier field in MAX_PATH_ID frames
        let max_for_cid =
            std::cmp::min(self.paths.local_max_path_id, self.paths.remote_max_path_id);
        if max_for_cid == 0 {
            return;
        }
        let local_max = max_for_cid;
        // 既に CID が発行済みの Path ID を収集する
        let issued_path_ids: std::collections::HashSet<u32> =
            self.local_cid_table.keys().map(|(pid, _)| *pid).collect();
        // 未使用 Path ID に各 1 つずつ CID を先行発行する
        // パスがまだ存在しなくても CID を生成する (プロアクティブ発行)
        for pid in 1..=local_max {
            if issued_path_ids.contains(&pid) {
                continue;
            }
            // パスが存在しない場合はシーケンス番号 0 で CID を直接生成する
            let seq = self
                .paths
                .get(PathId(pid))
                .map(|p| p.next_local_cid_seq)
                .unwrap_or(0);
            // varint に収まらないシーケンス番号では CID を発行しない
            let Some(seq_varint) = VarInt::new(seq) else {
                continue;
            };
            // 接続全体で一意な CID を生成する
            let Ok(cid) = self.generate_unique_local_cid() else {
                continue;
            };
            // 生成器が設定されていれば CID から決定的に Token を生成し、
            // 未設定なら従来どおり乱数で生成する (RFC 9000 Section 10.3.2)
            let token = match &self.stateless_reset_generator {
                Some(generator) => generator.generate(cid.as_bytes()),
                None => {
                    let mut token = [0u8; 16];
                    if aws_lc_rs::rand::fill(&mut token).is_err() {
                        continue;
                    }
                    token
                }
            };
            self.local_cid_table.insert((pid, seq), cid.clone());
            self.paths.register_cid(cid.clone(), PathId(pid));
            // I/O 層のルーティングテーブルにも登録を依頼する
            self.output_queue
                .push_back(ConnectionOutput::RegisterLocalCid {
                    cid: cid.clone(),
                    path_id: PathId(pid),
                });
            if let Some(path) = self.paths.get_mut(PathId(pid)) {
                path.next_local_cid_seq = seq + 1;
            } else {
                // パスがまだ存在しない場合、次の seq を記録する
                // パス作成時に next_local_cid_seq をこの値で初期化する
                self.proactive_cid_next_seq.insert(pid, seq + 1);
            }
            self.streams
                .pending_frames
                .push_back(Frame::PathNewConnectionId(
                    frame::path_new_connection_id::PathNewConnectionId {
                        path_id: pid,
                        sequence_number: seq_varint,
                        retire_prior_to: VarInt::new(0).expect("value fits in 62-bit varint"),
                        connection_id: cid,
                        stateless_reset_token: token,
                    },
                ));
        }
    }

    /// Closing/Draining 状態の 3×PTO 猶予期間タイマーを設定する
    ///
    /// RFC 9000 Section 10.2, RFC 10069 Section 2.6
    fn set_closing_draining_timer(&mut self, now: Timestamp) {
        // 全パスの最大 PTO に実効 ACK delay を加えた値を使う
        let timeout = self.lifecycle_max_pto().mul(3);
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::ClosingDraining,
            deadline: now + timeout,
        });
    }

    /// 既存の自ローカル CID と重複しないランダム CID を生成する
    ///
    /// RFC 10069 Section 3.2.1 / RFC 9000 Section 5.1:
    /// "connection IDs cannot be issued more than once on the same connection"。
    /// 接続全体のスコープ (path_id にかかわらず) で重複しない値を返す。
    /// 8 バイトランダム CID の衝突確率は 2^-64 と極めて低いが、理論的な
    /// 衝突を避けるため最大 16 回まで再生成する。
    fn generate_unique_local_cid(&self) -> Result<ConnectionId, Error> {
        for _ in 0..16 {
            let mut cid_bytes = [0u8; 20];
            let cid_slice = &mut cid_bytes[..self.local_cid_len];
            aws_lc_rs::rand::fill(cid_slice)
                .map_err(|_| Error::InvalidData("failed to generate CID".into()))?;
            let cid = ConnectionId::from_slice(cid_slice)?;
            if !self
                .local_cid_table
                .values()
                .any(|existing| existing == &cid)
            {
                return Ok(cid);
            }
        }
        Err(Error::InvalidData(
            "unique CID generation exhausted retries".into(),
        ))
    }

    /// 新しい CID を生成してテーブルに登録する
    ///
    /// パスごとに独立したシーケンス番号空間を使用する
    /// (RFC 10069 Section 4)。
    /// 生成される CID は既存の自ローカル CID すべてと衝突しないことが
    /// `generate_unique_local_cid` により保証される。
    fn generate_new_cid(
        &mut self,
        path_id: PathId,
    ) -> Result<(u64, ConnectionId, [u8; 16]), Error> {
        let cid = self.generate_unique_local_cid()?;

        let path = self
            .paths
            .get_mut(path_id)
            .ok_or_else(|| Error::InvalidData(format!("path {path_id} not found")))?;
        let seq = path.next_local_cid_seq;
        // ピアが RETIRE を返す限り発行を続けられるため、理論上は 2^62 を
        // 超え得る。varint に収まらない場合は発行を諦め、panic を避ける。
        if seq > tobi_core::varint::MAX_VALUE {
            return Err(Error::InvalidData(
                "local CID sequence number exceeds the varint range".into(),
            ));
        }
        path.next_local_cid_seq += 1;

        // 生成器が設定されていれば CID から決定的に Token を生成し、
        // 未設定なら従来どおり乱数で生成する (RFC 9000 Section 10.3.2)
        let stateless_reset_token = match &self.stateless_reset_generator {
            Some(generator) => generator.generate(cid.as_bytes()),
            None => {
                let mut token = [0u8; 16];
                aws_lc_rs::rand::fill(&mut token)
                    .map_err(|_| Error::InvalidData("failed to generate reset token".into()))?;
                token
            }
        };

        self.local_cid_table.insert((path_id.0, seq), cid.clone());
        // CID→Path マッピングを登録して受信時にパスを特定可能にする
        self.paths.register_cid(cid.clone(), path_id);
        // I/O 層のルーティングテーブルにも登録を依頼する
        // RFC 9000 Section 5.1.1 / RFC 10069 Section 4.4
        self.output_queue
            .push_back(ConnectionOutput::RegisterLocalCid {
                cid: cid.clone(),
                path_id,
            });
        Ok((seq, cid, stateless_reset_token))
    }

    /// ピアに提供できるアクティブ CID の実用上限。
    fn peer_active_cid_limit(&self) -> usize {
        self.peer_params.as_ref().map_or(2, |params| {
            params
                .active_connection_id_limit
                .min(MAX_PEER_ACTIVE_CID_LIMIT) as usize
        })
    }

    /// RETIRE の到着待ちになっている CID を除いた、使用可能な発行済み CID 数。
    fn active_local_cid_count(&self, path_id: PathId) -> usize {
        let boundary = self
            .local_cid_retire_prior_to
            .get(&path_id.0)
            .copied()
            .unwrap_or(0);
        self.local_cid_table
            .keys()
            .filter(|(pid, seq)| *pid == path_id.0 && *seq >= boundary)
            .count()
    }

    /// 標準 QUIC の CID が切り替わったら、古い CID の退役を求めて予備を補充する。
    /// 初期プールを使い切る前に送ることで、ピアが次の移行を開始できる。
    /// 退役待ちの CID は RETIRE を受けるまで受信可能なまま保持する。
    fn refill_local_cids_after_rotation(&mut self, path_id: PathId, dcid: &ConnectionId) {
        if path_id != PathId::INITIAL || self.multipath_negotiated() || self.local_cid.is_empty() {
            return;
        }
        let Some(sequence) = self
            .local_cid_table
            .iter()
            .find_map(|((pid, seq), cid)| (*pid == path_id.0 && cid == dcid).then_some(*seq))
        else {
            return;
        };
        let boundary = self.local_cid_retire_prior_to.entry(path_id.0).or_default();
        if sequence <= *boundary {
            return;
        }
        *boundary = sequence;
        while self.active_local_cid_count(path_id) < self.peer_active_cid_limit() {
            // RETIRE を返さないピアに対しても、保持数の実用上限を越えて発行しない。
            let Ok((seq, cid, token, retire_prior_to)) =
                self.generate_new_cid_with_rotation(path_id)
            else {
                break;
            };
            self.streams
                .pending_frames
                .push_back(Frame::NewConnectionId(
                    frame::new_connection_id::NewConnectionId {
                        sequence_number: VarInt::new(seq).expect("value fits in 62-bit varint"),
                        retire_prior_to: VarInt::new(retire_prior_to)
                            .expect("value fits in 62-bit varint"),
                        connection_id: cid,
                        stateless_reset_token: token,
                    },
                ));
        }
    }

    /// retire_prior_to ベースの CID ローテーション付きで新しい CID を発行する
    ///
    /// RFC 10069 Section 4.3 / RFC 9000 Section 5.1.1:
    /// ピアの `active_connection_id_limit` を超えるアクティブ CID を発行して
    /// はならない。発行後にパスごとのアクティブ CID 数が上限を超える場合は、
    /// `retire_prior_to` で古い CID をリタイアさせて回転する。
    ///
    /// 戻り値: (sequence_number, connection_id, stateless_reset_token, retire_prior_to)
    fn generate_new_cid_with_rotation(
        &mut self,
        path_id: PathId,
    ) -> Result<(u64, ConnectionId, [u8; 16], u64), Error> {
        // ピアが RETIRE を返す前に発行を続けると、ローカル CID テーブルが
        // 増え続ける。パスごとの実用上限に達したら、RETIRE が届くまで発行しない。
        let path_cid_count = self
            .local_cid_table
            .keys()
            .filter(|(pid, _)| *pid == path_id.0)
            .count();
        if path_cid_count >= MAX_LOCAL_CIDS_PER_PATH {
            return Err(Error::InvalidData(format!(
                "path {path_id} has {path_cid_count} local CIDs, reaching the practical limit"
            )));
        }
        let peer_limit = self.peer_active_cid_limit();
        let previous_retire = self
            .local_cid_retire_prior_to
            .get(&path_id.0)
            .copied()
            .unwrap_or(0);

        // 対象パスで発行済みのシーケンス番号を昇順で集める
        let mut issued_seqs: Vec<u64> = self
            .local_cid_table
            .keys()
            .filter(|(pid, seq)| *pid == path_id.0 && *seq >= previous_retire)
            .map(|(_, seq)| *seq)
            .collect();
        issued_seqs.sort_unstable();

        // 新規発行 (+1) 後のアクティブ CID 数が peer_limit を超えないよう
        // 古い CID から retire_count 個をリタイア対象にする
        let retire_count = (issued_seqs.len() + 1).saturating_sub(peer_limit);
        let retire_prior_to = if retire_count > 0 {
            issued_seqs[retire_count - 1] + 1
        } else {
            previous_retire
        };

        let (seq, cid, token) = self.generate_new_cid(path_id)?;
        self.local_cid_retire_prior_to
            .insert(path_id.0, retire_prior_to);
        Ok((seq, cid, token, retire_prior_to))
    }

    /// AEAD 認証失敗カウンタを加算する (RFC 9001 Section 6.6)
    ///
    /// integrity limit は接続生涯で「認証に失敗した受信パケット数」を
    /// across all keys で累積して判定する。鍵更新ではリセットしない。
    fn record_aead_auth_failure(&mut self) {
        self.aead_auth_failures = self.aead_auth_failures.saturating_add(1);
    }

    /// 1-RTT 鍵の AEAD 使用制限を検査する
    ///
    /// RFC 9001 Appendix B / RFC 10069 Section 7.3:
    /// 制限は単一鍵での全パス送信/受信パケット合計に対して適用される。
    ///
    /// - 送信カウンタが confidentiality limit 以上に達した場合、鍵更新を起動する。
    ///   鍵更新が失敗した (クールダウン中・次鍵未準備など) 場合は
    ///   AEAD_LIMIT_REACHED で接続を閉じる。
    /// - 認証失敗カウンタが integrity limit を超えた場合は AEAD_LIMIT_REACHED で
    ///   接続を閉じる (RFC 9001 Section 6.6)。
    ///   判定は 1-RTT 鍵確立後から行う (Initial / Handshake の復号失敗も
    ///   カウンタには累積されるが、limit 判定は 1-RTT 鍵の AEAD 制限で行う)。
    fn check_aead_limits(&mut self, now: Timestamp) -> Result<(), Error> {
        let Some(keys) = self.one_rtt_keys.as_ref() else {
            return Ok(());
        };
        let conf_limit = keys.local_packet.confidentiality_limit();
        let integ_limit = keys
            .remote_packet
            .as_ref()
            .map_or(0, |key| key.integrity_limit());

        if self.aead_auth_failures > integ_limit {
            let error = Error::Protocol {
                code: tobi_core::error::TransportErrorCode::AEAD_LIMIT_REACHED,
                reason: format!(
                    "integrity limit {} exceeded (auth failures {})",
                    integ_limit, self.aead_auth_failures
                ),
            };
            self.close_on_output_error(&error);
            return Err(error);
        }

        if self.one_rtt_packets_sent >= conf_limit {
            // 鍵更新をトリガーする
            if let Err(e) = self.update_keys(now) {
                let error = Error::Protocol {
                    code: tobi_core::error::TransportErrorCode::AEAD_LIMIT_REACHED,
                    reason: format!(
                        "confidentiality limit {} reached, key update failed: {}",
                        conf_limit, e
                    ),
                };
                self.close_on_output_error(&error);
                return Err(error);
            }
        }
        Ok(())
    }

    // --- パケット送信 ---

    /// Initial / Handshake パケットを運ぶ UDP データグラムのペイロード上限
    ///
    /// RFC 9000 Section 14.2 と Section 18.2 に基づき、初期パスの PMTU と
    /// ピアが広告した `max_udp_payload_size` の小さい方に収める。ピアの上限は
    /// ハンドシェイクで確定するまで不明なため、確定までは QUIC の最小
    /// データグラム長 (1200) を保守的な上限として使う。ピア上限の確定時には
    /// `apply_peer_max_udp_payload_size` が `Path::pmtu` を引き下げ済みである。
    fn long_packet_send_limit(&self) -> usize {
        let pmtu = usize::from(self.paths.initial_path().pmtu);
        if self.peer_params_finalized {
            pmtu
        } else {
            pmtu.min(MIN_INITIAL_DATAGRAM_SIZE)
        }
    }

    /// Length フィールドを含む Long Header パケットの全体長を返す
    ///
    /// `fixed_len` は Length フィールドより前のバイト数。`ack_len` は ACK
    /// フレームの符号化長、`crypto` は CRYPTO フレームを載せる場合の
    /// (offset, データ長)。Long Header の Length と CRYPTO の length は
    /// 可変長整数であり、値によって符号化長が変わる点まで含めて計算する。
    fn long_packet_len(
        fixed_len: usize,
        pn_len: usize,
        tag_len: usize,
        ack_len: usize,
        crypto: Option<(u64, usize)>,
    ) -> usize {
        let crypto_len = crypto.map_or(0, |(offset, data_len)| {
            let offset_size = VarInt::new(offset)
                .expect("crypto offset fits in 62-bit varint")
                .encoded_size();
            let data_len_size = VarInt::new(data_len as u64)
                .expect("crypto data length fits in 62-bit varint")
                .encoded_size();
            // CRYPTO フレームは type(1) + offset + length + data
            1 + offset_size + data_len_size + data_len
        });
        let length_value = pn_len + ack_len + crypto_len + tag_len;
        let length_field_size = VarInt::new(length_value as u64)
            .expect("packet length fits in 62-bit varint")
            .encoded_size();
        fixed_len + length_field_size + length_value
    }

    /// PADDING を含めたパケット全体長と Length フィールドの符号化長を返す
    ///
    /// `min_payload_len` は実際に載せるフレームのバイト数、`min_total` は
    /// PADDING を含めたパケット全体の最小長である。Length の値
    /// (`全体長 - Length フィールドより前の長さ - Length 自身の長さ`) は
    /// Length 自身の符号化長にも依存するため、全体長を数バイト伸ばしながら
    /// 自分自身と矛盾しない最小の全体長を探す。PADDING はこの全体長に
    /// 合わせてペイロードへ詰める。
    fn long_packet_padded_len(
        fixed_len: usize,
        pn_len: usize,
        tag_len: usize,
        min_payload_len: usize,
        min_total: usize,
    ) -> (usize, usize) {
        // Length の値は少なくとも PN と AEAD タグとフレームのバイト数を含む
        let minimum = (fixed_len + pn_len + min_payload_len + tag_len).max(min_total);
        // Length の符号化長は 1 / 2 / 4 バイトのいずれかであり、全体長を
        // 数バイト伸ばせば必ず自分自身と矛盾しない長さが見つかる。
        for total in minimum..=minimum.saturating_add(8) {
            for size in [1usize, 2, 4] {
                let Some(length_value) = total.checked_sub(fixed_len + size) else {
                    continue;
                };
                if length_value < pn_len + min_payload_len + tag_len {
                    continue;
                }
                if VarInt::new(length_value as u64).map(VarInt::encoded_size) == Some(size) {
                    return (total, size);
                }
            }
        }
        // 呼び出し元が渡す最小長は実際に符号化できる長さから作られるため、
        // ここには到達しない。到達した場合もフレームを切り詰めないよう、
        // PADDING なしで符号化できる最小構成へフォールバックする。
        debug_assert!(false, "no consistent Long Header packet length was found");
        let length_value = pn_len + min_payload_len + tag_len;
        let size = VarInt::new(length_value as u64)
            .expect("packet length fits in 62-bit varint")
            .encoded_size();
        (fixed_len + size + length_value, size)
    }

    /// Long Header パケットに載せられる CRYPTO データ長を返す
    ///
    /// `target_len` はパケット全体の上限長。ACK フレーム (符号化長 `ack_len`)
    /// と CRYPTO フレームのヘッダを含めて上限に収まる最大のデータ長を求める。
    /// CRYPTO の length と Length フィールドはいずれもデータ長に依存する
    /// 可変長整数なので、実際の長さで再計算しながら収束させる。
    fn long_packet_crypto_capacity(
        fixed_len: usize,
        pn_len: usize,
        tag_len: usize,
        ack_len: usize,
        crypto_offset: u64,
        target_len: usize,
    ) -> usize {
        let offset_size = VarInt::new(crypto_offset)
            .expect("crypto offset fits in 62-bit varint")
            .encoded_size();
        // CRYPTO フレームのヘッダ (type + offset + length) と Length フィールドの
        // 可変長整数を最小の 1 バイトと仮定して初期値を見積もる。
        let mut data_len = target_len
            .saturating_sub(fixed_len + 1 + pn_len + tag_len + ack_len + 1 + offset_size + 1);
        loop {
            let packet_len = Self::long_packet_len(
                fixed_len,
                pn_len,
                tag_len,
                ack_len,
                Some((crypto_offset, data_len)),
            );
            if packet_len <= target_len || data_len == 0 {
                return data_len;
            }
            // 超過分だけ縮める。可変長整数の境界を跨いだ場合も次の周で
            // 再計算するため、数バイトの超過は 1〜2 周で収束する。
            data_len = data_len.saturating_sub(packet_len - target_len);
        }
    }

    /// Initial パケットの送信に必要なバースト予算を控えめに見積もる
    ///
    /// Handshake パケットを先に組み立てるため、Handshake が Initial の送信機会を
    /// 奪わないよう Initial 分の予算を先に確保する (RFC 9002 Section 7.7:
    /// バーストは初期輻輳ウィンドウ以下に制限する)。Initial の CRYPTO は
    /// 複数パケットに分割され得るため、CRYPTO データ長から分割数を見積もる。
    /// 過大に見積もった場合も Handshake の送信が次の送信機会へ回るだけで、
    /// 送信内容は変わらない。
    fn initial_burst_reservation(&self) -> u64 {
        if self.initial_keys.is_none() {
            return 0;
        }
        let crypto_len = self.crypto_send_initial.len()
            + self
                .crypto_retransmit_initial
                .iter()
                .map(|(_, data)| data.len())
                .sum::<usize>();
        if crypto_len == 0 {
            return if self.initial_ack_tracker.should_send_ack_immediately() {
                MIN_INITIAL_DATAGRAM_SIZE as u64
            } else {
                0
            };
        }
        // 1 パケットに載る CRYPTO データ量の下限を見積もる。Long Header、
        // PN、AEAD タグ、CRYPTO フレームのヘッダを多めに 120 バイト引く。
        // Token が長い場合は実際の容量がこれより小さくなり得るため、この値は
        // バースト予算の下限保証ではない (予約が不足しても送信内容は変わらない)。
        let per_packet = MIN_INITIAL_DATAGRAM_SIZE - 120;
        let packets = crypto_len.div_ceil(per_packet);
        (packets * MIN_INITIAL_DATAGRAM_SIZE) as u64
    }

    fn emit_packets(&mut self, now: Timestamp) -> Result<(), Error> {
        // Closing / Draining / Closed 中は CONNECTION_CLOSE の再送 (`receive` が
        // `closing_packet` を使って行う) 以外を送信しない。close 直後の `receive` 末尾や
        // ロス検出タイマーの発火から呼ばれても、閉鎖データグラムとは別の
        // Initial / Handshake パケットを追加 push しないために早期 return する
        // (RFC 9000 Section 10.2)。
        // 送信パケット番号の上限到達などで閉じた接続も含めて以降のパケットを送信しない
        // (RFC 9000 Section 12.3)。
        if matches!(
            self.state,
            ConnectionState::Closing | ConnectionState::Draining | ConnectionState::Closed
        ) {
            return Ok(());
        }
        // この送信機会で実際に出力したパスを記録する
        self.emit_tracking = true;
        self.emit_used_paths.clear();
        // AEAD 使用制限を先に検査する
        // (送信 count が confidentiality limit に達していたら先に鍵更新する)
        self.check_aead_limits(now)?;
        // Coalesced パケット送信 (RFC 9000 Section 12.2, RFC 9001 Section 4.9)
        //
        // Handshake パケットを Initial より先に組み立てる。サーバーが Initial と
        // Handshake を 1 つの UDP データグラムに連結する場合、データグラムを
        // 1200 バイト以上にするための PADDING 量は最初の Handshake パケット長に
        // 依存する。PADDING は Initial の暗号化より前にペイロードへ含める必要が
        // あるため、先に Handshake パケットを組み立てて長さを確定させる。
        // 送信順序は Initial を先に保つ (RFC 9000 Section 12.2)。
        //
        // Initial / Handshake は ack-eliciting な CRYPTO を、0-RTT は
        // ack-eliciting なフレームを運ぶため、送信機会ごとのバーストを初期
        // 輻輳ウィンドウ以下に制限する (RFC 9002 Section 7.7)。ACK のみの
        // パケットは制限しない。Handshake が Initial の送信機会を先食いしない
        // よう、Initial 分の予算を先に確保してから Handshake を組み立てる。
        // pacing rate が未設定の間はこのバースト上限が効くが、pacing rate が
        // 設定された後は `pacing_blocked` が departure time だけを見るため、
        // 予約は Initial の送信順序を保つ目的に限定される。
        let initial_reservation = self.initial_burst_reservation();
        let mut long_header_burst_bytes: u64 = initial_reservation;
        let mut handshake_packets: Vec<Vec<u8>> = Vec::new();
        loop {
            // RFC 9000 Section 13.2.1: Handshake 空間の ack-eliciting パケットは
            // 即座に ACK する MUST。CRYPTO が無くても ACK があれば送る。
            let handshake_crypto_pending = !self.crypto_send_handshake.is_empty()
                || !self.crypto_retransmit_handshake.is_empty();
            let handshake_pending = handshake_crypto_pending
                || self.handshake_ack_tracker.needs_ack()
                || self.handshake_pto_probes_pending > 0;
            if self.handshake_keys.is_none() || !handshake_pending {
                break;
            }
            // ACK のみのパケットは pacing しない (RFC 9002 Section 7.7:
            // ACK のみのパケットは pacing すべきでない SHOULD、RFC 9000
            // Section 13.2.1: Handshake の ack-eliciting パケットは即時 ACK の
            // MUST)。CRYPTO を運ぶパケットだけバースト予算を守る。
            if handshake_crypto_pending
                && self.pacing_blocked(PathId::INITIAL, now, long_header_burst_bytes)
            {
                break;
            }
            let bytes = self.emit_handshake_bytes(now)?;
            if bytes.is_empty() {
                break;
            }
            long_header_burst_bytes = long_header_burst_bytes.saturating_add(bytes.len() as u64);
            handshake_packets.push(bytes);
        }
        // CRYPTO データが上限に収まらない場合は複数の Initial パケットに
        // 分割する。最初の Initial パケットは、連結できる場合だけ Handshake と
        // 1 つのデータグラムにする。
        let mut initial_packets: Vec<Vec<u8>> = Vec::new();
        let mut first_initial_coalesces: Option<usize> = None;
        if self.initial_keys.is_some() {
            // Handshake で実際に送ったバイト数をバースト予算として引き継ぎ、
            // 1 回の送信機会の合計が初期輻輳ウィンドウを超えないようにする
            // (RFC 9002 Section 7.7)。
            let mut initial_burst_bytes: u64 =
                long_header_burst_bytes.saturating_sub(initial_reservation);
            while !self.crypto_send_initial.is_empty()
                || !self.crypto_retransmit_initial.is_empty()
                || self.initial_ack_tracker.should_send_ack_immediately()
                || self.initial_pto_probes_pending > 0
            {
                if (!self.crypto_send_initial.is_empty()
                    || !self.crypto_retransmit_initial.is_empty())
                    && self.pacing_blocked(PathId::INITIAL, now, initial_burst_bytes)
                {
                    break;
                }
                // 最初の Initial パケットだけ、連結する Handshake パケット長を
                // 渡して PADDING 量を決められるようにする。
                let coalesce_hint = if initial_packets.is_empty() {
                    handshake_packets.first().map(Vec::len)
                } else {
                    None
                };
                let (packet, coalesced_len) = self.emit_initial_bytes(now, coalesce_hint)?;
                if packet.is_empty() {
                    // 送信パケット番号が上限に達した場合は収集済みのパケットも
                    // 送信しない (RFC 9000 Section 12.3)。それ以外の理由で
                    // 空の場合は次の送信機会へ回す。
                    if self.state == ConnectionState::Closed {
                        return Ok(());
                    }
                    break;
                }
                if initial_packets.is_empty() {
                    first_initial_coalesces = coalesced_len;
                }
                initial_burst_bytes = initial_burst_bytes.saturating_add(packet.len() as u64);
                initial_packets.push(packet);
            }
            // 0-RTT などの後続の送信のために、Initial と Handshake の合計
            // バイト数をバースト予算として引き継ぐ。
            long_header_burst_bytes = initial_burst_bytes;
        }
        // Initial / Handshake のデータグラムは 0-RTT を組み立てた後にまとめて
        // 出力キューへ積む。送信順序は Initial を先に保つ (RFC 9000 Section 12.2)。
        // 0-RTT パケット送信 (クライアントのみ、ハンドシェイク中に 0-RTT 鍵が利用可能な場合)
        //
        // 同一 UDP データグラムへの異なる暗号化レベルのパケットの連結は
        // RFC 9000 Section 12.2 が定める。RFC 9001 Section 4 は、異なる種類の
        // パケットを送る必要がある場合にコアレシングしたパケットを使うことを
        // SHOULD としている。しかし本実装は 0-RTT を常に単独のデータグラムとして
        // 送る。既定の 1,200 バイト PMTU では、クライアントの Initial を
        // 1,200 バイトへパディングし (RFC 9000 Section 14.1)、そこへ 0-RTT を
        // 連結するとデータグラムが PMTU を超える (RFC 9000 Section 14.2)。
        // DPLPMTUD で PMTU が広がった後なら、小さい 0-RTT パケットは Initial と
        // 同じデータグラムに収まり得るが、本実装は送信経路を単純に保つため
        // 常に別のデータグラムとする。
        let zero_rtt = if self.role == Role::Client
            && self.state == ConnectionState::Handshaking
            && self.zero_rtt_keys.is_some()
            && self.peer_params.is_some()
            && !self.pacing_blocked(PathId::INITIAL, now, long_header_burst_bytes)
        {
            self.emit_zero_rtt_bytes()?
        } else {
            None
        };

        // Initial / Handshake / 0-RTT の送信途中で送信パケット番号が上限に達した場合は
        // 構築済みのパケットも送信せずに終了する (RFC 9000 Section 12.3)
        if self.state == ConnectionState::Closed {
            return Ok(());
        }

        // Initial / Handshake を暗号化レベルの昇順にコアレシングして先に積む
        // (RFC 9000 Section 12.2)。最初の Initial は Handshake と連結できる場合だけ
        // 1 つのデータグラムにし、残りのパケットは個別のデータグラムとして
        // 送信順序どおりに積む。
        let first_initial = if initial_packets.is_empty() {
            None
        } else {
            Some(initial_packets.remove(0))
        };
        if let Some(mut initial) = first_initial {
            if let Some(assumed_handshake_len) = first_initial_coalesces
                && let Some(handshake) = handshake_packets.first()
            {
                // emit_initial_bytes が合計長を上限内に収め、データグラムが
                // 1200 バイト以上になるよう PADDING を済ませている。
                // 連結対象が前提とした長さであることを debug ビルドで確認する。
                debug_assert_eq!(
                    handshake.len(),
                    assumed_handshake_len,
                    "coalescing assumption must match the handshake packet length"
                );
                initial.extend_from_slice(handshake);
                handshake_packets.remove(0);
            }
            // Initial のパディング量と連結可否は emit_initial_bytes が上限と
            // 最小サイズを満たすよう決めている。
            self.output_queue
                .push_front(self.make_send_datagram(initial, PathId::INITIAL));
        }
        for packet in initial_packets {
            self.output_queue
                .push_back(self.make_send_datagram(packet, PathId::INITIAL));
        }
        for packet in handshake_packets {
            self.output_queue
                .push_back(self.make_send_datagram(packet, PathId::INITIAL));
        }

        // 構築した 0-RTT は必ず出力キューへ積む。フレームの書き込みで送信位置が
        // 進んでいるため、ここで積み忘れるとデータだけが失われる。
        if let Some(pending) = zero_rtt {
            self.queue_zero_rtt_datagram(pending, now);
        }

        if self.role == Role::Server
            && self.state == ConnectionState::Connected
            && !self.handshake_done_sent
            && self.one_rtt_keys.is_some()
        {
            self.emit_1rtt_handshake_done(now)?;
        }
        // クライアントの確認応答は HANDSHAKE_DONE の受信前も送る
        // (RFC 9000 Section 13.2)。サーバーは TLS 完了前の 1-RTT を受理しない。
        // 完了通知が失われた場合も ACK で損失検出を進め、ハンドシェイクの停滞を防ぐ。
        if self.one_rtt_keys.is_some() {
            self.emit_1rtt_path_acks(now)?;
        }
        // PATH_RESPONSE 送信: 受信した PATH_CHALLENGE に応答する。
        // RFC 9000 Section 8.2.2 は PATH_CHALLENGE への応答を MUST とする。
        // ハンドシェイク確認前でも 1-RTT 鍵があれば応答する。
        if self.one_rtt_keys.is_some() {
            self.emit_1rtt_path_responses(now)?;
        }
        // PATH_CHALLENGE 送信: ピア CID の到着待ちで保留していたものを送る
        if self.one_rtt_keys.is_some() && self.state == ConnectionState::Connected {
            self.emit_1rtt_path_challenges(now)?;
        }
        // 制御フレームと STREAM データ送信: 制御フレームを優先してパケット化する
        if self.one_rtt_keys.is_some() && self.state == ConnectionState::Connected {
            self.emit_1rtt_data(now)?;
        }
        // DATAGRAM フレーム送信 (RFC 9221 Section 5)
        if self.one_rtt_keys.is_some() && self.state == ConnectionState::Connected {
            self.emit_1rtt_datagrams(now)?;
        }
        // ハンドシェイク確認前の PTO では、経路検証用の CID を先に送る
        if self.pre_confirmation_cids_pending && self.one_rtt_keys.is_some() {
            self.emit_pre_confirmation_cids(now)?;
            self.pre_confirmation_cids_pending = false;
        }
        // PTO プローブ送信: PTO 発火したパスに ack-eliciting パケットを送信する
        if self.one_rtt_keys.is_some() && !self.pto_probe_paths.is_empty() {
            self.emit_pto_probes(now)?;
        }

        // DPLPMTUD プローブ送信 (RFC 8899)
        if self.one_rtt_keys.is_some() && self.state == ConnectionState::Connected {
            self.emit_pmtu_probes(now)?;
        }

        // 鍵廃棄 (RFC 9001 Section 4.9.1)
        //
        // - クライアント: 最初の Handshake パケットを送信した時点で Initial 鍵を破棄する。
        // - サーバー: 最初の Handshake パケットを正常に処理した時点で破棄する。
        //   Handshake 鍵を得ただけ (ServerHello 送信時) で破棄すると、
        //   ServerHello のロストでハンドシェイクが停止する。
        let initial_keys_unused = match self.role {
            Role::Client => {
                self.handshake_keys.is_some()
                    && self.handshake_send_pn > 0
                    && self.crypto_send_initial.is_empty()
                    && self.crypto_retransmit_initial.is_empty()
            }
            Role::Server => self.initial_handshake_processed,
        };
        if initial_keys_unused && self.initial_keys.is_some() {
            self.discard_initial_keys();
        }

        // 全パスの損失検出タイマー設定 (RFC 9002 Section 6.2.1 / Appendix A.8)
        //
        // パケット番号空間ごとに time threshold loss time と PTO 期限を計算し、
        // パスごとに最も早い (空間, 期限) の組を 1 つのタイマーとして設定する。
        let path_ids: Vec<PathId> = self.paths.all_paths().map(|path| path.id).collect();
        for path_id in path_ids {
            if let Some((space, deadline)) = self.loss_detection_timer(path_id, now) {
                self.set_loss_detection_timer(path_id, space, deadline);
            } else {
                // 時間閾値タイマーも PTO も無い、またはサーバーがアンチアンプリ
                // フィケーション制限で送信できない間はタイマーを破棄する
                // (RFC 9002 Section 6.2.2.1 MUST NOT)。
                self.clear_loss_detection_timer(path_id);
            }
        }

        Ok(())
    }

    /// Initial パケットのバイト列を構築する (aws-lc-rs ベース)
    ///
    /// コアレシング対応: SendDatagram に直接 push せず、バイト列を返す。
    /// `coalesce_hint` に最初の Handshake パケット長が渡された場合、その
    /// パケットと 1 つのデータグラムに連結できるかを判断し、データグラムが
    /// 1200 バイト以上になるよう Initial のペイロードへ PADDING を含める
    /// (RFC 9000 Section 14.1)。戻り値の `Option<usize>` は、連結を前提に
    /// パディングした場合の Handshake パケット長 (連結しない場合は None) で
    /// ある。呼び出し側はこの長さのパケットを連結しなければならない。
    fn emit_initial_bytes(
        &mut self,
        _now: Timestamp,
        coalesce_hint: Option<usize>,
    ) -> Result<(Vec<u8>, Option<usize>), Error> {
        let ik = self
            .initial_keys
            .as_ref()
            .ok_or_else(|| Error::InvalidData("no initial keys".into()))?;

        // Initial パケット番号空間 (RFC 9000 Section 12.3)
        // 送信パケット番号が 2^62-1 に達したら接続を閉じる (RFC 9000 Section 12.3 MUST)
        if self.initial_send_pn >= number::MAX_PACKET_NUMBER {
            self.close_on_send_pn_limit();
            return Ok((Vec::new(), None));
        }
        let pn = self.initial_send_pn;
        let pn_len = number::encode_length(pn, self.initial_sent_packets.largest_acked);

        // ヘッダ構築 (Length フィールドはパディング量が決まってから書く)
        let first_byte = LongHeader::build_first_byte_with_quic_bit(
            self.version,
            LongPacketType::Initial,
            pn_len,
            self.send_quic_bit_zero(),
        );
        let mut packet = Vec::with_capacity(MIN_INITIAL_DATAGRAM_SIZE);
        packet.push(first_byte);
        packet.extend_from_slice(&self.version.to_be_bytes());
        packet.push(self.peer_cid.len() as u8);
        packet.extend_from_slice(self.peer_cid.as_bytes());
        packet.push(self.local_cid.len() as u8);
        packet.extend_from_slice(self.local_cid.as_bytes());
        // Token フィールド (RFC 9000 Section 17.2.2)
        // Retry トークンが優先、なければ NEW_TOKEN で受信したアドレス検証トークンを使用する
        let token = if !self.retry_token.is_empty() {
            &self.retry_token
        } else {
            &self.address_token
        };
        VarInt::try_from(token.len() as u64)
            .expect("token length fits in 62-bit varint")
            .encode_to_vec(&mut packet);
        packet.extend_from_slice(token);
        // Length フィールドより前のバイト数
        let fixed_len = packet.len();

        // ACK を先に生成し、符号化長を確定させてから CRYPTO の切り出し量を決める。
        let ack = self.initial_ack_tracker.generate_ack(0);
        let ack_len = ack.as_ref().map_or(0, |ack| {
            let mut encoded = Vec::new();
            Frame::Ack(ack.clone()).encode(&mut encoded);
            encoded.len()
        });

        // ペイロード構築
        // 1 つの Initial パケットは最小データグラム長 (1200) に収める。
        // CRYPTO データが収まらない場合は切り出して残りを送信待ちに戻す。
        let mut payload = Vec::new();
        let mut frames = Vec::new();
        let mut crypto_field: Option<(u64, usize)> = None;
        // Initial の CRYPTO 再送を優先し、送信時の offset を維持する。
        if let Some((offset, data)) = self.crypto_retransmit_initial.front().cloned() {
            let capacity = Self::long_packet_crypto_capacity(
                fixed_len,
                pn_len as usize,
                INITIAL_AEAD_TAG_LEN,
                ack_len,
                offset,
                MIN_INITIAL_DATAGRAM_SIZE,
            );
            let send_len = data.len().min(capacity);
            if send_len > 0 {
                self.crypto_retransmit_initial.pop_front();
                if send_len < data.len() {
                    // 1 パケットに収まらない場合は先頭部分を送り、残りを
                    // 元の offset の続きとして再送待ちへ戻す。新規データを
                    // 先に送って再送を遅らせない。
                    self.crypto_retransmit_initial
                        .push_front((offset + send_len as u64, data[send_len..].to_vec()));
                }
                Frame::Crypto(frame::crypto::Crypto {
                    offset: VarInt::new(offset).expect("value fits in 62-bit varint"),
                    data: data[..send_len].to_vec(),
                })
                .encode(&mut payload);
                frames.push(SentFrameInfo::Crypto {
                    offset,
                    length: send_len,
                });
                crypto_field = Some((offset, send_len));
            }
        }
        if crypto_field.is_none()
            && self.crypto_retransmit_initial.is_empty()
            && !self.crypto_send_initial.is_empty()
        {
            let offset = self.crypto_send_initial_offset;
            let capacity = Self::long_packet_crypto_capacity(
                fixed_len,
                pn_len as usize,
                INITIAL_AEAD_TAG_LEN,
                ack_len,
                offset,
                MIN_INITIAL_DATAGRAM_SIZE,
            );
            let send_len = self.crypto_send_initial.len().min(capacity);
            if send_len > 0 {
                // 送信した Initial CRYPTO の範囲をすべて保持する。初回フライト
                // だけでなく、HRR 後の 2 通目の ClientHello のように後から
                // offset が進むデータも追記する。PTO の全体再送ではこれを
                // 先頭から送り直し、部分再送では元の offset で送る。
                let sent_end = offset as usize + send_len;
                if self.crypto_sent_initial.len() < sent_end {
                    self.crypto_sent_initial
                        .extend_from_slice(&self.crypto_send_initial[..send_len]);
                }
                let send_data: Vec<u8> = self.crypto_send_initial.drain(..send_len).collect();
                self.crypto_send_initial_offset += send_len as u64;
                Frame::Crypto(frame::crypto::Crypto {
                    offset: VarInt::new(offset).expect("value fits in 62-bit varint"),
                    data: send_data,
                })
                .encode(&mut payload);
                frames.push(SentFrameInfo::Crypto {
                    offset,
                    length: send_len,
                });
                crypto_field = Some((offset, send_len));
            }
        }
        if let Some(ack) = ack {
            // Initial 空間の qlog は SentFrameInfo から packet_sent を作るため、
            // qlog 有効時だけ生成した ACK の実レンジを保持する
            // (qlog-quic-events-13 Section 8.13.3)。
            frames.push(sent_ack_info(&ack, self.qlog_writer.is_some()));
            Frame::Ack(ack).encode(&mut payload);
        }
        // RFC 9000 Section 12.4: フレームを 1 つも含まないパケットは送信しては
        // ならない。CRYPTO も ACK も無い場合はパケット番号を消費せずに戻る。
        // ただし anti-deadlock の PTO プローブ待ちなら PING を載せて
        // ack-eliciting なパケットにする (RFC 9002 Section 6.2.4 MUST)。
        let initial_probe_pending = self.initial_pto_probes_pending > 0;
        if frames.is_empty() && !initial_probe_pending {
            return Ok((Vec::new(), None));
        }
        if initial_probe_pending
            && !frames
                .iter()
                .any(|frame| !matches!(frame, SentFrameInfo::Ack { .. }))
        {
            // ACK のみのパケットは ack-eliciting ではないため、probe として
            // 送れない。PING を追加して probe の条件を満たす。
            Frame::Ping(frame::ping::Ping).encode(&mut payload);
            frames.push(SentFrameInfo::Other);
        }

        // PADDING 量を決める (RFC 9000 Section 14.1)。
        // - 最初の Handshake パケットと連結できる場合は、データグラムが 1200
        //   バイト以上になる最小の長さまで Initial をパディングする。
        // - 連結しない場合は、クライアントの Initial を含むデータグラムと
        //   サーバーの ack-eliciting Initial を含むデータグラムを 1200 バイト
        //   以上にする。
        let unpadded_len = Self::long_packet_len(
            fixed_len,
            pn_len as usize,
            INITIAL_AEAD_TAG_LEN,
            ack_len,
            crypto_field,
        );
        let ack_eliciting = frames
            .iter()
            .any(|frame| !matches!(frame, SentFrameInfo::Ack { .. }));
        let requires_min_datagram = self.role == Role::Client || ack_eliciting;
        let limit = self.long_packet_send_limit();
        // 単独のデータグラムとして送る場合の必要最小長
        let min_total = if requires_min_datagram {
            MIN_INITIAL_DATAGRAM_SIZE
        } else {
            0
        };
        let (mut target_len, mut length_field_size) = Self::long_packet_padded_len(
            fixed_len,
            pn_len as usize,
            INITIAL_AEAD_TAG_LEN,
            payload.len(),
            unpadded_len.max(min_total),
        );
        let mut coalesced: Option<usize> = None;
        if let Some(handshake_len) = coalesce_hint {
            // 連結したデータグラムを 1200 バイト以上にするために必要な長さまで
            // Initial を伸ばす。PADDING は Initial の暗号化より前に含める。
            let (coalesce_len, coalesce_field_size) = Self::long_packet_padded_len(
                fixed_len,
                pn_len as usize,
                INITIAL_AEAD_TAG_LEN,
                payload.len(),
                unpadded_len.max(MIN_INITIAL_DATAGRAM_SIZE.saturating_sub(handshake_len)),
            );
            if coalesce_len + handshake_len <= limit {
                target_len = coalesce_len;
                length_field_size = coalesce_field_size;
                coalesced = Some(handshake_len);
            }
        }
        let length_value = target_len - fixed_len - length_field_size;
        debug_assert_eq!(
            VarInt::new(length_value as u64)
                .expect("packet length fits in 62-bit varint")
                .encoded_size(),
            length_field_size,
            "Length field size must match the target packet length"
        );
        VarInt::try_from(length_value as u64)
            .expect("packet length fits in 62-bit varint")
            .encode_to_vec(&mut packet);
        // PADDING は暗号化と送信記録より前にペイロードへ含める。0x00 は
        // PADDING フレームである (RFC 9000 Section 19.1)。
        let padded_payload_len = length_value - pn_len as usize - INITIAL_AEAD_TAG_LEN;
        debug_assert!(
            payload.len() <= padded_payload_len,
            "padded payload must not be shorter than the encoded frames"
        );
        payload.resize(padded_payload_len, 0);
        self.initial_send_pn += 1;
        self.initial_pto_probes_pending = self.initial_pto_probes_pending.saturating_sub(1);

        // パケット番号
        let pn_offset = packet.len();
        let mut pn_buf = [0u8; 4];
        number::encode(pn, pn_len, &mut pn_buf)?;
        packet.extend_from_slice(&pn_buf[..pn_len as usize]);

        // AEAD 暗号化 (aws-lc-rs)
        let aad = packet.clone();
        let pn_nonce = nonce::compute_nonce(ik.send.aead.iv(), pn);
        protection::encrypt_payload(&ik.send.aead, &pn_nonce, &aad, &mut payload)?;
        packet.extend_from_slice(&payload);

        // Header Protection 適用 (aws-lc-rs)
        protection::apply_header_protection(&mut packet, pn_offset, pn_len, &ik.send.hp)?;

        // qlog: packet_sent (Initial)
        let time_ms = self.qlog_time_ms();
        let ack_delay_exponent = self.local_ack_delay_exponent();
        if let Some(writer) = self.qlog_writer.as_mut() {
            let qlog_header = qlog::PacketHeader {
                packet_type: qlog::PacketType::Initial,
                packet_number: pn,
                dcid: qlog::cid_to_hex(&self.peer_cid),
                scid: Some(qlog::cid_to_hex(&self.local_cid)),
                version: Some(format!("{:08x}", self.version)),
                length: Some(packet.len()),
            };
            // ACK Delay は送信側 (= ローカル) の ack_delay_exponent で ms に
            // 変換する (RFC 9000 Section 19.3)。
            let qlog_frames: Vec<qlog::QlogFrame> = frames
                .iter()
                .filter_map(|info| sent_frame_to_qlog(info, ack_delay_exponent))
                .collect();
            writer.on_packet_sent(time_ms, &qlog_header, &qlog_frames, packet.len());
        }
        // 観測イベント: パケット送信
        self.observe(ConnectionObservationEvent::PacketSent {
            path_id: PathId::INITIAL,
            packet_number: pn,
            size: packet.len(),
        });

        // 輻輳制御と損失検出に送信を通知する
        // 送信済みパケットは Initial PN 空間に記録する (RFC 9000 Section 12.3)
        let sent_bytes = packet.len() as u64;
        // ACK のみのパケットは ack-eliciting でも in-flight でもない
        // (RFC 9000 Section 12.4 / RFC 9002 Section 2)。
        let ack_eliciting = frames
            .iter()
            .any(|frame| !matches!(frame, SentFrameInfo::Ack { .. }));
        let path = self.paths.initial_path_mut();
        // ACK のみのパケットは in-flight ではないため輻輳制御に算入しない
        // (RFC 9002 Section 2 / Section 7)。算入すると ACK 専用パケットが
        // 輻輳ウィンドウを消費し、回収されないまま送信が停止する。
        if ack_eliciting {
            path.congestion.on_packet_sent(sent_bytes);
            path.congestion.on_packet_sent_cc_unpaced(
                PacketNumberSpace::Initial,
                pn,
                sent_bytes,
                _now,
            );
        }
        path.loss_detectors
            .on_packet_sent(PacketNumberSpace::Initial, _now, ack_eliciting);
        path.record_sent(_now);
        self.initial_sent_packets.record(SentPacket {
            pn,
            time_sent: _now,
            ack_eliciting,
            in_flight: ack_eliciting,
            sent_bytes,
            frames,
            // Initial / Handshake は ECN 検証対象外 (本実装では 1-RTT のみ)
            ecn: EcnCodepoint::NotEct,
        });

        Ok((packet, coalesced))
    }

    /// 0-RTT パケットのバイト列を構築する (rustls ベース)
    ///
    /// クライアントのみ。セッション再開時に 0-RTT 鍵でストリームデータを送信する。
    /// Application PN 空間を 1-RTT と共有する (RFC 9000 Section 12.3)。
    ///
    /// パケット全体 (Long Header、PN、Length、AEAD タグ) が輻輳窓の残量と PMTU に
    /// 収まる範囲でだけフレームを書き込む。収まらないデータ、制御フレーム、FIN は
    /// 送信バッファに残し、ACK などで枠が戻った後の送信機会に回す。
    ///
    /// この関数は出力キューへ積まない。パケット番号・`bytes_in_flight`・損失検出は
    /// 進めず、返したパケットを出力キューへ積む
    /// [`Self::queue_zero_rtt_datagram`] が送信会計を確定する。
    fn emit_zero_rtt_bytes(&mut self) -> Result<Option<PendingZeroRttPacket>, Error> {
        // Application PN 空間 (1-RTT と共有) の送信パケット番号が上限に達したら
        // 接続を閉じる (RFC 9000 Section 12.3 MUST)
        if self.paths.initial_path().send_pn >= number::MAX_PACKET_NUMBER {
            self.close_on_send_pn_limit();
            return Ok(None);
        }

        let zk = self
            .zero_rtt_keys
            .as_ref()
            .ok_or_else(|| Error::InvalidData("no 0-RTT keys".into()))?;

        // Application PN 空間 (1-RTT と共有、初期パスで送信)
        let pn = self.paths.initial_path().send_pn;
        let largest_acked = self.paths.initial_path().sent_packets.largest_acked;
        let pn_len = number::encode_length(pn, largest_acked);

        // RFC 9002 Section 7: bytes_in_flight が輻輳窓を超える送信は、PTO 発火と
        // Recovery 進入時 (Section 7.3.2) の例外を除いて禁止される (MUST NOT)。
        // 0-RTT の通常送信はどちらの例外にも該当しないため、回復開始直後の
        // 1 パケット分を含む `available_window()` は使わず、窓と in-flight の
        // 差をそのまま予算にする。ここで例外分を許すと、送信直後に
        // bytes_in_flight が輻輳窓を超える。
        // 併せて 1 パケットが PMTU を超えないよう、小さい方を予算とする
        // (RFC 9000 Section 14.2)。
        let tag_len = zk.packet.tag_len();
        // 0-RTT Long Header は Token フィールドを持たない。
        // first_byte(1) + version(4) + dcid_len(1) + dcid + scid_len(1) + scid
        let fixed_header_len = 1 + 4 + 1 + self.peer_cid.len() + 1 + self.local_cid.len();
        let fixed_without_payload = fixed_header_len + pn_len as usize + tag_len;
        let packet_budget = {
            let path = self.paths.initial_path();
            let congestion_budget = path
                .congestion
                .congestion_window()
                .saturating_sub(path.congestion.bytes_in_flight());
            // 前回のセッションで記憶したピアの max_udp_payload_size を超えない
            // ようにする (RFC 9000 Section 7.4.1)。ハンドシェイクで得た今回の
            // 確定値は 1-RTT にだけ適用し、0-RTT の送信には使わない。
            let early_limit = self
                .early_peer_params
                .as_ref()
                .map(|params| params.max_udp_payload_size)
                .unwrap_or(u64::from(tobi_core::path::mtu::MAX_UDP_PAYLOAD));
            // PMTU は u16 なので、記憶値との最小値を取れば usize に収まる
            congestion_budget.min(u64::from(path.pmtu)).min(early_limit) as usize
        };
        // Length フィールドの VarInt すら収まらない場合は、フレームを 1 つも
        // 書かずに送信を保留する。送信バッファは変更しない。
        if packet_budget <= fixed_without_payload + 1 {
            return Ok(None);
        }
        // ペイロード長の最大値を求める。Length フィールドの VarInt 長は Length
        // の値そのものに依存するため、まず 1 バイトと仮定して残りをすべて
        // ペイロードへ充て、実際の VarInt 長が 2 バイト以上ならその差
        // (`length_size - 1`) を一度だけ差し引く。差し引いた結果 Length が
        // 下位の VarInt 長へ戻る境界では最大 2 バイト使わずに送るが、予算を
        // 超えることはない。
        //
        // PMTU が u16 であるため Length は最大でも 4 バイト VarInt に収まり、
        // 差し引きは 1 回で足りる。将来 PMTU が u16 を超える設計にする場合は、
        // 差し引きが収束するまで繰り返す必要がある。
        let mut max_payload = packet_budget - fixed_without_payload - 1;
        let length_value = pn_len as usize + max_payload + tag_len;
        let length_size = VarInt::try_from(length_value as u64)
            .expect("0-RTT packet length fits in a 62-bit varint")
            .encoded_size();
        if length_size > 1 {
            max_payload -= length_size - 1;
        }
        // ヘッダー保護は PN オフセットの 4 バイト後からサンプル長
        // (現在の AEAD では 16 バイト) を読む。短い制御フレームだけのパケットでも
        // サンプルを確保できるよう、必要な最小ペイロード長を求めておく。
        // 満たせない予算では送信を保留し、制御フレームを送信キューに残す。
        let sample_len = zk.header.sample_len();
        let hp_min_payload = (4 + sample_len).saturating_sub(pn_len as usize + tag_len);
        if max_payload < hp_min_payload {
            return Ok(None);
        }

        // ペイロード構築: 0-RTT で許可されるフレームのみを書く
        // (RFC 9000 Section 12.4 Table 3)。
        let mut payload_frames = Vec::new();
        let mut frames = Vec::new();

        // 制御フレームを先に書く。RESET_STREAM_AT を 0-RTT で送れるように
        // することで、記憶した広告に基づく 0-RTT 利用を実現する
        // (draft-ietf-quic-reliable-stream-reset-11 Section 3)。
        //
        // 0-RTT では記憶したフロー制御上限が適用される。上限を超える
        // リセットフレームは送信を延期する (同 Section 4)。
        let pending_count = self.streams.pending_frames.len();
        for _ in 0..pending_count {
            let Some(control_frame) = self.streams.pending_frames.pop_front() else {
                break;
            };
            if !is_control_frame_allowed_in_zero_rtt(&control_frame) {
                self.streams.pending_frames.push_front(control_frame);
                break;
            }
            if !self.streams.reset_frame_fits_flow_control(&control_frame) {
                self.streams.pending_frames.push_back(control_frame);
                continue;
            }
            let mut tmp = Vec::new();
            control_frame.encode(&mut tmp);
            if payload_frames.len() + tmp.len() > max_payload {
                self.streams.pending_frames.push_front(control_frame);
                break;
            }
            payload_frames.extend_from_slice(&tmp);
            // 0-RTT は初期パスでのみ送信するため、送信パスは初期パスとする。
            frames.push(sent_frame_info_for_control(&control_frame, PathId::INITIAL));
        }

        // ストリームフレームを書き込む。max_payload を超えるデータは
        // 送信バッファに残る (FIN の位置も変えない)。
        let stream_outs = self
            .streams
            .write_stream_frames(&mut payload_frames, max_payload);
        for so in &stream_outs {
            frames.push(SentFrameInfo::Stream {
                stream_id: so.stream_id,
                offset: so.offset,
                length: so.length,
                fin: so.fin,
                retransmission_count: so.retransmission_count,
            });
        }

        // 送信データがなければパケット番号を消費せずに戻る
        if payload_frames.is_empty() {
            return Ok(None);
        }
        // 短い制御フレームだけの場合でもヘッダー保護のサンプル長を確保する。
        // PADDING はフレーム列の末尾に置き、Length に含める。
        if payload_frames.len() < hp_min_payload {
            payload_frames.resize(hp_min_payload, 0);
        }

        // ヘッダ構築 (0-RTT は Token フィールドがない)
        let first_byte = LongHeader::build_first_byte_with_quic_bit(
            self.version,
            LongPacketType::ZeroRtt,
            pn_len,
            self.send_quic_bit_zero(),
        );
        let mut packet = Vec::with_capacity(1200);
        packet.push(first_byte);
        packet.extend_from_slice(&self.version.to_be_bytes());
        packet.push(self.peer_cid.len() as u8);
        packet.extend_from_slice(self.peer_cid.as_bytes());
        packet.push(self.local_cid.len() as u8);
        packet.extend_from_slice(self.local_cid.as_bytes());

        // Length フィールド
        let total = pn_len as usize + payload_frames.len() + tag_len;
        VarInt::try_from(total as u64)
            .expect("0-RTT packet length fits in a 62-bit varint")
            .encode_to_vec(&mut packet);

        // パケット番号
        let pn_offset = packet.len();
        let mut pn_buf = [0u8; 4];
        number::encode(pn, pn_len, &mut pn_buf)?;
        packet.extend_from_slice(&pn_buf[..pn_len as usize]);

        // AEAD 暗号化 (rustls)
        //
        // ここで失敗するとフレームの書き込みで進めたストリームの送信位置だけが
        // 残る。黙ってエラーを返さず接続を閉じ、失われたデータを再送しないことを
        // 呼び出し側へ明示する。予算超過時と同じ扱いに揃える。
        let aad = &packet;
        let encrypt_result = {
            let zk = self
                .zero_rtt_keys
                .as_ref()
                .expect("0-RTT keys are checked before building the packet");
            zk.packet.encrypt_in_place(pn, aad, &mut payload_frames)
        };
        let tag = match encrypt_result {
            Ok(tag) => tag,
            Err(_) => {
                let error = Error::InvalidData("0-RTT encryption failed".into());
                self.close_on_output_error(&error);
                return Err(error);
            }
        };
        packet.extend_from_slice(&payload_frames);
        packet.extend_from_slice(tag.as_ref());

        // Header Protection 適用 (rustls)
        //
        // 暗号化と同じく、失敗時は送信位置だけが進むため接続を閉じる。
        let hp_result = {
            let zk = self
                .zero_rtt_keys
                .as_ref()
                .expect("0-RTT keys are checked before building the packet");
            apply_hp_rustls(&mut packet, pn_offset, pn_len, &*zk.header, true)
        };
        if let Err(error) = hp_result {
            self.close_on_output_error(&error);
            return Err(error);
        }

        // フレームの書き込み側が max_payload を守るため、この検査には通常
        // 到達しない。到達した場合は輻輳窓または PMTU を超えるデータグラムを
        // 送ることになる。データを消費したまま黙ってエラーを返すと送信位置だけが
        // 進むため、接続を閉じて以降の送信を止める
        // (RFC 9002 Section 7 / RFC 9000 Section 14.2)。
        //
        // 同じ不変条件を `debug_assert!` でも検査すると二重防御になり、
        // release ビルドだけ経路が変わる。ここでは予算計算の将来の変更に
        // 対しても安全側に倒すため、release でも動く実行時検査の一本に絞る。
        if packet.len() > packet_budget {
            let error =
                Error::InvalidData("0-RTT packet exceeds the congestion or PMTU budget".into());
            self.close_on_output_error(&error);
            return Err(error);
        }

        Ok(Some(PendingZeroRttPacket {
            bytes: packet,
            pn,
            frames,
        }))
    }

    /// 0-RTT パケットを単独のデータグラムとして出力キューへ積み、送信会計を確定する
    ///
    /// 出力キューへ積んだ後にだけ、パケット番号・`bytes_in_flight`・損失検出・
    /// 送信済みパケットの記録を更新する。`emit_zero_rtt_bytes` が構築した時点では
    /// まだ送信していないため、そこで進めてはならない。
    fn queue_zero_rtt_datagram(&mut self, pending: PendingZeroRttPacket, now: Timestamp) {
        let PendingZeroRttPacket { bytes, pn, frames } = pending;
        // 輻輳制御へ通知するバイト数は実際に積むデータグラム長から求める。
        let sent_bytes = bytes.len() as u64;
        // qlog: packet_sent (0-RTT)
        let time_ms = self.qlog_time_ms();
        let ack_delay_exponent = self.local_ack_delay_exponent();
        if let Some(writer) = self.qlog_writer.as_mut() {
            let qlog_header = qlog::PacketHeader {
                packet_type: qlog::PacketType::ZeroRtt,
                packet_number: pn,
                dcid: qlog::cid_to_hex(&self.peer_cid),
                scid: Some(qlog::cid_to_hex(&self.local_cid)),
                version: Some(format!("{:08x}", self.version)),
                length: Some(sent_bytes as usize),
            };
            let qlog_frames: Vec<qlog::QlogFrame> = frames
                .iter()
                .filter_map(|info| sent_frame_to_qlog(info, ack_delay_exponent))
                .collect();
            writer.on_packet_sent(time_ms, &qlog_header, &qlog_frames, sent_bytes as usize);
        }
        self.output_queue
            .push_back(self.make_send_datagram(bytes, PathId::INITIAL));

        // 0-RTT 送信フラグを設定する (拒否時フォールバック用)
        self.zero_rtt_sent = true;
        // 拒否後に 0-RTT パケットへの ACK を受けた場合の違反検出用に
        // 送信したパケット番号の範囲を記録する (RFC 9001 Section 4.6.2)。
        self.zero_rtt_sent_pn_range = Some(match self.zero_rtt_sent_pn_range {
            Some((min, max)) => (min, max.max(pn)),
            None => (pn, pn),
        });

        // RESET_STREAM_AT は実際に送信した時点で送信済みにする
        // (draft-ietf-quic-reliable-stream-reset-11 Section 5.3)。
        for info in &frames {
            if let SentFrameInfo::ResetStreamAt { stream_id, .. } = info {
                self.streams.mark_reset_stream_at_sent(*stream_id);
            }
        }

        // PN をインクリメントする
        let path = self.paths.initial_path_mut();
        path.send_pn += 1;

        // 輻輳制御と損失検出に通知する
        path.congestion.on_packet_sent(sent_bytes);
        path.congestion.on_packet_sent_cc_unpaced(
            PacketNumberSpace::ApplicationData,
            pn,
            sent_bytes,
            now,
        );
        path.loss_detectors
            .on_packet_sent(PacketNumberSpace::ApplicationData, now, true);
        path.record_sent(now);
        path.sent_packets.record(SentPacket {
            pn,
            time_sent: now,
            ack_eliciting: true,
            in_flight: true,
            sent_bytes,
            frames,
            // 0-RTT も ECN 検証対象外 (本実装では 1-RTT のみ検証する)
            ecn: EcnCodepoint::NotEct,
        });
    }

    /// Handshake パケットのバイト列を構築する (rustls ベース)
    ///
    /// コアレシング対応: SendDatagram に直接 push せず、バイト列を返す。
    /// 1 つのパケットは Initial / Handshake を運ぶ UDP データグラムの実効上限
    /// ([`Self::long_packet_send_limit`]) に収める。CRYPTO データが収まらない
    /// 場合は切り出して残りを送信待ちに戻す (RFC 9000 Section 14.2)。
    fn emit_handshake_bytes(&mut self, _now: Timestamp) -> Result<Vec<u8>, Error> {
        if self.handshake_keys.is_none() {
            return Ok(Vec::new());
        }

        // Handshake パケット番号空間 (RFC 9000 Section 12.3)
        // 送信パケット番号が 2^62-1 に達したら接続を閉じる (RFC 9000 Section 12.3 MUST)
        if self.handshake_send_pn >= number::MAX_PACKET_NUMBER {
            self.close_on_send_pn_limit();
            return Ok(Vec::new());
        }
        let pn = self.handshake_send_pn;
        let pn_len = number::encode_length(pn, self.handshake_sent_packets.largest_acked);
        let limit = self.long_packet_send_limit();
        let tag_len = self
            .handshake_keys
            .as_ref()
            .expect("handshake keys are present")
            .local_packet
            .tag_len();

        let first_byte = LongHeader::build_first_byte_with_quic_bit(
            self.version,
            LongPacketType::Handshake,
            pn_len,
            self.send_quic_bit_zero(),
        );
        let mut packet = Vec::with_capacity(MIN_INITIAL_DATAGRAM_SIZE);
        packet.push(first_byte);
        packet.extend_from_slice(&self.version.to_be_bytes());
        packet.push(self.peer_cid.len() as u8);
        packet.extend_from_slice(self.peer_cid.as_bytes());
        packet.push(self.local_cid.len() as u8);
        packet.extend_from_slice(self.local_cid.as_bytes());
        // Length フィールドより前のバイト数
        let fixed_len = packet.len();

        // RFC 9000 Section 13.2.1: Handshake 空間で ack-eliciting パケットを
        // 受信したら、次の送信機会に ACK を乗せる。ACK は CRYPTO より先に置く。
        // ECN カウントは Handshake 空間の AckTracker が保持する累計を載せる
        // (RFC 9000 Section 13.4.1)。
        //
        // クライアントは自分の Finished を送った後もサーバーの Handshake フライトを
        // ACK する必要がある (RFC 9000 Section 13.2.1)。Finished と ACK は同じ
        // Handshake パケットに相乗りさせ、サーバーが Finished を処理する時点で
        // ACK も処理できるようにする。
        let ack = self.handshake_ack_tracker.generate_ack(0);
        let ack_len = ack.as_ref().map_or(0, |ack| {
            let mut encoded = Vec::new();
            Frame::Ack(ack.clone()).encode(&mut encoded);
            encoded.len()
        });

        // 最初の probe が最後の再送範囲を消費した場合も、2 個目には
        // 未確認の CRYPTO を含める。PING だけでは失われた Finished を補えず、
        // 相手の短いハンドシェイク待機時間を越えることがある。
        if self.handshake_pto_probes_pending > 0
            && self.crypto_retransmit_handshake.is_empty()
            && self.crypto_send_handshake.is_empty()
        {
            let outstanding = self.handshake_sent_packets.iter().find_map(|packet| {
                packet.frames.iter().find_map(|frame| match frame {
                    SentFrameInfo::Crypto { offset, length } => Some((*offset, *length)),
                    _ => None,
                })
            });
            if let Some((offset, length)) = outstanding
                && let Ok(start) = usize::try_from(offset)
                && let Some(end) = start.checked_add(length)
                && let Some(data) = self.crypto_sent_handshake.get(start..end)
            {
                self.queue_handshake_crypto_retransmit(offset, data.to_vec());
            }
        }
        // CRYPTO は再送待ちを優先し、無ければ未送信の新規データを送る。
        // 新規データを分割しても `crypto_send_handshake_offset` は巻き戻さない。
        let crypto_state = if let Some((offset, data)) = self.crypto_retransmit_handshake.front() {
            Some((*offset, data.len(), true))
        } else if !self.crypto_send_handshake.is_empty() {
            Some((
                self.crypto_send_handshake_offset,
                self.crypto_send_handshake.len(),
                false,
            ))
        } else {
            None
        };

        let mut payload_frames = Vec::new();
        let mut frames = Vec::new();
        if let Some(ack) = ack {
            // Handshake 空間の qlog は SentFrameInfo から packet_sent を作るため、
            // qlog 有効時だけ生成した ACK の実レンジを保持する
            // (qlog-quic-events-13 Section 8.13.3)。
            frames.push(sent_ack_info(&ack, self.qlog_writer.is_some()));
            Frame::Ack(ack).encode(&mut payload_frames);
        }
        let mut crypto_field: Option<(u64, usize)> = None;
        if let Some((offset, available, is_retransmit)) = crypto_state {
            let capacity = Self::long_packet_crypto_capacity(
                fixed_len,
                pn_len as usize,
                tag_len,
                ack_len,
                offset,
                limit,
            );
            let send_len = available.min(capacity);
            if send_len > 0 {
                let send_data = if is_retransmit {
                    // 再送は最初に送ったときと同じ offset で送る。パケットに
                    // 収まらない場合は先頭部分だけを送り、残りを同じ offset の
                    // 続きとして再送待ちへ戻す (RFC 9001 Section 4.9、
                    // RFC 9000 Section 19.6)。
                    let (queued_offset, mut queued_data) = self
                        .crypto_retransmit_handshake
                        .pop_front()
                        .expect("retransmit queue is not empty");
                    debug_assert_eq!(queued_offset, offset);
                    if send_len < queued_data.len() {
                        let remaining = queued_data.split_off(send_len);
                        self.crypto_retransmit_handshake
                            .push_front((offset + send_len as u64, remaining));
                    }
                    queued_data
                } else {
                    debug_assert_eq!(offset, self.crypto_send_handshake_offset);
                    let send_data: Vec<u8> = self.crypto_send_handshake.drain(..send_len).collect();
                    self.crypto_send_handshake_offset += send_len as u64;
                    // 再送用に送信済みデータを保持する。新規データは offset 0
                    // から連続で送るため、末尾への追加で連続性が保たれる。
                    self.crypto_sent_handshake.extend_from_slice(&send_data);
                    send_data
                };
                Frame::Crypto(frame::crypto::Crypto {
                    offset: VarInt::new(offset).expect("value fits in 62-bit varint"),
                    data: send_data,
                })
                .encode(&mut payload_frames);
                frames.push(SentFrameInfo::Crypto {
                    offset,
                    length: send_len,
                });
                crypto_field = Some((offset, send_len));
            }
        }
        // RFC 9000 Section 12.4: フレームを 1 つも含まないパケットは送信しては
        // ならない。CRYPTO も ACK も無い場合はパケット番号を消費せずに戻る。
        // ただし anti-deadlock PTO の probe 待ちなら PING を載せて
        // ack-eliciting なパケットにする (RFC 9002 Section 6.2.2.1 MUST)。
        let probe_pending = self.handshake_pto_probes_pending > 0;
        if frames.is_empty() && !probe_pending {
            return Ok(Vec::new());
        }
        if probe_pending
            && !frames
                .iter()
                .any(|frame| !matches!(frame, SentFrameInfo::Ack { .. }))
        {
            // ACK のみのパケットは ack-eliciting ではないため、probe として
            // 送れない。PING を追加して probe の条件を満たす。
            Frame::Ping(frame::ping::Ping).encode(&mut payload_frames);
            frames.push(SentFrameInfo::Other);
        }
        // Header Protection のサンプル (16 バイト) を確保するため、短い
        // ペイロードは PADDING (0x00) で伸ばす。PING だけの probe が該当する。
        let min_payload_with_tag = 4usize.saturating_sub(pn_len as usize) + HP_SAMPLE_LEN;
        if payload_frames.len() + tag_len < min_payload_with_tag {
            let needed = min_payload_with_tag - payload_frames.len() - tag_len;
            payload_frames.resize(payload_frames.len() + needed, 0);
        }
        self.handshake_send_pn += 1;
        // CRYPTO を含むパケットもプローブの 1 個として数える。
        self.handshake_pto_probes_pending = self.handshake_pto_probes_pending.saturating_sub(1);
        // Length フィールド
        let total = pn_len as usize + payload_frames.len() + tag_len;
        debug_assert!(
            crypto_field.is_none()
                || Self::long_packet_len(
                    fixed_len,
                    pn_len as usize,
                    tag_len,
                    ack_len,
                    crypto_field
                ) <= limit,
            "Handshake packet must fit in the datagram limit"
        );
        VarInt::try_from(total as u64)
            .expect("packet length fits in 62-bit varint")
            .encode_to_vec(&mut packet);

        // パケット番号
        let pn_offset = packet.len();
        let mut pn_buf = [0u8; 4];
        number::encode(pn, pn_len, &mut pn_buf)?;
        packet.extend_from_slice(&pn_buf[..pn_len as usize]);

        // AEAD 暗号化 (rustls): encrypt_in_place は payload を in-place で暗号化し Tag を返す
        let aad = packet.clone();
        let hk = self
            .handshake_keys
            .as_ref()
            .expect("handshake keys are present");
        let tag = hk
            .local_packet
            .encrypt_in_place(pn, &aad, &mut payload_frames)
            .map_err(|_| Error::InvalidData("handshake encryption failed".into()))?;
        packet.extend_from_slice(&payload_frames);
        packet.extend_from_slice(tag.as_ref());

        // Header Protection 適用 (rustls)
        let hk = self
            .handshake_keys
            .as_ref()
            .expect("handshake keys are present");
        apply_hp_rustls(&mut packet, pn_offset, pn_len, &*hk.local_header, true)?;

        // qlog: packet_sent (Handshake)
        let time_ms = self.qlog_time_ms();
        let ack_delay_exponent = self.local_ack_delay_exponent();
        if let Some(writer) = self.qlog_writer.as_mut() {
            let qlog_header = qlog::PacketHeader {
                packet_type: qlog::PacketType::Handshake,
                packet_number: pn,
                dcid: qlog::cid_to_hex(&self.peer_cid),
                scid: Some(qlog::cid_to_hex(&self.local_cid)),
                version: Some(format!("{:08x}", self.version)),
                length: Some(packet.len()),
            };
            // ACK Delay は送信側 (= ローカル) の ack_delay_exponent で ms に
            // 変換する (RFC 9000 Section 19.3)。
            let qlog_frames: Vec<qlog::QlogFrame> = frames
                .iter()
                .filter_map(|info| sent_frame_to_qlog(info, ack_delay_exponent))
                .collect();
            writer.on_packet_sent(time_ms, &qlog_header, &qlog_frames, packet.len());
        }
        // 観測イベント: パケット送信
        self.observe(ConnectionObservationEvent::PacketSent {
            path_id: PathId::INITIAL,
            packet_number: pn,
            size: packet.len(),
        });

        // 輻輳制御と損失検出に送信を通知する
        // 送信済みパケットは Handshake PN 空間に記録する (RFC 9000 Section 12.3)
        let sent_bytes = packet.len() as u64;
        // ACK のみのパケットは ack-eliciting でも in-flight でもない
        // (RFC 9000 Section 12.4 / RFC 9002 Section 2)。
        let ack_eliciting = frames
            .iter()
            .any(|frame| !matches!(frame, SentFrameInfo::Ack { .. }));
        let path = self.paths.initial_path_mut();
        // ACK のみのパケットは in-flight ではないため輻輳制御に算入しない
        // (RFC 9002 Section 2 / Section 7)。算入すると ACK 専用パケットが
        // 輻輳ウィンドウを消費し、回収されないまま送信が停止する。
        if ack_eliciting {
            path.congestion.on_packet_sent(sent_bytes);
            path.congestion.on_packet_sent_cc_unpaced(
                PacketNumberSpace::Handshake,
                pn,
                sent_bytes,
                _now,
            );
        }
        path.loss_detectors
            .on_packet_sent(PacketNumberSpace::Handshake, _now, ack_eliciting);
        path.record_sent(_now);
        self.handshake_sent_packets.record(SentPacket {
            pn,
            time_sent: _now,
            ack_eliciting,
            in_flight: ack_eliciting,
            sent_bytes,
            frames,
            // Initial / Handshake は ECN 検証対象外 (本実装では 1-RTT のみ)
            ecn: EcnCodepoint::NotEct,
        });

        Ok(packet)
    }

    /// CONNECTION_CLOSE 単発送信用の Initial パケットを構築する (aws-lc-rs ベース)
    ///
    /// RFC 9000 Section 10.2.3 (Immediate Close during the Handshake): ハンドシェイク
    /// 確定前は保持している鍵レベルで CONNECTION_CLOSE を送る。本メソッドは Initial
    /// 空間の閉鎖パケット 1 個のバイト列を返し、コアレスは呼び出し側が行う。
    ///
    /// `emit_initial_bytes` と異なり以下を行う:
    /// - `crypto_send_initial` / `initial_ack_tracker` を消費しない (CRYPTO / ACK を載せない)
    /// - パケット番号を消費しない (`initial_send_pn` は据え置き)
    /// - `initial_sent_packets` に記録しない (CONNECTION_CLOSE は ack-eliciting でない)
    ///
    /// 再送は `closing_packet` に保存した暗号化済みバイト列をそのまま使うため、
    /// 新しいパケット番号は不要 (RFC 9000 Section 10.2.1)。
    ///
    /// RFC 9000 Section 14.1: クライアントは Initial を含むデータグラムを
    /// 1200 バイト以上に拡張しなければならない (MUST) ため、クライアントの Initial は
    /// パケット単体で 1200 バイト以上になるよう PADDING を載せる。
    fn build_initial_close_bytes(&mut self, frame: &Frame) -> Result<Vec<u8>, Error> {
        let pn = self.initial_send_pn;
        let pn_len = number::encode_length(pn, self.initial_sent_packets.largest_acked);

        // Long Header 構築 (emit_initial_bytes と同型、RFC 9000 Section 17.2.2)
        let first_byte = LongHeader::build_first_byte_with_quic_bit(
            self.version,
            LongPacketType::Initial,
            pn_len,
            self.send_quic_bit_zero(),
        );
        let mut packet = Vec::with_capacity(MIN_INITIAL_DATAGRAM_SIZE);
        packet.push(first_byte);
        packet.extend_from_slice(&self.version.to_be_bytes());
        packet.push(self.peer_cid.len() as u8);
        packet.extend_from_slice(self.peer_cid.as_bytes());
        packet.push(self.local_cid.len() as u8);
        packet.extend_from_slice(self.local_cid.as_bytes());
        // Token フィールド (RFC 9000 Section 17.2.2)
        // Retry トークンが優先、なければ NEW_TOKEN で受信したアドレス検証トークンを使用する
        let token = if !self.retry_token.is_empty() {
            &self.retry_token
        } else {
            &self.address_token
        };
        VarInt::try_from(token.len() as u64)
            .expect("token length fits in 62-bit varint")
            .encode_to_vec(&mut packet);
        packet.extend_from_slice(token);

        // ペイロードは CONNECTION_CLOSE のみ (CRYPTO / ACK は載せない)
        let mut payload = Vec::new();
        frame.encode(&mut payload);

        // HP サンプル確保: apply_header_protection は pn_offset + 4 から 16 バイトの
        // サンプルを読むため、短い payload は PADDING で伸ばす
        let min_payload_with_tag = 4usize.saturating_sub(pn_len as usize) + HP_SAMPLE_LEN;
        if payload.len() + INITIAL_AEAD_TAG_LEN < min_payload_with_tag {
            let needed = min_payload_with_tag - payload.len() - INITIAL_AEAD_TAG_LEN;
            payload.extend(core::iter::repeat_n(0u8, needed));
        }

        // RFC 9000 Section 14.1: クライアントは Initial を含むデータグラムを
        // 1200 バイト以上にする (MUST)。Initial → Handshake → 1-RTT とコアレスしても
        // 満たせるよう、Initial パケット自体を 1200 バイト以上にする。
        // Length フィールドの VarInt サイズがパディング量に依存するため、
        // パケット長が 1200 バイト以上に収束するまで PADDING を追加する。
        if self.role == Role::Client {
            loop {
                let total = pn_len as usize + payload.len() + INITIAL_AEAD_TAG_LEN;
                let length_size = VarInt::try_from(total as u64)
                    .expect("packet length fits in 62-bit varint")
                    .encoded_size();
                let current_total = packet.len() + length_size + total;
                if current_total >= MIN_INITIAL_DATAGRAM_SIZE {
                    break;
                }
                payload.extend(core::iter::repeat_n(
                    0u8,
                    MIN_INITIAL_DATAGRAM_SIZE - current_total,
                ));
            }
        }

        // Length フィールド = pn_len + payload + AEAD tag
        // (パディング確定後に計算してエンコードする)
        let total = pn_len as usize + payload.len() + INITIAL_AEAD_TAG_LEN;
        VarInt::try_from(total as u64)
            .expect("packet length fits in 62-bit varint")
            .encode_to_vec(&mut packet);

        // パケット番号 (PN は消費しない: 再送も同一バイト列を使うため)
        let pn_offset = packet.len();
        let mut pn_buf = [0u8; 4];
        number::encode(pn, pn_len, &mut pn_buf)?;
        packet.extend_from_slice(&pn_buf[..pn_len as usize]);

        // AEAD 暗号化 (aws-lc-rs): nonce は明示計算する
        let aad = packet.clone();
        let ik = self
            .initial_keys
            .as_ref()
            .ok_or_else(|| Error::InvalidData("no initial keys".into()))?;
        let pn_nonce = nonce::compute_nonce(ik.send.aead.iv(), pn);
        protection::encrypt_payload(&ik.send.aead, &pn_nonce, &aad, &mut payload)?;
        packet.extend_from_slice(&payload);

        // Header Protection 適用 (aws-lc-rs)
        protection::apply_header_protection(&mut packet, pn_offset, pn_len, &ik.send.hp)?;

        // qlog: packet_sent (Initial)。閉鎖パケットが qlog から欠落しないようにする
        let time_ms = self.qlog_time_ms();
        let ack_delay_exponent = self.local_ack_delay_exponent();
        if let Some(writer) = self.qlog_writer.as_mut() {
            let qlog_header = qlog::PacketHeader {
                packet_type: qlog::PacketType::Initial,
                packet_number: pn,
                dcid: qlog::cid_to_hex(&self.peer_cid),
                scid: Some(qlog::cid_to_hex(&self.local_cid)),
                version: Some(format!("{:08x}", self.version)),
                length: Some(packet.len()),
            };
            let qlog_frames = vec![qlog::QlogFrame::from_frame(frame, ack_delay_exponent)];
            writer.on_packet_sent(time_ms, &qlog_header, &qlog_frames, packet.len());
        }
        // 観測イベント: パケット送信
        self.observe(ConnectionObservationEvent::PacketSent {
            path_id: PathId::INITIAL,
            packet_number: pn,
            size: packet.len(),
        });

        Ok(packet)
    }

    /// CONNECTION_CLOSE 単発送信用の Handshake パケットを構築する (rustls ベース)
    ///
    /// RFC 9000 Section 10.2.3 に基づく保持鍵レベル別の閉鎖送信の Handshake 版。
    /// 詳細 (副作用を伴わない点・再送・PN 非消費) は `build_initial_close_bytes` を参照。
    fn build_handshake_close_bytes(&mut self, frame: &Frame) -> Result<Vec<u8>, Error> {
        let pn = self.handshake_send_pn;
        let pn_len = number::encode_length(pn, self.handshake_sent_packets.largest_acked);

        // Long Header 構築 (emit_handshake_bytes と同型)
        let first_byte = LongHeader::build_first_byte_with_quic_bit(
            self.version,
            LongPacketType::Handshake,
            pn_len,
            self.send_quic_bit_zero(),
        );
        let mut packet = Vec::with_capacity(256);
        packet.push(first_byte);
        packet.extend_from_slice(&self.version.to_be_bytes());
        packet.push(self.peer_cid.len() as u8);
        packet.extend_from_slice(self.peer_cid.as_bytes());
        packet.push(self.local_cid.len() as u8);
        packet.extend_from_slice(self.local_cid.as_bytes());

        // ペイロードは CONNECTION_CLOSE のみ (CRYPTO は載せない)
        let mut payload = Vec::new();
        frame.encode(&mut payload);

        // HP サンプル確保: apply_hp_rustls は pn_offset + 4 から 16 バイトを読む
        let min_payload_with_tag = 4usize.saturating_sub(pn_len as usize) + HP_SAMPLE_LEN;
        if payload.len() + 16 < min_payload_with_tag {
            let needed = min_payload_with_tag - payload.len() - 16;
            payload.extend(core::iter::repeat_n(0u8, needed));
        }

        // Length フィールド = pn_len + payload + AEAD tag (パディング確定後に計算)
        let hk = self
            .handshake_keys
            .as_ref()
            .ok_or_else(|| Error::InvalidData("no handshake keys".into()))?;
        let tag_len = hk.local_packet.tag_len();
        let total = pn_len as usize + payload.len() + tag_len;
        VarInt::try_from(total as u64)
            .expect("packet length fits in 62-bit varint")
            .encode_to_vec(&mut packet);

        // パケット番号 (PN は消費しない)
        let pn_offset = packet.len();
        let mut pn_buf = [0u8; 4];
        number::encode(pn, pn_len, &mut pn_buf)?;
        packet.extend_from_slice(&pn_buf[..pn_len as usize]);

        // AEAD 暗号化 (rustls): encrypt_in_place が nonce を内部計算し Tag を返す
        let aad = packet.clone();
        let hk = self
            .handshake_keys
            .as_ref()
            .expect("handshake keys are present");
        let tag = hk
            .local_packet
            .encrypt_in_place(pn, &aad, &mut payload)
            .map_err(|_| Error::InvalidData("handshake encryption failed".into()))?;
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(tag.as_ref());

        // Header Protection 適用 (rustls)
        let hk = self
            .handshake_keys
            .as_ref()
            .expect("handshake keys are present");
        apply_hp_rustls(&mut packet, pn_offset, pn_len, &*hk.local_header, true)?;

        // qlog: packet_sent (Handshake)
        let time_ms = self.qlog_time_ms();
        let ack_delay_exponent = self.local_ack_delay_exponent();
        if let Some(writer) = self.qlog_writer.as_mut() {
            let qlog_header = qlog::PacketHeader {
                packet_type: qlog::PacketType::Handshake,
                packet_number: pn,
                dcid: qlog::cid_to_hex(&self.peer_cid),
                scid: Some(qlog::cid_to_hex(&self.local_cid)),
                version: Some(format!("{:08x}", self.version)),
                length: Some(packet.len()),
            };
            let qlog_frames = vec![qlog::QlogFrame::from_frame(frame, ack_delay_exponent)];
            writer.on_packet_sent(time_ms, &qlog_header, &qlog_frames, packet.len());
        }
        // 観測イベント: パケット送信
        self.observe(ConnectionObservationEvent::PacketSent {
            path_id: PathId::INITIAL,
            packet_number: pn,
            size: packet.len(),
        });

        Ok(packet)
    }

    /// CONNECTION_CLOSE 単発送信用の 1-RTT パケットを構築する (rustls ベース)
    ///
    /// `emit_1rtt_single_frame_padded` と異なり `output_queue` へ直接 push せず、
    /// 完成したバイト列を返す (コアレス用)。PN の消費・`sent_packets` への記録は
    /// 行わない (`build_initial_close_bytes` と同様の理由)。
    ///
    /// このパケットには CONNECTION_CLOSE だけを載せる。閉鎖パケットを
    /// CONNECTION_CLOSE だけにするのは実装ポリシーである。RFC 9000
    /// Section 19.16 が禁じるのは、RETIRE のシーケンス番号がそのパケットの DCID を
    /// 指すこと (MUST NOT) だけであり、閉鎖パケットに RETIRE を載せること自体を
    /// 禁じているわけではない。同じ DCID を退役させる RETIRE を混ぜると MUST NOT に
    /// 反するため、退役待ちのフレームは閉鎖パケットには使わず、ここには渡らない。
    /// DCID に退役済み CID を使う例外については `close_inner` を参照。
    fn build_1rtt_close_bytes(&mut self, frame: &Frame, path_id: PathId) -> Result<Vec<u8>, Error> {
        // 閉鎖パケットには CONNECTION_CLOSE 以外を載せない。将来この関数へ
        // RETIRE を渡す変更が入っても、DCID 自身を退役させるパケットを
        // 生成しないよう、debug ビルドで検出する。
        debug_assert!(
            matches!(frame, Frame::ConnectionClose(_)),
            "the 1-RTT close packet must contain only CONNECTION_CLOSE"
        );
        // 指定パスの現在の送信 PN を使う (消費しない)。再送は同じバイト列を使う。
        let path = self
            .paths
            .get(path_id)
            .ok_or_else(|| Error::InvalidData(format!("path {path_id} not found")))?;
        // パスごとの peer CID を使用する (RFC 10069 Section 4)
        let Some(dcid) = self.path_dcid(path_id) else {
            return Err(Error::InvalidData(format!(
                "peer connection ID for path {path_id} is not known yet"
            )));
        };
        let pn = path.send_pn;
        let pn_len = number::encode_length(pn, path.sent_packets.largest_acked);

        // RFC 9001 Section 6.1: Key Phase bit は送信側の現在の key_phase を反映する
        let first_byte = ShortHeader::build_first_byte_with_quic_bit(
            false,
            self.key_phase,
            pn_len,
            self.send_quic_bit_zero(),
        );
        let mut packet = Vec::new();
        packet.push(first_byte);
        packet.extend_from_slice(dcid.as_bytes());

        let pn_offset = packet.len();
        let mut pn_buf = [0u8; 4];
        number::encode(pn, pn_len, &mut pn_buf)?;
        packet.extend_from_slice(&pn_buf[..pn_len as usize]);

        let aad = packet.clone();

        // ペイロードは CONNECTION_CLOSE のみ
        let mut payload = Vec::new();
        frame.encode(&mut payload);

        // HP サンプル確保
        let min_payload_with_tag = 4usize.saturating_sub(pn_len as usize) + HP_SAMPLE_LEN;
        if payload.len() + 16 < min_payload_with_tag {
            let needed = min_payload_with_tag - payload.len() - 16;
            payload.extend(core::iter::repeat_n(0u8, needed));
        }

        // AEAD 暗号化 (rustls): パス対応 nonce で暗号化する
        let rk = self
            .one_rtt_keys
            .as_ref()
            .ok_or_else(|| Error::InvalidData("no 1-RTT keys".into()))?;
        let tag = rk
            .local_packet
            .encrypt_in_place_for_path(path_id.0, pn, &aad, &mut payload)
            .map_err(|_| Error::InvalidData("1-RTT encryption failed".into()))?;
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(tag.as_ref());

        // Header Protection 適用 (rustls)
        let rk = self.one_rtt_keys.as_ref().expect("1-RTT keys are present");
        apply_hp_rustls(&mut packet, pn_offset, pn_len, &*rk.local_header, false)?;

        // qlog: packet_sent (1-RTT)
        let time_ms = self.qlog_time_ms();
        let ack_delay_exponent = self.local_ack_delay_exponent();
        if let Some(writer) = self.qlog_writer.as_mut() {
            let qlog_header = qlog::PacketHeader {
                packet_type: qlog::PacketType::OneRtt,
                packet_number: pn,
                dcid: qlog::cid_to_hex(&dcid),
                scid: None,
                version: None,
                length: Some(packet.len()),
            };
            let qlog_frames = vec![qlog::QlogFrame::from_frame(frame, ack_delay_exponent)];
            writer.on_packet_sent(time_ms, &qlog_header, &qlog_frames, packet.len());
        }
        // 観測イベント: パケット送信
        self.observe(ConnectionObservationEvent::PacketSent {
            path_id,
            packet_number: pn,
            size: packet.len(),
        });

        Ok(packet)
    }

    /// 1-RTT HANDSHAKE_DONE パケットを送信する
    ///
    /// HANDSHAKE_DONE も通常の 1-RTT 制御フレームとして送る。
    /// これにより path ごとの peer CID、AEAD nonce、送信記録、損失検出の
    /// 共通経路を使え、他の 1-RTT 制御フレームとの不整合を防げる。
    fn emit_1rtt_handshake_done(&mut self, now: Timestamp) -> Result<(), Error> {
        self.emit_1rtt_single_frame(
            PathId::INITIAL,
            Frame::HandshakeDone(frame::handshake_done::HandshakeDone),
            now,
        )?;
        self.handshake_done_sent = true;
        // ハンドシェイク完了後の初期パスで観測アドレスを通知する
        // (draft-ietf-quic-address-discovery-01 Section 5)
        self.send_observed_address(PathId::INITIAL, now)?;
        Ok(())
    }

    /// サーバーが 0-RTT 鍵を破棄するタイマーを設定する (RFC 9001 Section 4.9.3)
    ///
    /// 1-RTT パケットを初めて受信した時点を起点に、全パスの最大 PTO の
    /// 3 倍後に 0-RTT 鍵を破棄する。順序が入れ替わって届いた 0-RTT パケットを
    /// 一定期間だけ復号できるようにしつつ、いつまでも鍵を保持しない。
    /// 1-RTT パケットが Handshake Finished より先着してハンドシェイク未確認の
    /// 間にタイマーを張る場合は、Application Data 空間の実効 ACK delay を
    /// 加算しない。
    fn schedule_zero_rtt_keys_discard(&mut self, now: Timestamp) {
        if self.zero_rtt_keys.is_none() || self.zero_rtt_keys_discard_at.is_some() {
            return;
        }
        let max_pto = self.lifecycle_max_pto();
        let deadline = now + max_pto.mul(3);
        self.zero_rtt_keys_discard_at = Some(deadline);
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::ZeroRttKeys,
            deadline,
        });
    }

    /// 0-RTT 拒否時に送信済みパケットを破棄し、再送対象へ戻す
    ///
    /// RFC 9001 Section 4.6.2: サーバーが 0-RTT を拒否した場合、クライアントは
    /// 0-RTT で送ったデータを 1-RTT で送り直す必要がある。
    /// RFC 9002 Section 6.4: 破棄したパケットの `bytes_in_flight` を回収しなければ
    /// ならない。回収しないと輻輳ウィンドウが使用済みのまま残る。
    fn discard_sent_packets_for_zero_rtt_rejection(&mut self, now: Timestamp) {
        let mut lost_streams: Vec<(u64, u64, usize, bool, u32)> = Vec::new();
        let mut control_frames: Vec<SentFrameInfo> = Vec::new();
        let mut discarded_bytes: u64 = 0;
        let mut discarded_pns: Vec<u64> = Vec::new();
        if let Some(path) = self.paths.get_mut(PathId::INITIAL) {
            let drained = path.sent_packets.drain_all();
            for packet in drained {
                discarded_pns.push(packet.pn);
                if packet.in_flight {
                    discarded_bytes = discarded_bytes.saturating_add(packet.sent_bytes);
                }
                for frame in packet.frames {
                    match frame {
                        SentFrameInfo::Stream {
                            stream_id,
                            offset,
                            length,
                            fin,
                            retransmission_count,
                        } => lost_streams.push((
                            stream_id,
                            offset,
                            length,
                            fin,
                            retransmission_count,
                        )),
                        SentFrameInfo::Ack { .. }
                        | SentFrameInfo::PathAck
                        | SentFrameInfo::Other => {}
                        other => control_frames.push(other),
                    }
                }
            }
            // 破棄したパケットの bytes_in_flight を回収する (RFC 9002 Section 6.4)
            path.congestion.on_packet_discarded_bytes(discarded_bytes);
            // per-packet delivery state も同じ空間から破棄する
            path.congestion
                .on_packets_discarded_cc(PacketNumberSpace::ApplicationData, &discarded_pns);
        }
        // 破棄したパケットに含まれていたストリームの終端遷移を試みる対象を
        // 集める。再送キューへの復元はこの後のループで行う。
        let mut discarded_stream_ids: Vec<u64> = Vec::new();
        for (stream_id, _, _, _, _) in &lost_streams {
            discarded_stream_ids.push(*stream_id);
        }
        for frame in &control_frames {
            if let Some(stream_id) = sent_frame_stream_id(frame) {
                discarded_stream_ids.push(stream_id);
            }
        }
        for (stream_id, offset, length, fin, retransmission_count) in lost_streams {
            // 0-RTT 拒否はパケットロストではないが、同じデータを 1-RTT で
            // 送り直す必要がある。時間閾値ロストとして再送キューへ戻す。
            self.streams.mark_lost(
                stream_id,
                offset,
                length,
                fin,
                RetxMeta {
                    original_path: PathId::INITIAL,
                    loss_reason: LossReason::TimeThreshold,
                    retransmission_count,
                },
            );
        }
        // 0-RTT で送った制御フレームも 1-RTT で送り直す
        self.retransmit_lost_control_frames(control_frames, now);
        // 再送キューへの復元が終わったストリームは、ACK 済み範囲しか
        // 残っていない場合に終端状態へ遷移できる
        // (RFC 9000 Section 3.1, Section 13.3)。
        for stream_id in discarded_stream_ids {
            self.streams.try_transition_send_terminal(stream_id);
        }
        // RFC 9002 Section 6.4: 0-RTT 拒否で Application Data 空間の回復状態を
        // 破棄する。0-RTT は Application Data 空間を 1-RTT と共有するが、
        // 拒否時点では同空間の送信済みパケットは 0-RTT のみである。
        // タイマーは次の emit_packets が残りの in-flight 空間から再計算する。
        self.clear_loss_detection_timer_for_space(
            PathId::INITIAL,
            PacketNumberSpace::ApplicationData,
        );
        self.paths
            .initial_path_mut()
            .loss_detectors
            .reset_space(PacketNumberSpace::ApplicationData);
    }

    /// Initial 鍵と Initial 空間の recovery state を廃棄する
    ///
    /// RFC 9001 Section 4.9.1 に基づき Initial パケットが不要になった時点で
    /// Initial 鍵と対応する CRYPTO バッファを解放し、RFC 9002 Section 6.4 に基づき
    /// Initial 空間の recovery state (sent_packets / ACK tracker) も破棄する。
    /// 破棄したパケットはロスト再送しない (鍵が無いため送信できない)。
    ///
    fn discard_initial_keys(&mut self) {
        // 破棄済みフラグを立て、以後の Initial パケットを silent discard する。
        self.initial_keys_discarded = true;
        self.initial_keys = None;
        // 破棄後に Initial の再送データを保持しても送信経路が無いため解放する。
        self.crypto_send_initial.clear();
        self.crypto_sent_initial.clear();
        self.crypto_send_initial_offset = 0;
        self.crypto_retransmit_initial.clear();
        self.initial_pto_probes_pending = 0;
        self.crypto_recv_initial =
            CryptoRecvBuffer::new(CRYPTO_RECV_INITIAL_MAX_BYTES, CRYPTO_RECV_MAX_PENDING_COUNT);
        // 鍵破棄後に Initial ACK を生成・送信する経路は無いため tracker を初期化する
        self.initial_ack_tracker = AckTracker::new();
        // in-flight に算入した分だけを除く (RFC 9002 Section 6.4 MUST)。
        // ACK 専用パケットの sent_bytes を二重に差し引かない。
        let discarded_packets = self.initial_sent_packets.drain_all();
        let discarded_bytes: u64 = discarded_packets
            .iter()
            .filter(|packet| packet.in_flight)
            .map(|packet| packet.sent_bytes)
            .sum();
        if !discarded_packets.is_empty() {
            let discarded_pns: Vec<u64> =
                discarded_packets.iter().map(|packet| packet.pn).collect();
            let path = self.paths.initial_path_mut();
            path.congestion.on_packet_discarded_bytes(discarded_bytes);
            // per-packet delivery state も Initial 空間から破棄する
            path.congestion
                .on_packets_discarded_cc(PacketNumberSpace::Initial, &discarded_pns);
        }
        // RFC 9002 Section 6.2.2 / Section 6.4: Initial 空間を破棄したら、
        // その空間の損失検出状態とタイマーを破棄する。他空間の in-flight が
        // 残る場合は次の emit_packets が改めてタイマーを armed する。
        self.clear_loss_detection_timer_for_space(PathId::INITIAL, PacketNumberSpace::Initial);
        self.paths
            .initial_path_mut()
            .loss_detectors
            .reset_space(PacketNumberSpace::Initial);
        // RFC 9002 Appendix A.11: 鍵を破棄したときは共有 PTO バックオフも戻す。
        self.paths
            .initial_path_mut()
            .loss_detectors
            .reset_pto_backoff();
    }

    /// Handshake 鍵と Handshake 空間の recovery state を廃棄する
    ///
    /// RFC 9001 Section 4.9.2 に基づき、Handshake パケットが不要になった時点で
    /// Handshake 鍵と対応する CRYPTO バッファを解放し、RFC 9002 Section 6.4 に基づき
    /// Handshake 空間の recovery state (sent_packets / ACK tracker) も破棄する。
    /// 破棄したパケットはロスト再送しない (鍵が無いため送信できない)。
    ///
    fn discard_handshake_keys(&mut self) {
        self.handshake_keys = None;
        self.crypto_send_handshake.clear();
        // 鍵破棄後は CRYPTO を送信できないため、送信済みデータと再送待ちも
        // まとめて破棄する (RFC 9000 Section 13.3)。
        self.crypto_sent_handshake.clear();
        self.crypto_retransmit_handshake.clear();
        self.crypto_send_handshake_offset = 0;
        self.handshake_pto_probes_pending = 0;
        self.crypto_recv_handshake = CryptoRecvBuffer::new(
            CRYPTO_RECV_HANDSHAKE_MAX_BYTES,
            CRYPTO_RECV_MAX_PENDING_COUNT,
        );
        // 鍵破棄後に Handshake ACK を生成・送信する経路は無いため tracker を初期化する
        self.handshake_ack_tracker = AckTracker::new();
        // in-flight に算入した分だけを除く (RFC 9002 Section 6.4 MUST)。
        // ACK 専用パケットの sent_bytes を二重に差し引かない。
        let discarded_packets = self.handshake_sent_packets.drain_all();
        let discarded_bytes: u64 = discarded_packets
            .iter()
            .filter(|packet| packet.in_flight)
            .map(|packet| packet.sent_bytes)
            .sum();
        if !discarded_packets.is_empty() {
            let discarded_pns: Vec<u64> =
                discarded_packets.iter().map(|packet| packet.pn).collect();
            let path = self.paths.initial_path_mut();
            path.congestion.on_packet_discarded_bytes(discarded_bytes);
            // per-packet delivery state も Handshake 空間から破棄する
            path.congestion
                .on_packets_discarded_cc(PacketNumberSpace::Handshake, &discarded_pns);
        }
        // RFC 9002 Section 6.2.2 / Section 6.4: Handshake 空間を破棄したら、
        // その空間の損失検出状態とタイマーを破棄する。他空間の in-flight が
        // 残る場合は次の emit_packets が改めてタイマーを armed する。
        self.clear_loss_detection_timer_for_space(PathId::INITIAL, PacketNumberSpace::Handshake);
        self.paths
            .initial_path_mut()
            .loss_detectors
            .reset_space(PacketNumberSpace::Handshake);
        self.paths
            .initial_path_mut()
            .loss_detectors
            .reset_pto_backoff();
    }

    /// 全パスの未 ACK パケットに対して PATH_ACK を含む 1-RTT パケットを送信する
    ///
    /// RFC 10069 Section 4.1 に基づき、
    /// 各パスの ack_tracker から ACK を生成し PATH_ACK フレームとして送信する。
    /// Path ID 0 でも PATH_ACK を使用する (Multipath First)。
    /// ACK が必要なパスごとに ACK / PATH_ACK フレームを生成する
    ///
    /// RFC 9000 Section 13.4.1: ECN カウントは (パケット番号空間, パス) ごとに
    /// 独立している。アプリケーションデータ空間の受信累計は各パスの
    /// `AckTracker` が保持しており、`generate_ack` はそのパスの累計だけを
    /// ACK_ECN に載せる。そのため他のパスの最大値を混ぜてはならない。
    fn build_path_acks(
        &mut self,
        now: Timestamp,
    ) -> Vec<(
        PathId,
        frame::ack::Ack,
        Option<frame::receive_timestamps::ReceiveTimestamps>,
    )> {
        // RFC 9000 Section 19.3: ACK Delay は送信者 (= local) の ack_delay_exponent で
        // `delay_micros >> exponent` として scale する。指数の選択は ACK の qlog
        // 記録と共通の `local_ack_delay_exponent` に集約している。
        let ack_delay_exponent = self.local_ack_delay_exponent();
        // Receive Timestamps 拡張の送信設定。ピアが広告していない場合は None のまま。
        let peer_receive_timestamps = self.peer_receive_timestamps;
        let mut acks_to_send = Vec::new();
        for path in self.paths.all_paths_mut() {
            // ACK Frequency 拡張の閾値に達していない場合は ACK を生成しない
            // (draft-ietf-quic-ack-frequency-14 Section 6)。
            if !path.ack_tracker.should_send_ack_now() {
                continue;
            }
            let ack_delay = path
                .ack_tracker
                .largest_received_time()
                .map(|t| {
                    let delay_micros = now.saturating_duration_since(t).as_micros();
                    delay_micros >> ack_delay_exponent
                })
                .unwrap_or(0);
            if let Some(ack) = path.ack_tracker.generate_ack(ack_delay) {
                // draft-ietf-quic-receive-ts-03 Section 6: ピアが広告した
                // max_receive_timestamps_per_ack の範囲で受信タイムスタンプを載せる。
                let timestamps = peer_receive_timestamps.and_then(|peer| {
                    path.ack_tracker.generate_receive_timestamps(
                        ack.largest_acknowledged.as_u64(),
                        ack.first_ack_range.as_u64(),
                        &ack.ack_ranges,
                        peer.max_per_ack,
                        RECEIVE_TIMESTAMP_BASIS,
                        peer.exponent,
                    )
                });
                acks_to_send.push((path.id, ack, timestamps));
            }
        }
        acks_to_send
    }

    fn emit_1rtt_path_acks(&mut self, now: Timestamp) -> Result<(), Error> {
        for (ack_path_id, ack, receive_timestamps) in self.build_path_acks(now) {
            // ACK パスポリシーで送信パスを選択する (PATH_ACK は任意のパスで送信可能)
            // (RFC 10069 Section 5.4)
            let metrics = self.paths.collect_metrics();
            let ack_ctx = AckCtx { paths: &metrics };
            let send_path_id = self
                .scheduler
                .ack
                .select_ack_path(&ack_ctx, ack_path_id)
                .unwrap_or(PathId::INITIAL);

            // ACK パスの変更を追跡する
            // (RFC 10069 Section 5.4)
            let prev_ack_path = self.last_ack_send_path.get(&ack_path_id).copied();
            if prev_ack_path.is_some() && prev_ack_path != Some(send_path_id) {
                // ACK 返送パスが変更された: acked_path の delivery_time_estimate を
                // リセットし、RTT サンプルが安定するまで smoothed_rtt にフォールバックする
                if let Some(acked_path) = self.paths.get_mut(ack_path_id) {
                    acked_path.ack_path_changed = true;
                    acked_path.delivery_time_estimate = tobi_core::time::Duration::ZERO;
                }
            } else if prev_ack_path == Some(send_path_id) {
                // ACK パスが安定: ack_path_changed をクリアし delivery_time_estimate を更新。
                // RFC 10069 Section 5.4 は、パスの実 RTT ではなく
                // 「送信パスの片道遅延 + ACK 返送パスの片道遅延」の和を推定することを
                // 推奨する。片道遅延は smoothed_rtt の半分で近似する
                // (`MinCompletionTime` は delivery_time_estimate の半分を片方向遅延として
                //  扱うため、この解釈と整合する)。
                let ack_send_half_rtt = self.paths.get(send_path_id).map_or(
                    tobi_core::time::Duration::ZERO,
                    |send_path| {
                        tobi_core::time::Duration::from_micros(
                            send_path.rtt.smoothed_rtt.as_micros() / 2,
                        )
                    },
                );
                if let Some(acked_path) = self.paths.get_mut(ack_path_id) {
                    acked_path.ack_path_changed = false;
                    let total_micros = acked_path
                        .rtt
                        .smoothed_rtt
                        .as_micros()
                        .saturating_div(2)
                        .saturating_add(ack_send_half_rtt.as_micros());
                    acked_path.delivery_time_estimate =
                        tobi_core::time::Duration::from_micros(total_micros);
                }
            }
            self.last_ack_send_path.insert(ack_path_id, send_path_id);

            // Multipath 有効時は PATH_ACK、無効時は通常の ACK を使用する
            // 双方が initial_max_path_id を提示した場合のみ Multipath 有効とする
            // (RFC 10069 Section 5.4 / RFC 9000 Section 19.3)
            let mut payload = Vec::new();
            let multipath_enabled =
                self.paths.local_max_path_id > 0 && self.paths.remote_max_path_id > 0;
            // 送信済みパケットへ記録するフレーム情報を先に作る。
            // PATH_ACK も ACK と同じく再送不要だが、種別は正しく記録する。
            // PATH_ACK の確認応答内容は 1-RTT の packet_sent が payload の
            // デコードから作るため、SentFrameInfo には保持しない。
            let frame_info = if multipath_enabled {
                SentFrameInfo::PathAck
            } else {
                // 1-RTT の packet_sent は `prepare_one_rtt_output` が送信 payload を
                // デコードして作るため、ここで保持する SentFrameInfo は qlog から
                // 読まれない。ACK を送るたびにレンジを確保しないよう空にしておく
                // (1-RTT の ACK Delay は payload 側の更新だけで足りる)。
                SentFrameInfo::Ack {
                    acked_ranges: Vec::new(),
                    ack_delay: 0,
                }
            };
            if multipath_enabled {
                if let Some(receive_timestamps) = receive_timestamps {
                    // draft-ietf-quic-receive-ts-03 Section 5:
                    // PATH_ACK に受信タイムスタンプを続けたフレームを送る。
                    let path_ack = frame::receive_timestamps::PathAckReceiveTimestamps {
                        path_id: ack_path_id.0,
                        ack: ack.clone(),
                        timestamps: receive_timestamps,
                    };
                    Frame::PathAckReceiveTimestamps(path_ack).encode(&mut payload);
                } else {
                    let path_ack = frame::path_ack::PathAck {
                        path_id: ack_path_id.0,
                        largest_acknowledged: ack.largest_acknowledged,
                        ack_delay: ack.ack_delay,
                        first_ack_range: ack.first_ack_range,
                        ack_ranges: ack.ack_ranges,
                        ecn_counts: ack.ecn_counts,
                    };
                    Frame::PathAck(path_ack).encode(&mut payload);
                }
            } else if let Some(receive_timestamps) = receive_timestamps {
                // draft-ietf-quic-receive-ts-03 Section 4:
                // ACK に受信タイムスタンプを続けたフレームを送る。
                let ack_with_timestamps = frame::receive_timestamps::AckReceiveTimestamps {
                    ack: ack.clone(),
                    timestamps: receive_timestamps,
                };
                Frame::AckReceiveTimestamps(ack_with_timestamps).encode(&mut payload);
            } else {
                Frame::Ack(ack).encode(&mut payload);
            }

            self.queue_one_rtt(PendingOneRtt {
                path_id: send_path_id,
                payload,
                frames: vec![frame_info],
                ack_eliciting: false,
                min_size: 0,
                remote_addr: None,
                local_addr: None,
                // ACK はパスの送信先 CID で送る (移行の検証パケットではない)。
                dcid_override: None,
                purpose: OneRttPurpose::Regular,
                prepared_at: now,
                reserved: false,
            });

            // ACK を送信したので、未発火の AckDelay タイマーを解除する。
            // ACK Frequency 拡張を使っている場合のみ行う。拡張未使用時の
            // 既存の ACK タイミング (タイマー) は変えない。
            if self
                .paths
                .get(ack_path_id)
                .is_some_and(|p| p.ack_tracker.is_ack_frequency_active())
            {
                self.output_queue.push_back(ConnectionOutput::ClearTimer {
                    id: TimerId::AckDelay {
                        path_id: ack_path_id,
                    },
                });
            }
        }
        Ok(())
    }

    /// プローブを送る被疑パス以外のパスを選ぶ
    ///
    /// データスケジューラーの選択結果が被疑パスと一致する場合 (MinRtt は最短 RTT の
    /// 被疑パスを選び得る) や選択結果が無い場合は、被疑パスを除いた usable かつ
    /// 輻輳制限の無いパスのうち smoothed_rtt が最小のものを選ぶ。
    /// 候補が無ければ `None` を返し、呼び出し側は被疑パスへのプローブだけを行う。
    fn select_pto_alt_path(&mut self, suspect_path: PathId) -> Option<PathId> {
        let metrics = self.paths.collect_metrics();
        {
            let ctx = ScheduleCtx { paths: &metrics };
            if let Some(path_id) = self.scheduler.data.select_path(&ctx)
                && path_id != suspect_path
            {
                // データスケジューラーが被疑パス以外を選んだならそれを尊重する
                return Some(path_id);
            }
        }
        // データスケジューラーが被疑パス (または None) を選んだ場合の明示的な探索
        metrics
            .iter()
            .filter(|p| p.path_id != suspect_path && p.is_usable && !p.is_congestion_limited)
            .min_by_key(|p| p.smoothed_rtt)
            .map(|p| p.path_id)
    }

    /// ハンドシェイク確認前に、経路検証用の NEW_CONNECTION_ID だけを送る
    ///
    /// 通常の 1-RTT データ送信はハンドシェイク確認後に行うが、対向が新しい
    /// 経路を検証するための CID は確認前でも送れる (RFC 9000 Section 5.1.1)。
    /// STREAM などの他の送信待ちフレームは動かさない。
    fn emit_pre_confirmation_cids(&mut self, now: Timestamp) -> Result<(), Error> {
        if self.one_rtt_keys.is_none() {
            return Ok(());
        }
        while let Some(index) = self
            .streams
            .pending_frames
            .iter()
            .position(|frame| matches!(frame, Frame::NewConnectionId(_)))
        {
            let frame = self
                .streams
                .pending_frames
                .remove(index)
                .expect("見つけたフレームを取り出せる");
            if !self.emit_1rtt_single_frame(PathId::INITIAL, frame.clone(), now)? {
                self.streams.pending_frames.push_back(frame);
                break;
            }
        }
        Ok(())
    }

    /// PTO 発火したパスに対してプローブパケットを送信する
    ///
    /// RFC 9002 Section 6.2: PTO 発火時に ack-eliciting パケットを送信する。
    /// 送信データがなければ PING フレームを送信する。
    ///
    /// RFC 10069 Section 5.7: PTO が連続して
    /// 発火した場合は、被疑パス以外の輻輳ウィンドウが許すパスでもプローブを
    /// 送信してパスの多様性を活用する。
    fn emit_pto_probes(&mut self, now: Timestamp) -> Result<(), Error> {
        let probe_paths = std::mem::take(&mut self.pto_probe_paths);
        for path_id in probe_paths {
            let Some(path) = self.paths.get(path_id) else {
                continue;
            };

            // 廃棄済み/廃棄中のパスにはプローブを送信しない (MUST)
            // RFC 10069 Section 3.4:
            // PATH_ABANDON 送信後はそのパスに一切送信してはならない
            if path.state == PathState::Abandoning || path.state == PathState::Abandoned {
                continue;
            }

            // 連続 PTO (pto_count >= 2) の場合、別パスでもプローブを送信する
            // (RFC 10069 Section 5.7)。MinRtt が被疑パスを
            // 選ぶ場合でも別パスへ出せるよう、被疑パスを除いて明示的に選ぶ。
            let pto_count = path.loss_detectors.pto_count();
            let alt_path_id = if pto_count >= 2 {
                self.select_pto_alt_path(path_id)
            } else {
                None
            };
            if let Some(alt_path_id) = alt_path_id {
                self.emit_1rtt_single_frame(alt_path_id, Frame::Ping(frame::ping::Ping), now)?;
                if let Some(pending) = self.one_rtt_outputs.back_mut() {
                    pending.purpose = OneRttPurpose::Pto;
                }
            }

            // 元のパスでもプローブを送信する (パスの生存確認)
            self.emit_1rtt_single_frame(path_id, Frame::Ping(frame::ping::Ping), now)?;
            if let Some(pending) = self.one_rtt_outputs.back_mut() {
                pending.purpose = OneRttPurpose::Pto;
            }
        }
        Ok(())
    }

    /// 全パスの DPLPMTUD を有効化する (RFC 8899)
    ///
    /// ハンドシェイク完了後に呼び出す。ピアのパラメータが既に確定している
    /// 場合は、探索開始前に `max_udp_payload_size` を反映する。未確定の
    /// 場合は最大 UDP ペイロードで初期化し、確定時に
    /// `maybe_apply_peer_params` で引き下げる。
    fn enable_dplpmtud(&mut self) {
        let limit = if self.peer_params_finalized {
            // `peer_params_finalized` は `peer_params` を `Some` にした直後にだけ
            // 立てるため、確定済みならピアの値が存在する。
            self.peer_params
                .as_ref()
                .expect("finalized peer parameters are stored")
                .max_udp_payload_size
        } else {
            // 0-RTT で記憶した古いパラメータは使わず、ハンドシェイク確定時に
            // 改めて反映する。
            u64::from(MAX_UDP_PAYLOAD)
        };
        self.apply_peer_max_udp_payload_size(limit);
        self.paths.enable_dplpmtud();
    }

    /// ピアの `max_udp_payload_size` を送信 MTU の上限として反映する
    ///
    /// RFC 9000 Section 18.2 の最大 UDP ペイロードに clamp してから `u16` に
    /// 変換する。`TransportParams::decode` は下限 (1200) だけを検証し、上限は
    /// 検証しないため、ここでの clamp が実効上限になる。
    fn apply_peer_max_udp_payload_size(&mut self, limit: u64) {
        let limit = limit.min(u64::from(MAX_UDP_PAYLOAD));
        // clamp 後の値は MAX_UDP_PAYLOAD 以下なので u16 に必ず収まる。
        let limit = u16::try_from(limit).expect("limit is clamped to MAX_UDP_PAYLOAD");
        let invalidated = self.paths.set_max_udp_payload_size(limit);
        for path_id in invalidated {
            if let Some(path) = self.paths.get_mut(path_id) {
                discard_sent_pmtu_probes(path, path_id, &mut self.pmtu_probe_pns);
            }
        }
    }

    /// DPLPMTUD プローブの次回タイムアウトまでの期間を返す
    ///
    /// 連続タイムアウトでは PTO を指数的に倍加する (RFC 9002 Section 6.2.1 と
    /// 同じ PTO バックオフ。プローブの再送間隔を空け、アイドル中のピアへ
    /// プローブを送り続けないようにする)。
    ///
    /// RFC 8899 Section 5.1.1: PROBE_TIMER は 1 秒未満にしてはならない
    /// (MUST NOT)。RTT が小さい接続でもプローブのタイムアウトが短くなりすぎて
    /// 不要な再送と `probe_count` の消費が起きないよう、バックオフ後の値を
    /// 1 秒以上へ clamp する。
    fn pmtu_probe_timeout(&self, path_id: PathId, pto: Duration) -> Duration {
        let backoff = self
            .pmtu_probe_backoff
            .get(&path_id)
            .copied()
            .unwrap_or(0)
            .min(6);
        pto.mul(1u32 << backoff).max(PMTU_PROBE_TIMER_MIN)
    }

    /// DPLPMTUD プローブパケットを送信する (RFC 8899)
    ///
    /// プローブは PING + PADDING で構成する。
    /// 輻輳ウィンドウを消費しないよう、CC の on_packet_sent は通常通り呼ぶが、
    /// プローブのロストは輻輳イベントとして扱わない (MtuController で処理する)。
    fn emit_pmtu_probes(&mut self, now: Timestamp) -> Result<(), Error> {
        // プローブが必要なパスを収集する
        let probe_paths: Vec<(PathId, u16)> = self
            .paths
            .all_paths()
            .filter(|p| {
                p.mtu_controller.needs_probe()
                    && p.is_usable()
                    && !self.one_rtt_outputs.iter().any(|pending| {
                        pending.path_id == p.id && pending.purpose == OneRttPurpose::Pmtu
                    })
            })
            .map(|p| (p.id, p.mtu_controller.probe_size()))
            .collect();

        for (path_id, probe_size) in probe_paths {
            // RFC 8899 Section 5.7: 輻輳コントローラでプローブ送信を制御する場合、
            // 輻輳中はプローブを延期してよい。輻輳ウィンドウに空きがないときに
            // プローブを送ると、プローブの再送でウィンドウを使い切り、同じパス上の
            // STREAM データ (特にハンドシェイク直後の制御フレーム) を送れなくなる。
            // 空きができるまで延期し、PmtuProbe タイマーで再試行する。
            // プローブ以外のデータ (STREAM / 制御フレーム) を送る余裕も残す。
            // 空きが 1 データグラム未満になると `Path` が輻輳制限中と判定され、
            // データを送れなくなるため、プローブサイズに加えて現在の PMTU 分を
            // 確保できなければプローブを延期する。
            let (available_window, pmtu) = self.paths.get(path_id).map_or((0, 0), |p| {
                (self.one_rtt_generation_budget(path_id), u64::from(p.pmtu))
            });
            if available_window < u64::from(probe_size).saturating_add(pmtu) {
                if let Some(path) = self.paths.get(path_id) {
                    let deadline = now + self.pmtu_probe_timeout(path_id, path.rtt.pto());
                    self.output_queue.push_back(ConnectionOutput::SetTimer {
                        id: TimerId::PmtuProbe { path_id },
                        deadline,
                    });
                }
                continue;
            }
            // PING + PADDING で probe_size のデータグラムを構成する
            self.emit_1rtt_single_frame_padded(
                path_id,
                Frame::Ping(frame::ping::Ping),
                probe_size as usize,
                now,
            )?;

            if let Some(pending) = self.one_rtt_outputs.back_mut() {
                pending.purpose = OneRttPurpose::Pmtu;
            }
        }

        // 再プローブタイマーの確認
        let reprobe_updates: Vec<(PathId, Option<Timestamp>)> = self
            .paths
            .all_paths_mut()
            .map(|p| {
                p.mtu_controller.check_reprobe(now);
                (p.id, p.mtu_controller.reprobe_deadline())
            })
            .collect();
        for (path_id, deadline) in reprobe_updates {
            if let Some(deadline) = deadline {
                self.output_queue.push_back(ConnectionOutput::SetTimer {
                    id: TimerId::PmtuRaise { path_id },
                    deadline,
                });
            }
        }

        Ok(())
    }

    /// PATH_CHALLENGE を含む 1-RTT パケットを送信する
    ///
    /// RFC 9000 Section 8.2.1: 増幅制限が許す場合は 1,200 バイトに拡張し、
    /// 許さない場合は小さいプローブと、その応答後の MTU 検証に分ける。
    /// 仕様変更時には両段階の検証条件を見直す。
    fn emit_1rtt_path_challenge(
        &mut self,
        target_path_id: PathId,
        challenge_data: [u8; 8],
        now: Timestamp,
    ) -> Result<(), Error> {
        self.emit_1rtt_path_challenge_to(target_path_id, challenge_data, None, None, now)
    }

    /// 新しい 4-tuple からの probe に対して、自前の経路検証を開始する
    ///
    /// preferred_address へ移行したクライアントの probe には、PATH_RESPONSE を
    /// 返すことが必須である (RFC 9000 Section 9.6.2)。同じパケットまたは先の
    /// パケットに自前の PATH_CHALLENGE を含めることは許されており
    /// (RFC 9000 Section 8.2)、サーバーは移行先の経路を検証しなければならない。
    /// 新しい 4-tuple への最初のサーバー パケットを PATH_CHALLENGE にするため、
    /// 応答の生成より先に検証を開始し、応答は検証後の送信に回す。
    fn maybe_start_validation_for_probe(
        &mut self,
        path_id: PathId,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
        now: Timestamp,
    ) -> Result<(), Error> {
        if self.role != Role::Server || self.state != ConnectionState::Connected {
            return Ok(());
        }
        let Some(path) = self.paths.get(path_id) else {
            return Ok(());
        };
        if !matches!(path.state, PathState::Active | PathState::Validating) {
            return Ok(());
        }
        // パスの現在の 4-tuple と同じなら移行ではない。
        if path.remote_addr == remote_addr && path.local_addr == local_addr {
            return Ok(());
        }
        // 検証中のチャレンジがあれば、その応答を待つ。
        if path.validation.has_pending_challenge() {
            return Ok(());
        }
        let mut challenge = [0u8; 8];
        aws_lc_rs::rand::fill(&mut challenge)
            .map_err(|_| Error::InvalidData("failed to generate random bytes".into()))?;
        self.paths
            .get_mut(path_id)
            .expect("path exists")
            .validation
            .request_challenge(challenge);
        // PATH_CHALLENGE は 1,200 バイト以上へ拡張される (RFC 9000 Section 8.2.1)。
        // 送信できるまで、同じパスの PATH_RESPONSE を含む他の出力を保留し、
        // 新しい 4-tuple への最初のパケットを PATH_CHALLENGE にする。
        self.emit_1rtt_path_challenge_to(
            path_id,
            challenge,
            Some(remote_addr),
            Some(local_addr),
            now,
        )?;
        self.defer_path_datagrams_until_challenge = Some(path_id);
        let pto = self.path_validation_pto(path_id);
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::PathValidation { path_id },
            deadline: now + pto,
        });
        Ok(())
    }

    /// PATH_CHALLENGE を指定アドレス宛てに送信する
    ///
    /// `remote_addr_override` / `local_addr_override` が `Some` の場合、
    /// パスの 4-tuple を変更せずにそのアドレス宛ての `SendDatagram` を生成する
    /// (4-tuple 移行の検証用)。
    ///
    /// 送信先が移行候補の 4-tuple と一致する場合だけ、現在の送信先 CID ではなく
    /// 移行候補の CID を DCID に使う (RFC 9000 Section 9.5 の MUST NOT)。
    /// 候補以外の 4-tuple へ送る PATH_CHALLENGE はパスの送信先 CID を使う。
    /// 候補 CID は `Connection::pending_migrations` が保持する。
    fn emit_1rtt_path_challenge_to(
        &mut self,
        target_path_id: PathId,
        challenge_data: [u8; 8],
        remote_addr_override: Option<std::net::SocketAddr>,
        local_addr_override: Option<std::net::SocketAddr>,
        now: Timestamp,
    ) -> Result<(), Error> {
        let Some(path) = self.paths.get(target_path_id) else {
            return Ok(());
        };
        // 応答待ちや出力待ちを再生成しない。準備後の CID / pacing 待ちは
        // 未暗号化の出力キューが保持する。
        if path.validation.unsent_challenge() != Some(challenge_data) {
            return Ok(());
        }
        // 上書きが無い場合はパスの現在の 4-tuple へ送る。候補 CID を使うのは、
        // 実際の送信先が移行候補の 4-tuple と一致する場合だけである。
        let remote_addr = remote_addr_override.unwrap_or(path.remote_addr);
        let local_addr = local_addr_override.unwrap_or(path.local_addr);
        let dcid_override =
            self.migration_candidate_dcid_for(target_path_id, remote_addr, local_addr);
        self.emit_1rtt_single_frame_padded_to(
            target_path_id,
            &[Frame::PathChallenge(frame::path_challenge::PathChallenge {
                data: challenge_data,
            })],
            0,
            OneRttSendOverride {
                remote_addr: remote_addr_override,
                local_addr: local_addr_override,
                dcid: dcid_override,
            },
            now,
        )
        .map(|_| ())
    }

    /// PATH_RESPONSE を含む 1-RTT パケットを、受信した 4-tuple を送信先にして送る
    ///
    /// RFC 9000 Section 8.2.2: PATH_RESPONSE は PATH_CHALLENGE を受信した
    /// ネットワークパスへ送らなければならない (MUST)。パスの 4-tuple を
    /// 書き換えずに、そのパケットの remote_addr / local_addr を送信先に使う。
    ///
    /// 送信先が移行の候補 4-tuple と一致する場合は、候補 CID を DCID に使う。
    /// 同じ CID を移行前と移行先の両方の宛先アドレスへ送ってはならない
    /// (RFC 9000 Section 9.5 の MUST NOT)。
    fn emit_1rtt_path_response_to(
        &mut self,
        target_path_id: PathId,
        response_data: [u8; 8],
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
        challenge_datagram_len: usize,
        now: Timestamp,
    ) -> Result<(), Error> {
        let dcid_override =
            self.migration_candidate_dcid_for(target_path_id, remote_addr, local_addr);
        // 応答先がパスの現在の 4-tuple と異なる場合 (移行の probe への応答など) は、
        // チャレンジを運んだデータグラム長から拡張の可否を確定する。この予算は
        // 出力時にも変わらないため、生成時に決めてよい。
        let min_datagram_size = self.path_response_min_datagram_size(
            target_path_id,
            remote_addr,
            local_addr,
            challenge_datagram_len,
        );
        self.emit_1rtt_single_frame_padded_to(
            target_path_id,
            &[Frame::PathResponse(frame::path_response::PathResponse {
                data: response_data,
            })],
            min_datagram_size,
            OneRttSendOverride {
                remote_addr: Some(remote_addr),
                local_addr: Some(local_addr),
                dcid: dcid_override,
            },
            now,
        )
        .map(|_| ())
    }

    /// PATH_RESPONSE を含むデータグラムを 1,200 バイトへ拡張できるか判定する
    ///
    /// RFC 9000 Section 8.2.2 は、増幅制限で許されない場合を除き、PATH_RESPONSE
    /// を含むデータグラムを 1,200 バイト以上へ拡張することを MUST とする。
    /// 応答先がパスの現在の 4-tuple と一致する場合は、そのアドレスが検証済みか
    /// 十分な増幅枠を持つ場合だけ拡張する。異なる 4-tuple へ返す場合は、旧アドレスで
    /// 検証済みの状態や受信量を流用せず、チャレンジを運んだデータグラム長から
    /// そのアドレスの増幅枠を評価する (RFC 9000 Section 8.1)。`challenge_datagram_len`
    /// が不明 (0) の場合や枠が 1,200 バイトに満たない場合は拡張しない。
    fn path_response_min_datagram_size(
        &self,
        path_id: PathId,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
        challenge_datagram_len: usize,
    ) -> usize {
        let Some(path) = self.paths.get(path_id) else {
            return 0;
        };
        if path.remote_addr != remote_addr || path.local_addr != local_addr {
            // 応答先が未検証アドレスである。使える予算は、そのアドレスから受信した
            // バイト数の 3 倍であり、ここではチャレンジを運んだデータグラム長を
            // その受信量として使う (RFC 9000 Section 8.2.2 の MUST は、増幅制限が
            // 許す場合に限って適用される)。
            let budget = (challenge_datagram_len as u64).saturating_mul(3);
            if budget >= MIN_INITIAL_DATAGRAM_SIZE as u64 {
                return MIN_INITIAL_DATAGRAM_SIZE;
            }
            return 0;
        }
        if path.address_validated || path.can_send_bytes(MIN_INITIAL_DATAGRAM_SIZE as u64) {
            MIN_INITIAL_DATAGRAM_SIZE
        } else {
            // 増幅枠が 1,200 バイトに満たない場合は拡張しない。
            0
        }
    }

    /// 複数フレームを 1 つの 1-RTT パケットにして送る
    fn emit_1rtt_frames(
        &mut self,
        send_path_id: PathId,
        frames: &[Frame],
        now: Timestamp,
    ) -> Result<bool, Error> {
        self.emit_1rtt_single_frame_padded_to(
            send_path_id,
            frames,
            0,
            OneRttSendOverride::default(),
            now,
        )
    }

    /// 単一フレームを含む 1-RTT パケットを送信する汎用ヘルパー
    fn emit_1rtt_single_frame(
        &mut self,
        send_path_id: PathId,
        frame: Frame,
        now: Timestamp,
    ) -> Result<bool, Error> {
        self.emit_1rtt_single_frame_padded(send_path_id, frame, 0, now)
    }

    /// 単一フレームを含む 1-RTT パケットを送信する (最小データグラムサイズ指定可)
    ///
    /// `min_datagram_size` > 0 の場合、データグラム全体がそのサイズ以上になるよう
    /// PADDING フレームで埋める。PATH_CHALLENGE の 1200 byte MTU 検証に使用する。
    fn emit_1rtt_single_frame_padded(
        &mut self,
        send_path_id: PathId,
        frame: Frame,
        min_datagram_size: usize,
        now: Timestamp,
    ) -> Result<bool, Error> {
        self.emit_1rtt_single_frame_padded_to(
            send_path_id,
            &[frame],
            min_datagram_size,
            OneRttSendOverride::default(),
            now,
        )
    }

    /// 単一フレームを含む 1-RTT パケットを送信する (送信先アドレス上書き付き)
    ///
    /// `overrides` が `Some` の値を指定した場合、パスの 4-tuple や送信先 CID を
    /// 変更せずにその値で `SendDatagram` を生成する。preferred_address の検証の
    /// ように、パスの 4-tuple を確定する前に特定アドレスへ PATH_CHALLENGE を
    /// 送る用途 (RFC 9000 Section 9.6.1) と、PATH_CHALLENGE を受信した 4-tuple へ
    /// PATH_RESPONSE を返す用途 (RFC 9000 Section 8.2.2 の MUST) で使う。
    ///
    /// 4-tuple 移行の検証パケットは、送信先アドレスごとに別の CID を
    /// 使わなければならない (RFC 9000 Section 9.5 の MUST NOT)。
    ///
    /// パケット番号・輻輳制御・損失検出はパスの通常の送信と同じ扱いになる。
    fn emit_1rtt_single_frame_padded_to(
        &mut self,
        send_path_id: PathId,
        frames: &[Frame],
        min_datagram_size: usize,
        overrides: OneRttSendOverride,
        now: Timestamp,
    ) -> Result<bool, Error> {
        if matches!(
            self.state,
            ConnectionState::Closed | ConnectionState::Draining
        ) {
            return Ok(false);
        }
        let path = self
            .paths
            .get_mut(send_path_id)
            .ok_or_else(|| Error::InvalidData(format!("path {send_path_id} not found")))?;
        let purpose = if let [Frame::PathChallenge(challenge)] = frames {
            path.validation.challenge_queued(&challenge.data);
            OneRttPurpose::PathChallenge {
                data: challenge.data,
                generation: path.validation.generation(),
            }
        } else if let [Frame::PathResponse(response)] = frames {
            OneRttPurpose::PathResponse {
                data: response.data,
            }
        } else {
            OneRttPurpose::Regular
        };
        let mut payload = Vec::new();
        for frame in frames {
            frame.encode(&mut payload);
        }
        let frame_infos: Vec<SentFrameInfo> = frames
            .iter()
            .map(|frame| sent_frame_info_for_control(frame, send_path_id))
            .collect();
        self.queue_one_rtt(PendingOneRtt {
            path_id: send_path_id,
            payload,
            frames: frame_infos,
            ack_eliciting: !frames_are_ack_only(frames),
            min_size: min_datagram_size,
            remote_addr: overrides.remote_addr,
            local_addr: overrides.local_addr,
            dcid_override: overrides.dcid,
            purpose,
            prepared_at: now,
            reserved: true,
        });
        Ok(true)
    }

    /// 1-RTT データパケットの送信パスを選ぶ
    ///
    /// 再送待ちの STREAM データがあれば `MultipathScheduler::retx` の
    /// `RetransmissionPolicy::decide_retx` に再送先パスを決めさせ、その判断を
    /// 送信パスに反映する。再送が無い場合、または `RetxDecision::Defer` の
    /// 場合はデータスケジューラーで新規データの送信パスを選ぶ。
    ///
    /// `retx_deferred` はこの送信処理中に Defer が出たことを示す。一度 Defer
    /// したら同じ送信処理では再送を試さず、再送対象は捨てずに次の送信機会へ
    /// 回す。
    fn select_1rtt_send_path(
        &mut self,
        retx_deferred: &mut bool,
        skip_paths: &[PathId],
    ) -> Option<DataSendPath> {
        // この送信ラウンドで pacing / バースト制限によりスキップしたパスを除外する
        let metrics: Vec<PathMetrics> = self
            .paths
            .collect_metrics()
            .into_iter()
            .filter(|p| !skip_paths.contains(&p.path_id))
            .collect();

        if !*retx_deferred && let Some(target) = self.streams.next_retransmit() {
            // 再送候補は usable なパスの ID 一覧
            let candidates: Vec<PathId> = metrics
                .iter()
                .filter(|p| p.is_usable)
                .map(|p| p.path_id)
                .collect();
            let ctx = RetxCtx {
                paths: &metrics,
                loss_reason: target.info.meta.loss_reason,
                frame_class: FrameClass::StreamData,
                retransmission_count: target.info.meta.retransmission_count,
            };
            let decision =
                self.scheduler
                    .retx
                    .decide_retx(&ctx, target.info.meta.original_path, &candidates);
            match decision {
                RetxDecision::SamePath => {
                    let path_id = target.info.meta.original_path;
                    if Self::path_can_send(&metrics, path_id) {
                        return Some(DataSendPath {
                            path_id,
                            retx: Some(target),
                            duplicate_path: None,
                            duplicate_paths: Vec::new(),
                        });
                    }
                }
                RetxDecision::CrossPath(path_id) => {
                    if Self::path_can_send(&metrics, path_id) {
                        return Some(DataSendPath {
                            path_id,
                            retx: Some(target),
                            duplicate_path: None,
                            duplicate_paths: Vec::new(),
                        });
                    }
                }
                RetxDecision::Duplicate(path_id) => {
                    let original_path = target.info.meta.original_path;
                    let duplicate_sendable = Self::path_can_send(&metrics, path_id);
                    if Self::path_can_send(&metrics, original_path) {
                        return Some(DataSendPath {
                            path_id: original_path,
                            retx: Some(target),
                            duplicate_path: if duplicate_sendable {
                                Some(path_id)
                            } else {
                                None
                            },
                            duplicate_paths: Vec::new(),
                        });
                    }
                    if duplicate_sendable {
                        // 元パスが使えない場合は複製先を主パスにする
                        return Some(DataSendPath {
                            path_id,
                            retx: Some(target),
                            duplicate_path: None,
                            duplicate_paths: Vec::new(),
                        });
                    }
                }
                RetxDecision::Defer => {
                    // 再送対象は捨てず、次の送信機会に改めて判断する
                    *retx_deferred = true;
                }
            }
        }

        // 再送しない、または再送先パスが送信可能でない: 新規データの
        // 送信パスをデータスケジューラーで選ぶ。冗長スケジューラーは
        // 2 本目以降も返すため、先頭を主パス、残りを複製先パスとして扱う。
        let ctx = ScheduleCtx { paths: &metrics };
        if self.scheduler.data.max_paths() > 1 {
            let mut selected = self.scheduler.data.select_paths(&ctx, MAX_REDUNDANT_PATHS);
            if selected.is_empty() {
                return None;
            }
            let path_id = selected.remove(0);
            return Some(DataSendPath {
                path_id,
                retx: None,
                duplicate_path: None,
                duplicate_paths: selected,
            });
        }
        self.scheduler
            .data
            .select_path(&ctx)
            .map(|path_id| DataSendPath {
                path_id,
                retx: None,
                duplicate_path: None,
                duplicate_paths: Vec::new(),
            })
    }

    /// pacing により今すぐ送信できない場合に true を返し、Pacing タイマーを設定する
    ///
    /// `burst_bytes` はこの送信機会で送信済みのバイト数。pacing rate が未設定の
    /// 間は初期輻輳ウィンドウを超えるバーストを許可しない (RFC 9002 Section 7.7)。
    fn pacing_blocked(&mut self, path_id: PathId, now: Timestamp, burst_bytes: u64) -> bool {
        let blocked = {
            let Some(path) = self.paths.get(path_id) else {
                return false;
            };
            if let Some(departure_time) = path.congestion.earliest_departure_time() {
                if departure_time > now {
                    Some(departure_time)
                } else {
                    None
                }
            } else if path.congestion.pacing_rate().is_none() {
                let max_burst = tobi_core::recovery::initial_window(path.pmtu as u64);
                if burst_bytes.saturating_add(path.pmtu as u64) > max_burst {
                    // バースト上限に達したときは短いタイマーで次の送信機会に回す。
                    Some(
                        now + tobi_core::time::Duration::from_micros(
                            PACING_BURST_RETRY_INTERVAL_MICROS,
                        ),
                    )
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(deadline) = blocked {
            self.schedule_pacing_timer(path_id, deadline);
            return true;
        }
        false
    }

    /// Pacing タイマーを設定する
    fn schedule_pacing_timer(&mut self, path_id: PathId, deadline: Timestamp) {
        if self.pacing_deadlines.get(&path_id) == Some(&deadline) {
            return;
        }
        self.pacing_deadlines.insert(path_id, deadline);
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::Pacing { path_id },
            deadline,
        });
    }

    /// 指定パスが現在データを送信できるかを返す
    ///
    /// パスが usable で、輻輳ウィンドウに空きがある (輻輳制限中でない) こと。
    fn path_can_send(metrics: &[PathMetrics], path_id: PathId) -> bool {
        metrics
            .iter()
            .any(|p| p.path_id == path_id && p.is_usable && !p.is_congestion_limited)
    }

    /// `RetxDecision::Duplicate` で選ばれた複製先パスへ同じ STREAM データを送る
    ///
    /// 元の再送パケットとは別の 1-RTT パケットとして送る。複製先パスの PMTU に
    /// 収まらない場合は先頭部分のみを複製する (残りは元パスの再送が担う)。
    /// この複製パケットは冗長化のための追加送信であり、ロストしても再送しない
    /// (冗長なコピーを追跡すると、原本の ACK 後に不要な再送が発生するため)。
    fn emit_duplicate_stream_frame(
        &mut self,
        path_id: PathId,
        frame: &StreamFrameOut,
        now: Timestamp,
    ) -> Result<(), Error> {
        let max_data = {
            let Some(path) = self.paths.get(path_id) else {
                return Ok(());
            };
            // 廃棄済み/輻輳制限中のパスへは複製しない
            if !path.is_usable() || path.congestion.is_congestion_limited() {
                return Ok(());
            }
            // 出力時の CID / PN 長の変化を見込む。
            let header_overhead = MAX_ONE_RTT_OVERHEAD;
            let frame_overhead = 25;
            let Some(max_data) = (path.pmtu as usize)
                .checked_sub(header_overhead)
                .and_then(|v| v.checked_sub(frame_overhead))
            else {
                return Ok(());
            };
            max_data
        };

        let length = frame.length.min(max_data);
        if length == 0 && !frame.fin {
            return Ok(());
        }
        let Some(data) = self
            .streams
            .retransmit_data(frame.stream_id, frame.offset, length)
        else {
            return Ok(());
        };
        let data = data.to_vec();
        let fin = frame.fin && length == frame.length;
        let stream_frame = frame::stream::Stream {
            stream_id: VarInt::new(frame.stream_id).expect("value fits in 62-bit varint"),
            offset: VarInt::new(frame.offset).expect("value fits in 62-bit varint"),
            fin,
            data,
        };
        self.emit_1rtt_single_frame(path_id, Frame::Stream(stream_frame), now)
            .map(|_| ())
    }

    /// 制御フレームと STREAM フレームを含む 1-RTT パケットを送信する
    ///
    /// RFC 9000 Section 13.3 に基づき、制御フレームを STREAM フレームより
    /// 優先してパケットに組み込む。pending_frames の制御フレームを先に
    /// 書き込み、残りの空間に再送 STREAM フレームと新規 STREAM フレームを詰める。
    /// 再送 STREAM フレームの送信パスは `select_1rtt_send_path` の判断に従う。
    fn emit_1rtt_data(&mut self, now: Timestamp) -> Result<(), Error> {
        // この送信処理中に Defer された再送対象があるか
        let mut retx_deferred = false;
        // 送信可能なフレームが無い状態で送信ループを終えたか
        let mut no_frames_to_send = false;
        // この送信処理で送信したバイト数 (pacing 未使用時のバースト制限用)
        let mut burst_bytes: u64 = 0;
        // pacing / バースト制限でこのラウンドの送信を見送ったパス
        let mut skipped_paths: Vec<PathId> = Vec::new();
        // パス選択の試行回数 (スキップしたパスがある場合の無限ループ防止)
        let mut path_attempts = 0usize;
        // 再送ポリシーまたはデータスケジューラーで送信パスを選ぶ
        loop {
            // 空の flush で RR などの選択状態を進めない。キューへ移した後も
            // 次の周の先頭で確認し、実データのない選択機会を消費しない。
            if self.streams.pending_frames.is_empty()
                && self.streams.next_retransmit().is_none()
                && !self.streams.has_unsent_data()
                && self.crypto_send_1rtt.is_empty()
                && self.crypto_retransmit_1rtt.is_empty()
            {
                no_frames_to_send = true;
                break;
            }

            path_attempts += 1;
            if path_attempts > MAX_SEND_PATH_ATTEMPTS {
                break;
            }
            let Some(selection) = self.select_1rtt_send_path(&mut retx_deferred, &skipped_paths)
            else {
                break;
            };
            let send_path_id = selection.path_id;

            // RFC 9002 Section 7.7: pacing の departure time / バースト上限を守る。
            // このパスでは今すぐ送れない場合はスキップして他のパスを試す。
            if self.pacing_blocked(send_path_id, now, burst_bytes) {
                if !skipped_paths.contains(&send_path_id) {
                    skipped_paths.push(send_path_id);
                }
                continue;
            }

            let Some(path) = self.paths.get(send_path_id) else {
                skipped_paths.push(send_path_id);
                continue;
            };
            let pmtu = path.pmtu as usize;
            // ピア CID が未確定の追加パスでは送らない
            // (RFC 10069 Section 3.1)。このパスをスキップして
            // 他のパスを試す。
            let Some(_) = self.path_dcid(send_path_id) else {
                skipped_paths.push(send_path_id);
                continue;
            };

            // パケットヘッダのオーバーヘッドを計算する
            // Short Header: first_byte(1) + DCID + pn_len + AEAD tag(16)
            let header_overhead = MAX_ONE_RTT_OVERHEAD;
            if pmtu <= header_overhead {
                skipped_paths.push(send_path_id);
                continue;
            }
            let max_payload = pmtu - header_overhead;

            // RFC 9002 Section 7 / RFC 10069 Section 5.5:
            // in-flight を増やすパケットは、そのパスの輻輳ウィンドウに空きが
            // ある範囲でしか送れない。データスケジューラーは輻輳制限中のパスも
            // 小さなパケット向けに選び得るため、ここでも available_window を
            // 上限としてペイロード長を制限する。
            let congestion_budget =
                usize::try_from(self.one_rtt_generation_budget(send_path_id)).unwrap_or(usize::MAX);
            let max_payload = max_payload.min(congestion_budget.saturating_sub(header_overhead));
            if max_payload == 0 {
                skipped_paths.push(send_path_id);
                continue;
            }

            // ペイロードを構築する: 制御フレームを優先して書き込む
            let mut payload = Vec::new();
            let mut sent_frame_infos: Vec<SentFrameInfo> = Vec::new();

            // 1-RTT CRYPTO の再送を優先する。再送は最初に送ったときと同じ
            // オフセットで送らなければならない (RFC 9001 Section 4.1.3)。
            if let Some((offset, data)) = self.crypto_retransmit_1rtt.pop_front() {
                let frame = Frame::Crypto(frame::crypto::Crypto {
                    offset: VarInt::new(offset).expect("value fits in 62-bit varint"),
                    data: data.clone(),
                });
                let mut tmp = Vec::new();
                frame.encode(&mut tmp);
                if tmp.len() <= max_payload {
                    payload.extend_from_slice(&tmp);
                    sent_frame_infos.push(SentFrameInfo::Crypto {
                        offset,
                        length: data.len(),
                    });
                } else {
                    // PMTU に収まらない場合は再送待ちへ戻して延期する
                    self.crypto_retransmit_1rtt.push_front((offset, data));
                }
            }

            // 1-RTT CRYPTO の新規送信 (ポストハンドシェイクメッセージ:
            // NewSessionTicket 等)。再送待ちが残っている間は新しいデータを
            // 載せず、次のパケットに回す。
            if self.crypto_retransmit_1rtt.is_empty() && !self.crypto_send_1rtt.is_empty() {
                let data = std::mem::take(&mut self.crypto_send_1rtt);
                let offset = self.crypto_send_1rtt_offset;
                let frame = Frame::Crypto(frame::crypto::Crypto {
                    offset: VarInt::new(offset).expect("value fits in 62-bit varint"),
                    data: data.clone(),
                });
                let mut tmp = Vec::new();
                frame.encode(&mut tmp);
                if tmp.len() <= max_payload {
                    payload.extend_from_slice(&tmp);
                    self.crypto_send_1rtt_offset += data.len() as u64;
                    // 再送用に送信済みデータを保持する。新規送信のオフセットは
                    // 0 から連続に進むため、末尾への追記で送信済み範囲を表せる。
                    let offset_usize = usize::try_from(offset).unwrap_or(usize::MAX);
                    if offset_usize == self.crypto_sent_1rtt.len() {
                        self.crypto_sent_1rtt.extend_from_slice(&data);
                    }
                    sent_frame_infos.push(SentFrameInfo::Crypto {
                        offset,
                        length: data.len(),
                    });
                } else {
                    // PMTU に収まらない場合は送信を延期する
                    self.crypto_send_1rtt = data;
                }
            }

            // 制御フレームを先に書き込む (RFC 9000 Section 13.3)。
            //
            // フロー制御上限を超えるリセットフレームは送信を延期し、後続の
            // フレーム送信を妨げないようキューを 1 周だけ走査する
            // (draft-ietf-quic-reliable-stream-reset-11 Section 4)。
            let pending_count = self.streams.pending_frames.len();
            for _ in 0..pending_count {
                let Some(control_frame) = self.streams.pending_frames.pop_front() else {
                    break;
                };
                if !self.streams.reset_frame_fits_flow_control(&control_frame) {
                    // MAX_DATA / MAX_STREAM_DATA でクレジットが増えるまで延期する
                    self.streams.pending_frames.push_back(control_frame);
                    continue;
                }
                let mut tmp = Vec::new();
                control_frame.encode(&mut tmp);
                if payload.len() + tmp.len() > max_payload {
                    // パケットに収まらないフレームは次回へ回す
                    self.streams.pending_frames.push_front(control_frame);
                    break;
                }
                payload.extend_from_slice(&tmp);
                // フレームタイプに応じた SentFrameInfo を記録する
                // (ロスト時の再送方式がフレームごとに異なるため)
                let frame_info = sent_frame_info_for_control(&control_frame, send_path_id);
                if let Some(stream_id) = sent_frame_stream_id(&frame_info) {
                    self.streams.reserve_queued_frame(stream_id);
                }
                sent_frame_infos.push(frame_info);
            }

            // 再送 STREAM フレームを書き込む
            let mut retx_frame_out: Option<StreamFrameOut> = None;
            if let Some(target) = &selection.retx {
                retx_frame_out =
                    self.streams
                        .write_retransmit_frame(&mut payload, max_payload, target);
                if let Some(sf) = &retx_frame_out {
                    self.streams.reserve_queued_frame(sf.stream_id);
                    sent_frame_infos.push(SentFrameInfo::Stream {
                        stream_id: sf.stream_id,
                        offset: sf.offset,
                        length: sf.length,
                        fin: sf.fin,
                        retransmission_count: sf.retransmission_count,
                    });
                }
            }

            // 残りの空間に新規 STREAM フレームを書き込む
            let stream_frames = self
                .streams
                .write_new_data_frames(&mut payload, max_payload);
            for sf in &stream_frames {
                // パケット化したフレームの所有を未出力の予約として保持する。
                self.streams.reserve_queued_frame(sf.stream_id);
                sent_frame_infos.push(SentFrameInfo::Stream {
                    stream_id: sf.stream_id,
                    offset: sf.offset,
                    length: sf.length,
                    fin: sf.fin,
                    retransmission_count: sf.retransmission_count,
                });
            }

            // 送信すべきフレームがなければ終了する
            if sent_frame_infos.is_empty() {
                no_frames_to_send = true;
                break;
            }

            // 複製に必要な STREAM 範囲は、本文をキューへ移す前に取り出す。
            // 冗長スケジューラーが複製先パスを選んでいる場合、このパケットに
            // 含まれる STREAM フレームを複製する。sent_frame_infos は後で
            // SentPacket へ move するため、先に複製用に取り出しておく。
            let redundant_duplicate_paths = selection.duplicate_paths.clone();
            let duplicate_stream_frames: Vec<StreamFrameOut> =
                if redundant_duplicate_paths.is_empty() {
                    Vec::new()
                } else {
                    sent_frame_infos
                        .iter()
                        .filter_map(|frame_info| match frame_info {
                            SentFrameInfo::Stream {
                                stream_id,
                                offset,
                                length,
                                fin,
                                retransmission_count,
                            } => Some(StreamFrameOut {
                                stream_id: *stream_id,
                                offset: *offset,
                                length: *length,
                                fin: *fin,
                                encoded_len: 0,
                                retransmission_count: *retransmission_count,
                            }),
                            _ => None,
                        })
                        .collect()
                };

            burst_bytes = burst_bytes.saturating_add((payload.len() + header_overhead) as u64);
            let ack_eliciting = !sent_frame_infos_are_ack_only(&sent_frame_infos);
            self.queue_one_rtt(PendingOneRtt {
                path_id: send_path_id,
                payload,
                frames: sent_frame_infos,
                ack_eliciting,
                min_size: 0,
                remote_addr: None,
                local_addr: None,
                // 通常の 1-RTT データはパスの送信先 CID で送る。
                dcid_override: None,
                purpose: OneRttPurpose::Regular,
                prepared_at: now,
                reserved: true,
            });

            // 冗長スケジューラーの指定時は、同じ STREAM フレームを複製先パスへ送る。
            // 複製はパスごとに独立した PN 空間と AEAD nonce (PPN) で送信される
            // (RFC 10069 Section 2.4 / 3.1)。
            if !duplicate_stream_frames.is_empty() {
                for duplicate_path in &redundant_duplicate_paths {
                    if *duplicate_path == send_path_id {
                        continue;
                    }
                    for frame in &duplicate_stream_frames {
                        self.emit_duplicate_stream_frame(*duplicate_path, frame, now)?;
                    }
                }
            }

            // Duplicate 指定時は同じデータを複製先パスにも送る
            if let (Some(duplicate_path), Some(frame)) =
                (selection.duplicate_path, retx_frame_out.as_ref())
            {
                self.emit_duplicate_stream_frame(duplicate_path, frame, now)?;
            }
        }

        // 送信可能なフレームが無い状態でループを終えた場合、アプリケーションが
        // 送信可能なデータを持っていない可能性がある。未送信データ・再送待ち・
        // 制御フレーム・DATAGRAM・CRYPTO のいずれも残っていなければ
        // application-limited を通知する
        // (draft-ietf-ccwg-bbr-06 Section 4.1.2.4 CheckIfApplicationLimited)。
        // CUBIC もこの通知を使ってアプリケーション制限期間を輻輳回避の経過時間
        // から除外する (RFC 9438 Section 4.2 / Section 5.8)。
        if no_frames_to_send {
            self.notify_app_limited_if_idle();
        } else {
            self.notify_unselected_paths_idle(now);
        }
        self.emit_tracking = false;
        Ok(())
    }

    /// 送信機会で選ばれなかったパスの遊休を通知する
    ///
    /// 実際に 1-RTT パケットを出力したパスを基準にするため、送信数の前後比較では
    /// なく送信ループの記録 (`emit_used_paths`) を使う。送信可能で cwnd・pacing に
    /// 余裕があり、ピア CID が確定しているパスだけを対象にする。検証中・廃棄中、
    /// cwnd 律速、pacing 待ちのパスは対象外。
    fn notify_unselected_paths_idle(&mut self, now: Timestamp) {
        if self.emit_used_paths.is_empty() {
            return;
        }
        for path in self.paths.all_paths_mut() {
            if self.emit_used_paths.contains(&path.id) {
                continue;
            }
            if !path.is_usable() || path.state != PathState::Active {
                continue;
            }
            if path.peer_cid.is_none() && path.id != PathId::INITIAL {
                continue;
            }
            if path.congestion.is_congestion_limited() {
                continue;
            }
            if path
                .congestion
                .earliest_departure_time()
                .is_some_and(|departure| departure > now)
            {
                continue;
            }
            path.congestion.on_idle(IdleReason::PathNotSelected);
        }
    }

    /// 送信可能なアプリケーションデータが尽きた場合に輻輳制御へ通知する
    ///
    /// draft-ietf-ccwg-bbr-06 Section 4.1.2.4 CheckIfApplicationLimited の
    /// 「NoUnsentData かつ pending_transmissions == 0 かつ
    /// lost_out <= retrans_out」の判定に相当する。inflight < cwnd の判定は
    /// 各輻輳制御実装 (BBR / CUBIC) 側で行う。
    fn notify_app_limited_if_idle(&mut self) {
        // 送信待ちがリセットフレームだけで、その Final Size が現在の
        // フロー制御上限を超えている場合は、送信可能なデータが無いのではなく
        // フロー制御で待機している。この場合だけ pending_frames が空でなくても
        // 休止通知へ進む。
        let control_frame_blocked = self.streams.pending_frames_flow_control_blocked();
        if (!self.streams.pending_frames.is_empty() && !control_frame_blocked)
            || self.streams.next_retransmit().is_some()
            || !self.datagram_send_queue.is_empty()
            || !self.crypto_send_1rtt.is_empty()
            || !self.crypto_retransmit_1rtt.is_empty()
            || self
                .one_rtt_outputs
                .iter()
                .any(|pending| pending.ack_eliciting)
        {
            return;
        }
        // 未送信データが残っていても、フロー制御で送れない場合はデータ枯渇と
        // 区別する。送信可能なデータが残っているなら休止ではない。
        let reason = if self.streams.has_unsent_data() {
            if !self.streams.unsent_data_flow_control_blocked() {
                return;
            }
            IdleReason::FlowControlLimited
        } else if control_frame_blocked {
            IdleReason::FlowControlLimited
        } else {
            IdleReason::NoData
        };
        for path in self.paths.all_paths_mut() {
            path.congestion.on_idle(reason);
        }
    }

    /// 送信キューのデータグラムを 1-RTT パケットとして送信する (RFC 9221)
    ///
    /// 各データグラムを個別の 1-RTT パケットに含めて送信する。
    /// 輻輳制御はパケット送信時に適用される。
    ///
    /// 送信パスは制御フレームや STREAM フレームと同じくデータスケジューラーで
    /// 選ぶ (RFC 10069 Section 5)。DATAGRAM はフロー制御の
    /// 対象外で、ロスしても再送しない (RFC 9221 Section 5.2) ため、送信キューは
    /// 接続単位のままにして送出のたびにパスを選び直し、その時点で最適なパスへ
    /// 振り分ける。
    ///
    /// 選択パスがピア CID 未確定、pacing 待ち、PMTU 不適合、生成予約不足の
    /// いずれかの場合は、そのパスを一時的に除外して別のパスを有限回まで選び
    /// 直す。どのパスでも今すぐ送れない場合はキューの先頭へ戻し、次の送信機会を
    /// 待つ (スケジューラーが利用可能なパスを返さない場合も同じ)。廃棄中のパスを
    /// 除くどのパスの PMTU にも収まらないデータグラムは破棄する
    /// (RFC 9000 Section 14.2)。
    fn emit_1rtt_datagrams(&mut self, now: Timestamp) -> Result<(), Error> {
        // この送信処理で送信したバイト数 (pacing 未設定時のバースト制限用)
        let mut burst_bytes: u64 = 0;
        while let Some(mut data) = self.datagram_send_queue.pop_front() {
            let frame_size = frame::datagram::Datagram::encoded_size_for(data.len());
            let overhead = MAX_ONE_RTT_OVERHEAD;
            // 廃棄中のパスを除く全パスで、PMTU に収まる可能性があるか判定する。
            // 収まるパスが 1 本も無ければ、送信機会ごとに再試行し続けないよう
            // 破棄する (RFC 9000 Section 14.2)。
            let fits_any = self.paths.all_paths().any(|path| {
                !matches!(path.state, PathState::Abandoning | PathState::Abandoned)
                    && (path.pmtu as usize)
                        .checked_sub(overhead)
                        .is_some_and(|frame_max| frame_size <= frame_max)
            });
            if !fits_any {
                continue;
            }

            // その送信機会で使えないパスを一時的に除外し、別のパスを試す。
            let mut skipped_paths: Vec<PathId> = Vec::new();
            let mut path_attempts = 0usize;
            let mut sent = false;
            while !sent {
                path_attempts += 1;
                // 除外したパスを除いた全パスを一度は試せる回数を上限にする
                if path_attempts > self.paths.count().saturating_add(1) {
                    break;
                }
                let send_path_id = {
                    let metrics: Vec<PathMetrics> = self
                        .paths
                        .collect_metrics()
                        .into_iter()
                        .filter(|p| !skipped_paths.contains(&p.path_id))
                        .collect();
                    let ctx = ScheduleCtx { paths: &metrics };
                    match self.scheduler.data.select_path(&ctx) {
                        Some(path_id) => path_id,
                        None => break,
                    }
                };
                if skipped_paths.contains(&send_path_id) {
                    break;
                }
                // ピア CID が未確定のパスでは送らない。このパスをスキップして
                // 他のパスを試す (RFC 10069 Section 3.1)。
                if self.path_dcid(send_path_id).is_none() {
                    skipped_paths.push(send_path_id);
                    continue;
                }
                // RFC 9002 Section 7.7: pacing の departure time / バースト上限を
                // 守る。このパスでは今すぐ送れない場合はスキップして他のパスを
                // 試す。
                if self.pacing_blocked(send_path_id, now, burst_bytes) {
                    skipped_paths.push(send_path_id);
                    continue;
                }
                // RFC 9000 Section 14.2: 選択したパスの PMTU を超えるデータグラムは
                // 送らない。この送信機会では別のパスを試す。
                let fits = self
                    .paths
                    .get(send_path_id)
                    .and_then(|p| (p.pmtu as usize).checked_sub(overhead))
                    .is_some_and(|frame_max| frame_size <= frame_max);
                if !fits {
                    skipped_paths.push(send_path_id);
                    continue;
                }
                // パスの輻輳制限や生成予約で送れない場合も別のパスを試す。
                let datagram_size = (frame_size + overhead) as u64;
                if self.one_rtt_generation_budget(send_path_id) < datagram_size {
                    skipped_paths.push(send_path_id);
                    continue;
                }
                let dg = frame::datagram::Datagram {
                    data: core::mem::take(&mut data),
                };
                let frame = Frame::Datagram(dg);
                self.emit_1rtt_single_frame(send_path_id, frame, now)?;
                burst_bytes = burst_bytes.saturating_add(datagram_size);
                sent = true;
            }
            if !sent {
                // 待てば送れるパスがあるため、このデータグラムはキューへ
                // 戻して次の送信機会を待つ。
                self.datagram_send_queue.push_front(data);
                break;
            }
        }
        Ok(())
    }

    /// ピア CID が判明したパスの未送信 PATH_CHALLENGE を送信する
    ///
    /// `open_path` はピアがそのパスの CID を通知する前に呼ばれうる。その場合、
    /// PATH_CHALLENGE の DCID に使える CID がまだ無いため送信を保留している。
    /// ピアの `PATH_NEW_CONNECTION_ID` を受信して `peer_cid` が設定された時点で
    /// この関数が送信する。保留中の PATH_CHALLENGE が無いパスでは何もしない。
    fn emit_1rtt_path_challenges(&mut self, now: Timestamp) -> Result<(), Error> {
        // 借用の問題を避けるため、送信すべきデータを先に収集する
        let mut challenges: Vec<(PathId, [u8; 8])> = Vec::new();
        for path in self.paths.all_paths() {
            if matches!(path.state, PathState::Validating | PathState::Active)
                && path.peer_cid.is_some()
                && let Some(data) = path.validation.unsent_challenge()
            {
                challenges.push((path.id, data));
            }
        }
        for (path_id, data) in challenges {
            let (remote, local) = self
                .pending_migrations
                .get(&path_id)
                .map(|migration| {
                    (
                        Some(migration.candidate_remote_addr),
                        migration.candidate_local_addr,
                    )
                })
                .unwrap_or((None, None));
            self.emit_1rtt_path_challenge_to(path_id, data, remote, local, now)?;
        }
        Ok(())
    }

    /// 全パスの未送信 PATH_RESPONSE を送信する
    fn emit_1rtt_path_responses(&mut self, now: Timestamp) -> Result<(), Error> {
        /// 1 回の送信処理で応答する PATH_CHALLENGE の上限
        ///
        /// 1 つのデータグラムに大量の PATH_CHALLENGE を詰められた場合でも、
        /// 応答パケット数のバーストを抑える。残りは次の送信機会に回す。
        const MAX_RESPONSES_PER_EMIT: usize = 8;

        // 借用の問題を避けるため、送信すべきデータを先に収集する
        let mut responses: Vec<(PathId, tobi_core::path::validation::PendingPathResponse)> =
            Vec::new();
        for path in self.paths.all_paths_mut() {
            // ピア CID が未確定の追加パスでは PATH_RESPONSE を保留する
            // (RFC 10069 Section 3.1 は PATH_RESPONSE を
            // PATH_CHALLENGE と同じ path ID の Connection ID で返すことを MUST と
            // する)。CID が確定した後に同じ保留応答を送る。
            if path.peer_cid.is_none() && path.id != PathId::INITIAL {
                continue;
            }
            while responses.len() < MAX_RESPONSES_PER_EMIT {
                let Some(pending) = path.validation.take_pending_response() else {
                    break;
                };
                responses.push((path.id, pending));
            }
            if responses.len() >= MAX_RESPONSES_PER_EMIT {
                break;
            }
        }
        for (resp_path_id, pending) in responses {
            // PATH_CHALLENGE を受信した 4-tuple へ返す (RFC 9000 Section 8.2.2 の MUST)
            // 拡張の可否は、チャレンジを運んだデータグラム長と実出力時の増幅枠で
            // 判定する。
            self.emit_1rtt_path_response_to(
                resp_path_id,
                pending.data,
                pending.remote_addr,
                pending.local_addr,
                pending.datagram_len,
                now,
            )?;
        }
        Ok(())
    }

    /// 4-tuple 移行の検証が成功したときにアドレスと CID を確定する
    ///
    /// 検証に使った PATH_CHALLENGE と PATH_RESPONSE の照合は
    /// `PathValidation::response_received` で完了している。ここでは移行文脈を
    /// 持つパスかどうかだけを確認し、新しいアドレスと CID を確定する。
    /// 検証成功の直後に呼ばれるため、通常のパス検証 (追加パス) では
    /// 移行文脈が存在せず何もしない。
    ///
    /// 検証中に Retire Prior To の増加で candidate が退役した場合は、
    /// `reconcile_pending_migrations_after_cid_retire` が有効な CID に
    /// 置き換えている。その場合も退役済み CID へ戻さず、置き換え後の CID を
    /// 使う。置き換え先が無い状態は通常経路では到達しないが、到達した場合は
    /// 警告を記録して移行を確定せずに取り消す (debug / release で同じ挙動)。
    fn commit_pending_migration(&mut self, path_id: PathId, now: Timestamp) {
        let Some(migration) = self.pending_migrations.get(&path_id) else {
            return;
        };
        // RFC 9000 Section 5.1.2: 退役した CID を使い続けてはならない。
        // 保存時点の candidate が退役している場合は、未使用の CID に置き換える。
        // この経路は reconcile が先に処理しているため通常は到達しない。
        let candidate_peer_cid = if self.is_active_peer_cid(path_id, &migration.candidate_peer_cid)
        {
            migration.candidate_peer_cid.clone()
        } else {
            let Some(replacement) = self.take_unused_peer_cid_for_path(path_id) else {
                // 移行先の DCID に使える CID が無い。PathValidated の後に
                // PathValidationFailed を積む矛盾を避けるため、イベントを出さずに
                // 破棄する。予約済みの CID は未送信なら解放する。
                // 通常は reconcile が先に候補を置き換えるため到達しないが、
                // debug / release で挙動を揃えるためログだけ残して破棄する。
                tracing::warn!(
                    path_id = %path_id,
                    "retired migration candidate has no replacement; discarding the pending migration"
                );
                self.discard_pending_migration(path_id);
                return;
            };
            replacement
        };
        // 送信済みの候補は予約時点で used になっている。まだ送っていない候補で
        // commit した場合も、送信先として使うため used にする
        // (RFC 9000 Section 9.5)。
        self.mark_peer_cid_used(path_id, &candidate_peer_cid);
        let Some(migration) = self.pending_migrations.remove(&path_id) else {
            // 上の get で存在を確認済みであり、通常は到達しない。到達した場合は
            // 状態を変更せず黙って戻る。呼び出し側はすでに PathValidated を
            // 通知しているため、ここで PathValidationFailed を積むと矛盾する。
            return;
        };
        let Some(path) = self.paths.get_mut(path_id) else {
            // パスが消えている場合は commit しない。呼び出し側はすでに
            // PathValidated を通知しているため、イベントを重ねない
            // (PathClosed / PathAbandoned が別経路で通知される)。
            return;
        };
        // 旧 4-tuple からの遅延パケット抑止のため、アドレスを書き換える前に
        // 移行確定時刻と旧 4-tuple を記録する
        path.note_migration_committed(now);
        path.remote_addr = migration.candidate_remote_addr;
        if let Some(local_addr) = migration.candidate_local_addr {
            path.local_addr = local_addr;
        }
        if path_id == PathId::INITIAL {
            self.peer_cid = candidate_peer_cid.clone();
        }
        path.peer_cid = Some(candidate_peer_cid);
        if migration.from_preferred_address {
            self.acted_on_preferred_address = true;
        }
        // 移行後の 4-tuple を I/O 層へ通知する
        let (remote_addr, local_addr) = (path.remote_addr, path.local_addr);
        self.output_queue.push_back(ConnectionOutput::PathOpened {
            path_id,
            local_addr,
            remote_addr,
        });
    }

    /// 4-tuple 移行の検証が失敗したときに元の状態へ戻す
    ///
    /// パスの 4-tuple と CID は検証中に変更していないため、新しいアドレスの
    /// 破棄とイベント通知だけを行う。preferred_address への移行では
    /// RFC 9000 Section 9.6.1 の MUST に従い、検証に失敗した場合は元の
    /// アドレスを使い続ける。
    ///
    /// 検証中に Retire Prior To の増加で original が退役した場合や、能動回転で
    /// 送信先 CID が変わった場合も、退役済みの CID を書き戻さない
    /// (RFC 9000 Section 5.1.2)。現在のパスが有効な CID を保持していればそれを
    /// 維持し、そうでなければ保存した original、それも無効なら有効な CID を
    /// 選び直す。置き換え先が無い場合は現在のパス状態を維持する
    /// (新しい CID の受信後に送信先が更新される)。
    ///
    /// 戻り値は移行検証中だったかどうか。`false` の場合は通常のパス検証失敗
    /// として扱う (呼び出し側がパスを廃棄する)。
    fn abort_pending_migration(&mut self, path_id: PathId) -> bool {
        // 可変借用より前に、判定に使う値を控える。
        let (saved_original_peer_cid, candidate_peer_cid, candidate_probe_sent) =
            match self.pending_migrations.get(&path_id) {
                Some(migration) => (
                    migration.original_peer_cid.clone(),
                    migration.candidate_peer_cid.clone(),
                    migration.candidate_probe_sent,
                ),
                None => return false,
            };
        // RFC 9000 Section 5.1.2: 退役した CID を使い続けてはならない。
        // 検証中に送信先が更新されている場合は、その有効な CID を維持する。
        // 更新されていない、または退役している場合だけ保存値へ戻す。
        let current_peer_cid = self
            .paths
            .get(path_id)
            .and_then(|path| path.peer_cid.clone())
            .or_else(|| (path_id == PathId::INITIAL).then(|| self.peer_cid.clone()));
        let original_peer_cid = if current_peer_cid
            .as_ref()
            .is_some_and(|cid| self.is_active_peer_cid(path_id, cid))
        {
            current_peer_cid
        } else if let Some(cid) =
            saved_original_peer_cid.filter(|cid| self.is_active_peer_cid(path_id, cid))
        {
            Some(cid)
        } else {
            self.take_peer_cid_for_path(path_id)
        };
        if let Some(cid) = &original_peer_cid {
            self.mark_peer_cid_used(path_id, cid);
        }
        // 検証パケットを一度も送っていない候補 CID は予約を解放する。送信済みなら
        // RFC 9000 Section 9.5 により再利用できないため used のまま残す。
        if !candidate_probe_sent {
            self.release_peer_cid_reservation(path_id, &candidate_peer_cid);
        }
        let Some(migration) = self.pending_migrations.remove(&path_id) else {
            // 上の get で存在を確認済みであり、通常は到達しない。競合して
            // 消えていた場合は状態を変更せず false を返す。
            return false;
        };
        // 検証前の値へ戻す (検証中は変更していないが、防御的に書き戻す)
        if let Some(path) = self.paths.get_mut(path_id) {
            path.remote_addr = migration.original_remote_addr;
            path.local_addr = migration.original_local_addr;
            if let Some(peer_cid) = original_peer_cid {
                if path_id == PathId::INITIAL {
                    self.peer_cid = peer_cid.clone();
                }
                path.peer_cid = Some(peer_cid);
            }
            path.migration_reset_pending = false;
            path.validation.restart();
        }
        self.push_event(ConnectionEvent::PathValidationFailed { path_id });
        true
    }
}

// --- ヘルパー関数 ---

/// アプリケーションイベントが対象とするストリーム ID を返す
///
/// ストリーム GC が未消費イベントを見落とさないようにするために使う。
fn connection_event_stream_id(event: &ConnectionEvent) -> Option<u64> {
    match event {
        ConnectionEvent::NewStream { stream_id }
        | ConnectionEvent::StreamReadable { stream_id }
        | ConnectionEvent::StreamWritable { stream_id }
        | ConnectionEvent::StreamReset { stream_id, .. }
        | ConnectionEvent::StreamStopSending { stream_id, .. } => Some(*stream_id),
        _ => None,
    }
}

/// preferred_address から使用するアドレスを選ぶ (RFC 9000 Section 9.6.1)
///
/// サーバーは IPv4 / IPv6 の両方を通知できるため、`reference` (初期パスの
/// リモートアドレス) と同じアドレスファミリのアドレスを優先する。同じ
/// ファミリのアドレスが通知されていない場合は、port が 0 でない側を使う
/// (port 0 は未使用を意味する)。
///
/// どちらも使えない場合は port 0 のアドレスを返し、呼び出し側がエラーにする。
fn resolve_preferred_addr(
    pa: &tobi_core::transport_params::PreferredAddress,
    reference: std::net::SocketAddr,
) -> std::net::SocketAddr {
    let ipv4 =
        std::net::SocketAddr::from((std::net::Ipv4Addr::from(pa.ipv4_address), pa.ipv4_port));
    let ipv6 =
        std::net::SocketAddr::from((std::net::Ipv6Addr::from(pa.ipv6_address), pa.ipv6_port));
    let prefer_ipv6 = reference.is_ipv6();
    let (preferred, fallback) = if prefer_ipv6 {
        (ipv6, ipv4)
    } else {
        (ipv4, ipv6)
    };
    // port 0 は未使用を意味する (RFC 9000 Section 18.2)。非ゼロ port でも
    // unspecified アドレスは接続先にできないため、使えるアドレスとして扱わない。
    let usable = |addr: std::net::SocketAddr| addr.port() != 0 && !addr.ip().is_unspecified();
    if usable(preferred) {
        preferred
    } else if usable(fallback) {
        fallback
    } else {
        // 呼び出し側が port 0 を見てエラーにする
        std::net::SocketAddr::new(preferred.ip(), 0)
    }
}

/// PTO 計算に加算する実効 max_ack_delay を解決する (RFC 9002 Section 6.2.1)
///
/// - Initial / Handshake 空間の PTO には加算しない (`Duration::ZERO`)
/// - Application Data (OneRtt) 空間でもハンドシェイク未確認の間は加算しない
/// - ハンドシェイク確認済みでも Initial / Handshake 空間の in-flight が
///   1 つでも残っている間は加算しない
///
/// `process_ack` の level 分岐をピュア関数として切り出し、
/// 全組み合わせをユニットテストで検証できるようにする。
/// ECN 検証状態を qlog の ECNState 文字列へ変換する
///
/// qlog-quic-events-13 Section 7.6 の ECNState は
/// `"testing"` / `"unknown"` / `"failed"` / `"capable"` を取る。
/// 本実装は `Testing` / `Capable` / `Failed` の 3 状態なので `"unknown"` は使わない。
fn ecn_state_name(state: EcnValidationState) -> &'static str {
    match state {
        EcnValidationState::Testing => "testing",
        EcnValidationState::Capable => "capable",
        EcnValidationState::Failed => "failed",
    }
}

/// DATAGRAM フレーム全体の最大サイズから、ペイロード部分の最大サイズを求める
///
/// DATAGRAM フレーム (LEN ビットあり、0x31) はフレームタイプ (1 byte) と
/// Length (VarInt) とペイロードで構成される。Length の VarInt 長はペイロード長に
/// 依存するため、ペイロードが収まる最大値を求める。
fn datagram_payload_limit(frame_max: usize) -> usize {
    // フレームタイプ (0x31 は 1 byte VarInt) を差し引く
    let remaining = frame_max.saturating_sub(1);
    if remaining <= 63 + 1 {
        // Length は 1 byte VarInt
        remaining.saturating_sub(1)
    } else if remaining <= 16383 + 2 {
        // Length は 2 byte VarInt
        remaining.saturating_sub(2)
    } else if remaining <= 1073741823 + 4 {
        // Length は 4 byte VarInt
        remaining.saturating_sub(4)
    } else {
        // Length は 8 byte VarInt
        remaining.saturating_sub(8)
    }
}

/// RTT サンプル調整に使う実効 max_ack_delay を決める (RFC 9002 Section 5.3)
///
/// - ハンドシェイク確認前はピアの `max_ack_delay` を無視する (SHOULD)。
///   上限なしを表す `Duration::from_micros(u64::MAX)` を返し、`RttEstimator::update`
///   の `capped_delay = min(ack_delay, max_ack_delay)` でキャップが外れるようにする。
///   ハンドシェイク中はピアが `max_ack_delay` を超える `ack_delay` を報告し得るため
///   (RFC 9000 Section 13.2.1)、キャップすると RTT を過大評価する。
/// - 確認後はピアの `max_ack_delay` を使う (MUST: lesser of ack_delay and max_ack_delay)。
///   ピアの transport parameter 未取得時は既定の 25ms を使う。
///
/// ピュア関数として切り出し、確認状態ごとのマッピングをユニットテストで検証できるようにする。
/// RTT サンプルの ACK 遅延補正に使う遅延を返す (RFC 9002 Section 5.3)
///
/// ACK Delay フィールドの値をそのまま減算してよいのは、Application Data
/// 空間かつハンドシェイク確認後の ACK だけである。
/// - Initial / Handshake 空間の ACK は遅延なく送られる (RFC 9000 Section 13.2.1)
///   ため、ACK Delay は RTT サンプルに反映しない。
/// - 0-RTT パケットの ACK はハンドシェイク確認前に届くため、ローカルの
///   鍵待ち遅延が混入する。確認前は補正しない。
///
/// 戻り値は減算対象の遅延で、実際の減算と min_rtt によるクランプは
/// `RttEstimator::update` が行う (負にはならない)。
fn ack_delay_for_rtt_sample(
    space: PacketNumberSpace,
    handshake_confirmed: bool,
    ack_delay: Duration,
) -> Duration {
    if matches!(space, PacketNumberSpace::ApplicationData) && handshake_confirmed {
        ack_delay
    } else {
        Duration::ZERO
    }
}

fn effective_max_ack_delay(
    handshake_confirmed: bool,
    peer_max_ack_delay: Option<Duration>,
) -> Duration {
    if handshake_confirmed {
        peer_max_ack_delay.unwrap_or_else(|| Duration::from_millis(25))
    } else {
        Duration::from_micros(u64::MAX)
    }
}

/// `retry_source_connection_id` を検証する (RFC 9000 Section 7.3)
///
/// - Retry を受信した場合: 通知された値が Retry パケットの SCID と一致する (MUST)
/// - Retry を受信していない場合: `retry_source_connection_id` を送信してはならない (MUST NOT)
///
/// 違反時は `PROTOCOL_VIOLATION` を返す。
fn validate_retry_source_connection_id(
    retry_scid: Option<&ConnectionId>,
    received: Option<&ConnectionId>,
) -> Result<(), Error> {
    match (retry_scid, received) {
        (Some(expected), Some(received)) if expected.as_bytes() != received.as_bytes() => {
            Err(Error::Protocol {
                code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
                reason: "retry_source_connection_id mismatch with Retry packet SCID".into(),
            })
        }
        (Some(_), None) => Err(Error::Protocol {
            code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
            reason: "retry_source_connection_id is missing after Retry".into(),
        }),
        (None, Some(_)) => Err(Error::Protocol {
            code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
            reason: "retry_source_connection_id received without Retry".into(),
        }),
        _ => Ok(()),
    }
}

/// クライアントが受信したサーバーのトランスポートパラメータを検証する
/// (RFC 9000 Section 7.3)
///
/// クライアントは次の値を検証しなければならない (MUST)。
///
/// - `original_destination_connection_id` が自身の最初の Initial の DCID と一致すること
///   (欠落は `TRANSPORT_PARAMETER_ERROR`)
/// - `initial_source_connection_id` がサーバーの最初の Initial の SCID と一致すること
///   (欠落は `TRANSPORT_PARAMETER_ERROR`)
/// - Retry 受信時は `retry_source_connection_id` が Retry の SCID と一致すること
fn validate_server_transport_params(
    params: &TransportParams,
    original_dcid: &ConnectionId,
    server_initial_scid: &ConnectionId,
    retry_scid: Option<&ConnectionId>,
) -> Result<(), Error> {
    let odcid = params
        .original_destination_connection_id
        .as_ref()
        .ok_or_else(|| Error::Protocol {
            code: tobi_core::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            reason: "original_destination_connection_id is missing".into(),
        })?;
    if odcid.as_bytes() != original_dcid.as_bytes() {
        return Err(Error::Protocol {
            code: tobi_core::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            reason: "original_destination_connection_id mismatch with the first Initial DCID"
                .into(),
        });
    }

    let iscid = params
        .initial_source_connection_id
        .as_ref()
        .ok_or_else(|| Error::Protocol {
            code: tobi_core::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            reason: "initial_source_connection_id is missing".into(),
        })?;
    if iscid.as_bytes() != server_initial_scid.as_bytes() {
        return Err(Error::Protocol {
            code: tobi_core::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            reason: "initial_source_connection_id mismatch with the server Initial SCID".into(),
        });
    }

    validate_retry_source_connection_id(retry_scid, params.retry_source_connection_id.as_ref())
}

/// サーバーが受信したクライアントのトランスポートパラメータを検証する
/// (RFC 9000 Section 7.3 / Section 18.2)
///
/// クライアントはサーバー専用のトランスポートパラメータを送信してはならない。
/// 送信されていた場合は `TRANSPORT_PARAMETER_ERROR` で接続を閉じる。
/// `initial_source_connection_id` はクライアントの最初の Initial の SCID と
/// 一致しなければならず、欠落も不一致も `TRANSPORT_PARAMETER_ERROR` とする。
fn validate_client_transport_params(
    params: &TransportParams,
    client_initial_scid: &ConnectionId,
) -> Result<(), Error> {
    let server_only_params = [
        (
            params.original_destination_connection_id.is_some(),
            "original_destination_connection_id",
        ),
        (params.preferred_address.is_some(), "preferred_address"),
        (
            params.retry_source_connection_id.is_some(),
            "retry_source_connection_id",
        ),
        (
            params.stateless_reset_token.is_some(),
            "stateless_reset_token",
        ),
    ];
    for (present, name) in server_only_params {
        if present {
            return Err(Error::Protocol {
                code: tobi_core::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                reason: format!("client sent server-only transport parameter {name}"),
            });
        }
    }

    let iscid = params
        .initial_source_connection_id
        .as_ref()
        .ok_or_else(|| Error::Protocol {
            code: tobi_core::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            reason: "initial_source_connection_id is missing".into(),
        })?;
    if iscid.as_bytes() != client_initial_scid.as_bytes() {
        return Err(Error::Protocol {
            code: tobi_core::error::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            reason: "initial_source_connection_id mismatch with the client Initial SCID".into(),
        });
    }
    Ok(())
}

/// 指定パスのピア CID 数が `active_connection_id_limit` を超えていないか検査する
///
/// RFC 9000 Section 5.1.1 / RFC 10069 Section 2.2:
/// Multipath 有効時は `active_connection_id_limit` をパスごとに適用する。
/// 超過した場合は `CONNECTION_ID_LIMIT_ERROR` で接続を閉じる。
///
/// `Connection::enforce_peer_cid_limit` から呼び出される薄いピュア関数として
/// 切り出し、ユニットテストを書きやすくする。
fn check_peer_cid_limit(
    entries: &[PeerCidEntry],
    path_id: PathId,
    limit: u64,
) -> Result<(), Error> {
    let count = entries.iter().filter(|e| e.path_id == path_id).count() as u64;
    if count > limit {
        return Err(Error::Protocol {
            code: tobi_core::error::TransportErrorCode::CONNECTION_ID_LIMIT_ERROR,
            reason: format!(
                "peer CID count {count} for path {path_id} exceeds active_connection_id_limit {limit}"
            ),
        });
    }
    Ok(())
}

/// 制御フレームに対応する `SentFrameInfo` を返す
///
/// 1-RTT / 0-RTT の `pending_frames` 経由の送信と、`emit_1rtt_single_frame`
/// 経由の送信で同じ記録を使う。`send_path_id` は OBSERVED_ADDRESS のように
/// フレーム自身が送信パスを持たない制御フレームの記録に使う
/// (draft-ietf-quic-address-discovery-01 Section 4.1)。
fn sent_frame_info_for_control(frame: &Frame, send_path_id: PathId) -> SentFrameInfo {
    match frame {
        Frame::PathAbandon(abandon) => SentFrameInfo::PathAbandon {
            path_id: abandon.path_id,
            error_code: abandon.error_code.as_u64(),
        },
        Frame::PathStatusAvailable(status) => SentFrameInfo::PathStatus {
            path_id: status.path_id,
            status: PathStatus::Available,
            sequence_number: status.path_status_sequence_number.as_u64(),
        },
        Frame::PathStatusBackup(status) => SentFrameInfo::PathStatus {
            path_id: status.path_id,
            status: PathStatus::Backup,
            sequence_number: status.path_status_sequence_number.as_u64(),
        },
        Frame::MaxPathId(maximum) => SentFrameInfo::MaxPathId {
            maximum_path_id: maximum.maximum_path_id,
        },
        Frame::RetireConnectionId(retire) => SentFrameInfo::RetireConnectionId {
            path_id: 0,
            sequence_number: retire.sequence_number.as_u64(),
        },
        Frame::PathRetireConnectionId(retire) => SentFrameInfo::RetireConnectionId {
            path_id: retire.path_id,
            sequence_number: retire.sequence_number.as_u64(),
        },
        Frame::PathsBlocked(blocked) => SentFrameInfo::PathsBlocked {
            maximum_path_id: blocked.maximum_path_id,
        },
        Frame::PathCidsBlocked(blocked) => SentFrameInfo::PathCidsBlocked {
            path_id: blocked.path_id,
            next_sequence_number: blocked.next_sequence_number.as_u64(),
        },
        // RFC 9000 Section 13.3: NEW_TOKEN はロスト時に同一内容で再送する。
        Frame::NewToken(token) => SentFrameInfo::NewToken {
            token: token.token.clone(),
        },
        Frame::DataBlocked(_) => SentFrameInfo::DataBlocked,
        Frame::StreamDataBlocked(blocked) => SentFrameInfo::StreamDataBlocked {
            stream_id: blocked.stream_id.as_u64(),
        },
        Frame::StreamsBlocked(blocked) => SentFrameInfo::StreamsBlocked {
            bidirectional: blocked.bidirectional,
        },
        Frame::MaxData(_) => SentFrameInfo::MaxData,
        Frame::MaxStreamData(msd) => SentFrameInfo::MaxStreamData {
            stream_id: msd.stream_id.as_u64(),
        },
        Frame::MaxStreams(ms) => SentFrameInfo::MaxStreams {
            is_bidi: ms.bidirectional,
        },
        Frame::ResetStream(rs) => SentFrameInfo::ResetStream {
            stream_id: rs.stream_id.as_u64(),
            error_code: rs.application_protocol_error_code.as_u64(),
            final_size: rs.final_size.as_u64(),
        },
        Frame::ResetStreamAt(rsa) => SentFrameInfo::ResetStreamAt {
            stream_id: rsa.stream_id.as_u64(),
            error_code: rsa.application_protocol_error_code.as_u64(),
            final_size: rsa.final_size.as_u64(),
            reliable_size: rsa.reliable_size.as_u64(),
        },
        Frame::StopSending(ss) => SentFrameInfo::StopSending {
            stream_id: ss.stream_id.as_u64(),
            error_code: ss.application_protocol_error_code.as_u64(),
        },
        Frame::NewConnectionId(ncid) => SentFrameInfo::NewConnectionId {
            path_id: 0,
            sequence_number: ncid.sequence_number.as_u64(),
            retire_prior_to: ncid.retire_prior_to.as_u64(),
            connection_id: ncid.connection_id.clone(),
            stateless_reset_token: ncid.stateless_reset_token,
        },
        Frame::PathNewConnectionId(pncid) => SentFrameInfo::NewConnectionId {
            path_id: pncid.path_id,
            sequence_number: pncid.sequence_number.as_u64(),
            retire_prior_to: pncid.retire_prior_to.as_u64(),
            connection_id: pncid.connection_id.clone(),
            stateless_reset_token: pncid.stateless_reset_token,
        },
        Frame::ObservedAddress(oa) => SentFrameInfo::ObservedAddress {
            path_id: send_path_id.0,
            sequence_number: oa.sequence_number.as_u64(),
            addr: oa.addr,
        },
        Frame::HandshakeDone(_) => SentFrameInfo::HandshakeDone,
        Frame::AckFrequency(af) => SentFrameInfo::AckFrequency {
            sequence_number: af.sequence_number.as_u64(),
            requested_max_ack_delay: af.requested_max_ack_delay.as_u64(),
        },
        // PATH_ACK は 1-RTT 専用であり、1-RTT の packet_sent は送信 payload の
        // デコードから作るため、確認応答内容は保持しない。
        Frame::PathAck(_) => SentFrameInfo::PathAck,
        _ => SentFrameInfo::Other,
    }
}

/// 制御フレームが 0-RTT パケットで送信できるかを判定する
///
/// RFC 9000 Section 12.4 Table 3 の 0-RTT 列に基づく。RESET_STREAM_AT は
/// draft-ietf-quic-reliable-stream-reset-11 Section 3 により 0-RTT で利用できる。
fn is_control_frame_allowed_in_zero_rtt(frame: &Frame) -> bool {
    matches!(
        frame,
        Frame::Padding(_)
            | Frame::Ping(_)
            | Frame::ResetStream(_)
            | Frame::ResetStreamAt(_)
            | Frame::StopSending(_)
            | Frame::MaxData(_)
            | Frame::MaxStreamData(_)
            | Frame::MaxStreams(_)
            | Frame::DataBlocked(_)
            | Frame::StreamDataBlocked(_)
            | Frame::StreamsBlocked(_)
            | Frame::NewConnectionId(_)
            | Frame::RetireConnectionId(_)
            | Frame::PathChallenge(_)
            | Frame::Datagram(_)
    )
}

/// フレームが指定された暗号化レベルで許可されるかを判定する
///
/// RFC 9000 Section 12.4 Table 3 および
/// RFC 10069 Section 4 に基づく。
///
/// I = Initial, H = Handshake, 0 = 0-RTT, 1 = 1-RTT
/// アプリケーション由来のシーケンス番号を varint の範囲内で進める
///
/// ACK_FREQUENCY や PATH_STATUS のシーケンス番号はアプリの呼び出しごとに
/// 増える。呼び出し回数が 2^62 に達しても `VarInt::new` が失敗しないよう、
/// 最大値で飽和させる。
fn next_varint_sequence(counter: &mut u64) -> VarInt {
    let value = (*counter).min(tobi_core::varint::MAX_VALUE);
    *counter = value.saturating_add(1).min(tobi_core::varint::MAX_VALUE);
    VarInt::new(value).expect("clamped to 62-bit varint")
}

fn is_frame_allowed_in_level(frame: &Frame, level: EncryptionLevel) -> bool {
    // 0-RTT で送受信できるフレームは RFC 9000 Section 12.4 Table 3 が定める。
    // 許可: PADDING / PING / RESET_STREAM / STOP_SENDING / STREAM /
    //       MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS / DATA_BLOCKED /
    //       STREAM_DATA_BLOCKED / STREAMS_BLOCKED / NEW_CONNECTION_ID /
    //       RETIRE_CONNECTION_ID / PATH_CHALLENGE / CONNECTION_CLOSE(0x1c, 0x1d)
    // 禁止: ACK / CRYPTO / NEW_TOKEN / PATH_RESPONSE / HANDSHAKE_DONE
    //
    // 0x1d (APPLICATION_CLOSE) はアプリケーションデータのパケット番号空間
    // (0-RTT / 1-RTT) でのみ送信できる (RFC 9000 Section 12.5)。
    // そのため 0-RTT では 0x1c と 0x1d の両方を受理する。
    //
    // multipath 拡張のフレーム (PATH_ACK / PATH_ABANDON / PATH_STATUS /
    // PATH_NEW_CONNECTION_ID / PATH_RETIRE_CONNECTION_ID / MAX_PATH_ID /
    // PATHS_BLOCKED / PATH_CIDS_BLOCKED) は 1-RTT 専用とする
    // (RFC 10069 Section 4)。
    // DATAGRAM は 0-RTT でも送受信できる (RFC 9221 Section 5.1: __01)。
    //
    // RESET_STREAM_AT も 0-RTT で使用できる
    // (draft-ietf-quic-reliable-stream-reset-11 Section 3: 0-RTT では両端が
    //  前回セッションでサーバーがこの拡張を広告したかを記憶する MUST)。
    // 送信可否は StreamManager の peer_supports_reset_stream_at ガードが
    // 記憶した広告値で判定するため、ここでは暗号化レベル上の可否だけを扱う。
    if level == EncryptionLevel::ZeroRtt {
        return matches!(
            frame,
            Frame::Padding(_)
                | Frame::Ping(_)
                | Frame::ResetStream(_)
                | Frame::StopSending(_)
                | Frame::Stream(_)
                | Frame::MaxData(_)
                | Frame::MaxStreamData(_)
                | Frame::MaxStreams(_)
                | Frame::DataBlocked(_)
                | Frame::StreamDataBlocked(_)
                | Frame::StreamsBlocked(_)
                | Frame::NewConnectionId(_)
                | Frame::RetireConnectionId(_)
                | Frame::PathChallenge(_)
                | Frame::Datagram(_)
                | Frame::ResetStreamAt(_)
                | Frame::ConnectionClose(_)
        );
    }

    match frame {
        // PADDING: IH01
        Frame::Padding(_) => true,
        // PING: IH01
        Frame::Ping(_) => true,
        // ACK: IH_1
        Frame::Ack(_) => true,
        // CRYPTO: IH_1
        Frame::Crypto(_) => true,
        // CONNECTION_CLOSE (type 0x1c): IH01
        // CONNECTION_CLOSE (type 0x1d / application): __01 のみ
        Frame::ConnectionClose(cc) => {
            if cc.application {
                level == EncryptionLevel::OneRtt
            } else {
                true
            }
        }
        // 以下は 1-RTT のみ
        Frame::ResetStream(_)
        | Frame::StopSending(_)
        | Frame::NewToken(_)
        | Frame::Stream(_)
        | Frame::MaxData(_)
        | Frame::MaxStreamData(_)
        | Frame::MaxStreams(_)
        | Frame::DataBlocked(_)
        | Frame::StreamDataBlocked(_)
        | Frame::StreamsBlocked(_)
        | Frame::NewConnectionId(_)
        | Frame::RetireConnectionId(_)
        | Frame::PathChallenge(_)
        | Frame::PathResponse(_)
        | Frame::HandshakeDone(_)
        | Frame::PathAck(_)
        | Frame::PathAbandon(_)
        | Frame::PathStatusAvailable(_)
        | Frame::PathStatusBackup(_)
        | Frame::PathNewConnectionId(_)
        | Frame::PathRetireConnectionId(_)
        | Frame::MaxPathId(_)
        | Frame::PathsBlocked(_)
        | Frame::PathCidsBlocked(_)
        | Frame::ObservedAddress(_)
        | Frame::ResetStreamAt(_)
        | Frame::AckFrequency(_)
        | Frame::ImmediateAck(_)
        | Frame::AckReceiveTimestamps(_)
        | Frame::PathAckReceiveTimestamps(_)
        // DATAGRAM: __01 (RFC 9221 Section 5)
        | Frame::Datagram(_) => level == EncryptionLevel::OneRtt,
    }
}

/// フレーム処理の結果
///
/// `Connection::process_frames` が返す。migration の判定に使うため、
/// ack-eliciting だけでなく non-probing の有無も伝える。
#[derive(Debug)]
pub(crate) struct FrameProcessOutcome {
    /// ack-eliciting フレームを含んでいたか (RFC 9000 Section 13.2.1)
    pub(crate) ack_eliciting: bool,
    /// non-probing フレームを含んでいたか (RFC 9000 Section 9.1)
    pub(crate) non_probing: bool,
}

/// PTO で再送できるフレームを含むパケットかどうかを判定する
///
/// ACK / PATH_ACK と再送不要フレーム (PING 等) だけのパケットは、PTO で内容を
/// 再送する意味が無い。PTO の再送対象を選ぶときに、この判定で
/// 再送できるフレームを持つ最も古い ack-eliciting in-flight パケットを探す。
/// 1 回の 1-RTT データ送信で試すパス選択の上限
///
/// pacing / バースト制限でパスをスキップした場合に、他パスを試すための
/// 上限。無限ループを防ぐ。
const MAX_SEND_PATH_ATTEMPTS: usize = 16;

/// 冗長スケジューラーで 1 回の送信機会に複製送信する最大パス数
///
/// スケジューラーの設定値と候補パス数の小さい方に制限される。
const MAX_REDUNDANT_PATHS: usize = 8;

/// pacing のバースト上限に達したときの再試行間隔 (マイクロ秒)
const PACING_BURST_RETRY_INTERVAL_MICROS: u64 = 1_000;

/// Receive Timestamps 拡張で使う受信タイムスタンプの基準値 (マイクロ秒)
///
/// draft-ietf-quic-receive-ts-03 Section 6.1: 基準値はセッション中に一定で、
/// 報告する最小の受信タイムスタンプより小さくなければならない (MUST)。
/// `Timestamp` は単調増加するマイクロ秒表現のため 0 を基準値にする。
/// 受信時刻が 0 のパケットは報告対象から除外する (AckTracker 側で記録しない)。
const RECEIVE_TIMESTAMP_BASIS: u64 = 0;

/// ACK / PATH_ACK / PADDING のみで構成されるフレーム列かを返す
///
/// RFC 9000 Section 12.4 / RFC 9002 Section 7.7: ACK と PATH_ACK のみの
/// パケットは ack-eliciting ではなく、pacing の対象にもしない。
fn frames_are_ack_only(frames: &[Frame]) -> bool {
    frames.iter().all(|frame| {
        matches!(
            frame,
            Frame::Ack(_)
                | Frame::PathAck(_)
                | Frame::AckReceiveTimestamps(_)
                | Frame::PathAckReceiveTimestamps(_)
                | Frame::Padding(_)
        )
    })
}

/// ACK / PATH_ACK のみで構成される送信フレーム列かを返す
///
/// RFC 9000 Section 12.4 / RFC 9002 Section 2: PATH_ACK も ACK と同様に
/// ack-eliciting ではない。
fn sent_frame_infos_are_ack_only(frames: &[SentFrameInfo]) -> bool {
    frames
        .iter()
        .all(|frame| matches!(frame, SentFrameInfo::Ack { .. } | SentFrameInfo::PathAck))
}

/// `MtuController` の現在値がパスの PMTU と異なれば反映し、変化を返す
///
/// 反映と輻輳制御への通知を 1 箇所にまとめ、ACK 済みパケット・ロスト・移行の
/// どの経路でも同じ処理を通す。戻り値は (変更前, 変更後, 探索完了) で、
/// 変化が無ければ `None` を返す。qlog の `mtu_updated` は呼び出し側が 1 回だけ出す
/// (qlog-quic-events-13 Section 4.8)。
fn apply_pmtu_from_controller<CC: CongestionControl>(
    mtu_controller: &mut tobi_core::path::mtu::MtuController,
    pmtu: &mut u16,
    congestion: &mut CC,
) -> Option<(u16, u16, bool)> {
    let new_mtu = mtu_controller.current_mtu();
    if new_mtu == *pmtu {
        return None;
    }
    let old_mtu = *pmtu;
    *pmtu = new_mtu;
    congestion.on_mtu_update(u64::from(new_mtu));
    // 探索完了は次のプローブが必要なくなった時点で通知する
    let done = !mtu_controller.needs_probe();
    Some((old_mtu, new_mtu, done))
}

/// BASE フェーズへ遷移したパスの旧探索の未送信プローブを破棄する
///
/// 旧探索で生成した未送信プローブは旧探索サイズのまま送信待ちに残る。BASE
/// フェーズでは base MTU の確認プローブを送る必要があるため、旧プローブを
/// 送らずに破棄する (RFC 8899 Section 5.2: PROBED_SIZE は BASE_PLPMTU)。
/// 送信済みプローブの追跡 (`pmtu_probe_pns`) とタイマーは、そのプローブの
/// ロストを輻輳として数えないために残す。
fn discard_pending_old_probe(path_id: PathId, one_rtt_outputs: &mut VecDeque<PendingOneRtt>) {
    one_rtt_outputs
        .retain(|pending| !(pending.path_id == path_id && pending.purpose == OneRttPurpose::Pmtu));
}

/// 旧探索で送信済みの PMTU プローブを回収する
///
/// BASE フェーズへ遷移すると、旧探索のプローブはタイマーの監視対象から外れる。
/// 送信記録を残すと `bytes_in_flight` と輻輳制御の per-packet 状態が残り続ける
/// ため、通常のロスト経路と同じ会計で破棄する。
fn discard_sent_pmtu_probes<CC: CongestionControl>(
    path: &mut Path<CC>,
    path_id: PathId,
    pmtu_probe_pns: &mut Vec<(PathId, u64)>,
) {
    for pn in path.sent_packets.pmtu_probe_pns() {
        if let Some(packet) = path.sent_packets.remove_packet(pn) {
            if packet.in_flight {
                path.congestion.on_packet_discarded_bytes(packet.sent_bytes);
            }
            path.congestion
                .on_packets_discarded_cc(PacketNumberSpace::ApplicationData, &[pn]);
        }
        pmtu_probe_pns
            .retain(|(probe_path, probe_pn)| !(*probe_path == path_id && *probe_pn == pn));
    }
}

/// ロストしたパケットを DPLPMTUD へ通知し、PMTU の変化を反映する
///
/// in-flight だったパケットだけを対象にする。ACK 済みパケット側の
/// `on_large_packet_acked` も in-flight だったパケットに限っており、
/// ロストと ACK の対象を対称に保つ。
///
/// RFC 8899 Section 4.3 の 3 番目の指標 (特定サイズで送ったデータの過剰な
/// 損失) を、本実装では base MTU を超えるパケットの連続ロストとして扱う。
/// ACK 受信で確定したロストと時間閾値のタイマーで確定したロストを同じ入力
/// として扱うのは実装方針であり、両経路で最終的な PMTU を一致させる。
///
/// probe のロストは探索の再試行 (MAX_PROBES は RFC 8899 Section 5.1.2、
/// PROBE_COUNT は Section 5.1.3、探索状態は Section 5.2) が扱うため、
/// ブラックホール検出のカウントには含めない。同じ事象を 2 つの機構へ
/// 通知しないための実装方針である。
fn apply_pmtu_loss_feedback<CC: CongestionControl>(
    path: &mut Path<CC>,
    lost_packets: &[SentPacket],
    now: Timestamp,
) -> Option<(u16, u16, bool)> {
    // ブラックホール検出の対象はパスごとの base MTU を超えるパケットである
    // (MtuController::on_large_packet_lost の契約)。
    let base_mtu = u64::from(path.mtu_controller.base_mtu());
    for packet in lost_packets.iter().filter(|packet| packet.in_flight) {
        // プローブのロストは PROBE_TIMER の経路で扱うため、ここでは通常
        // パケットのブラックホール検出だけを行う。
        if packet.sent_bytes > base_mtu {
            path.mtu_controller.on_large_packet_lost(now);
        }
    }
    // MTU が更新されたら反映する (ブラックホール検出等)
    apply_pmtu_from_controller(
        &mut path.mtu_controller,
        &mut path.pmtu,
        &mut path.congestion,
    )
}

/// フレームが送信対象としているストリームの ID を返す
///
/// STREAM / RESET_STREAM / RESET_STREAM_AT だけがストリームに紐づく。
/// これらのフレームはパケット化の時点でストリームの未出力予約
/// (`send_queued_count`) を消費するため、実出力・取り消し・終端遷移の対象を
/// 判定するときに使う。
fn sent_frame_stream_id(frame: &SentFrameInfo) -> Option<u64> {
    match frame {
        SentFrameInfo::Stream { stream_id, .. }
        | SentFrameInfo::ResetStream { stream_id, .. }
        | SentFrameInfo::ResetStreamAt { stream_id, .. } => Some(*stream_id),
        _ => None,
    }
}

fn has_retransmittable_frame(frames: &[SentFrameInfo]) -> bool {
    frames.iter().any(|frame| {
        !matches!(
            frame,
            SentFrameInfo::Ack { .. }
                | SentFrameInfo::PathAck
                | SentFrameInfo::AckFrequency { .. }
                | SentFrameInfo::Other
        )
    })
}

/// RFC 9000 Section 9.1 の probing フレームかどうかを判定する
///
/// > PATH_CHALLENGE, PATH_RESPONSE, NEW_CONNECTION_ID, and PADDING frames
/// > are "probing frames", and all other frames are "non-probing frames".
///
/// multipath 拡張の PATH_NEW_CONNECTION_ID は NEW_CONNECTION_ID の拡張であるため
/// probing として扱う。
fn is_probing_frame(frame: &Frame) -> bool {
    matches!(
        frame,
        Frame::Padding(_)
            | Frame::PathChallenge(_)
            | Frame::PathResponse(_)
            | Frame::NewConnectionId(_)
            | Frame::PathNewConnectionId(_)
            // OBSERVED_ADDRESS も probing フレームである
            // (draft-ietf-quic-address-discovery-01 Section 4)
            | Frame::ObservedAddress(_)
    )
}

/// multipath 拡張専用フレームかどうかを判定する
///
/// RFC 10069 Section 4 が定義する 9 種を対象とする。
/// PATH_CHALLENGE / PATH_RESPONSE は RFC 9000 の基本フレームのため含めない。
fn is_multipath_only_frame(frame: &Frame) -> bool {
    matches!(
        frame,
        Frame::PathAck(_)
            | Frame::PathAckReceiveTimestamps(_)
            | Frame::PathAbandon(_)
            | Frame::PathStatusAvailable(_)
            | Frame::PathStatusBackup(_)
            | Frame::PathNewConnectionId(_)
            | Frame::PathRetireConnectionId(_)
            | Frame::MaxPathId(_)
            | Frame::PathsBlocked(_)
            | Frame::PathCidsBlocked(_)
    )
}

/// Address Discovery の 0-RTT 再開時の値不変検証
///
/// draft-ietf-quic-address-discovery-01 Section 3:
/// サーバーが 0-RTT を受理した場合、address_discovery transport parameter を
/// 無効化または値変更してはならない (MUST NOT)。
fn validate_address_discovery_unchanged(
    early: Option<u64>,
    new: Option<u64>,
    zero_rtt_accepted: bool,
) -> Result<(), Error> {
    if zero_rtt_accepted
        && let Some(early_value) = early
        && new != Some(early_value)
    {
        return Err(Error::Protocol {
            code: tobi_core::error::TransportErrorCode::PROTOCOL_VIOLATION,
            reason: format!(
                "server changed address_discovery from {early_value} in 0-RTT to {new:?}"
            ),
        });
    }
    Ok(())
}

/// Long Header の Length フィールドを読み、ペイロード開始位置とパケット終端を返す
///
/// `header_len` は [`LongHeader::decode`] が返す固定部分の長さ (先頭バイトから
/// SCID の末尾まで)。戻り値は (Length フィールドの直後 = パケット番号の開始位置,
/// データグラム内のパケット終端) である。
///
/// 0-RTT / Handshake パケットは Length フィールドを持つ。鍵が無い場合でも
/// パケットの終端を求め、連結された後続パケットの処理を継続するために使う。
/// Initial パケットには使わない。Initial は Length の前に Token Length と Token が
/// 先行するため、`process_initial` が個別に解析する。
///
/// # エラー
///
/// `Error::Incomplete { needed }` の `needed` は、データグラムが Length が示す
/// パケット全体を含むために追加で必要なバイト数 (`packet_end - data.len()`)。
/// Length フィールド自体が途中で切れている場合は [`VarInt::decode`] が返す
/// 不足バイト数をそのまま返す。`header_len` がデータグラム長を超える場合は
/// `needed: 1` を返すが、`LongHeader::decode` が成功した `header_len` は常に
/// データグラム長以下であるため、通常の受信経路では到達しない。
/// `header_len` や Length の値が `usize` に収まらない場合や加算がオーバーフロー
/// する場合は `Error::InvalidData` を返す (64 ビット環境では通常到達しない)。
fn long_header_packet_end(data: &[u8], header_len: usize) -> Result<(usize, usize), Error> {
    let mut pos = header_len;
    let rest = data.get(pos..).ok_or(Error::Incomplete { needed: 1 })?;
    let (payload_length, n) = VarInt::decode(rest)?;
    pos += n;
    let payload_len = usize::try_from(payload_length.as_u64())
        .map_err(|_| Error::InvalidData("packet length exceeds usize".into()))?;
    let packet_end = pos
        .checked_add(payload_len)
        .ok_or_else(|| Error::InvalidData("packet length overflow".into()))?;
    if data.len() < packet_end {
        return Err(Error::Incomplete {
            needed: packet_end - data.len(),
        });
    }
    Ok((pos, packet_end))
}

/// rustls の HeaderProtectionKey で HP を除去する
///
/// first byte と packet number を in-place で変更し、pn_len を返す。
fn remove_hp_rustls(
    packet: &mut [u8],
    pn_offset: usize,
    hp_key: &dyn rustls::quic::HeaderProtectionKey,
    _is_long: bool,
) -> Result<u8, Error> {
    let sample_offset = pn_offset + 4;
    let sample_len = hp_key.sample_len();
    if packet.len() < sample_offset + sample_len {
        return Err(Error::InvalidData("packet too short for HP sample".into()));
    }
    let sample = packet[sample_offset..sample_offset + sample_len].to_vec();

    // まず first byte のマスクを除去して pn_len を取得するため、
    // 最大 4 バイトの pn をコピーして HP 除去する
    let pn_max = 4.min(packet.len() - pn_offset);
    let mut pn_bytes = packet[pn_offset..pn_offset + pn_max].to_vec();
    let mut first = packet[0];

    hp_key
        .decrypt_in_place(&sample, &mut first, &mut pn_bytes)
        .map_err(|_| Error::InvalidData("HP removal failed".into()))?;

    let pn_len = (first & 0x03) + 1;

    // 変更を書き戻す
    packet[0] = first;
    packet[pn_offset..pn_offset + pn_max].copy_from_slice(&pn_bytes);

    Ok(pn_len)
}

/// rustls の HeaderProtectionKey で HP を適用する
fn apply_hp_rustls(
    packet: &mut [u8],
    pn_offset: usize,
    pn_len: u8,
    hp_key: &dyn rustls::quic::HeaderProtectionKey,
    _is_long: bool,
) -> Result<(), Error> {
    let sample_offset = pn_offset + 4;
    let sample_len = hp_key.sample_len();
    if packet.len() < sample_offset + sample_len {
        return Err(Error::InvalidData("packet too short for HP sample".into()));
    }
    let sample = packet[sample_offset..sample_offset + sample_len].to_vec();

    let mut first = packet[0];
    let mut pn_bytes = packet[pn_offset..pn_offset + pn_len as usize].to_vec();

    hp_key
        .encrypt_in_place(&sample, &mut first, &mut pn_bytes)
        .map_err(|_| Error::InvalidData("HP application failed".into()))?;

    packet[0] = first;
    packet[pn_offset..pn_offset + pn_len as usize].copy_from_slice(&pn_bytes);

    Ok(())
}

// --- qlog ヘルパー ---

/// SentFrameInfo を QlogFrame に変換する
///
/// SentFrameInfo はフレームの完全な情報を持たないため、
/// 変換できないフレームは None を返す。
///
/// 呼び出し元は Initial / Handshake 空間の packet_sent だけである。
/// 1-RTT 空間の packet_sent は `prepare_one_rtt_output` が送信 payload を
/// デコードして作るため、この関数は通らない。
///
/// `ack_delay_exponent` は送信した ACK の ACK Delay を ms に変換するための
/// ローカルの指数である (RFC 9000 Section 19.3)。Initial / Handshake 空間の
/// ACK は即時送信のため、`SentFrameInfo::Ack` の `ack_delay` は常に 0 である。
fn sent_frame_to_qlog(info: &SentFrameInfo, ack_delay_exponent: u32) -> Option<qlog::QlogFrame> {
    match info {
        // ACK Frequency 拡張のフレームは qlog-quic-events-13 に対応イベントが
        // 無いため、`QlogFrame::from_frame` と同じ未知フレーム表現で記録する。
        SentFrameInfo::AckFrequency { .. } => Some(qlog::QlogFrame::Unknown {
            frame_type: tobi_core::frame::frame_type::ACK_FREQUENCY,
        }),
        SentFrameInfo::Crypto { offset, length } => Some(qlog::QlogFrame::Crypto {
            offset: *offset,
            length: *length,
        }),
        SentFrameInfo::Stream {
            stream_id,
            offset,
            length,
            fin,
            ..
        } => Some(qlog::QlogFrame::Stream {
            stream_id: *stream_id,
            offset: *offset,
            length: *length,
            fin: *fin,
        }),
        SentFrameInfo::NewConnectionId {
            path_id,
            sequence_number,
            connection_id,
            ..
        } => Some(qlog::QlogFrame::PathNewConnectionId {
            path_id: *path_id,
            sequence_number: *sequence_number,
            connection_id: qlog::cid_to_hex(connection_id),
        }),
        SentFrameInfo::RetireConnectionId {
            path_id,
            sequence_number,
        } => Some(qlog::QlogFrame::PathRetireConnectionId {
            path_id: *path_id,
            sequence_number: *sequence_number,
        }),
        SentFrameInfo::MaxPathId { maximum_path_id } => Some(qlog::QlogFrame::MaxPathId {
            maximum: *maximum_path_id,
        }),
        SentFrameInfo::PathsBlocked { maximum_path_id } => Some(qlog::QlogFrame::PathsBlocked {
            maximum: *maximum_path_id,
        }),
        SentFrameInfo::PathCidsBlocked {
            path_id,
            next_sequence_number,
        } => Some(qlog::QlogFrame::PathCidsBlocked {
            path_id: *path_id,
            sequence_number: *next_sequence_number,
        }),
        SentFrameInfo::PathStatus {
            path_id, status, ..
        } => Some(qlog::QlogFrame::PathStatus {
            path_id: *path_id,
            status: match status {
                PathStatus::Available => "available",
                PathStatus::Backup => "backup",
            },
        }),
        SentFrameInfo::PathAbandon {
            path_id,
            error_code,
        } => Some(qlog::QlogFrame::PathAbandon {
            path_id: *path_id,
            error_code: *error_code,
        }),
        SentFrameInfo::Ack {
            acked_ranges,
            ack_delay,
        } => Some(qlog::QlogFrame::Ack {
            acked_ranges: acked_ranges.clone(),
            ack_delay: qlog::ack_delay_ms(*ack_delay, ack_delay_exponent),
        }),
        // draft-ietf-quic-qlog-quic-events-13 Section 8.13:
        // RESET_STREAM / RESET_STREAM_AT / STOP_SENDING も packet_sent に記録する。
        SentFrameInfo::ResetStream {
            stream_id,
            error_code,
            final_size,
        } => Some(qlog::QlogFrame::ResetStream {
            stream_id: *stream_id,
            error_code: *error_code,
            final_size: *final_size,
        }),
        SentFrameInfo::ResetStreamAt {
            stream_id,
            error_code,
            final_size,
            reliable_size,
        } => Some(qlog::QlogFrame::ResetStreamAt {
            stream_id: *stream_id,
            error_code: *error_code,
            final_size: *final_size,
            reliable_size: *reliable_size,
        }),
        SentFrameInfo::StopSending {
            stream_id,
            error_code,
        } => Some(qlog::QlogFrame::StopSending {
            stream_id: *stream_id,
            error_code: *error_code,
        }),
        _ => None,
    }
}

/// ピアのトランスポートパラメータから受信 ACK の ACK Delay 指数を求める
///
/// `Connection::peer_ack_delay_exponent` の実体。受信 ACK の処理
/// (`process_ack`) は `self.paths` を可変借用したまま指数を必要とするため、
/// メソッドを呼ぶと `&self` の借用と衝突する。借用の衝突を避けられるよう
/// パラメータだけを受け取る形にしている。
///
/// RFC 9000 Section 18.2 の上限 20 で制限し、未取得時は既定値 3 を使う。
fn peer_ack_delay_exponent(peer_params: Option<&TransportParams>) -> u32 {
    peer_params.map_or(3, |params| params.ack_delay_exponent.min(20) as u32)
}

/// ACK から送信フレーム情報を作る
///
/// Initial / Handshake 空間の packet_sent は `SentFrameInfo::Ack` から
/// イベントを作るため、qlog 有効時は確認応答範囲と ACK Delay を保持する。
/// qlog 無効時はこの情報を読む経路が無いため、レンジの展開と Vec の確保を
/// 行わず空にしておく。
///
/// ACK Delay は ACK 生成時のエンコード値のまま保持し、qlog 出力時に送信側の
/// ack_delay_exponent で ms へ変換する (RFC 9000 Section 19.3)。
fn sent_ack_info(ack: &frame::ack::Ack, qlog_enabled: bool) -> SentFrameInfo {
    if !qlog_enabled {
        return SentFrameInfo::Ack {
            acked_ranges: Vec::new(),
            ack_delay: 0,
        };
    }
    SentFrameInfo::Ack {
        acked_ranges: ack.expand_ack_ranges(),
        ack_delay: ack.ack_delay.as_u64(),
    }
}

/// 復号済みペイロードからフレームをデコードして QlogFrame に変換する
///
/// `ack_delay_exponent` は受信した ACK / PATH_ACK の ACK Delay を ms に
/// 変換するためのピアの指数である (RFC 9000 Section 19.3)。
fn decode_frames_for_qlog(payload: &[u8], ack_delay_exponent: u32) -> Vec<qlog::QlogFrame> {
    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        match Frame::decode(&payload[offset..]) {
            Ok((frame, consumed)) => {
                frames.push(qlog::QlogFrame::from_frame(&frame, ack_delay_exponent));
                offset += consumed;
            }
            Err(_) => break,
        }
    }
    frames
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_observed_local;

#[cfg(test)]
mod tests_path_validation;

#[cfg(test)]
mod tests_resumption;
