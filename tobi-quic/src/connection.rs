// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tobi_core::connection::{
    ConnectionEvent as CoreConnectionEvent, ConnectionObservationEvent as CoreObservationEvent,
    ConnectionState,
};
use tobi_core::connection_id::ConnectionId;
use tobi_core::path::PathStatus;
use tobi_core::transport_params::{PreferredAddress, TransportParams};
use tokio::sync::{Notify, mpsc, oneshot, watch};

use tobi_platform::QuicConnection;
use tobi_platform::QuicServerConnection;

use crate::error::{ConnectionError, Error};
use crate::path::{NetworkEvent, NewPath, PathEvent, PathHandle, PathSnapshot};
use crate::stream::{BidirectionalStream, ReceiveStream, SendStream};
use tobi_core::stats::ConnectionStats;

/// driver task が `stream_recv()` の返り値を統一的に送り返すための型。
///
/// 受信データ本体を `Vec<u8>` で返し、呼び出し側の `ReceiveStream` が
/// 必要な長さだけ利用者バッファへコピーする。
type StreamRecvResult = Result<(Vec<u8>, usize, bool), Error>;

/// 接続の実体。
///
/// 公開 API は client / server を区別しない `Connection` だが、
/// driver task の内部では低水準実装の差分をここで吸収する。
enum ConnectionInner {
    Client(QuicConnection),
    Server(QuicServerConnection),
}

impl ConnectionInner {
    fn state(&self) -> ConnectionState {
        match self {
            ConnectionInner::Client(conn) => conn.state(),
            ConnectionInner::Server(conn) => conn.state(),
        }
    }

    fn version(&self) -> u32 {
        match self {
            ConnectionInner::Client(conn) => conn.version(),
            ConnectionInner::Server(conn) => conn.version(),
        }
    }

    fn version_negotiation_versions(&self) -> Option<Vec<u32>> {
        match self {
            ConnectionInner::Client(conn) => {
                conn.version_negotiation_versions().map(<[u32]>::to_vec)
            }
            // サーバーは Version Negotiation を送るだけで受信しないため常に None
            ConnectionInner::Server(_) => None,
        }
    }

    fn max_datagram_size(&self) -> Option<usize> {
        match self {
            ConnectionInner::Client(conn) => conn.max_datagram_size(),
            ConnectionInner::Server(conn) => conn.max_datagram_size(),
        }
    }

    fn paths(&self) -> Vec<PathSnapshot> {
        match self {
            ConnectionInner::Client(conn) => conn
                .path_metrics()
                .iter()
                .map(PathSnapshot::from_metrics)
                .collect(),
            ConnectionInner::Server(conn) => conn
                .path_metrics()
                .iter()
                .map(PathSnapshot::from_metrics)
                .collect(),
        }
    }

    fn pending_path_event_count(&self) -> usize {
        match self {
            Self::Client(conn) => conn.pending_path_event_count(),
            Self::Server(conn) => conn.pending_path_event_count(),
        }
    }

    fn local_addr(&self) -> Result<SocketAddr, Error> {
        match self {
            ConnectionInner::Client(conn) => conn.local_addr(),
            ConnectionInner::Server(conn) => conn.local_addr(),
        }
    }

    fn remote_addr(&self) -> SocketAddr {
        match self {
            ConnectionInner::Client(conn) => conn.remote_addr(),
            ConnectionInner::Server(conn) => conn.remote_addr(),
        }
    }

    fn alpn_protocol(&self) -> Option<Vec<u8>> {
        match self {
            ConnectionInner::Client(conn) => conn.alpn_protocol().map(|p| p.to_vec()),
            ConnectionInner::Server(conn) => conn.alpn_protocol().map(|p| p.to_vec()),
        }
    }

    fn peer_supports_reset_stream_at(&self) -> bool {
        match self {
            ConnectionInner::Client(conn) => conn.peer_supports_reset_stream_at(),
            ConnectionInner::Server(conn) => conn.peer_supports_reset_stream_at(),
        }
    }

    fn zero_rtt_accepted(&self) -> bool {
        match self {
            ConnectionInner::Client(conn) => conn.zero_rtt_accepted(),
            ConnectionInner::Server(conn) => conn.zero_rtt_accepted(),
        }
    }

    fn peer_transport_params(&self) -> Option<TransportParams> {
        match self {
            ConnectionInner::Client(conn) => conn.peer_transport_params().cloned(),
            ConnectionInner::Server(conn) => conn.peer_transport_params().cloned(),
        }
    }

    fn peer_preferred_address(&self) -> Option<PreferredAddress> {
        match self {
            ConnectionInner::Client(conn) => conn.peer_preferred_address().cloned(),
            ConnectionInner::Server(conn) => conn.peer_preferred_address().cloned(),
        }
    }

    fn path_peer_cid(&self) -> Option<ConnectionId> {
        match self {
            ConnectionInner::Client(conn) => conn.path_peer_cid(),
            ConnectionInner::Server(conn) => conn.path_peer_cid(),
        }
    }

    fn initial_token_validated(&self) -> bool {
        match self {
            ConnectionInner::Client(conn) => conn.initial_token_validated(),
            ConnectionInner::Server(conn) => conn.initial_token_validated(),
        }
    }

    /// 観測イベントの記録を有効化・無効化する
    fn set_observation_enabled(&mut self, enabled: bool) {
        match self {
            ConnectionInner::Client(conn) => conn.set_observation_enabled(enabled),
            ConnectionInner::Server(conn) => conn.set_observation_enabled(enabled),
        }
    }

    /// 観測イベントを 1 件取り出す
    fn poll_observation_event(&mut self) -> Option<CoreObservationEvent> {
        match self {
            ConnectionInner::Client(conn) => conn.poll_observation_event(),
            ConnectionInner::Server(conn) => conn.poll_observation_event(),
        }
    }

    /// サーバーが広告した preferred_address へ移行を開始する
    ///
    /// preferred_address を広告するのはサーバーであり、移行するのはクライアント
    /// だけであるため、サーバー側の接続ではエラーを返す。
    async fn migrate_to_preferred_address(&mut self) -> Result<(), Error> {
        match self {
            ConnectionInner::Client(conn) => conn.migrate_to_preferred_address().await,
            ConnectionInner::Server(_) => Err(Error::Protocol(
                "migrate_to_preferred_address is only available for client connections".into(),
            )),
        }
    }

    fn accept_application_event_now(&mut self) -> Result<ApplicationEvent, Error> {
        let event = match self {
            ConnectionInner::Client(conn) => conn.accept_application_event_now()?,
            ConnectionInner::Server(conn) => conn.accept_application_event_now()?,
        };
        ApplicationEvent::from_core(event).ok_or_else(|| {
            Error::Internal("application event variant mismatch after take_event filter".into())
        })
    }

    async fn set_keep_alive(&mut self, enabled: bool) -> Result<(), Error> {
        match self {
            ConnectionInner::Client(conn) => conn.set_keep_alive(enabled).await,
            ConnectionInner::Server(conn) => conn.set_keep_alive(enabled).await,
        }
    }

    async fn set_path_keep_alive(&mut self, path: PathHandle, enabled: bool) -> Result<(), Error> {
        match self {
            ConnectionInner::Client(conn) => conn.set_path_keep_alive(path.raw(), enabled).await,
            ConnectionInner::Server(conn) => conn.set_path_keep_alive(path.raw(), enabled).await,
        }
    }

    /// 双方向ストリームを開く
    ///
    /// client / server で同じ公開 API を呼ぶ差分をここで吸収する。
    fn open_stream_bidi(&mut self) -> Result<u64, Error> {
        match self {
            ConnectionInner::Client(conn) => conn.open_stream_bidi(),
            ConnectionInner::Server(conn) => conn.open_stream_bidi(),
        }
    }

    /// 単方向ストリームを開く
    fn open_stream_uni(&mut self) -> Result<u64, Error> {
        match self {
            ConnectionInner::Client(conn) => conn.open_stream_uni(),
            ConnectionInner::Server(conn) => conn.open_stream_uni(),
        }
    }

    /// ピアが許可したストリームの残枠 (双方向, 単方向) を返す
    fn remaining_streams(&self) -> (u64, u64) {
        match self {
            ConnectionInner::Client(conn) => {
                (conn.remaining_bidi_streams(), conn.remaining_uni_streams())
            }
            ConnectionInner::Server(conn) => {
                (conn.remaining_bidi_streams(), conn.remaining_uni_streams())
            }
        }
    }

    /// ピアが起動できる双方向ストリームの累積上限を引き上げる
    ///
    /// 公開 API の表記に合わせ、platform 層の `set_max_streams_bidi` を呼ぶ。
    async fn set_max_streams_bidirectional(&mut self, maximum_streams: u64) -> Result<(), Error> {
        match self {
            ConnectionInner::Client(conn) => conn.set_max_streams_bidi(maximum_streams).await,
            ConnectionInner::Server(conn) => conn.set_max_streams_bidi(maximum_streams).await,
        }
    }

    /// ピアが起動できる単方向ストリームの累積上限を引き上げる
    ///
    /// 公開 API の表記に合わせ、platform 層の `set_max_streams_uni` を呼ぶ。
    async fn set_max_streams_unidirectional(&mut self, maximum_streams: u64) -> Result<(), Error> {
        match self {
            ConnectionInner::Client(conn) => conn.set_max_streams_uni(maximum_streams).await,
            ConnectionInner::Server(conn) => conn.set_max_streams_uni(maximum_streams).await,
        }
    }

    /// 未送信フレームの生成と、生成済み出力の送信を行う
    ///
    /// transport が保持する保留フレーム (ACK / MAX_DATA / PATH_STATUS 等) を
    /// パケット化してから出力キューを送信する。driver はコマンド処理後に
    /// 必ずこれを呼び、コマンドが生成した出力を取りこぼさない。
    async fn flush_pending(&mut self) -> Result<(), Error> {
        match self {
            ConnectionInner::Client(conn) => conn.flush_pending().await,
            ConnectionInner::Server(conn) => conn.flush_pending().await,
        }
    }

    /// Pacing タイマーが残っているかを返す
    fn has_pending_pacing_timer(&self) -> bool {
        match self {
            ConnectionInner::Client(conn) => conn.has_pending_pacing_timer(),
            ConnectionInner::Server(conn) => conn.has_pending_pacing_timer(),
        }
    }

    async fn wait_and_process_only(&mut self) -> Result<(), Error> {
        match self {
            ConnectionInner::Client(conn) => conn.wait_and_process().await,
            ConnectionInner::Server(conn) => conn.wait_and_process().await,
        }
    }

    /// ピアまたはローカルの close で確定した終了理由を返す
    fn close_reason(&self) -> Option<ConnectionError> {
        match self {
            ConnectionInner::Client(conn) => conn.close_reason(),
            ConnectionInner::Server(conn) => conn.close_reason(),
        }
    }

    /// 接続が終了していれば、その理由を表す型付きエラーを返す
    ///
    /// 終了状態でなければ `None` を返す。終了理由が共有されていればそれを
    /// 使い、理由が残っていない場合は正常クローズとして扱う。DATAGRAM を
    /// 送信キューへ積む直前の確認に使う。
    fn closed_error_if_any(&self) -> Option<Error> {
        if !is_closed_state(self.state()) {
            return None;
        }
        Some(Error::Connection(
            self.close_reason().unwrap_or(ConnectionError::Closed),
        ))
    }

    /// 接続が `Closed` なら、その理由を表す型付きエラーを返す
    ///
    /// `Closing` / `Draining` は close の送出とドレインの進行にパケットと
    /// タイマーを使うため対象にしない。待機を解除するタイマーがなく、
    /// パケット到着による進捗も保証されない `Closed` だけを待機の終了条件と
    /// みなす用途で使う。
    fn closed_error_if_terminal(&self) -> Option<Error> {
        if self.state() != ConnectionState::Closed {
            return None;
        }
        self.closed_error_if_any()
    }

    /// データグラムの送信内容を検証する (RFC 9221 / RFC 9000 Section 14.2)
    ///
    /// 送信キューへ追加する前の検査だけを行い、キューは変更しない。
    fn validate_datagram(&self, data: &[u8]) -> Result<(), Error> {
        match self {
            ConnectionInner::Client(conn) => conn.validate_datagram(data),
            ConnectionInner::Server(conn) => conn.validate_datagram(data),
        }
    }

    /// DATAGRAM の送信キューに空きがあるかを返す
    fn datagram_send_queue_has_space(&self) -> bool {
        match self {
            ConnectionInner::Client(conn) => conn.datagram_send_queue_has_space(),
            ConnectionInner::Server(conn) => conn.datagram_send_queue_has_space(),
        }
    }

    /// データグラムを送信キューへ積む (flush はしない)
    ///
    /// 送信キューの空きは呼び出し側が確認する。満杯のまま呼ぶと最も古い
    /// データグラムが破棄されるため、待機方針の経路では呼ばない。
    fn send_datagram_now(&mut self, data: Vec<u8>) -> Result<(), Error> {
        match self {
            ConnectionInner::Client(conn) => conn.send_datagram_now(data),
            ConnectionInner::Server(conn) => conn.send_datagram_now(data),
        }
    }
}

/// `Connection` が driver task へ送るコマンド。
///
/// 高水準 API のすべての操作を command queue へ正規化することで、
/// 利用者は `Connection` / `SendStream` / `ReceiveStream` を
/// 複数のタスクから並行利用できる。
/// 待機するコマンドの `on_block` は、試行時に driver が登録する進捗通知。
/// would-block の返信と別に Drive を送る隙間を作らず、受信通知を保持する。
///
/// 受理と DATAGRAM・イベント受信の `reply` は進捗 (成功したか) だけを返す。
/// driver が transport から取り出した結果は [`SharedResults`] に積まれ、
/// 呼び出し側が後から回収する。返信の受信者が future のキャンセルで消えて
/// いても、取り出した結果を失わないためである。
pub(crate) enum Command {
    Drive {
        reply: oneshot::Sender<Result<(), Error>>,
    },
    /// graceful shutdown: 接続を閉じて driver task を終了する
    ///
    /// router から `ConnectionShutdown` が届いたときに送られる。
    /// `close()` と違い、閉じた後に driver task 自体を終了させる。
    Shutdown,
    /// バックグラウンド受信を有効化する (opt-in)
    ///
    /// 既定の driver はコマンド駆動であり、コマンドが無い間はソケット受信と
    /// タイマー発火を処理しない。このコマンドを受信した後は、アプリケーション
    /// が API を呼んでいない間も受信とタイマーを処理する。
    EnableBackgroundDriver {
        reply: oneshot::Sender<Result<(), Error>>,
    },
    State {
        reply: oneshot::Sender<ConnectionState>,
    },
    /// 接続で使用している QUIC バージョンを返す
    Version {
        reply: oneshot::Sender<u32>,
    },
    /// 受信した Version Negotiation が提示したバージョン一覧を返す
    VersionNegotiationVersions {
        reply: oneshot::Sender<Option<Vec<u32>>>,
    },
    MaxDatagramSize {
        reply: oneshot::Sender<Option<usize>>,
    },
    Paths {
        reply: oneshot::Sender<Vec<PathSnapshot>>,
    },
    /// パスイベントを共有キューへ引き渡す
    ///
    /// `reply` は進捗通知のみを返す。結果は [`SharedResults`] のパスイベント
    /// キューに積む。
    AcceptPathEvent {
        reply: oneshot::Sender<Result<(), Error>>,
        on_block: oneshot::Sender<Result<(), Error>>,
    },
    /// 観測イベントの購読を登録する
    ///
    /// 接続ごとに 1 購読まで。既に購読中の場合や capacity が 0 の場合は
    /// エラーを返す。
    SubscribeEvents {
        capacity: usize,
        reply: oneshot::Sender<Result<mpsc::Receiver<ConnectionEvent>, Error>>,
    },
    NotifyNetworkEvent {
        event: NetworkEvent,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    IsHandshaking {
        reply: oneshot::Sender<bool>,
    },
    CloseReason {
        reply: oneshot::Sender<Option<ConnectionError>>,
    },
    /// 接続全体の累積統計を取得する
    Stats {
        reply: oneshot::Sender<ConnectionStats>,
    },
    /// ピアが許可したストリームの残枠 (双方向, 単方向) を取得する
    RemainingStreams {
        reply: oneshot::Sender<(u64, u64)>,
    },
    // 接続情報
    LocalAddr {
        reply: oneshot::Sender<Result<SocketAddr, Error>>,
    },
    RemoteAddr {
        reply: oneshot::Sender<SocketAddr>,
    },
    AlpnProtocol {
        reply: oneshot::Sender<Option<Vec<u8>>>,
    },
    // ピアの reset_stream_at transport parameter サポート判定
    PeerSupportsResetStreamAt {
        reply: oneshot::Sender<bool>,
    },
    // 0-RTT 状態と transport parameter
    ZeroRttAccepted {
        reply: oneshot::Sender<bool>,
    },
    PeerTransportParams {
        reply: oneshot::Sender<Option<TransportParams>>,
    },
    // preferred_address (RFC 9000 Section 9.6 / Section 18.2)
    PeerPreferredAddress {
        reply: oneshot::Sender<Option<PreferredAddress>>,
    },
    MigrateToPreferredAddress {
        reply: oneshot::Sender<Result<(), Error>>,
    },
    PathPeerCid {
        reply: oneshot::Sender<Option<ConnectionId>>,
    },
    InitialTokenValidated {
        reply: oneshot::Sender<bool>,
    },
    // アプリケーションイベント (SessionTicketReceived / ZeroRttRejected / NewToken)
    /// アプリケーションイベントを共有キューへ引き渡す
    ///
    /// `reply` は進捗通知のみを返す。結果は [`SharedResults`] のアプリケーション
    /// イベントキューに積む。
    AcceptApplicationEvent {
        reply: oneshot::Sender<Result<(), Error>>,
        on_block: oneshot::Sender<Result<(), Error>>,
    },
    // Keep-Alive
    SetKeepAlive {
        enabled: bool,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    SetPathKeepAlive {
        path: PathHandle,
        enabled: bool,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    /// 双方向ストリームを開く
    ///
    /// `on_block` がある場合は、上限到達時に進捗通知として登録し、呼び出し側が
    /// 通知後に同じコマンドを再試行する。試行と登録を同じコマンド内で行うため、
    /// その間に MAX_STREAMS を含む受信が進んでも通知を失わない。待機しない
    /// 呼び出しは `None` を渡す。
    OpenBidirectionalStream {
        reply: oneshot::Sender<Result<u64, Error>>,
        on_block: Option<oneshot::Sender<Result<(), Error>>>,
    },
    /// 単方向ストリームを開く
    ///
    /// [`Command::OpenBidirectionalStream`] の単方向版。
    OpenSendStream {
        reply: oneshot::Sender<Result<u64, Error>>,
        on_block: Option<oneshot::Sender<Result<(), Error>>>,
    },
    /// ピアが起動できるストリームの累積上限を引き上げ、MAX_STREAMS を送る
    ///
    /// `bidirectional` により双方向と単方向を切り替える。上限到達の待機と
    /// 異なり、送信結果をそのまま返す。
    SetMaxStreams {
        bidirectional: bool,
        maximum_streams: u64,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    /// 双方向ストリームを共有キューへ引き渡す
    ///
    /// `reply` は進捗通知のみを返す。結果は [`SharedResults`] の受理キューに積む。
    AcceptBidirectionalStream {
        reply: oneshot::Sender<Result<(), Error>>,
        on_block: oneshot::Sender<Result<(), Error>>,
    },
    /// 単方向受信ストリームを共有キューへ引き渡す
    ///
    /// `reply` は進捗通知のみを返す。結果は [`SharedResults`] の受理キューに積む。
    AcceptReceiveStream {
        reply: oneshot::Sender<Result<(), Error>>,
        on_block: oneshot::Sender<Result<(), Error>>,
    },
    // 種別不問のストリーム受け入れ
    /// 種別不問のストリームを共有キューへ引き渡す
    ///
    /// `reply` は進捗通知のみを返す。結果は [`SharedResults`] の受理キューに積む。
    AcceptStream {
        reply: oneshot::Sender<Result<(), Error>>,
        on_block: oneshot::Sender<Result<(), Error>>,
    },
    /// 受信した STOP_SENDING を共有キューへ引き渡す
    ///
    /// `reply` は進捗通知のみを返す。結果は [`SharedResults`] の STOP_SENDING
    /// キューに積む。
    AcceptStopSending {
        reply: oneshot::Sender<Result<(), Error>>,
        on_block: oneshot::Sender<Result<(), Error>>,
    },
    StreamSend {
        stream_id: u64,
        data: Arc<[u8]>,
        fin: bool,
        reply: oneshot::Sender<Result<usize, Error>>,
        on_block: oneshot::Sender<Result<(), Error>>,
        /// driver が受理済みバイト数を記録する先
        ///
        /// 呼び出し側の future がキャンセルされても受理量を回収できるよう、
        /// 返信とは独立した共有カウンタへ記録する。
        accepted: Option<Arc<AtomicUsize>>,
    },
    StreamRecv {
        stream_id: u64,
        len: usize,
        reply: oneshot::Sender<StreamRecvResult>,
        on_block: oneshot::Sender<Result<(), Error>>,
    },
    ResetStream {
        stream_id: u64,
        error_code: u64,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    // RESET_STREAM_AT 送信
    ResetStreamAt {
        stream_id: u64,
        error_code: u64,
        reliable_size: u64,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    StopSending {
        stream_id: u64,
        error_code: u64,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    SendDatagram {
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    /// 送信キューの空きを待って DATAGRAM を送る (RFC 9221)
    ///
    /// 送信キューに空きがあれば積んで成功を返す。空きが無い場合は
    /// [`DatagramSendWaitReply::Blocked`] を返し、`on_block` を進捗通知として
    /// 登録する。呼び出し側は `Blocked` を受け取ったら、`on_block` の進捗通知を
    /// 待って同じ payload で再試行する。
    SendDatagramWait {
        data: Arc<[u8]>,
        reply: oneshot::Sender<DatagramSendWaitReply>,
        on_block: oneshot::Sender<Result<(), Error>>,
    },
    /// 受信済み DATAGRAM を共有キューへ引き渡す
    ///
    /// `reply` は進捗通知のみを返す。結果は [`SharedResults`] の DATAGRAM
    /// キューに積む。
    ReceiveDatagram {
        reply: oneshot::Sender<Result<(), Error>>,
        on_block: oneshot::Sender<Result<(), Error>>,
    },
    OpenPath {
        request: NewPath,
        reply: oneshot::Sender<Result<PathHandle, Error>>,
    },
    /// 初期パス (Path ID 0) を新しい 4-tuple へ移行する
    Migrate {
        request: NewPath,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    AbandonPath {
        path: PathHandle,
        error_code: u64,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    /// 指定パスで使用するピア Connection ID を未使用のものへ切り替える
    RotatePathCid {
        path: PathHandle,
        reply: oneshot::Sender<Result<bool, Error>>,
    },
    SetPathStatus {
        path: PathHandle,
        status: PathStatus,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    SetMaxPathId {
        max_path_id: u32,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    Ping {
        reply: oneshot::Sender<Result<(), Error>>,
    },
    /// 1-RTT 鍵更新を開始する (RFC 9001 Section 6.1)
    UpdateKeys {
        reply: oneshot::Sender<Result<(), Error>>,
    },
    PingPath {
        path: PathHandle,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    SendAckFrequency {
        path: PathHandle,
        ack_eliciting_threshold: u64,
        requested_max_ack_delay: std::time::Duration,
        reordering_threshold: u64,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    SendImmediateAck {
        path: PathHandle,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    Close {
        /// true なら application-level の CONNECTION_CLOSE (type 0x1d)、
        /// false なら transport-level の CONNECTION_CLOSE (type 0x1c) を送る
        application: bool,
        error_code: u64,
        reason: Vec<u8>,
        reply: oneshot::Sender<Result<(), Error>>,
    },
}

/// `SendDatagramWait` コマンドの結果
///
/// driver の内部状態をそのまま公開 API のエラーへ漏らさないため、待機に入った
/// ことと失敗したことを型で区別する。呼び出し側は `Blocked` を受け取ったら
/// 進捗通知を待って同じ payload で再試行する。
#[derive(Debug)]
pub(crate) enum DatagramSendWaitReply {
    /// 送信キューへ積んだ (受理点に到達した)
    Accepted,
    /// 送信キューに空きが無く、進捗通知を登録した
    Blocked,
    /// 待機では解決しないエラーで失敗した
    Failed(Error),
}

/// driver へのコマンド送信と、接続終了理由を共有するハンドル
///
/// `mpsc::Sender` だけを持つと、接続が終了した理由を送信失敗時に参照できない。
/// driver が取り出した結果を保持する [`SharedResults`] と一緒に持つことで、
/// 停止後のコマンドを `Error::Internal` ではなく接続終了の型付きエラーとして
/// 返せる。crate 内のハンドルであり、公開 API には現れない。
#[derive(Clone)]
pub(crate) struct SharedConnection {
    /// driver へのコマンド送信
    tx: mpsc::Sender<Command>,
    /// driver と共有する結果キュー・接続終了理由
    results: Arc<SharedResults>,
}

impl SharedConnection {
    /// コマンド sender と共有結果からハンドルを作る
    pub(crate) fn new(tx: mpsc::Sender<Command>, results: Arc<SharedResults>) -> Self {
        Self { tx, results }
    }

    /// コマンドを driver へ送る
    pub(crate) async fn send(
        &self,
        command: Command,
    ) -> Result<(), mpsc::error::SendError<Command>> {
        self.tx.send(command).await
    }

    /// 共有する結果キューの参照を返す
    fn results(&self) -> &SharedResults {
        &self.results
    }

    /// コマンド送信に失敗したときのエラーを返す
    ///
    /// driver が接続終了理由を残して停止している場合は、接続終了の型付き
    /// エラーを返す。driver task の中断などで理由が残っていない場合だけ、
    /// 従来どおり内部エラーにする。
    pub(crate) fn send_failure_error(&self) -> Error {
        self.results
            .closed_reason()
            .map(Error::Connection)
            .unwrap_or_else(|| Error::Internal("connection driver stopped".into()))
    }

    /// driver からの返信が消失したときのエラーを返す
    ///
    /// driver がコマンドを受け取った後に停止した場合も、接続終了理由が
    /// 残っていれば接続終了として返す。
    pub(crate) fn reply_dropped_error(&self) -> Error {
        self.results
            .closed_reason()
            .map(Error::Connection)
            .unwrap_or_else(|| Error::Internal("connection driver reply dropped".into()))
    }

    /// driver task への弱参照を作る
    ///
    /// 監視タスクが強い sender を保持すると、アプリケーションがハンドルを
    /// drop してもチャネルが閉じず driver がリークするため、停止指示の送信には
    /// 弱参照を使う。
    fn downgrade(&self) -> WeakSharedConnection {
        WeakSharedConnection {
            tx: self.tx.downgrade(),
            results: Arc::clone(&self.results),
        }
    }
}

/// [`SharedConnection`] の弱参照
///
/// driver が停止している場合は [`Self::upgrade`] が `None` を返すため、
/// 停止済みの driver へ停止指示を送ろうとしても何も起きない。
struct WeakSharedConnection {
    /// driver へのコマンド送信の弱参照
    tx: mpsc::WeakSender<Command>,
    /// 強い参照へ戻すときに引き継ぐ共有結果
    results: Arc<SharedResults>,
}

impl WeakSharedConnection {
    /// 強い参照に戻す
    ///
    /// driver task が既に終了している場合は `None` を返す。
    fn upgrade(&self) -> Option<SharedConnection> {
        // `upgrade` は弱参照を借用して強参照を作るため、clone は不要である。
        let tx = self.tx.upgrade()?;
        Some(SharedConnection {
            tx,
            results: Arc::clone(&self.results),
        })
    }
}

/// driver が transport から取り出した結果を、呼び出し側が回収するまで保持する
///
/// 受理系・DATAGRAM・path event・application event・STOP_SENDING のコマンドは、
/// driver が結果を取り出した時点でここへ積み、呼び出し側へは進捗だけを返信する。
/// 返信を待つ future がキャンセルされても結果はここに残るため、次の呼び出しで
/// 回収できる。
///
/// 共有キューは 1 つの `Mutex` で保護する。キューごとにロックを分けると
/// ロック順序と poison の扱いが増えるが、driver とハンドルが同時に触るのは
/// 短い出し入れだけで、キュー間の contention は観測されていない。1 つの
/// ロックにまとめることで、ロック保持中に await しないことと、ロック順序が
/// 単一であることを構造として保証する。チャネル方式は「種別の合う最初の
/// 要素だけを取り出す」操作のために取り出し済みの要素を別に保持する状態が
/// 増えるため採らない。
#[derive(Debug, Default)]
pub(crate) struct SharedResults {
    /// 共有キューの中身
    inner: Mutex<SharedResultsInner>,
}

/// [`SharedResults`] のロックで保護するキュー群
#[derive(Debug, Default)]
struct SharedResultsInner {
    /// 受理済みストリーム (stream ID, 双方向か)
    accepts: VecDeque<(u64, bool)>,
    /// 受信済み DATAGRAM
    datagrams: VecDeque<Vec<u8>>,
    /// 回収待ちのパスイベント
    path_events: VecDeque<PathEvent>,
    /// 回収待ちのアプリケーションイベント
    application_events: VecDeque<ApplicationEvent>,
    /// 回収待ちの STOP_SENDING (stream ID, エラーコード)
    stop_sending: VecDeque<(u64, u64)>,
    /// 接続が終了した理由 (最初に観測した理由を保持する)
    ///
    /// 接続終了後に発行されたコマンドは、この理由を接続終了の型付き
    /// エラーとして返す。理由が無いまま driver が停止した場合 (タスク中断など)
    /// だけ、呼び出し側は内部エラーを受け取る。
    closed_reason: Option<ConnectionError>,
}

impl SharedResults {
    /// 共有キューを 1 回だけロックして操作する
    ///
    /// ロックはこの関数の呼び出し内で解放する。ロック保持中に await しない。
    fn with_inner<R>(&self, f: impl FnOnce(&mut SharedResultsInner) -> R) -> R {
        let mut inner = self
            .inner
            .lock()
            .expect("shared results mutex is not poisoned");
        f(&mut inner)
    }

    /// 受理済みストリームを 1 本積む
    fn push_accept(&self, stream_id: u64, is_bidirectional: bool) {
        self.with_inner(|inner| inner.accepts.push_back((stream_id, is_bidirectional)));
    }

    /// 受理済みストリームがあるか
    fn has_accept(&self) -> bool {
        self.with_inner(|inner| !inner.accepts.is_empty())
    }

    /// 双方向ストリームが受理済みか
    fn has_bidirectional_stream(&self) -> bool {
        self.with_inner(|inner| {
            inner
                .accepts
                .iter()
                .any(|(_, is_bidirectional)| *is_bidirectional)
        })
    }

    /// 単方向受信ストリームが受理済みか
    fn has_receive_stream(&self) -> bool {
        self.with_inner(|inner| {
            inner
                .accepts
                .iter()
                .any(|(_, is_bidirectional)| !*is_bidirectional)
        })
    }

    /// 種別を問わず、受理済みストリームの先頭を取り出す
    fn claim_stream(&self) -> Option<(u64, bool)> {
        self.with_inner(|inner| inner.accepts.pop_front())
    }

    /// 受理済みの双方向ストリームのうち、最初の 1 本を取り出す
    fn claim_bidirectional_stream(&self) -> Option<u64> {
        self.with_inner(|inner| {
            let index = inner
                .accepts
                .iter()
                .position(|(_, is_bidirectional)| *is_bidirectional)?;
            inner.accepts.remove(index).map(|(stream_id, _)| stream_id)
        })
    }

    /// 受理済みの単方向受信ストリームのうち、最初の 1 本を取り出す
    ///
    /// peer が開始した単方向ストリームだけがここへ積まれる。ローカル開始の
    /// ストリームは受理イベントにならないため、単方向かどうかだけで判別できる。
    fn claim_receive_stream(&self) -> Option<u64> {
        self.with_inner(|inner| {
            let index = inner
                .accepts
                .iter()
                .position(|(_, is_bidirectional)| !*is_bidirectional)?;
            inner.accepts.remove(index).map(|(stream_id, _)| stream_id)
        })
    }

    /// 受信済み DATAGRAM を 1 件積む
    fn push_datagram(&self, data: Vec<u8>) {
        self.with_inner(|inner| inner.datagrams.push_back(data));
    }

    /// 受信済み DATAGRAM があるか
    fn has_datagram(&self) -> bool {
        self.with_inner(|inner| !inner.datagrams.is_empty())
    }

    /// 受信済み DATAGRAM の先頭を取り出す
    fn claim_datagram(&self) -> Option<Vec<u8>> {
        self.with_inner(|inner| inner.datagrams.pop_front())
    }

    /// パスイベントを 1 件積む
    fn push_path_event(&self, event: PathEvent) {
        self.with_inner(|inner| inner.path_events.push_back(event));
    }

    /// 回収待ちのパスイベントがあるか
    fn has_path_event(&self) -> bool {
        self.with_inner(|inner| !inner.path_events.is_empty())
    }

    /// パスイベントの先頭を取り出す
    fn claim_path_event(&self) -> Option<PathEvent> {
        self.with_inner(|inner| inner.path_events.pop_front())
    }

    /// アプリケーションイベントを 1 件積む
    fn push_application_event(&self, event: ApplicationEvent) {
        self.with_inner(|inner| inner.application_events.push_back(event));
    }

    /// 回収待ちのアプリケーションイベントがあるか
    fn has_application_event(&self) -> bool {
        self.with_inner(|inner| !inner.application_events.is_empty())
    }

    /// アプリケーションイベントの先頭を取り出す
    fn claim_application_event(&self) -> Option<ApplicationEvent> {
        self.with_inner(|inner| inner.application_events.pop_front())
    }

    /// 受信した STOP_SENDING を 1 件積む
    fn push_stop_sending(&self, stream_id: u64, error_code: u64) {
        self.with_inner(|inner| inner.stop_sending.push_back((stream_id, error_code)));
    }

    /// 回収待ちの STOP_SENDING があるか
    fn has_stop_sending(&self) -> bool {
        self.with_inner(|inner| !inner.stop_sending.is_empty())
    }

    /// STOP_SENDING の先頭を取り出す
    fn claim_stop_sending(&self) -> Option<(u64, u64)> {
        self.with_inner(|inner| inner.stop_sending.pop_front())
    }

    /// 接続が終了した理由を記録する
    ///
    /// 最初に記録された理由を保持し、後から別の理由が届いても上書きしない。
    /// ピアまたはローカルの close で確定した理由を、接続終了後も
    /// コマンド送信側から参照できるようにする。
    fn set_closed_reason(&self, reason: ConnectionError) {
        self.with_inner(|inner| {
            if inner.closed_reason.is_none() {
                inner.closed_reason = Some(reason);
            }
        });
    }

    /// 記録済みの接続終了理由を返す
    fn closed_reason(&self) -> Option<ConnectionError> {
        self.with_inner(|inner| inner.closed_reason.clone())
    }
}

/// `StreamRecv` コマンドが「まだデータが無い」ことを表す内部エラー文字列
///
/// 公開するエラーではない。driver が再試行可能な空読みと実際のエラーを
/// 区別し、空読みの場合だけ進捗通知を登録するために使う。
pub(crate) const STREAM_RECV_WOULD_BLOCK: &str = "stream receive would block";

/// 接続終了時に [`Connection::closed`] へ通知する理由
#[derive(Debug, Clone)]
struct ClosedInfo {
    /// ピアまたはローカルの close で確定した理由
    ///
    /// 明示的な close を伴わずに driver task が停止した場合は `None`。
    reason: Option<ConnectionError>,
}

/// [`Client::wait_idle`](crate::Client::wait_idle) 用の接続追跡
///
/// 接続ハンドルを生成した時点でカウントを増やし、接続の終了または driver task
/// の停止時に減らす。待機側はカウンタと [`Notify`] だけで待つため、
/// ロックを持たない。
#[derive(Debug, Default)]
pub(crate) struct ConnectionTracker {
    /// 終了していない接続数
    active: AtomicUsize,
    /// 接続数が 0 になったことを待機者へ通知する
    notify: Notify,
}

impl ConnectionTracker {
    /// 接続を 1 本登録する
    pub(crate) fn register(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    /// 接続を 1 本登録解除し、0 本になったら待機者を起こす
    pub(crate) fn unregister(&self) {
        if self.active.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.notify.notify_waiters();
        }
    }

    /// 登録中の接続がすべて終了するまで待つ
    ///
    /// カウンタが 0 になった時点で完了する。待機中に新しく登録された接続も、
    /// カウンタが 0 に戻るまで待機対象に含まれる。
    pub(crate) async fn wait_idle(&self) {
        loop {
            if self.active.load(Ordering::Relaxed) == 0 {
                return;
            }
            // notify_waiters の取りこぼしを避けるため、future を作ってから
            // カウンタを再確認する。登録解除が先に起きていれば再確認で 0 を見る。
            let notified = self.notify.notified();
            if self.active.load(Ordering::Relaxed) == 0 {
                return;
            }
            notified.await;
        }
    }
}

/// 接続が閉じ始めているかを判定する
fn is_closed_state(state: ConnectionState) -> bool {
    matches!(
        state,
        ConnectionState::Closing | ConnectionState::Draining | ConnectionState::Closed
    )
}

/// 終了状態を観測したら [`Connection::closed`] と [`ConnectionTracker`] へ通知する
///
/// `published` は通知済みかどうか、`tracker_released` は接続追跡の解除済みかどうかを
/// 保持する。driver task は複数回この関数を呼ぶため、二重通知を防ぐ。
fn publish_closed_state(
    inner: &ConnectionInner,
    closed_tx: &watch::Sender<Option<ClosedInfo>>,
    tracker: Option<&Arc<ConnectionTracker>>,
    published: &mut bool,
    tracker_released: &mut bool,
) {
    if !*published && is_closed_state(inner.state()) {
        let reason = inner.close_reason();
        let _ = closed_tx.send(Some(ClosedInfo { reason }));
        *published = true;
    }
    if *published && !*tracker_released {
        if let Some(tracker) = tracker {
            tracker.unregister();
        }
        *tracker_released = true;
    }
}

/// 観測イベントを購読チャネルへ転送する
///
/// 購読者がいない場合は何もしない。チャネルが満杯の場合はイベントを破棄し、
/// 接続処理をブロックしない。購読者が receiver を drop した場合は購読を解除し、
/// 観測の記録を無効化する。
fn dispatch_observation_events(
    inner: &mut ConnectionInner,
    observer: &mut Option<mpsc::Sender<ConnectionEvent>>,
) {
    let Some(tx) = observer.as_mut() else {
        return;
    };
    while let Some(event) = inner.poll_observation_event() {
        match tx.try_send(ConnectionEvent::from_core(event)) {
            Ok(()) => {}
            // 購読が遅い場合はイベントを破棄する (接続処理をブロックしない)
            Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // 購読解除: 観測の記録を止めてオーバーヘッドをゼロに戻す
                inner.set_observation_enabled(false);
                *observer = None;
                break;
            }
        }
    }
}

/// 接続終了イベントを購読チャネルへ送る
///
/// 終了状態を観測した最初の 1 回だけ送る。チャネルが満杯の場合は破棄する。
fn dispatch_connection_closed(
    inner: &ConnectionInner,
    observer: &mut Option<mpsc::Sender<ConnectionEvent>>,
    closed_event_sent: &mut bool,
) {
    if *closed_event_sent || observer.is_none() || !is_closed_state(inner.state()) {
        return;
    }
    let reason = inner.close_reason();
    if let Some(tx) = observer.as_mut() {
        let _ = tx.try_send(ConnectionEvent::ConnectionClosed { reason });
    }
    *closed_event_sent = true;
}

/// 命令駆動モードで Pacing タイマーを処理する最大ステップ数
///
/// 送信データが多く quantum 間隔の待ちが連続しても、長時間 driver を
/// 占有しないための上限。
const MAX_PACING_DRAIN_STEPS: usize = 64;

/// Pacing タイマー処理の 1 ステップで許容する最大待ち時間
const PACING_DRAIN_STEP_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(50);

/// `Command::Drive` を 1 件処理する
///
/// 保留中の出力をフラッシュし、送信キューの空きができていれば DATAGRAM 送信の
/// 待機者を起こしてから、呼び出し元を進捗待ちに登録する。
///
/// 接続が `Closed` の場合は登録せずに接続終了のエラーを返す。`Closed` では
/// 待機を解除するタイマーがなく、パケット到着による進捗も保証されないため、
/// 登録すると `drive()` が永久に戻り得る。
/// `Closing` / `Draining` は close の送出とドレインの進行にパケットとタイマーを
/// 使うため、対象にしない。フラッシュが接続を終了させた場合に備え、保留中の
/// 待機者も接続終了のエラーで完了させる。
async fn handle_drive(
    inner: &mut ConnectionInner,
    drive_replies: &mut Vec<oneshot::Sender<Result<(), Error>>>,
    datagram_send_waiters: &mut Vec<oneshot::Sender<Result<(), Error>>>,
    results: &SharedResults,
    reply: oneshot::Sender<Result<(), Error>>,
) {
    let _ = inner.flush_pending().await;
    wake_datagram_send_waiters_after_flush(inner, datagram_send_waiters);
    if let Some(error) = inner.closed_error_if_terminal() {
        notify_connection_closed(inner, drive_replies, datagram_send_waiters, results);
        let _ = reply.send(Err(error));
        return;
    }
    drive_replies.push(reply);
}

/// 接続 driver のメインループ。
///
/// すべての state mutation はこのタスクで直列化する。
/// これにより stream handle 側は `Arc<Mutex<...>>` を持たずに済み、
/// backpressure を保ったまま tokio task 間で安全に共有できる。
///
/// Drive コマンドのヘッドオブラインブロッキングを防ぐため、
/// Drive リクエストを収集し、他のコマンドを先に処理してから
/// まとめてパケット受信待ちに入る。
async fn driver_loop(
    mut inner: ConnectionInner,
    mut rx: mpsc::Receiver<Command>,
    closed_tx: watch::Sender<Option<ClosedInfo>>,
    tracker: Option<Arc<ConnectionTracker>>,
    results: Arc<SharedResults>,
    background_driver: bool,
) {
    // Drive の返信と、待機コマンド (受理・受信・送信) の進捗通知を
    // 蓄積する。どちらも「接続が進んだら呼び出し元を再開させる」ための
    // oneshot であり、パケットまたはタイマーを処理した時点でまとめて完了させる。
    // DATAGRAM の送信待ちは、送信キューの空きができたときに送信待ちだけを
    // 起こせるよう別のリストで保持する。送信待ちも進捗契機で起こすが、それは
    // 再試行のきっかけを作るためである。待機側の future がキャンセルされた
    // 通知は登録しない (登録すると受信者がいない送信者がパケット進捗まで
    // 残り続ける)。
    let mut drive_replies: Vec<oneshot::Sender<Result<(), Error>>> = Vec::new();
    // DATAGRAM の送信キュー空き待ちの進捗通知を別に保持する。
    // 受信待ちなどの他の待機者はキューに空きができても再開できないため、
    // 空きを契機に起こす対象を送信待ちに限定する。
    let mut datagram_send_waiters: Vec<oneshot::Sender<Result<(), Error>>> = Vec::new();
    // バックグラウンド受信 (opt-in) が有効か。接続生成時に
    // `with_background_driver(true)` が指定されていれば最初から有効にする。
    // 既定は無効 (コマンド駆動)。
    let mut background = background_driver;
    // 接続終了の通知と接続追跡の解除を 1 度だけ行うためのフラグ
    let mut closed_published = false;
    let mut tracker_released = false;
    // 観測イベントの購読者 (接続ごとに 1 つまで)
    let mut observer: Option<mpsc::Sender<ConnectionEvent>> = None;
    // 接続終了イベントを送信済みか
    let mut closed_event_sent = false;

    loop {
        // 待機側がキャンセルされた通知を落とす。登録時にも確認するが、
        // 登録後にキャンセルされた分はここで回収する。
        drive_replies.retain(|reply| !reply.is_closed());
        datagram_send_waiters.retain(|reply| !reply.is_closed());
        // 前回の処理ステップで発生した観測イベントを購読者へ転送する。
        dispatch_observation_events(&mut inner, &mut observer);
        dispatch_connection_closed(&inner, &mut observer, &mut closed_event_sent);
        if background {
            // opt-in のバックグラウンド受信: アプリケーションが API を呼んで
            // いない間もソケット受信とタイマー発火を処理する。アイドル中は
            // socket reader の受信 future とタイマーの sleep でブロックするため、
            // ビジーループにはならない。
            tokio::select! {
                biased;
                command = rx.recv() => {
                    let Some(command) = command else {
                        break;
                    };
                    match command {
                        Command::Drive { reply } => {
                            handle_drive(
                                &mut inner,
                                &mut drive_replies,
                                &mut datagram_send_waiters,
                                &results,
                                reply,
                            )
                            .await;
                        }
                        Command::EnableBackgroundDriver { reply } => {
                            // 既に有効
                            let _ = reply.send(Ok(()));
                        }
                        Command::Shutdown => {
                            shutdown_and_notify(
                                &mut inner,
                                &mut drive_replies,
                                &mut datagram_send_waiters,
                                &results,
                            )
                            .await;
                            break;
                        }
                        other => {
                            // 出力の送信は process_command 末尾の共通 flush が行う
                            process_command(
                                &mut inner,
                                &mut observer,
                                &mut drive_replies,
                                &mut datagram_send_waiters,
                                &results,
                                other,
                            )
                            .await;
                            publish_closed_state(
                                &inner,
                                &closed_tx,
                                tracker.as_ref(),
                                &mut closed_published,
                                &mut tracker_released,
                            );
                        }
                    }
                }
                result = inner.wait_and_process_only() => {
                    match result {
                        Ok(()) => {
                            complete_waiters_on_progress(
                                &inner,
                                &mut drive_replies,
                                &mut datagram_send_waiters,
                                &results,
                            );
                            publish_closed_state(
                                &inner,
                                &closed_tx,
                                tracker.as_ref(),
                                &mut closed_published,
                                &mut tracker_released,
                            );
                        }
                        Err(e) => {
                            publish_closed_state(
                                &inner,
                                &closed_tx,
                                tracker.as_ref(),
                                &mut closed_published,
                                &mut tracker_released,
                            );
                            finish_waiters_with_error(
                                &inner,
                                &mut drive_replies,
                                &mut datagram_send_waiters,
                                &results,
                                e,
                            );
                            break;
                        }
                    }
                }
            }
            continue;
        }

        // Drive リクエストまたは DATAGRAM の空き待ちが保留中の場合は
        // コマンドキューを非ブロッキングでドレインし、Drive 以外のコマンド
        // (StreamRecv, Accept 等) を優先処理する。コマンドがなくなって初めて
        // パケット受信を待つ。空き待ちはパケット処理 (ACK や PMTU の更新) で
        // しか解消しないため、drive_replies と同じく接続を進め続ける必要がある。
        if !drive_replies.is_empty() || !datagram_send_waiters.is_empty() {
            match rx.try_recv() {
                Ok(Command::Drive { reply }) => {
                    // 追加の Drive: フラッシュのみ行い蓄積する
                    handle_drive(
                        &mut inner,
                        &mut drive_replies,
                        &mut datagram_send_waiters,
                        &results,
                        reply,
                    )
                    .await;
                    continue;
                }
                Ok(Command::Shutdown) => {
                    shutdown_and_notify(
                        &mut inner,
                        &mut drive_replies,
                        &mut datagram_send_waiters,
                        &results,
                    )
                    .await;
                    break;
                }
                Ok(Command::EnableBackgroundDriver { reply }) => {
                    // バックグラウンド受信を有効化し、次回ループから opt-in 経路に入る
                    let _ = inner.flush_pending().await;
                    wake_datagram_send_waiters_after_flush(&inner, &mut datagram_send_waiters);
                    let _ = reply.send(Ok(()));
                    background = true;
                    continue;
                }
                Ok(other) => {
                    // Drive 以外: 即座に処理する
                    process_command(
                        &mut inner,
                        &mut observer,
                        &mut drive_replies,
                        &mut datagram_send_waiters,
                        &results,
                        other,
                    )
                    .await;
                    publish_closed_state(
                        &inner,
                        &closed_tx,
                        tracker.as_ref(),
                        &mut closed_published,
                        &mut tracker_released,
                    );
                    continue;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    // コマンドがなくなった: パケット受信とコマンド到着の両方を待つ。
                    // wait_and_process_only のみを待つと、待機中に到着したコマンド
                    // (StreamSend 等) が次のパケット受信またはタイマー発火まで
                    // 処理されず、不要な遅延が発生する。
                    let _ = inner.flush_pending().await;
                    wake_datagram_send_waiters_after_flush(&inner, &mut datagram_send_waiters);
                    tokio::select! {
                        biased;
                        Some(cmd) = rx.recv() => {
                            // コマンドが先に到着: パケット待ちを中断して処理する
                            match cmd {
                                Command::Drive { reply } => {
                                    handle_drive(
                                        &mut inner,
                                        &mut drive_replies,
                                        &mut datagram_send_waiters,
                                        &results,
                                        reply,
                                    )
                                    .await;
                                }
                                Command::EnableBackgroundDriver { reply } => {
                                    let _ = inner.flush_pending().await;
                                    wake_datagram_send_waiters_after_flush(
                                        &inner,
                                        &mut datagram_send_waiters,
                                    );
                                    let _ = reply.send(Ok(()));
                                    background = true;
                                }
                                Command::Shutdown => {
                                    shutdown_and_notify(
                                        &mut inner,
                                        &mut drive_replies,
                                        &mut datagram_send_waiters,
                                        &results,
                                    )
                                    .await;
                                    break;
                                }
                                other => {
                                    process_command(
                                        &mut inner,
                                        &mut observer,
                                        &mut drive_replies,
                                        &mut datagram_send_waiters,
                                        &results,
                                        other,
                                    )
                                    .await;
                                    publish_closed_state(
                                        &inner,
                                        &closed_tx,
                                        tracker.as_ref(),
                                        &mut closed_published,
                                        &mut tracker_released,
                                    );
                                }
                            }
                        }
                        result = inner.wait_and_process_only() => {
                            match result {
                                Ok(()) => {
                                    complete_waiters_on_progress(
                                        &inner,
                                        &mut drive_replies,
                                        &mut datagram_send_waiters,
                                        &results,
                                    );
                                    publish_closed_state(
                                        &inner,
                                        &closed_tx,
                                        tracker.as_ref(),
                                        &mut closed_published,
                                        &mut tracker_released,
                                    );
                                }
                                Err(e) => {
                                    publish_closed_state(
                                        &inner,
                                        &closed_tx,
                                        tracker.as_ref(),
                                        &mut closed_published,
                                        &mut tracker_released,
                                    );
                                    finish_waiters_with_error(
                                        &inner,
                                        &mut drive_replies,
                                        &mut datagram_send_waiters,
                                        &results,
                                        e,
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    continue;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    break;
                }
            }
        }

        // Pacing タイマーが残っている間は、送信が完了するまでタイマーを処理する。
        // 命令駆動モード (background 無効) ではタイマーを処理する契機が無いため、
        // ここで上限付きで処理する。上限を超えた場合はコマンド待ちへ戻る。
        for _ in 0..MAX_PACING_DRAIN_STEPS {
            if !inner.has_pending_pacing_timer() {
                break;
            }
            // 1 ステップの待ち時間にも上限を設け、長時間 driver を占有しない
            let step =
                tokio::time::timeout(PACING_DRAIN_STEP_TIMEOUT, inner.wait_and_process_only())
                    .await;
            if !matches!(step, Ok(Ok(()))) {
                break;
            }
            let _ = inner.flush_pending().await;
            // 待機者がいる間は上のドレイン経路が continue するため、ここでは空である。
            debug_assert!(drive_replies.is_empty() && datagram_send_waiters.is_empty());
            // pacing 待ちの間に接続が終了した場合に備えて、終了理由を確定させ、
            // closed() の完了と接続追跡の解除を進める。待機者はいないため、
            // ここで接続終了エラーを配る必要はない。
            publish_closed_state(
                &inner,
                &closed_tx,
                tracker.as_ref(),
                &mut closed_published,
                &mut tracker_released,
            );
            // 待機中にコマンドが到着している場合は、そちらを優先する
            if !rx.is_empty() {
                break;
            }
        }

        // Drive リクエストがない場合はブロッキングでコマンドを待つ。
        //
        // ここでパケット受信も同時に待つと、アプリケーションが操作していない間も
        // ソケットを読み続けることになり、0-RTT の再送やフロー制御クレジット通知の
        // タイミングが変わる。パケット処理を進めたい場合は `drive()` を呼ぶ。
        let Some(command) = rx.recv().await else {
            break;
        };

        match command {
            Command::Drive { reply } => {
                handle_drive(
                    &mut inner,
                    &mut drive_replies,
                    &mut datagram_send_waiters,
                    &results,
                    reply,
                )
                .await;
                // continue して drive_replies の分岐に入る
            }
            Command::EnableBackgroundDriver { reply } => {
                // バックグラウンド受信を有効化し、次回ループから opt-in 経路に入る
                let _ = inner.flush_pending().await;
                wake_datagram_send_waiters_after_flush(&inner, &mut datagram_send_waiters);
                let _ = reply.send(Ok(()));
                background = true;
            }
            Command::Shutdown => {
                // router からの graceful shutdown 指示: CONNECTION_CLOSE を
                // 送ってから driver task を終了する。待機中の呼び出しには
                // 接続終了のエラーを返してから終了する。
                shutdown_and_notify(
                    &mut inner,
                    &mut drive_replies,
                    &mut datagram_send_waiters,
                    &results,
                )
                .await;
                break;
            }
            other => {
                process_command(
                    &mut inner,
                    &mut observer,
                    &mut drive_replies,
                    &mut datagram_send_waiters,
                    &results,
                    other,
                )
                .await;
                publish_closed_state(
                    &inner,
                    &closed_tx,
                    tracker.as_ref(),
                    &mut closed_published,
                    &mut tracker_released,
                );
            }
        }
    }

    // ループを抜けた時点で残っている待機者も、接続終了として完了させる。
    // `Command::Shutdown` の経路では既に空になっている。チャネル切断などで
    // 抜けた場合も、待機中の API が内部エラー文字列で終わらないようにする。
    notify_connection_closed(
        &inner,
        &mut drive_replies,
        &mut datagram_send_waiters,
        &results,
    );

    // driver task の終了時にも購読者へ残りのイベントと終了を通知する。
    dispatch_observation_events(&mut inner, &mut observer);
    dispatch_connection_closed(&inner, &mut observer, &mut closed_event_sent);
    // driver task の終了時にも `closed()` を完了させる。明示的な close を
    // 伴わない停止 (チャネル切断や受信エラー) では理由は `None` になる。
    // 接続追跡もここで必ず解除し、`Client::wait_idle` が取り残されないようにする。
    if !closed_published {
        let reason = inner.close_reason();
        let _ = closed_tx.send(Some(ClosedInfo { reason }));
    }
    if !tracker_released && let Some(tracker) = tracker.as_ref() {
        tracker.unregister();
    }
}

/// graceful shutdown 指示に従って接続を閉じる (RFC 9000 Section 10.2)
///
/// CONNECTION_CLOSE をピアへ送ってから driver task を終了する。
/// タスク drop による切断ではピアから異常終了に見えるため、
/// 明示的に閉じる経路をここに集約する。
async fn shutdown_connection(inner: &mut ConnectionInner) {
    let result = match inner {
        ConnectionInner::Client(conn) => conn.close().await,
        ConnectionInner::Server(conn) => conn.close().await,
    };
    // close() が失敗しても driver task は終了させる。
    // ピアには Stateless Reset など別経路で切断が伝わる。
    let _ = result;
}

/// graceful shutdown を実行し、待機中の呼び出しを接続終了で完了させる
///
/// `drive_replies` には Drive の返信と、受理・受信の待機通知が混在する。
/// `datagram_send_waiters` には送信キュー空き待ちの通知が入る。どちらも接続
/// 終了後に成功を返しても意味が無いため、接続終了のエラーで完了させてから
/// driver task を終了する。
async fn shutdown_and_notify(
    inner: &mut ConnectionInner,
    drive_replies: &mut Vec<oneshot::Sender<Result<(), Error>>>,
    datagram_send_waiters: &mut Vec<oneshot::Sender<Result<(), Error>>>,
    results: &SharedResults,
) {
    shutdown_connection(inner).await;
    notify_connection_closed(inner, drive_replies, datagram_send_waiters, results);
}

/// 待機中の通知を接続終了のエラーで完了させる
///
/// 接続が終了した時点で呼ぶ。driver の停止時に限らず、接続が閉状態に
/// なった時点 ([`process_command`] の末尾) でも呼ばれる。
///
/// 待機者を放置すると、呼び出し元は oneshot の切断を受けて `Error::Internal`
/// などのドライバー内部のエラー文字列を受け取る。接続終了として観測できる
/// 型付きエラー (`Error::Connection`) に揃える。
///
/// あわせて終了理由を [`SharedResults`] へ記録する。接続終了後に発行された
/// コマンドは、この理由を使って送信失敗を接続終了として返す。
///
/// [`SharedResults`] に理由が記録済みの場合はそれを優先する。駆動エラーで
/// 停止した直後は、close が確定していなくても実際のエラーが記録されている。
fn notify_connection_closed(
    inner: &ConnectionInner,
    drive_replies: &mut Vec<oneshot::Sender<Result<(), Error>>>,
    datagram_send_waiters: &mut Vec<oneshot::Sender<Result<(), Error>>>,
    results: &SharedResults,
) {
    let reason = results
        .closed_reason()
        .or_else(|| inner.close_reason())
        .unwrap_or(ConnectionError::Closed);
    results.set_closed_reason(reason.clone());
    for reply in drive_replies.drain(..) {
        let _ = reply.send(Err(Error::Connection(reason.clone())));
    }
    for reply in datagram_send_waiters.drain(..) {
        let _ = reply.send(Err(Error::Connection(reason.clone())));
    }
}

/// パケット・タイマー処理後の待機通知を完了させる
///
/// 接続が終了状態なら、成功を返して再試行させず、接続終了の型付きエラーで
/// 待機者を完了させる。終了していなければ、進捗があったものとして Drive の
/// 返信と待機中の呼び出しに成功を返す。
///
/// DATAGRAM の送信待ちを進捗契機で起こすのは、空きができたことを通知するため
/// ではなく、再試行のきっかけを作るためである。再試行のコマンド処理が空きを
/// 確認して flush するため、ACK やタイマーの進捗に合わせて再試行させる。
/// 空きの発生だけを契機にした起床は
/// [`wake_datagram_send_waiters_if_space`] が担う。
fn complete_waiters_on_progress(
    inner: &ConnectionInner,
    drive_replies: &mut Vec<oneshot::Sender<Result<(), Error>>>,
    datagram_send_waiters: &mut Vec<oneshot::Sender<Result<(), Error>>>,
    results: &SharedResults,
) {
    if is_closed_state(inner.state()) {
        notify_connection_closed(inner, drive_replies, datagram_send_waiters, results);
    } else {
        for reply in drive_replies.drain(..) {
            let _ = reply.send(Ok(()));
        }
        for reply in datagram_send_waiters.drain(..) {
            let _ = reply.send(Ok(()));
        }
    }
}

/// 送信キューに空きがあれば、DATAGRAM の送信待ちだけを起こす
///
/// transport の flush は、DATAGRAM の送出だけでなく、PMTU の縮小などで
/// 収まらなくなった DATAGRAM の破棄によっても送信キューの空きを作る。破棄の
/// 場合はパケットもタイマーも発生しないため、flush の直後にここで起床しないと
/// 待機者が次の進捗まで待ち続ける。
///
/// 受信待ちなどの他の待機者はキューに空きができても再開できないため、対象を
/// `datagram_send_waiters` に限定する。`has_space` は呼び出し側が flush 直後に
/// 取得した値を渡す。接続が終了している場合の扱いは呼び出し側に委ねる
/// (終了時は接続終了のエラーで完了させる経路が別にある)。
fn wake_datagram_send_waiters_if_space(
    has_space: bool,
    datagram_send_waiters: &mut Vec<oneshot::Sender<Result<(), Error>>>,
) {
    if !has_space || datagram_send_waiters.is_empty() {
        return;
    }
    for reply in datagram_send_waiters.drain(..) {
        let _ = reply.send(Ok(()));
    }
}

/// `flush_pending` の直後に DATAGRAM 送信の待機者を起こす
///
/// flush で送信キューの空きができていれば待機者を起こす。接続が終了している
/// 場合は、成功を返して再試行させず、接続終了のエラーで完了させる経路
/// (`notify_connection_closed` など) に委ねる。受信待ちを含む `drive_replies`
/// は対象にしない。
fn wake_datagram_send_waiters_after_flush(
    inner: &ConnectionInner,
    datagram_send_waiters: &mut Vec<oneshot::Sender<Result<(), Error>>>,
) {
    let has_space = !is_closed_state(inner.state()) && inner.datagram_send_queue_has_space();
    wake_datagram_send_waiters_if_space(has_space, datagram_send_waiters);
}

/// 駆動エラーで driver を停止するときの待機者の完了処理
///
/// 最初の待機者には実際に観測したエラーを返し、残りは記録した接続終了理由を
/// 型付きエラーとして返す。`close_reason` が確定していない場合は、正常
/// クローズとして扱わず、実際に観測したエラーを [`ConnectionError::Internal`]
/// として接続終了理由に記録する。停止後に発行されたコマンドも、この理由で
/// 失敗する。
fn finish_waiters_with_error(
    inner: &ConnectionInner,
    drive_replies: &mut Vec<oneshot::Sender<Result<(), Error>>>,
    datagram_send_waiters: &mut Vec<oneshot::Sender<Result<(), Error>>>,
    results: &SharedResults,
    error: Error,
) {
    // 理由の生成には error の内容を使うため、先頭の待機者へ move する前に作る。
    let reason = inner
        .close_reason()
        .unwrap_or_else(|| ConnectionError::Internal(error.to_string()));
    results.set_closed_reason(reason);
    if !drive_replies.is_empty() {
        // 先頭は Drive の返信であることが多く、実際の受信エラーを返すことで
        // 呼び出し側が原因を観測できる。
        let first = drive_replies.remove(0);
        let _ = first.send(Err(error));
    }
    notify_connection_closed(inner, drive_replies, datagram_send_waiters, results);
}

/// 待機コマンドの進捗通知を登録する
///
/// 待機側の future がキャンセルされている (`on_block` の受信者が消えている)
/// 場合は登録しない。登録すると、誰も受け取らない送信者がパケット進捗まで
/// 蓄積し続ける。
///
/// `waiters` は進捗通知の待機者リストであり、Drive の返信もこのリストに
/// 積まれることがある。
fn register_on_block(
    waiters: &mut Vec<oneshot::Sender<Result<(), Error>>>,
    on_block: oneshot::Sender<Result<(), Error>>,
) {
    if on_block.is_closed() {
        return;
    }
    waiters.push(on_block);
}

/// ストリーム開設コマンドの結果を返信し、待機するコマンドだけ進捗通知を登録する
///
/// 上限到達は接続終了ではないため、待機するコマンドでは `on_block` を進捗通知
/// として登録し、呼び出し側が MAX_STREAMS を含む受信・タイマーの進捗後に
/// 再試行できるようにする。上限到達以外のエラーでは登録せず、呼び出し側が
/// 待たずにエラーを観測できるようにする。
///
/// 返信先が既に破棄されている場合は、呼び出し側が future をキャンセルして
/// いるため何も返さず、進捗通知も登録しない。登録すると、誰も受け取らない
/// 送信者が driver のパケット進捗のたびに蓄積する。
///
/// エラーは変換せずにそのまま返す。platform 層の `open_stream_bidi` /
/// `open_stream_uni` が、接続終了を [`Error::Connection`]、それ以外を操作の
/// 文脈付きの [`Error::Protocol`] へ変換済みである。ここで再び文脈を付けると
/// 同じ文言が二重になる。
fn reply_open_result(
    result: Result<u64, Error>,
    reply: oneshot::Sender<Result<u64, Error>>,
    on_block: Option<oneshot::Sender<Result<(), Error>>>,
    drive_replies: &mut Vec<oneshot::Sender<Result<(), Error>>>,
) {
    if reply.is_closed() {
        return;
    }
    match result {
        Ok(stream_id) => {
            let _ = reply.send(Ok(stream_id));
        }
        Err(error) => {
            if matches!(error, Error::StreamLimitReached { .. })
                && let Some(on_block) = on_block
            {
                register_on_block(drive_replies, on_block);
            }
            let _ = reply.send(Err(error));
        }
    }
}

/// Drive 以外のコマンドを処理する
///
/// コマンド処理の最後に必ず `flush_pending` を呼ぶ。コマンドはデータ送信
/// (STREAM / DATAGRAM / PING) だけでなく、受信データの消費によるフロー制御
/// クレジット (MAX_DATA / MAX_STREAM_DATA)、PATH_STATUS、RESET_STREAM などの
/// 送信フレームも生成する。これらは transport の保留フレームに積まれるため、
/// パケット化して送信しないと次の受信まで停滞する。個々のハンドラで個別に
/// flush するのではなく、ここで一元的に送信する。既に flush 済みのハンドラでは
/// 出力キューが空のため、追加のコストは小さい。
async fn process_command(
    inner: &mut ConnectionInner,
    observer: &mut Option<mpsc::Sender<ConnectionEvent>>,
    drive_replies: &mut Vec<oneshot::Sender<Result<(), Error>>>,
    datagram_send_waiters: &mut Vec<oneshot::Sender<Result<(), Error>>>,
    results: &SharedResults,
    command: Command,
) {
    let path_events_before = inner.pending_path_event_count();
    let resets_stream = matches!(
        &command,
        Command::ResetStream { .. } | Command::ResetStreamAt { .. }
    );
    match command {
        Command::Drive { .. } => unreachable!("Drive is handled by driver_loop directly"),
        Command::Shutdown => unreachable!("Shutdown is handled by driver_loop directly"),
        Command::EnableBackgroundDriver { .. } => {
            unreachable!("EnableBackgroundDriver is handled by driver_loop directly")
        }
        Command::State { reply } => {
            let _ = reply.send(inner.state());
        }
        Command::Version { reply } => {
            let _ = reply.send(inner.version());
        }
        Command::VersionNegotiationVersions { reply } => {
            let _ = reply.send(inner.version_negotiation_versions());
        }
        Command::MaxDatagramSize { reply } => {
            let _ = reply.send(inner.max_datagram_size());
        }
        Command::Paths { reply } => {
            let _ = reply.send(inner.paths());
        }
        Command::AcceptPathEvent { reply, on_block } => {
            let result = if results.has_path_event() {
                // キャンセルされた呼び出しの分も含め、driver が既に取り出した
                // イベントは呼び出し側が回収する。
                Ok(())
            } else {
                match inner {
                    ConnectionInner::Client(conn) => conn.accept_path_event_now(),
                    ConnectionInner::Server(conn) => conn.accept_path_event_now(),
                }
                .and_then(|event| match event {
                    Some(event) => {
                        // 返信の受信者が消えていても失わないよう、先に共有
                        // キューへ積んでから進捗だけを返す。
                        results.push_path_event(event);
                        Ok(())
                    }
                    None => {
                        // 空の確認と登録を同じ処理で行い、通常の driver へ戻す。
                        register_on_block(drive_replies, on_block);
                        Err(Error::Internal("path event not ready".into()))
                    }
                })
            };
            let _ = reply.send(result);
        }
        Command::AcceptStopSending { reply, on_block } => {
            let result = if results.has_stop_sending() {
                // キャンセルされた呼び出しの分も含め、driver が既に取り出した
                // イベントは呼び出し側が回収する。
                Ok(())
            } else {
                match inner {
                    ConnectionInner::Client(conn) => conn.accept_stop_sending_now(),
                    ConnectionInner::Server(conn) => conn.accept_stop_sending_now(),
                }
                .and_then(|event| match event {
                    Some((stream_id, error_code)) => {
                        // 返信の受信者が消えていても失わないよう、先に共有
                        // キューへ積んでから進捗だけを返す。
                        results.push_stop_sending(stream_id, error_code);
                        Ok(())
                    }
                    None => {
                        // 空の確認と登録を同じ処理で行い、通常の driver へ戻す。
                        register_on_block(drive_replies, on_block);
                        Err(Error::Internal("stop sending not ready".into()))
                    }
                })
            };
            let _ = reply.send(result);
        }
        Command::SubscribeEvents { capacity, reply } => {
            if capacity == 0 {
                let _ = reply.send(Err(Error::Protocol(
                    "event subscription capacity must be greater than 0".into(),
                )));
                return;
            }
            if observer.is_some() {
                let _ = reply.send(Err(Error::Protocol(
                    "connection events are already subscribed".into(),
                )));
                return;
            }
            let (tx, rx) = mpsc::channel(capacity);
            inner.set_observation_enabled(true);
            *observer = Some(tx);
            let _ = reply.send(Ok(rx));
        }
        Command::NotifyNetworkEvent { event, reply } => {
            let result = match inner {
                ConnectionInner::Client(conn) => conn.notify_network_event(event).await,
                ConnectionInner::Server(conn) => conn.notify_network_event(event).await,
            };
            let _ = reply.send(result);
        }
        Command::IsHandshaking { reply } => {
            let _ = reply.send(matches!(inner.state(), ConnectionState::Handshaking));
        }
        Command::CloseReason { reply } => {
            let _ = reply.send(inner.close_reason());
        }
        Command::Stats { reply } => {
            let stats = match inner {
                ConnectionInner::Client(conn) => conn.stats(),
                ConnectionInner::Server(conn) => conn.stats(),
            };
            let _ = reply.send(stats);
        }
        Command::RemainingStreams { reply } => {
            let _ = reply.send(inner.remaining_streams());
        }
        // 接続情報
        Command::LocalAddr { reply } => {
            let _ = reply.send(inner.local_addr());
        }
        Command::RemoteAddr { reply } => {
            let _ = reply.send(inner.remote_addr());
        }
        Command::AlpnProtocol { reply } => {
            let _ = reply.send(inner.alpn_protocol());
        }
        // ピアの reset_stream_at transport parameter サポート判定
        Command::PeerSupportsResetStreamAt { reply } => {
            let _ = reply.send(inner.peer_supports_reset_stream_at());
        }
        // 0-RTT 状態と transport parameter
        Command::ZeroRttAccepted { reply } => {
            let _ = reply.send(inner.zero_rtt_accepted());
        }
        Command::PeerTransportParams { reply } => {
            let _ = reply.send(inner.peer_transport_params());
        }
        // preferred_address (RFC 9000 Section 9.6 / Section 18.2)
        Command::PeerPreferredAddress { reply } => {
            let _ = reply.send(inner.peer_preferred_address());
        }
        Command::MigrateToPreferredAddress { reply } => {
            let result = inner.migrate_to_preferred_address().await;
            let _ = reply.send(result);
        }
        Command::PathPeerCid { reply } => {
            let _ = reply.send(inner.path_peer_cid());
        }
        Command::InitialTokenValidated { reply } => {
            let _ = reply.send(inner.initial_token_validated());
        }
        Command::AcceptApplicationEvent { reply, on_block } => {
            let result = if results.has_application_event() {
                // キャンセルされた呼び出しの分も含め、driver が既に取り出した
                // イベントは呼び出し側が回収する。
                Ok(())
            } else {
                match inner.accept_application_event_now() {
                    Ok(event) => {
                        // 返信の受信者が消えていても失わないよう、先に共有
                        // キューへ積んでから進捗だけを返す。
                        results.push_application_event(event);
                        Ok(())
                    }
                    Err(error) => {
                        register_on_block(drive_replies, on_block);
                        Err(error)
                    }
                }
            };
            let _ = reply.send(result);
        }
        // Keep-Alive
        Command::SetKeepAlive { enabled, reply } => {
            let result = inner.set_keep_alive(enabled).await;
            let _ = reply.send(result);
        }
        Command::SetPathKeepAlive {
            path,
            enabled,
            reply,
        } => {
            let result = inner.set_path_keep_alive(path, enabled).await;
            let _ = reply.send(result);
        }
        Command::OpenBidirectionalStream { reply, on_block } => {
            // 返信の受信者が消えている場合は、呼び出し側が future を破棄した
            // (キャンセルした) ことを意味する。開設するとピアの許可数を消費した
            // ままストリームのハンドルが誰にも返らず、接続上に残るため、開設
            // する前に確認する。SendDatagramWait と同じ方針である。
            if !reply.is_closed() {
                reply_open_result(inner.open_stream_bidi(), reply, on_block, drive_replies);
            }
        }
        Command::OpenSendStream { reply, on_block } => {
            // 双方向と同じ理由で、開設する前にキャンセルを確認する。
            if !reply.is_closed() {
                reply_open_result(inner.open_stream_uni(), reply, on_block, drive_replies);
            }
        }
        Command::SetMaxStreams {
            bidirectional,
            maximum_streams,
            reply,
        } => {
            let result = if bidirectional {
                inner.set_max_streams_bidirectional(maximum_streams).await
            } else {
                inner.set_max_streams_unidirectional(maximum_streams).await
            };
            let _ = reply.send(result);
        }
        Command::AcceptBidirectionalStream { reply, on_block } => {
            let result = if results.has_bidirectional_stream() {
                // キャンセルされた呼び出しの分も含め、受理済みストリームは
                // 呼び出し側が回収する。
                Ok(())
            } else {
                let result = match inner {
                    ConnectionInner::Client(conn) => {
                        conn.accept_bidirectional_stream_now().map_err(|e| {
                            Error::Protocol(format!("accept bidirectional stream failed: {e}"))
                        })
                    }
                    ConnectionInner::Server(conn) => {
                        conn.accept_bidirectional_stream_now().map_err(|e| {
                            Error::Protocol(format!("accept bidirectional stream failed: {e}"))
                        })
                    }
                };
                match result {
                    Ok(stream_id) => {
                        // 返信の受信者が消えていても失わないよう、先に共有
                        // キューへ積んでから進捗だけを返す。
                        results.push_accept(stream_id, true);
                        Ok(())
                    }
                    Err(error) => {
                        register_on_block(drive_replies, on_block);
                        Err(error)
                    }
                }
            };
            let _ = reply.send(result);
        }
        Command::AcceptReceiveStream { reply, on_block } => {
            let result = if results.has_receive_stream() {
                Ok(())
            } else {
                let result = match inner {
                    ConnectionInner::Client(conn) => conn
                        .accept_receive_stream_now()
                        .map_err(|e| Error::Protocol(format!("accept receive stream failed: {e}"))),
                    ConnectionInner::Server(conn) => conn
                        .accept_receive_stream_now()
                        .map_err(|e| Error::Protocol(format!("accept receive stream failed: {e}"))),
                };
                match result {
                    Ok(stream_id) => {
                        results.push_accept(stream_id, false);
                        Ok(())
                    }
                    Err(error) => {
                        register_on_block(drive_replies, on_block);
                        Err(error)
                    }
                }
            };
            let _ = reply.send(result);
        }
        // 種別不問のストリーム受け入れ
        Command::AcceptStream { reply, on_block } => {
            let result = if results.has_accept() {
                Ok(())
            } else {
                let result = match inner {
                    ConnectionInner::Client(conn) => conn.accept_stream_now(),
                    ConnectionInner::Server(conn) => conn.accept_stream_now(),
                };
                match result {
                    Ok((stream_id, is_bidirectional)) => {
                        results.push_accept(stream_id, is_bidirectional);
                        Ok(())
                    }
                    Err(error) => {
                        register_on_block(drive_replies, on_block);
                        Err(error)
                    }
                }
            };
            let _ = reply.send(result);
        }
        Command::StreamSend {
            stream_id,
            data,
            fin,
            reply,
            on_block,
            accepted,
        } => {
            let result = match inner {
                ConnectionInner::Client(conn) => conn.stream_send_now(stream_id, &data, fin),
                ConnectionInner::Server(conn) => conn.stream_send_now(stream_id, &data, fin),
            };
            // 受理量はフロー制御の待機や UDP 出力より前に確定する。出力
            // エラーで返信が失われても、呼び出し側は accepted から受理済み
            // バイト数を回収できる。
            let result = match result {
                Ok(n) => {
                    if let Some(accepted) = &accepted {
                        accepted.store(n, Ordering::Release);
                    }
                    inner.flush_pending().await.map(|()| n)
                }
                Err(error) => {
                    if let Some(accepted) = &accepted {
                        accepted.store(0, Ordering::Release);
                    }
                    Err(error)
                }
            };
            // パケット生成と UDP 出力の失敗は返信前に返す。フロー制御に
            // よる待機はこの中では行わない。
            let result = result.and_then(|n| {
                if n == 0 && !data.is_empty() {
                    // 空入力と空 FIN の成功は待機にしない。送信クレジットが
                    // 足りないときだけ返信前に待機を登録する。
                    register_on_block(drive_replies, on_block);
                    Err(Error::Internal("stream send would block".into()))
                } else {
                    Ok(n)
                }
            });
            let _ = reply.send(result);
        }
        Command::StreamRecv {
            stream_id,
            len,
            reply,
            on_block,
        } => {
            let result = if len == 0 {
                // 長さ 0 の要求では読み取らない。内部バッファを 1 バイト確保して
                // 読み進めると n が呼び出し側のバッファ長を超える。receive 系は
                // 範囲外アクセスで panic し、receive_vectored は受け渡す先が無い
                // ままデータを失う。would block の Err にすると start_read が
                // Drive を繰り返すため、読み取りを行わずに 0 バイトを返す。
                //
                // 不変条件: tobi-transport の `RecvBuffer::read` は空バッファでは
                // ループに入らず、データの消費も `read_offset` の前進も行わない。
                // 終端状態でも `StreamManager::recv` が `(0, is_fully_read())` を
                // 返すため、その fin をそのまま返す。
                //
                // 0 長読み取りがデータを消費すると、呼び出し側に渡す先が無い
                // ままデータが失われる。不変条件が破られた場合は、データを
                // 二重に失わないよう実装不整合としてエラーにする。
                match inner {
                    ConnectionInner::Client(conn) => conn.stream_recv_now(stream_id, &mut []),
                    ConnectionInner::Server(conn) => conn.stream_recv_now(stream_id, &mut []),
                }
                .and_then(|(n, fin)| {
                    if n > 0 {
                        Err(Error::Internal(format!(
                            "empty stream receive consumed {n} bytes"
                        )))
                    } else {
                        Ok((Vec::new(), 0, fin))
                    }
                })
            } else {
                // `stream_recv()` は caller が要求したサイズぶんだけ読む。
                let mut buf = vec![0u8; len];
                match inner {
                    ConnectionInner::Client(conn) => conn.stream_recv_now(stream_id, &mut buf),
                    ConnectionInner::Server(conn) => conn.stream_recv_now(stream_id, &mut buf),
                }
                .and_then(|(n, fin)| {
                    if n > 0 || fin {
                        Ok((buf, n, fin))
                    } else {
                        Err(Error::Protocol(STREAM_RECV_WOULD_BLOCK.into()))
                    }
                })
            };
            // 空の確認後に別タスクの Drive が受信を進めても、通知を失わない。
            // would-block の返信を送る前に、この同じ driver 内で待機を登録する。
            if matches!(&result, Err(Error::Protocol(msg)) if msg == STREAM_RECV_WOULD_BLOCK) {
                register_on_block(drive_replies, on_block);
            }
            let _ = reply.send(result);
            // データ消費で生成される MAX_DATA / MAX_STREAM_DATA の送信は
            // process_command 末尾の共通 flush が行う。
        }
        Command::ResetStream {
            stream_id,
            error_code,
            reply,
        } => {
            let result = match inner {
                ConnectionInner::Client(conn) => conn.stream_reset(stream_id, error_code).await,
                ConnectionInner::Server(conn) => conn.stream_reset(stream_id, error_code).await,
            };
            let _ = reply.send(result);
        }
        // RESET_STREAM_AT 送信
        Command::ResetStreamAt {
            stream_id,
            error_code,
            reliable_size,
            reply,
        } => {
            let result = match inner {
                ConnectionInner::Client(conn) => {
                    conn.stream_reset_at(stream_id, error_code, reliable_size)
                        .await
                }
                ConnectionInner::Server(conn) => {
                    conn.stream_reset_at(stream_id, error_code, reliable_size)
                        .await
                }
            };
            let _ = reply.send(result);
        }
        Command::StopSending {
            stream_id,
            error_code,
            reply,
        } => {
            let result = match inner {
                ConnectionInner::Client(conn) => {
                    conn.stream_stop_sending(stream_id, error_code).await
                }
                ConnectionInner::Server(conn) => {
                    conn.stream_stop_sending(stream_id, error_code).await
                }
            };
            let _ = reply.send(result);
        }
        Command::SendDatagram { data, reply } => {
            let result = match inner {
                ConnectionInner::Client(conn) => conn.send_datagram(data).await,
                ConnectionInner::Server(conn) => conn.send_datagram(data).await,
            };
            let _ = reply.send(result);
        }
        Command::SendDatagramWait {
            data,
            reply,
            on_block,
        } => {
            // 返信の受信者が既に消えている場合は送信要求がキャンセル済みである。
            // payload を送信キューへ積むと、キャンセルしたのに送信されてしまう。
            // 待機登録もしない (誰も再開しないため)。
            if !reply.is_closed() {
                // 接続が終了している場合は、送信キューに空きがあっても積まない。
                // Draining / Closed では送られず、成功を返すと接続終了後も
                // 受理されたように見えるためである。
                let result = if let Some(error) = inner.closed_error_if_any() {
                    Some(DatagramSendWaitReply::Failed(error))
                } else {
                    // 待機では解決しないエラー (ピア非対応・フレームサイズ超過・
                    // PMTU から求めたペイロード上限超過) を先に返す。エラーが
                    // ある場合は空きを待たずに失敗させる。
                    match inner.validate_datagram(&data) {
                        Err(error) => Some(DatagramSendWaitReply::Failed(error)),
                        Ok(()) => {
                            // 空きが無い場合は、保留中の出力を 1 回送ってから
                            // 空きを再確認する。ACK や pacing の進行で空きが
                            // できていれば、待機に入らずに受理できる。
                            if !inner.datagram_send_queue_has_space() {
                                let _ = inner.flush_pending().await;
                            }
                            // flush は await を伴うため、その間に呼び出し側が
                            // future をキャンセルできる。受理点 (積む直前) を
                            // 越えていないことをここで再確認し、キャンセル済み
                            // なら payload を積まず、待機登録もせずに終了する。
                            // 返信の受信者は既に消えているため送信しない。
                            if reply.is_closed() {
                                None
                            } else if let Some(error) = inner.closed_error_if_any() {
                                // flush が出力エラーで接続を閉じた場合に備えて、
                                // 受理前に終了状態を再確認する。
                                Some(DatagramSendWaitReply::Failed(error))
                            } else if inner.datagram_send_queue_has_space() {
                                // 空きがあるので積む。パケット化は
                                // process_command 末尾の共通 flush が行う。
                                Some(match inner.send_datagram_now(data.to_vec()) {
                                    Ok(()) => DatagramSendWaitReply::Accepted,
                                    Err(error) => DatagramSendWaitReply::Failed(error),
                                })
                            } else {
                                // 送信キューの空き待ち。DATAGRAM が送出されて
                                // 空きができた時点で driver が進捗通知を完了させ、
                                // 呼び出し側が同じ payload で再試行する。再試行の
                                // 判定は Blocked の返信で行う。
                                register_on_block(datagram_send_waiters, on_block);
                                Some(DatagramSendWaitReply::Blocked)
                            }
                        }
                    }
                };
                if let Some(result) = result {
                    let _ = reply.send(result);
                }
            }
        }
        Command::ReceiveDatagram { reply, on_block } => {
            let result = if results.has_datagram() {
                // キャンセルされた呼び出しの分も含め、受信済み DATAGRAM は
                // 呼び出し側が回収する。
                Ok(())
            } else {
                let result = match inner {
                    ConnectionInner::Client(conn) => conn.recv_datagram_now(),
                    ConnectionInner::Server(conn) => conn.recv_datagram_now(),
                };
                match result {
                    Ok(data) => {
                        // 返信の受信者が消えていても失わないよう、先に共有
                        // キューへ積んでから進捗だけを返す。
                        results.push_datagram(data);
                        Ok(())
                    }
                    Err(error) => {
                        register_on_block(drive_replies, on_block);
                        Err(error)
                    }
                }
            };
            let _ = reply.send(result);
        }
        Command::OpenPath { request, reply } => {
            let result = match inner {
                ConnectionInner::Client(conn) => conn.open_path(request).await.map(PathHandle::new),
                ConnectionInner::Server(conn) => conn.open_path(request).await.map(PathHandle::new),
            };
            let _ = reply.send(result);
        }
        Command::Migrate { request, reply } => {
            let result = match inner {
                ConnectionInner::Client(conn) => conn.migrate(request).await,
                ConnectionInner::Server(_) => Err(Error::Protocol(
                    "connection migration is only available for client connections".into(),
                )),
            };
            let _ = reply.send(result);
        }
        Command::AbandonPath {
            path,
            error_code,
            reply,
        } => {
            let result = match inner {
                ConnectionInner::Client(conn) => conn.abandon_path(path.raw(), error_code).await,
                ConnectionInner::Server(conn) => conn.abandon_path(path.raw(), error_code).await,
            };
            let _ = reply.send(result);
        }
        Command::RotatePathCid { path, reply } => {
            let result = match inner {
                ConnectionInner::Client(conn) => conn.rotate_path_cid(path.raw()).await,
                ConnectionInner::Server(conn) => conn.rotate_path_cid(path.raw()).await,
            };
            let _ = reply.send(result);
        }
        Command::SetPathStatus {
            path,
            status,
            reply,
        } => {
            let result = match inner {
                ConnectionInner::Client(conn) => conn.set_path_status(path.raw(), status).await,
                ConnectionInner::Server(conn) => conn.set_path_status(path.raw(), status).await,
            };
            let _ = reply.send(result);
        }
        Command::SetMaxPathId { max_path_id, reply } => {
            let result = match inner {
                ConnectionInner::Client(conn) => conn.set_max_path_id(max_path_id).await,
                ConnectionInner::Server(conn) => conn.set_max_path_id(max_path_id).await,
            };
            let _ = reply.send(result);
        }
        Command::Ping { reply } => {
            let result = match inner {
                ConnectionInner::Client(conn) => conn.ping().await,
                ConnectionInner::Server(conn) => conn.ping().await,
            };
            let _ = reply.send(result);
        }
        Command::UpdateKeys { reply } => {
            let result = match inner {
                ConnectionInner::Client(conn) => conn.update_keys().await,
                ConnectionInner::Server(conn) => conn.update_keys().await,
            };
            let _ = reply.send(result);
        }
        Command::PingPath { path, reply } => {
            let result = match inner {
                ConnectionInner::Client(conn) => conn.ping_on(path.raw()).await,
                ConnectionInner::Server(conn) => conn.ping_on(path.raw()).await,
            };
            let _ = reply.send(result);
        }
        Command::SendAckFrequency {
            path,
            ack_eliciting_threshold,
            requested_max_ack_delay,
            reordering_threshold,
            reply,
        } => {
            let result = match inner {
                ConnectionInner::Client(conn) => {
                    conn.send_ack_frequency(
                        path.raw(),
                        ack_eliciting_threshold,
                        requested_max_ack_delay,
                        reordering_threshold,
                    )
                    .await
                }
                ConnectionInner::Server(conn) => {
                    conn.send_ack_frequency(
                        path.raw(),
                        ack_eliciting_threshold,
                        requested_max_ack_delay,
                        reordering_threshold,
                    )
                    .await
                }
            };
            let _ = reply.send(result);
        }
        Command::SendImmediateAck { path, reply } => {
            let result = match inner {
                ConnectionInner::Client(conn) => conn.send_immediate_ack(path.raw()).await,
                ConnectionInner::Server(conn) => conn.send_immediate_ack(path.raw()).await,
            };
            let _ = reply.send(result);
        }
        Command::Close {
            application,
            error_code,
            reason,
            reply,
        } => {
            let result = match inner {
                ConnectionInner::Client(conn) => {
                    if application {
                        conn.close_with_application_error(error_code, &reason).await
                    } else {
                        conn.close_with_error(error_code, &reason).await
                    }
                }
                ConnectionInner::Server(conn) => {
                    if application {
                        conn.close_with_application_error(error_code, &reason).await
                    } else {
                        conn.close_with_error(error_code, &reason).await
                    }
                }
            };
            let _ = reply.send(result);
        }
    }

    // コマンドが生成した transport 出力を必ず送信する。返信は各ハンドラが既に
    // 送っているため、flush のエラーはここでは呼び出し元に伝えられない。
    // 次の受信またはコマンド処理で再送・再試行されるため、ここでは握りつぶす。
    let _ = inner.flush_pending().await;
    if is_closed_state(inner.state()) {
        // 終了は進捗と区別する。空の受理・受信要求へ成功通知を返すと、
        // 終了後も would-block の確認と通知だけを繰り返してしまう。
        notify_connection_closed(inner, drive_replies, datagram_send_waiters, results);
    } else {
        if resets_stream || inner.pending_path_event_count() > path_events_before {
            // ローカル RESET でも送信状態が終端へ変わる。出力に失敗した場合も
            // 状態変更は済んでいる可能性があるため、待機者に再確認させる。
            // パスイベントはローカル操作でも発生する。新たに積まれたときだけ
            // 通知し、未回収のイベントがあるだけで空読みを起こし続けない。
            for reply in drive_replies.drain(..) {
                let _ = reply.send(Ok(()));
            }
        }
        // 送信キューに空きができた場合は、飽和で待機している DATAGRAM 送信
        // だけを再開させる。RESET とパスイベントは DATAGRAM の送信キュー長を
        // 変えないため、待機者を起こすのはこの確認に一本化する。
        wake_datagram_send_waiters_if_space(
            inner.datagram_send_queue_has_space(),
            datagram_send_waiters,
        );
    }
}

/// ピアから受け入れたストリーム
///
/// 双方向/単方向を問わず受け入れたストリームを表す。
#[derive(Debug)]
pub enum PeerStream {
    /// 双方向ストリーム
    Bidirectional(BidirectionalStream),
    /// 単方向受信ストリーム
    Receive(ReceiveStream),
}

/// 接続の観測イベント
///
/// [`Connection::subscribe_events`] で購読すると、driver task が接続の進行に
/// 伴って発生した観測イベントをこの型で通知する。メトリクス収集・デバッグ・
/// テストでの検証など、アプリケーションがリアルタイムにイベントを消費する
/// 用途向け。
///
/// qlog との使い分け: qlog (`QlogWriter`) は JSON-SEQ としてファイルへ記録し
/// 後から解析する用途向け。本イベントは記録形式を持たず、アプリケーションが
/// 直接フィルタして利用する用途向けである。パケット単位の完全な記録が必要な
/// 場合は qlog を使う。
///
/// イベントは driver task から非同期に送信される。購読チャネルが満杯の場合は
/// イベントを破棄し、接続処理をブロックしない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionEvent {
    /// パケットを送信した
    PacketSent {
        /// 送信したパス
        path_id: tobi_core::path::PathId,
        /// パケット番号
        packet_number: u64,
        /// パケットのバイト数
        size: usize,
    },
    /// パケットを受信した
    PacketReceived {
        /// 受信したパス
        path_id: tobi_core::path::PathId,
        /// パケット番号
        packet_number: u64,
        /// パケットのバイト数
        size: usize,
    },
    /// パケットをロストした
    PacketLost {
        /// ロストしたパケットを送信したパス
        path_id: tobi_core::path::PathId,
        /// パケット番号
        packet_number: u64,
    },
    /// 輻輳制御の状態が変化した
    CongestionStateChanged {
        /// 状態が変化したパス
        path_id: tobi_core::path::PathId,
        /// 新しい輻輳制御の状態の分類
        ///
        /// 輻輳制御アルゴリズムごとに状態型が異なるため、共通の分類に丸めた値。
        state: tobi_core::recovery::congestion::CongestionStateKind,
    },
    /// パス検証が完了した
    PathValidated {
        /// 検証が完了したパス
        path_id: tobi_core::path::PathId,
    },
    /// 1-RTT 鍵が更新された (RFC 9001 Section 6)
    KeyUpdated {
        /// 新しい鍵フェーズ (0 または 1)
        key_phase: u8,
    },
    /// 接続が終了した
    ///
    /// 明示的な CONNECTION_CLOSE を伴わない driver task の停止では `reason` は
    /// `None` になる。
    ConnectionClosed {
        /// 接続終了の理由
        reason: Option<ConnectionError>,
    },
}

impl ConnectionEvent {
    /// transport の観測イベントを公開型へ変換する
    fn from_core(event: CoreObservationEvent) -> Self {
        match event {
            CoreObservationEvent::PacketSent {
                path_id,
                packet_number,
                size,
            } => Self::PacketSent {
                path_id,
                packet_number,
                size,
            },
            CoreObservationEvent::PacketReceived {
                path_id,
                packet_number,
                size,
            } => Self::PacketReceived {
                path_id,
                packet_number,
                size,
            },
            CoreObservationEvent::PacketLost {
                path_id,
                packet_number,
            } => Self::PacketLost {
                path_id,
                packet_number,
            },
            CoreObservationEvent::CongestionStateChanged { path_id, state } => {
                Self::CongestionStateChanged { path_id, state }
            }
            CoreObservationEvent::PathValidated { path_id } => Self::PathValidated { path_id },
            CoreObservationEvent::KeyUpdated { key_phase } => Self::KeyUpdated { key_phase },
        }
    }
}

/// アプリケーションへ通知するコネクション関連イベント
///
/// `accept_application_event()` で非同期に 1 件ずつ取り出す。
/// 0-RTT のセッション管理や NEW_TOKEN 永続化に使用する。
#[derive(Debug, Clone)]
pub enum ApplicationEvent {
    /// セッションチケットを受信した (RFC 9001 Section 4.6)
    ///
    /// サーバーからの NewSessionTicket を処理し、rustls の session store に
    /// 保存された。同じストアを設定した `ClientConfig` を用いれば次回接続で
    /// 0-RTT が利用可能になる。`tobi_quic::session::SessionTicketStore` を
    /// `ClientTlsConfig::with_session_store` に渡すと、保存されたチケットの数を
    /// 観測できる。
    ///
    /// rustls はチケットのバイト列表現を公開しないため、本イベントは
    /// チケットのバイト列を持たない。再開情報はストア内に保持される。
    SessionTicketReceived,
    /// サーバーが 0-RTT を拒否した (RFC 9001 Section 4.6.2)
    ///
    /// 0-RTT で送信したデータはサーバーに到達していない。バッファされた
    /// ストリームデータは 1-RTT で自動的に再送される。
    ZeroRttRejected,
    /// NEW_TOKEN フレームを受信した (RFC 9000 Section 19.7)
    ///
    /// アプリケーションはトークンを保存し、次回接続時の Initial パケットへ
    /// `address validation token` として含めることで、再接続時の検証往復を省ける。
    NewToken { token: Vec<u8> },
}

impl ApplicationEvent {
    fn from_core(event: CoreConnectionEvent) -> Option<Self> {
        match event {
            CoreConnectionEvent::SessionTicketReceived => Some(Self::SessionTicketReceived),
            CoreConnectionEvent::ZeroRttRejected => Some(Self::ZeroRttRejected),
            CoreConnectionEvent::NewToken { token } => Some(Self::NewToken { token }),
            _ => None,
        }
    }
}

/// ストリーム受け入れ専用ハンドル
///
/// `Connection::split()` で取得する。ストリームの受け入れ操作のみを提供する。
/// 受理結果は [`Connection`] と共有するキューに保持されるため、受理の future を
/// キャンセルしても、次に受理を呼んだときに同じストリームを受け取れる。
pub struct StreamAcceptor {
    tx: SharedConnection,
}

impl StreamAcceptor {
    /// 双方向ストリームを受け入れる
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルしても、driver が受理したストリームは失われない。
    /// 次に受理を呼ぶと、キャンセル前に受理していたストリームを受け取れる。
    /// 複数のタスクで待つ場合、どの呼び出しが 1 本を受け取るかは共有キューの
    /// 取り出し順に依存する。接続が終了した場合でも、共有キューに残った
    /// ストリームを返し切った後に接続終了のエラーを返す。接続終了理由が
    /// 共有されている場合は `Error::Connection` を返し、driver が理由を残さずに
    /// 停止した場合だけ `Error::Internal` になる。
    ///
    /// 待機中は、既定のコマンド駆動モードでも driver が受信とタイマーを処理する。
    pub async fn accept_bidirectional_stream(&self) -> Result<BidirectionalStream, Error> {
        let stream_id = wait_for_shared_result(
            &self.tx,
            |results| results.claim_bidirectional_stream(),
            |reply, on_block| Command::AcceptBidirectionalStream { reply, on_block },
        )
        .await?;
        Ok(BidirectionalStream::new(self.tx.clone(), stream_id))
    }

    /// 単方向受信ストリームを受け入れる
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルしても、driver が受理したストリームは失われない。
    /// 次に受理を呼ぶと、キャンセル前に受理していたストリームを受け取れる。
    /// 複数のタスクで待つ場合、どの呼び出しが 1 本を受け取るかは共有キューの
    /// 取り出し順に依存する。接続が終了した場合でも、共有キューに残った
    /// ストリームを返し切った後に接続終了のエラーを返す。接続終了理由が
    /// 共有されている場合は `Error::Connection` を返し、driver が理由を残さずに
    /// 停止した場合だけ `Error::Internal` になる。
    ///
    /// 待機中は、既定のコマンド駆動モードでも driver が受信とタイマーを処理する。
    pub async fn accept_receive_stream(&self) -> Result<ReceiveStream, Error> {
        let stream_id = wait_for_shared_result(
            &self.tx,
            |results| results.claim_receive_stream(),
            |reply, on_block| Command::AcceptReceiveStream { reply, on_block },
        )
        .await?;
        Ok(ReceiveStream::new(self.tx.clone(), stream_id))
    }

    /// 種別不問でストリームを受け入れる
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルしても、driver が受理したストリームは失われない。
    /// 次に受理を呼ぶと、キャンセル前に受理していたストリームを受け取れる。
    /// 複数のタスクで待つ場合、どの呼び出しが 1 本を受け取るかは共有キューの
    /// 取り出し順に依存する。接続が終了した場合でも、共有キューに残った
    /// ストリームを返し切った後に接続終了のエラーを返す。接続終了理由が
    /// 共有されている場合は `Error::Connection` を返し、driver が理由を残さずに
    /// 停止した場合だけ `Error::Internal` になる。
    ///
    /// 待機中は、既定のコマンド駆動モードでも driver が受信とタイマーを処理する。
    ///
    /// 種別付きの受理と `accept_stream` を混在させた場合、`accept_stream` の
    /// 受理順は到着順にならない。種別付きの受理が、先に種別の一致する要素を
    /// 共有キューから取り出すためである。
    pub async fn accept_stream(&self) -> Result<PeerStream, Error> {
        let (stream_id, is_bidi) = wait_for_shared_result(
            &self.tx,
            |results| results.claim_stream(),
            |reply, on_block| Command::AcceptStream { reply, on_block },
        )
        .await?;
        if is_bidi {
            Ok(PeerStream::Bidirectional(BidirectionalStream::new(
                self.tx.clone(),
                stream_id,
            )))
        } else {
            Ok(PeerStream::Receive(ReceiveStream::new(
                self.tx.clone(),
                stream_id,
            )))
        }
    }
}

/// driver を 1 ステップ進めるヘルパー
async fn drive_once(tx: &SharedConnection) -> Result<(), Error> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(Command::Drive { reply: reply_tx })
        .await
        .map_err(|_| tx.send_failure_error())?;
    reply_rx.await.map_err(|_| tx.reply_dropped_error())?
}

/// 空の確認と待機登録を同じコマンドで行い、進捗後に再試行する。
///
/// 確認と Drive を別々に送ると、その間に別タスクが受信した通知を失う。
/// driver が would-block の返信前に登録した on_block を使い、既に受信が
/// 進んでいる場合は新しいパケットを待たずに再試行する。
///
/// 返信がエラーでも on_block が登録されていれば、その通知を待って再試行する。
/// 通知が成功なら再試行し、通知がエラーならそのエラーを呼び出し元へ返す。
/// on_block が登録されていない (通知の送信者が残っていない) 場合は、再試行
/// できないため元のエラーをそのまま返す。ただし上限到達の返信は待機コマンドで
/// 必ず通知を登録するため、通知が届かない場合は driver の停止とみなし、古い
/// 上限到達ではなく接続終了のエラーを返す。接続終了理由が記録済みの場合も
/// 同様に接続終了のエラーを返す。
pub(crate) async fn wait_for_command<T>(
    tx: &SharedConnection,
    make_cmd: impl Fn(oneshot::Sender<Result<T, Error>>, oneshot::Sender<Result<(), Error>>) -> Command,
) -> Result<T, Error> {
    loop {
        let (ready_tx, ready_rx) = oneshot::channel();
        let result = send_command(tx, |reply| make_cmd(reply, ready_tx)).await?;
        match result {
            Ok(value) => return Ok(value),
            Err(error) => match ready_rx.await {
                Ok(result) => result?,
                // 通知の送信者が破棄された場合、上限到達の返信後に driver が
                // 停止したか、そもそも再試行不能なエラーで通知を登録しなかった
                // かのどちらかである。上限到達は待機コマンドでは必ず登録される
                // ため停止とみなす。接続終了理由が記録済みの場合も、古いエラーを
                // 返さず接続終了として返す。
                Err(_)
                    if matches!(error, Error::StreamLimitReached { .. })
                        || tx.results().closed_reason().is_some() =>
                {
                    return Err(tx.send_failure_error());
                }
                // 登録されないエラーは再試行不能であり、そのまま呼び出し元へ返す。
                Err(_) => return Err(error),
            },
        }
    }
}

/// driver が共有キューへ引き渡した結果を回収するまで待つ
///
/// 受理・DATAGRAM・イベント受信のコマンドは進捗だけを返すため、結果は
/// [`SharedResults`] から取り出す。取り出しは 1 回だけ行い、同じ結果を
/// 二重に返さない。
///
/// 1. 共有キューに結果があれば返す
/// 2. 無ければコマンドを送り、driver が結果を引き渡すまで待つ
/// 3. コマンドが完了したら先頭に戻り、再度共有キューを確認する
/// 4. コマンドが接続終了のエラーを返した場合も、共有キューに残った結果を
///    返し切ってからエラーを返す
///
/// 3 は、同時に待機している別のタスクが先に結果を回収した場合に備える。
/// その場合は改めて待機を登録し直す。
async fn wait_for_shared_result<T>(
    tx: &SharedConnection,
    claim: impl Fn(&SharedResults) -> Option<T>,
    make_cmd: impl Fn(oneshot::Sender<Result<(), Error>>, oneshot::Sender<Result<(), Error>>) -> Command,
) -> Result<T, Error> {
    let results = tx.results();
    loop {
        // キャンセルされた呼び出しの分も含め、driver が引き渡した結果を先に回収する。
        if let Some(value) = claim(results) {
            return Ok(value);
        }
        // 共有キューが空なら driver に結果の引き渡しを要求する。would-block の
        // 場合は進捗通知を待って再試行する。
        match wait_for_command(tx, &make_cmd).await {
            Ok(()) => {}
            Err(error) => {
                // 接続終了のエラーでも、driver が先に引き渡した結果を返し切る。
                // 待機中に別タスクが結果を回収した場合もここで拾える。
                if let Some(value) = claim(results) {
                    return Ok(value);
                }
                return Err(error);
            }
        }
    }
}

/// oneshot コマンドの送信と受信を行うヘルパー
async fn send_command<T>(
    tx: &SharedConnection,
    make_cmd: impl FnOnce(oneshot::Sender<T>) -> Command,
) -> Result<T, Error> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(make_cmd(reply_tx))
        .await
        .map_err(|_| tx.send_failure_error())?;
    reply_rx.await.map_err(|_| tx.reply_dropped_error())
}

/// Multipath-first な高水準接続
///
/// `Clone` 可能であり、複数タスクから同一接続を操作できる。
/// クローンはコマンドチャネルの Sender、受理・DATAGRAM・イベントの結果を
/// 保持する共有キューの `Arc`、接続終了通知の receiver を複製するだけなので
/// 安価。
#[derive(Clone)]
pub struct Connection {
    /// driver へのコマンド送信と、受理・DATAGRAM・path event /
    /// application event / STOP_SENDING の結果を共有するハンドル
    ///
    /// 複数タスクへ clone しても、接続状態そのものは driver task に残る。
    /// 受理・DATAGRAM・イベント受信の future をキャンセルしても結果を失わない
    /// よう、driver は結果を共有キューへ積んでから進捗だけを返信する。
    /// `Connection` の clone と [`StreamAcceptor`] が同じキューを共有する。
    tx: SharedConnection,
    /// driver task が接続の終了を観測したときに通知される理由
    ///
    /// `closed()` はこの receiver を clone して待つ。driver task が終了した
    /// 場合も、終了直前の理由が送られる。
    closed_rx: watch::Receiver<Option<ClosedInfo>>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // watch の read lock は 1 回だけ取り、borrow を保持したまま別の borrow を
        // しない。内部の channel / future / キューは出力しない。
        let closed_rx = &self.closed_rx;
        let (closed, reason) = {
            let borrowed = closed_rx.borrow();
            (
                borrowed.is_some(),
                borrowed.as_ref().and_then(|info| info.reason.clone()),
            )
        };
        let driver_stopped = closed_rx.is_closed();
        f.debug_struct("Connection")
            .field("closed", &closed)
            .field("driver_stopped", &driver_stopped)
            .field("reason", &reason)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for StreamAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamAcceptor").finish_non_exhaustive()
    }
}

impl Connection {
    pub(crate) fn from_client(
        inner: QuicConnection,
        tracker: Option<Arc<ConnectionTracker>>,
        background_driver: bool,
    ) -> Self {
        Self::spawn_driver(ConnectionInner::Client(inner), tracker, background_driver)
    }

    pub(crate) fn from_server(inner: QuicServerConnection, background_driver: bool) -> Self {
        let mut inner = inner;
        // router からの graceful shutdown 指示を受け取る口を先に取り出す。
        // 接続実体より先に取り出すことで、driver task が動き始める前に
        // 指示を取りこぼすことがない。
        let shutdown_rx = inner.take_shutdown_receiver();
        let (tx, closed_rx) =
            Self::spawn_driver_inner(ConnectionInner::Server(inner), None, background_driver);
        // 指示が届いたら driver task へ停止コマンドを送る。
        //
        // router は接続の driver task を直接止められないため、専用チャネルで
        // 指示を渡し、CONNECTION_CLOSE の送信は driver task 自身に行わせる。
        if let Some(mut rx) = shutdown_rx {
            // driver task を生かし続けないよう、監視タスクは weak sender を持つ。
            // strong sender を clone すると、アプリケーションが `Connection` を
            // drop してもチャネルが閉じず、driver task と接続実体がリークする
            // (CID の Unregister も走らない)。
            let weak_tx = tx.downgrade();
            tokio::spawn(async move {
                if rx.recv().await.is_some()
                    && let Some(tx) = weak_tx.upgrade()
                {
                    let _ = tx.send(Command::Shutdown).await;
                }
            });
        }
        Self { tx, closed_rx }
    }

    /// 接続実体を専用 driver task に移し、高水準 handle を返す。
    fn spawn_driver(
        inner: ConnectionInner,
        tracker: Option<Arc<ConnectionTracker>>,
        background_driver: bool,
    ) -> Self {
        let (tx, closed_rx) = Self::spawn_driver_inner(inner, tracker, background_driver);
        Self { tx, closed_rx }
    }

    /// 接続実体を driver task に移し、command ハンドルと終了通知 receiver を返す
    ///
    /// [`SharedConnection`] は driver と共有する [`SharedResults`] を保持する。
    /// driver は結果キューと接続終了理由を同じ `Arc` へ書き込む。
    fn spawn_driver_inner(
        inner: ConnectionInner,
        tracker: Option<Arc<ConnectionTracker>>,
        background_driver: bool,
    ) -> (SharedConnection, watch::Receiver<Option<ClosedInfo>>) {
        let (raw_tx, rx) = mpsc::channel(256);
        let (closed_tx, closed_rx) = watch::channel(None);
        let results = Arc::new(SharedResults::default());
        let tx = SharedConnection::new(raw_tx, Arc::clone(&results));
        tokio::spawn(driver_loop(
            inner,
            rx,
            closed_tx,
            tracker,
            results,
            background_driver,
        ));
        (tx, closed_rx)
    }

    pub(crate) fn shared(&self) -> SharedConnection {
        self.tx.clone()
    }

    /// 接続を操作ハンドルとストリーム受け入れハンドルに分割する
    ///
    /// 返される `Connection` はクローン可能で、ストリームの開閉や
    /// データグラム送受信を任意のタスクから行える。
    /// `StreamAcceptor` はストリーム受け入れ専用。
    /// 両者は受理結果の共有キューを共有するため、どちらで受理しても、
    /// キャンセルされた受理の結果を回収できる。
    pub fn split(&self) -> (Connection, StreamAcceptor) {
        let handle = self.clone();
        let acceptor = StreamAcceptor {
            tx: self.tx.clone(),
        };
        (handle, acceptor)
    }

    /// 接続状態を取得する
    ///
    /// ドライバータスクが停止している場合は `ConnectionState::Closed` を返す。
    /// 本ライブラリでは「ドライバー停止 == 接続終了」を設計上同義とみなし、
    /// コマンド送信失敗を明示的にエラーとして伝播しない。
    pub async fn state(&self) -> ConnectionState {
        send_command(&self.tx, |reply| Command::State { reply })
            .await
            .unwrap_or(ConnectionState::Closed)
    }

    /// 接続で使用している QUIC バージョンを取得する
    ///
    /// Version Negotiation で別バージョンに切り替えた場合、再試行後の
    /// バージョンを返す (RFC 9000 Section 6)。ドライバータスクが停止している
    /// 場合は、この実装が対応する最初のバージョン (v1) を返す。
    pub async fn version(&self) -> u32 {
        send_command(&self.tx, |reply| Command::Version { reply })
            .await
            .unwrap_or(tobi_core::packet::QUIC_VERSION_1)
    }

    /// 受信した Version Negotiation が提示したバージョン一覧を取得する
    ///
    /// `None` は Version Negotiation を受信していないことを表す。
    /// [`Client::connect_early`](crate::Client::connect_early) は Version
    /// Negotiation を受信すると自動再試行せず接続を終了するため、その場合は
    /// 本メソッドで提示一覧を確認し、必要なら [`Client::connect`](crate::Client::connect)
    /// で改めて接続する。
    pub async fn version_negotiation_versions(&self) -> Option<Vec<u32>> {
        send_command(&self.tx, |reply| Command::VersionNegotiationVersions {
            reply,
        })
        .await
        .unwrap_or(None)
    }

    /// 接続を 1 度駆動する
    ///
    /// 送信待ちのデータを送信し、次のパケットまたはタイマーを処理できるまで
    /// 待ってから戻る (blocking)。アプリケーションが接続を操作していない間も
    /// 接続を進めたい場合 (ピアからの CONNECTION_CLOSE・ACK・キープアライブの
    /// 処理など) に呼ぶ。
    ///
    /// 本ライブラリの接続は専用 task が駆動するため、通常は明示的な呼び出しを
    /// 必要としない。到着パケットも発火するタイマーも無い場合は、次の到着まで
    /// 戻らない。ただし、接続が `Closed` に至っている場合は待たずに戻る
    /// (エラー節を参照)。`Closing` / `Draining` の間は、close の送出と
    /// ドレインの進行のためにパケットとタイマーを処理する。
    ///
    /// # エラー
    ///
    /// driver の駆動エラーが発生した場合は、その実際のエラー ([`Error::Io`] や
    /// [`Error::Protocol`] など) を返す。接続が終了した場合は
    /// [`Error::Connection`] を返す。駆動した結果として CONNECTION_CLOSE を
    /// 処理した場合と、呼び出し時点で既に `Closed` だった場合のどちらも対象で
    /// ある。driver が停止した場合は [`Error::Internal`] を返し得る。
    ///
    /// 終了の理由が driver から共有されている場合は [`Self::closed`] または
    /// [`Self::close_reason`] で確認できる。driver が理由を残さずに停止した
    /// 場合は `None` になり得る。
    ///
    /// `Closed` では待機を解除するタイマーがなく、パケット到着による進捗も
    /// 保証されないため、待機せずに接続終了のエラーを返す。
    pub async fn drive(&self) -> Result<(), Error> {
        drive_once(&self.tx).await
    }

    /// バックグラウンド受信を有効化する (opt-in)
    ///
    /// 既定の driver はコマンド駆動であり、アプリケーションが API を呼んで
    /// いない間はソケット受信とタイマー発火を処理しない。この API を呼ぶと、
    /// 以降は API を呼んでいない間も driver が受信とタイマーを処理する。
    ///
    /// バックグラウンドで処理したいものの例:
    ///
    /// - ピアからの CONNECTION_CLOSE や ACK の処理
    /// - keep-alive の PING 送信とアイドルタイムアウトの発火
    /// - ピアからの一方向ストリームの受信
    ///
    /// 有効化しない場合は `drive()` またはパケット処理を伴う API を呼んだ
    /// ときに接続が進む。ただし、待機中の API (受理・受信・送信) がある間は、
    /// 有効化しなくても driver が受信とタイマーを処理する。有効化後も
    /// `drive()` は利用できる。
    ///
    /// [`ClientBuilder::with_background_driver`](crate::ClientBuilder::with_background_driver)
    /// または
    /// [`ServerBuilder::with_background_driver`](crate::ServerBuilder::with_background_driver)
    /// に `true` を指定した接続では、生成時から有効になっているためこのメソッド
    /// は不要である。呼んでもエラーにならず、冪等に `Ok(())` を返す。
    pub async fn enable_background_driver(&self) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::EnableBackgroundDriver { reply }).await?
    }

    /// 送信可能な最大 DATAGRAM ペイロードサイズを取得する
    ///
    /// ドライバータスクが停止している場合は `None` を返す (DATAGRAM 未サポートと同じ値)。
    /// これは「ドライバー停止 == 接続終了 == もう送信できない」という同一意味に
    /// 帰着するための意図的な挙動。
    pub async fn max_datagram_size(&self) -> Option<usize> {
        send_command(&self.tx, |reply| Command::MaxDatagramSize { reply })
            .await
            .unwrap_or(None)
    }

    /// 全パスのメトリクススナップショットを取得する
    ///
    /// ドライバータスクが停止している場合は空の `Vec` を返す (パスなしと同じ値)。
    /// 「ドライバー停止 == 接続終了 == パスなし」という同一意味に帰着する。
    pub async fn paths(&self) -> Vec<PathSnapshot> {
        send_command(&self.tx, |reply| Command::Paths { reply })
            .await
            .unwrap_or_default()
    }

    /// 接続全体の累積統計を取得する
    ///
    /// 送受信バイト数・パケット数、ロスト数、再送回数、開いたストリーム数、
    /// DATAGRAM の飽和による破棄回数、接続経過時間を返す。パケット数と
    /// バイト数は UDP データグラム単位で数える。パス別の内訳は
    /// [`Self::paths`] が返す [`PathSnapshot::stats`](crate::PathSnapshot) を
    /// 参照する。
    ///
    /// DATAGRAM の破棄回数は、RFC 9221 Section 5.4 が許す「送信せずに破棄する」
    /// 方針を選んだ [`Self::send_datagram`] が、送信キューの飽和時に最も古い
    /// payload を追い出した件数である。遅延を選ぶ [`Self::send_datagram_wait`]
    /// は破棄を起こさないため、この値を増やさない。
    ///
    /// `stop_sending_dropped` は、アプリが [`Self::accept_stop_sending`] を
    /// 呼ばないまま platform の専用キュー (上限 1024) が満杯になり、
    /// STOP_SENDING を捨てた件数である。transport 層は記録しない。
    ///
    /// `packet_dropped` は受信時に破棄したパケットの合計である。qlog の
    /// `packet_dropped` と同じ対象であり、UDP データグラム単位ではない破棄
    /// イベント数である。内訳として `packet_dropped_decryption_failure` と
    /// `packet_dropped_invalid` を持ち、
    /// `packet_dropped >= packet_dropped_decryption_failure + packet_dropped_invalid`
    /// を保つ。Closing / Draining / Closed 中の破棄、バージョン不一致、
    /// `MAX_PACKET_NUMBER` 超過、Key Phase trial の復号失敗は含まない。
    ///
    /// ドライバータスクが停止している場合はゼロ値の統計を返す。
    pub async fn stats(&self) -> ConnectionStats {
        send_command(&self.tx, |reply| Command::Stats { reply })
            .await
            .unwrap_or_default()
    }

    /// 利用可能と判断されたパスだけを返す
    ///
    /// [`Self::paths`] のうち `is_usable` が真のパスを返す。
    pub async fn usable_paths(&self) -> Vec<PathSnapshot> {
        self.paths()
            .await
            .into_iter()
            .filter(|path| path.is_usable)
            .collect()
    }

    /// 接続全体の帯域推定値 (bytes/sec) を返す
    ///
    /// 利用可能なパスの `bandwidth_estimate` を合計する。BBR などの
    /// 帯域推定を持つ輻輳制御を使っている場合に値が返り、複数パスを
    /// 同時に使うときの合計帯域の目安になる。推定を持つパスが無い場合や
    /// 輻輳制御が NewReno / CUBIC の場合は `None` を返す。
    pub async fn aggregate_bandwidth_estimate(&self) -> Option<u64> {
        let mut total = 0u64;
        let mut any = false;
        for path in self.paths().await {
            if !path.is_usable {
                continue;
            }
            if let Some(bandwidth) = path.bandwidth_estimate {
                total = total.saturating_add(bandwidth);
                any = true;
            }
        }
        any.then_some(total)
    }

    /// path 制御層から surfaced されたイベントを 1 件受け取る。
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルしても、driver が取り出したパスイベントは
    /// 失われない。次に `accept_path_event` を呼ぶと、キャンセル前に取り出して
    /// いたイベントを受け取れる。接続が終了した場合でも、共有キューに残った
    /// イベントを返し切った後に接続終了のエラーを返す。接続終了理由が共有されて
    /// いる場合は `Error::Connection` を返し、driver が理由を残さずに停止した
    /// 場合だけ `Error::Internal` になる。
    /// 複数のタスクで待つ場合、どの呼び出しがイベントを受け取るかは共有キュー
    /// の取り出し順に依存する。
    pub async fn accept_path_event(&self) -> Result<PathEvent, Error> {
        wait_for_shared_result(
            &self.tx,
            |results| results.claim_path_event(),
            |reply, on_block| Command::AcceptPathEvent { reply, on_block },
        )
        .await
    }

    /// 受信した STOP_SENDING を 1 件受け取る
    ///
    /// ピアが送信の停止を要求したストリームの ID とエラーコードを
    /// `(stream_id, error_code)` で返す (RFC 9000 Section 19.5)。`error_code` は
    /// STOP_SENDING の Application Protocol Error Code である
    /// (RFC 9000 Section 20.2)。既にイベントがキューにあれば即時に返し、
    /// 無ければ driver に取り出しを要求して待つ。
    ///
    /// 送信側が既に終端しているストリーム (RESET_STREAM 送信済み、または全データ
    /// が ACK 済み) では、RESET_STREAM で応答する必要がないため
    /// (RFC 9000 Section 3.5)、transport は通知を生成しない。その場合この API は
    /// イベントを返さない。内部のイベントキューが満杯のときは通知が破棄され、
    /// この API に現れないことがある。その場合も、ストリームの状態が保持されて
    /// いる間は [`SendStream::send`] などが `StreamError::Stopped` で同じコードを
    /// 返す。
    /// 受理 API とは別の取り出し口であり、STOP_SENDING が対応するストリームの
    /// 受理より先に返ることがある。STOP_SENDING を送る API は
    /// [`Self::stop_sending`] であり、受信側のストリームハンドルから送る場合は
    /// [`ReceiveStream::stop_sending`] / [`BidirectionalStream::stop_sending`] を
    /// 使う。
    ///
    /// この API はストリームの状態を変更せず、RESET_STREAM / STOP_SENDING を
    /// 送らない。応答の RESET_STREAM は transport が STOP_SENDING の受信時に
    /// 生成する (RFC 9000 Section 3.5)。
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルしても、driver が取り出したイベントは失われない。
    /// 次に `accept_stop_sending` を呼ぶと、キャンセル前に取り出していた
    /// イベントを受け取れる。接続が終了した場合、既に待機していた呼び出しには
    /// 接続終了のエラーを返すことがある。内部のイベントキューに残ったイベントは
    /// その後の呼び出しで返し切る。driver が停止した場合は、driver が既に
    /// 引き渡したイベントを返し切った後に同じエラーを返す。接続終了理由が
    /// 共有されている場合は `Error::Connection` を返し、driver が理由を残さずに
    /// 停止した場合だけ `Error::Internal` になる。
    /// 複数のタスクで待つ場合、どの呼び出しがイベントを受け取るかはイベント
    /// キューの取り出し順に依存する。
    ///
    /// アプリがこの API を呼ばないまま platform の専用キューが満杯になると、
    /// 新しい STOP_SENDING は破棄される。破棄件数は
    /// [`Connection::stats`] の `ConnectionStats::stop_sending_dropped` で
    /// 観測できる。破棄されても transport は RESET_STREAM を送るため、
    /// RFC 9000 Section 3.5 のプロトコル上の義務は果たされる。
    pub async fn accept_stop_sending(&self) -> Result<(u64, u64), Error> {
        wait_for_shared_result(
            &self.tx,
            |results| results.claim_stop_sending(),
            |reply, on_block| Command::AcceptStopSending { reply, on_block },
        )
        .await
    }

    pub async fn notify_network_event(&self, event: NetworkEvent) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::NotifyNetworkEvent {
            event,
            reply,
        })
        .await?
    }

    /// ハンドシェイク中かどうかを取得する
    ///
    /// ドライバータスクが停止している場合は `false` を返す。接続が閉じられた
    /// 後はハンドシェイク状態ではないため、この挙動は「ドライバー停止 == 接続終了」の
    /// 意味と一致する。
    pub async fn is_handshaking(&self) -> bool {
        send_command(&self.tx, |reply| Command::IsHandshaking { reply })
            .await
            .unwrap_or(false)
    }

    /// 接続の終了を待つ
    ///
    /// driver task が接続の終了 (Closing / Draining / Closed のいずれか) を
    /// 観測したとき、または driver task 自体が停止したときに完了する。
    /// 戻り値は [`Self::close_reason`] と同じく [`ConnectionError`] で、
    /// 明示的な CONNECTION_CLOSE を伴わない停止では `None` になる。
    ///
    /// [`Self::enable_background_driver`] を有効にすると、アプリケーションが
    /// 他の API を呼んでいない間も driver がパケットを処理するため、ピア主導の
    /// close でもこの future だけで完了できる。有効にしない場合も、待機中の
    /// API (受理・受信・送信) がある間は driver が受信とタイマーを処理するため、
    /// それらの進捗に伴ってこの future が完了し得る。待機中の API が無い場合は、
    /// `drive()` などで接続を進めるか、driver task が停止するまで待つ必要がある。
    ///
    /// この future は接続を進めない。複数回・複数タスクから同時に呼んでもよい。
    pub async fn closed(&self) -> Option<ConnectionError> {
        let mut rx = self.closed_rx.clone();
        loop {
            if let Some(info) = rx.borrow_and_update().clone() {
                return info.reason;
            }
            // driver task が終了通知を送らずに停止した場合は、終了したものとして
            // 理由なしの `None` を返す。
            if rx.changed().await.is_err() {
                return None;
            }
        }
    }

    /// 接続を閉じた理由を取得する
    ///
    /// ドライバータスクが停止している場合は `None` を返す (理由なしと同じ値)。
    /// アプリケーションが理由を必要とするのは「接続が閉じられたが明示的に close
    /// コードを受け取っていない」ケースに限られるため、ドライバー停止時は
    /// 「理由なし」として扱う。driver task が停止した後の理由は
    /// [`Self::closed`] の戻り値を使う。
    pub async fn close_reason(&self) -> Option<ConnectionError> {
        send_command(&self.tx, |reply| Command::CloseReason { reply })
            .await
            .unwrap_or(None)
    }

    // --- 接続情報 API ---

    /// ローカルアドレスを取得する
    pub async fn local_addr(&self) -> Result<SocketAddr, Error> {
        send_command(&self.tx, |reply| Command::LocalAddr { reply }).await?
    }

    /// リモートアドレスを取得する
    ///
    /// ドライバータスクが停止している場合は、接続終了理由を共有していれば
    /// `Error::Connection` を、理由を残さずに停止した場合だけ
    /// `Error::Internal("connection driver stopped")` を返す。driver が返信せずに
    /// 終了した場合も同様に、理由があれば `Error::Connection` を返す。
    pub async fn remote_addr(&self) -> Result<SocketAddr, Error> {
        send_command(&self.tx, |reply| Command::RemoteAddr { reply }).await
    }

    /// ネゴシエートされた ALPN プロトコルを取得する
    ///
    /// ドライバータスクが停止している場合は `None` を返す (ALPN 未指定と同じ値)。
    /// ALPN の利用者は通常ハンドシェイク完了直後に呼び出すため、ドライバー停止時は
    /// 「ALPN が確定しなかった」として扱う。
    pub async fn application_protocol(&self) -> Option<Vec<u8>> {
        send_command(&self.tx, |reply| Command::AlpnProtocol { reply })
            .await
            .unwrap_or(None)
    }

    /// ピアが `reset_stream_at` transport parameter を提示しているかを取得する
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 3 で定義される
    /// QUIC transport parameter (`0x1d`、draft-11 Section 8.1) の値を参照する。
    /// ハンドシェイク未完了またはドライバータスク停止時は `false` を返す
    /// (拡張未対応と同じ値)。
    pub async fn peer_supports_reset_stream_at(&self) -> bool {
        send_command(&self.tx, |reply| Command::PeerSupportsResetStreamAt {
            reply,
        })
        .await
        .unwrap_or(false)
    }

    /// サーバーが 0-RTT を受理したかを返す (RFC 9001 Section 4.6)
    ///
    /// クライアント側では、前回セッションの再開試行が成功したかを判定できる。
    /// 0-RTT 送信中はまだ確定していないため `false` を返すことがあり、確定は
    /// ハンドシェイク完了後になる。サーバー側では、当該接続で 0-RTT パケットを
    /// 実際に受理したかを判定できる (TLS が early_data を拒否した場合は `false`)。
    /// ドライバータスク停止時も `false` を返す (未受理と同じ値)。
    pub async fn zero_rtt_accepted(&self) -> bool {
        send_command(&self.tx, |reply| Command::ZeroRttAccepted { reply })
            .await
            .unwrap_or(false)
    }

    /// ネゴシエート済みのピア transport parameter を返す
    ///
    /// 次回接続で 0-RTT を利用するためにアプリ側が値を保存する用途で使う。
    /// ハンドシェイク未完了またはドライバータスク停止時は `None` を返す。
    pub async fn peer_transport_params(&self) -> Option<TransportParams> {
        send_command(&self.tx, |reply| Command::PeerTransportParams { reply })
            .await
            .unwrap_or(None)
    }

    /// ピアが広告した preferred_address を返す (RFC 9000 Section 18.2)
    ///
    /// サーバーがハンドシェイク応答の transport parameter で通知した
    /// 移行先アドレスと CID を返す。ハンドシェイク未完了、ピアが広告していない
    /// 場合、またはドライバータスク停止時は `None` を返す。
    pub async fn peer_preferred_address(&self) -> Option<PreferredAddress> {
        send_command(&self.tx, |reply| Command::PeerPreferredAddress { reply })
            .await
            .unwrap_or(None)
    }

    /// サーバーが広告した preferred_address へ移行を開始する
    /// (RFC 9000 Section 9.6.1)
    ///
    /// PATH_CHALLENGE を候補アドレスへ送信し、PATH_RESPONSE の受信で検証が
    /// 完了した時点で初期パスの 4-tuple と宛先 CID を移行先へ更新する。
    /// 検証の完了は [`Self::accept_path_event`] の `PathEvent::Validated`、
    /// 失敗は `PathEvent::ValidationFailed` で通知される。
    ///
    /// サーバー側の接続では移行する側にならないため、`Err(Error::Protocol)` を
    /// 返す。接続が確立していない場合や、ピアが preferred_address を広告して
    /// いない場合も `Err(Error::Protocol)` を返す。
    pub async fn migrate_to_preferred_address(&self) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::MigrateToPreferredAddress {
            reply,
        })
        .await?
    }

    /// 初期パスで送信に使うピアの Connection ID を返す
    ///
    /// preferred_address への移行が確定した場合は、ピアが通知した移行先の
    /// CID を返す (RFC 9000 Section 9.6.1)。まだ確定していない場合や
    /// ドライバータスク停止時は `None` を返す。
    pub async fn peer_connection_id(&self) -> Option<ConnectionId> {
        send_command(&self.tx, |reply| Command::PathPeerCid { reply })
            .await
            .unwrap_or(None)
    }

    /// Initial で受信したアドレストークンが検証できたかを返す
    /// (RFC 9000 Section 8.1.3)
    ///
    /// サーバー側の接続では、クライアントが Initial に有効なアドレストークンを
    /// 含めていた場合に `true` になる。トークンが無い、または検証に失敗した
    /// 場合はハンドシェイク完了後も `false` のままである。クライアント側の
    /// 接続では常に `false`。
    ///
    /// ドライバータスク停止時は `false` を返す (未検証と同じ値)。
    pub async fn initial_token_validated(&self) -> bool {
        send_command(&self.tx, |reply| Command::InitialTokenValidated { reply })
            .await
            .unwrap_or(false)
    }

    /// 次のアプリケーションイベントを受け取る
    ///
    /// `ApplicationEvent` に相当するイベント (SessionTicketReceived / ZeroRttRejected /
    /// NewToken) がキューに届くまで待機する。path event と同様、キューが空の間は
    /// driver をドライブして packet 受信を進める。
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルしても、driver が取り出したイベントは失われない。
    /// 次に `accept_application_event` を呼ぶと、キャンセル前に取り出していた
    /// イベントを受け取れる。接続が終了した場合でも、共有キューに残った
    /// イベントを返し切った後に接続終了のエラーを返す。接続終了理由が共有されて
    /// いる場合は `Error::Connection` を返し、driver が理由を残さずに停止した
    /// 場合だけ `Error::Internal` になる。
    /// 複数のタスクで待つ場合、どの呼び出しがイベントを受け取るかは共有キュー
    /// の取り出し順に依存する。
    pub async fn accept_application_event(&self) -> Result<ApplicationEvent, Error> {
        wait_for_shared_result(
            &self.tx,
            |results| results.claim_application_event(),
            |reply, on_block| Command::AcceptApplicationEvent { reply, on_block },
        )
        .await
    }

    /// 接続の観測イベントを購読する
    ///
    /// 戻り値の receiver に、接続の進行に伴う観測イベント ([`ConnectionEvent`])
    /// が非同期に届く。購読は接続ごとに 1 つまでで、既に購読中の場合や
    /// `capacity` が 0 の場合はエラーを返す。
    ///
    /// 購読者の遅延が接続処理をブロックしないよう、チャネルが満杯の場合は
    /// イベントを破棄する。receiver を drop すると購読が解除され、以降の
    /// 観測オーバーヘッドはゼロに戻る。
    ///
    /// 既定の接続はコマンド駆動であり、アプリケーションが API を呼んでいない間は
    /// パケットを処理しない。継続的にイベントを観測するには
    /// [`Self::enable_background_driver`] を併用する。
    ///
    /// qlog との使い分け: qlog は記録・後解析向け、本 API はアプリケーションに
    /// よるリアルタイム消費向けである。
    pub async fn subscribe_events(
        &self,
        capacity: usize,
    ) -> Result<mpsc::Receiver<ConnectionEvent>, Error> {
        send_command(&self.tx, |reply| Command::SubscribeEvents {
            capacity,
            reply,
        })
        .await?
    }

    // --- Keep-Alive ---

    /// パス単位 Keep-Alive の有効/無効の既定値を設定する (RFC 9000 Section 10.1.2)
    ///
    /// 既存の全パスに適用し、以降に作成されるパスにも継承される。
    /// パスごとに設定する場合は [`Self::set_path_keep_alive`] を使う。
    pub async fn keep_alive(&self, enabled: bool) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::SetKeepAlive { enabled, reply }).await?
    }

    /// パス単位 Keep-Alive の有効/無効を設定する (RFC 9000 Section 10.1.2)
    ///
    /// 指定したパスだけに PING による keep-alive を適用する。使用されない
    /// 待機パスを middlebox のタイムアウトで失わないようにするために使う
    /// (RFC 10069 Section 5.9)。
    pub async fn set_path_keep_alive(&self, path: &PathHandle, enabled: bool) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::SetPathKeepAlive {
            path: *path,
            enabled,
            reply,
        })
        .await?
    }

    // --- ストリーム API ---

    /// ピアが許可した双方向ストリームの残枠を返す
    ///
    /// ピアの累積許可数 (`initial_max_streams_bidi` と MAX_STREAMS で通知された
    /// 値) から、ローカルが既に開いた双方向ストリームの数を引いた値である。
    /// 許可数は接続の生存期間における累積値であり、ストリームを閉じても残枠は
    /// 戻らない (RFC 9000 Section 19.11)。ピアからより大きい MAX_STREAMS を
    /// 受信すると増える。
    ///
    /// 返り値は参照時点の値であり、後続の [`Self::open_bidirectional_stream`] や
    /// [`Self::open_bidirectional_stream_wait`] に対する予約ではない。同じ値を
    /// 参照した後に別のタスクがストリームを開くと、残枠はその分だけ減る。
    /// ハンドシェイク完了まではピアの許可数が未確定のため 0 を返し得る。
    ///
    /// ドライバータスクが停止している場合も 0 を返すため、実際に残枠が 0 の
    /// 状態とは型で区別できない。接続自体が利用可能かは [`Self::state`] と
    /// [`Self::closed`] で確認する。
    ///
    /// 返り値は driver が処理済みの受信内容を反映する。既定のコマンド駆動
    /// モードでは、ピアから届いた MAX_STREAMS を反映するには [`Self::drive`]
    /// などで接続を進める必要がある。
    pub async fn remaining_bidirectional_streams(&self) -> u64 {
        self.remaining_streams().await.0
    }

    /// ピアが許可した単方向ストリームの残枠を返す
    ///
    /// [`Self::remaining_bidirectional_streams`] の単方向版。単方向ストリームは
    /// [`Self::open_send_stream`] で開く。残枠の意味、返り値が参照時点の値で
    /// あること、driver の処理状況を反映すること、ドライバータスク停止時に 0 を
    /// 返すことは同じ。
    pub async fn remaining_unidirectional_streams(&self) -> u64 {
        self.remaining_streams().await.1
    }

    /// ピアが許可したストリームの残枠 (双方向, 単方向) を 1 回のコマンドで取得する
    ///
    /// 公開 API は方向ごとに分かれているが、内部では 1 回のコマンドで両方を
    /// 取得する。ドライバータスクが停止している場合は `(0, 0)` を返す。
    async fn remaining_streams(&self) -> (u64, u64) {
        send_command(&self.tx, |reply| Command::RemainingStreams { reply })
            .await
            .unwrap_or((0, 0))
    }

    /// ピアが起動できる双方向ストリームの累積上限を引き上げ、MAX_STREAMS を送る
    ///
    /// RFC 9000 Section 19.11: MAX_STREAMS はピアが接続の生存期間に開ける
    /// 双方向ストリームの累積数を通知する。現在の上限以下の値は広告しても効果が
    /// ないため無視し、フレームを送らずに `Ok(())` を返す (同 Section 4.6 /
    /// Section 19.11)。
    ///
    /// [`Self`] には現在広告している上限を取得する API がない。値は transport の
    /// `StreamManager::local_max_streams_bidi` が保持しており、公開 API からは
    /// 観測できない。適用されたかどうかも返さないため、呼び出し側は指定値が
    /// 広告されたことを確認できない。現在の上限以下の値を渡してもエラーにせず、
    /// 何も送らない (silent no-op)。
    ///
    /// # エラー
    ///
    /// - 2^60 を超える値は [`Error::Protocol`]。2^60 はストリーム ID を表現
    ///   できる上限として受理する
    /// - 接続が確立していない場合も [`Error::Protocol`]
    /// - 接続が閉鎖中の場合は [`Error::Connection`]
    pub async fn set_max_streams_bidirectional(&self, maximum_streams: u64) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::SetMaxStreams {
            bidirectional: true,
            maximum_streams,
            reply,
        })
        .await?
    }

    /// ピアが起動できる単方向ストリームの累積上限を引き上げ、MAX_STREAMS を送る
    ///
    /// [`Self::set_max_streams_bidirectional`] の単方向版。現在の上限以下の値を
    /// 無視して `Ok(())` を返す点、現在値を取得する API がない点、エラーの条件も
    /// 同じ。現在の上限は transport の `StreamManager::local_max_streams_uni` が
    /// 保持している。
    pub async fn set_max_streams_unidirectional(&self, maximum_streams: u64) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::SetMaxStreams {
            bidirectional: false,
            maximum_streams,
            reply,
        })
        .await?
    }

    /// 双方向ストリームを開く
    ///
    /// 1 回だけ試行する。上限の到着を待って開設したい場合は
    /// [`Self::open_bidirectional_stream_wait`] を使う。
    ///
    /// # エラー
    ///
    /// - ピアが許可したストリーム数の上限に達している場合は
    ///   [`Error::StreamLimitReached`]。このエラーは接続を閉じず、ピアから
    ///   より大きい MAX_STREAMS を受信した後に同じ open を再試行できる
    /// - 接続が閉鎖中 (Closing / Draining / Closed) の場合は
    ///   [`Error::Connection`]
    /// - それ以外は [`Error::Protocol`]。ピアの transport parameter の適用に
    ///   失敗した場合などが該当する
    /// - ドライバータスクが停止している場合は [`Error::Internal`] になり得る
    pub async fn open_bidirectional_stream(&self) -> Result<BidirectionalStream, Error> {
        let stream_id = send_command(&self.tx, |reply| Command::OpenBidirectionalStream {
            reply,
            on_block: None,
        })
        .await??;
        Ok(BidirectionalStream::new(self.shared(), stream_id))
    }

    /// 上限到達時にピアの進捗を待って双方向ストリームを開く
    ///
    /// ピアが許可したストリーム数の上限に達している場合は、driver に進捗通知を
    /// 登録し、パケット受信またはタイマーの進捗があるたびに開設を再試行する。
    /// ピアが MAX_STREAMS を送って上限を増やすと、再試行で開設に成功する。
    ///
    /// 1 回だけ試行する [`Self::open_bidirectional_stream`] と異なり、上限到達を
    /// 呼び出し側へ返さずに待つ。待機中も driver は他のコマンドを処理するため、
    /// 同じ接続で状態取得、統計取得、close などを行える。既定のコマンド駆動
    /// モードでも、この future が driver に受信とタイマーを処理させる。ピアが
    /// 上限を増やさず接続が継続している間は待ち続けるため、必要なら future を
    /// キャンセルする。
    ///
    /// # エラー
    ///
    /// 上限到達は待機の対象であり、呼び出し側へは返らない。上限到達以外の
    /// エラーは待たずに返す。
    ///
    /// - 接続が終了した場合は [`Error::Connection`]。ただし終了を観測した先頭の
    ///   待機者には、駆動で観測した生のエラーが返るため [`Error::Internal`] などに
    ///   なり得る
    /// - driver が終了理由を残さずに停止した場合も [`Error::Internal`] になり得る
    /// - 接続は継続しているが開設できない場合は [`Error::Protocol`]
    ///
    /// # キャンセルの安全性
    ///
    /// この future をドロップすると、driver に届いた開設コマンドは開設する前に
    /// キャンセルを確認し、ストリームを作らずに終わる。ピアの許可数を消費しない
    /// ため、キャンセル後に driver がコマンドを処理しても残枠は減らない。
    ///
    /// ただし、キャンセルの確認と開設は不可分ではない。driver が確認してから
    /// 開設するまでのわずかな間に呼び出し側がキャンセルすると、開設済みの
    /// ストリームは接続上に残り、その分の許可数は消費されたまま戻らない。
    /// この場合もストリームのハンドルは返らない。キャンセル後の残枠は
    /// [`Self::remaining_bidirectional_streams`] で確認できる。
    pub async fn open_bidirectional_stream_wait(&self) -> Result<BidirectionalStream, Error> {
        let stream_id = wait_for_command(&self.tx, |reply, on_block| {
            Command::OpenBidirectionalStream {
                reply,
                on_block: Some(on_block),
            }
        })
        .await?;
        Ok(BidirectionalStream::new(self.shared(), stream_id))
    }

    /// 双方向ストリームを受け入れる
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルしても、driver が受理したストリームは失われない。
    /// 次に受理を呼ぶと、キャンセル前に受理していたストリームを受け取れる。
    /// 複数のタスクで待つ場合、どの呼び出しが 1 本を受け取るかは共有キューの
    /// 取り出し順に依存する。接続が終了した場合でも、共有キューに残った
    /// ストリームを返し切った後に接続終了のエラーを返す。接続終了理由が
    /// 共有されている場合は `Error::Connection` を返し、driver が理由を残さずに
    /// 停止した場合だけ `Error::Internal` になる。
    ///
    /// 待機中は、既定のコマンド駆動モードでも driver が受信とタイマーを処理する。
    pub async fn accept_bidirectional_stream(&self) -> Result<BidirectionalStream, Error> {
        let stream_id = wait_for_shared_result(
            &self.tx,
            |results| results.claim_bidirectional_stream(),
            |reply, on_block| Command::AcceptBidirectionalStream { reply, on_block },
        )
        .await?;
        Ok(BidirectionalStream::new(self.shared(), stream_id))
    }

    /// 単方向受信ストリームを受け入れる
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルしても、driver が受理したストリームは失われない。
    /// 次に受理を呼ぶと、キャンセル前に受理していたストリームを受け取れる。
    /// 複数のタスクで待つ場合、どの呼び出しが 1 本を受け取るかは共有キューの
    /// 取り出し順に依存する。接続が終了した場合でも、共有キューに残った
    /// ストリームを返し切った後に接続終了のエラーを返す。接続終了理由が
    /// 共有されている場合は `Error::Connection` を返し、driver が理由を残さずに
    /// 停止した場合だけ `Error::Internal` になる。
    ///
    /// 待機中は、既定のコマンド駆動モードでも driver が受信とタイマーを処理する。
    pub async fn accept_receive_stream(&self) -> Result<ReceiveStream, Error> {
        let stream_id = wait_for_shared_result(
            &self.tx,
            |results| results.claim_receive_stream(),
            |reply, on_block| Command::AcceptReceiveStream { reply, on_block },
        )
        .await?;
        Ok(ReceiveStream::new(self.shared(), stream_id))
    }

    /// 種別不問でストリームを受け入れる
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルしても、driver が受理したストリームは失われない。
    /// 次に受理を呼ぶと、キャンセル前に受理していたストリームを受け取れる。
    /// 複数のタスクで待つ場合、どの呼び出しが 1 本を受け取るかは共有キューの
    /// 取り出し順に依存する。接続が終了した場合でも、共有キューに残った
    /// ストリームを返し切った後に接続終了のエラーを返す。接続終了理由が
    /// 共有されている場合は `Error::Connection` を返し、driver が理由を残さずに
    /// 停止した場合だけ `Error::Internal` になる。
    ///
    /// 待機中は、既定のコマンド駆動モードでも driver が受信とタイマーを処理する。
    ///
    /// 種別付きの受理と `accept_stream` を混在させた場合、`accept_stream` の
    /// 受理順は到着順にならない。種別付きの受理が、先に種別の一致する要素を
    /// 共有キューから取り出すためである。
    pub async fn accept_stream(&self) -> Result<PeerStream, Error> {
        let (stream_id, is_bidi) = wait_for_shared_result(
            &self.tx,
            |results| results.claim_stream(),
            |reply, on_block| Command::AcceptStream { reply, on_block },
        )
        .await?;
        if is_bidi {
            Ok(PeerStream::Bidirectional(BidirectionalStream::new(
                self.shared(),
                stream_id,
            )))
        } else {
            Ok(PeerStream::Receive(ReceiveStream::new(
                self.shared(),
                stream_id,
            )))
        }
    }

    /// 単方向ストリームを開く
    ///
    /// 1 回だけ試行する。上限の到着を待って開設したい場合は
    /// [`Self::open_send_stream_wait`] を使う。
    ///
    /// # エラー
    ///
    /// - ピアが許可したストリーム数の上限に達している場合は
    ///   [`Error::StreamLimitReached`]。このエラーは接続を閉じず、ピアから
    ///   より大きい MAX_STREAMS を受信した後に同じ open を再試行できる
    /// - 接続が閉鎖中 (Closing / Draining / Closed) の場合は
    ///   [`Error::Connection`]
    /// - それ以外は [`Error::Protocol`]
    /// - ドライバータスクが停止している場合は [`Error::Internal`] になり得る
    pub async fn open_send_stream(&self) -> Result<SendStream, Error> {
        let stream_id = send_command(&self.tx, |reply| Command::OpenSendStream {
            reply,
            on_block: None,
        })
        .await??;
        Ok(SendStream::new(self.shared(), stream_id))
    }

    /// 上限到達時にピアの進捗を待って単方向ストリームを開く
    ///
    /// [`Self::open_bidirectional_stream_wait`] の単方向版。待機と再試行の
    /// 仕組み、エラーの種類、キャンセル時の扱いは同じ。
    ///
    /// # エラー
    ///
    /// [`Self::open_bidirectional_stream_wait`] と同じ。上限到達は待機の対象で
    /// あり呼び出し側へは返らず、接続終了は [`Error::Connection`]、その他の
    /// 開設エラーは [`Error::Protocol`] になる。
    ///
    /// # キャンセルの安全性
    ///
    /// [`Self::open_bidirectional_stream_wait`] と同じ。キャンセル後に driver が
    /// コマンドを処理してもストリームを作らないため、ピアの許可数は消費され
    /// ない。確認と開設の間のわずかな競合で開設済みになった場合だけ、その
    /// ストリームが接続上に残る。
    pub async fn open_send_stream_wait(&self) -> Result<SendStream, Error> {
        let stream_id = wait_for_command(&self.tx, |reply, on_block| Command::OpenSendStream {
            reply,
            on_block: Some(on_block),
        })
        .await?;
        Ok(SendStream::new(self.shared(), stream_id))
    }

    /// 双方向ストリームを開いて送信側と受信側に分割する
    ///
    /// 上限到達を待って開設する待機版はない。待つ場合は
    /// [`Self::open_bidirectional_stream_wait`] で開設してから
    /// [`BidirectionalStream::split`] を使う。
    ///
    /// # エラー
    ///
    /// [`Self::open_bidirectional_stream`] と同じ。
    pub async fn open_bidirectional_stream_split(
        &self,
    ) -> Result<(SendStream, ReceiveStream), Error> {
        Ok(self.open_bidirectional_stream().await?.split())
    }

    pub async fn accept_bidirectional_stream_split(
        &self,
    ) -> Result<(SendStream, ReceiveStream), Error> {
        Ok(self.accept_bidirectional_stream().await?.split())
    }

    /// ストリームをリセットする (RESET_STREAM フレームを送信する)
    ///
    /// 確定した peer transport parameter のフロー制御上限 (ストリーム上限・
    /// 接続上限) を Final Size が超える場合は `Err` を返す
    /// (RFC 9000 Section 19.9, 19.10)。
    pub async fn reset_stream(&self, stream_id: u64, error_code: u64) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::ResetStream {
            stream_id,
            error_code,
            reply,
        })
        .await?
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
    /// `reliable_size` が以前の値より大きい場合は仕様 Section 5.2 に従い無視される
    /// (戻り値は `Ok`)。
    pub async fn reset_stream_at(
        &self,
        stream_id: u64,
        error_code: u64,
        reliable_size: u64,
    ) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::ResetStreamAt {
            stream_id,
            error_code,
            reliable_size,
            reply,
        })
        .await?
    }

    /// ピアに STOP_SENDING を送り、指定ストリームの送信を停止させる
    ///
    /// STOP_SENDING はピアの送信側にデータ送信の中止を要求する
    /// (RFC 9000 Section 3.5, Section 19.5)。このハンドルはストリームの状態を
    /// 保持しないため、既に受理した [`ReceiveStream`] や
    /// [`BidirectionalStream`] の受信状態は変化しない。ストリームハンドルの
    /// 終端状態も更新する場合は [`ReceiveStream::stop_sending`] /
    /// [`BidirectionalStream::stop_sending`] を使う。
    ///
    /// STOP_SENDING を送っても、受信バッファに溜まっているデータは受理済みの
    /// ストリームから引き続き読み出せる。STOP_SENDING は受信データの無視を
    /// 保証しないため (RFC 9000 Section 3.5)、本実装は受信済みデータの配信を
    /// 中断しない方針を採る (RFC 9000 Section 3.2 は中断してよいとする)。
    /// ピアから受信した STOP_SENDING の観測は [`Self::accept_stop_sending`] を
    /// 使う。
    pub async fn stop_sending(&self, stream_id: u64, error_code: u64) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::StopSending {
            stream_id,
            error_code,
            reply,
        })
        .await?
    }

    /// データグラムを送信キューへ積む (RFC 9221)
    ///
    /// RFC 9221 Section 5.4 は、輻輳制御が送信を許すまで DATAGRAM を遅延させるか、
    /// 送信せずに破棄するかのいずれかを実装に求めている。この API は破棄を選ぶ。
    /// 送信キューが満杯の場合は最も古いデータグラムを破棄して新しいものを
    /// 追加し、成功を返す。音声のように古いデータより新しいデータを優先する
    /// 用途向けの方針である。破棄回数は [`Self::stats`] が返す
    /// `ConnectionStats::datagram_send_dropped` で観測できる。現在のキュー長は
    /// `ConnectionStats::datagram_send_queue_len` で取得できる。キューの上限は
    /// [`DatagramConfig::send_queue_max`](crate::DatagramConfig) で設定する。
    /// 遅延を選びたい場合は [`Self::send_datagram_wait`] を使う。
    ///
    /// ピアが DATAGRAM に対応していない場合はエラーを返す。サイズの検査は 2 つ
    /// あり、片方はエンコード後のフレームサイズ (フレームタイプ + Length +
    /// payload) をピアの `max_datagram_frame_size` と比較する (RFC 9221
    /// Section 3)。もう片方は payload 単体を PMTU から求めたペイロード上限と
    /// 比較する (RFC 9000 Section 14.2)。payload 単体の上限は
    /// [`Self::max_datagram_size`] で取得できる。
    ///
    /// # エラー
    ///
    /// ピアが DATAGRAM に対応していない場合、エンコード後のフレームサイズが
    /// ピアの `max_datagram_frame_size` を超える場合、payload が PMTU から
    /// 求めたペイロード上限を超える場合は [`Error::Protocol`] を返す。接続が
    /// 既に終了している場合は [`Error::Connection`] を返す。driver の駆動エラー
    /// で接続が終了した場合は [`Error::Connection`] の理由が
    /// [`ConnectionError::Internal`]、driver が理由を残さずに停止した場合は
    /// [`Error::Internal`] になる。
    pub async fn send_datagram(&self, data: Vec<u8>) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::SendDatagram { data, reply }).await?
    }

    /// 送信キューの空きを待ってデータグラムを送る (RFC 9221)
    ///
    /// RFC 9221 Section 5.4 は、輻輳制御が送信を許すまで DATAGRAM を遅延させるか、
    /// 送信せずに破棄するかのいずれかを実装に求めている。この API は遅延を選ぶ。
    /// 送信キューに空きがあれば積んで成功を返し、満杯の場合は空きができるまで
    /// 待つ。この API だけを使う場合、飽和を理由に既存の payload が暗黙に
    /// 破棄されることはない。同じ接続で破棄方針の [`Self::send_datagram`] を
    /// 併用すると、その API が送信キュー内で最も古い payload を破棄し得る。
    /// キューの上限は [`DatagramConfig::send_queue_max`](crate::DatagramConfig)
    /// で設定する。
    ///
    /// 待機は接続の送信処理に委ねられる。先行して送信したデータの ACK が届いて
    /// 輻輳ウィンドウが開くと、送信キューの DATAGRAM が送出されて空きができる。
    /// 待機中は後述のとおり driver が受信とタイマーを処理するため、既定の
    /// コマンド駆動モードでも `drive()` を呼ばずに ACK を処理できる。ピア側で
    /// 接続が駆動されず ACK が返らない場合は、そのぶん待機が続く。
    ///
    /// # キャンセルの安全性
    ///
    /// driver が送信キューへ積む前の最後のキャンセル確認を通過した時点が
    /// 受理点である。受理点より前にキャンセルした場合 (送信キューの空き待ちで
    /// 進捗通知を待っている間や、driver が flush している間)、payload は送信
    /// キューに積まれず、送信もされない。受理点より後にキャンセルした場合、
    /// たとえ future が `Ready` を返す前に破棄しても、payload は送信キューに
    /// 積まれているため送信され得る。キャンセル確認と push の間には await が
    /// 無いが、別スレッドから future が破棄される競合は理論上残る。
    ///
    /// # 待機中の driver
    ///
    /// 待機中は、既定のコマンド駆動モードでも driver が受信とタイマーを処理する。
    /// [`Self::enable_background_driver`] を有効にしなくても、ACK の処理と
    /// タイマー発火が進む。
    ///
    /// # エラー
    ///
    /// 待機では解決しない次のエラーは、待たずに [`Error::Protocol`] で返す。
    ///
    /// - ピアが DATAGRAM に対応していない場合
    /// - エンコード後のフレームサイズ (フレームタイプ + Length + payload) が
    ///   ピアの `max_datagram_frame_size` を超える場合 (RFC 9221 Section 3)
    /// - payload が PMTU から求めたペイロード上限を超える場合 (RFC 9000
    ///   Section 14.2)
    ///
    /// payload 単体の上限は [`Self::max_datagram_size`] で取得できる。
    ///
    /// 接続が既に終了している場合は、待たずに [`Error::Connection`] を返す。
    /// 待機中に接続が終了した場合は、待機中の呼び出しをすべて接続終了の型付き
    /// エラー ([`Error::Connection`]) で完了させる。接続終了理由が共有されて
    /// いない場合も正常クローズ ([`ConnectionError::Closed`]) として扱う。
    /// driver の駆動エラーで接続が終了した場合は [`Error::Connection`] の理由が
    /// [`ConnectionError::Internal`]、driver が理由を残さずに停止した場合は
    /// [`Error::Internal`] になる。
    pub async fn send_datagram_wait(&self, data: Vec<u8>) -> Result<(), Error> {
        // 再試行では payload を複製せず共有し、受理時に 1 回だけ Vec へコピーする。
        let data: Arc<[u8]> = data.into();
        loop {
            let (on_block, progress) = oneshot::channel();
            let reply = send_command(&self.tx, |reply| Command::SendDatagramWait {
                data: Arc::clone(&data),
                reply,
                on_block,
            })
            .await?;
            match reply {
                DatagramSendWaitReply::Accepted => return Ok(()),
                DatagramSendWaitReply::Failed(error) => return Err(error),
                // 進捗通知が成功なら空きを確認して再試行し、エラーなら接続終了
                // として返す。通知自体が届かない場合は driver の停止であり、
                // 共有された接続終了理由があればそれを使う。
                DatagramSendWaitReply::Blocked => match progress.await {
                    Ok(Ok(())) => continue,
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return Err(self.tx.send_failure_error()),
                },
            }
        }
    }

    /// DATAGRAM を 1 件受信する (RFC 9221)
    ///
    /// # キャンセルの安全性
    ///
    /// この future をキャンセルしても、driver が取り出した DATAGRAM は失われない。
    /// 次に `receive_datagram` を呼ぶと、キャンセル前に取り出していた DATAGRAM を
    /// 受け取れる。接続が終了した場合でも、共有キューに残った DATAGRAM を返し
    /// 切った後に接続終了のエラーを返す。接続終了理由が共有されている場合は
    /// `Error::Connection` を返し、driver が理由を残さずに停止した場合だけ
    /// `Error::Internal` になる。
    ///
    /// 待機中は、既定のコマンド駆動モードでも driver が受信とタイマーを処理する。
    /// DATAGRAM はロス検出で再送されないため (RFC 9221 Section 5.2)、受信待ちの
    /// 間に受信側のソケットバッファや受信キューの上限に達すると破棄され得る。
    /// 受信キューの上限は [`DatagramConfig::recv_queue_max`](crate::DatagramConfig)
    /// で設定する。上限に達した状態で新しい DATAGRAM を受信すると、最も古い
    /// DATAGRAM を破棄する。破棄回数は `ConnectionStats::datagram_recv_dropped`、
    /// 現在のキュー長は `ConnectionStats::datagram_recv_queue_len` で観測できる。
    ///
    /// 複数のタスクで待つ場合、どの呼び出しが DATAGRAM を受け取るかは共有
    /// キューの取り出し順に依存する。
    pub async fn receive_datagram(&self) -> Result<Vec<u8>, Error> {
        wait_for_shared_result(
            &self.tx,
            |results| results.claim_datagram(),
            |reply, on_block| Command::ReceiveDatagram { reply, on_block },
        )
        .await
    }

    /// 初期パス (Path ID 0) を新しい 4-tuple へ移行する
    ///
    /// RFC 9000 Section 9 の接続移行をアプリケーションから開始する。このメソッドは
    /// 移行先への PATH_CHALLENGE の送信を開始した時点で返り、検証はバックグラウンドで
    /// 進む。成否は [`Self::accept_path_event`] に届く
    /// [`PathEvent::Validated`](crate::PathEvent) (Path ID 0) または
    /// [`PathEvent::ValidationFailed`](crate::PathEvent) で確認する。
    ///
    /// 検証が完了するまでの間は元の 4-tuple で送受信を継続できる。成功時は 4-tuple と
    /// 送信先 CID が新しい値に更新され、IP アドレスが変わる移行では輻輳制御と RTT
    /// 推定がリセットされる (RFC 9000 Section 9.4)。検証に失敗した場合は元の
    /// 4-tuple と輻輳制御の状態を維持する。
    ///
    /// `request.local_addr` が `Some` の場合はそのアドレスを移行先のローカル
    /// アドレスに使う。ポート 0 を指定すると I/O 層が新しいソケットをバインドし、
    /// 実際のポートは OS が選ぶ。移行用のソケットは `SO_REUSEADDR` と
    /// `SO_REUSEPORT` を設定せずに bind するため、既存ソケットの受信範囲と
    /// 重なるアドレスを指定すると [`Error::Io`] を返す。
    /// `request.remote_addr` は変更しない場合は `None` を指定する。両方が
    /// 現在の値と同じ場合はエラーになる。
    ///
    /// ハンドシェイク確定前と、移行の検証中はエラーを返す。ピアが
    /// `disable_active_migration` を通知している場合、ハンドシェイクアドレスへ
    /// 新しいローカルアドレスから移行することはできない
    /// (preferred_address に従って移行済みの場合は除く)。
    ///
    /// 移行先のソケットは移行の開始が受理されてから登録し、受信タスクを起動
    /// する。開始が拒否された場合は新しくバインドしたソケットを解放し、完全一致で
    /// 再利用した既存ソケットとその受信タスクは維持する。
    ///
    /// サーバー側の接続では使用できない。
    pub async fn migrate(&self, request: NewPath) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::Migrate { request, reply }).await?
    }

    /// 新しいパスを開く
    ///
    /// `request.local_addr` に具体的な IP と非 0 ポートを指定した場合、I/O 層は
    /// そのアドレスにバインドしたソケットで新しいパスのパケットを送受信する。
    /// パスは PATH_CHALLENGE / PATH_RESPONSE で検証され、完了は
    /// [`PathEvent::Validated`](crate::PathEvent) で通知される
    /// (RFC 10069 Section 3.1 / RFC 9000 Section 8.2)。
    ///
    /// `None` を指定した側は初期パスのアドレスを継承する。ポート 0 を指定した
    /// 場合は既存のソケット選択に従う。通常は初期ソケットと同じポートになるが、
    /// 同じ IP の追加ソケットが既にある場合はそのポートになる。追加パスのために
    /// 新しいエフェメラルポートを割り当てることはしない。unspecified IP を指定
    /// した場合は宛先アドレスファミリによる既存の選択に従う。これらの場合は
    /// 実際の送信元アドレスが指定値と一致しないことがある。サーバー側の接続では
    /// `open_path` 自体が使用できない (常にエラーになる)。
    ///
    /// IPv4-mapped IPv6 アドレス (`::ffff:a.b.c.d`) は `IPV6_V6ONLY` を立てた
    /// IPv6 ソケットへのバインドになる。Linux では `EINVAL` で失敗するため、
    /// IPv4 のアドレスを指定すること。
    ///
    /// 専用ソケットは `SO_REUSEADDR` と `SO_REUSEPORT` を設定せずに bind する。
    /// wildcard の初期ソケットと同じポートに具体 IP を指定するなど、既存
    /// ソケットの受信範囲と重なる場合はポート共有で回避せず [`Error::Io`] を
    /// 返す。回避するには初期ソケットを具体 IP で bind するか別ポートを使う。
    ///
    /// # エラー
    ///
    /// - 指定アドレスにバインドできない場合は [`Error::Io`] を返し、パスも
    ///   通知も行わない
    /// - 接続が確立していない場合や、transport がパス ID の上限やレート制限で
    ///   パス作成を拒否した場合は [`Error::Protocol`] を返し、新規にバインドした
    ///   ソケットだけを解放する。既存ソケットを再利用した場合は解放しない
    /// - パス作成後の送信 (flush) に失敗した場合はエラーを返し、作成済みの
    ///   パスを best-effort で破棄する。廃棄は
    ///   [`PathEvent::Closed`](crate::PathEvent) として通知されうるが、
    ///   [`PathEvent::Opened`](crate::PathEvent) は通知されない可能性がある。
    ///   パスを廃棄しても、新しくバインドしたソケットと受信タスクは接続の
    ///   終了まで残る
    pub async fn open_path(&self, request: NewPath) -> Result<PathHandle, Error> {
        send_command(&self.tx, |reply| Command::OpenPath { request, reply }).await?
    }

    /// パスを廃棄する
    ///
    /// RFC 10069 Section 3.4 に基づき PATH_ABANDON を送り、
    /// パスを廃棄する。パスを廃棄しても、そのパス専用に用意したソケットは接続の
    /// 終了まで残る。同じローカルアドレスのソケットを他のパスが使っている
    /// 可能性があり、受信タスクを停止する手段も持たないためである。
    pub async fn abandon_path(&self, path: &PathHandle, error_code: u64) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::AbandonPath {
            path: *path,
            error_code,
            reply,
        })
        .await?
    }

    /// 指定パスで使用するピア Connection ID を未使用のものへ切り替える
    ///
    /// RFC 9000 Section 5.1.2 / RFC 10069 Section 3.2.2:
    /// 同じ path ID に紐づく未使用の CID へ切り替える。戻り値は切り替えたか。
    /// 未使用の CID が無い場合は false を返し、multipath がネゴシエーション
    /// 済みなら PATH_CIDS_BLOCKED をピアへ送る。接続は閉じない。
    pub async fn rotate_path_cid(&self, path: &PathHandle) -> Result<bool, Error> {
        send_command(&self.tx, |reply| Command::RotatePathCid {
            path: *path,
            reply,
        })
        .await?
    }

    pub async fn set_path_status(
        &self,
        path: &PathHandle,
        status: PathStatus,
    ) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::SetPathStatus {
            path: *path,
            status,
            reply,
        })
        .await?
    }

    pub async fn set_max_path_id(&self, max_path_id: u32) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::SetMaxPathId {
            max_path_id,
            reply,
        })
        .await?
    }

    pub async fn ping(&self) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::Ping { reply }).await?
    }

    /// 1-RTT 鍵更新を開始する (RFC 9001 Section 6.1)
    ///
    /// ハンドシェイク確認済みで、現在の鍵フェーズで送ったパケットが 1 つ以上
    /// ACK されている必要がある。条件を満たさない場合はエラーを返す。
    /// 更新後のフェーズを確認する最初の ACK を受信した時点から、3 × PTO の
    /// クールダウンが適用される (RFC 9001 Section 6.5)。マルチパス接続では
    /// 全パスの最大 PTO を使う。
    pub async fn update_keys(&self) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::UpdateKeys { reply }).await?
    }

    pub async fn ping_on(&self, path: &PathHandle) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::PingPath { path: *path, reply }).await?
    }

    /// ピアに ACK の送信頻度と遅延を要求する (ACK_FREQUENCY)
    ///
    /// draft-ietf-quic-ack-frequency-14 Section 4:
    /// - `ack_eliciting_threshold`: ACK を送らずに受け取れる ack-eliciting
    ///   パケットの最大数
    /// - `requested_max_ack_delay`: ピアに要求する ACK 遅延の最大値
    /// - `reordering_threshold`: 再順序で即時 ACK を出す閾値
    ///
    /// ピアが `min_ack_delay` を広告していない場合や、要求値が不正な場合は
    /// エラーになる。
    pub async fn send_ack_frequency(
        &self,
        path: &PathHandle,
        ack_eliciting_threshold: u64,
        requested_max_ack_delay: std::time::Duration,
        reordering_threshold: u64,
    ) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::SendAckFrequency {
            path: *path,
            ack_eliciting_threshold,
            requested_max_ack_delay,
            reordering_threshold,
            reply,
        })
        .await?
    }

    /// ピアに即時 ACK を要求する (IMMEDIATE_ACK)
    ///
    /// draft-ietf-quic-ack-frequency-14 Section 5。
    /// ピアが `min_ack_delay` を広告している場合に送信できる。
    pub async fn send_immediate_ack(&self, path: &PathHandle) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::SendImmediateAck {
            path: *path,
            reply,
        })
        .await?
    }

    /// transport-level の CONNECTION_CLOSE (type 0x1c) を送って接続を閉じる
    ///
    /// RFC 9000 Section 10.2.3 / Section 19.19 に基づき Closing 状態へ遷移する。
    /// `error_code` に 0 を渡すと NO_ERROR (RFC 9000 Section 20.1) による
    /// 正常クローズになる。
    /// ハンドシェイク確定前は、保持している Initial / Handshake / 1-RTT のうち
    /// 利用可能な保護レベルへコアレスして送る。確定後は 1-RTT のみで送る。
    ///
    /// すでに閉じ始めている (Closing / Draining / Closed) 場合はフレームを送らずに
    /// `Ok(())` を返す。すでにクローズ理由が記録されている場合は上書きしない
    /// (最初の close を優先する)。ただし `error_code` が 62 ビット varint に
    /// 収まらない場合は、接続状態に関わらずエラーを返し、接続状態と
    /// `close_reason` は変更しない。
    ///
    /// アプリケーションプロトコルのエラーコードを通知する場合は
    /// [`Self::close_application`] を使う。
    pub async fn close(&self, error_code: u64, reason: &[u8]) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::Close {
            application: false,
            error_code,
            reason: reason.to_vec(),
            reply,
        })
        .await?
    }

    /// アプリケーションエラーで接続を閉じる
    ///
    /// RFC 9000 Section 19.19 の application-level CONNECTION_CLOSE (type 0x1d) を
    /// 送って Closing 状態へ遷移する。`error_code` は MOQT / HTTP/3 などの
    /// アプリケーションプロトコルが定義する code space の値であり、
    /// transport error の code space (RFC 9000 Section 20.1) とは区別される。
    ///
    /// この呼び出しで新たにクローズを開始した場合は、成功後に `close_reason` が
    /// `ConnectionError::Application` (error code 0 の場合は
    /// `ConnectionError::Closed`) になる。すでにクローズ理由が記録されている場合は
    /// それを保持する。
    ///
    /// ハンドシェイク確定前は、1-RTT 鍵を保持していれば 1-RTT に 0x1d を送り、
    /// 保持している Initial / Handshake 空間には RFC 9000 Section 10.2.3 に従って
    /// 0x1c へ変換したフレーム (Error Code は APPLICATION_ERROR、Frame Type は 0、
    /// Reason Phrase は空) を送る。確定後は 1-RTT のみで送る。
    /// そのためハンドシェイク確定前の application close は、1-RTT を復号できない
    /// ピアには Initial / Handshake の 0x1c (APPLICATION_ERROR) として観測される。
    ///
    /// すでに閉じ始めている (Closing / Draining / Closed) 場合はフレームを送らずに
    /// `Ok(())` を返す。すでにクローズ理由が記録されている場合は上書きしない
    /// (最初の close を優先する)。
    ///
    /// `error_code` が 62 ビット varint に収まらない場合はエラーになり、接続状態と
    /// `close_reason` は変更しない。
    pub async fn close_application(&self, error_code: u64, reason: &[u8]) -> Result<(), Error> {
        send_command(&self.tx, |reply| Command::Close {
            application: true,
            error_code,
            reason: reason.to_vec(),
            reply,
        })
        .await?
    }

    // --- poll_* バリアント ---

    /// `accept_bidirectional_stream` の poll バリアント
    ///
    /// 呼び出しごとに一時的な future を作って 1 回だけ poll する。`Pending` を
    /// 返しても受理結果は失われず、driver を進めてから再度 poll すると、先に
    /// 受理していたストリームを `Ready` で受け取れる。
    ///
    /// `Pending` を返したとき、この呼び出しが作った一時 future は破棄されるため、
    /// 呼び出し側の waker は保持されない。呼び出し側が `drive()` などで接続を
    /// 進めてから再度 poll する必要がある。
    pub fn poll_accept_bidirectional_stream(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<BidirectionalStream, Error>> {
        let mut fut = Box::pin(self.accept_bidirectional_stream());
        fut.as_mut().poll(cx)
    }

    /// `accept_receive_stream` の poll バリアント
    ///
    /// `Pending` を返しても受理結果は失われず、driver を進めてから再度 poll
    /// すると、先に受理していたストリームを `Ready` で受け取れる。
    ///
    /// `Pending` を返したとき、この呼び出しが作った一時 future は破棄されるため、
    /// 呼び出し側の waker は保持されない。呼び出し側が `drive()` などで接続を
    /// 進めてから再度 poll する必要がある。
    pub fn poll_accept_receive_stream(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ReceiveStream, Error>> {
        let mut fut = Box::pin(self.accept_receive_stream());
        fut.as_mut().poll(cx)
    }

    /// `accept_stream` の poll バリアント
    ///
    /// `Pending` を返しても受理結果は失われず、driver を進めてから再度 poll
    /// すると、先に受理していたストリームを `Ready` で受け取れる。
    ///
    /// `Pending` を返したとき、この呼び出しが作った一時 future は破棄されるため、
    /// 呼び出し側の waker は保持されない。呼び出し側が `drive()` などで接続を
    /// 進めてから再度 poll する必要がある。
    pub fn poll_accept_stream(&self, cx: &mut Context<'_>) -> Poll<Result<PeerStream, Error>> {
        let mut fut = Box::pin(self.accept_stream());
        fut.as_mut().poll(cx)
    }

    /// `open_bidirectional_stream` の poll バリアント
    pub fn poll_open_bidirectional_stream(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<BidirectionalStream, Error>> {
        let mut fut = Box::pin(self.open_bidirectional_stream());
        fut.as_mut().poll(cx)
    }

    /// `open_send_stream` の poll バリアント
    pub fn poll_open_send_stream(&self, cx: &mut Context<'_>) -> Poll<Result<SendStream, Error>> {
        let mut fut = Box::pin(self.open_send_stream());
        fut.as_mut().poll(cx)
    }

    /// `send_datagram` の poll バリアント
    ///
    /// 破棄方針の送信 API を 1 回だけ poll する。送信キューの空きを待つ方針を
    /// 使う場合は [`Self::send_datagram_wait`] を使う。待機は空きができるまで
    /// 完了しないため、poll で扱うと待機のたびに future を作り直すことになる。
    pub fn poll_send_datagram(
        &self,
        data: Vec<u8>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Error>> {
        let mut fut = Box::pin(self.send_datagram(data));
        fut.as_mut().poll(cx)
    }

    /// `receive_datagram` の poll バリアント
    ///
    /// `Pending` を返しても受信結果は失われず、driver を進めてから再度 poll
    /// すると、先に受信していた DATAGRAM を `Ready` で受け取れる。
    ///
    /// `Pending` を返したとき、この呼び出しが作った一時 future は破棄されるため、
    /// 呼び出し側の waker は保持されない。呼び出し側が `drive()` などで接続を
    /// 進めてから再度 poll する必要がある。
    pub fn poll_receive_datagram(&self, cx: &mut Context<'_>) -> Poll<Result<Vec<u8>, Error>> {
        let mut fut = Box::pin(self.receive_datagram());
        fut.as_mut().poll(cx)
    }
}

#[cfg(test)]
mod tests;
