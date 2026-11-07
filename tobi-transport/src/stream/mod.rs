// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! ストリーム管理 (RFC 9000 Section 2, 3)
//!
//! 双方向/単方向ストリームの開閉、状態マシン、送受信バッファ、
//! フロー制御を管理する。

pub mod buffer;
pub mod state;

use std::collections::{HashMap, VecDeque};

use tobi_core::error::{Error, TransportErrorCode};
use tobi_core::frame;
use tobi_core::role::Role;
use tobi_core::transport_params::TransportParams;

use buffer::{RecvBuffer, RetransmitInfo, RetxMeta, SendBuffer};
use state::{RecvState, SendState};
use tobi_core::varint::VarInt;

/// ストリームタイプ (RFC 9000 Section 2.1)
///
/// ストリーム ID の下位 2 ビットで識別される。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    ClientBidi = 0x00,
    ServerBidi = 0x01,
    ClientUni = 0x02,
    ServerUni = 0x03,
}

impl StreamType {
    /// ストリーム ID からストリームタイプを取得する
    pub fn from_id(id: u64) -> Self {
        match id & 0x03 {
            0x00 => Self::ClientBidi,
            0x01 => Self::ServerBidi,
            0x02 => Self::ClientUni,
            0x03 => Self::ServerUni,
            _ => unreachable!(),
        }
    }

    /// 双方向ストリームか
    pub fn is_bidirectional(self) -> bool {
        matches!(self, Self::ClientBidi | Self::ServerBidi)
    }

    /// 単方向ストリームか
    pub fn is_unidirectional(self) -> bool {
        !self.is_bidirectional()
    }

    /// クライアント起動か
    pub fn is_client_initiated(self) -> bool {
        matches!(self, Self::ClientBidi | Self::ClientUni)
    }

    /// サーバー起動か
    pub fn is_server_initiated(self) -> bool {
        !self.is_client_initiated()
    }
}

/// ストリーム ID からシーケンス番号を取得する
pub fn stream_sequence(id: u64) -> u64 {
    id >> 2
}

/// ストリームタイプとシーケンス番号からストリーム ID を生成する
pub fn make_stream_id(stream_type: StreamType, sequence: u64) -> u64 {
    stream_type as u64 + 4 * sequence
}

/// フレームが対象とするストリーム ID を返す
///
/// GC 済みストリーム宛の送信待ちフレームを検出するために使う。
fn frame_stream_id(frame: &frame::Frame) -> Option<u64> {
    match frame {
        frame::Frame::Stream(f) => Some(f.stream_id.as_u64()),
        frame::Frame::ResetStream(f) => Some(f.stream_id.as_u64()),
        frame::Frame::ResetStreamAt(f) => Some(f.stream_id.as_u64()),
        frame::Frame::StopSending(f) => Some(f.stream_id.as_u64()),
        frame::Frame::MaxStreamData(f) => Some(f.stream_id.as_u64()),
        frame::Frame::StreamDataBlocked(f) => Some(f.stream_id.as_u64()),
        _ => None,
    }
}

/// クライアント起動のストリームか
pub fn is_client_initiated(id: u64) -> bool {
    id & 0x01 == 0
}

/// 双方向ストリームか
pub fn is_bidirectional(id: u64) -> bool {
    id & 0x02 == 0
}

/// 個別ストリーム
#[derive(Debug)]
pub struct Stream {
    pub id: u64,
    /// 送信状態 (None: 受信専用ストリーム)
    pub send_state: Option<SendState>,
    /// 受信状態 (None: 送信専用ストリーム)
    pub recv_state: Option<RecvState>,
    /// 送信バッファ
    pub send_buf: Option<SendBuffer>,
    /// 受信バッファ
    pub recv_buf: Option<RecvBuffer>,
    /// ピアが許可した送信上限 (絶対バイトオフセット)
    pub send_max_data: u64,
    /// ローカルが許可した受信上限 (絶対バイトオフセット)
    pub recv_max_data: u64,
    /// 受信上限の初期値 (クレジット更新の閾値計算用)
    recv_max_data_initial: u64,
    /// 最後に STREAM_DATA_BLOCKED を送信した上限値 (重複送信防止)
    last_stream_data_blocked_at: Option<u64>,

    // --- 送信側の終端遷移判定 (RFC 9000 Section 3.1) ---
    /// パケット化済みで I/O へまだ渡していないフレーム数
    send_queued_count: u32,

    // --- RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset-11) ---
    /// 送信側: RESET_STREAM_AT で宣言した reliable_size
    pub reset_at_reliable_size: Option<u64>,
    /// 送信側: RESET_STREAM_AT の error_code
    pub reset_at_error_code: Option<u64>,
    /// 送信側: RESET_STREAM_AT の final_size
    pub reset_at_final_size: Option<u64>,
    /// 送信側: 現在の RELIABLE_SIZE を持つ RESET_STREAM_AT が送信キューに残っているか
    ///
    /// 送信済みで ACK 待ちの状態と区別する。Data Recvd への遷移は、現在の
    /// Reliable Size を持つフレームが送信済みかつ ACK 済みであることを要求する
    /// (draft-ietf-quic-reliable-stream-reset-11 Section 5.3)。
    pub reset_at_frame_queued: bool,
    /// 送信側: 現在のリセット情報 (RESET_STREAM / RESET_STREAM_AT) が ACK されたか
    ///
    /// RESET_STREAM_AT では現在の最小 Reliable Size を持つフレームの ACK で
    /// 真になる (draft-ietf-quic-reliable-stream-reset-11 Section 5.3)。
    /// RESET_STREAM は Reliable Size 0 相当であるため、ResetSent 中の ACK で
    /// 真になる。Data Recvd / Reset Recvd への遷移条件に使う。
    pub reset_at_frame_acked: bool,
    /// 受信側: ピアが宣言した reliable_size (減少のみ許可)
    pub recv_reliable_size: Option<u64>,
    /// 受信側: RESET_STREAM_AT 由来の Reliable Size
    ///
    /// `RESET_STREAM` は Reliable Size 0 相当であり `recv_reliable_size` が
    /// `Some(0)` になるため、`recv_reliable_size` だけでは RESET_STREAM_AT
    /// 由来かを区別できない (draft-ietf-quic-reliable-stream-reset-11
    /// Section 4 / Section 5)。このフィールドは有効な RESET_STREAM_AT を
    /// 受信したときだけ設定し、RESET_STREAM を受信したときは `None` に戻す。
    /// 増加扱いで無視するフレーム、重複フレーム、終端後のフレームでは更新しない。
    pub recv_reset_at_reliable_size: Option<u64>,
    /// 受信側: ピアの RESET_STREAM_AT error_code
    pub recv_reset_error_code: Option<u64>,
    /// 受信側: RESET_STREAM_AT のリセットイベントを通知済みか
    ///
    /// 保証データの到着前には通知せず、Data Recvd へ遷移した時点で 1 回だけ
    /// 通知する (draft-ietf-quic-reliable-stream-reset-11 Section 1 / 5.3)。
    pub recv_reset_event_emitted: bool,
    /// 送信側: ピアが STOP_SENDING で通知した error_code
    pub peer_stop_sending_error_code: Option<u64>,
}

impl Stream {
    /// ローカルが起動した双方向ストリームを作成する
    fn new_local_bidi(id: u64, peer_max_stream_data: u64, local_max_stream_data: u64) -> Self {
        Self {
            id,
            send_state: Some(SendState::Ready),
            recv_state: Some(RecvState::Recv),
            send_buf: Some(SendBuffer::new()),
            recv_buf: Some(RecvBuffer::new()),
            send_max_data: peer_max_stream_data,
            recv_max_data: local_max_stream_data,
            recv_max_data_initial: local_max_stream_data,
            last_stream_data_blocked_at: None,
            send_queued_count: 0,
            reset_at_reliable_size: None,
            reset_at_error_code: None,
            reset_at_final_size: None,
            reset_at_frame_queued: false,
            reset_at_frame_acked: false,
            recv_reliable_size: None,
            recv_reset_at_reliable_size: None,
            recv_reset_error_code: None,
            recv_reset_event_emitted: false,
            peer_stop_sending_error_code: None,
        }
    }

    /// ローカルが起動した単方向ストリームを作成する
    fn new_local_uni(id: u64, peer_max_stream_data: u64) -> Self {
        Self {
            id,
            send_state: Some(SendState::Ready),
            recv_state: None,
            send_buf: Some(SendBuffer::new()),
            recv_buf: None,
            send_max_data: peer_max_stream_data,
            recv_max_data: 0,
            recv_max_data_initial: 0,
            last_stream_data_blocked_at: None,
            send_queued_count: 0,
            reset_at_reliable_size: None,
            reset_at_error_code: None,
            reset_at_final_size: None,
            reset_at_frame_queued: false,
            reset_at_frame_acked: false,
            recv_reliable_size: None,
            recv_reset_at_reliable_size: None,
            recv_reset_error_code: None,
            recv_reset_event_emitted: false,
            peer_stop_sending_error_code: None,
        }
    }

    /// ピアが起動した双方向ストリームを作成する
    fn new_peer_bidi(id: u64, peer_max_stream_data: u64, local_max_stream_data: u64) -> Self {
        Self {
            id,
            send_state: Some(SendState::Ready),
            recv_state: Some(RecvState::Recv),
            send_buf: Some(SendBuffer::new()),
            recv_buf: Some(RecvBuffer::new()),
            send_max_data: peer_max_stream_data,
            recv_max_data: local_max_stream_data,
            recv_max_data_initial: local_max_stream_data,
            last_stream_data_blocked_at: None,
            send_queued_count: 0,
            reset_at_reliable_size: None,
            reset_at_error_code: None,
            reset_at_final_size: None,
            reset_at_frame_queued: false,
            reset_at_frame_acked: false,
            recv_reliable_size: None,
            recv_reset_at_reliable_size: None,
            recv_reset_error_code: None,
            recv_reset_event_emitted: false,
            peer_stop_sending_error_code: None,
        }
    }

    /// ピアが起動した単方向ストリームを作成する
    fn new_peer_uni(id: u64, local_max_stream_data: u64) -> Self {
        Self {
            id,
            send_state: None,
            recv_state: Some(RecvState::Recv),
            send_buf: None,
            recv_buf: Some(RecvBuffer::new()),
            send_max_data: 0,
            recv_max_data: local_max_stream_data,
            recv_max_data_initial: local_max_stream_data,
            last_stream_data_blocked_at: None,
            send_queued_count: 0,
            reset_at_reliable_size: None,
            reset_at_error_code: None,
            reset_at_final_size: None,
            reset_at_frame_queued: false,
            reset_at_frame_acked: false,
            recv_reliable_size: None,
            recv_reset_at_reliable_size: None,
            recv_reset_error_code: None,
            recv_reset_event_emitted: false,
            peer_stop_sending_error_code: None,
        }
    }

    /// 送信と受信の両方が終端状態か (ストリーム完了)
    pub fn is_finished(&self) -> bool {
        let send_done = self.send_state.is_none_or(|s| s.is_terminal());
        let recv_done = self.recv_state.is_none_or(|s| s.is_terminal());
        send_done && recv_done
    }
}

/// ストリームイベント
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    /// 新しいストリームがピアから開かれた
    NewStream { stream_id: u64 },
    /// ストリームにデータが到着し、読み取り可能になった
    StreamReadable { stream_id: u64 },
    /// ストリームの送信フロー制御が更新され、書き込み可能になった
    StreamWritable { stream_id: u64 },
    /// ピアがストリームをリセットした
    StreamReset { stream_id: u64, error_code: u64 },
    /// ピアが STOP_SENDING を送信した
    StreamStopSending { stream_id: u64, error_code: u64 },
}

/// ストリームマネージャ
///
/// 接続内の全ストリームを管理する。
/// PathManager パターンに従い、Connection から独立した構造体。
#[derive(Debug)]
pub struct StreamManager {
    /// 全ストリーム
    streams: HashMap<u64, Stream>,
    /// 新規データを最後にフレーム化したストリーム。次回はその次から巡回する。
    last_new_data_stream: Option<u64>,
    /// ストリームタイプごとの GC 済み下限 ID
    ///
    /// この値未満のストリーム ID は終端済みで削除されている。遅延して届いた
    /// フレームは再作成せずに無視する (RFC 9000 Section 3)。
    gc_watermarks: [u64; 4],
    /// ロール
    role: Role,

    // --- ストリーム ID シーケンス ---
    /// ローカル起動の双方向ストリームの次のシーケンス番号
    next_local_bidi_seq: u64,
    /// ローカル起動の単方向ストリームの次のシーケンス番号
    next_local_uni_seq: u64,
    /// ピア起動の双方向ストリームの次のシーケンス番号
    next_peer_bidi_seq: u64,
    /// ピア起動の単方向ストリームの次のシーケンス番号
    next_peer_uni_seq: u64,

    // --- ストリーム数制限 ---
    /// ローカルが許可するピア起動の双方向ストリーム数上限
    local_max_streams_bidi: u64,
    /// ローカルが許可するピア起動の単方向ストリーム数上限
    local_max_streams_uni: u64,
    /// ピアが許可するローカル起動の双方向ストリーム数上限
    peer_max_streams_bidi: u64,
    /// ピアが許可するローカル起動の単方向ストリーム数上限
    peer_max_streams_uni: u64,

    // --- 接続レベルフロー制御 ---
    /// ピアが許可した送信上限 (接続レベル)
    pub send_max_data: u64,
    /// 全ストリームで送信したバイト数の合計
    send_data_total: u64,
    /// ローカルが許可した受信上限 (接続レベル)
    recv_max_data: u64,
    /// 全ストリームで受信したバイト数の合計
    recv_data_total: u64,
    /// 全ストリームでアプリケーションが消費 (または消費不能として信用付与) した
    /// バイト数の合計。接続レベルウィンドウ (MAX_DATA) の前進基準に使う。
    /// 不変条件として `consumed_total <= recv_data_total <= recv_max_data` を保つ。
    consumed_total: u64,

    // --- ストリームごとの初期フロー制御上限 ---
    /// ローカルが許可する双方向ストリーム (ローカル起動) のデータ上限
    local_initial_max_stream_data_bidi_local: u64,
    /// ローカルが許可する双方向ストリーム (ピア起動) のデータ上限
    local_initial_max_stream_data_bidi_remote: u64,
    /// ローカルが許可する単方向ストリームのデータ上限
    local_initial_max_stream_data_uni: u64,
    /// ピアが許可する双方向ストリーム (ローカル起動) のデータ上限
    peer_initial_max_stream_data_bidi_local: u64,
    /// ピアが許可する双方向ストリーム (ピア起動) のデータ上限
    peer_initial_max_stream_data_bidi_remote: u64,
    /// ピアが許可する単方向ストリームのデータ上限
    peer_initial_max_stream_data_uni: u64,

    // --- 受信クレジット自動更新用 ---
    /// 接続レベル受信上限の初期値 (閾値計算用)
    recv_max_data_initial: u64,

    // --- ブロック通知の重複送信防止 ---
    /// 最後に DATA_BLOCKED を送信した上限値
    last_data_blocked_at: Option<u64>,
    /// 最後に STREAMS_BLOCKED (bidi) を送信した上限値
    last_streams_blocked_bidi_at: Option<u64>,
    /// 最後に STREAMS_BLOCKED (uni) を送信した上限値
    last_streams_blocked_uni_at: Option<u64>,

    // --- RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset-11) ---
    /// ピアが RESET_STREAM_AT をサポートするか
    peer_supports_reset_stream_at: bool,

    // --- 送信待ちフレーム ---
    pub pending_frames: VecDeque<frame::Frame>,

    // --- イベントキュー ---
    /// アプリケーションへ通知するストリームイベント
    ///
    /// `Connection` がフレーム処理のたびに `poll_event` で取り出して
    /// `ConnectionEvent` へ変換する。イベントを保持するのは次の drain までであり、
    /// 1 フレームで生成される件数は `local_max_streams_*` で抑えられる。
    events: VecDeque<StreamEvent>,
}

impl StreamManager {
    /// 新しい StreamManager を作成する
    pub fn new(role: Role, local_params: &TransportParams) -> Self {
        Self {
            streams: HashMap::new(),
            last_new_data_stream: None,
            // 各タイプの最初のストリーム ID (下位 2 ビットがタイプ)
            gc_watermarks: [0, 1, 2, 3],
            role,
            next_local_bidi_seq: 0,
            next_local_uni_seq: 0,
            next_peer_bidi_seq: 0,
            next_peer_uni_seq: 0,
            local_max_streams_bidi: local_params.initial_max_streams_bidi,
            local_max_streams_uni: local_params.initial_max_streams_uni,
            peer_max_streams_bidi: 0,
            peer_max_streams_uni: 0,
            send_max_data: 0,
            send_data_total: 0,
            recv_max_data: local_params.initial_max_data,
            recv_data_total: 0,
            consumed_total: 0,
            local_initial_max_stream_data_bidi_local: local_params
                .initial_max_stream_data_bidi_local,
            local_initial_max_stream_data_bidi_remote: local_params
                .initial_max_stream_data_bidi_remote,
            local_initial_max_stream_data_uni: local_params.initial_max_stream_data_uni,
            peer_initial_max_stream_data_bidi_local: 0,
            peer_initial_max_stream_data_bidi_remote: 0,
            peer_initial_max_stream_data_uni: 0,
            recv_max_data_initial: local_params.initial_max_data,
            last_data_blocked_at: None,
            last_streams_blocked_bidi_at: None,
            last_streams_blocked_uni_at: None,
            peer_supports_reset_stream_at: false,
            pending_frames: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// ピアのトランスポートパラメータを適用する
    pub fn apply_peer_params(&mut self, peer_params: &TransportParams) {
        self.peer_max_streams_bidi = peer_params.initial_max_streams_bidi;
        self.peer_max_streams_uni = peer_params.initial_max_streams_uni;
        self.send_max_data = peer_params.initial_max_data;
        self.peer_initial_max_stream_data_bidi_local =
            peer_params.initial_max_stream_data_bidi_local;
        self.peer_initial_max_stream_data_bidi_remote =
            peer_params.initial_max_stream_data_bidi_remote;
        self.peer_initial_max_stream_data_uni = peer_params.initial_max_stream_data_uni;
        self.peer_supports_reset_stream_at = peer_params.reset_stream_at;

        // Handshake 前後に生成済みの stream にも、確定した peer transport parameter
        // を反映する。これをしないと、peer params 適用前に作られた stream の
        // send_max_data が 0 のまま残り、受信はできても送信できない。
        for (&stream_id, stream) in &mut self.streams {
            if stream.send_state.is_none() {
                continue;
            }

            let stream_type = StreamType::from_id(stream_id);
            let is_local_initiated = match self.role {
                Role::Client => stream_type.is_client_initiated(),
                Role::Server => stream_type.is_server_initiated(),
            };

            // 送信側を持つストリームだけがここに残る。上のループ先頭で
            // `send_state.is_none()` を除外しており、送信側を持たないのは
            // ピア起動の単方向ストリームだけである (受信専用)。
            stream.send_max_data = match (stream_type.is_bidirectional(), is_local_initiated) {
                (true, true) => self.peer_initial_max_stream_data_bidi_remote,
                (true, false) => self.peer_initial_max_stream_data_bidi_local,
                // 送信側を持つ単方向ストリームはローカル起動のみ
                (false, _) => self.peer_initial_max_stream_data_uni,
            };
        }
    }

    /// ピアが `reset_stream_at` transport parameter を広告したかを返す
    ///
    /// 0-RTT では前回セッションの記憶値、ハンドシェイク完了後は確定値になる。
    pub fn peer_supports_reset_stream_at(&self) -> bool {
        self.peer_supports_reset_stream_at
    }

    /// イベントを取り出す
    pub fn poll_event(&mut self) -> Option<StreamEvent> {
        self.events.pop_front()
    }

    /// 終端済みストリームを削除する
    ///
    /// ストリーム ID はタイプごとに昇順で作成されるため、下限 ID から順に
    /// 「終端済みで、未消費のイベントも送信待ちフレームも無い」ものを削除し、
    /// 下限を進める。削除済み ID は `gc_watermarks` で識別し、遅延フレームを
    /// 再作成しない。
    ///
    /// `conn_event_pending` は Connection 側のイベントキューにそのストリームの
    /// イベントが残っているかを返す。イベントを消費する前に削除すると、
    /// アプリケーションが終端やデータ到着を観測できなくなる。
    /// 下限 ID のストリームが未終端の間は、それより後ろの終端済みストリームは
    /// 削除されない。保持量は `initial_max_streams_*` で許可したストリーム数と
    /// 各ストリームの受信ウィンドウの積で上限が決まる。
    pub fn gc_finished_streams<F>(&mut self, conn_event_pending: F)
    where
        F: Fn(u64) -> bool,
    {
        loop {
            let mut advanced = false;
            for index in 0..4 {
                let id = self.gc_watermarks[index];
                let removable = match self.streams.get(&id) {
                    Some(stream) => {
                        stream.is_finished()
                            && !self.stream_has_pending_event(id)
                            && !conn_event_pending(id)
                            && !self.stream_has_pending_frame(id)
                    }
                    None => {
                        // まだ作成されていない ID に達したら、そのタイプの GC は止める。
                        // 作成済みなら削除済みなので下限を進める。
                        if !self.stream_ever_created(id) {
                            continue;
                        }
                        true
                    }
                };
                if removable {
                    self.streams.remove(&id);
                    self.gc_watermarks[index] = id + 4;
                    advanced = true;
                }
            }
            if !advanced {
                break;
            }
        }
    }

    /// 指定 ID のストリームが現在保持されているか
    pub fn contains_stream(&self, stream_id: u64) -> bool {
        self.streams.contains_key(&stream_id)
    }

    /// 保持しているストリーム数
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// 指定 ID のストリームが GC 済みか
    ///
    /// true の場合、そのストリーム宛の遅延フレームは無視する。
    pub fn is_gc_closed(&self, stream_id: u64) -> bool {
        stream_id < self.gc_watermarks[(stream_id & 0x03) as usize]
    }

    /// 指定 ID のストリームがこれまでに作成されたか
    fn stream_ever_created(&self, stream_id: u64) -> bool {
        let stream_type = StreamType::from_id(stream_id);
        let seq = stream_sequence(stream_id);
        let is_local = match self.role {
            Role::Client => stream_type.is_client_initiated(),
            Role::Server => stream_type.is_server_initiated(),
        };
        let next_seq = if is_local {
            if stream_type.is_bidirectional() {
                self.next_local_bidi_seq
            } else {
                self.next_local_uni_seq
            }
        } else if stream_type.is_bidirectional() {
            self.next_peer_bidi_seq
        } else {
            self.next_peer_uni_seq
        };
        seq < next_seq
    }

    /// 指定 ID のストリームのイベントが未消費で残っているか
    fn stream_has_pending_event(&self, stream_id: u64) -> bool {
        self.events.iter().any(|event| match event {
            StreamEvent::NewStream { stream_id: id }
            | StreamEvent::StreamReadable { stream_id: id }
            | StreamEvent::StreamWritable { stream_id: id }
            | StreamEvent::StreamReset { stream_id: id, .. }
            | StreamEvent::StreamStopSending { stream_id: id, .. } => *id == stream_id,
        })
    }

    /// 指定 ID のストリームの送信待ちフレームが残っているか
    fn stream_has_pending_frame(&self, stream_id: u64) -> bool {
        self.pending_frames
            .iter()
            .any(|frame| frame_stream_id(frame) == Some(stream_id))
    }

    // --- ストリーム開閉 ---

    /// ロストした DATA_BLOCKED を現在の上限で再送待ちへ戻す
    ///
    /// RFC 9000 Section 13.3: 最新の DATA_BLOCKED を含むパケットがロストした
    /// 場合、まだブロック中なら現在の上限値を含む新しいフレームを送る。
    /// ブロックが解消していれば再送しない。戻り値は再送待ちへ積んだかどうか。
    pub(crate) fn requeue_data_blocked(&mut self) -> bool {
        if self.send_data_total < self.send_max_data {
            return false;
        }
        let limit = self.send_max_data;
        self.last_data_blocked_at = Some(limit);
        self.pending_frames.push_back(frame::Frame::DataBlocked(
            frame::data_blocked::DataBlocked {
                maximum_data: VarInt::new(limit).expect("value fits in 62-bit varint"),
            },
        ));
        true
    }

    /// ロストした STREAM_DATA_BLOCKED を現在の上限で再送待ちへ戻す
    ///
    /// 対象ストリームが存在しない場合、送信が完了している場合、または
    /// 現在の上限に達していない場合は再送しない (RFC 9000 Section 13.3)。
    pub(crate) fn requeue_stream_data_blocked(&mut self, stream_id: u64) -> bool {
        if self.send_finished(stream_id) {
            return false;
        }
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return false;
        };
        let Some(send_buf) = stream.send_buf.as_ref() else {
            return false;
        };
        if send_buf.write_offset() < stream.send_max_data {
            return false;
        }
        let limit = stream.send_max_data;
        stream.last_stream_data_blocked_at = Some(limit);
        self.pending_frames
            .push_back(frame::Frame::StreamDataBlocked(
                frame::stream_data_blocked::StreamDataBlocked {
                    stream_id: VarInt::new(stream_id).expect("value fits in 62-bit varint"),
                    maximum_stream_data: VarInt::new(limit).expect("value fits in 62-bit varint"),
                },
            ));
        true
    }

    /// ロストした STREAMS_BLOCKED を現在の上限で再送待ちへ戻す
    ///
    /// 残枠がある場合は再送しない (RFC 9000 Section 13.3)。
    pub(crate) fn requeue_streams_blocked(&mut self, bidirectional: bool) -> bool {
        let remaining = if bidirectional {
            self.remaining_bidi_streams()
        } else {
            self.remaining_uni_streams()
        };
        if remaining > 0 {
            return false;
        }
        let limit = if bidirectional {
            self.last_streams_blocked_bidi_at = Some(self.peer_max_streams_bidi);
            self.peer_max_streams_bidi
        } else {
            self.last_streams_blocked_uni_at = Some(self.peer_max_streams_uni);
            self.peer_max_streams_uni
        };
        self.pending_frames.push_back(frame::Frame::StreamsBlocked(
            frame::streams_blocked::StreamsBlocked {
                bidirectional,
                maximum_streams: VarInt::new(limit).expect("value fits in 62-bit varint"),
            },
        ));
        true
    }

    /// ピアが許可した双方向ストリームの残枠を返す
    ///
    /// ピアの累積許可数から、ローカルが既に開いた数を引いた値を返す。ピアの
    /// 許可数は接続の生存期間における累積値であり、ストリームを閉じても残枠は
    /// 戻らない (RFC 9000 Section 19.11)。ピアからより大きい MAX_STREAMS を
    /// 受信すると増える。
    ///
    /// 返り値は参照時点の値であり、後続の [`Self::open_bidi`] に対する予約では
    /// ない。同じ値を参照した後に別の呼び出しがストリームを開くと、残枠は
    /// その分だけ減る。
    pub fn remaining_bidi_streams(&self) -> u64 {
        self.peer_max_streams_bidi
            .saturating_sub(self.next_local_bidi_seq)
    }

    /// ピアが許可した単方向ストリームの残枠を返す
    ///
    /// [`Self::remaining_bidi_streams`] の単方向版。残枠の意味と、返り値が
    /// 参照時点の値であることは同じ。
    pub fn remaining_uni_streams(&self) -> u64 {
        self.peer_max_streams_uni
            .saturating_sub(self.next_local_uni_seq)
    }

    /// ピアが起動できる双方向ストリームの累積上限を引き上げる
    ///
    /// ピアへ送る MAX_STREAMS を送信待ちフレームに積む。現在の上限以下の値は
    /// 広告しても効果がないため無視する (RFC 9000 Section 4.6 / Section 19.11)。
    /// その場合も `Ok` を返し、フレームを送らない。現在の上限は
    /// [`Self::local_max_streams_bidi`] で取得できる。
    ///
    /// 2^60 を超える値はストリーム ID を表現できないため `InvalidData` を返す
    /// (RFC 9000 Section 19.11)。
    pub fn set_local_max_streams_bidi(&mut self, maximum_streams: u64) -> Result<(), Error> {
        self.set_local_max_streams(maximum_streams, true)
    }

    /// ピアが起動できる単方向ストリームの累積上限を引き上げる
    ///
    /// [`Self::set_local_max_streams_bidi`] の単方向版。現在の上限以下の値を
    /// 無視して `Ok` を返す点も同じ。
    pub fn set_local_max_streams_uni(&mut self, maximum_streams: u64) -> Result<(), Error> {
        self.set_local_max_streams(maximum_streams, false)
    }

    /// ピアが起動できるストリームの累積上限を引き上げる
    ///
    /// 双方向と単方向で処理が同じため、公開ラッパーから共通化している。
    /// `bidirectional` は引き上げる上限の種別を表す。
    fn set_local_max_streams(
        &mut self,
        maximum_streams: u64,
        bidirectional: bool,
    ) -> Result<(), Error> {
        let stream_type = if bidirectional {
            "bidirectional"
        } else {
            "unidirectional"
        };
        if maximum_streams > (1u64 << 60) {
            return Err(Error::InvalidData(format!(
                "max streams {stream_type} {maximum_streams} exceeds 2^60"
            )));
        }
        let current = if bidirectional {
            self.local_max_streams_bidi
        } else {
            self.local_max_streams_uni
        };
        if maximum_streams <= current {
            return Ok(());
        }
        if bidirectional {
            self.local_max_streams_bidi = maximum_streams;
        } else {
            self.local_max_streams_uni = maximum_streams;
        }
        self.pending_frames
            .push_back(frame::Frame::MaxStreams(frame::max_streams::MaxStreams {
                bidirectional,
                maximum_streams: VarInt::new(maximum_streams).expect("value fits in 62-bit varint"),
            }));
        Ok(())
    }

    /// 双方向ストリームを開く
    ///
    /// ピアが許可した上限に達している場合は STREAMS_BLOCKED を送信待ちに積み、
    /// [`Error::StreamLimitReached`] を返す。これは接続を閉じるエラーではない。
    pub fn open_bidi(&mut self) -> Result<u64, Error> {
        if self.next_local_bidi_seq >= self.peer_max_streams_bidi {
            // STREAMS_BLOCKED を送信 (RFC 9000 Section 4.6 SHOULD)
            let limit = self.peer_max_streams_bidi;
            if self.last_streams_blocked_bidi_at != Some(limit) {
                self.last_streams_blocked_bidi_at = Some(limit);
                self.pending_frames.push_back(frame::Frame::StreamsBlocked(
                    frame::streams_blocked::StreamsBlocked {
                        bidirectional: true,
                        maximum_streams: VarInt::new(limit).expect("value fits in 62-bit varint"),
                    },
                ));
            }
            return Err(Error::StreamLimitReached {
                bidirectional: true,
                maximum_streams: limit,
            });
        }

        let stream_type = match self.role {
            Role::Client => StreamType::ClientBidi,
            Role::Server => StreamType::ServerBidi,
        };
        let id = make_stream_id(stream_type, self.next_local_bidi_seq);
        self.next_local_bidi_seq += 1;

        // ピアの initial_max_stream_data_bidi_remote がローカルの送信上限
        // ローカルの initial_max_stream_data_bidi_local が受信上限
        let stream = Stream::new_local_bidi(
            id,
            self.peer_initial_max_stream_data_bidi_remote,
            self.local_initial_max_stream_data_bidi_local,
        );
        self.streams.insert(id, stream);

        Ok(id)
    }

    /// 単方向ストリームを開く
    ///
    /// ピアが許可した上限に達している場合は STREAMS_BLOCKED を送信待ちに積み、
    /// [`Error::StreamLimitReached`] を返す。これは接続を閉じるエラーではない。
    pub fn open_uni(&mut self) -> Result<u64, Error> {
        if self.next_local_uni_seq >= self.peer_max_streams_uni {
            // STREAMS_BLOCKED を送信 (RFC 9000 Section 4.6 SHOULD)
            let limit = self.peer_max_streams_uni;
            if self.last_streams_blocked_uni_at != Some(limit) {
                self.last_streams_blocked_uni_at = Some(limit);
                self.pending_frames.push_back(frame::Frame::StreamsBlocked(
                    frame::streams_blocked::StreamsBlocked {
                        bidirectional: false,
                        maximum_streams: VarInt::new(limit).expect("value fits in 62-bit varint"),
                    },
                ));
            }
            return Err(Error::StreamLimitReached {
                bidirectional: false,
                maximum_streams: limit,
            });
        }

        let stream_type = match self.role {
            Role::Client => StreamType::ClientUni,
            Role::Server => StreamType::ServerUni,
        };
        let id = make_stream_id(stream_type, self.next_local_uni_seq);
        self.next_local_uni_seq += 1;

        let stream = Stream::new_local_uni(id, self.peer_initial_max_stream_data_uni);
        self.streams.insert(id, stream);

        Ok(id)
    }

    /// ピアからのストリームを暗黙的に開く (RFC 9000 Section 2.1)
    ///
    /// stream_id 以下の未作成のストリームも全て作成する。
    ///
    /// ローカル起動ストリームは作成しない。未作成のローカル起動ストリーム宛の
    /// フレームは STREAM_STATE_ERROR で接続を閉じる (RFC 9000 Section 19.8 / 19.5)。
    /// この契約により呼び出し元は、本関数の成功後に `streams` から該当ストリームを
    /// 必ず取得できる。`streams` に削除経路 (GC 等) を導入する場合はこの前提が
    /// 崩れるため、削除済みストリーム宛の遅延フレーム (RFC 9000 Section 3) の
    /// 扱いを再検討すること。
    fn ensure_peer_stream(&mut self, stream_id: u64) -> Result<(), Error> {
        let st = StreamType::from_id(stream_id);
        let seq = stream_sequence(stream_id);

        // ローカル起動のストリームはここでは作成しない
        let is_peer_initiated = match self.role {
            Role::Client => st.is_server_initiated(),
            Role::Server => st.is_client_initiated(),
        };
        if !is_peer_initiated {
            // ローカル起動ストリームは open_bidi / open_uni が連番で作成するため、
            // 作成済みのシーケンス番号は [0, next_local_*_seq) に隙間なく並ぶ。
            // よって閾値比較だけで未作成を判定できる。
            //
            // RFC 9000 Section 19.8 (STREAM) / 19.5 (STOP_SENDING) は、未作成の
            // ローカル起動ストリーム宛フレームの受信を STREAM_STATE_ERROR として
            // 接続を閉じることを MUST で規定する。RESET_STREAM / RESET_STREAM_AT は
            // 明文の規定がないが、Section 20.1 の STREAM_STATE_ERROR の定義と
            // Section 19.8 の対称性から同じ扱いにする。
            let next_local_seq = if st.is_bidirectional() {
                self.next_local_bidi_seq
            } else {
                self.next_local_uni_seq
            };
            if seq >= next_local_seq {
                return Err(Error::Protocol {
                    code: TransportErrorCode::STREAM_STATE_ERROR,
                    reason: format!(
                        "locally initiated stream {stream_id} has not yet been created"
                    ),
                });
            }
            return Ok(());
        }

        // ストリーム数制限チェック
        let (next_seq, max_streams) = if st.is_bidirectional() {
            (&mut self.next_peer_bidi_seq, self.local_max_streams_bidi)
        } else {
            (&mut self.next_peer_uni_seq, self.local_max_streams_uni)
        };

        if seq >= max_streams {
            return Err(Error::Protocol {
                code: TransportErrorCode::STREAM_LIMIT_ERROR,
                reason: format!(
                    "peer exceeded stream limit: stream {stream_id} (seq {seq}) >= max {max_streams}"
                ),
            });
        }

        // 未作成のストリームを順番に作成
        while *next_seq <= seq {
            let new_id = make_stream_id(st, *next_seq);
            if !self.streams.contains_key(&new_id) {
                let stream = if st.is_bidirectional() {
                    // ピア起動の双方向ストリーム
                    // ピアの initial_max_stream_data_bidi_local がローカルの送信上限
                    // ローカルの initial_max_stream_data_bidi_remote が受信上限
                    Stream::new_peer_bidi(
                        new_id,
                        self.peer_initial_max_stream_data_bidi_local,
                        self.local_initial_max_stream_data_bidi_remote,
                    )
                } else {
                    // ピア起動の単方向ストリーム (受信のみ)
                    Stream::new_peer_uni(new_id, self.local_initial_max_stream_data_uni)
                };
                self.streams.insert(new_id, stream);
                self.events
                    .push_back(StreamEvent::NewStream { stream_id: new_id });
            }
            *next_seq += 1;
        }

        Ok(())
    }

    // --- データ送受信 ---

    /// ストリームにデータを書き込む
    pub fn send(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<usize, Error> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| Error::InvalidData(format!("unknown stream {stream_id}")))?;

        let send_state = stream.send_state.ok_or(Error::Protocol {
            code: TransportErrorCode::STREAM_STATE_ERROR,
            reason: format!("stream {stream_id} is receive-only"),
        })?;

        // 送信可能な状態か確認
        match send_state {
            SendState::Ready | SendState::Send => {}
            _ => {
                return Err(Error::Protocol {
                    code: TransportErrorCode::STREAM_STATE_ERROR,
                    reason: format!("stream {stream_id} send state is {send_state:?}"),
                });
            }
        }

        let send_buf = stream
            .send_buf
            .as_mut()
            .expect("send state implies a send buffer");

        // フロー制御: ストリームレベル
        let stream_budget = stream.send_max_data.saturating_sub(send_buf.write_offset());
        // フロー制御: 接続レベル
        let conn_budget = self.send_max_data.saturating_sub(self.send_data_total);
        let max_len = (stream_budget.min(conn_budget) as usize).min(data.len());
        // フロー制御でブロックされている場合
        if max_len == 0 && !data.is_empty() {
            // ブロック通知フレームを生成
            if stream_budget == 0 {
                let limit = stream.send_max_data;
                if stream.last_stream_data_blocked_at != Some(limit) {
                    stream.last_stream_data_blocked_at = Some(limit);
                    self.pending_frames
                        .push_back(frame::Frame::StreamDataBlocked(
                            frame::stream_data_blocked::StreamDataBlocked {
                                stream_id: VarInt::new(stream_id)
                                    .expect("value fits in 62-bit varint"),
                                maximum_stream_data: VarInt::new(limit)
                                    .expect("value fits in 62-bit varint"),
                            },
                        ));
                }
            }
            if conn_budget == 0 {
                let limit = self.send_max_data;
                if self.last_data_blocked_at != Some(limit) {
                    self.last_data_blocked_at = Some(limit);
                    self.pending_frames.push_back(frame::Frame::DataBlocked(
                        frame::data_blocked::DataBlocked {
                            maximum_data: VarInt::new(limit).expect("value fits in 62-bit varint"),
                        },
                    ));
                }
            }
            // FIN のみの場合は 0 バイトでも送信できる
            if !fin {
                return Ok(0);
            }
        }

        let actual_data = &data[..max_len];
        let written = send_buf.write(actual_data, fin && max_len == data.len());

        // 接続レベルの送信済みバイト数を更新
        self.send_data_total += written as u64;

        // 状態遷移
        if send_state == SendState::Ready && (written > 0 || fin) {
            stream.send_state = Some(send_state.transition_to_send()?);
        }

        Ok(written)
    }

    /// ストリームからデータを読み取る
    /// (読み取りバイト数, FIN 到達フラグ) を返す
    pub fn recv(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| Error::InvalidData(format!("unknown stream {stream_id}")))?;

        let recv_state = stream.recv_state.ok_or(Error::Protocol {
            code: TransportErrorCode::STREAM_STATE_ERROR,
            reason: format!("stream {stream_id} is send-only"),
        })?;

        // RESET_STREAM_AT 受信済みストリームは、Reliable Size までのデータを
        // 読み切った時点でリセットを報告する。RESET_STREAM (reliable_size = 0)
        // と同じく、読み切るまではバッファ済みデータを返す
        // (draft-ietf-quic-reliable-stream-reset-11 Section 1 / Section 5)。
        if !buf.is_empty()
            && matches!(recv_state, RecvState::SizeKnown | RecvState::DataRecvd)
            && let Some(reliable_size) = stream.recv_reliable_size
            && let Some(error_code) = stream.recv_reset_error_code
        {
            let recv_buf = stream
                .recv_buf
                .as_ref()
                .expect("stream with a receive state must have a receive buffer");
            if recv_buf.read_offset() >= reliable_size {
                stream.recv_state = Some(RecvState::ResetRead);
                return Err(Error::Protocol {
                    code: TransportErrorCode::STREAM_STATE_ERROR,
                    reason: format!(
                        "stream {stream_id} was reset by peer (error_code={error_code})"
                    ),
                });
            }
        }

        match recv_state {
            RecvState::Recv | RecvState::SizeKnown | RecvState::DataRecvd => {}
            RecvState::ResetRecvd => {
                // RFC 9000 Section 3.2: リセット前に受信してバッファ済みの連続
                // データはアプリへ渡す。読み切った後にリセットを報告する。
                if buf.is_empty() {
                    return Ok((0, false));
                }
                let recv_buf = stream
                    .recv_buf
                    .as_ref()
                    .expect("stream with a receive state must have a receive buffer");
                if recv_buf.read_offset() >= recv_buf.contiguous_offset() {
                    // バッファ済みデータを読み切った。以後は終端状態として
                    // リセットを報告する。
                    stream.recv_state = Some(recv_state.transition_to_reset_read()?);
                    return Err(Error::Protocol {
                        code: TransportErrorCode::STREAM_STATE_ERROR,
                        reason: format!(
                            "stream {} was reset by peer (error_code={})",
                            stream_id,
                            stream
                                .recv_reset_error_code
                                .expect("reset state must have an error code")
                        ),
                    });
                }
            }
            // 終端状態でも長さ 0 の要求には読み取り完了状態を返す。長さ 0 では
            // データを消費しないため状態を変えずに fin だけを観測できる。
            // ここでエラーにすると、呼び出し側が would-block と区別できず
            // 再試行を繰り返して戻らなくなる。
            _ if buf.is_empty() => {
                let recv_buf = stream
                    .recv_buf
                    .as_ref()
                    .expect("stream with a receive state must have a receive buffer");
                // リセット済みのストリームは FIN で終端したわけではないため、
                // 読み取り完了状態でも fin は偽とする。
                let fin = stream.recv_reset_error_code.is_none() && recv_buf.is_fully_read();
                return Ok((0, fin));
            }
            _ => {
                return Err(Error::Protocol {
                    code: TransportErrorCode::STREAM_STATE_ERROR,
                    reason: format!("stream {stream_id} recv state is {recv_state:?}"),
                });
            }
        }

        // RESET_STREAM_AT 受信済みのストリームでは、Reliable Size までの
        // データを読み切った後の呼び出しでリセットを報告する。それまでは
        // バッファ済みデータを返し、fin は常に偽とする。
        let reset_at_received = stream.recv_reliable_size.is_some();
        let recv_buf = stream
            .recv_buf
            .as_mut()
            .expect("stream with a receive state must have a receive buffer");
        let (n, mut fin) = recv_buf.read(buf);

        // リセット済みストリームの読み出しでは FIN 相当の終端フラグを立てない
        // (FIN で終端したわけではないため)。読み切った後のリセット報告は
        // 次回の recv() が行う。
        if recv_state == RecvState::ResetRecvd || reset_at_received {
            fin = false;
        }

        // 状態遷移: 全データ読み取り完了
        if fin && recv_state == RecvState::DataRecvd {
            stream.recv_state = Some(recv_state.transition_to_data_read()?);
        }

        // ストリームレベルのクレジット自動更新 (RFC 9000 Section 4.1)
        // Recv 状態でのみ MAX_STREAM_DATA を送信する
        // SizeKnown 以降は最終サイズ確定済みなので不要
        if n > 0 && matches!(stream.recv_state, Some(RecvState::Recv)) {
            let read_offset = recv_buf.read_offset();
            // 不変条件: read_offset <= recv_max_data
            // (on_stream_frame / RESET 経路のフロー制御検査で保証される)
            debug_assert!(stream.recv_max_data >= read_offset);
            let remaining = stream.recv_max_data - read_offset;
            if remaining <= stream.recv_max_data_initial / 2 {
                // 消費分だけクレジットを追加
                // 設定上限 (validate_local) で実用的な範囲に制限しているが、
                // 加算結果が varint の最大値を超えないよう飽和させる。
                stream.recv_max_data = read_offset
                    .saturating_add(stream.recv_max_data_initial)
                    .min(tobi_core::varint::MAX_VALUE);
                self.pending_frames.push_back(frame::Frame::MaxStreamData(
                    frame::max_stream_data::MaxStreamData {
                        stream_id: VarInt::new(stream_id).expect("value fits in 62-bit varint"),
                        maximum_stream_data: VarInt::new(stream.recv_max_data)
                            .expect("value fits in 62-bit varint"),
                    },
                ));
            }
        }

        // 接続レベルのクレジット自動更新
        if n > 0 {
            self.consumed_total += n as u64;
            self.maybe_advance_conn_window();
        }

        Ok((n, fin))
    }

    /// RESET_STREAM / RESET_STREAM_AT のリセットイベントを 1 回だけ通知する
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 1: QUIC 実装は
    /// Reliable Size までのデータを提供した後にリセットを通知する。
    /// Section 5.3: 受信側は最小 Reliable Size までのデータが揃った時点で
    /// Data Recvd へ遷移する。到着前に通知すると、イベント駆動のアプリが
    /// 保証データを読まずにストリームを閉じうるため、Data Recvd 到達まで待つ。
    fn emit_reset_event_if_ready(&mut self, stream_id: u64) {
        let Some(stream) = self.streams.get(&stream_id) else {
            return;
        };
        if stream.recv_reset_event_emitted {
            return;
        }
        let Some(error_code) = stream.recv_reset_error_code else {
            return;
        };
        let Some(reliable_size) = stream.recv_reliable_size else {
            return;
        };
        let Some(recv_buf) = stream.recv_buf.as_ref() else {
            return;
        };
        if recv_buf.contiguous_offset() < reliable_size {
            return;
        }
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.recv_reset_event_emitted = true;
        }
        self.events.push_back(StreamEvent::StreamReset {
            stream_id,
            error_code,
        });
    }

    /// 接続レベルウィンドウ (MAX_DATA) を消費済み総量基準で前進させる
    ///
    /// RFC 9000 Section 4.1 は接続レベル上限を「全ストリームの消費済みバイト合計」を
    /// 基準に advertise してもよい (could) と述べる (非規範)。本実装はこれを採用する。
    /// 受信済み総量 (recv_data_total) を基準にすると、アプリがほとんど読まなくても
    /// ウィンドウが広がり続け、受信バッファが積み上がるメモリ枯渇 DoS になるため。
    /// ストリームレベルの read_offset 基準の前進と対称になる。
    ///
    /// recv() での通常消費と、RESET_STREAM / RESET_STREAM_AT での信用付与の両方から
    /// 呼ぶ。リセットだけでも解放したウィンドウをピアへ通知しないと、接続ウィンドウを
    /// 使い切った直後に全ストリームをリセットされた場合に MAX_DATA が送出されず、送信
    /// 側が接続レベルで恒久的にブロックされてストールする。
    ///
    /// 残量計算は生の減算を使う (recv() 既存実装と同じ)。`saturating_sub` にすると
    /// recv_data_total が上限を超える不正入力時に残量 0 と誤認してウィンドウを再前進
    /// させ、違反した相手にクレジットを再広告する fail-open になるため使わない。
    /// この不正入力の遮断は RESET 経路のフロー制御検査の責務であり本メソッドの範囲外。
    fn maybe_advance_conn_window(&mut self) {
        let conn_remaining = self.recv_max_data - self.consumed_total;
        if conn_remaining <= self.recv_max_data_initial / 2 {
            // 加算結果が varint の最大値を超えないよう飽和させる
            self.recv_max_data = self
                .consumed_total
                .saturating_add(self.recv_max_data_initial)
                .min(tobi_core::varint::MAX_VALUE);
            self.pending_frames
                .push_back(frame::Frame::MaxData(frame::max_data::MaxData {
                    maximum_data: VarInt::new(self.recv_max_data)
                        .expect("value fits in 62-bit varint"),
                }));
        }
    }

    /// ストリームをリセットする
    pub fn reset_stream(&mut self, stream_id: u64, error_code: u64) -> Result<(), Error> {
        // RFC 9000 Section 16: フレームの値フィールドは 62 ビット varint に
        // 収まる必要がある。アプリケーション由来の値を構築前に検証し、
        // encode 時の panic ではなく Result のエラーとして扱う。
        let error_code = VarInt::try_from(error_code)
            .map_err(|e| Error::InvalidData(format!("invalid application error code: {e}")))?;
        let stream_id_varint = VarInt::try_from(stream_id)
            .map_err(|e| Error::InvalidData(format!("invalid stream id: {e}")))?;
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| Error::InvalidData(format!("unknown stream {stream_id}")))?;

        let send_state = stream.send_state.ok_or(Error::Protocol {
            code: TransportErrorCode::STREAM_STATE_ERROR,
            reason: format!("stream {stream_id} is receive-only"),
        })?;

        // draft-ietf-quic-reliable-stream-reset-11 Section 5.2:
        // 後続の RESET_STREAM_AT / RESET_STREAM で Application Error Code を
        // 変更してはならない (MUST NOT)。既にリセットを送っている場合は
        // 同じコードのみ受理する。
        if let Some(existing) = stream.reset_at_error_code
            && existing != error_code.as_u64()
        {
            return Err(Error::InvalidData(format!(
                "application error code cannot change from {existing} to {} for stream {stream_id}",
                error_code.as_u64()
            )));
        }

        let final_size = stream.send_buf.as_ref().map_or(0, |b| b.write_offset());
        // RFC 9000 Section 19.4 / draft-ietf-quic-reliable-stream-reset-11 Section 4:
        // RESET_STREAM の Final Size もストリーム・接続のフロー制御上限に
        // 収まらなければならない。0-RTT 拒否後に上限が縮小した場合は
        // 送信せずエラーとしてアプリケーションへ通知する。
        if final_size > stream.send_max_data {
            return Err(Error::InvalidData(format!(
                "final_size {final_size} exceeds stream flow control limit {} for stream {stream_id}",
                stream.send_max_data
            )));
        }
        if self.send_data_total > self.send_max_data {
            return Err(Error::InvalidData(format!(
                "final_size {final_size} exceeds connection flow control limit {} for stream {stream_id}",
                self.send_max_data
            )));
        }

        let new_state = send_state.transition_to_reset_sent()?;
        stream.send_state = Some(new_state);
        // RESET_STREAM は Reliable Size 0 の RESET_STREAM_AT と等価である
        // (draft-ietf-quic-reliable-stream-reset-11 Section 5)。再送待ちの
        // ストリームデータは配信義務がないため破棄し、Reliable Size 0 として扱う。
        if let Some(send_buf) = stream.send_buf.as_mut() {
            send_buf.trim_retransmit_for_reliable_size(0);
        }
        stream.reset_at_error_code = Some(error_code.as_u64());
        stream.reset_at_reliable_size = Some(0);
        stream.reset_at_frame_queued = false;
        stream.reset_at_frame_acked = false;

        let final_size = VarInt::try_from(final_size)
            .map_err(|e| Error::InvalidData(format!("invalid final size: {e}")))?;
        self.pending_frames.push_back(frame::Frame::ResetStream(
            frame::reset_stream::ResetStream {
                stream_id: stream_id_varint,
                application_protocol_error_code: error_code,
                final_size,
            },
        ));

        Ok(())
    }

    /// reliable_size までのデータ配信を保証しつつストリームをリセットする
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 5。
    /// ピアが `reset_stream_at` transport parameter を広告していない場合は
    /// `Err(Error::InvalidData)` を返す (Section 3 の MUST)。
    /// `reliable_size > final_size` の場合も `Err(Error::InvalidData)` を返す。
    /// `reliable_size` が以前の値より大きい場合は Section 5.2 に従い無視する
    /// (戻り値は `Ok`)。既にリセットを送信済みで Application Error Code が
    /// 異なる場合は `Err(Error::InvalidData)` を返す (Section 5.2 MUST NOT)。
    pub fn reset_stream_at(
        &mut self,
        stream_id: u64,
        error_code: u64,
        reliable_size: u64,
    ) -> Result<(), Error> {
        // RFC 9000 Section 16: アプリケーション由来の値域を構築前に検証する。
        let error_code_varint = VarInt::try_from(error_code)
            .map_err(|e| Error::InvalidData(format!("invalid application error code: {e}")))?;
        let stream_id_varint = VarInt::try_from(stream_id)
            .map_err(|e| Error::InvalidData(format!("invalid stream id: {e}")))?;
        let reliable_size_varint = VarInt::try_from(reliable_size)
            .map_err(|e| Error::InvalidData(format!("invalid reliable size: {e}")))?;
        // draft-ietf-quic-reliable-stream-reset-11 Section 3:
        // "An endpoint MUST NOT send a RESET_STREAM_AT frame unless the peer
        //  advertised support using the reset_stream_at transport parameter."
        // ピアの広告は 0-RTT では前回セッションで記憶した値を
        // apply_peer_params 経由で参照する。
        if !self.peer_supports_reset_stream_at {
            return Err(Error::InvalidData(
                "peer does not support reset_stream_at".to_string(),
            ));
        }

        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| Error::InvalidData(format!("unknown stream {stream_id}")))?;

        let send_state = stream.send_state.ok_or(Error::Protocol {
            code: TransportErrorCode::STREAM_STATE_ERROR,
            reason: format!("stream {stream_id} is receive-only"),
        })?;

        // Ready, Send, DataSent からのみ遷移可能
        match send_state {
            SendState::Ready | SendState::Send | SendState::DataSent => {}
            _ => {
                return Err(Error::Protocol {
                    code: TransportErrorCode::STREAM_STATE_ERROR,
                    reason: format!(
                        "cannot reset_stream_at in state {send_state:?} for stream {stream_id}"
                    ),
                });
            }
        }

        let final_size = stream.send_buf.as_ref().map_or(0, |b| b.write_offset());

        // draft-ietf-quic-reliable-stream-reset-11 Section 4:
        // "Final Size is subject to stream and connection-level flow control.
        //  An endpoint MUST NOT send a RESET_STREAM_AT frame that exceeds the
        //  largest maximum stream data value advertised by the receiver for the
        //  stream, or that violates the receiver's maximum data limit."
        //
        // 通常時は `send()` がストリーム (send_max_data - write_offset) と接続
        // (send_max_data - send_data_total) の両予算内でのみ書き込むため、
        // final_size は両方の上限に収まる。しかし 0-RTT 拒否後は確定した
        // peer transport parameter が記憶値より小さくなりうる (RFC 9000
        // Section 7.4.1)。その場合は Section 4 の MUST NOT を守るため、
        // 送信延期ではなくエラーとしてアプリケーションへ通知する。
        if final_size > stream.send_max_data {
            return Err(Error::InvalidData(format!(
                "final_size {final_size} exceeds stream flow control limit {} for stream {stream_id}",
                stream.send_max_data
            )));
        }
        if self.send_data_total > self.send_max_data {
            return Err(Error::InvalidData(format!(
                "final_size {final_size} exceeds connection flow control limit {} for stream {stream_id}",
                self.send_max_data
            )));
        }

        if reliable_size > final_size {
            return Err(Error::InvalidData(format!(
                "reliable_size {reliable_size} exceeds final_size {final_size} for stream {stream_id}"
            )));
        }

        // draft-ietf-quic-reliable-stream-reset-11 Section 5.2:
        // 後続の RESET_STREAM_AT / RESET_STREAM で Application Error Code を
        // 変更してはならない (MUST NOT)。Reliable Size の増加を無視する場合も
        // コードの一致は検証する。
        if let Some(existing) = stream.reset_at_error_code
            && existing != error_code
        {
            return Err(Error::InvalidData(format!(
                "application error code cannot change from {existing} to {error_code} for stream {stream_id}"
            )));
        }

        // draft-ietf-quic-reliable-stream-reset-11 Section 5.2:
        // reliable_size の減少のみ許可する (増加は無視)
        if let Some(existing) = stream.reset_at_reliable_size
            && reliable_size > existing
        {
            return Ok(());
        }

        stream.reset_at_reliable_size = Some(reliable_size);
        stream.reset_at_error_code = Some(error_code);
        stream.reset_at_final_size = Some(final_size);
        // 現在の Reliable Size を持つフレームをこれから送信する。以前の
        // Reliable Size のフレームが ACK 済みでも、より小さい値の情報が
        // ACK されるまで Data Recvd には遷移しない (Section 5.3)。
        stream.reset_at_frame_queued = true;
        stream.reset_at_frame_acked = false;
        // Reliable Size を超える再送予定データは配信義務がないため破棄する
        // (Section 5 SHOULD NOT)。
        if let Some(send_buf) = stream.send_buf.as_mut() {
            send_buf.trim_retransmit_for_reliable_size(reliable_size);
        }

        // draft-ietf-quic-reliable-stream-reset-11 Section 5.3:
        // 状態遷移は FIN と同じパス (DataSent へ直接遷移)
        stream.send_state = Some(SendState::DataSent);

        let final_size_varint = VarInt::try_from(final_size)
            .map_err(|e| Error::InvalidData(format!("invalid final size: {e}")))?;
        self.pending_frames.push_back(frame::Frame::ResetStreamAt(
            frame::reset_stream_at::ResetStreamAt {
                stream_id: stream_id_varint,
                application_protocol_error_code: error_code_varint,
                final_size: final_size_varint,
                reliable_size: reliable_size_varint,
            },
        ));

        Ok(())
    }

    /// ピアに送信停止を要求する
    pub fn stop_sending(&mut self, stream_id: u64, error_code: u64) -> Result<(), Error> {
        // RFC 9000 Section 16: アプリケーション由来の値域を構築前に検証する。
        let error_code = VarInt::try_from(error_code)
            .map_err(|e| Error::InvalidData(format!("invalid application error code: {e}")))?;
        let stream_id_varint = VarInt::try_from(stream_id)
            .map_err(|e| Error::InvalidData(format!("invalid stream id: {e}")))?;
        let stream = self
            .streams
            .get(&stream_id)
            .ok_or_else(|| Error::InvalidData(format!("unknown stream {stream_id}")))?;

        let recv_state = stream.recv_state.ok_or(Error::Protocol {
            code: TransportErrorCode::STREAM_STATE_ERROR,
            reason: format!("stream {stream_id} is send-only"),
        })?;

        // ResetRecvd, ResetRead 状態では STOP_SENDING を送信しない
        match recv_state {
            RecvState::Recv | RecvState::SizeKnown | RecvState::DataRecvd => {}
            _ => {
                return Err(Error::Protocol {
                    code: TransportErrorCode::STREAM_STATE_ERROR,
                    reason: format!("stream {stream_id} recv state is {recv_state:?}"),
                });
            }
        }

        self.pending_frames.push_back(frame::Frame::StopSending(
            frame::stop_sending::StopSending {
                stream_id: stream_id_varint,
                application_protocol_error_code: error_code,
            },
        ));

        Ok(())
    }

    // --- フレーム受信処理 ---

    /// STREAM フレームを処理する
    pub fn on_stream_frame(&mut self, f: &frame::stream::Stream) -> Result<(), Error> {
        if self.is_gc_closed(f.stream_id.as_u64()) {
            return Ok(());
        }
        self.ensure_peer_stream(f.stream_id.as_u64())?;

        // ensure_peer_stream 成功後はストリームの存在が保証される。
        // streams に削除経路 (GC 等) を導入する場合は、削除済みストリーム宛の
        // 遅延フレーム (RFC 9000 Section 3) の扱いを再検討する必要がある。
        let stream = self
            .streams
            .get_mut(&f.stream_id.as_u64())
            .expect("stream must exist after ensure_peer_stream; None is an implementation bug");

        let recv_state = stream.recv_state.ok_or(Error::Protocol {
            code: TransportErrorCode::STREAM_STATE_ERROR,
            reason: format!("stream {} has no receive side", f.stream_id),
        })?;

        // 終端状態では無視 (パケット遅延の可能性)
        if recv_state.is_terminal() {
            return Ok(());
        }

        let recv_buf = stream
            .recv_buf
            .as_mut()
            .expect("stream with a receive state must have a receive buffer");
        let end_offset = f.offset + f.data.len() as u64;

        // フロー制御チェック: ストリームレベル
        if end_offset > stream.recv_max_data {
            return Err(Error::Protocol {
                code: TransportErrorCode::FLOW_CONTROL_ERROR,
                reason: format!(
                    "stream {} flow control violation: {} > {}",
                    f.stream_id, end_offset, stream.recv_max_data
                ),
            });
        }

        // フロー制御チェック: 接続レベル
        let new_bytes = end_offset.saturating_sub(recv_buf.max_recv_offset());
        if self.recv_data_total + new_bytes > self.recv_max_data {
            return Err(Error::Protocol {
                code: TransportErrorCode::FLOW_CONTROL_ERROR,
                reason: format!(
                    "connection flow control violation: {} + {} > {}",
                    self.recv_data_total, new_bytes, self.recv_max_data
                ),
            });
        }

        // 接続レベルの受信カウンタを更新
        self.recv_data_total += new_bytes;

        // draft-ietf-quic-reliable-stream-reset-11 Section 5.2:
        // RESET_STREAM / RESET_STREAM_AT を先に受信済みのストリームで、
        // STREAM-FIN の final_size (= end_offset) が既設 final_size と異なる場合は
        // FINAL_SIZE_ERROR で接続を閉じる。同節は Application Error Code の変更に
        // STREAM_STATE_ERROR、Final Size の変更に FINAL_SIZE_ERROR をそれぞれ MUST で
        // 要求する (RFC 9000 Section 4.5 と一致)。
        if f.fin
            && stream.recv_reliable_size.is_some()
            && let Some(existing) = recv_buf.final_size()
            && existing != end_offset
        {
            return Err(Error::Protocol {
                code: TransportErrorCode::FINAL_SIZE_ERROR,
                reason: format!(
                    "STREAM FIN final_size changed from {} to {} for stream {} after RESET_STREAM_AT/RESET_STREAM",
                    existing, end_offset, f.stream_id
                ),
            });
        }

        // データをバッファに格納する。
        // リセット済み (RESET_STREAM / RESET_STREAM_AT 受信済み) のストリームでは、
        // reliable_size を超える部分は配信されないため格納しない。格納すると、リセットで
        // 切り詰めた領域がリオーダした STREAM フレームで再バッファされ、recv() で再消費
        // されて consumed_total を二重計上してしまう
        // (draft-ietf-quic-reliable-stream-reset-11 Section 5.2: 受信側は reliable_size
        //  までのデータを提供すれば足りる)。
        match stream.recv_reliable_size {
            Some(reliable) if end_offset > reliable => {
                // final_size を超えるデータは RFC 9000 Section 4.5 の FINAL_SIZE_ERROR を
                // 維持する。reliable_size で切り詰めると receive() 内の超過検査に届かない
                // ため、格納前に明示的に検出する。
                if let Some(fs) = recv_buf.final_size()
                    && end_offset > fs
                {
                    return Err(Error::Protocol {
                        code: TransportErrorCode::FINAL_SIZE_ERROR,
                        reason: format!(
                            "stream {} data exceeds final size: {} > {}",
                            f.stream_id, end_offset, fs
                        ),
                    });
                }
                if f.offset < reliable {
                    let keep = (reliable - f.offset) as usize;
                    // reliable_size を超える末尾を落とすため fin は伝えない
                    // (final_size は既にリセットで確定済み)。
                    recv_buf.receive(f.offset.as_u64(), &f.data[..keep], false)?;
                }
                // offset >= reliable_size のデータは全て配信対象外のため格納しない。
            }
            _ => {
                recv_buf.receive(f.offset.as_u64(), &f.data, f.fin)?;
            }
        }

        // 状態遷移
        match recv_state {
            RecvState::Recv if f.fin => {
                stream.recv_state = Some(recv_state.transition_to_size_known()?);
                if recv_buf.is_complete() {
                    stream.recv_state = Some(RecvState::SizeKnown.transition_to_data_recvd()?);
                }
            }
            RecvState::SizeKnown => {
                // draft-ietf-quic-reliable-stream-reset-11 Section 5.3:
                // RESET_STREAM_AT の場合は reliable_size までのデータで DataRecvd へ遷移
                let complete = if let Some(reliable_size) = stream.recv_reliable_size {
                    recv_buf.contiguous_offset() >= reliable_size
                } else {
                    recv_buf.is_complete()
                };
                if complete {
                    stream.recv_state = Some(recv_state.transition_to_data_recvd()?);
                }
            }
            _ => {}
        }

        // Reliable Size までのデータが揃ったらリセットを通知する
        self.emit_reset_event_if_ready(f.stream_id.as_u64());

        self.events.push_back(StreamEvent::StreamReadable {
            stream_id: f.stream_id.as_u64(),
        });

        Ok(())
    }

    /// RESET_STREAM フレームを処理する
    pub fn on_reset_stream(&mut self, f: &frame::reset_stream::ResetStream) -> Result<(), Error> {
        if self.is_gc_closed(f.stream_id.as_u64()) {
            return Ok(());
        }
        self.ensure_peer_stream(f.stream_id.as_u64())?;

        // ensure_peer_stream 成功後はストリームの存在が保証される。
        // streams に削除経路 (GC 等) を導入する場合は、削除済みストリーム宛の
        // 遅延フレーム (RFC 9000 Section 3) の扱いを再検討する必要がある。
        let stream = self
            .streams
            .get_mut(&f.stream_id.as_u64())
            .expect("stream must exist after ensure_peer_stream; None is an implementation bug");

        let recv_state = stream.recv_state.ok_or(Error::Protocol {
            code: TransportErrorCode::STREAM_STATE_ERROR,
            reason: format!("stream {} has no receive side", f.stream_id),
        })?;

        // 終端状態では無視
        if recv_state.is_terminal() {
            return Ok(());
        }

        // draft-ietf-quic-reliable-stream-reset-11 Section 5.2:
        // RESET_STREAM は reliable_size = 0 の RESET_STREAM_AT と等価
        // error_code の変更を検出する
        if let Some(existing_error) = stream.recv_reset_error_code
            && existing_error != f.application_protocol_error_code
        {
            return Err(Error::Protocol {
                code: TransportErrorCode::STREAM_STATE_ERROR,
                reason: format!(
                    "RESET_STREAM error_code changed from {} to {} for stream {}",
                    existing_error, f.application_protocol_error_code, f.stream_id
                ),
            });
        }

        // 最終サイズの整合性チェック
        // draft-ietf-quic-reliable-stream-reset-11 Section 5.2:
        // 同一ストリームの後続フレームで final_size が変わった場合は FINAL_SIZE_ERROR
        // で接続を閉じる (MUST)。RESET_STREAM は reliable_size = 0 の RESET_STREAM_AT と
        // 等価のため同節が適用される (RFC 9000 Section 4.5 と一致)。
        // 信用付与の増分計算で使う前回の信用下限を、recv_buf を借用する前に取得する。
        let old_reliable = stream.recv_reliable_size;
        // RFC 9000 Section 4.5 / 19.9: final_size のフロー制御検査 (ストリームレベル)
        // 超過は FLOW_CONTROL_ERROR で接続を閉じる (MUST)
        if f.final_size > stream.recv_max_data {
            return Err(Error::Protocol {
                code: TransportErrorCode::FLOW_CONTROL_ERROR,
                reason: format!(
                    "stream {} final_size {} exceeds stream flow control limit {}",
                    f.stream_id, f.final_size, stream.recv_max_data
                ),
            });
        }
        if let Some(recv_buf) = &mut stream.recv_buf {
            if let Some(existing) = recv_buf.final_size()
                && existing != f.final_size
            {
                return Err(Error::Protocol {
                    code: TransportErrorCode::FINAL_SIZE_ERROR,
                    reason: format!(
                        "RESET_STREAM final_size changed from {} to {} for stream {}",
                        existing, f.final_size, f.stream_id
                    ),
                });
            }

            // 既に RESET_STREAM 受信済み (ResetRecvd) のストリームへの同一パラメータの
            // RESET_STREAM はピアのロス再送であるため冪等に無視する。
            // error_code / final_size の整合性検査を通過した後に判定するため、矛盾する
            // 重複フレームは上の検査で FINAL_SIZE_ERROR / STREAM_STATE_ERROR のままとなる。
            // ここで早期 return することで状態遷移を重複させず、StreamReset イベントも
            // 再発行しない。RESET_STREAM_AT の重複が状態遷移パスで Ok になるのと対称の
            // 扱いになる。
            if recv_state == RecvState::ResetRecvd {
                return Ok(());
            }

            // 接続レベルフロー制御: 最終サイズ分を計上 (RFC 9000 Section 4.5 / 19.9)
            let new_bytes = f.final_size.saturating_sub(recv_buf.max_recv_offset());
            if self.recv_data_total.saturating_add(new_bytes) > self.recv_max_data {
                return Err(Error::Protocol {
                    code: TransportErrorCode::FLOW_CONTROL_ERROR,
                    reason: format!(
                        "connection flow control violation: {} + {} > {}",
                        self.recv_data_total, new_bytes, self.recv_max_data
                    ),
                });
            }
            // RFC 9000 Section 4.5: 最終サイズより大きいデータを受信済みだった
            // 場合は FINAL_SIZE_ERROR で接続を閉じる。受信側は final_size の
            // 検証結果を、リセットによるストリーム終端より優先する
            // (接続エラーはストリーム状態に依存しない)。
            if recv_buf.max_recv_offset() > f.final_size {
                return Err(Error::Protocol {
                    code: TransportErrorCode::FINAL_SIZE_ERROR,
                    reason: format!(
                        "RESET_STREAM final_size {} is smaller than data already received {} for stream {}",
                        f.final_size,
                        recv_buf.max_recv_offset(),
                        f.stream_id
                    ),
                });
            }
            recv_buf.set_final_size(f.final_size.as_u64())?;
            self.recv_data_total += new_bytes;
            // 計上済みオフセットを final_size まで進める。
            // これにより同一 final_size の複数リセットやリオーダした STREAM フレームで
            // 同じ領域を二重計上しない。
            recv_buf.advance_max_recv_offset(f.final_size.as_u64());

            // RFC 9000 Section 3.2: リセット前に受信してバッファ済みの連続データは
            // アプリへ渡すため保持する。配信されないのはバッファ済みデータより後の
            // 領域だけなので、その領域のみを消費済みとして信用付与する。バッファ済み
            // データは recv() で読み出した時に消費済みとして計上される (二重計上しない)。
            // 前回の信用下限 (old_floor) は RESET_STREAM_AT で既に信用付与した領域を
            // 示すため、その領域を含めないようにする。アプリがデータを読み切るまで
            // 接続レベルウィンドウは回復しないため、読み切るか破棄する必要がある。
            let read_offset = recv_buf.read_offset();
            let deliverable_end = recv_buf.contiguous_offset();
            let old_floor = old_reliable.unwrap_or(f.final_size.as_u64());
            let credit_lo = read_offset.max(deliverable_end.min(old_floor));
            let credit_hi = read_offset.max(old_floor).min(f.final_size.as_u64());
            self.consumed_total += credit_hi.saturating_sub(credit_lo);
            // 配信しない領域 (連続データより後) のチャンクは保持しない。
            // 受信バッファ構造体自体は保持し、後続の遅延 STREAM フレームの
            // final_size 整合性検査を引き続き機能させる。
            recv_buf.truncate(deliverable_end.max(old_floor).min(f.final_size.as_u64()));
        }

        // RESET_STREAM は reliable_size = 0 に相当する
        stream.recv_reliable_size = Some(0);
        // RESET_STREAM は Reliable Size 0 相当のため、後着の RESET_STREAM_AT は
        // すべて増加として無視される。このストリームが RESET_STREAM_AT 由来に
        // なることはない。
        stream.recv_reset_at_reliable_size = None;
        stream.recv_reset_error_code = Some(f.application_protocol_error_code.as_u64());

        stream.recv_state = Some(recv_state.transition_to_reset_recvd()?);

        // RESET_STREAM は Reliable Size 0 相当のため、保証データの到着を
        // 待たずにリセットを通知できる。重複フレームでは再通知しない。
        self.emit_reset_event_if_ready(f.stream_id.as_u64());

        // 信用付与で解放したウィンドウをピアへ通知する (リセットだけでもストールを防ぐ)。
        self.maybe_advance_conn_window();

        Ok(())
    }

    /// RESET_STREAM_AT フレームを処理する
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 5
    pub fn on_reset_stream_at(
        &mut self,
        f: &frame::reset_stream_at::ResetStreamAt,
    ) -> Result<(), Error> {
        if self.is_gc_closed(f.stream_id.as_u64()) {
            return Ok(());
        }
        self.ensure_peer_stream(f.stream_id.as_u64())?;

        // ensure_peer_stream 成功後はストリームの存在が保証される。
        // streams に削除経路 (GC 等) を導入する場合は、削除済みストリーム宛の
        // 遅延フレーム (RFC 9000 Section 3) の扱いを再検討する必要がある。
        let stream = self
            .streams
            .get_mut(&f.stream_id.as_u64())
            .expect("stream must exist after ensure_peer_stream; None is an implementation bug");

        let recv_state = stream.recv_state.ok_or(Error::Protocol {
            code: TransportErrorCode::STREAM_STATE_ERROR,
            reason: format!("stream {} has no receive side", f.stream_id),
        })?;

        // 終端状態では無視
        if recv_state.is_terminal() {
            return Ok(());
        }

        // draft-ietf-quic-reliable-stream-reset-11 Section 5.2:
        // error_code の変更は STREAM_STATE_ERROR
        if let Some(existing_error) = stream.recv_reset_error_code
            && existing_error != f.application_protocol_error_code
        {
            return Err(Error::Protocol {
                code: TransportErrorCode::STREAM_STATE_ERROR,
                reason: format!(
                    "RESET_STREAM_AT error_code changed from {} to {} for stream {}",
                    existing_error, f.application_protocol_error_code, f.stream_id
                ),
            });
        }

        // final_size の整合性チェック
        // draft-ietf-quic-reliable-stream-reset-11 Section 5.2:
        // 同一ストリームの後続フレームで final_size が変わった場合は FINAL_SIZE_ERROR
        // で接続を閉じる (MUST) (RFC 9000 Section 4.5 と一致)。
        if let Some(recv_buf) = &stream.recv_buf
            && let Some(existing) = recv_buf.final_size()
            && existing != f.final_size
        {
            return Err(Error::Protocol {
                code: TransportErrorCode::FINAL_SIZE_ERROR,
                reason: format!(
                    "RESET_STREAM_AT final_size changed from {} to {} for stream {}",
                    existing, f.final_size, f.stream_id
                ),
            });
        }

        // draft-ietf-quic-reliable-stream-reset-11 Section 5.2:
        // reliable_size の増加は無視する。加えて、同じ Reliable Size を持つ
        // フレームの重複 (ピアのロス再送) も状態・イベント・バッファ・信用の
        // いずれも変更せず無視する。整合性検査の後・計上とフロー制御検査の
        // 前に判定することで、無視するフレームで recv_data_total を加算しない。
        if let Some(existing_reliable) = stream.recv_reliable_size
            && existing_reliable <= f.reliable_size.as_u64()
        {
            return Ok(());
        }

        // RFC 9000 Section 4.5 / 19.9: final_size のフロー制御検査 (ストリームレベル)
        // 超過は FLOW_CONTROL_ERROR で接続を閉じる (MUST)
        if f.final_size > stream.recv_max_data {
            return Err(Error::Protocol {
                code: TransportErrorCode::FLOW_CONTROL_ERROR,
                reason: format!(
                    "stream {} final_size {} exceeds stream flow control limit {}",
                    f.stream_id, f.final_size, stream.recv_max_data
                ),
            });
        }

        if let Some(recv_buf) = &mut stream.recv_buf {
            // 接続レベルフロー制御: final_size 分を計上 (RFC 9000 Section 4.5 / 19.9)
            let new_bytes = f.final_size.saturating_sub(recv_buf.max_recv_offset());
            if self.recv_data_total.saturating_add(new_bytes) > self.recv_max_data {
                return Err(Error::Protocol {
                    code: TransportErrorCode::FLOW_CONTROL_ERROR,
                    reason: format!(
                        "connection flow control violation: {} + {} > {}",
                        self.recv_data_total, new_bytes, self.recv_max_data
                    ),
                });
            }
            // RFC 9000 Section 4.5 / FINAL_SIZE_ERROR の定義 (2):
            // 既受信データより小さい final_size は FINAL_SIZE_ERROR として扱う。
            // RESET_STREAM 経路 (on_reset_stream) と対称にする。
            if recv_buf.max_recv_offset() > f.final_size.as_u64() {
                return Err(Error::Protocol {
                    code: TransportErrorCode::FINAL_SIZE_ERROR,
                    reason: format!(
                        "RESET_STREAM_AT final_size {} is smaller than data already received {} for stream {}",
                        f.final_size,
                        recv_buf.max_recv_offset(),
                        f.stream_id
                    ),
                });
            }
            recv_buf.set_final_size(f.final_size.as_u64())?;
            self.recv_data_total += new_bytes;
            // 計上済みオフセットを final_size まで進める。
            // これにより同一 final_size の複数リセットやリオーダした STREAM フレームで
            // 同じ領域を二重計上しない。
            recv_buf.advance_max_recv_offset(f.final_size.as_u64());
        }

        // reliable_size を超える配信されない部分を消費済みとして信用付与し、その領域の
        // バッファを切り詰めてメモリを返す。reliable tail (reliable_size まで) は保持し、
        // 後続の recv() で消費される。reliable_size は減少方向のみ受理するため、前回の
        // 信用下限 (old_floor) から今回の reliable_size (new_floor) までの、新たに配信
        // 不能になった領域だけを増分で信用付与する。各バイトは「recv() で読まれる
        // (下限未満)」か「信用付与される (下限以上)」のどちらか一方にちょうど 1 回だけ
        // 計上され、このストリームの consumed 寄与は最終的に final_size に一致する
        // (consumed_total <= recv_data_total の不変条件を構造的に保つ)。
        let old_reliable = stream.recv_reliable_size;
        if let Some(recv_buf) = &mut stream.recv_buf
            && let Some(final_size) = recv_buf.final_size()
        {
            let read_offset = recv_buf.read_offset();
            let old_floor = old_reliable.unwrap_or(final_size);
            let new_floor = f.reliable_size.min(old_floor);
            let credit_lo = read_offset.max(new_floor);
            let credit_hi = read_offset.max(old_floor).min(final_size);
            recv_buf.truncate(credit_lo);
            self.consumed_total += credit_hi.saturating_sub(credit_lo);
        }

        stream.recv_reliable_size = Some(f.reliable_size.as_u64());
        stream.recv_reset_at_reliable_size = Some(f.reliable_size.as_u64());
        stream.recv_reset_error_code = Some(f.application_protocol_error_code.as_u64());

        // draft-ietf-quic-reliable-stream-reset-11 Section 5.3:
        // 状態遷移は FIN と同じパス (SizeKnown へ)
        match recv_state {
            RecvState::Recv => {
                stream.recv_state = Some(RecvState::SizeKnown);
                // reliable_size までのデータが既に揃っていれば DataRecvd へ
                if let Some(recv_buf) = &stream.recv_buf
                    && recv_buf.contiguous_offset() >= f.reliable_size
                {
                    stream.recv_state = Some(RecvState::DataRecvd);
                }
            }
            RecvState::SizeKnown => {
                // 既に SizeKnown (FIN を先に受信した場合)
                // reliable_size までのデータが揃っていれば DataRecvd へ
                if let Some(recv_buf) = &stream.recv_buf
                    && recv_buf.contiguous_offset() >= f.reliable_size
                {
                    stream.recv_state = Some(RecvState::DataRecvd);
                }
            }
            RecvState::DataRecvd => {
                // 既にデータ受信完了、何もしない
            }
            _ => {}
        }

        // 保証データが揃った時点でリセットイベントを 1 回だけ通知する。
        // 到着前に通知すると、イベント駆動のアプリが保証データを読まずに
        // ストリームを閉じうる (draft-ietf-quic-reliable-stream-reset-11
        // Section 1: 保証データを提供した後にリセットを通知する)。
        self.emit_reset_event_if_ready(f.stream_id.as_u64());

        // 信用付与で解放したウィンドウをピアへ通知する (リセットだけでもストールを防ぐ)。
        self.maybe_advance_conn_window();

        Ok(())
    }

    /// STOP_SENDING フレームを処理する
    pub fn on_stop_sending(&mut self, f: &frame::stop_sending::StopSending) -> Result<(), Error> {
        if self.is_gc_closed(f.stream_id.as_u64()) {
            return Ok(());
        }
        self.ensure_peer_stream(f.stream_id.as_u64())?;

        // ensure_peer_stream 成功後はストリームの存在が保証される。
        // streams に削除経路 (GC 等) を導入する場合は、削除済みストリーム宛の
        // 遅延フレーム (RFC 9000 Section 3) の扱いを再検討する必要がある。
        let stream = self
            .streams
            .get_mut(&f.stream_id.as_u64())
            .expect("stream must exist after ensure_peer_stream; None is an implementation bug");

        let send_state = stream.send_state.ok_or(Error::Protocol {
            code: TransportErrorCode::STREAM_STATE_ERROR,
            reason: format!("stream {} has no send side", f.stream_id),
        })?;

        // 終端状態や ResetSent では無視
        match send_state {
            SendState::Ready | SendState::Send | SendState::DataSent => {}
            _ => return Ok(()),
        }

        // RFC 9000 Section 3.5: STOP_SENDING を受信したら RESET_STREAM で応答する。
        //
        // draft-ietf-quic-reliable-stream-reset-11 Section 5.4:
        // "If it sends a RESET_STREAM_AT frame in response, it SHOULD set the
        //  Reliable Size to zero, since the peer has indicated that it does not
        //  intend to process further stream data."
        // 本実装は RFC 9000 Section 3.5 に従い RESET_STREAM で応答する。
        // RESET_STREAM は Reliable Size 0 の RESET_STREAM_AT と等価 (Section 5) で
        // あり、RESET_STREAM 自体には Reliable Size フィールドがないため、この
        // SHOULD の対象外である。応答を RESET_STREAM_AT に変更する場合は
        // Reliable Size を 0 にすること。
        // draft-ietf-quic-reliable-stream-reset-11 Section 5.2:
        // 既に RESET_STREAM_AT / RESET_STREAM を送っている場合、Application
        // Error Code を変更してはならない (MUST NOT)。応答には既存のコードを
        // 使い、未送信の場合のみピアが指定したコードを採用する。
        let error_code = stream
            .reset_at_error_code
            .unwrap_or_else(|| f.application_protocol_error_code.as_u64());
        let final_size = stream.send_buf.as_ref().map_or(0, |b| b.write_offset());
        stream.send_state = Some(send_state.transition_to_reset_sent()?);
        stream.peer_stop_sending_error_code = Some(f.application_protocol_error_code.as_u64());
        stream.reset_at_error_code = Some(error_code);
        // RESET_STREAM は Reliable Size 0 相当である
        stream.reset_at_reliable_size = Some(0);
        stream.reset_at_frame_queued = false;
        stream.reset_at_frame_acked = false;
        // 配信義務のない再送待ちデータを破棄する
        if let Some(send_buf) = stream.send_buf.as_mut() {
            send_buf.trim_retransmit_for_reliable_size(0);
        }

        self.pending_frames.push_back(frame::Frame::ResetStream(
            frame::reset_stream::ResetStream {
                stream_id: f.stream_id,
                application_protocol_error_code: VarInt::new(error_code)
                    .expect("value fits in 62-bit varint"),
                final_size: VarInt::new(final_size).expect("value fits in 62-bit varint"),
            },
        ));

        self.events.push_back(StreamEvent::StreamStopSending {
            stream_id: f.stream_id.as_u64(),
            error_code: f.application_protocol_error_code.as_u64(),
        });

        Ok(())
    }

    /// MAX_STREAM_DATA フレームを処理する
    pub fn on_max_stream_data(
        &mut self,
        f: &frame::max_stream_data::MaxStreamData,
    ) -> Result<(), Error> {
        if self.is_gc_closed(f.stream_id.as_u64()) {
            return Ok(());
        }
        // RFC 9000 Section 19.10: 未作成のローカル起動ストリーム宛 MAX_STREAM_DATA の
        // 受信は STREAM_STATE_ERROR で接続を閉じる MUST。ensure_peer_stream と同じ
        // 導出でローカル起動かを判定し、未作成ならエラーにする。共通化を待たず
        // 本ハンドラ単独で完結させる (判定式は複製してよい)。
        let stream_type = StreamType::from_id(f.stream_id.as_u64());
        let is_peer_initiated = match self.role {
            Role::Client => stream_type.is_server_initiated(),
            Role::Server => stream_type.is_client_initiated(),
        };
        if !is_peer_initiated {
            // ローカル起動ストリームは open_bidi / open_uni が連番で作成するため、
            // 作成済みのシーケンス番号は [0, next_local_*_seq) に隙間なく並ぶ。
            // よって閾値比較だけで未作成を判定できる。
            let next_local_seq = if stream_type.is_bidirectional() {
                self.next_local_bidi_seq
            } else {
                self.next_local_uni_seq
            };
            if stream_sequence(f.stream_id.as_u64()) >= next_local_seq {
                return Err(Error::Protocol {
                    code: TransportErrorCode::STREAM_STATE_ERROR,
                    reason: format!(
                        "MAX_STREAM_DATA for locally initiated stream {} that has not yet been created",
                        f.stream_id
                    ),
                });
            }
        }

        // RFC 9000 Section 3: 未作成のピア起動 bidi ストリーム宛 MAX_STREAM_DATA の
        // 受信は受信側がストリームを開く。ピア起動 uni もここで生成し、後段の
        // receive-only 判定で STREAM_STATE_ERROR にする (未作成ピア uni 宛の黙殺を
        // 残さない)。ストリーム数制限超過は ensure_peer_stream の
        // STREAM_LIMIT_ERROR に委ねる。
        self.ensure_peer_stream(f.stream_id.as_u64())?;

        // ensure_peer_stream 成功後はストリームの存在が保証される。
        let stream = self
            .streams
            .get_mut(&f.stream_id.as_u64())
            .expect("stream must exist after ensure_peer_stream; None is an implementation bug");

        // RFC 9000 Section 19.10: receive-only ストリーム (ピア起動 uni) 宛
        // MAX_STREAM_DATA は STREAM_STATE_ERROR で接続を閉じる MUST。作成済みと
        // ensure_peer_stream が今回生成したものの両方を send_state の None で捕捉する。
        if stream.send_state.is_none() {
            return Err(Error::Protocol {
                code: TransportErrorCode::STREAM_STATE_ERROR,
                reason: format!("MAX_STREAM_DATA for receive-only stream {}", f.stream_id),
            });
        }

        // 上限の増加のみ受け入れる (RFC 9000 Section 4.1)
        if f.maximum_stream_data > stream.send_max_data {
            stream.send_max_data = f.maximum_stream_data.as_u64();
            self.events.push_back(StreamEvent::StreamWritable {
                stream_id: f.stream_id.as_u64(),
            });
        }
        Ok(())
    }

    /// MAX_STREAMS フレームを処理する
    pub fn on_max_streams(&mut self, f: &frame::max_streams::MaxStreams) -> Result<(), Error> {
        // RFC 9000 Section 19.11: maximum_streams は 2^60 を超えてはならない。
        // 超過値は FRAME_ENCODING_ERROR または STREAM_LIMIT_ERROR で接続を閉じる MUST。
        if f.maximum_streams > (1u64 << 60) {
            return Err(Error::Protocol {
                code: tobi_core::error::TransportErrorCode::FRAME_ENCODING_ERROR,
                reason: format!(
                    "MAX_STREAMS maximum_streams {} exceeds 2^60",
                    f.maximum_streams
                ),
            });
        }

        // 上限の増加のみ受け入れる (RFC 9000 Section 4.6)
        if f.bidirectional {
            if f.maximum_streams > self.peer_max_streams_bidi {
                self.peer_max_streams_bidi = f.maximum_streams.as_u64();
            }
        } else if f.maximum_streams > self.peer_max_streams_uni {
            self.peer_max_streams_uni = f.maximum_streams.as_u64();
        }
        Ok(())
    }

    /// MAX_DATA フレームを処理する
    pub fn on_max_data(&mut self, maximum_data: u64) {
        if maximum_data > self.send_max_data {
            self.send_max_data = maximum_data;
        }
    }

    /// STREAM_DATA_BLOCKED フレームを処理する
    ///
    /// send-only ストリーム (自身が起動した単方向ストリーム) 宛の
    /// STREAM_DATA_BLOCKED は STREAM_STATE_ERROR で接続を閉じる
    /// (RFC 9000 Section 19.13 MUST)。それ以外は情報提供のみで
    /// アクションを起こさない (RFC 9000 Section 4.1)。
    pub fn on_stream_data_blocked(
        &mut self,
        f: &frame::stream_data_blocked::StreamDataBlocked,
    ) -> Result<(), Error> {
        if self.is_gc_closed(f.stream_id.as_u64()) {
            return Ok(());
        }
        let stream_type = StreamType::from_id(f.stream_id.as_u64());
        let is_local_initiated = match self.role {
            Role::Client => stream_type.is_client_initiated(),
            Role::Server => stream_type.is_server_initiated(),
        };
        if is_local_initiated && stream_type.is_unidirectional() {
            return Err(Error::Protocol {
                code: TransportErrorCode::STREAM_STATE_ERROR,
                reason: format!("STREAM_DATA_BLOCKED for send-only stream {}", f.stream_id),
            });
        }
        Ok(())
    }

    /// STREAMS_BLOCKED フレームを処理する (情報提供のみ)
    ///
    /// RFC 9000 Section 19.14: Maximum Streams は 2^60 を超えてはならない。
    /// 超過値は STREAM_LIMIT_ERROR または FRAME_ENCODING_ERROR で接続を閉じる
    /// (MUST)。MAX_STREAMS の検証と同じく FRAME_ENCODING_ERROR を使う。
    pub fn on_streams_blocked(
        &mut self,
        f: &frame::streams_blocked::StreamsBlocked,
    ) -> Result<(), Error> {
        if f.maximum_streams > (1u64 << 60) {
            return Err(Error::Protocol {
                code: TransportErrorCode::FRAME_ENCODING_ERROR,
                reason: format!(
                    "STREAMS_BLOCKED maximum_streams {} exceeds 2^60",
                    f.maximum_streams
                ),
            });
        }
        // RFC 9000 Section 4.6: 情報提供フレーム、アクション不要
        Ok(())
    }

    /// 接続レベルの受信上限 (recv_max_data) を返す
    /// RFC 9000 Section 13.3: MAX_DATA ロスト時の再送で使用する
    pub fn recv_max_data(&self) -> u64 {
        self.recv_max_data
    }

    /// 指定ストリームの受信上限 (recv_max_data) を返す
    /// RFC 9000 Section 13.3: MAX_STREAM_DATA ロスト時の再送で使用する
    /// ストリームが存在しない場合は None を返す
    pub fn recv_max_stream_data(&self, stream_id: u64) -> Option<u64> {
        self.streams.get(&stream_id).map(|s| s.recv_max_data)
    }

    /// リセット済みストリームの最終サイズを返す
    ///
    /// RESET_STREAM で確定した final_size を返す。リセットを受けていない
    /// ストリームや存在しないストリームの場合は `None` を返す。
    pub fn recv_final_size(&self, stream_id: u64) -> Option<u64> {
        let stream = self.streams.get(&stream_id)?;
        // FIN でも final_size は設定されるため、リセット受信済みのストリームに
        // 限って返す。
        stream.recv_reset_error_code?;
        stream.recv_buf.as_ref()?.final_size()
    }

    /// ピアが RESET_STREAM で通知したエラーコードを返す
    ///
    /// ピアがストリームをリセットしていない場合や、ストリームが存在しない
    /// 場合は `None` を返す。アプリへ `StreamError::Reset` を返すために使う。
    pub fn recv_reset_error_code(&self, stream_id: u64) -> Option<u64> {
        self.streams
            .get(&stream_id)
            .and_then(|s| s.recv_reset_error_code)
    }

    /// ピアが RESET_STREAM_AT で通知した Reliable Size を返す
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 4 / Section 5。
    /// RESET_STREAM_AT を受信していない場合、ストリームが存在しない場合、
    /// RESET_STREAM によるリセットの場合は `None` を返す。`Some(0)` は
    /// RESET_STREAM_AT が Reliable Size 0 を宣言したことを表し、
    /// RESET_STREAM とは区別される。
    pub fn recv_reset_at_reliable_size(&self, stream_id: u64) -> Option<u64> {
        self.streams
            .get(&stream_id)
            .and_then(|s| s.recv_reset_at_reliable_size)
    }

    /// ストリームの送信側がアプリからの書き込みを受け付けない状態かを返す
    ///
    /// FIN を送信済み (DataSent / DataRecvd) またはリセット済み
    /// (ResetSent / ResetRecvd) の場合に `true` を返す。GC 済みのストリームも
    /// 保持されていないため、`gc_watermarks` で終端済みと判定して `true` を
    /// 返す。追加送信の拒否を `StreamError::FinishedSending` として扱うために使う。
    pub fn send_finished(&self, stream_id: u64) -> bool {
        if self.is_gc_closed(stream_id) {
            return true;
        }
        self.streams.get(&stream_id).is_some_and(|s| {
            matches!(
                s.send_state,
                Some(
                    SendState::DataSent
                        | SendState::DataRecvd
                        | SendState::ResetSent
                        | SendState::ResetRecvd
                )
            )
        })
    }

    /// ピアが STOP_SENDING で通知したエラーコードを返す
    ///
    /// ピアが送信停止を要求していない場合は `None` を返す。アプリへ
    /// `StreamError::Stopped` を返すために使う。
    pub fn send_stopped_error_code(&self, stream_id: u64) -> Option<u64> {
        self.streams
            .get(&stream_id)
            .and_then(|s| s.peer_stop_sending_error_code)
    }

    /// ローカルが許容する双方向ストリームの最大数を返す
    /// RFC 9000 Section 13.3: MAX_STREAMS ロスト時の再送で使用する
    pub fn local_max_streams_bidi(&self) -> u64 {
        self.local_max_streams_bidi
    }

    /// ローカルが許容する単方向ストリームの最大数を返す
    /// RFC 9000 Section 13.3: MAX_STREAMS ロスト時の再送で使用する
    pub fn local_max_streams_uni(&self) -> u64 {
        self.local_max_streams_uni
    }

    /// ロストした STREAM フレームのデータを再送キューに追加する
    ///
    /// `meta` は元の送信パスとロスト理由を保持し、送信時の再送パス選択
    /// (`RetransmissionPolicy::decide_retx`) に渡す。
    ///
    /// 終端状態の判定だけをここで行い、ACK 済み範囲の除外、Reliable Size に
    /// よる切り詰め、FIN の再送可否の判定は `SendBuffer::mark_lost` に任せる。
    /// これらの状態は `reset_stream` / `reset_stream_at` / `on_stop_sending` /
    /// `demote_unsupported_reset_stream_at` の各リセット経路が
    /// `SendBuffer::trim_retransmit_for_reliable_size` で反映済みであり、
    /// ここで再度判定すると同じ規則が二重になる。
    pub fn mark_lost(
        &mut self,
        stream_id: u64,
        offset: u64,
        length: usize,
        fin: bool,
        meta: RetxMeta,
    ) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        // 送信側が終端状態に達した後は、遅延したロスト判定で再送を復活させない
        // (RFC 9000 Section 3.1)。
        if matches!(
            stream.send_state,
            Some(SendState::DataRecvd | SendState::ResetRecvd)
        ) {
            return;
        }
        let Some(send_buf) = stream.send_buf.as_mut() else {
            return;
        };
        // draft-ietf-quic-reliable-stream-reset-11 Section 5:
        // RESET_STREAM_AT / RESET_STREAM 後の Reliable Size 超過分は
        // SendBuffer 側で保持データから既に切り詰められている。FIN も
        // リセット後は再送不要として無視される。
        send_buf.mark_lost(offset, length, fin, meta);
    }

    /// 次に再送する STREAM データの情報を返す
    ///
    /// ストリーム ID の昇順で最初に再送待ちを持つストリームを選ぶ。
    /// 返り値はそのまま `write_retransmit_frame` に渡せる。
    /// 再送パス選択ポリシーはこの情報を使って送信パスを決める。
    pub fn next_retransmit(&self) -> Option<RetxTarget> {
        let mut stream_ids: Vec<u64> = self.streams.keys().copied().collect();
        stream_ids.sort_unstable();
        for stream_id in stream_ids {
            let Some(stream) = self.streams.get(&stream_id) else {
                continue;
            };
            let Some(send_buf) = stream.send_buf.as_ref() else {
                continue;
            };
            if let Some(info) = send_buf.pending_retransmit_info() {
                return Some(RetxTarget { stream_id, info });
            }
        }
        None
    }

    /// 未送信の STREAM データが残っているかを返す
    ///
    /// フロー制御で今すぐ送れない場合も「未送信データあり」として true を返す。
    /// BBR の CheckIfApplicationLimited が「送信可能なアプリケーションデータが
    /// 無い」ことを判定するために使う
    /// (draft-ietf-ccwg-bbr-06 Section 4.1.2.4)。
    pub fn has_unsent_data(&self) -> bool {
        self.streams.values().any(|stream| {
            let Some(send_state) = stream.send_state else {
                return false;
            };
            let Some(send_buf) = stream.send_buf.as_ref() else {
                return false;
            };
            // RESET_STREAM_AT 送信後は DataSent でも Reliable Size までの
            // 未送信データが残りうる (draft-ietf-quic-reliable-stream-reset-11
            // Section 5 MUST)。
            let reset_at_pending_data = send_state == SendState::DataSent
                && stream
                    .reset_at_reliable_size
                    .is_some_and(|reliable| send_buf.send_offset() < reliable);
            if !matches!(send_state, SendState::Ready | SendState::Send) && !reset_at_pending_data {
                return false;
            }
            // max_len に上限を渡さず、フロー制御バジェットを無視して
            // 未送信バイトまたは未送信 FIN の有無だけを見る。
            send_buf.pending_data(usize::MAX).is_some()
        })
    }

    /// バッファ済みの未送信データがフロー制御だけで止まっているか
    ///
    /// 受理済みデータの接続全体クレジットは `send()` の時点で予約されているため、
    /// 送信可否はストリーム単位のクレジットだけで決まる。未送信データがあり、
    /// どのストリームも 1 バイト送れない場合に true を返す。FIN だけが未送信の
    /// 場合はフロー制御で止まらないため false を返す。
    pub fn unsent_data_flow_control_blocked(&self) -> bool {
        let mut has_pending = false;
        for stream in self.streams.values() {
            let Some(send_state) = stream.send_state else {
                continue;
            };
            let Some(send_buf) = stream.send_buf.as_ref() else {
                continue;
            };
            let reset_at_pending_data = send_state == SendState::DataSent
                && stream
                    .reset_at_reliable_size
                    .is_some_and(|reliable| send_buf.send_offset() < reliable);
            if !matches!(send_state, SendState::Ready | SendState::Send) && !reset_at_pending_data {
                continue;
            }
            let Some((offset, data, _fin)) = send_buf.pending_data(usize::MAX) else {
                continue;
            };
            if data.is_empty() {
                return false;
            }
            has_pending = true;
            if stream.send_max_data.saturating_sub(offset) > 0 {
                return false;
            }
        }
        has_pending
    }

    /// 接続全体の送信クレジットの残量を返す
    ///
    /// 再送先パスの PMTU が元パスより小さくても収まるよう、STREAM フレームの
    /// データ長を `max_payload` に合わせて分割する。分割した残りは再送キューに
    /// 残り、次の送信機会に改めて再送される。cross-path 再送で PMTU の異なる
    /// パスへ送る場合の再分割はこの経路で行う。
    ///
    /// 再送対象が `next_retransmit` の結果から変わっていた場合は `None`。
    pub fn write_retransmit_frame(
        &mut self,
        payload: &mut Vec<u8>,
        max_payload: usize,
        target: &RetxTarget,
    ) -> Option<StreamFrameOut> {
        let remaining = max_payload.saturating_sub(payload.len());
        // STREAM フレームの最悪ヘッダ長 (stream_id / offset / length の varint) を確保する
        let overhead = 25;
        if remaining <= overhead {
            return None;
        }
        let max_data_len = remaining - overhead;

        let stream = self.streams.get(&target.stream_id)?;
        let send_buf = stream.send_buf.as_ref()?;
        let (offset, data, fin) = send_buf.pending_retransmit(max_data_len)?;
        if offset != target.info.offset {
            return None;
        }

        let data_len = data.len();
        let stream_frame = frame::stream::Stream {
            stream_id: VarInt::new(target.stream_id).expect("value fits in 62-bit varint"),
            offset: VarInt::new(offset).expect("value fits in 62-bit varint"),
            fin,
            data: data.to_vec(),
        };

        let before_len = payload.len();
        frame::Frame::Stream(stream_frame).encode(payload);
        let encoded_len = payload.len() - before_len;

        if payload.len() > max_payload {
            payload.truncate(before_len);
            return None;
        }

        let stream = self.streams.get_mut(&target.stream_id)?;
        let send_buf = stream.send_buf.as_mut()?;
        send_buf.mark_retransmit_sent(offset, data_len, fin);

        Some(StreamFrameOut {
            stream_id: target.stream_id,
            offset,
            length: data_len,
            fin,
            encoded_len,
            // このフレームは 1 回再送されたので、再送回数を 1 つ進める
            retransmission_count: target.info.meta.after_retransmit().retransmission_count,
        })
    }

    /// 再送済み範囲のデータを取得する
    ///
    /// `RetxDecision::Duplicate` で同じデータをもう 1 つのパスへ複製送信
    /// するときに使う。範囲外なら `None`。
    pub fn retransmit_data(&self, stream_id: u64, offset: u64, length: usize) -> Option<&[u8]> {
        let stream = self.streams.get(&stream_id)?;
        stream.send_buf.as_ref()?.data_at(offset, length)
    }

    /// パケット化したフレームの所有を未出力として保持する。
    pub(crate) fn reserve_queued_frame(&mut self, stream_id: u64) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.send_queued_count += 1;
        }
    }

    /// 実出力または取り消しにより、未出力フレームの予約を解放する。
    pub(crate) fn release_queued_frame(&mut self, stream_id: u64) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.send_queued_count = stream.send_queued_count.saturating_sub(1);
        }
    }

    /// RESET_STREAM_AT を送信キューから取り出したときに呼ぶ
    ///
    /// 送信キューに残っている間は Data Recvd への遷移を保留するため、
    /// 実際にパケットへ書き込んだ時点でフラグを下ろす。
    pub fn mark_reset_stream_at_sent(&mut self, stream_id: u64) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.reset_at_frame_queued = false;
        }
    }

    /// ACK された RESET_STREAM_AT を記録し、送信側の終端遷移を試みる
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 5.2 / Section 5.3:
    /// Data Recvd への遷移条件は「現在の最小 Reliable Size を持つ
    /// RESET_STREAM_AT が ACK されること」である。Reliable Size を縮小した
    /// 場合、より大きい Reliable Size を持つ古いフレームの ACK で条件を
    /// 満たしてはならないため、ACK されたフレームの Reliable Size が現在値と
    /// 一致する場合にのみ ACK 済みフラグを立てる。
    ///
    /// 同じ Reliable Size のフレームが再送待ちで送信キューに残っていても、
    /// 現在のリセット情報がピアへ届いたことは変わらないため ACK 済みとして
    /// 扱う。残っている再送は終端遷移の時点で破棄する (RFC 9000 Section 3.3)。
    pub fn on_reset_stream_at_acked(&mut self, stream_id: u64, reliable_size: u64) {
        if let Some(stream) = self.streams.get_mut(&stream_id)
            && stream.reset_at_reliable_size == Some(reliable_size)
        {
            stream.reset_at_frame_acked = true;
        }
        self.try_transition_send_terminal(stream_id);
    }

    /// ACK された STREAM フレームの ACK 範囲を記録し、送信側の終端遷移を試みる
    ///
    /// ACK された `(offset, length)` を送信バッファへ記録し、ACK 済み範囲を
    /// 再送待ちと保持データから取り除く (RFC 9000 Section 13.3)。同じパケットに
    /// 複数の STREAM フレームが含まれる場合も、フレームごとに ACK 範囲が
    /// 異なるため個別に処理する。
    ///
    /// RFC 9002 Section 6.1: ロスト判定は後から覆ることがある。ロスト判定済み
    /// パケットの STREAM フレームが後から ACK された場合も、ACK された情報は
    /// 再送しなくてよい (RFC 9000 Section 13.3) ため、同じ処理で ACK 済み範囲を
    /// 記録して終端遷移を試みる。
    pub fn on_stream_frame_acked(&mut self, stream_id: u64, offset: u64, length: usize, fin: bool) {
        self.acknowledge_stream_frame(stream_id, offset, length, fin);
        self.try_transition_send_terminal(stream_id);
    }

    /// ACK された STREAM フレームの範囲を送信バッファへ記録する
    ///
    /// 終端遷移は呼び出し側が記録の後に行う。
    fn acknowledge_stream_frame(&mut self, stream_id: u64, offset: u64, length: usize, fin: bool) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let Some(send_buf) = stream.send_buf.as_mut() else {
            return;
        };
        send_buf.acknowledge(offset, length, fin);
    }

    /// ACK された RESET_STREAM フレームを記録し、送信側の終端遷移を試みる
    ///
    /// RESET_STREAM は STREAM データの ACK 範囲を持たないため、送信バッファの
    /// ACK 範囲は更新しない。RESET_STREAM は Reliable Size 0 の
    /// RESET_STREAM_AT と等価である (draft-ietf-quic-reliable-stream-reset-11
    /// Section 5)。ResetSent の間は現在の Reliable Size も 0 であるため、
    /// この ACK で現在のリセット情報が ACK されたものとして扱う。
    pub fn on_reset_stream_acked(&mut self, stream_id: u64) {
        if let Some(stream) = self.streams.get_mut(&stream_id)
            && stream.send_state == Some(SendState::ResetSent)
        {
            stream.reset_at_frame_acked = true;
        }
        self.try_transition_send_terminal(stream_id);
    }

    /// 送信側が終端状態 (DataRecvd / ResetRecvd) か
    pub(crate) fn is_send_terminal(&self, stream_id: u64) -> bool {
        self.streams
            .get(&stream_id)
            .and_then(|stream| stream.send_state)
            .is_some_and(SendState::is_terminal)
    }

    /// 未出力の予約が無く、再送待ちと保持データが無く、必要なフレームが
    /// ACK 済みのストリームの終端遷移を試みる
    ///
    /// DataSent → DataRecvd は、RESET_STREAM_AT を送ったストリームでは
    /// 「現在の最小 Reliable Size を持つフレームが ACK 済み」「Reliable Size
    /// までのデータを送信済み」「保持データが無い」「再送待ちが無い」ことを
    /// 確認する。FIN 経路では FIN が ACK 済みであることも確認する。
    /// ResetSent → ResetRecvd は現在のリセット情報の ACK で遷移する。
    /// RESET_STREAM の ACK、または Reliable Size 0 の RESET_STREAM_AT の
    /// ACK がこれに当たる。RESET_STREAM_AT を使ったストリームでも
    /// reset_stream / STOP_SENDING 応答 / 0-RTT 降格で ResetSent になり得る。
    ///
    /// 判定は送信フレームの in-flight 件数ではなく、送信バッファが保持する
    /// ACK 済み範囲と再送待ちの状態で行う。再送キューから再送した STREAM
    /// フレームのうち 1 つが ACK されれば、その範囲は ACK 済みであり再送は
    /// 不要になる (RFC 9000 Section 13.3)。in-flight の件数を待つと、ACK が
    /// 先に届いて元パケットが後からロスト判定される場合に終端遷移が起きない。
    /// 冗長スケジューラで複製送信したパケットの ACK 会計は、この判定の対象外
    /// とする。
    ///
    /// # 呼び出し順序
    ///
    /// ロスト・破棄・キャンセルの各経路では、状態を変える処理をすべて終えた
    /// 後に呼ぶこと。具体的には、再送キューへの復元 (`mark_lost`)、未出力の
    /// 予約の解放 (`release_queued_frame`)、ACK 済み範囲の記録 (`acknowledge`)
    /// が済んでいる必要がある。この順序を守らないと、まだ再送待ちや保持データ
    /// が残っている状態を終端と誤判定するか、逆に遷移可能な状態を見逃す。
    ///
    /// 終端状態へ遷移した時点で送信バッファの保持データを解放し、未送信の
    /// リセットフレームも破棄する。通常は ACK の trim や RESET_STREAM の trim で
    /// 解放済みであり、ここでの解放は終端状態で保持データを残さないための防御で
    /// ある。GC まで待たないため、ピアが受信側ストリームを長く開いたままでも
    /// 送信データは残らない。
    pub(crate) fn try_transition_send_terminal(&mut self, stream_id: u64) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        // パケット化済みでまだ実送信していないフレームがある間は、送信後に
        // 状態が変わり得るため遷移しない。
        if stream.send_queued_count > 0 {
            return;
        }
        let next_state = match stream.send_state {
            Some(SendState::DataSent) => {
                let Some(send_buf) = stream.send_buf.as_ref() else {
                    return;
                };
                // 再送待ちデータがないことを確認する
                if send_buf.has_pending_retransmit() {
                    return;
                }
                // 保持データが残っている間は、まだ ACK されていない範囲がある。
                // ACK 済みの先頭連続範囲は SendBuffer が解放済みである。
                if send_buf.retained_len() > 0 {
                    return;
                }
                if let Some(reliable) = stream.reset_at_reliable_size {
                    // 現在の Reliable Size を持つフレームの ACK が確認できるまで
                    // 遷移しない。同じ Reliable Size のフレームが再送待ちで
                    // 残っていても、その Reliable Size の ACK が届いていれば
                    // 現在のリセット情報はピアへ届いており再送は不要である。
                    if !stream.reset_at_frame_acked {
                        return;
                    }
                    // 内部の経路ではここへ到達しない防御である。保持データが 0 で
                    // 再送待ちも無いなら、Reliable Size までのデータはすべて
                    // ACK 済みであり、Reliable Size を超えるデータは
                    // `trim_retransmit_for_reliable_size` で解放済みのため、
                    // `send_offset` は必ず Reliable Size 以上になる。将来この
                    // 不変条件が崩れたときに終端状態へ誤遷移しないように残す。
                    if send_buf.send_offset() < reliable {
                        return;
                    }
                } else if !send_buf.is_fin_acked() {
                    // FIN 経路では FIN 自体が ACK 済みであることを確認する。
                    return;
                }
                Some(SendState::DataRecvd)
            }
            Some(SendState::ResetSent) => {
                // RESET_STREAM / RESET_STREAM_AT の ACK が確認できるまで遷移
                // しない。ロスト判定だけでは Reset Recvd にならない
                // (RFC 9000 Section 3.1)。
                if !stream.reset_at_frame_acked {
                    return;
                }
                Some(SendState::ResetRecvd)
            }
            _ => None,
        };
        let Some(next_state) = next_state else {
            return;
        };
        stream.send_state = Some(next_state);
        // 終端状態では現在のリセット情報を送り直さないため、送信待ちの印も
        // 落とす。送信キューに残っているフレームは下の
        // `discard_pending_reset_frames` で破棄する (RFC 9000 Section 3.3)。
        stream.reset_at_frame_queued = false;
        // 通常は ACK による trim や RESET_STREAM の trim で解放済みである。
        // ここでの解放は、終端状態へ遷移した以上は保持データを残さないための
        // 防御であり、GC まで送信データを保持しないことを保証する
        // (RFC 9000 Section 3.1, Section 13.3)。
        if let Some(send_buf) = stream.send_buf.as_mut() {
            send_buf.release_all();
        }
        // 終端状態では RESET_STREAM / RESET_STREAM_AT を送信してはならない
        // (RFC 9000 Section 3.3)。ロスト再送で積まれた未送信のリセットも
        // ここで破棄する。
        self.discard_pending_reset_frames(stream_id);
    }

    /// 指定ストリームの未送信リセットフレームを送信キューから取り除く
    ///
    /// 終端状態へ遷移した後はリセットを再送しない (RFC 9000 Section 3.3)。
    /// 予約済みで実送信前のフレームは `send_queued_count` が残るため、
    /// 呼び出し側は予約が無いことを確認してからこのメソッドを呼ぶ。
    fn discard_pending_reset_frames(&mut self, stream_id: u64) {
        self.pending_frames.retain(|frame| match frame {
            frame::Frame::ResetStream(reset) => reset.stream_id.as_u64() != stream_id,
            frame::Frame::ResetStreamAt(reset) => reset.stream_id.as_u64() != stream_id,
            _ => true,
        });
    }

    /// ロストした RESET_STREAM_AT を、現在の Reliable Size で再キューする
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 4: ロストした
    /// RESET_STREAM_AT は Data Recvd / Reset Recvd へ遷移済みでない限り
    /// 再送しなければならない (MUST)。Section 5.2: 再送する情報は送信時の
    /// ものではなく、現在の最小 Reliable Size を持つフレームのものでなければ
    /// ならない (MUST)。送信キューに既にフレームがある場合は、それが現在の
    /// 情報を運ぶため重複して積まない。
    pub fn requeue_reset_stream_at(
        &mut self,
        stream_id: u64,
    ) -> Option<frame::reset_stream_at::ResetStreamAt> {
        let stream = self.streams.get_mut(&stream_id)?;
        // DataSent 以外 (DataRecvd / ResetSent / ResetRecvd) では再送しない
        if stream.send_state != Some(SendState::DataSent) {
            return None;
        }
        if stream.reset_at_frame_queued {
            return None;
        }
        let reliable_size = stream.reset_at_reliable_size?;
        let error_code = stream.reset_at_error_code?;
        let final_size = stream.reset_at_final_size?;
        // 再送したフレームが ACK されるまで Data Recvd へ遷移させない
        stream.reset_at_frame_queued = true;
        stream.reset_at_frame_acked = false;
        Some(frame::reset_stream_at::ResetStreamAt {
            stream_id: VarInt::new(stream_id).expect("value fits in 62-bit varint"),
            application_protocol_error_code: VarInt::new(error_code)
                .expect("value fits in 62-bit varint"),
            final_size: VarInt::new(final_size).expect("value fits in 62-bit varint"),
            reliable_size: VarInt::new(reliable_size).expect("value fits in 62-bit varint"),
        })
    }

    /// 送信可能な STREAM フレームをペイロードバッファに書き込む
    ///
    /// 再送データを通常データより優先する。
    /// 各ストリームの SendBuffer から未送信データを取得し、
    /// ストリームレベル・接続レベルのフロー制御を考慮して
    /// STREAM フレームとしてエンコードする。
    /// 返り値は SentPacket 記録用のフレーム情報リスト。
    ///
    /// この関数は再送パス選択を行わない経路 (0-RTT など) 用である。
    /// 1-RTT の再送は `next_retransmit` と `write_retransmit_frame` を使い、
    /// 選択した送信パスの PMTU に合わせて再分割する。
    pub fn write_stream_frames(
        &mut self,
        payload: &mut Vec<u8>,
        max_payload: usize,
    ) -> Vec<StreamFrameOut> {
        let mut result = Vec::new();

        // 再送待ちのストリーム ID を先に収集する
        let retransmit_ids: Vec<u64> = self
            .streams
            .iter()
            .filter_map(|(&id, stream)| {
                let send_buf = stream.send_buf.as_ref()?;
                if send_buf.has_pending_retransmit() {
                    Some(id)
                } else {
                    None
                }
            })
            .collect();

        // 再送データを優先して書き込む
        for stream_id in retransmit_ids {
            let Some(stream) = self.streams.get(&stream_id) else {
                continue;
            };
            let Some(send_buf) = stream.send_buf.as_ref() else {
                continue;
            };
            let Some(info) = send_buf.pending_retransmit_info() else {
                continue;
            };
            let target = RetxTarget { stream_id, info };
            if let Some(out) = self.write_retransmit_frame(payload, max_payload, &target) {
                result.push(out);
            }
        }

        // 通常の未送信データを書き込む
        result.extend(self.write_new_data_frames(payload, max_payload));
        result
    }

    /// 未送信の STREAM データをペイロードバッファに書き込む
    ///
    /// 接続レベルのフロー制御 (RFC 9000 Section 4.1) は `send()` で
    /// `send_data_total` を増やすときに既に適用済みなので、ここでは
    /// ストリームレベルのバジェットのみチェックする。接続レベルのチェックを
    /// ここでも行うと、`send()` が `send_max_data` 一杯までバッファに書き込んだ
    /// 直後、`write_new_data_frames` 側で `conn_budget == 0` となり、
    /// バッファに滞留したデータが一切フレーム化されない不具合が生じる。
    pub fn write_new_data_frames(
        &mut self,
        payload: &mut Vec<u8>,
        max_payload: usize,
    ) -> Vec<StreamFrameOut> {
        let mut result = Vec::new();

        let mut stream_ids: Vec<u64> = self
            .streams
            .iter()
            .filter_map(|(&id, stream)| {
                let send_state = stream.send_state?;
                let send_buf = stream.send_buf.as_ref()?;
                // RESET_STREAM_AT 送信後は DataSent のままでも、Reliable Size
                // までの未送信データを送り切る必要がある
                // (draft-ietf-quic-reliable-stream-reset-11 Section 5 MUST)。
                // FIN 送信済みの DataSent は send_offset == write_offset のため
                // 下の Reliable Size 判定で送信対象にならない。
                let reliable_limit = stream.reset_at_reliable_size;
                let reset_at_pending_data = send_state == SendState::DataSent
                    && reliable_limit.is_some_and(|reliable| send_buf.send_offset() < reliable);
                if !matches!(send_state, SendState::Ready | SendState::Send)
                    && !reset_at_pending_data
                {
                    return None;
                }
                let stream_budget = stream.send_max_data.saturating_sub(send_buf.send_offset());
                let mut max_len = stream_budget as usize;
                if let Some(reliable) = reliable_limit {
                    // Reliable Size を超えるデータは送信しない。RESET_STREAM_AT は
                    // 終端を通知するため FIN も送らない。
                    let reliable_remaining = reliable.saturating_sub(send_buf.send_offset());
                    max_len = max_len.min(reliable_remaining as usize);
                }
                if send_buf.pending_data(max_len).is_some() {
                    Some(id)
                } else {
                    None
                }
            })
            .collect();

        // HashMap の順序を毎回使うと、大きな転送が他のストリームを送り切るまで
        // 占有する。前回の次の ID から巡回し、各パケットで順番に送信機会を渡す。
        // 前回のストリームが終了・削除されていても、その次から進められる。
        stream_ids.sort_unstable();
        if let Some(last) = self.last_new_data_stream {
            let next = stream_ids.partition_point(|id| *id <= last);
            stream_ids.rotate_left(next);
        }

        for stream_id in stream_ids {
            if payload.len() >= max_payload {
                break;
            }
            let remaining = max_payload - payload.len();
            let overhead = 25;
            if remaining <= overhead {
                break;
            }
            let max_data_len = remaining - overhead;

            let stream = self
                .streams
                .get(&stream_id)
                .expect("送信待ちストリームが存在する");
            let send_buf = stream.send_buf.as_ref().expect("送信バッファが存在する");

            // 接続レベルのバジェットは `send()` 側で消費済みなので再チェックしない。
            let stream_budget = stream.send_max_data.saturating_sub(send_buf.send_offset());
            let mut max_len = max_data_len.min(stream_budget as usize);
            if let Some(reliable) = stream.reset_at_reliable_size {
                // Reliable Size を超えるデータを送らない (Section 5)
                let reliable_remaining = reliable.saturating_sub(send_buf.send_offset());
                max_len = max_len.min(reliable_remaining as usize);
            }

            let Some((offset, data, fin)) = send_buf.pending_data(max_len) else {
                continue;
            };
            // RESET_STREAM_AT は Final Size を運ぶため、FIN は送らない
            let fin = fin && stream.reset_at_reliable_size.is_none();

            let data_len = data.len();
            let stream_frame = frame::stream::Stream {
                stream_id: VarInt::new(stream_id).expect("value fits in 62-bit varint"),
                offset: VarInt::new(offset).expect("value fits in 62-bit varint"),
                fin,
                data: data.to_vec(),
            };

            let before_len = payload.len();
            frame::Frame::Stream(stream_frame).encode(payload);
            let encoded_len = payload.len() - before_len;

            if payload.len() > max_payload {
                payload.truncate(before_len);
                break;
            }

            let stream = self
                .streams
                .get_mut(&stream_id)
                .expect("送信待ちストリームが存在する");
            let send_buf = stream.send_buf.as_mut().expect("送信バッファが存在する");
            send_buf.mark_sent(data_len, fin);
            self.last_new_data_stream = Some(stream_id);

            if let Some(state) = stream.send_state {
                if state == SendState::Ready && (data_len > 0 || fin) {
                    stream.send_state = Some(SendState::Send);
                }
                if fin && stream.send_state == Some(SendState::Send) {
                    stream.send_state = Some(SendState::DataSent);
                }
            }

            result.push(StreamFrameOut {
                stream_id,
                offset,
                length: data_len,
                fin,
                encoded_len,
                // 未送信データの初回送信なので再送回数は 0
                retransmission_count: 0,
            });
        }

        result
    }

    /// リセットフレームが現在のフロー制御上限に収まるかを判定する
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 4:
    /// 「受信側が広告したそのストリームの最大ストリームデータ値を超える、
    /// または受信側の最大データ制限に違反する RESET_STREAM_AT を送っては
    /// ならない (MUST NOT)。したがって送信側は、ストリームまたは接続レベルの
    /// フロー制御クレジットが十分になるまで RESET_STREAM_AT の送信を延期する
    /// 必要がある場合がある」。
    ///
    /// 0-RTT 拒否後に確定した peer transport parameter が記憶値より小さい場合、
    /// 送信キューに残っているリセットフレームが上限を超えることがある。
    /// その場合は false を返し、クレジットが増えるまで送信を延期する。
    /// 送信待ちフレームがフロー制御で送れないリセットフレームだけか
    ///
    /// `pending_frames` が空でない場合に、送信可能なフレームが 1 つも
    /// 残っていないかを判定する。リセット以外のフレームはフロー制御の
    /// 対象外として送信可能と扱う。
    pub fn pending_frames_flow_control_blocked(&self) -> bool {
        !self.pending_frames.is_empty()
            && self
                .pending_frames
                .iter()
                .all(|frame| !self.reset_frame_fits_flow_control(frame))
    }

    pub fn reset_frame_fits_flow_control(&self, frame: &frame::Frame) -> bool {
        let (stream_id, final_size) = match frame {
            frame::Frame::ResetStream(reset) => {
                (reset.stream_id.as_u64(), reset.final_size.as_u64())
            }
            frame::Frame::ResetStreamAt(reset) => {
                (reset.stream_id.as_u64(), reset.final_size.as_u64())
            }
            // リセット以外のフレームは対象外
            _ => return true,
        };
        let Some(stream) = self.streams.get(&stream_id) else {
            return true;
        };
        // RFC 9000 Section 19.10: ストリームの Final Size はストリーム上限に収まること
        if final_size > stream.send_max_data {
            return false;
        }
        // RFC 9000 Section 19.9: 全ストリームの Final Size の合計は接続上限を
        // 超えてはならない。書込済みバイトはすべて将来の Final Size として
        // 計上されるため、書込総量で保守的に判定する。
        self.send_data_total <= self.send_max_data
    }

    /// 送信待ちの RESET_STREAM_AT を RESET_STREAM に降格する
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 3:
    /// 「ピアが reset_stream_at を広告していない場合は RESET_STREAM_AT を
    /// 送ってはならない (MUST NOT)」。0-RTT では前回セッションの広告を
    /// 記憶してフレームをキューするため、確定した今回の peer transport
    /// parameter が未広告だった場合にこのメソッドで置き換える。
    /// RESET_STREAM は Reliable Size 0 相当であり、リセット自体は伝わる。
    ///
    /// 戻り値は降格したストリーム数。
    pub fn demote_unsupported_reset_stream_at(&mut self) -> usize {
        let stream_ids: Vec<u64> = self
            .streams
            .iter()
            .filter(|(_, stream)| {
                stream.send_state == Some(SendState::DataSent)
                    && stream.reset_at_reliable_size.is_some()
            })
            .map(|(&stream_id, _)| stream_id)
            .collect();
        if stream_ids.is_empty() {
            return 0;
        }
        // 送信キューに残っている RESET_STREAM_AT を除去する
        self.pending_frames.retain(|frame| {
            !matches!(
                frame,
                frame::Frame::ResetStreamAt(rsa) if stream_ids.contains(&rsa.stream_id.as_u64())
            )
        });
        let mut demoted = 0;
        for stream_id in stream_ids {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                continue;
            };
            let Some(final_size) = stream.reset_at_final_size else {
                continue;
            };
            let error_code = stream.reset_at_error_code.unwrap_or(0);
            stream.send_state = Some(SendState::ResetSent);
            stream.reset_at_reliable_size = Some(0);
            stream.reset_at_frame_queued = false;
            stream.reset_at_frame_acked = false;
            if let Some(send_buf) = stream.send_buf.as_mut() {
                send_buf.trim_retransmit_for_reliable_size(0);
            }
            self.pending_frames.push_back(frame::Frame::ResetStream(
                frame::reset_stream::ResetStream {
                    stream_id: VarInt::new(stream_id).expect("value fits in 62-bit varint"),
                    application_protocol_error_code: VarInt::new(error_code)
                        .expect("value fits in 62-bit varint"),
                    final_size: VarInt::new(final_size).expect("value fits in 62-bit varint"),
                },
            ));
            demoted += 1;
        }
        demoted
    }

    /// ストリームを取得する
    pub fn get_stream(&self, stream_id: u64) -> Option<&Stream> {
        self.streams.get(&stream_id)
    }

    /// ストリームを可変で取得する
    pub fn get_stream_mut(&mut self, stream_id: u64) -> Option<&mut Stream> {
        self.streams.get_mut(&stream_id)
    }
}

/// 再送対象の STREAM データ
///
/// 再送キューから取り出した 1 件分の再送情報。送信パス選択ポリシーは
/// `info.meta` の元パス・ロスト理由を使って送信パスを決める。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetxTarget {
    /// ストリーム ID
    pub stream_id: u64,
    /// 再送対象の情報
    pub info: RetransmitInfo,
}

/// STREAM フレーム送信結果 (SentPacket 記録用)
#[derive(Debug, Clone)]
pub struct StreamFrameOut {
    /// ストリーム ID
    pub stream_id: u64,
    /// データオフセット
    pub offset: u64,
    /// データ長
    pub length: usize,
    /// FIN フラグ
    pub fin: bool,
    /// エンコード後のフレームサイズ
    pub encoded_len: usize,
    /// このフレームをこれまでに再送した回数 (初回送信は 0)
    pub retransmission_count: u32,
}

#[cfg(test)]
mod tests;
