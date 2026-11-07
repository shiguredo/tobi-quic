// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

use alloc::vec::Vec;
use core::net::SocketAddr;

use crate::path::{PathId, PathStatus};

/// 接続終了の種別 (RFC 9000 Section 19.19)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionCloseKind {
    /// ピアからのトランスポートエラー (CONNECTION_CLOSE type 0x1c)
    Transport,
    /// ピアからのアプリケーションエラー (CONNECTION_CLOSE type 0x1d)
    Application,
    /// アイドルタイムアウトによる終了 (RFC 9000 Section 10.1)
    IdleTimeout,
    /// ローカルで明示的に閉じた (アプリケーションの close など)
    Local,
    /// ローカルの内部要因による終了 (プロトコル制限、Stateless Reset 等)
    Internal,
}

/// アプリケーションへのイベント通知
#[derive(Debug)]
pub enum ConnectionEvent {
    Connected,
    ConnectionClosed {
        error_code: u64,
        reason: Vec<u8>,
        /// 終了の種別 (ピア由来かローカル由来か、エラーの種類)
        kind: ConnectionCloseKind,
    },
    /// 新しいストリームがピアから開かれた
    NewStream {
        stream_id: u64,
    },
    /// ストリームにデータが到着し、読み取り可能になった
    StreamReadable {
        stream_id: u64,
    },
    /// ストリームの送信フロー制御が更新され、書き込み可能になった
    StreamWritable {
        stream_id: u64,
    },
    /// ピアがストリームをリセットした
    StreamReset {
        stream_id: u64,
        error_code: u64,
    },
    /// ピアが STOP_SENDING を送信した
    StreamStopSending {
        stream_id: u64,
        error_code: u64,
    },
    /// パス検証が完了した
    PathValidated {
        path_id: PathId,
    },
    /// ローカルのパス状態 (Available / Backup) が変わった
    ///
    /// `Connection::set_path_status` または PathController の判断で
    /// ローカルの状態が変更されたときに通知する。ピアの希望による変更は
    /// [`Self::PeerPathStatusChanged`] で通知する。
    PathStatusChanged {
        path_id: PathId,
        status: PathStatus,
    },
    /// ピアが PATH_STATUS で通知したパスの利用希望が変わった
    ///
    /// draft-ietf-quic-multipath-21 Section 3.3: ピアの希望はローカルの
    /// パス状態を上書きしない。受信済み以下のシーケンス番号の通知は無視する
    /// ため、その場合はイベントも通知しない (Section 4.3)。未開設の path ID
    /// への PATH_STATUS は受信時にイベントを発行せず、パスを生成した時点で
    /// `PeerPathStatusChanged` を 1 回通知する。
    PeerPathStatusChanged {
        path_id: PathId,
        status: PathStatus,
    },
    /// パスの検証に失敗した
    ///
    /// 1 回の検証について 1 回だけ通知する。同じパスで改めて検証を開始し、
    /// その検証も失敗した場合は再度通知する。通知するのは次の場合である。
    ///
    /// - RFC 9000 Section 9.6.1: preferred_address への移行検証がタイムアウトした。
    ///   パスの 4-tuple と送信先 CID は検証前の値へ戻っており、元のアドレスを
    ///   使い続ける。
    /// - パス検証のリトライ上限を超えた。移行検証中なら移行を取り消し、
    ///   そうでなければ通知した後にパスを廃棄する。
    /// - 検証中の 4-tuple 移行が、候補 CID の退役などで継続できず取り消された。
    ///   この場合、移行だけを取り消してパスは維持する。送信可能な CID が残らず
    ///   送信先を確保できない場合は、移行を取り消したうえで接続を閉じる。
    ///
    /// ピアから PATH_ABANDON を受信した場合や、ローカルにパスを廃棄する場合は
    /// [`Self::PathAbandoned`] が通知を担う。同じパスについて
    /// `PathValidationFailed` を重ねて通知しない。検証タイマーを解除済みの場合や、
    /// 同じ移行を取り消した後に改めて失敗が判明した場合も二重に通知しない。
    PathValidationFailed {
        path_id: PathId,
    },
    /// パスが廃棄された (ピアから PATH_ABANDON を受信)
    PathAbandoned {
        path_id: PathId,
        error_code: u64,
    },
    /// ピアがパス数上限に達した (PATHS_BLOCKED 受信)
    PathsBlocked {
        maximum_path_id: u32,
    },
    /// ピアが観測した自分のアドレスを受信した (draft-ietf-quic-address-discovery-01)
    ///
    /// draft であり将来変更される可能性がある。
    ObservedAddress {
        /// 観測されたパス ID
        path_id: PathId,
        /// ピアから観測されたアドレス
        addr: SocketAddr,
    },
    /// データグラムを受信した (RFC 9221)
    DatagramReceived {
        data: Vec<u8>,
    },
    /// NEW_TOKEN フレームを受信した (RFC 9000 Section 19.7)
    ///
    /// アプリケーションはトークンを保存し、次回接続の Initial パケットに含める。
    NewToken {
        token: Vec<u8>,
    },
    /// セッションチケットを受信した (RFC 9001 Section 4.6)
    ///
    /// サーバーからの NewSessionTicket を処理し、rustls のセッションストアに保存された。
    /// 同じ `ClientConfig` を使って次回接続を行えば 0-RTT が利用可能になる。
    SessionTicketReceived,
    /// サーバーが 0-RTT を拒否した (RFC 9001 Section 4.6.2)
    ///
    /// 0-RTT で送信したデータはサーバーに到達していない。
    /// 既にバッファされたストリームデータは 1-RTT で自動的に再送される。
    ZeroRttRejected,
}
