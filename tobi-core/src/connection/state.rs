// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::path::PathId;
use crate::recovery::PacketNumberSpace;

/// 接続状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Idle,
    Handshaking,
    Connected,
    /// CONNECTION_CLOSE を送信済み (自発的)
    Closing,
    /// ピアから CONNECTION_CLOSE を受信
    Draining,
    Closed,
}

/// タイマー ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerId {
    /// 損失検出 / PTO タイマー
    ///
    /// パケット番号空間ごとに独立した PTO を持つため、どの空間の期限かを
    /// `space` で識別する (RFC 9002 Section 6.2.1)。
    LossDetection {
        path_id: PathId,
        space: PacketNumberSpace,
    },
    Idle,
    AckDelay {
        path_id: PathId,
    },
    /// Closing/Draining 状態の猶予期間タイマー
    ClosingDraining,
    /// パス検証タイムアウト (PATH_CHALLENGE のリトライ/廃棄)
    PathValidation {
        path_id: PathId,
    },
    /// PATH_ABANDON 後の 3 PTO クリーンアップタイマー
    /// (RFC 10069 Section 3.4)
    PathCleanup {
        path_id: PathId,
    },
    /// BBR Pacing タイマー
    ///
    /// pacing_rate に基づく送信間隔の制御に使用する。
    /// draft-ietf-ccwg-bbr-06: CC が pacing_rate を計算し、
    /// Connection がタイマーで送信タイミングを制御する (Sans I/O)。
    Pacing {
        path_id: PathId,
    },
    /// パス単位の Keep-Alive タイマー (RFC 9000 Section 10.1.2 / RFC 10069 Section 5.9)
    ///
    /// パスごとの最終送受信時刻から keep-alive 間隔が経過した時点で、
    /// そのパスにだけ PING を自動送信する。タイマーはパスごとに独立しており、
    /// 有効化されたパスの分だけ存在する。
    KeepAlive {
        path_id: PathId,
    },
    /// DPLPMTUD プローブタイムアウト (RFC 8899)
    ///
    /// プローブの ACK/Loss が一定時間内に確認できない場合のタイムアウト。
    PmtuProbe {
        path_id: PathId,
    },
    /// DPLPMTUD 再プローブタイマー (RFC 8899)
    ///
    /// 探索完了後に MTU 増加の余地を再確認する。
    PmtuRaise {
        path_id: PathId,
    },
    /// サーバーが 0-RTT 鍵を破棄するタイマー (RFC 9001 Section 4.9.3)
    ///
    /// 1-RTT パケットを初めて受信してから 3 × PTO 経過後に 0-RTT 鍵を破棄する。
    ZeroRttKeys,
}
