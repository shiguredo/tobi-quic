// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 接続の観測イベント
//!
//! アプリケーションが購読する観測イベントの内部表現。
//! 公開 API では `tobi_quic` クレートの型に変換して提供する。

use crate::path::PathId;
use crate::recovery::congestion::CongestionStateKind;

/// 接続で発生した観測イベント
///
/// パケットの送受信・ロスト、輻輳状態の変化、パス検証、鍵更新を表す。
/// アプリケーションへは `tobi_quic` クレートの公開型に変換して通知する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionObservationEvent {
    /// パケットを送信した
    PacketSent {
        /// 送信したパス
        path_id: PathId,
        /// パケット番号
        packet_number: u64,
        /// データグラムのバイト数
        size: usize,
    },
    /// パケットを受信した
    PacketReceived {
        /// 受信したパス
        path_id: PathId,
        /// パケット番号
        packet_number: u64,
        /// データグラムのバイト数
        size: usize,
    },
    /// パケットをロストした
    PacketLost {
        /// ロストしたパケットを送信したパス
        path_id: PathId,
        /// パケット番号
        packet_number: u64,
    },
    /// 輻輳制御の状態が変化した
    CongestionStateChanged {
        /// 状態が変化したパス
        path_id: PathId,
        /// 新しい輻輳制御の状態の分類
        state: CongestionStateKind,
    },
    /// パス検証が完了した
    PathValidated {
        /// 検証が完了したパス
        path_id: PathId,
    },
    /// 1-RTT 鍵が更新された
    KeyUpdated {
        /// 新しい鍵フェーズ (RFC 9001 Section 6)
        key_phase: u8,
    },
}
