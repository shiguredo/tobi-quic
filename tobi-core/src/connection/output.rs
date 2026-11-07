// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

use alloc::vec::Vec;
use core::net::SocketAddr;

use crate::connection_id::ConnectionId;
use crate::path::PathId;
use crate::time::Timestamp;

use super::state::TimerId;

/// ECN コードポイント (RFC 3168)
///
/// I/O 層が IP ヘッダの ECN フィールドに設定する値。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EcnCodepoint {
    /// ECN 非対応 (Not-ECT)
    #[default]
    NotEct,
    /// ECN Capable Transport (ECT(0))
    Ect0,
    /// ECN Capable Transport (ECT(1))
    Ect1,
    /// Congestion Experienced (CE)
    ///
    /// 輻輳したルータが付ける値であり、送信側が指定することはない。
    /// 受信したパケットの観測結果としてのみ現れる (RFC 3168 Section 5)。
    Ce,
}

impl EcnCodepoint {
    /// IP ヘッダの ECN フィールド (2 bit) から変換する
    ///
    /// 値は RFC 3168 Section 5 の定義に対応する。
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0b01 => Self::Ect1,
            0b10 => Self::Ect0,
            0b11 => Self::Ce,
            _ => Self::NotEct,
        }
    }

    /// IP ヘッダの ECN フィールド (2 bit) へ変換する
    ///
    /// `Ce` は送信側で指定しない値だが、往復変換のために値を返す。
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::NotEct => 0b00,
            Self::Ect1 => 0b01,
            Self::Ect0 => 0b10,
            Self::Ce => 0b11,
        }
    }
}

/// アプリケーションへの出力指示
#[derive(Debug)]
pub enum ConnectionOutput {
    SendDatagram {
        data: Vec<u8>,
        path_id: PathId,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        /// 送信パケットに設定する ECN コードポイント (RFC 3168)
        ecn: EcnCodepoint,
    },
    SetTimer {
        id: TimerId,
        deadline: Timestamp,
    },
    ClearTimer {
        id: TimerId,
    },
    /// PathController がパスを開いた (I/O 層がソケットを作成する)
    PathOpened {
        path_id: PathId,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    },
    /// パスが接続から除去された (I/O 層がソケットを閉じる)
    ///
    /// Connection がローカルに廃棄したパスについて、[`ConnectionOutput::PathOpened`]
    /// を通知済みなら閉じる経路で 1 回だけ発行する。開設途中で `PathOpened` を
    /// 発行しなかった場合は発行しない。ピア起点の PATH_ABANDON では発行せず、
    /// `ConnectionEvent::PathAbandoned` で通知する。3 PTO 後のクリーンアップでも
    /// 再発行しない。
    PathClosed {
        path_id: PathId,
    },
    /// Sans I/O がローカル CID を新規発行した (I/O 層がルーティングテーブルに登録する)
    ///
    /// RFC 9000 Section 5.1.1 / draft-ietf-quic-multipath-21 Section 4.4 に従い、
    /// NEW_CONNECTION_ID / PATH_NEW_CONNECTION_ID で発行したサーバー CID は
    /// 以降ピアが DCID として使ってくる。I/O 層は CID をルーターの CID マップに
    /// 登録し、該当 CID 宛のパケットを本接続に配送する必要がある。
    RegisterLocalCid {
        cid: ConnectionId,
        path_id: PathId,
    },
    /// Sans I/O がローカル CID を retire した (I/O 層がルーティングテーブルから削除する)
    ///
    /// RFC 9000 Section 5.1.2 / draft-ietf-quic-multipath-21 Section 4.4:
    /// RETIRE_CONNECTION_ID で retire された CID はルーティングテーブルからも削除する。
    UnregisterLocalCid {
        cid: ConnectionId,
    },
}
