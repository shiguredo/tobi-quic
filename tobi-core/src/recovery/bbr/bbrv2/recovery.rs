// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Recovery 状態マシン (draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.6.4.4)
//!
//! Fast Recovery の状態遷移と fast retransmission の制御。
//! BBR の Recovery は NewReno とは異なり、cwnd の保存/復元と
//! fast retransmission の制御に焦点を当てる。

use crate::time::Timestamp;

/// Fast Retransmission の状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastRetransmission {
    /// 通常状態
    Idle,
    /// fast retransmission が必要 (cwnd 制約を 1 パケット分バイパスできる)
    RequiresTransmission,
}

/// Recovery の状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// 回復済み (通常動作)
    Recovered,
    /// 回復中
    ///
    /// recovery_start_time より後に送信されたパケットの ACK で終了する。
    Recovering {
        /// Recovery 開始時刻
        start_time: Timestamp,
        /// fast retransmission の状態
        fast_retransmission: FastRetransmission,
    },
}

impl State {
    /// 新しい Recovery 状態を作成する (Recovered で初期化)
    pub fn new() -> Self {
        Self::Recovered
    }

    /// Recovery 中かどうかを返す
    pub fn in_recovery(&self) -> bool {
        matches!(self, Self::Recovering { .. })
    }

    /// cwnd をバイパスして 1 パケット送信可能かを返す
    pub fn requires_fast_retransmission(&self) -> bool {
        matches!(
            self,
            Self::Recovering {
                fast_retransmission: FastRetransmission::RequiresTransmission,
                ..
            }
        )
    }

    /// パケット送信時に fast retransmission フラグを Idle に戻す
    pub fn on_packet_sent(&mut self) {
        if let Self::Recovering {
            fast_retransmission,
            ..
        } = self
        {
            *fast_retransmission = FastRetransmission::Idle;
        }
    }

    /// パケット破棄時に、未使用の fast retransmission の送信権を取り消す
    ///
    /// bytes_in_flight が減るため、破棄前に与えた追加の送信権を残さない。
    /// 回復状態自体は、回復開始後のパケットが ACK されるまで維持する。
    pub fn on_packet_discarded(&mut self) {
        self.on_packet_sent();
    }

    /// ACK 受信時に Recovery 終了を判定する
    ///
    /// ACK されたパケットの送信時刻が recovery_start_time より後なら
    /// Recovery を終了し true を返す。
    pub fn on_ack(&mut self, time_sent: Timestamp) -> bool {
        if let Self::Recovering { start_time, .. } = *self
            && time_sent > start_time
        {
            *self = Self::Recovered;
            return true;
        }
        false
    }

    /// 輻輳イベント (ロスト検出) 時に Recovery に入る
    ///
    /// 既に Recovery 中なら false を返す (同一 RTT 内で複数回反応しない)。
    /// 新たに Recovery に入った場合は true を返す。
    pub fn on_congestion_event(&mut self, now: Timestamp) -> bool {
        if self.in_recovery() {
            return false;
        }
        *self = Self::Recovering {
            start_time: now,
            fast_retransmission: FastRetransmission::RequiresTransmission,
        };
        true
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
