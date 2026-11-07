// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! ラウンドカウント (draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.5.1)
//!
//! BBR のラウンドトリップ境界検出。パケット送信時の累計配送バイト数と
//! 現在の累計配送バイト数を比較し、ラウンドの開始を判定する。
//! Multipath QUIC ではパスごとに独立したカウンタを持つ。

/// ラウンドカウンタ
///
/// BBR の複数コンポーネント (full_pipe 検出、輻輳信号、ProbeBW サイクル等) が
/// ラウンド境界を基準に動作するため、共通の基盤として提供する。
#[derive(Debug)]
pub struct Counter {
    /// 次のラウンド開始を判定する配送バイト数の閾値
    next_round_delivered: u64,

    /// 現在の ACK がラウンド開始を含むか
    round_start: bool,

    /// 累計ラウンド数
    round_count: u64,
}

impl Counter {
    /// 新しいラウンドカウンタを作成する
    pub fn new() -> Self {
        Self {
            next_round_delivered: 0,
            round_start: false,
            round_count: 0,
        }
    }

    /// ACK 受信時にラウンド境界を検出する
    ///
    /// `packet_delivered` はACK されたパケット送信時の累計配送バイト数
    /// (RateSample.prior_delivered に相当)。
    /// `current_delivered` は現在の累計配送バイト数。
    ///
    /// draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.5.1:
    /// if (C.delivered >= BBR.next_round_delivered)
    ///   BBRStartRound()
    ///   BBR.round_count++
    pub fn on_ack(&mut self, packet_delivered: u64, current_delivered: u64) {
        if packet_delivered >= self.next_round_delivered {
            self.set_round_end(current_delivered);
            self.round_count += 1;
            self.round_start = true;
        } else {
            self.round_start = false;
        }
    }

    /// ラウンド終了マーカーを設定する
    ///
    /// 現在の累計配送バイト数を次のラウンド開始の閾値として記録する。
    /// start_round() から呼ばれるほか、ProbeBW フェーズ遷移時にも使用する。
    pub fn set_round_end(&mut self, delivered: u64) {
        self.next_round_delivered = delivered;
    }

    /// 現在の ACK がラウンド開始を含むかを返す
    pub fn round_start(&self) -> bool {
        self.round_start
    }

    /// 累計ラウンド数を返す
    pub fn round_count(&self) -> u64 {
        self.round_count
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}
