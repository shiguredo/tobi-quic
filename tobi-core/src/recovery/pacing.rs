// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pacing (RFC 9002 Section 7.7)
//!
//! 輻輳制御アルゴリズムから得た pacing rate (bytes/sec) に基づいて
//! send quantum 単位で送信間隔を空け、バースト送信によるキュー蓄積を防ぐ。
//! パスごと・輻輳制御インスタンスごとに 1 つの Pacer を持つ。
//!
//! 送信経路は `earliest_departure_time()` が未来を返す間は送信を止め、
//! その時刻で送信を再開する。pacing rate が 0 の間は pacing せず、
//! 呼び出し側が初期輻輳ウィンドウ以下のバースト制限を行う
//! (RFC 9002 Section 7.7 の MUST)。

use crate::recovery::bbr::bandwidth::Bandwidth;
use crate::time::{Duration, Timestamp};

/// Pacing マージン (1%)
const PACING_MARGIN_PERCENT: u64 = 1;

/// Pacer
///
/// departure time 追跡付きの pacing 制御。
/// send quantum 単位でバーストを許可し、バースト間に pacing interval を設ける。
#[derive(Debug)]
pub struct Pacer {
    /// 現在の departure time スロットの残容量 (バイト)
    capacity: u64,

    /// 現在のスロットで実際に送った量。最後のパケットが残容量を越えた分も含む。
    slot_bytes_sent: u64,

    /// 次の送信可能時刻 (スロットの開始時刻)
    next_departure_time: Option<Timestamp>,

    /// 現在の pacing rate (bytes/sec)
    pacing_rate: u64,

    /// 1 回の送信でまとめるバイト数の上限
    send_quantum: u64,

    /// 最大データグラムサイズ (send quantum の下限計算に使う)
    max_datagram_size: u64,
}

impl Pacer {
    /// 新しい Pacer を作成する
    pub fn new(max_datagram_size: u64) -> Self {
        Self {
            capacity: 0,
            slot_bytes_sent: 0,
            next_departure_time: None,
            pacing_rate: 0,
            send_quantum: max_datagram_size,
            max_datagram_size,
        }
    }

    /// pacing rate を返す (bytes/sec)
    pub fn pacing_rate(&self) -> u64 {
        self.pacing_rate
    }

    /// send quantum を返す
    pub fn send_quantum(&self) -> u64 {
        self.send_quantum
    }

    /// 次の送信可能時刻を返す
    ///
    /// None なら即座に送信可能。
    pub fn earliest_departure_time(&self) -> Option<Timestamp> {
        self.next_departure_time.filter(|_| self.pacing_rate > 0)
    }

    /// パケット送信時に departure time と capacity を更新する
    ///
    /// 戻り値はこのパケットの送信予定時刻 (departure time)。
    /// pacing rate が 0 の場合は pacing せず `now` を返す。
    pub fn on_packet_sent(&mut self, now: Timestamp, bytes_sent: u64) -> Timestamp {
        if self.pacing_rate == 0 {
            return now;
        }

        if self.capacity == 0 {
            // 新しいスロットを開始する
            self.next_departure_time = Some(match self.next_departure_time {
                Some(next_departure_time) => next_departure_time.max(now),
                None => now,
            });
            self.capacity = self.send_quantum;
            self.slot_bytes_sent = 0;
        }

        let departure_time = match self.next_departure_time {
            Some(next_departure_time) => next_departure_time.max(now),
            None => now,
        };

        self.capacity = self.capacity.saturating_sub(bytes_sent);
        self.slot_bytes_sent = self.slot_bytes_sent.saturating_add(bytes_sent);

        if self.capacity == 0 {
            // スロットを使い切った → 次のスロットの departure time を計算する
            // 量子に収まらなかった端数も算入する。残容量を飽和減算するだけでは、
            // 小さいパケットを連続送信したときに設定した rate を超えてしまう。
            let interval_us = self.slot_bytes_sent as u128 * 1_000_000 / self.pacing_rate as u128;
            let interval = Duration::from_micros(interval_us.min(u64::MAX as u128) as u64);
            if let Some(next_departure_time) = self.next_departure_time.as_mut() {
                *next_departure_time = *next_departure_time + interval;
            }
        }

        departure_time
    }

    /// 初期 RTT から pacing rate を設定する
    ///
    /// cwnd / rtt * gain で初期 pacing rate を推定する。
    pub fn initialize_pacing_rate(
        &mut self,
        cwnd: u64,
        rtt: Duration,
        gain_num: u64,
        gain_den: u64,
    ) {
        let rtt_us = rtt.as_micros().max(1);
        let nominal_bw = cwnd as u128 * 1_000_000 / rtt_us as u128;
        self.set_pacing_rate_value(
            (nominal_bw * gain_num as u128 / gain_den as u128).min(u64::MAX as u128) as u64,
        );
    }

    /// 帯域推定に基づく pacing rate を設定する
    ///
    /// rate = bw * gain * (1 - PACING_MARGIN)
    /// filled_pipe が false の場合、現在の rate より低い値には設定しない。
    pub fn set_pacing_rate(
        &mut self,
        bw: Bandwidth,
        gain_num: u64,
        gain_den: u64,
        filled_pipe: bool,
    ) {
        let bw_bps = bw.as_bytes_per_second() as u128;
        let rate = (bw_bps * gain_num as u128 * (100 - PACING_MARGIN_PERCENT) as u128
            / (gain_den as u128 * 100))
            .min(u64::MAX as u128) as u64;
        if filled_pipe || rate > self.pacing_rate {
            self.set_pacing_rate_value(rate);
        }
    }

    /// pacing rate (bytes/sec) を直接設定する
    ///
    /// ウィンドウベースの輻輳制御 (NewReno / CUBIC) が
    /// `rate = N * cwnd / smoothed_rtt` で計算した値を設定する用途に使う。
    /// rate が 0 になった場合は departure time を破棄して即時送信に戻す。
    pub fn set_pacing_rate_value(&mut self, rate: u64) {
        let rate_changed = rate != self.pacing_rate;
        self.pacing_rate = rate;
        if rate == 0 {
            self.next_departure_time = None;
            self.capacity = 0;
            self.slot_bytes_sent = 0;
            return;
        }
        if rate_changed {
            // send quantum は rate に比例するため、rate 変更時に再計算する。
            self.set_send_quantum(self.max_datagram_size);
            // 古い quantum に基づく残容量は新しい quantum にクランプする。
            self.capacity = self.capacity.min(self.send_quantum);
            // 量子を使い切って設定した待機時刻は保つ。ACK ごとの rate 更新で
            // 消すと、そのたびに無料のバーストを許可してしまう。
        }
    }

    /// pacing rate に基づく send quantum を計算する
    ///
    /// RFC 9002 Section 7.7 は「初期輻輳ウィンドウ以下のバースト」を求めており、
    /// ここでは 2 * SMSS を下限とする (SMSS は最大データグラムサイズ)。
    pub fn set_send_quantum(&mut self, max_datagram_size: u64) {
        self.max_datagram_size = max_datagram_size;
        // pacing_rate * 1ms = pacing_rate / 1000
        let quantum = (self.pacing_rate / 1000).min(64 * 1024);
        self.send_quantum = quantum.max(2 * max_datagram_size);
    }
}

#[cfg(test)]
mod tests;
