// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! RTT 推定 (RFC 9002 Section 5.3)
//!
//! パスごとに独立したインスタンスを持つ。

use crate::path::PathId;
use crate::time::{Duration, Timestamp};

/// RTT 推定器
#[derive(Debug)]
pub struct RttEstimator {
    /// 最新の RTT サンプル
    pub latest_rtt: Duration,
    /// 平滑化 RTT
    pub smoothed_rtt: Duration,
    /// RTT の変動
    pub rttvar: Duration,
    /// 最小 RTT
    pub min_rtt: Duration,
    /// 最初のサンプルを受信したか
    has_sample: bool,
    /// 最初の RTT サンプルを取得した時刻
    ///
    /// Persistent Congestion の判定で「事前 RTT サンプルがあったか」を
    /// 判断するために使う (RFC 9002 Section 7.6.2)。
    first_rtt_sample: Option<Timestamp>,
    /// min_rtt を記録した PATH_ACK の受信パス (RFC 10069 Section 5.4)
    /// ACK 受信パスが変わった場合に min_rtt をリセットする
    min_rtt_ack_path: Option<PathId>,
}

/// 初期 RTT (RFC 9002 Section 6.2.2)
const INITIAL_RTT: Duration = Duration::from_millis(333);

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl RttEstimator {
    pub fn new() -> Self {
        Self {
            latest_rtt: INITIAL_RTT,
            smoothed_rtt: INITIAL_RTT,
            rttvar: Duration::from_micros(INITIAL_RTT.as_micros() / 2),
            min_rtt: Duration::ZERO,
            has_sample: false,
            first_rtt_sample: None,
            min_rtt_ack_path: None,
        }
    }

    /// RTT サンプルを更新する (RFC 9002 Section 5.3)
    ///
    /// - `rtt_sample`: 測定した RTT
    /// - `ack_delay`: 相手が報告した ACK 遅延
    /// - `max_ack_delay`: 相手の max_ack_delay トランスポートパラメータ
    /// - `ack_recv_path`: PATH_ACK を受信したパス ID (RFC 10069 Section 5.4)
    /// - `now`: 現在時刻。最初のサンプルでは取得時刻として記録する
    pub fn update(
        &mut self,
        rtt_sample: Duration,
        ack_delay: Duration,
        max_ack_delay: Duration,
        ack_recv_path: PathId,
        now: Timestamp,
    ) {
        self.latest_rtt = rtt_sample;

        if !self.has_sample {
            // 最初のサンプル。RFC 9002 Appendix A.7 の UpdateRtt と同様に
            // first_rtt_sample もここで記録する
            self.min_rtt = rtt_sample;
            self.smoothed_rtt = rtt_sample;
            self.rttvar = Duration::from_micros(rtt_sample.as_micros() / 2);
            self.has_sample = true;
            self.first_rtt_sample = Some(now);
            self.min_rtt_ack_path = Some(ack_recv_path);
            return;
        }

        // ACK 受信パスが変わった場合、min_rtt をリセットする
        // (RFC 10069 Section 5.4)
        if self.min_rtt_ack_path != Some(ack_recv_path) {
            self.min_rtt = rtt_sample;
            self.min_rtt_ack_path = Some(ack_recv_path);
        }

        // min_rtt の更新
        if rtt_sample < self.min_rtt {
            self.min_rtt = rtt_sample;
        }

        // ACK 遅延の調整
        let adjusted_rtt = if rtt_sample > self.min_rtt {
            let capped_delay = if ack_delay < max_ack_delay {
                ack_delay
            } else {
                max_ack_delay
            };
            let excess = rtt_sample.saturating_sub(self.min_rtt);
            // RFC 9002 Section 5.3 の「latest_rtt >= min_rtt + ack_delay」に対応する。
            // excess == capped_delay の境界でも減算する
            if excess >= capped_delay {
                Duration::from_micros(rtt_sample.as_micros() - capped_delay.as_micros())
            } else {
                rtt_sample
            }
        } else {
            rtt_sample
        };

        // EWMA 更新
        // rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|
        let diff = if self.smoothed_rtt > adjusted_rtt {
            self.smoothed_rtt.saturating_sub(adjusted_rtt)
        } else {
            adjusted_rtt.saturating_sub(self.smoothed_rtt)
        };
        // 重み付き和を広い整数で計算し、最後に一度だけ丸める。
        // 各項を先に丸めると一定の短い RTT でも推定値が減り、u64 の乗算では
        // 大きな RTT でオーバーフローする。平均は入力の最大値を超えない。
        self.rttvar = Duration::from_micros(
            ((u128::from(self.rttvar.as_micros()) * 3 + u128::from(diff.as_micros())) / 4) as u64,
        );

        // smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
        self.smoothed_rtt = Duration::from_micros(
            ((u128::from(self.smoothed_rtt.as_micros()) * 7 + u128::from(adjusted_rtt.as_micros()))
                / 8) as u64,
        );
    }

    /// PTO (Probe Timeout) を計算する (RFC 9002 Section 6.2.1)
    pub fn pto(&self) -> Duration {
        // PTO = smoothed_rtt + max(4 * rttvar, 1ms)
        let var = self.rttvar.mul(4);
        let granularity = Duration::from_millis(1);
        let max_var = if var > granularity { var } else { granularity };
        self.smoothed_rtt.saturating_add(max_var)
    }

    /// 最初のサンプルを受信したか
    pub fn has_sample(&self) -> bool {
        self.has_sample
    }

    /// 最初の RTT サンプルを取得した時刻を返す
    ///
    /// 未取得の場合は `None` を返す。
    pub fn first_rtt_sample(&self) -> Option<Timestamp> {
        self.first_rtt_sample
    }

    /// 指定パスが廃棄された場合に min_rtt を再計算可能にする
    /// (RFC 10069 Section 5.4)
    pub fn on_ack_path_abandoned(&mut self, abandoned_path: PathId) {
        if self.min_rtt_ack_path == Some(abandoned_path) {
            // min_rtt の ACK 受信パスが廃棄されたのでリセットする
            // 次の RTT サンプルで min_rtt が再計算される
            self.min_rtt = self.latest_rtt;
            self.min_rtt_ack_path = None;
        }
    }
}
