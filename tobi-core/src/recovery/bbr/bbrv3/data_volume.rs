// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! BBRv3 inflight モデル (draft-ietf-ccwg-bbr-06 Section 5.5.6)
//!
//! BBRv2 との差分:
//! - inflight_hi → inflight_longterm
//! - inflight_lo → inflight_shortterm
//! - HandleSpuriousLossDetection() による inflight_longterm / inflight_shortterm 復元
//! - extra_acked フィルタ長が Startup 中は 1 ラウンド、それ以外は 10 ラウンド
//!   (Section 5.5.9)

use crate::recovery::bbr::bandwidth::Bandwidth;
use crate::recovery::windowed_filter::RoundBasedMaxFilter;
use crate::time::{Duration, Timestamp};

/// min_rtt フィルタ長 (10s)
const MIN_RTT_FILTER_LEN: Duration = Duration::from_secs(10);

/// ProbeRTT 間隔 (5s)
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(5);

/// Startup 中の ExtraACKed フィルタのウィンドウ長 (1 ラウンド)
///
/// draft-ietf-ccwg-bbr-06 Section 5.5.9: Startup 中は 1 ラウンド分のみ記憶する。
pub const STARTUP_EXTRA_ACKED_FILTER_LEN: u64 = 1;

/// 定常状態の ExtraACKed フィルタのウィンドウ長 (10 ラウンド)
///
/// draft-ietf-ccwg-bbr-06 Section 5.5.9 / Section 2.12:
/// BBR.ExtraAckedFilterLen = 10 packet-timed round trips。
pub const STEADY_EXTRA_ACKED_FILTER_LEN: u64 = 10;

/// 損失時の乗算減少係数 (0.7)
const BETA_NUM: u64 = 7;
const BETA_DEN: u64 = 10;

/// inflight の「制限なし」を表す値
const INFLIGHT_UNLIMITED: u64 = u64::MAX;

/// BBRv3 inflight モデル
#[derive(Debug)]
pub struct Model {
    // --- min_rtt ---
    min_rtt: Option<Duration>,
    min_rtt_stamp: Option<Timestamp>,

    // --- ProbeRTT スケジューリング ---
    probe_rtt_min_delay: Option<Duration>,
    probe_rtt_min_stamp: Option<Timestamp>,
    probe_rtt_expired: bool,

    // --- ExtraACKed ---
    extra_acked_filter: RoundBasedMaxFilter,
    extra_acked_interval_start: Option<Timestamp>,
    extra_acked_delivered: u64,
    extra_acked: u64,

    // --- inflight 上下限 ---
    /// 長期 inflight 上限 (BBRv2 の inflight_hi)
    /// None = 制限なし (初期状態、または未設定)
    inflight_longterm: Option<u64>,
    /// 短期 inflight 下限 (BBRv2 の inflight_lo)
    /// None = 制限なし (初期状態、またはリセット済み)
    inflight_shortterm: Option<u64>,
}

impl Model {
    pub fn new() -> Self {
        Self {
            min_rtt: None,
            min_rtt_stamp: None,
            probe_rtt_min_delay: None,
            probe_rtt_min_stamp: None,
            probe_rtt_expired: false,
            extra_acked_filter: RoundBasedMaxFilter::new(STEADY_EXTRA_ACKED_FILTER_LEN),
            extra_acked_interval_start: None,
            extra_acked_delivered: 0,
            extra_acked: 0,
            inflight_longterm: None,
            inflight_shortterm: None,
        }
    }

    pub fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt
    }

    pub fn extra_acked(&self) -> u64 {
        self.extra_acked
    }

    /// inflight 長期上限を返す (未設定の場合は INFLIGHT_UNLIMITED)
    pub fn inflight_longterm(&self) -> u64 {
        self.inflight_longterm.unwrap_or(INFLIGHT_UNLIMITED)
    }

    /// inflight 長期上限が設定済みか
    pub fn has_inflight_longterm(&self) -> bool {
        self.inflight_longterm.is_some()
    }

    pub fn set_inflight_longterm(&mut self, value: u64) {
        self.inflight_longterm = Some(value);
    }

    /// inflight 短期下限を返す (未設定の場合は INFLIGHT_UNLIMITED)
    pub fn inflight_shortterm(&self) -> u64 {
        self.inflight_shortterm.unwrap_or(INFLIGHT_UNLIMITED)
    }

    pub fn probe_rtt_expired(&self) -> bool {
        self.probe_rtt_expired
    }

    pub fn update_min_rtt(&mut self, rtt_sample: Duration, now: Timestamp) {
        self.probe_rtt_expired = match self.probe_rtt_min_stamp {
            Some(stamp) => now >= stamp + PROBE_RTT_INTERVAL,
            // 未測定なら期限切れではなく、測定期間をここから始める。
            // draft-ietf-ccwg-bbr-06 Section 5.3.4.3: 古い測定値の再測定と
            // 初回測定を区別する。draft 改訂で期間が変わる可能性がある。
            None => false,
        };

        if self.probe_rtt_min_delay.is_none_or(|d| rtt_sample < d) || self.probe_rtt_expired {
            self.probe_rtt_min_delay = Some(rtt_sample);
            self.probe_rtt_min_stamp = Some(now);
        }

        let min_rtt_expired = match self.min_rtt_stamp {
            Some(stamp) => now >= stamp + MIN_RTT_FILTER_LEN,
            None => true,
        };

        if self.min_rtt.is_none_or(|d| {
            self.probe_rtt_min_delay
                .expect("probe_rtt_min_delay must be set before min_rtt")
                < d
        }) || min_rtt_expired
        {
            self.min_rtt = self.probe_rtt_min_delay;
            self.min_rtt_stamp = self.probe_rtt_min_stamp;
        }
    }

    pub fn schedule_next_probe_rtt(&mut self, now: Timestamp) {
        self.probe_rtt_min_stamp = Some(now);
    }

    /// ACK aggregation 推定を更新する
    ///
    /// draft-ietf-ccwg-bbr-06 Section 5.5.9
    ///
    /// `filter_len` は extra_acked フィルタのウィンドウ長 (ラウンド数)。
    /// Startup 中は `STARTUP_EXTRA_ACKED_FILTER_LEN` (1)、
    /// それ以外は `STEADY_EXTRA_ACKED_FILTER_LEN` (10) を渡す。
    pub fn update_ack_aggregation(
        &mut self,
        bw: Bandwidth,
        newly_acked: u64,
        cwnd: u64,
        round_count: u64,
        filter_len: u64,
        now: Timestamp,
    ) {
        let interval = match self.extra_acked_interval_start {
            Some(start) => now - start,
            None => {
                self.extra_acked_interval_start = Some(now);
                Duration::ZERO
            }
        };
        let mut expected_delivered = bw.bytes_for_duration(interval);
        // ACK レートが期待帯域を下回る場合は集約エピソードが終了したとみなし、
        // サンプリング区間を現在時刻からやり直す。
        // このとき expected_delivered も 0 に戻さないと、直後に追加する
        // newly_acked から古い区間の期待配送量を差し引いてしまう。
        if self.extra_acked_delivered <= expected_delivered {
            self.extra_acked_delivered = 0;
            self.extra_acked_interval_start = Some(now);
            expected_delivered = 0;
        }
        self.extra_acked_delivered += newly_acked;
        let extra = self
            .extra_acked_delivered
            .saturating_sub(expected_delivered)
            .min(cwnd);
        self.extra_acked_filter
            .update_with_window_length(extra, round_count, filter_len);
        self.extra_acked = self.extra_acked_filter.value().unwrap_or(0);
    }

    pub fn reset_ack_aggregation_interval(&mut self) {
        self.extra_acked_interval_start = None;
    }

    pub fn raise_inflight_longterm(&mut self, delta: u64) {
        self.inflight_longterm = Some(self.inflight_longterm().saturating_add(delta));
    }

    pub fn init_inflight_shortterm(&mut self, cwnd: u64) {
        if self.inflight_shortterm.is_none() {
            self.inflight_shortterm = Some(cwnd);
        }
    }

    pub fn update_inflight_shortterm(&mut self, inflight_latest: u64) {
        let current = self.inflight_shortterm();
        self.inflight_shortterm =
            Some(inflight_latest.max(current.saturating_mul(BETA_NUM) / BETA_DEN));
    }

    pub fn reset_inflight_shortterm(&mut self) {
        self.inflight_shortterm = None;
    }

    /// Spurious loss 検出時に inflight_longterm を復元する
    ///
    /// draft-ietf-ccwg-bbr-06 Section 5.5.11.2:
    /// BBR.inflight_longterm = max(BBR.inflight_longterm, BBR.undo_inflight_longterm)
    ///
    /// 損失回復開始時に保存した値 (`saved`) を渡す。
    pub fn restore_inflight_longterm(&mut self, saved: u64) {
        // u64::MAX は「制限なし (Infinity)」の内部表現である。現在値または
        // 保存値のどちらかが Infinity なら max() の結果も Infinity であり、
        // 通常の値として max() すると制限なしを表す Some(u64::MAX) が
        // 設定済みに変わってしまうため、None のまま維持する。
        let current = self.inflight_longterm();
        if current == INFLIGHT_UNLIMITED || saved == INFLIGHT_UNLIMITED {
            self.inflight_longterm = None;
            return;
        }
        self.inflight_longterm = Some(current.max(saved));
    }

    /// Spurious loss 検出時に inflight_shortterm を復元する
    ///
    /// draft-ietf-ccwg-bbr-06 Section 5.5.11.2:
    /// BBR.inflight_shortterm = max(BBR.inflight_shortterm, BBR.undo_inflight_shortterm)
    pub fn restore_inflight_shortterm(&mut self, saved: u64) {
        // restore_inflight_longterm と同じく、Infinity は Infinity のまま維持する。
        let current = self.inflight_shortterm();
        if current == INFLIGHT_UNLIMITED || saved == INFLIGHT_UNLIMITED {
            self.inflight_shortterm = None;
            return;
        }
        self.inflight_shortterm = Some(current.max(saved));
    }
}

impl Default for Model {
    fn default() -> Self {
        Self::new()
    }
}
