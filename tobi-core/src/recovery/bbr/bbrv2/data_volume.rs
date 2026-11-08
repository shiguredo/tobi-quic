// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! inflight モデル (draft-cardwell-iccrg-bbr-congestion-control-02 Section 2.9.2, 4.5.3, 4.5.5)
//!
//! min_rtt フィルタリング、ACK aggregation 推定、inflight 上下限管理。
//! Multipath QUIC ではパスごとに独立したモデルを持つ。

use crate::recovery::bbr::bandwidth::Bandwidth;
use crate::recovery::windowed_filter::RoundBasedMaxFilter;
use crate::time::{Duration, Timestamp};

/// min_rtt フィルタ長 (10s)
const MIN_RTT_FILTER_LEN: Duration = Duration::from_secs(10);

/// ProbeRTT 間隔 (5s)
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(5);

/// ExtraACKed フィルタのウィンドウ長 (10 ラウンド)
///
/// draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.5.5:
/// BBRExtraAckedFilterLen = 10 packet-timed round-trips。BBRv2 では常にこの値。
pub const EXTRA_ACKED_FILTER_LEN: u64 = 10;

/// 損失時の乗算減少係数 (0.7)
const BETA_NUM: u64 = 7;
const BETA_DEN: u64 = 10;

/// inflight の「制限なし」を表す値
///
/// Option<u64> の内部表現から外部 API (u64) に変換する際に使用する。
/// mod.rs では `cap.min(inflight_lo())` パターンで自然に「無制限」として機能する。
const INFLIGHT_UNLIMITED: u64 = u64::MAX;

/// inflight モデル
///
/// min_rtt フィルタ、ACK aggregation 推定、inflight 上下限を管理する。
#[derive(Debug)]
pub struct Model {
    // --- min_rtt ---
    /// 最小 RTT
    min_rtt: Option<Duration>,
    /// min_rtt のタイムスタンプ
    min_rtt_stamp: Option<Timestamp>,

    // --- ProbeRTT スケジューリング ---
    /// ProbeRTT 用の最小 RTT
    probe_rtt_min_delay: Option<Duration>,
    /// ProbeRTT 用のタイムスタンプ
    probe_rtt_min_stamp: Option<Timestamp>,
    /// ProbeRTT 間隔が期限切れか
    probe_rtt_expired: bool,

    // --- ExtraACKed (ACK aggregation 推定) ---
    /// ExtraACKed フィルタ
    extra_acked_filter: RoundBasedMaxFilter,
    /// ACK aggregation 間隔の開始時刻
    extra_acked_interval_start: Option<Timestamp>,
    /// ACK aggregation 間隔中の配送バイト数
    extra_acked_delivered: u64,
    /// フィルタ出力値
    extra_acked: u64,

    // --- inflight 上下限 ---
    /// inflight 上限 (ProbeBW_UP 中のロスト応答で設定)
    /// None = 制限なし (初期状態、または未設定)
    inflight_hi: Option<u64>,
    /// inflight 下限 (ロスト応答で Beta を適用して縮小)
    /// None = 制限なし (初期状態、またはリセット済み)
    inflight_lo: Option<u64>,
}

impl Model {
    /// 新しい inflight モデルを作成する
    pub fn new() -> Self {
        Self {
            min_rtt: None,
            min_rtt_stamp: None,

            probe_rtt_min_delay: None,
            probe_rtt_min_stamp: None,
            probe_rtt_expired: false,

            extra_acked_filter: RoundBasedMaxFilter::new(EXTRA_ACKED_FILTER_LEN),
            extra_acked_interval_start: None,
            extra_acked_delivered: 0,
            extra_acked: 0,

            inflight_hi: None,
            inflight_lo: None,
        }
    }

    // --- アクセサ ---

    /// 最小 RTT を返す
    pub fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt
    }

    /// ExtraACKed 値を返す
    pub fn extra_acked(&self) -> u64 {
        self.extra_acked
    }

    /// inflight 上限を返す (未設定の場合は INFLIGHT_UNLIMITED)
    pub fn inflight_hi(&self) -> u64 {
        self.inflight_hi.unwrap_or(INFLIGHT_UNLIMITED)
    }

    /// inflight 上限が設定済みか
    pub fn has_inflight_hi(&self) -> bool {
        self.inflight_hi.is_some()
    }

    /// inflight 上限を設定する
    pub fn set_inflight_hi(&mut self, value: u64) {
        self.inflight_hi = Some(value);
    }

    /// inflight 下限を返す (未設定の場合は INFLIGHT_UNLIMITED)
    pub fn inflight_lo(&self) -> u64 {
        self.inflight_lo.unwrap_or(INFLIGHT_UNLIMITED)
    }

    /// ProbeRTT が期限切れかを返す
    pub fn probe_rtt_expired(&self) -> bool {
        self.probe_rtt_expired
    }

    // --- min_rtt 更新 ---

    /// min_rtt フィルタを更新する
    ///
    /// draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.5.3
    pub fn update_min_rtt(&mut self, rtt_sample: Duration, now: Timestamp) {
        // ProbeRTT スケジューリング
        self.probe_rtt_expired = match self.probe_rtt_min_stamp {
            Some(stamp) => now >= stamp + PROBE_RTT_INTERVAL,
            // 初回測定には古いサンプルがない。初回 ACK で ProbeRTT に入ると
            // Startup の cwnd を不必要に縮めるため、測定期間をここから始める。
            // draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.4.4 の
            // 経過時間による再測定に対応する。draft 改訂で期間は変わり得る。
            None => false,
        };

        if self.probe_rtt_min_delay.is_none_or(|d| rtt_sample < d) || self.probe_rtt_expired {
            self.probe_rtt_min_delay = Some(rtt_sample);
            self.probe_rtt_min_stamp = Some(now);
        }

        // min_rtt 更新
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

    /// ProbeRTT 完了時にタイマーをリセットする
    pub fn schedule_next_probe_rtt(&mut self, now: Timestamp) {
        self.probe_rtt_min_stamp = Some(now);
    }

    // --- ExtraACKed 更新 ---

    /// ACK aggregation 推定を更新する
    ///
    /// draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.5.5
    ///
    /// `filter_len` は extra_acked フィルタのウィンドウ長 (ラウンド数)。
    /// BBRv2 は常に `EXTRA_ACKED_FILTER_LEN` (10) を渡す。
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

    /// ACK aggregation 間隔をリセットする (アイドル復帰時)
    pub fn reset_ack_aggregation_interval(&mut self) {
        self.extra_acked_interval_start = None;
    }

    // --- inflight 上下限 ---

    /// inflight 上限を引き上げる
    pub fn raise_inflight_hi(&mut self, delta: u64) {
        self.inflight_hi = Some(self.inflight_hi().saturating_add(delta));
    }

    /// 初回ロスト時に inflight 下限を初期化する
    ///
    /// inflight_lo が未設定の場合のみ cwnd で初期化する。
    pub fn init_inflight_lo(&mut self, cwnd: u64) {
        if self.inflight_lo.is_none() {
            self.inflight_lo = Some(cwnd);
        }
    }

    /// ロスト応答で inflight 下限を更新する
    ///
    /// inflight_lo = max(inflight_latest, Beta * inflight_lo)
    ///
    /// 事前条件: init_inflight_lo が呼ばれていること。
    pub fn update_inflight_lo(&mut self, inflight_latest: u64) {
        let current = self.inflight_lo();
        self.inflight_lo = Some(inflight_latest.max(current.saturating_mul(BETA_NUM) / BETA_DEN));
    }

    /// inflight 下限をリセットする (ProbeBW_REFILL 遷移時等)
    pub fn reset_inflight_lo(&mut self) {
        self.inflight_lo = None;
    }
}

impl Default for Model {
    fn default() -> Self {
        Self::new()
    }
}
