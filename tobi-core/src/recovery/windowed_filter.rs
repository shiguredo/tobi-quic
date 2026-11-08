// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! ウィンドウ化最大/最小フィルタ
//!
//! BBR が帯域推定 (max_bw) と RTT 追跡 (min_rtt) に使用する。
//! ウィンドウ期間内の最大値または最小値を追跡する。
//!
//! ## 参考
//!
//! - draft-ietf-ccwg-bbr-06 Section 5.5.3 (max_bw フィルタ)
//! - draft-ietf-ccwg-bbr-06 Section 5.5.7 (min_rtt フィルタ)

use alloc::collections::VecDeque;

use crate::time::{Duration, Timestamp};

// ---------------------------------------------------------------------------
// 汎用ウィンドウ化フィルタ (時間ベース)
// ---------------------------------------------------------------------------

/// 時間ベースのウィンドウ化最大フィルタ
///
/// `window_length` 以内の最大値を追跡する。
/// ウィンドウが期限切れになると、新しいサンプルで置き換える。
#[derive(Debug, Clone)]
pub struct WindowedMaxFilter<T: Copy + PartialOrd> {
    /// 現在の値
    value: Option<T>,
    /// 最終更新時刻
    last_updated: Option<Timestamp>,
    /// ウィンドウ長
    window_length: Duration,
}

impl<T: Copy + PartialOrd> WindowedMaxFilter<T> {
    /// 新しいフィルタを作成する
    pub fn new(window_length: Duration) -> Self {
        Self {
            value: None,
            last_updated: None,
            window_length,
        }
    }

    /// サンプルで更新する
    ///
    /// ウィンドウが期限切れ、または新しいサンプルが現在の値以上の場合に更新する。
    pub fn update(&mut self, sample: T, now: Timestamp) {
        if self.is_expired(now) || self.value.is_none_or(|v| sample >= v) {
            self.value = Some(sample);
            self.last_updated = Some(now);
        }
    }

    /// 現在の値を返す
    pub fn value(&self) -> Option<T> {
        self.value
    }

    /// ウィンドウが期限切れか
    pub fn is_expired(&self, now: Timestamp) -> bool {
        match self.last_updated {
            Some(updated) => (now - updated) >= self.window_length,
            None => false,
        }
    }

    /// 最終更新時刻を返す
    pub fn last_updated(&self) -> Option<Timestamp> {
        self.last_updated
    }

    /// 最終更新時刻を上書きする (ProbeRTT スケジューリング用)
    pub fn set_last_updated(&mut self, now: Timestamp) {
        self.last_updated = Some(now);
    }

    /// 値をリセットする
    pub fn reset(&mut self) {
        self.value = None;
        self.last_updated = None;
    }
}

/// 時間ベースのウィンドウ化最小フィルタ
///
/// `window_length` 以内の最小値を追跡する。
/// ウィンドウが期限切れになると、新しいサンプルで置き換える。
#[derive(Debug, Clone)]
pub struct WindowedMinFilter<T: Copy + PartialOrd> {
    /// 現在の値
    value: Option<T>,
    /// 最終更新時刻
    last_updated: Option<Timestamp>,
    /// ウィンドウ長
    window_length: Duration,
}

impl<T: Copy + PartialOrd> WindowedMinFilter<T> {
    /// 新しいフィルタを作成する
    pub fn new(window_length: Duration) -> Self {
        Self {
            value: None,
            last_updated: None,
            window_length,
        }
    }

    /// サンプルで更新する
    ///
    /// ウィンドウが期限切れ、または新しいサンプルが現在の値以下の場合に更新する。
    pub fn update(&mut self, sample: T, now: Timestamp) {
        if self.is_expired(now) || self.value.is_none_or(|v| sample <= v) {
            self.value = Some(sample);
            self.last_updated = Some(now);
        }
    }

    /// 現在の値を返す
    pub fn value(&self) -> Option<T> {
        self.value
    }

    /// ウィンドウが期限切れか
    pub fn is_expired(&self, now: Timestamp) -> bool {
        match self.last_updated {
            Some(updated) => (now - updated) >= self.window_length,
            None => false,
        }
    }

    /// 最終更新時刻を返す
    pub fn last_updated(&self) -> Option<Timestamp> {
        self.last_updated
    }

    /// 最終更新時刻を上書きする
    pub fn set_last_updated(&mut self, now: Timestamp) {
        self.last_updated = Some(now);
    }

    /// 値をリセットする
    pub fn reset(&mut self) {
        self.value = None;
        self.last_updated = None;
    }
}

// ---------------------------------------------------------------------------
// ラウンドベースのウィンドウ化最大フィルタ
// ---------------------------------------------------------------------------

/// ラウンドベースのウィンドウ化最大フィルタ
///
/// BBR の max_bw 追跡に使用する。N ラウンド以内の最大値を追跡する。
/// draft-ietf-ccwg-bbr-06 Section 5.5.3:
/// max_bw フィルタのウィンドウ長は 2 (現在と前の ProbeBW サイクル)。
///
/// draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.5.3.2:
/// max_bw フィルタのウィンドウ長は 2。
#[derive(Debug, Clone)]
pub struct RoundBasedMaxFilter {
    /// ラウンドの昇順かつ値の降順に保持する最大値の候補
    samples: VecDeque<(u64, u64)>,
    /// ウィンドウ長 (ラウンド数)
    window_length: u64,
}

impl RoundBasedMaxFilter {
    /// 新しいフィルタを作成する
    pub fn new(window_length: u64) -> Self {
        Self {
            samples: VecDeque::new(),
            window_length,
        }
    }

    /// サンプルで更新する
    ///
    /// 現在ラウンドとの差がウィンドウ長未満のサンプルの最大値を保持する。
    /// `current_round` は単調非減少で渡すこと。
    pub fn update(&mut self, sample: u64, current_round: u64) {
        self.update_with_window_length(sample, current_round, self.window_length);
    }

    /// 呼び出しごとにウィンドウ長を指定してサンプルで更新する
    ///
    /// BBR の extra_acked フィルタは Startup 中と定常状態でウィンドウ長が
    /// 異なるため (draft-ietf-ccwg-bbr-06 Section 5.5.9)、ウィンドウ長を
    /// 呼び出し単位で渡せる必要がある。
    /// `current_round` は単調非減少で渡すこと。期限切れのサンプルは、後から
    /// ウィンドウ長を広げても復元しない。長さ 0 では今回のサンプルだけを保持する。
    pub fn update_with_window_length(
        &mut self,
        sample: u64,
        current_round: u64,
        window_length: u64,
    ) {
        // draft-ietf-ccwg-bbr-06 Section 5.5.3 の窓内最大値を保持する。
        // draft の改訂で期間が変わる可能性があるため、期限は呼び出し側から受け取る。
        // 最大値だけを覚えると、その期限切れ時に窓内の次点まで失ってしまう。
        while self
            .samples
            .front()
            .is_some_and(|&(round, _)| current_round.saturating_sub(round) >= window_length)
        {
            self.samples.pop_front();
        }
        // 新しいサンプル以上に古く、値も小さい候補は今後最大値にならない。
        while self
            .samples
            .back()
            .is_some_and(|&(_, value)| value <= sample)
        {
            self.samples.pop_back();
        }
        // 同じラウンドのより大きい候補が残っていれば、小さい値は不要。
        // 1 ラウンドに多数の ACK があっても、保持数はラウンド数で制限される。
        if self
            .samples
            .back()
            .is_none_or(|&(round, _)| round != current_round)
        {
            self.samples.push_back((current_round, sample));
        }
    }

    /// 現在の値を返す
    pub fn value(&self) -> Option<u64> {
        self.samples.front().map(|&(_, value)| value)
    }

    /// 値をリセットする
    pub fn reset(&mut self) {
        self.samples.clear();
    }
}

// ---------------------------------------------------------------------------
// MinRtt フィルタ (BBR 専用)
// ---------------------------------------------------------------------------

/// ProbeRTT 間隔 (5 秒)
///
/// draft-ietf-ccwg-bbr-06 Section 5.3.4:
/// draft-cardwell-iccrg-bbr-congestion-control-02 Section 2.14.2:
/// ProbeRTTInterval は 5 秒。将来変更される可能性あり。
pub const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(5);

/// min_rtt フィルタのウィンドウ長 (10 秒)
///
/// draft-cardwell-iccrg-bbr-congestion-control-02 Section 2.14.1:
/// MinRTTFilterLen は 10 秒。将来変更される可能性あり。
const MIN_RTT_FILTER_LEN: Duration = Duration::from_secs(10);

/// BBR 用 MinRtt フィルタ
///
/// probe_rtt (5 秒ウィンドウ) と min_rtt (10 秒ウィンドウ) の 2 層構造。
/// probe_rtt が期限切れになると ProbeRTT 状態への遷移を要求する。
///
/// draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.4.4:
/// BBRUpdateMinRTT() の実装。
#[derive(Debug, Clone)]
pub struct MinRttFilter {
    /// 短期最小 RTT (ProbeRTT 間隔で更新)
    probe_rtt: WindowedMinFilter<Duration>,
    /// 長期最小 RTT (MinRTTFilterLen で更新)
    min_rtt: WindowedMinFilter<Duration>,
    /// ProbeRTT の期限切れフラグ
    probe_rtt_expired: bool,
}

impl Default for MinRttFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl MinRttFilter {
    /// 新しいフィルタを作成する
    pub fn new() -> Self {
        Self {
            probe_rtt: WindowedMinFilter::new(PROBE_RTT_INTERVAL),
            min_rtt: WindowedMinFilter::new(MIN_RTT_FILTER_LEN),
            probe_rtt_expired: false,
        }
    }

    /// RTT サンプルで更新する
    ///
    /// draft-cardwell-iccrg-bbr-congestion-control-02 Section 4.3.4.4:
    /// BBRUpdateMinRTT() の実装。
    pub fn update(&mut self, rtt: Duration, now: Timestamp) {
        // probe_rtt の期限切れを記録してから更新する
        self.probe_rtt_expired = self.probe_rtt.is_expired(now);
        self.probe_rtt.update(rtt, now);

        let probe_rtt_value = self.probe_rtt.value().expect("just updated");

        // min_rtt が期限切れ、または probe_rtt が min_rtt より小さい場合に更新する
        if self.min_rtt.is_expired(now) || self.min_rtt.value().is_none_or(|v| probe_rtt_value <= v)
        {
            // min_rtt を probe_rtt の値と時刻で更新する (両者の同期を保つ)
            self.min_rtt.value = self.probe_rtt.value;
            self.min_rtt.last_updated = self.probe_rtt.last_updated;
        }
    }

    /// 現在の最小 RTT を返す
    pub fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt.value()
    }

    /// ProbeRTT が期限切れか (ProbeRTT 状態への遷移が必要)
    pub fn probe_rtt_expired(&self) -> bool {
        self.probe_rtt_expired
    }

    /// 次の ProbeRTT をスケジュールする (ProbeRTT 終了時に呼ぶ)
    pub fn schedule_next_probe_rtt(&mut self, now: Timestamp) {
        self.probe_rtt.set_last_updated(now);
    }
}
