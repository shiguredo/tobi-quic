// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! ACK 範囲追跡
//!
//! 受信したパケット番号を追跡し、ACK フレームを生成する。
//! パスごとに独立したインスタンスを持つ。

use alloc::vec::Vec;

use crate::connection::EcnCodepoint;
use crate::frame::ack::{Ack, AckRange, EcnCounts};
use crate::frame::receive_timestamps::{ReceiveTimestamps, TimestampRange};
use crate::time::Timestamp;
use crate::varint::VarInt;

/// 受信パケット番号の範囲
#[derive(Debug, Clone)]
struct Range {
    /// 範囲の開始 (含む)
    start: u64,
    /// 範囲の終了 (含む)
    end: u64,
}

/// ACK 範囲数の上限 (RFC 9000 Section 13.2.3)
///
/// 範囲数を制限してメモリと ACK 生成の CPU を bounded にする。
/// 68 範囲まで保持し、ACK フレームが 1 パケットに収まる範囲に抑える。
pub const MAX_ACK_RANGES: usize = 68;

/// ACK 遅延中に上限超過を許容する ACK 範囲数の余裕
///
/// ACK Frequency 拡張で ACK を遅延している間、上限を超えた範囲を即時 ACK で
/// 送るために一時的に保持する。上限を大きく超えた場合はメモリ保護のため
/// 従来どおり古い範囲を破棄する。
const DEFERRED_TRIM_MAX_OVERFLOW: usize = 8;

/// Receive Timestamps 拡張で保持する受信時刻の上限
///
/// draft-ietf-quic-receive-ts-03 Section 9 の資源制限に従い、ピアが広告した
/// 上限とは独立に保持数を bounded にする。新しい受信に合わせて古い記録を捨てる。
const MAX_RECEIVE_TIMESTAMPS_STORED: usize = 256;

/// ECN カウントの内部累計
///
/// 受信のたびに加算するため u64 で保持し、ACK フレーム構築時に
/// [`EcnCounts`] (VarInt) へ変換する。
#[derive(Debug, Clone, Copy, Default)]
struct EcnCountsCounter {
    ect0: u64,
    ect1: u64,
    ecn_ce: u64,
}

/// ACK 追跡器
#[derive(Debug)]
pub struct AckTracker {
    /// 受信パケット番号の範囲リスト (降順)
    ranges: Vec<Range>,
    /// 破棄済み範囲の下限 PN
    ///
    /// RFC 9000 Section 13.2.3: 古い範囲は破棄してよいが、破棄した範囲の PN を
    /// 以後 accept してはならない (MUST)。この値以下の PN は受信済みとして扱い、
    /// 再 ACK しない。
    min_pn: Option<u64>,
    /// ACK 送信が必要か
    ack_eliciting_received: bool,
    /// 最初の未 ACK の ack-eliciting パケット受信時刻
    first_ack_eliciting_time: Option<Timestamp>,
    /// 最大受信パケット番号に対応する受信時刻 (RFC 9000 Section 13.2.5)
    largest_received_time: Option<Timestamp>,
    /// 未 ACK の ack-eliciting パケット受信カウント
    ack_eliciting_count: u32,
    /// 受信パケットの ECN コードポイント別累計 (RFC 9000 Section 13.4.2)
    ///
    /// 接続全体の累計であり、ACK 送信後もリセットしない。ACK_ECN には
    /// 生成時点の累計を載せる。
    ecn_counts_received: EcnCountsCounter,
    /// ACK Frequency 拡張の制御状態 (draft-ietf-quic-ack-frequency-14 Section 4)
    ack_frequency: AckFrequencyState,
    /// 直前の受信パケットの ECN コードポイント
    ///
    /// draft-ietf-quic-ack-frequency-14 Section 6.3 の CE 遷移検出に使う。
    previous_ecn: EcnCodepoint,
    /// 直前の受信が CE で今回も CE だったかを判定するための遷移フラグ
    ce_transition: bool,
    /// 受信時刻の記録 (パケット番号, 受信時刻)
    ///
    /// draft-ietf-quic-receive-ts-03 Section 4.1 のタイムスタンプレンジ生成に使う。
    /// ACK を送るかどうかとは独立に記録し、フレーム生成時に拡張の
    /// ネゴシエーション状態に応じて使う。
    received_times: Vec<(u64, Timestamp)>,
}

/// ACK Frequency 拡張 (draft-ietf-quic-ack-frequency-14) で受信した制御状態
#[derive(Debug, Clone)]
struct AckFrequencyState {
    /// 最後に処理した ACK_FREQUENCY のシーケンス番号
    largest_processed_sequence_number: Option<u64>,
    /// ACK を送らずに受け取れる ack-eliciting パケットの最大数
    ack_eliciting_threshold: u64,
    /// ピアが要求した max_ack_delay (マイクロ秒)
    requested_max_ack_delay: Option<u64>,
    /// 再順序で即時 ACK を出す閾値
    reordering_threshold: u64,
    /// 最後に送信した ACK の largest_acknowledged
    largest_acked_sent: Option<u64>,
    /// 受信した ack-eliciting パケットの最大パケット番号
    largest_ack_eliciting_received: Option<u64>,
    /// 次の ACK 生成を強制する (IMMEDIATE_ACK / AckDelay タイマー)
    force_ack: bool,
}

impl Default for AckFrequencyState {
    fn default() -> Self {
        Self {
            largest_processed_sequence_number: None,
            // RFC 9000 Section 13.2.2 の既定動作 (2 個目で即時 ACK) に対応する
            ack_eliciting_threshold: 1,
            requested_max_ack_delay: None,
            // 既定では再順序を受けたら即時 ACK する (RFC 9000 Section 13.2.1)
            reordering_threshold: 1,
            largest_acked_sent: None,
            largest_ack_eliciting_received: None,
            force_ack: false,
        }
    }
}

impl AckFrequencyState {
    /// ACK_FREQUENCY を受信して制御が有効になっているか
    fn is_active(&self) -> bool {
        self.largest_processed_sequence_number.is_some()
    }
}

impl Default for AckTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// ACK トラッカーの内部値を VarInt へ変換する
///
/// ACK 範囲のパケット番号は受信時に 2^62-1 以下であることが検証済みで、
/// ACK 遅延・ECN 累計も varint の範囲に収まるため、値域外にはならない。
fn to_varint(value: u64) -> VarInt {
    VarInt::new(value).expect("ACK tracker value fits in 62-bit varint")
}

impl AckTracker {
    pub fn new() -> Self {
        Self {
            ranges: Vec::new(),
            min_pn: None,
            ack_eliciting_received: false,
            first_ack_eliciting_time: None,
            largest_received_time: None,
            ack_eliciting_count: 0,
            ecn_counts_received: EcnCountsCounter::default(),
            ack_frequency: AckFrequencyState::default(),
            previous_ecn: EcnCodepoint::NotEct,
            ce_transition: false,
            received_times: Vec::new(),
        }
    }

    /// 受信パケットの ECN コードポイントを記録する (RFC 9000 Section 13.4.2)
    ///
    /// `NotEct` はカウントしない (ECT / CE のみが対象)。
    pub fn record_ecn(&mut self, ecn: EcnCodepoint) {
        // draft-ietf-quic-ack-frequency-14 Section 6.3:
        // 前回が CE でなく今回が CE の遷移を記録する。
        self.ce_transition =
            matches!(ecn, EcnCodepoint::Ce) && !matches!(self.previous_ecn, EcnCodepoint::Ce);
        self.previous_ecn = ecn;
        match ecn {
            EcnCodepoint::NotEct => {}
            EcnCodepoint::Ect0 => self.ecn_counts_received.ect0 += 1,
            EcnCodepoint::Ect1 => self.ecn_counts_received.ect1 += 1,
            EcnCodepoint::Ce => self.ecn_counts_received.ecn_ce += 1,
        }
    }

    /// 受信した ECN コードポイントの累計を返す
    pub fn ecn_counts_received(&self) -> EcnCounts {
        EcnCounts {
            ect0: VarInt::new(self.ecn_counts_received.ect0)
                .expect("received ECN count fits in 62-bit varint"),
            ect1: VarInt::new(self.ecn_counts_received.ect1)
                .expect("received ECN count fits in 62-bit varint"),
            ecn_ce: VarInt::new(self.ecn_counts_received.ecn_ce)
                .expect("received ECN count fits in 62-bit varint"),
        }
    }

    /// パケット番号を記録する
    ///
    /// Receive Timestamps 拡張用のパケット別の受信時刻は記録しない。
    /// ACK Delay 用の最大番号の受信時刻は保持する。0-RTT / Initial /
    /// Handshake パケットと、拡張を使わない 1-RTT パケットに使う。
    pub fn record_received(&mut self, pn: u64, ack_eliciting: bool, now: Timestamp) {
        self.record_received_inner(pn, ack_eliciting, now, false);
    }

    /// パケット番号と受信時刻を記録する
    ///
    /// Receive Timestamps 拡張は post-handshake の 1-RTT パケットを対象とする
    /// ため、受信時刻を記録するのは 1-RTT パケットの受信時だけにする。
    pub fn record_received_with_timestamp(&mut self, pn: u64, ack_eliciting: bool, now: Timestamp) {
        self.record_received_inner(pn, ack_eliciting, now, true);
    }

    fn record_received_inner(
        &mut self,
        pn: u64,
        ack_eliciting: bool,
        now: Timestamp,
        record_timestamp: bool,
    ) {
        // 破棄済み範囲の PN は受信済み扱いとし、再 ACK しない
        if let Some(min_pn) = self.min_pn
            && pn <= min_pn
        {
            return;
        }
        // ACK Delay は最大のパケット番号の受信時刻から計算する。
        // ACK のみのパケットでも更新し、再順序や重複で時刻を上書きしない。
        if self.largest_received().is_none_or(|largest| pn > largest) {
            self.largest_received_time = Some(now);
        }
        if ack_eliciting {
            // RFC 9000 Section 13.2.1: 再順序またはギャップを検出した場合は
            // 即時 ACK を送る (SHOULD)。ACK Frequency 拡張が有効な場合は
            // ピアが指定した Reordering Threshold に従うため、ここでは扱わない。
            // 比較対象は受信済みの最大パケット番号を使う。ACK のみのパケットも
            // パケット番号空間を消費するため、ack-eliciting の最大値だけを
            // 使うとギャップを誤検知する。
            if !self.ack_frequency.is_active()
                && let Some(largest) = self.ranges.first().map(|range| range.end)
                && (pn < largest || pn > largest + 1)
            {
                self.ack_frequency.force_ack = true;
            }
            self.ack_eliciting_received = true;
            // ACK を送るまでに受信した ack-eliciting パケット数の上限。
            // 極端に長い ACK 遅延でも debug ビルドで overflow しないよう飽和させる。
            self.ack_eliciting_count = self.ack_eliciting_count.saturating_add(1);
            if self.first_ack_eliciting_time.is_none() {
                self.first_ack_eliciting_time = Some(now);
            }
            self.ack_frequency.largest_ack_eliciting_received = Some(
                self.ack_frequency
                    .largest_ack_eliciting_received
                    .map_or(pn, |current| current.max(pn)),
            );
        }
        self.insert_pn(pn);
        if record_timestamp {
            self.record_receive_timestamp(pn, now);
        }
        if self.ack_frequency.is_active()
            && self.ack_eliciting_received
            && self.ranges.len() > MAX_ACK_RANGES
        {
            // draft-ietf-quic-ack-frequency-14 Section 6:
            // ACK を遅延している間に ACK 範囲の上限を超えた場合、ここで古い範囲を
            // 破棄すると未送信の範囲が ACK されずに失われる。即時 ACK を強制し、
            // 破棄は ACK 生成後に行う。
            // 上限を大きく超える場合はメモリ保護のため従来どおり破棄する。
            if self.ranges.len() <= MAX_ACK_RANGES + DEFERRED_TRIM_MAX_OVERFLOW {
                self.ack_frequency.force_ack = true;
                return;
            }
        }
        self.enforce_range_limit();
    }

    /// 受信時刻を記録する
    ///
    /// basis (0) 以下の時刻はタイムスタンプとして報告できないため記録しない。
    fn record_receive_timestamp(&mut self, pn: u64, now: Timestamp) {
        if now.as_micros() == 0 {
            return;
        }
        self.received_times.push((pn, now));
        if self.received_times.len() > MAX_RECEIVE_TIMESTAMPS_STORED {
            self.received_times.remove(0);
        }
    }

    /// Receive Timestamps 拡張のタイムスタンプレンジを生成する
    ///
    /// (draft-ietf-quic-receive-ts-03 Section 4.1)
    /// 現在の ACK で確認応答するパケットのうち、受信時刻を記録済みのものを
    /// 受信時刻の降順に最大 `max_count` 件選び、連続するパケット番号ごとに
    /// タイムスタンプレンジへまとめる。`basis` は全セッションで固定の基準値、
    /// `exponent` はピアが広告した `receive_timestamps_exponent` である。
    pub fn generate_receive_timestamps(
        &self,
        largest_acknowledged: u64,
        first_ack_range: u64,
        ack_ranges: &[AckRange],
        max_count: u64,
        basis: u64,
        exponent: u32,
    ) -> Option<ReceiveTimestamps> {
        if max_count == 0 {
            return None;
        }
        let max_count = usize::try_from(max_count).unwrap_or(usize::MAX);

        // 現在の ACK が確認応答するパケットで、受信時刻を記録済みのものを選ぶ。
        let mut entries: Vec<(u64, u64)> = self
            .received_times
            .iter()
            .filter(|(pn, ts)| {
                *pn <= largest_acknowledged
                    && ts.as_micros() > basis
                    && ack_range_contains(largest_acknowledged, first_ack_range, ack_ranges, *pn)
            })
            .map(|(pn, ts)| (*pn, ts.as_micros()))
            .collect();
        if entries.is_empty() {
            return None;
        }
        // 受信時刻の降順 (最も新しい受信を優先して保持する)
        entries.sort_unstable_by_key(|entry| core::cmp::Reverse(entry.1));
        entries.truncate(max_count);

        let mut timestamp_ranges: Vec<TimestampRange> = Vec::new();
        let mut current: Option<TimestampRange> = None;
        let mut previous_ts: Option<u64> = None;
        let mut previous_pn: Option<u64> = None;
        for (pn, ts) in entries {
            // 最初の delta は basis からの差、以降は直前のタイムスタンプとの差。
            let delta = match previous_ts {
                Some(previous) => previous.saturating_sub(ts),
                None => ts.saturating_sub(basis),
            };
            // exponent はピアが広告する値で、通常は 20 以下に検証されている。
            // 直接 API を呼ぶ利用者が 64 以上を渡しても debug ビルドで
            // panic しないよう、シフト量を 63 に丸める。
            let encoded = delta >> exponent.min(63);
            if encoded > crate::varint::MAX_VALUE {
                // varint で表現できない差分は報告しない (best effort)
                return None;
            }
            let continues = current.is_some() && previous_pn == Some(pn.saturating_add(1));
            if continues {
                current
                    .as_mut()
                    .expect("current range exists")
                    .deltas
                    .push(to_varint(encoded));
            } else {
                if let Some(range) = current.take() {
                    timestamp_ranges.push(range);
                }
                current = Some(TimestampRange {
                    delta_largest_acknowledged: to_varint(largest_acknowledged - pn),
                    deltas: alloc::vec![to_varint(encoded)],
                });
            }
            previous_ts = Some(ts);
            previous_pn = Some(pn);
        }
        if let Some(range) = current {
            timestamp_ranges.push(range);
        }
        Some(ReceiveTimestamps { timestamp_ranges })
    }

    /// ACK フレームを生成する
    ///
    /// ACK 送信が必要な場合に Some を返す。
    pub fn generate_ack(&mut self, ack_delay: u64) -> Option<Ack> {
        if self.ranges.is_empty() || !(self.ack_eliciting_received || self.ack_frequency.force_ack)
        {
            return None;
        }

        let largest = self.ranges[0].end;
        let first_range = self.ranges[0].end - self.ranges[0].start;

        let mut ack_ranges = Vec::new();
        for i in 1..self.ranges.len() {
            let gap = self.ranges[i - 1]
                .start
                .saturating_sub(self.ranges[i].end)
                .saturating_sub(2);
            let range_len = self.ranges[i].end - self.ranges[i].start;
            ack_ranges.push(AckRange {
                gap: to_varint(gap),
                ack_range: to_varint(range_len),
            });
        }

        self.ack_eliciting_received = false;
        self.ack_eliciting_count = 0;
        self.first_ack_eliciting_time = None;
        // 遅延中に上限を超えて保持した範囲は、この ACK で一度報告済みになるため
        // ここで破棄して上限内に戻す (draft-ietf-quic-ack-frequency-14 Section 6:
        // 全パケットは少なくとも 1 回 ACK されなければならない)。
        self.enforce_range_limit();
        // 送信した ACK の largest_acknowledged を記録する。
        // 再順序に基づく即時 ACK の判定 (draft-ietf-quic-ack-frequency-14 Section 6.2)
        // で Largest Acked として使う。
        self.ack_frequency.largest_acked_sent = Some(largest);
        self.ack_frequency.force_ack = false;

        // RFC 9000 Section 13.4.2: 受信した ECT(0) / ECT(1) / CE の累計を
        // ACK_ECN として報告する。累計が 0 の場合は ECN 非対応のピアと
        // 区別できないため ACK_ECN を付けない。
        let ecn_counter = self.ecn_counts_received;
        let ecn_counts =
            if ecn_counter.ect0 == 0 && ecn_counter.ect1 == 0 && ecn_counter.ecn_ce == 0 {
                None
            } else {
                Some(self.ecn_counts_received())
            };

        Some(Ack {
            largest_acknowledged: to_varint(largest),
            ack_delay: to_varint(ack_delay),
            first_ack_range: to_varint(first_range),
            ack_ranges,
            ecn_counts,
        })
    }

    /// ACK 送信が必要か
    ///
    /// 未 ACK の ack-eliciting パケットがあるかを返す。IMMEDIATE_ACK などの
    /// 強制フラグはここには含めない (未 ACK パケットが無い状態で強制しても
    /// ACK に載せる範囲が無いため)。
    pub fn needs_ack(&self) -> bool {
        self.ack_eliciting_received && !self.ranges.is_empty()
    }

    /// 即座に ACK を送信すべきか (RFC 9000 Section 13.2.1 / 13.2.2)
    ///
    /// 2 個以上の ack-eliciting パケットを受信した場合、または再順序・ギャップ・
    /// CE などで即時 ACK が要求されている場合に true を返す。
    pub fn should_send_ack_immediately(&self) -> bool {
        self.ack_frequency.force_ack || self.ack_eliciting_count >= 2
    }

    /// 今すぐ ACK を生成すべきか
    ///
    /// ACK Frequency 拡張を受信していない場合は、RFC 9000 Section 13.2.2 に
    /// 従い 2 個以上の ack-eliciting パケットを受信するまで遅延する。再順序・
    /// ギャップ・CE は `force_ack` で即時送信する (Section 13.2.1)。
    /// 拡張を受信した後は Ack-Eliciting Threshold を超えた場合、または
    /// IMMEDIATE_ACK / AckDelay タイマーで強制された場合に true を返す
    /// (draft-ietf-quic-ack-frequency-14 Section 6)。
    pub fn should_send_ack_now(&self) -> bool {
        // 未 ACK の ack-eliciting パケットが無ければ、強制フラグが残っていても
        // ACK を生成しない (古い AckDelay タイマーによる空 ACK を防ぐ)。
        if !self.ack_eliciting_received {
            return false;
        }
        if self.ack_frequency.force_ack {
            return true;
        }
        if self.ack_frequency.is_active() {
            return self.ack_eliciting_count as u64 > self.ack_frequency.ack_eliciting_threshold;
        }
        self.ack_eliciting_count >= 2
    }

    /// ACK 遅延タイマーの期限を返す
    ///
    /// 1 個の ack-eliciting パケットを受信し、まだ ACK を送信していない場合に
    /// max_ack_delay 後の期限を返す (RFC 9000 Section 13.2.1 / 13.2.2)。
    /// ACK Frequency 拡張が有効な場合は 1 個以上受信していれば期限を返す
    /// (draft-ietf-quic-ack-frequency-14 Section 6)。
    pub fn ack_delay_deadline(&self, max_ack_delay: crate::time::Duration) -> Option<Timestamp> {
        let target = if self.ack_frequency.is_active() {
            self.ack_eliciting_count >= 1
        } else {
            self.ack_eliciting_count == 1
        };
        if target {
            self.first_ack_eliciting_time.map(|t| t + max_ack_delay)
        } else {
            None
        }
    }

    /// 受信した ACK_FREQUENCY のシーケンス番号が新しく適用すべきものか
    ///
    /// draft-ietf-quic-ack-frequency-14 Section 4:
    /// 最後に処理した Sequence Number 以下は無視しなければならない (MUST)。
    pub fn is_new_ack_frequency_sequence(&self, sequence_number: u64) -> bool {
        self.ack_frequency
            .largest_processed_sequence_number
            .is_none_or(|processed| sequence_number > processed)
    }

    /// ACK_FREQUENCY フレームを適用する (draft-ietf-quic-ack-frequency-14 Section 4)
    ///
    /// シーケンス番号が既に処理した値以下の場合は古いフレームとして無視する (MUST)。
    /// 戻り値は適用したかどうか。値の妥当性検証 (Requested Max Ack Delay) は
    /// 呼び出し側が行う。
    pub fn apply_ack_frequency(
        &mut self,
        sequence_number: u64,
        ack_eliciting_threshold: u64,
        requested_max_ack_delay: u64,
        reordering_threshold: u64,
    ) -> bool {
        if self
            .ack_frequency
            .largest_processed_sequence_number
            .is_some_and(|processed| sequence_number <= processed)
        {
            return false;
        }
        self.ack_frequency.largest_processed_sequence_number = Some(sequence_number);
        self.ack_frequency.ack_eliciting_threshold = ack_eliciting_threshold;
        self.ack_frequency.requested_max_ack_delay = Some(requested_max_ack_delay);
        self.ack_frequency.reordering_threshold = reordering_threshold;
        true
    }

    /// ACK Frequency 拡張が有効か (ACK_FREQUENCY を受信済みか)
    pub fn is_ack_frequency_active(&self) -> bool {
        self.ack_frequency.is_active()
    }

    /// ピアが要求した max_ack_delay (マイクロ秒) を返す
    pub fn requested_max_ack_delay_micros(&self) -> Option<u64> {
        self.ack_frequency.requested_max_ack_delay
    }

    /// 次の ACK 生成を強制する
    ///
    /// IMMEDIATE_ACK の受信時と AckDelay タイマー発火時に使う。
    pub fn request_immediate_ack(&mut self) {
        self.ack_frequency.force_ack = true;
    }

    /// ECN の CE 遷移で即時 ACK を送るべきか
    ///
    /// draft-ietf-quic-ack-frequency-14 Section 6.3:
    /// Ack-Eliciting Threshold が 1 より大きい場合、CE マーク付きパケットを
    /// 受信し、直前の受信パケットが CE でなければ即時 ACK する (SHOULD)。
    /// 遷移フラグは 1 度だけ消費する。
    ///
    /// 閾値が 0 の場合は全 ack-eliciting パケットを即時 ACK し、1 の場合は
    /// RFC 9000 Section 13.2.1 の既定 ACK 戦略 (本実装では 2 個受信までの
    /// 遅延とタイマー) に委ねるため、ここでは CE 遷移による追加の即時 ACK を
    /// 行わない。拡張未使用時は RFC 9000 Section 13.2.1 に従い、CE マーク付き
    /// パケットの受信を即時 ACK する (SHOULD)。
    pub fn take_ecn_transition_ack(&mut self) -> bool {
        let transition = self.ce_transition;
        self.ce_transition = false;
        if !transition {
            return false;
        }
        if self.ack_frequency.is_active() {
            self.ack_frequency.ack_eliciting_threshold > 1
        } else {
            true
        }
    }

    /// 再順序に基づき即時 ACK を送るべきか
    /// (draft-ietf-quic-ack-frequency-14 Section 6.2)
    ///
    /// `received_pn` は順序外で受信した ack-eliciting パケットの番号。
    pub fn should_ack_for_reordering(&self, received_pn: u64) -> bool {
        if !self.ack_frequency.is_active() {
            // 拡張を受信していない場合は従来の挙動 (受信経路側で処理) を変えない
            return false;
        }
        let threshold = self.ack_frequency.reordering_threshold;
        if threshold == 0 {
            // 再順序では即時 ACK しない
            return false;
        }
        let Some(largest_unacked) = self.ack_frequency.largest_ack_eliciting_received else {
            return false;
        };
        let largest_acked = self.ack_frequency.largest_acked_sent;
        // 条件 2: 受信パケット番号が Largest Acked - Reordering Threshold 以下。
        // 送信側がすでに spurious なロスト判定をした可能性があるパケット。
        if let Some(largest_acked) = largest_acked
            && largest_acked >= threshold
            && received_pn <= largest_acked - threshold
        {
            return true;
        }
        // 条件 1: 最小の Unreported Missing と Largest Unacked の差が閾値以上。
        // 差が閾値以上になるのは Missing が Largest Unacked - Reordering Threshold
        // 以下の場合だけなので、その範囲だけを調べる。
        // Largest Reported Missing が未確定 (ACK 未送信) の場合は全範囲を調べる。
        let search_start = largest_acked.map_or(0, |largest_acked| {
            largest_acked.saturating_sub(threshold).saturating_add(1)
        });
        let Some(limit) = largest_unacked.checked_sub(threshold) else {
            // 最大受信番号より大きい閾値に達する missing は存在しない。
            return false;
        };
        let mut candidate = search_start;
        // 破棄した範囲は受信済み扱いなので、パケット番号ごとの走査を省く。
        // 大きな番号を飛び飛びに受信しても、走査量を ACK 範囲数に抑える。
        if let Some(floor) = self.min_pn {
            if floor >= limit {
                return false;
            }
            candidate = candidate.max(floor + 1);
        }
        if candidate > limit {
            return false;
        }
        for range in self.ranges.iter().rev() {
            if range.end < candidate {
                continue;
            }
            if range.start > candidate {
                return true;
            }
            if range.end >= limit {
                return false;
            }
            candidate = range.end + 1;
        }
        candidate <= limit
    }

    /// 最初の ack-eliciting パケット受信時刻を返す
    pub fn first_ack_eliciting_time(&self) -> Option<Timestamp> {
        self.first_ack_eliciting_time
    }

    /// 最大受信パケット番号の受信時刻を返す
    ///
    /// ACK Delay の基準時刻であり、ACK を生成した後も保持する。
    pub fn largest_received_time(&self) -> Option<Timestamp> {
        self.largest_received_time
    }

    /// 受信した最大パケット番号
    pub fn largest_received(&self) -> Option<u64> {
        self.ranges.first().map(|r| r.end)
    }

    /// パケット番号が既に受信済みかを判定する (RFC 9000 Section 13.2.3)
    pub fn is_already_received(&self, pn: u64) -> bool {
        // 上限超過で破棄した範囲の PN は受信済み扱いにする (MUST)
        if let Some(min_pn) = self.min_pn
            && pn <= min_pn
        {
            return true;
        }
        self.ranges.iter().any(|r| pn >= r.start && pn <= r.end)
    }

    /// 追跡中の ACK 範囲数を返す (テスト・監視用)
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// 破棄済み範囲の下限 PN を返す (テスト・監視用)
    pub fn min_pn(&self) -> Option<u64> {
        self.min_pn
    }

    /// 範囲数が上限を超えたら最古の範囲を破棄し、下限 PN を引き上げる
    ///
    /// RFC 9000 Section 13.2.3: 古い ACK 範囲は破棄してよいが、破棄した範囲の
    /// パケット番号を以後 accept しないため下限 PN を保持しなければならない (MUST)。
    fn enforce_range_limit(&mut self) {
        while self.ranges.len() > MAX_ACK_RANGES {
            // 降順リストの末尾が最古 (PN が最小) の範囲
            let oldest = self.ranges.pop().expect("ranges is not empty");
            let end = oldest.end;
            self.min_pn = Some(self.min_pn.map_or(end, |current| current.max(end)));
        }
    }

    /// パケット番号を範囲リストに挿入する
    ///
    /// ranges は降順 (end が大きい順) を維持する。
    /// 二分探索で挿入位置を決定し、ソートを不要にする。
    fn insert_pn(&mut self, pn: u64) {
        // 既存の範囲を拡張できるか確認
        for range in &mut self.ranges {
            if pn >= range.start && pn <= range.end {
                // 既に含まれている
                return;
            }
            if pn == range.end + 1 {
                range.end = pn;
                self.merge_ranges();
                return;
            }
            if pn + 1 == range.start {
                range.start = pn;
                self.merge_ranges();
                return;
            }
        }

        // 降順リストへの二分探索挿入
        let pos = self.ranges.partition_point(|r| r.end > pn);
        self.ranges.insert(pos, Range { start: pn, end: pn });
    }

    /// 隣接する範囲をマージする
    ///
    /// ranges が降順であることを前提とし、ソートせずに隣接範囲をマージする。
    fn merge_ranges(&mut self) {
        let mut i = 0;
        while i + 1 < self.ranges.len() {
            if self.ranges[i].start <= self.ranges[i + 1].end + 1 {
                let merged_start = self.ranges[i].start.min(self.ranges[i + 1].start);
                self.ranges[i].start = merged_start;
                self.ranges.remove(i + 1);
            } else {
                i += 1;
            }
        }
    }
}

/// ACK レンジが指定したパケット番号を確認応答しているかを返す
///
/// `largest_acknowledged` / `first_ack_range` / `ack_ranges` は
/// `Ack` のフィールドと同じ表現 (RFC 9000 Section 19.3)。
fn ack_range_contains(
    largest_acknowledged: u64,
    first_ack_range: u64,
    ack_ranges: &[AckRange],
    pn: u64,
) -> bool {
    if pn > largest_acknowledged {
        return false;
    }
    let mut range_largest = largest_acknowledged;
    let mut range_len = first_ack_range;
    for i in 0..=ack_ranges.len() {
        let range_smallest = range_largest.saturating_sub(range_len);
        if pn >= range_smallest && pn <= range_largest {
            return true;
        }
        let Some(range) = ack_ranges.get(i) else {
            break;
        };
        // 次のレンジは、直前のレンジの最小値から gap + 2 だけ小さい番号から始まる
        let Some(next_largest) = range_smallest
            .checked_sub(range.gap.as_u64())
            .and_then(|value| value.checked_sub(2))
        else {
            break;
        };
        range_largest = next_largest;
        range_len = range.ack_range.as_u64();
    }
    false
}
