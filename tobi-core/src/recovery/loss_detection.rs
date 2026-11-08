// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 損失検出 (RFC 9002 Section 6)
//!
//! パスごとに独立したインスタンスを持つ。
//! ACK 受信時のパケット閾値 / 時間閾値による損失判定と、
//! PTO (Probe Timeout) タイマーの管理を行う。

use alloc::vec::Vec;

use crate::recovery::rtt::RttEstimator;
use crate::recovery::sent_packets::{SentPacket, SentPackets};
use crate::scheduler::LossReason;
use crate::time::{Duration, Timestamp};

/// パケット閾値 (RFC 9002 Section 6.1.1)
const K_PACKET_THRESHOLD: u64 = 3;

/// 時間閾値の分子 (RFC 9002 Section 6.1.2)
const K_TIME_THRESHOLD_NUM: u64 = 9;

/// 時間閾値の分母 (RFC 9002 Section 6.1.2)
const K_TIME_THRESHOLD_DEN: u64 = 8;

/// タイマー粒度 (RFC 9002 Section 6.1.2)
const K_GRANULARITY: Duration = Duration::from_millis(1);

/// パケット番号空間 (RFC 9002 Section 4.1)
///
/// 各空間は独立したパケット番号空間を持ち、損失検出と PTO も空間ごとに
/// 計算する。0-RTT と 1-RTT は Application Data 空間を共有する
/// (RFC 9000 Section 12.3)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PacketNumberSpace {
    /// Initial 空間
    Initial,
    /// Handshake 空間
    Handshake,
    /// Application Data 空間 (0-RTT / 1-RTT)
    ApplicationData,
}

impl PacketNumberSpace {
    /// 全空間 (Initial, Handshake, Application Data の順)
    pub const ALL: [Self; 3] = [Self::Initial, Self::Handshake, Self::ApplicationData];

    /// 空間ごとの配列の添字を返す
    ///
    /// `ALL` と同じ順序 (Initial = 0, Handshake = 1, Application Data = 2)。
    /// 空間ごとに状態を持つ配列を引くときに使う。
    pub(crate) fn index(self) -> usize {
        match self {
            Self::Initial => 0,
            Self::Handshake => 1,
            Self::ApplicationData => 2,
        }
    }

    /// ログや qlog で使う空間名を返す
    pub fn name(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Handshake => "handshake",
            Self::ApplicationData => "application_data",
        }
    }
}

/// パケット番号空間ごとの損失検出器 (RFC 9002 Section 4.1 / 6.2)
///
/// Multipath ではパスごとに 1 つ持ち、(パス, パケット番号空間) の組で
/// `time_of_last_ack_eliciting_packet` / `loss_time` / `pto_count` を管理する。
///
/// RFC 9002 Section 6.2.1: PTO の指数的な増加は空間をまたいで行うため、
/// `on_pto_expired` / `on_ack_received` は全空間へ同時に適用する。
/// 空間ごとの値はあくまで各空間の PTO 期限計算に使い、バックオフ係数は同期させる。
#[derive(Debug, Default)]
pub struct LossDetectors {
    initial: LossDetector,
    handshake: LossDetector,
    application_data: LossDetector,
}

impl LossDetectors {
    /// 全空間を初期状態で作成する
    pub fn new() -> Self {
        Self::default()
    }

    /// 指定空間の損失検出器を返す
    pub fn get(&self, space: PacketNumberSpace) -> &LossDetector {
        match space {
            PacketNumberSpace::Initial => &self.initial,
            PacketNumberSpace::Handshake => &self.handshake,
            PacketNumberSpace::ApplicationData => &self.application_data,
        }
    }

    /// 指定空間の損失検出器を可変借用で返す
    pub fn get_mut(&mut self, space: PacketNumberSpace) -> &mut LossDetector {
        match space {
            PacketNumberSpace::Initial => &mut self.initial,
            PacketNumberSpace::Handshake => &mut self.handshake,
            PacketNumberSpace::ApplicationData => &mut self.application_data,
        }
    }

    fn all_mut(&mut self) -> [&mut LossDetector; 3] {
        [
            &mut self.initial,
            &mut self.handshake,
            &mut self.application_data,
        ]
    }

    /// 指定空間の損失検出状態を破棄して初期化する
    ///
    /// その空間の `time_of_last_ack_eliciting_packet` と `loss_time` を破棄する。
    /// 0-RTT 拒否後の再初期化にも使うため、共有 PTO バックオフは維持する。
    /// Initial / Handshake 鍵の破棄では、呼び出し側が [`Self::reset_pto_backoff`]
    /// も実行する (RFC 9002 Appendix A.11)。
    pub fn reset_space(&mut self, space: PacketNumberSpace) {
        let pto_count = self.pto_count();
        let detector = self.get_mut(space);
        *detector = LossDetector::new();
        // バックオフは空間横断の共有値なので維持する
        detector.pto_count = pto_count;
    }

    /// 指定空間で ACK 誘発パケットを送信したことを記録する
    pub fn on_packet_sent(
        &mut self,
        space: PacketNumberSpace,
        time_sent: Timestamp,
        ack_eliciting: bool,
    ) {
        self.get_mut(space).on_packet_sent(time_sent, ack_eliciting);
    }

    /// ACK 受信時に PTO バックオフをリセットする (RFC 9002 Section 6.2.1)
    ///
    /// バックオフは空間横断で 1 つの値として扱うため、全空間のカウンタを
    /// 同時にリセットする。
    pub fn on_ack_received(&mut self) {
        self.reset_pto_backoff();
    }

    /// 空間横断の PTO バックオフをリセットする。
    ///
    /// Initial / Handshake 鍵の破棄にも使う (RFC 9002 Appendix A.11)。
    /// ACK を受けていなくても、前の空間の待機時間を次の空間へ持ち越さない。
    pub fn reset_pto_backoff(&mut self) {
        for detector in self.all_mut() {
            detector.on_ack_received();
        }
    }

    /// PTO 発火時に PTO バックオフを進める (RFC 9002 Section 6.2.1)
    ///
    /// RFC 9002 Section 6.2.1: "a timeout in the Initial packet number space
    /// doubles the length of the timeout in the Handshake packet number space"
    /// のため、全空間のカウンタを同時に進める。
    pub fn on_pto_expired(&mut self) {
        for detector in self.all_mut() {
            detector.on_pto_expired();
        }
    }

    /// 同期している PTO バックオフの回数を返す
    pub fn pto_count(&self) -> u32 {
        self.application_data.pto_count()
    }

    /// 指定空間の PTO 期限を返す (RFC 9002 Section 6.2.1)
    ///
    /// 呼び出し側が in-flight の ack-eliciting パケットがあることを確認して呼ぶ。
    /// `max_ack_delay` は Initial / Handshake では `Duration::ZERO` を渡す。
    pub fn pto_time(
        &self,
        space: PacketNumberSpace,
        rtt: &RttEstimator,
        max_ack_delay: Duration,
    ) -> Option<Timestamp> {
        self.get(space).pto_time(rtt, true, max_ack_delay)
    }

    /// 指定空間の PTO 期間を返す (RFC 9002 Section 6.2.1)
    pub fn pto_period(
        &self,
        space: PacketNumberSpace,
        rtt: &RttEstimator,
        max_ack_delay: Duration,
    ) -> Duration {
        self.get(space).pto_period(rtt, max_ack_delay)
    }

    /// 空間ごとの time threshold loss time のうち最も早いものを返す
    ///
    /// RFC 9002 Section 6.2 / Appendix A.8: 時間閾値の損失タイマーがある間は
    /// PTO を設定せず、その期限でタイマーを設定する。
    pub fn earliest_loss_time(&self) -> Option<(PacketNumberSpace, Timestamp)> {
        PacketNumberSpace::ALL
            .iter()
            .filter_map(|space| {
                self.get(*space)
                    .loss_time()
                    .map(|loss_time| (*space, loss_time))
            })
            .min_by_key(|(_, loss_time)| *loss_time)
    }
}

/// 損失検出器
///
/// パケット番号空間ごとに独立して動作する (パスごとにも独立)。
/// RFC 9002 Section 6 に基づきパケット損失を判定し、
/// PTO タイマーを管理する。
/// RFC 9002 Section 6 に基づきパケット損失を判定し、
/// PTO タイマーを管理する。
#[derive(Debug)]
pub struct LossDetector {
    /// 時間閾値ベースの損失判定時刻
    loss_time: Option<Timestamp>,
    /// PTO バックオフカウンタ
    pto_count: u32,
    /// 最後の ACK 誘発パケット送信時刻
    time_of_last_ack_eliciting_packet: Option<Timestamp>,
}

impl Default for LossDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LossDetector {
    pub fn new() -> Self {
        Self {
            loss_time: None,
            pto_count: 0,
            time_of_last_ack_eliciting_packet: None,
        }
    }

    /// ACK 誘発パケット送信時に呼び出す
    pub fn on_packet_sent(&mut self, time_sent: Timestamp, ack_eliciting: bool) {
        if ack_eliciting {
            self.time_of_last_ack_eliciting_packet = Some(time_sent);
        }
    }

    /// ACK 受信時に呼び出す (PTO カウントをリセット)
    pub fn on_ack_received(&mut self) {
        self.pto_count = 0;
    }

    /// PTO タイマー発火時に呼び出す
    ///
    /// PTO の指数バックオフは `pto_count.min(62)` で丸めるため、
    /// カウンタ自体も飽和させて debug ビルドでの overflow を避ける。
    pub fn on_pto_expired(&mut self) {
        self.pto_count = self.pto_count.saturating_add(1);
    }

    /// 損失判定を実行する (RFC 9002 Section 6.1)
    ///
    /// ACK 受信後に呼び出す。ロストと判定されたパケットを返す。
    /// 内部で loss_time を更新する。
    pub fn detect_lost_packets(
        &mut self,
        sent_packets: &mut SentPackets,
        rtt: &RttEstimator,
        now: Timestamp,
    ) -> Vec<SentPacket> {
        let Some(largest_acked) = sent_packets.largest_acked else {
            return Vec::new();
        };

        // 時間閾値の計算 (RFC 9002 Section 6.1.2)
        let max_rtt = if rtt.smoothed_rtt > rtt.latest_rtt {
            rtt.smoothed_rtt
        } else {
            rtt.latest_rtt
        };
        let loss_delay = Duration::from_micros(
            // RTT の値域全体で乗算を保持し、表現できない待ち時間だけを飽和させる。
            ((u128::from(max_rtt.as_micros()) * u128::from(K_TIME_THRESHOLD_NUM)
                / u128::from(K_TIME_THRESHOLD_DEN))
            .min(u128::from(u64::MAX))) as u64,
        );
        let loss_delay = if loss_delay > K_GRANULARITY {
            loss_delay
        } else {
            K_GRANULARITY
        };

        // ロストパケットの判定
        let mut lost_pns = Vec::new();
        let mut new_loss_time: Option<Timestamp> = None;

        for pkt in sent_packets.iter() {
            // DPLPMTUD プローブのロストは PROBE_TIMER で確定させる
            // (RFC 8899 Section 5.1.1)。通常の時間閾値・パケット閾値の
            // 判定対象にしない。
            if sent_packets.is_pmtu_probe(pkt.pn) {
                continue;
            }
            if pkt.pn > largest_acked {
                continue;
            }

            // パケット閾値: largest_acked との差が K_PACKET_THRESHOLD 以上
            let packet_threshold_met = largest_acked - pkt.pn >= K_PACKET_THRESHOLD;

            // 時間閾値は送信後の経過時間で判定する。期限の減算を 0 に丸めると、
            // 接続開始時刻 0 に送ったパケットまで直後にロストと誤判定する。
            // 加算した期限との比較も、時刻上限での飽和による早期判定を避ける。
            let time_threshold_met = now.saturating_duration_since(pkt.time_sent) >= loss_delay;

            if packet_threshold_met || time_threshold_met {
                lost_pns.push(pkt.pn);
            } else {
                // まだロストではないが時間閾値に近いパケットの期限を記録
                let deadline = pkt.time_sent.add(loss_delay);
                match new_loss_time {
                    Some(existing) if deadline < existing => {
                        new_loss_time = Some(deadline);
                    }
                    None => {
                        new_loss_time = Some(deadline);
                    }
                    _ => {}
                }
            }
        }

        self.loss_time = new_loss_time;

        // ロストパケットを sent_packets から除去して返す。
        // 後から ACK されたときに spurious loss と判定できるよう、
        // 送信時刻とロスト判定時刻を SentPackets に保持する
        // (RFC 9002 Section 6.1 / draft-ietf-ccwg-bbr-06 Section 5.5.11)。
        let mut lost_packets = Vec::new();
        for pn in lost_pns {
            if let Some(pkt) = sent_packets.declare_lost(pn, now) {
                lost_packets.push(pkt);
            }
        }

        lost_packets
    }

    /// ACK 受信でロストしたパケットのロスト理由を返す
    ///
    /// `detect_lost_packets` はパケット閾値 (RFC 9002 Section 6.1.1) と
    /// 時間閾値 (RFC 9002 Section 6.1.2) のどちらでもロストと判定するが、
    /// 再送パス選択ポリシーは理由ごとに判断を変えられる。パケット閾値を
    /// 満たす場合は `LossReason::PacketThreshold`、そうでなければ
    /// 時間閾値によるロストとして `LossReason::TimeThreshold` を返す。
    pub fn loss_reason_for_packet(pn: u64, largest_acked: u64) -> LossReason {
        if largest_acked.saturating_sub(pn) >= K_PACKET_THRESHOLD {
            LossReason::PacketThreshold
        } else {
            LossReason::TimeThreshold
        }
    }

    /// 損失タイマーの期限を返す
    pub fn loss_time(&self) -> Option<Timestamp> {
        self.loss_time
    }

    /// PTO タイマーの期限を計算する (RFC 9002 Section 6.2.1)
    ///
    /// in-flight のパケットがない場合は None を返す。
    /// `max_ack_delay` は Application Data 空間にのみ加算され、
    /// Initial / Handshake 空間では呼び出し元が `Duration::ZERO` を渡す。
    pub fn pto_time(
        &self,
        rtt: &RttEstimator,
        has_in_flight: bool,
        max_ack_delay: Duration,
    ) -> Option<Timestamp> {
        if !has_in_flight {
            return None;
        }

        let last_sent = self.time_of_last_ack_eliciting_packet?;
        Some(last_sent.add(self.pto_period(rtt, max_ack_delay)))
    }

    /// PTO 期間を返す (RFC 9002 Section 6.2.1)
    ///
    /// PTO 基本値 = smoothed_rtt + max(4*rttvar, 1ms) + max_ack_delay に、
    /// バックオフ 2^pto_count を乗じる。max_ack_delay もバックオフの内側で
    /// 乗算される (RFC 9002 Appendix A.8)。
    /// Initial / Handshake 空間では呼び出し元が `Duration::ZERO` を渡す。
    pub fn pto_period(&self, rtt: &RttEstimator, max_ack_delay: Duration) -> Duration {
        let pto = rtt.pto().saturating_add(max_ack_delay);
        Duration::from_micros(
            pto.as_micros()
                .saturating_mul(1u64 << self.pto_count.min(62)),
        )
    }

    /// 次のタイマー期限を返す (損失タイマー優先)
    ///
    /// RFC 9002 Section 6.2: 損失タイマーがアクティブなら PTO は設定しない
    pub fn next_timer(
        &self,
        rtt: &RttEstimator,
        has_in_flight: bool,
        max_ack_delay: Duration,
    ) -> Option<Timestamp> {
        if let Some(lt) = self.loss_time {
            return Some(lt);
        }
        self.pto_time(rtt, has_in_flight, max_ack_delay)
    }

    /// PTO カウントを返す
    pub fn pto_count(&self) -> u32 {
        self.pto_count
    }

    /// Persistent Congestion を判定する (RFC 9002 Section 7.6)
    ///
    /// 以下の条件を全て満たす場合にのみ `true` を返す。
    ///
    /// - (a) ack-eliciting な lost パケットが 2 個以上ある
    /// - (b) 最古と最新の lost パケットの送信時刻区間内 (厳密開区間) に
    ///   newly-acked された送信時刻が無い
    /// - (c) 最古と最新の lost パケットの送信時刻の差が `congestion_period` を超える
    /// - (d) 最初の RTT サンプル取得後に送信された lost パケットのみを対象とする
    ///
    /// `congestion_period = (smoothed_rtt + max(4 * rttvar, 1ms) + max_ack_delay) * 3`
    ///
    /// `acked_times` には今回の ACK で newly-acked になったパケットの送信時刻を渡す。
    pub fn is_persistent_congestion(
        lost_packets: &[SentPacket],
        rtt: &RttEstimator,
        max_ack_delay: Duration,
        acked_times: &[Timestamp],
    ) -> bool {
        // (d) 最初の RTT サンプル取得時刻より後に送信された lost のみを判定対象にする。
        // 単なる has_sample() の真偽では不十分で、初期 RTT で PTO を張っていた期間の
        // パケットを除外できない (RFC 9002 Section 7.6.2 / Appendix B.8)。
        // サンプル未取得なら宣言しない (Appendix B.8 の first_rtt_sample == 0 に対応)。
        let Some(first_rtt_sample) = rtt.first_rtt_sample() else {
            return false;
        };
        // フィルタ後の集合に対して (a)(b)(c) を評価する。以降の earliest / latest は
        // この同一集合から取り、(b) の区間判定と (c) の duration で共用する
        // (フィルタ前の集合から取ると duration がずれる)。
        let ack_eliciting: Vec<&SentPacket> = lost_packets
            .iter()
            .filter(|p| p.ack_eliciting && p.time_sent > first_rtt_sample)
            .collect();

        // (a) ack-eliciting パケットが 2 つ以上必要
        if ack_eliciting.len() < 2 {
            return false;
        }

        // congestion_period = (smoothed_rtt + max(4 * rttvar, 1ms) + max_ack_delay) * 3
        // 係数 3 は kPersistentCongestionThreshold の RECOMMENDED 値
        // (RFC 9002 Section 7.6.1)
        let pto_component = rtt.pto(); // smoothed_rtt + max(4 * rttvar, 1ms)
        let congestion_period = Duration::from_micros(
            pto_component
                .as_micros()
                .saturating_add(max_ack_delay.as_micros())
                .saturating_mul(3),
        );

        // 直前の (a) 判定で 2 要素以上が保証されている
        let earliest = ack_eliciting
            .iter()
            .min_by_key(|p| p.time_sent)
            .expect("ack-eliciting lost packets must have >= 2 elements");
        let latest = ack_eliciting
            .iter()
            .max_by_key(|p| p.time_sent)
            .expect("ack-eliciting lost packets must have >= 2 elements");

        // (c) RFC 9002 Section 7.6.2 は「exceeds (超える)」を要求するため、
        // 境界 (duration == congestion_period) では宣言しない
        let duration = latest
            .time_sent
            .saturating_duration_since(earliest.time_sent);
        if duration <= congestion_period {
            return false;
        }

        // (b) 最古と最新の送信時刻の間 (厳密開区間) に newly-acked が無いことを確認する。
        // RFC 9002 Section 7.6.2 の "between the send times of these two packets" は
        // 端点の包含を明文化していないため、端点と同時刻は区間外として扱う。
        //
        // 簡略化: ack-eliciting な lost の min/max の 1 組のみを評価し、区間内に
        // acked があれば不成立とする (より狭い lost ペアの再探索は行わない)。
        //
        // 空間横断の評価 (RFC 9002 Section 7.6.2 の SHOULD) は、暗号化レベルごとに
        // SentPackets が別管理で送信時刻を空間横断比較できないため行わず、ACK された
        // 単一空間内で評価する (同節が認める MAY 側)。また `acked_times` は今回の ACK で
        // newly-acked になった分に限られ、区間内のパケットが過去の ACK で既に acked
        // 済みだった場合は検出できない。いずれも persistent congestion を誤って宣言する
        // 側に倒れるが、検出漏れにはならない (RFC 9002 Section 7.6.2)。
        !acked_times
            .iter()
            .any(|t| earliest.time_sent < *t && *t < latest.time_sent)
    }
}
