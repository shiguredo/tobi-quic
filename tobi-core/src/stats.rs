// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 接続・パスの統計カウンタ
//!
//! アプリケーションが運用監視・性能評価に使う累積カウンタを保持する。
//! パス単位のカウンタは [`PathStats`]、接続全体のカウンタは
//! [`ConnectionStats`] で表す。すべて単調増加し、接続生涯で
//! リセットしない。
//!
//! パケット数・バイト数は UDP データグラム単位で数える。1 つの
//! データグラムに複数の QUIC パケットがコアレスされている場合も
//! 1 として数える。

use crate::time::Duration;

/// パス単位の累積カウンタ
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PathStats {
    /// 送信したバイト数
    pub sent_bytes: u64,
    /// 送信したパケット (UDP データグラム) 数
    pub sent_packets: u64,
    /// 受信したバイト数
    pub received_bytes: u64,
    /// 受信したパケット (有効なパケットを 1 つ以上含む UDP データグラム) 数
    pub received_packets: u64,
    /// ロストした in-flight パケット数 (RFC 9002 Section 2)
    ///
    /// ACK / PATH_ACK 専用のパケットは in-flight ではないため含めない。
    /// DPLPMTUD プローブが PROBE_TIMER の満了でロストした分は、通常の損失検出の
    /// 対象外であり探索の再試行として扱うため含めない (RFC 8899 Section 5.1.1)。
    pub lost_packets: u64,
    /// 再送した in-flight パケット数
    ///
    /// ロスト確定後に再送対象のフレームを持ち、再送キューへ戻されたパケットを
    /// 1 つとして数える。ACK / PATH_ACK 専用のパケットは再送しないため含めない。
    pub retransmitted_packets: u64,
}

impl PathStats {
    /// 送信したパケットを記録する
    pub fn record_sent(&mut self, bytes: u64) {
        self.sent_bytes = self.sent_bytes.saturating_add(bytes);
        self.sent_packets = self.sent_packets.saturating_add(1);
    }

    /// 受信したパケットを記録する
    pub fn record_received(&mut self, bytes: u64) {
        self.received_bytes = self.received_bytes.saturating_add(bytes);
        self.received_packets = self.received_packets.saturating_add(1);
    }

    /// ロストした in-flight パケットを記録する
    pub fn record_lost(&mut self) {
        self.lost_packets = self.lost_packets.saturating_add(1);
    }

    /// 再送した in-flight パケットを記録する
    pub fn record_retransmitted(&mut self) {
        self.retransmitted_packets = self.retransmitted_packets.saturating_add(1);
    }
}

/// 接続全体の累積カウンタ
///
/// パス別の内訳は [`PathStats`] を参照する。`ConnectionStats` は
/// すべてのパスの合計に接続単位のカウンタを加えた値になる。
/// `datagram_send_queue_len` と `datagram_recv_queue_len` は累積値ではなく、
/// 統計を取得した時点のキュー長である。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionStats {
    /// 送信したバイト数 (全パス合計)
    pub sent_bytes: u64,
    /// 送信したパケット (UDP データグラム) 数 (全パス合計)
    pub sent_packets: u64,
    /// 受信したバイト数 (全パス合計)
    pub received_bytes: u64,
    /// 受信したパケット (UDP データグラム) 数 (全パス合計)
    pub received_packets: u64,
    /// ロストした in-flight パケット数 (全パス合計)
    pub lost_packets: u64,
    /// 再送した in-flight パケット数 (全パス合計)
    pub retransmitted_packets: u64,
    /// ロスト判定後に ACK された spurious loss の in-flight パケット数 (全パス合計)
    ///
    /// RFC 9002 Section 6.1: パケット閾値・時間閾値でロストと判定したパケットが
    /// 後から ACK された回数を数える。再順序による誤検出の頻度を監視する用途を
    /// 想定する。
    pub spurious_lost_packets: u64,
    /// アプリケーションが開いたストリーム数
    ///
    /// ローカル起動の双方向・単方向ストリームの合計。ピア起動のストリームは
    /// 含めない。ストリームはパスに帰属しないため接続単位でのみ数える。
    pub streams_opened: u64,
    /// 受信時に破棄したパケットの合計
    ///
    /// `record_dropped_packet` が呼ばれた回数。qlog の `packet_dropped` と同じ
    /// 対象であり、QUIC パケット単位でも UDP データグラム単位でもない破棄
    /// イベント数である。Closing / Draining / Closed 中の破棄、バージョン不一致、
    /// `MAX_PACKET_NUMBER` 超過、Key Phase trial の復号失敗は含まない。
    /// Stateless Reset の検出時は `PacketOutcome::Dropped` 腕では含まないが、
    /// 未登録 DCID の Short Header は `Err` 腕を通るため含む。
    pub packet_dropped: u64,
    /// 復号失敗として破棄したパケット数
    ///
    /// qlog の `trigger=decryption_failure` と同じ分類を使う。
    pub packet_dropped_decryption_failure: u64,
    /// 不正パケットとして破棄したパケット数
    ///
    /// qlog の `trigger=invalid` と同じ分類を使う。未知の DCID、
    /// `"no 1-RTT keys"`、ポリシー上の破棄も含み、壊れたパケットだけを意味しない。
    pub packet_dropped_invalid: u64,
    /// platform の STOP_SENDING キューが満杯で破棄した件数
    ///
    /// `tobi-platform` の `accept_stop_sending` 用キュー (上限 1024) が満杯に
    /// なり、通知を捨てた回数。transport 層は記録しないため、platform を
    /// 経由しない接続では 0 のままである。破棄は RFC 9000 Section 3.5 の
    /// RESET_STREAM 送信には影響しない。
    pub stop_sending_dropped: u64,
    /// ピア Connection ID の能動回転を実行した回数
    ///
    /// RFC 9000 Section 5.1.2 の CID 切り替えをアプリケーションが要求して
    /// 成功した回数。パス ID ごとの内訳は持たない。
    pub cid_rotations: u64,
    /// CID 枯渇により PATH_CIDS_BLOCKED を送信した回数
    ///
    /// RFC 10069 Section 4.7 の通知を送った回数。
    /// 同一の枯渇状態では 1 回だけ数える。
    pub path_cids_blocked_sent: u64,
    /// 送信キューの飽和により破棄した DATAGRAM 数 (RFC 9221)
    ///
    /// RFC 9221 Section 5.4 は、輻輳制御が送信を許すまで DATAGRAM を遅延させるか、
    /// 送信せずに破棄するかのいずれかを実装に求めている。この値は破棄を選んだ
    /// 場合の件数であり、送信キューが上限に達した状態で破棄方針の送信 API が
    /// DATAGRAM を追加し、最も古い DATAGRAM を追い出した回数を数える。
    /// 送信キューの空きを待つ送信 API 自身は破棄を起こさず、この値も増やさない。
    /// 同じ接続で両方の API を併用した場合は、破棄方針の API が追い出した
    /// 分だけ増える。
    pub datagram_send_dropped: u64,
    /// 受信キューの飽和により破棄した DATAGRAM 数 (RFC 9221)
    ///
    /// 受信キューはアプリケーションが取り出すまで受信済み DATAGRAM を保持する。
    /// 上限に達した状態で新しい DATAGRAM を受信すると、最も古い DATAGRAM を
    /// 破棄する。この値はその回数であり、ピアが送った DATAGRAM のうち
    /// アプリケーションへ渡る前に失われた件数を表す。
    pub datagram_recv_dropped: u64,
    /// 現在の DATAGRAM 送信キュー長 (件数)
    ///
    /// 累積値ではなく、統計を取得した時点の値である。
    pub datagram_send_queue_len: usize,
    /// 現在の DATAGRAM 受信キュー長 (件数)
    ///
    /// 累積値ではなく、統計を取得した時点の値である。
    pub datagram_recv_queue_len: usize,
    /// 接続を開始してからの経過時間
    ///
    /// 最初の送受信を観測した時点を起点とする。
    pub elapsed: Duration,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            sent_bytes: 0,
            sent_packets: 0,
            received_bytes: 0,
            received_packets: 0,
            lost_packets: 0,
            retransmitted_packets: 0,
            spurious_lost_packets: 0,
            streams_opened: 0,
            cid_rotations: 0,
            packet_dropped: 0,
            packet_dropped_decryption_failure: 0,
            packet_dropped_invalid: 0,
            stop_sending_dropped: 0,
            path_cids_blocked_sent: 0,
            datagram_send_dropped: 0,
            datagram_recv_dropped: 0,
            datagram_send_queue_len: 0,
            datagram_recv_queue_len: 0,
            elapsed: Duration::ZERO,
        }
    }
}

impl ConnectionStats {
    /// 送信したパケットを記録する
    pub fn record_sent(&mut self, bytes: u64) {
        self.sent_bytes = self.sent_bytes.saturating_add(bytes);
        self.sent_packets = self.sent_packets.saturating_add(1);
    }

    /// 受信したパケットを記録する
    pub fn record_received(&mut self, bytes: u64) {
        self.received_bytes = self.received_bytes.saturating_add(bytes);
        self.received_packets = self.received_packets.saturating_add(1);
    }

    /// ロストした in-flight パケットを記録する
    pub fn record_lost(&mut self) {
        self.lost_packets = self.lost_packets.saturating_add(1);
    }

    /// 再送した in-flight パケットを記録する
    pub fn record_retransmitted(&mut self) {
        self.retransmitted_packets = self.retransmitted_packets.saturating_add(1);
    }

    /// spurious loss と判定した in-flight パケットを記録する
    pub fn record_spurious_lost(&mut self) {
        self.spurious_lost_packets = self.spurious_lost_packets.saturating_add(1);
    }

    /// ピア Connection ID の能動回転を記録する
    pub fn record_cid_rotation(&mut self) {
        self.cid_rotations = self.cid_rotations.saturating_add(1);
    }

    /// CID 枯渇による PATH_CIDS_BLOCKED 送信を記録する
    pub fn record_path_cids_blocked_sent(&mut self) {
        self.path_cids_blocked_sent = self.path_cids_blocked_sent.saturating_add(1);
    }

    /// アプリケーションが開いたストリームを記録する
    pub fn record_stream_opened(&mut self) {
        self.streams_opened = self.streams_opened.saturating_add(1);
    }

    /// 送信キューの飽和により破棄した DATAGRAM を記録する
    pub fn record_datagram_send_dropped(&mut self) {
        self.datagram_send_dropped = self.datagram_send_dropped.saturating_add(1);
    }

    /// 受信キューの飽和により破棄した DATAGRAM を記録する
    pub fn record_datagram_recv_dropped(&mut self) {
        self.datagram_recv_dropped = self.datagram_recv_dropped.saturating_add(1);
    }

    /// 復号失敗として破棄したパケットを記録する
    ///
    /// 合計 `packet_dropped` も同じメソッドで加算する。
    pub fn record_packet_dropped_decryption_failure(&mut self) {
        self.packet_dropped = self.packet_dropped.saturating_add(1);
        self.packet_dropped_decryption_failure =
            self.packet_dropped_decryption_failure.saturating_add(1);
    }

    /// 不正パケットとして破棄したパケットを記録する
    ///
    /// 合計 `packet_dropped` も同じメソッドで加算する。
    pub fn record_packet_dropped_invalid(&mut self) {
        self.packet_dropped = self.packet_dropped.saturating_add(1);
        self.packet_dropped_invalid = self.packet_dropped_invalid.saturating_add(1);
    }

    /// qlog の `trigger=general` に対応する破棄を記録する
    ///
    /// 専用の内訳フィールドは持たず、合計だけを加算する。`general` は
    /// `packet_dropped` と 2 つの内訳の差で求める。現行の受信経路では
    /// 発生しないが、`Error` に variant が増えたときのために置く。
    pub fn record_packet_dropped_general(&mut self) {
        self.packet_dropped = self.packet_dropped.saturating_add(1);
    }
}
