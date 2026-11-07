// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 送信済みパケット追跡
//!
//! パスごとに独立したインスタンスを持つ。
//! ACK 受信時の損失検出に使用する。

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::connection::EcnCodepoint;
use crate::time::{Duration, Timestamp};

/// 送信済みパケットのメタデータ
#[derive(Debug, Clone)]
pub struct SentPacket {
    /// パケット番号
    pub pn: u64,
    /// 送信時刻
    pub time_sent: Timestamp,
    /// ACK 誘発パケットか
    pub ack_eliciting: bool,
    /// in-flight パケットか (RFC 9002 Section 2)
    ///
    /// in-flight なパケットは `ack_eliciting` なパケット、または PADDING フレームを
    /// 含むパケットである。ACK / PATH_ACK 専用のパケットは in-flight ではないため、
    /// 輻輳制御の `bytes_in_flight` と輻輳イベントの対象から除外する。
    /// `ack_eliciting` だけでは PADDING のみのパケットを表現できないため、
    /// 判定結果を明示的に保持する。
    pub in_flight: bool,
    /// in-flight バイト数 (このパケットが消費した輻輳ウィンドウ)
    pub sent_bytes: u64,
    /// パケットに含まれるフレームの情報 (再送に必要)
    pub frames: Vec<SentFrameInfo>,
    /// 送信時に IP ヘッダに設定した ECN コードポイント (RFC 9000 Section 13.4.2)
    /// ACK 処理時に ECN 検証の基準値として使用する
    pub ecn: EcnCodepoint,
}

/// STREAM フレームの範囲情報
///
/// ロスト判定時の退避と ACK 時の範囲伝達の両方で使う。ロスト判定したパケットが
/// 後から ACK された場合 (spurious loss) に、ACK 済みのストリーム範囲を送信
/// バッファへ伝えるために保持する (RFC 9000 Section 13.3: ACK された情報は
/// 再送しなくてよい)。再送時のパス選択には使わないため、再送回数などの
/// メタデータは持たない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LostStreamFrame {
    /// ストリーム ID
    pub stream_id: u64,
    /// データオフセット
    pub offset: u64,
    /// データ長
    pub length: usize,
    /// このフレームが FIN を運んだか
    pub fin: bool,
}

/// ロスト判定済みパケットに含まれていたリセットフレームの ACK 情報
///
/// ロスト判定したパケットが後から ACK された場合 (spurious loss) に、
/// 現在のリセット情報がピアへ届いていたことを送信側ストリーム状態へ伝える。
/// RESET_STREAM の ACK は Reset Recvd への遷移条件であり (RFC 9000
/// Section 3.1)、RESET_STREAM_AT の ACK は Reliable Size を含めて判定する
/// (draft-ietf-quic-reliable-stream-reset-11 Section 5.3) ため、RESET_STREAM_AT
/// は ACK されたフレームの Reliable Size も保持する。
///
/// 再送のパス選択には使わないため、エラーコードや Final Size は保持しない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LostResetFrame {
    /// RESET_STREAM の ACK 情報
    ResetStream {
        /// ストリーム ID
        stream_id: u64,
    },
    /// RESET_STREAM_AT の ACK 情報
    ResetStreamAt {
        /// ストリーム ID
        stream_id: u64,
        /// ACK されたフレームが要求した Reliable Size
        reliable_size: u64,
    },
}

/// ロスト判定済みパケットの記録
///
/// RFC 9002 Section 6.1: ロスト判定したパケットが後から ACK された場合、
/// spurious loss として扱う。ACK 受信時に照合できるよう、送信時刻と
/// ロスト判定時刻を一定期間保持する。
#[derive(Debug, Clone)]
pub struct RecentlyLostPacket {
    /// パケット番号
    pub pn: u64,
    /// 送信時刻
    pub time_sent: Timestamp,
    /// ロスト判定した時刻
    pub lost_at: Timestamp,
    /// 送信時のデータグラム長 (バイト)
    ///
    /// spurious loss でブラックホール検出のカウンタを戻すか判定するために保持する。
    pub sent_bytes: u64,
    /// in-flight パケットだったか (RFC 9002 Section 2)
    ///
    /// 輻輳制御への spurious loss 通知は、輻輳イベントの対象だった
    /// in-flight パケットに限る。
    pub in_flight: bool,
    /// 送信時に設定した ECN コードポイント (RFC 9000 Section 13.4.2)
    ///
    /// ECT(0) で送信したパケットが後から ACK された場合の spurious loss 判定で
    /// ECN 検証の全ロスト判定を取り消すために保持する。
    pub ecn: EcnCodepoint,
    /// パケットに含まれていた STREAM フレーム
    ///
    /// spurious loss で ACK されたときに、ACK 済み範囲の解放と FIN の再送待ちの
    /// 解除を行うために保持する。STREAM 以外のフレームは再送情報として
    /// 使い道がないため保持しない。
    pub stream_frames: Vec<LostStreamFrame>,
    /// パケットに含まれていた RESET_STREAM / RESET_STREAM_AT
    ///
    /// spurious loss で ACK されたときに、送信側ストリームの終端遷移へ
    /// 反映するために保持する。ロスト判定済みパケットは送信済みパケットの
    /// 追跡から外れているため、この情報が無いとリセットの ACK を終端遷移へ
    /// 伝えられない。
    pub reset_frames: Vec<LostResetFrame>,
}

/// ロスト判定済みパケットを保持する最大件数
///
/// 時間ベースの破棄に加えた上限。3 × PTO の保持期間内でも高 BDP では
/// 件数が多くなり得るため、メモリ使用量を bounded にする。
/// 全体のメモリ量は、この件数と 1 パケットあたりの STREAM / リセット
/// フレーム数の積で決まる。1 パケットに詰められるフレーム数はパケットサイズで
/// 抑えられるため、概算の上限は 512 × 1 パケットあたりの最大フレーム数 ×
/// 数十バイト程度になる。
pub const MAX_RECENTLY_LOST_PACKETS: usize = 512;

/// 送信したフレームの情報 (再送判断に使用)
///
/// RFC 9000 Section 13.3 に基づき、フレームタイプごとに再送方式が異なる:
/// - 最新値で再送: MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS
/// - まだブロック中なら現在値で再送: DATA_BLOCKED, STREAM_DATA_BLOCKED,
///   STREAMS_BLOCKED (RFC 9000 Section 13.3)
/// - 同一値で再送: RESET_STREAM, RESET_STREAM_AT, STOP_SENDING,
///   NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, NEW_TOKEN, HANDSHAKE_DONE
///   - RESET_STREAM_AT はエラーコードと Final Size を同一に保つが、Reliable Size
///     だけは現在の最小値で再送する
///     (draft-ietf-quic-reliable-stream-reset-11 Section 5.2)
/// - 再送不要: ACK, PING, PADDING, PATH_CHALLENGE
///
/// multipath 拡張の制御フレームは draft-ietf-quic-multipath-21 の次の節に従う:
/// - Section 4.2 PATH_ABANDON: 同じ内容を別パスで再送する (SHOULD)
/// - Section 4.3 PATH_STATUS: そのパスについて最後に送った状態だけを再送する (SHOULD)
/// - Section 4.5 PATH_RETIRE_CONNECTION_ID: 同一内容で再送する
/// - Section 4.6 MAX_PATH_ID: より新しい値を送っていない場合に最新値で再送する (SHOULD)
/// - Section 4.7 PATHS_BLOCKED / PATH_CIDS_BLOCKED: まだブロック中なら再送してよい (MAY)
#[derive(Debug, Clone)]
pub enum SentFrameInfo {
    /// ACK フレーム (再送不要)
    ///
    /// qlog の `quic:packet_sent` へ実送信内容を記録する経路のうち、
    /// Initial / Handshake 空間は `SentFrameInfo` からイベントを作るため、
    /// ACK 生成時の確認応答範囲と ACK Delay を保持する。1-RTT 空間の
    /// packet_sent は送信 payload のデコードから作るため、1-RTT の ACK は
    /// 空レンジと 0 を設定する (送信ごとのレンジ確保を避ける)。
    ///
    /// `acked_ranges` は Initial / Handshake 空間では qlog 有効時だけ実レンジを
    /// 持ち、qlog 無効時は空にする。qlog 無効時はこの情報を読む経路が無いため、
    /// レンジの展開と Vec の確保を行わない。
    ///
    /// `ack_delay` は RFC 9000 Section 19.3 のエンコード値 (マイクロ秒を
    /// 2^ack_delay_exponent で割った値) であり、qlog 出力時に送信側の
    /// ack_delay_exponent で ms へ変換する。Initial / Handshake 空間の ACK は
    /// 即時送信のため常に 0 である。
    ///
    /// 再送不要であるため、この情報を再送には使わない。
    Ack {
        /// 確認応答したパケット番号の範囲 (最小, 最大)
        ///
        /// 1-RTT 空間の ACK と qlog 無効時の ACK は空。
        acked_ranges: Vec<(u64, u64)>,
        /// エンコードされた ACK Delay
        ///
        /// Initial / Handshake 空間の ACK は常に 0。qlog 無効時も 0。
        ack_delay: u64,
    },
    /// CRYPTO フレーム
    Crypto { offset: u64, length: usize },
    /// STREAM フレーム
    Stream {
        stream_id: u64,
        offset: u64,
        length: usize,
        fin: bool,
        /// このフレームをこれまでに再送した回数 (初回送信は 0)
        ///
        /// 再送したフレームが再度ロストしたときに回数を引き継ぎ、
        /// 再送パス選択ポリシーの `RetxCtx::retransmission_count` に渡す。
        retransmission_count: u32,
    },
    /// DATA_BLOCKED フレーム
    ///
    /// ロスト時は送信時の値ではなく、再送時点の接続レベルの上限で再送する
    /// (RFC 9000 Section 13.3)。ブロックが解消していれば再送しない。
    DataBlocked,
    /// STREAM_DATA_BLOCKED フレーム
    ///
    /// ロスト時は対象ストリームの現在の上限で再送する (RFC 9000 Section 13.3)。
    /// 対象ストリームが存在しない場合や送信が完了している場合は再送しない。
    StreamDataBlocked {
        /// ブロックしているストリーム ID
        stream_id: u64,
    },
    /// STREAMS_BLOCKED フレーム
    ///
    /// ロスト時は現在のピアの許可数で再送する (RFC 9000 Section 13.3)。
    /// ストリームの残枠がある場合は再送しない。
    StreamsBlocked {
        /// 双方向ストリームなら true
        bidirectional: bool,
    },
    /// PATH_ABANDON フレーム (ロスト時は別パスで同じ内容を再送)
    /// draft-ietf-quic-multipath-21 Section 4.2
    PathAbandon { path_id: u32, error_code: u64 },
    /// PATH_STATUS フレーム (ロスト時は最後に送った状態のみ再送)
    /// draft-ietf-quic-multipath-21 Section 4.3
    PathStatus {
        path_id: u32,
        /// ピアへ通知した状態
        status: crate::path::PathStatus,
        /// このフレームに付けた Path Status Sequence Number
        ///
        /// 再送時に「そのパスについて最後に送った状態か」を判定し、同じ
        /// シーケンス番号のまま再送するために保持する。
        sequence_number: u64,
    },
    /// PATH_ACK フレーム (再送不要)
    ///
    /// PATH_ACK は 1-RTT 専用であり、1-RTT の packet_sent は送信 payload の
    /// デコードから作るため、qlog へ渡す確認応答内容はこの variant に保持
    /// しない。再送にも使わない。
    PathAck,
    /// MAX_PATH_ID フレーム (ロスト時は最新の値のみ再送)
    MaxPathId { maximum_path_id: u32 },
    /// MAX_DATA フレーム (ロスト時は最新の値で再送)
    /// RFC 9000 Section 13.3
    MaxData,
    /// MAX_STREAM_DATA フレーム (ロスト時は最新の値で再送)
    /// RFC 9000 Section 13.3
    MaxStreamData { stream_id: u64 },
    /// MAX_STREAMS フレーム (ロスト時は最新の値で再送)
    /// RFC 9000 Section 13.3
    MaxStreams { is_bidi: bool },
    /// RESET_STREAM フレーム (ロスト時は同一値で再送)
    /// RFC 9000 Section 13.3
    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },
    /// RESET_STREAM_AT フレーム (エラーコードと Final Size は同一値、Reliable Size は現在値)
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 5.2: ロストした
    /// RESET_STREAM_AT は、その時点で現在の Reliable Size を持つフレームの情報を
    /// 再送する。エラーコードと Final Size は変更しない。
    ResetStreamAt {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
        reliable_size: u64,
    },
    /// STOP_SENDING フレーム (ロスト時は同一値で再送)
    /// RFC 9000 Section 13.3
    StopSending { stream_id: u64, error_code: u64 },
    /// NEW_CONNECTION_ID / PATH_NEW_CONNECTION_ID フレーム (ロスト時は同一内容で再送)
    /// RFC 9000 Section 13.3
    NewConnectionId {
        path_id: u32,
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: crate::connection_id::ConnectionId,
        stateless_reset_token: [u8; 16],
    },
    /// NEW_TOKEN フレーム (ロスト時は同一内容で再送)
    ///
    /// RFC 9000 Section 13.3: ロストしたパケットに含まれる NEW_TOKEN は再送する。
    /// 同 Section 19.7: パケットが誤ってロスト判定されると、クライアントは同じ
    /// トークン値を含む NEW_TOKEN を複数受け取り得る。重複値の破棄はクライアントの
    /// 責任であるため、再送では送信済みのトークン値をそのまま使う。
    NewToken { token: Vec<u8> },
    /// RETIRE_CONNECTION_ID / PATH_RETIRE_CONNECTION_ID フレーム (ロスト時は同一内容で再送)
    /// RFC 9000 Section 13.3, draft-ietf-quic-multipath-21 Section 4.5
    RetireConnectionId { path_id: u32, sequence_number: u64 },
    /// PATHS_BLOCKED フレーム (ロスト時は最新の maximum_path_id で再送)
    /// draft-ietf-quic-multipath-21 Section 4.7:
    /// "ack-eliciting and MAY be retransmitted if the path is still blocked"
    PathsBlocked { maximum_path_id: u32 },
    /// PATH_CIDS_BLOCKED フレーム (ロスト時は最新値で再送)
    /// draft-ietf-quic-multipath-21 Section 4.7
    PathCidsBlocked {
        path_id: u32,
        next_sequence_number: u64,
    },
    /// HANDSHAKE_DONE フレーム (ロスト時は再送)
    /// RFC 9000 Section 13.3
    HandshakeDone,
    /// OBSERVED_ADDRESS フレーム (ロスト時は同一内容で元のパスに再送)
    /// draft-ietf-quic-address-discovery-01 Section 4.1
    ObservedAddress {
        path_id: u32,
        sequence_number: u64,
        addr: core::net::SocketAddr,
    },
    /// ACK_FREQUENCY フレーム
    ///
    /// draft-ietf-quic-ack-frequency-14 Section 4:
    /// ロスト時も再送しない (送信側は次の要求を送ることを推奨されるのみ)。
    /// PTO 計算に使う in-flight 要求値の追跡に使う (同 draft Section 7)。
    AckFrequency {
        /// ACK_FREQUENCY のシーケンス番号
        sequence_number: u64,
        /// 要求した max_ack_delay (マイクロ秒)
        requested_max_ack_delay: u64,
    },
    /// その他 (PING, PATH_CHALLENGE 等、再送不要)
    Other,
}

impl SentFrameInfo {
    /// STREAM フレームの範囲情報を取り出す
    ///
    /// ACK 済み範囲の記録とロスト判定時の退避で同じ [`LostStreamFrame`] を
    /// 使うための変換である。STREAM 以外のフレームは ACK 済み範囲の解放に
    /// 使わないため `None` を返す。
    pub fn stream_frame(&self) -> Option<LostStreamFrame> {
        match self {
            Self::Stream {
                stream_id,
                offset,
                length,
                fin,
                ..
            } => Some(LostStreamFrame {
                stream_id: *stream_id,
                offset: *offset,
                length: *length,
                fin: *fin,
            }),
            _ => None,
        }
    }
}

/// 送信済みパケット追跡器
///
/// BTreeMap でパケット番号順に管理し、O(log n) で検索・削除する。
#[derive(Debug)]
pub struct SentPackets {
    /// パケット番号 → 送信済みパケット
    packets: BTreeMap<u64, SentPacket>,
    /// ACK されたパケットの最大番号
    pub largest_acked: Option<u64>,
    /// パケット番号 → ロスト判定済みパケットの記録
    recently_lost: BTreeMap<u64, RecentlyLostPacket>,
    /// DPLPMTUD プローブとして送信したパケット番号
    ///
    /// プローブのロストは通常の損失検出ではなく PROBE_TIMER で確定させる
    /// (RFC 8899 Section 5.1.1)。`detect_lost_packets` はここに含まれる
    /// パケットをロスト判定から除外する。
    pmtu_probes: BTreeSet<u64>,
    /// 最後に保持期間経過分を破棄した時刻
    ///
    /// ACK 受信のたびに全件走査しないよう、破棄の間隔を空ける。
    recently_lost_pruned_at: Option<Timestamp>,
}

impl Default for SentPackets {
    fn default() -> Self {
        Self::new()
    }
}

impl SentPackets {
    pub fn new() -> Self {
        Self {
            packets: BTreeMap::new(),
            largest_acked: None,
            recently_lost: BTreeMap::new(),
            pmtu_probes: BTreeSet::new(),
            recently_lost_pruned_at: None,
        }
    }

    /// 送信済みパケットを記録する
    pub fn record(&mut self, packet: SentPacket) {
        self.packets.insert(packet.pn, packet);
    }

    /// PMTU プローブとして送信したパケットを記録する
    pub fn mark_pmtu_probe(&mut self, pn: u64) {
        self.pmtu_probes.insert(pn);
    }

    /// パケットが PMTU プローブか
    pub fn is_pmtu_probe(&self, pn: u64) -> bool {
        self.pmtu_probes.contains(&pn)
    }

    /// 送信済みの PMTU プローブのパケット番号を返す
    pub fn pmtu_probe_pns(&self) -> Vec<u64> {
        self.pmtu_probes.iter().copied().collect()
    }

    /// パケット番号から送信済みパケットを検索する
    pub fn get(&self, pn: u64) -> Option<&SentPacket> {
        self.packets.get(&pn)
    }

    /// ACK されたパケットを除去し、返す
    pub fn ack_packet(&mut self, pn: u64) -> Option<SentPacket> {
        let packet = self.remove_packet(pn);
        if packet.is_some() {
            match self.largest_acked {
                Some(largest) if pn > largest => self.largest_acked = Some(pn),
                None => self.largest_acked = Some(pn),
                _ => {}
            }
        }
        packet
    }

    /// 送信済みパケットを ACK として扱わずに取り除く
    ///
    /// PROBE_TIMER の満了など、ACK ではない理由で送信記録を消すときに使う。
    /// `ack_packet` と異なり `largest_acked` を更新しない
    /// (タイマー満了の PN を ACK 済みとして扱うと、パケット閾値の判定がずれる)。
    pub fn remove_packet(&mut self, pn: u64) -> Option<SentPacket> {
        self.pmtu_probes.remove(&pn);
        self.packets.remove(&pn)
    }

    /// ロスト判定したパケットを記録し、`packets` から除去して返す
    ///
    /// RFC 9002 Section 6.1: ロスト判定は後から覆ることがある。後で ACK された
    /// ときに spurious loss と判定できるよう、送信時刻とロスト判定時刻を
    /// `recently_lost` に保持する。保持期間の経過と件数上限は
    /// [`SentPackets::prune_recently_lost`] と
    /// [`MAX_RECENTLY_LOST_PACKETS`] で bounded にする。
    ///
    /// spurious loss で ACK されたときに送信バッファの ACK 済み範囲を解放できる
    /// よう、パケットに含まれていた STREAM フレームの範囲も
    /// [`RecentlyLostPacket::stream_frames`] に退避する。同じ理由で、
    /// RESET_STREAM / RESET_STREAM_AT の ACK 情報も
    /// [`RecentlyLostPacket::reset_frames`] に退避する。
    pub fn declare_lost(&mut self, pn: u64, now: Timestamp) -> Option<SentPacket> {
        self.pmtu_probes.remove(&pn);
        let packet = self.ack_packet(pn)?;
        let stream_frames = packet
            .frames
            .iter()
            .filter_map(SentFrameInfo::stream_frame)
            .collect();
        let reset_frames = packet
            .frames
            .iter()
            .filter_map(|frame| match frame {
                SentFrameInfo::ResetStream { stream_id, .. } => Some(LostResetFrame::ResetStream {
                    stream_id: *stream_id,
                }),
                SentFrameInfo::ResetStreamAt {
                    stream_id,
                    reliable_size,
                    ..
                } => Some(LostResetFrame::ResetStreamAt {
                    stream_id: *stream_id,
                    reliable_size: *reliable_size,
                }),
                _ => None,
            })
            .collect();
        self.recently_lost.insert(
            pn,
            RecentlyLostPacket {
                pn,
                time_sent: packet.time_sent,
                lost_at: now,
                sent_bytes: packet.sent_bytes,
                in_flight: packet.in_flight,
                ecn: packet.ecn,
                stream_frames,
                reset_frames,
            },
        );
        // 件数上限を超えたら最古のロスト判定を破棄する。パケット番号は
        // 送信順に増えるため、最小 PN が最も古いとみなしてよい。
        while self.recently_lost.len() > MAX_RECENTLY_LOST_PACKETS {
            let Some(oldest_pn) = self.recently_lost.keys().next().copied() else {
                break;
            };
            self.recently_lost.remove(&oldest_pn);
        }
        Some(packet)
    }

    /// 保持期間を過ぎたロスト判定済みパケットを破棄する
    ///
    /// `retention` は 3 × PTO など、ピアの再順序を許容する期間を呼び出し側が
    /// 決める。全件走査の頻度を抑えるため、前回の破棄から `retention` の
    /// 半分以上経過した場合だけ走査する。
    pub fn prune_recently_lost(&mut self, now: Timestamp, retention: Duration) {
        if self.recently_lost.is_empty() {
            return;
        }
        let interval = retention.as_micros() / 2;
        if let Some(pruned_at) = self.recently_lost_pruned_at
            && now.as_micros().saturating_sub(pruned_at.as_micros()) < interval
        {
            return;
        }
        self.recently_lost_pruned_at = Some(now);
        let cutoff = now.as_micros().saturating_sub(retention.as_micros());
        self.recently_lost
            .retain(|_, packet| packet.lost_at.as_micros() >= cutoff);
    }

    /// ACK された範囲に含まれるロスト判定済みパケットを取り出す
    ///
    /// 指定範囲は両端を含む。返したパケットは `recently_lost` から取り除き、
    /// 同じ ACK で二重に spurious loss と判定しないようにする。
    /// 保持期間 (`retention`) を過ぎたものは spurious loss とみなさず破棄する。
    /// 保持期間経過の判定に `now` を使う。
    ///
    /// 返したパケットの [`RecentlyLostPacket::stream_frames`] にはロスト判定時の
    /// STREAM フレームが残っている。[`RecentlyLostPacket::reset_frames`] には
    /// RESET_STREAM / RESET_STREAM_AT の ACK 情報が残っている。呼び出し側は
    /// これらを使って ACK 済みのストリーム範囲とリセットの ACK を送信側の
    /// 状態へ伝える。
    pub fn spurious_losses_in_range(
        &mut self,
        start: u64,
        end_inclusive: u64,
        now: Timestamp,
        retention: Duration,
    ) -> Vec<RecentlyLostPacket> {
        if start > end_inclusive {
            return Vec::new();
        }
        use core::ops::Bound::Included;
        let pns: Vec<u64> = self
            .recently_lost
            .range((Included(start), Included(end_inclusive)))
            .map(|(pn, _)| *pn)
            .collect();
        let cutoff = now.as_micros().saturating_sub(retention.as_micros());
        let mut spurious = Vec::new();
        for pn in pns {
            let Some(packet) = self.recently_lost.remove(&pn) else {
                continue;
            };
            if packet.lost_at.as_micros() >= cutoff {
                spurious.push(packet);
            }
        }
        spurious
    }

    /// 保持中のロスト判定済みパケット数を返す (テスト・監視用)
    pub fn recently_lost_count(&self) -> usize {
        self.recently_lost.len()
    }

    /// 未 ACK パケットの数
    pub fn in_flight_count(&self) -> usize {
        self.packets.len()
    }

    /// 未 ACK パケットをイテレートする (パケット番号の昇順)
    pub fn iter(&self) -> impl Iterator<Item = &SentPacket> {
        self.packets.values()
    }

    /// 未 ACK のパケットが 1 つでもあるか
    ///
    /// 損失検出タイマーの武装判定に使う。RFC 9002 の in-flight (ack-eliciting、
    /// または PADDING を含むパケット) とは意味が異なり、ACK / PATH_ACK 専用の
    /// パケットも数える。
    ///
    /// in-flight なものだけを数える実装に変えると、未 ACK が ACK 専用パケット
    /// だけになった時点で `LossDetector::pto_time` が `None` を返してタイマーが
    /// 解除され、以後に送る ack-eliciting パケットの再送が働かなくなる。
    /// 輻輳制御の in-flight 判定には `SentPacket::in_flight` を使うこと。
    pub fn has_in_flight(&self) -> bool {
        !self.packets.is_empty()
    }

    /// ACK 誘発パケットが in-flight か (RFC 9002 Section 2)
    ///
    /// ACK-only パケットは in-flight ではない。
    /// PTO プローブの要否判定に使用する。
    pub fn has_ack_eliciting_in_flight(&self) -> bool {
        self.packets.values().any(|p| p.ack_eliciting)
    }

    /// 全ての未 ACK パケットを取り出して返す (パス廃棄時に使用)
    ///
    /// draft-ietf-quic-multipath-21 Section 3.4:
    /// 「パス状態が削除された時点で未確認のパケットは lost とみなさなければならない (MUST)」
    pub fn drain_all(&mut self) -> Vec<SentPacket> {
        self.pmtu_probes.clear();
        // パス廃棄・鍵破棄では spurious loss を判定する意味がないため、
        // ロスト判定済みの記録も破棄する。
        self.recently_lost.clear();
        self.recently_lost_pruned_at = None;
        core::mem::take(&mut self.packets).into_values().collect()
    }

    /// 指定範囲 `[start, end_inclusive]` に含まれる未 ACK パケット番号の集合を返す
    ///
    /// ACK フレーム受信時にピア主張の範囲を逐次列挙すると DoS 可能なため、
    /// 自分が保持している送信済みパケットとの交差を BTreeMap::range で O(log n + k)
    /// で取得する。range_start > end_inclusive の場合は空 Vec を返す。
    pub fn pns_in_range(&self, start: u64, end_inclusive: u64) -> Vec<u64> {
        if start > end_inclusive {
            return Vec::new();
        }
        use core::ops::Bound::Included;
        self.packets
            .range((Included(start), Included(end_inclusive)))
            .map(|(pn, _)| *pn)
            .collect()
    }
}
