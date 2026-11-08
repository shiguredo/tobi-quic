// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 1-RTT の未送信内容と、実出力時のパケット化・送信会計。

use super::*;
use crate::stream::state::SendState;

/// 暗号化済み出力に、1-RTT と PN 空間を共有するパケットが含まれるか調べる。
///
/// RFC 9000 Section 12.2: Initial の後ろへ coalesce した 0-RTT も確認する。
/// ヘッダー保護で変わらない Length だけを使い、フレームや鍵には触れない。
pub(super) fn has_application_data(mut datagram: &[u8]) -> bool {
    while let Some(first) = datagram.first() {
        if !header::is_long_header(*first) {
            return true;
        }
        let Ok(long) = LongHeader::decode(datagram) else {
            return false;
        };
        match long.packet_type {
            LongPacketType::ZeroRtt => return true,
            LongPacketType::Initial | LongPacketType::Handshake => {}
            _ => return false,
        }
        let mut offset = long.header_len;
        if long.packet_type == LongPacketType::Initial {
            let Ok((token_len, used)) = VarInt::decode(&datagram[offset..]) else {
                return false;
            };
            let Ok(token_len) = usize::try_from(token_len.as_u64()) else {
                return false;
            };
            let Some(end) = offset
                .checked_add(used)
                .and_then(|value| value.checked_add(token_len))
            else {
                return false;
            };
            if end > datagram.len() {
                return false;
            }
            offset = end;
        }
        let Ok((length, used)) = VarInt::decode(&datagram[offset..]) else {
            return false;
        };
        let Ok(length) = usize::try_from(length.as_u64()) else {
            return false;
        };
        let Some(end) = offset
            .checked_add(used)
            .and_then(|value| value.checked_add(length))
        else {
            return false;
        };
        if end > datagram.len() {
            return false;
        }
        datagram = &datagram[end..];
        // Initial の最低サイズを満たすための、パケット外側の 0 埋めは終了とする。
        if datagram.iter().all(|byte| *byte == 0) {
            return false;
        }
    }
    false
}

/// CID と PN が出力待ちの間に変わっても収まるように確保する最大長。
pub(super) const MAX_ONE_RTT_OVERHEAD: usize = 1 + 20 + 4 + 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OneRttPurpose {
    Regular,
    PathChallenge { data: [u8; 8], generation: u64 },
    PathResponse { data: [u8; 8] },
    Pto,
    Pmtu,
}

/// PN、CID、鍵をまだ割り当てていない送信内容。
pub(super) struct PendingOneRtt {
    pub(super) path_id: PathId,
    pub(super) payload: Vec<u8>,
    pub(super) frames: Vec<SentFrameInfo>,
    pub(super) ack_eliciting: bool,
    pub(super) min_size: usize,
    pub(super) remote_addr: Option<std::net::SocketAddr>,
    pub(super) local_addr: Option<std::net::SocketAddr>,
    /// パスの送信先 CID ではなく、この送信だけで使う DCID
    ///
    /// 4-tuple 移行の検証パケットは、移行先の宛先アドレスへ送るため、パスが
    /// 現在使っている CID ではなく移行候補の CID を DCID にしなければならない
    /// (RFC 9000 Section 9.5)。`None` の場合は `Connection::path_dcid` が返す
    /// パスの送信先 CID を使う。
    pub(super) dcid_override: Option<ConnectionId>,
    pub(super) purpose: OneRttPurpose,
    /// ACK Delay に実際の出力待ち時間を加えるための基準時刻
    pub(super) prepared_at: Timestamp,
    /// 予約を譲った本文は保持し、新しい通常データの生成だけを止める。
    pub(super) reserved: bool,
}

impl PendingOneRtt {
    fn reserved_size(&self) -> u64 {
        let minimum = if matches!(
            self.purpose,
            OneRttPurpose::PathChallenge { .. } | OneRttPurpose::PathResponse { .. }
        ) {
            1200
        } else {
            self.min_size
        };
        (self.payload.len() + MAX_ONE_RTT_OVERHEAD).max(minimum) as u64
    }
}

/// RFC 9000 Section 3.3 に従い、終了済みの送信側へデータを追加しない。
///
/// reliable-stream-reset-11 Section 5.3 の DataSent では、Reliable Size までの
/// 配信を継続する必要がある。仕様の状態定義が変わる場合は、この判定も見直す。
fn stream_data_is_obsolete(streams: &StreamManager, stream_id: u64) -> bool {
    !matches!(
        streams
            .get_stream(stream_id)
            .and_then(|stream| stream.send_state),
        Some(SendState::Ready | SendState::Send | SendState::DataSent)
    )
}

impl<F: CongestionControlFactory, S: SchedulerFactory, P: PathControllerFactory>
    Connection<F, S, P>
{
    /// 送出準備に失敗した接続を終了し、未出力の所有を解放する。
    ///
    /// RFC 9001 Section 6.6: 鍵を更新できない使用上限では、使い切った鍵で
    /// CONNECTION_CLOSE を暗号化せず、以後の通常出力を止める。
    pub(super) fn close_on_output_error(&mut self, error: &Error) {
        if self.state == ConnectionState::Closed {
            return;
        }
        self.state = ConnectionState::Closed;
        self.discard_one_rtt_outputs(false);
        self.output_queue
            .retain(|output| !matches!(output, ConnectionOutput::SendDatagram { .. }));
        let code = match error {
            Error::Protocol { code, .. } => *code,
            _ => tobi_core::error::TransportErrorCode::INTERNAL_ERROR,
        };
        self.push_event(ConnectionEvent::ConnectionClosed {
            error_code: code.as_u64(),
            reason: error.to_string().into_bytes(),
            kind: ConnectionCloseKind::Internal,
        });
    }

    /// 通常データの生成で使える枠。未出力分は bytes in flight に入れない。
    pub(super) fn one_rtt_generation_budget(&self, path_id: PathId) -> u64 {
        let Some(path) = self.paths.get(path_id) else {
            return 0;
        };
        if self
            .one_rtt_outputs
            .iter()
            .any(|pending| pending.path_id == path_id && pending.ack_eliciting && !pending.reserved)
        {
            return 0;
        }
        let reserved = self
            .one_rtt_outputs
            .iter()
            .filter(|pending| {
                pending.path_id == path_id && pending.ack_eliciting && pending.reserved
            })
            .fold(0u64, |total, pending| {
                total.saturating_add(pending.reserved_size())
            });
        path.congestion.available_window().saturating_sub(reserved)
    }

    /// プローブの予約を優先するが、先に準備したデータの本文は捨てない。
    pub(super) fn queue_one_rtt(&mut self, pending: PendingOneRtt) {
        if self.emit_tracking && !self.emit_used_paths.contains(&pending.path_id) {
            self.emit_used_paths.push(pending.path_id);
        }
        if matches!(pending.purpose, OneRttPurpose::PathChallenge { .. }) {
            self.one_rtt_outputs.retain(|old| {
                old.path_id != pending.path_id
                    || !matches!(old.purpose, OneRttPurpose::PathChallenge { .. })
            });
            for old in &mut self.one_rtt_outputs {
                if old.path_id == pending.path_id && old.ack_eliciting {
                    old.reserved = false;
                }
            }
        }
        self.one_rtt_outputs.push_back(pending);
    }

    /// 指定パスの移行候補 CID を使う未出力のパケットを破棄する
    ///
    /// 移行を取り消した後、候補 CID を DCID にした検証パケットを送ってはならない
    /// (RFC 9000 Section 5.1.2 / Section 9.5)。未出力の予約を残すと、通常データの
    /// 生成枠を塞いで RETIRE などの制御フレームの送信を妨げるため、ここで破棄する。
    /// 予約したストリームの所有も解放する。
    pub(super) fn discard_pending_migration_outputs(&mut self, path_id: PathId) {
        let mut retained = VecDeque::new();
        while let Some(pending) = self.one_rtt_outputs.pop_front() {
            if pending.path_id == path_id && pending.dcid_override.is_some() {
                for info in &pending.frames {
                    if let Some(stream_id) = sent_frame_stream_id(info) {
                        self.streams.release_queued_frame(stream_id);
                    }
                }
                continue;
            }
            retained.push_back(pending);
        }
        self.one_rtt_outputs = retained;
    }

    /// 閉鎖する接続の予約と検証履歴を破棄する。
    pub(super) fn discard_one_rtt_outputs(&mut self, keep_final_abandon: bool) {
        let mut retained = VecDeque::new();
        while let Some(pending) = self.one_rtt_outputs.pop_front() {
            if keep_final_abandon
                && pending
                    .frames
                    .iter()
                    .any(|info| matches!(info, SentFrameInfo::PathAbandon { .. }))
            {
                retained.push_back(pending);
                continue;
            }
            for info in &pending.frames {
                if let Some(stream_id) = sent_frame_stream_id(info) {
                    self.streams.release_queued_frame(stream_id);
                }
            }
        }
        self.one_rtt_outputs = retained;
        for path in self.paths.all_paths_mut() {
            path.validation.restart();
        }
        if !keep_final_abandon {
            self.pending_abandon_completion.clear();
        }
    }

    /// パスが使えなくなった未送信内容を、実送信のロストとは区別して戻す。
    pub(super) fn cancel_one_rtt_path(&mut self, path_id: PathId) -> Result<(), Error> {
        let mut retained = VecDeque::new();
        while let Some(pending) = self.one_rtt_outputs.pop_front() {
            if pending.path_id != path_id {
                retained.push_back(pending);
                continue;
            }
            self.restore_unsent_one_rtt(pending)?;
        }
        self.one_rtt_outputs = retained;
        if let Some(path) = self.paths.get_mut(path_id) {
            path.validation.restart();
        }
        Ok(())
    }

    /// 新しいチャレンジを受ける前に、未出力の応答を上限付きキューへ戻す。
    ///
    /// 生成前と生成後に別々のキューを持つ間も、両方を合計した保持量を
    /// MAX_PENDING_RESPONSES に収める。実送信済みの応答は戻さない。
    pub(super) fn requeue_unsent_path_responses(&mut self, path_id: PathId) {
        let Some(path) = self.paths.get(path_id) else {
            return;
        };
        let default_addrs = (path.remote_addr, path.local_addr);
        let mut responses = Vec::new();
        self.one_rtt_outputs.retain(|pending| {
            if pending.path_id == path_id
                && let OneRttPurpose::PathResponse { data } = pending.purpose
            {
                responses.push(tobi_core::path::validation::PendingPathResponse {
                    data,
                    remote_addr: pending.remote_addr.unwrap_or(default_addrs.0),
                    local_addr: pending.local_addr.unwrap_or(default_addrs.1),
                    // 再投入した応答の拡張判定は、パスの現在の 4-tuple と同じ宛先
                    // なら実出力時の増幅枠で行うため、ここではデータグラム長を
                    // 引き継がない。異なる宛先への応答は拡張なしで送る (保守的)。
                    datagram_len: 0,
                });
                false
            } else {
                true
            }
        });
        let path = self.paths.get_mut(path_id).expect("response path exists");
        for response in responses.into_iter().rev() {
            path.validation.requeue_pending_response(response);
        }
    }

    fn restore_unsent_one_rtt(&mut self, pending: PendingOneRtt) -> Result<(), Error> {
        // 取り消した予約を解放し、STREAM データは再送キューへ戻す。
        // 同じフレームに複数の種類が混ざるため、終端遷移の対象は
        // ストリーム ID を集めてから処理する。
        let mut stream_ids = Vec::new();
        for info in &pending.frames {
            if let Some(stream_id) = sent_frame_stream_id(info) {
                self.streams.release_queued_frame(stream_id);
                stream_ids.push(stream_id);
            }
            if let SentFrameInfo::Stream {
                stream_id,
                offset,
                length,
                fin,
                retransmission_count,
            } = info
            {
                // この出力はまだ実送信していない。既存の再送キューへ戻す経路を
                // 再利用するためロスト理由は仮に TimeThreshold とするが、
                // パケットの送信統計やロスト統計には計上されない。
                self.streams.mark_lost(
                    *stream_id,
                    *offset,
                    *length,
                    *fin,
                    RetxMeta {
                        original_path: pending.path_id,
                        loss_reason: LossReason::TimeThreshold,
                        retransmission_count: *retransmission_count,
                    },
                );
            }
        }
        let mut remaining = pending.payload.as_slice();
        while !remaining.is_empty() {
            let (frame, consumed) = Frame::decode(remaining)?;
            remaining = &remaining[consumed..];
            match frame {
                Frame::Stream(_)
                | Frame::Datagram(_)
                | Frame::Padding(_)
                | Frame::Ping(_)
                | Frame::PathChallenge(_)
                | Frame::PathResponse(_)
                // この通知にはパス ID がなく、別パスへ戻すと観測対象が変わる。
                | Frame::ObservedAddress(_)
                | Frame::Ack(_)
                | Frame::PathAck(_)
                | Frame::AckReceiveTimestamps(_)
                | Frame::PathAckReceiveTimestamps(_) => {}
                Frame::Crypto(crypto) => self
                    .crypto_retransmit_1rtt
                    .push_back((crypto.offset.as_u64(), crypto.data)),
                frame => self.streams.pending_frames.push_back(frame),
            }
        }
        // 予約の解放と再送キューへの復元が終わったストリームは、ACK 済み
        // 範囲しか残っていない場合に終端状態へ遷移できる
        // (RFC 9000 Section 3.1, Section 13.3)。終端状態なら再キューした
        // リセットフレームは遷移時に破棄される。
        for stream_id in stream_ids {
            self.streams.try_transition_send_terminal(stream_id);
        }
        Ok(())
    }

    /// 生成済みの通常出力が実送信時のパス PMTU に収まらないかを返す
    ///
    /// RFC 8899 Section 3: PMTU probe 以外のデータグラムを現在の PLPMTU より
    /// 大きく送ってはならない (MUST NOT)。RFC 9000 Section 14.2 は probe 以外を
    /// 最大データグラムサイズに収めることを SHOULD とし、probe は現在値より
    /// 大きいデータグラムであること、その送り方を Section 14.4 に定める。
    /// RFC 10069 Section 5.8 はパスごとの最大データグラム
    /// サイズの扱いに注意することを求める。Section 5.6 は、より小さい MTU の
    /// パスへ再送する場合に STREAM フレームを小さく送り直すことがあることを
    /// 述べる。
    ///
    /// したがって PMTU probe は対象外とする。通常出力は、収まらない場合に
    /// 種別ごとに処理する (STREAM は取り消して再分割、DATAGRAM は破棄、
    /// ACK 専用は縮小)。
    /// PATH_CHALLENGE / PATH_RESPONSE は増幅制限が許す場合に 1200 バイトへ
    /// 拡張するが、PMTU の下限も 1200 バイトであるため通常はこの判定に
    /// 掛からない。
    fn pending_exceeds_pmtu(&self, pending: &PendingOneRtt) -> bool {
        if matches!(pending.purpose, OneRttPurpose::Pmtu) {
            return false;
        }
        let Some(path) = self.paths.get(pending.path_id) else {
            return false;
        };
        self.one_rtt_size(pending)
            .is_some_and(|size| size > usize::from(path.pmtu))
    }

    /// ACK 専用の出力待ちを PMTU に収まる大きさへ縮小する
    ///
    /// RFC 9000 Section 13.2.1: ack-eliciting パケットには max_ack_delay 以内に
    /// ACK を送らなければならない (MUST)。RFC 8899 Section 3: probe 以外を現在の
    /// PLPMTU より大きく送ってはならない (MUST NOT)。ACK 専用の出力は
    /// ロストデータと違って直ちに再生成されないため、両立させるには ACK を
    /// 小さく符号化し直す必要がある。
    ///
    /// 受信タイムスタンプを落とし、それでも収まらなければ古い ACK レンジから
    /// 削る (RFC 9000 Section 13.2.3 の ACK レンジ制限と同じ扱い)。
    fn shrink_ack_pending_for_pmtu(&mut self, index: usize) -> Result<bool, Error> {
        let ack_only = matches!(
            self.one_rtt_outputs[index].frames.as_slice(),
            [SentFrameInfo::Ack { .. }] | [SentFrameInfo::PathAck]
        );
        if !ack_only {
            return Ok(false);
        }
        let path_id = self.one_rtt_outputs[index].path_id;
        let Some(pmtu) = self.paths.get(path_id).map(|path| usize::from(path.pmtu)) else {
            return Ok(false);
        };
        let mut frame = match Frame::decode(&self.one_rtt_outputs[index].payload) {
            Ok((frame, _)) => frame,
            Err(_) => return Ok(false),
        };
        // 受信タイムスタンプは ACK の送達に必須ではないため最初に落とす。
        frame = match frame {
            Frame::AckReceiveTimestamps(receive) => Frame::Ack(receive.ack),
            Frame::PathAckReceiveTimestamps(receive) => Frame::PathAck(frame::path_ack::PathAck {
                path_id: receive.path_id,
                largest_acknowledged: receive.ack.largest_acknowledged,
                ack_delay: receive.ack.ack_delay,
                first_ack_range: receive.ack.first_ack_range,
                ack_ranges: receive.ack.ack_ranges,
                ecn_counts: receive.ack.ecn_counts,
            }),
            frame => frame,
        };
        loop {
            let mut payload = Vec::new();
            frame.encode(&mut payload);
            // `one_rtt_size` は本文の長さだけで決まるため、符号化した長さで判定する。
            let payload_len = payload.len();
            let fits = self
                .one_rtt_size_for_payload_len(&self.one_rtt_outputs[index], payload_len)
                .is_some_and(|size| size <= pmtu);
            if fits {
                let pending = &mut self.one_rtt_outputs[index];
                pending.payload = payload;
                // 受信タイムスタンプ付き ACK を plain ACK / PATH_ACK へ変換した
                // 場合、ACK 専用パケットとして扱い続ける (RFC 9000 Section 12.4:
                // ACK は ack-eliciting ではない)。
                pending.ack_eliciting = false;
                return Ok(true);
            }
            // 古い ACK レンジを 1 つ削って再試行する。最小構成でも収まらない
            // 場合は false を返し、通常の取り消し経路に委ねる。
            let ranges = match &mut frame {
                Frame::Ack(ack) => &mut ack.ack_ranges,
                Frame::PathAck(ack) => &mut ack.ack_ranges,
                _ => return Ok(false),
            };
            if ranges.pop().is_none() {
                return Ok(false);
            }
        }
    }

    /// 現在の宛先・CID・PN 長で必要なサイズを見積もる。
    fn one_rtt_size(&self, pending: &PendingOneRtt) -> Option<usize> {
        self.one_rtt_size_for_payload_len(pending, pending.payload.len())
    }

    /// 本文の長さを指定して必要なサイズを見積もる。
    ///
    /// 縮小処理では再符号化した本文の長さで判定するため、キューの内容を
    /// 差し替えずに済む。
    fn one_rtt_size_for_payload_len(
        &self,
        pending: &PendingOneRtt,
        payload_len: usize,
    ) -> Option<usize> {
        let path = self.paths.get(pending.path_id)?;
        // 移行の検証パケットはパスの送信先 CID ではなく候補 CID を使うため、
        // 実際に送る DCID でサイズを見積もる。
        let dcid = pending
            .dcid_override
            .clone()
            .or_else(|| self.path_dcid(pending.path_id))?;
        let pn_len = usize::from(number::encode_length(
            path.send_pn,
            path.sent_packets.largest_acked,
        ));
        let minimum = 1 + dcid.len() + pn_len + payload_len.max(4usize.saturating_sub(pn_len)) + 16;
        let padding = if matches!(pending.purpose, OneRttPurpose::PathChallenge { .. }) {
            if self.send_datagram_blocked(1200, pending.path_id) {
                0
            } else {
                1200
            }
        } else if matches!(pending.purpose, OneRttPurpose::PathResponse { .. }) {
            let remote = pending.remote_addr.unwrap_or(path.remote_addr);
            let local = pending.local_addr.unwrap_or(path.local_addr);
            if remote != path.remote_addr || local != path.local_addr {
                // パスの現在の 4-tuple と異なる応答先 (移行の probe への応答など)
                // は、チャレンジを受信した時点の増幅予算で拡張の可否が確定する。
                // 予算は応答の生成時に判定済みなので、ここではその結果を使う。
                pending.min_size
            } else {
                // 応答ごとに実出力時の増幅枠を確認する。最初の応答以外も
                // RFC 9000 Section 8.2.2 に従い、許される限り拡張する。
                if self.send_datagram_blocked(1200, pending.path_id)
                    || self.path_response_min_datagram_size(pending.path_id, remote, local, 0) == 0
                {
                    0
                } else {
                    1200
                }
            }
        } else {
            pending.min_size
        };
        Some(minimum.max(padding))
    }

    fn one_rtt_pending_valid(&self, pending: &PendingOneRtt) -> bool {
        let Some(path) = self.paths.get(pending.path_id) else {
            return false;
        };
        let terminal = pending
            .frames
            .iter()
            .any(|info| matches!(info, SentFrameInfo::PathAbandon { .. }));
        let final_abandon = self.state == ConnectionState::Closing
            && self.closing_packet.is_none()
            && terminal
            && !self.pending_abandon_completion.is_empty();
        if !matches!(
            self.state,
            ConnectionState::Connected | ConnectionState::Handshaking
        ) && !final_abandon
        {
            return false;
        }
        if matches!(path.state, PathState::Abandoning | PathState::Abandoned) && !terminal {
            return false;
        }
        // 移行候補の CID を送信直前に点検する。候補が退役したり、移行が取り消され
        // た後に、退役済み CID や別用途へ切り替わった CID を DCID にしたパケットを
        // 送ってはならない (RFC 9000 Section 5.1.2 / Section 9.5)。候補 CID を
        // 使えるのは、送信先の 4-tuple が現在の移行候補の 4-tuple と一致する
        // 場合だけである。abort 後に残った古い PATH_RESPONSE や、別の宛先へ
        // 再開した移行の古い出力を、新しい候補の CID で送らない。
        if let Some(cid) = &pending.dcid_override {
            let remote_addr = pending.remote_addr.unwrap_or(path.remote_addr);
            let local_addr = pending.local_addr.unwrap_or(path.local_addr);
            let candidate_dcid =
                self.migration_candidate_dcid_for(pending.path_id, remote_addr, local_addr);
            if candidate_dcid.as_ref() != Some(cid)
                || !self.is_active_peer_cid(pending.path_id, cid)
            {
                return false;
            }
        }
        if let OneRttPurpose::PathChallenge { data, generation } = pending.purpose {
            return path.validation.is_challenge_queued(&data, generation);
        }
        true
    }

    /// 待機中に変更された送信状態と制御情報を実送信時の状態へ合わせる。
    ///
    /// Reliable Size は増やさず (reliable-stream-reset-11 Section 5.2)、
    /// PATH_STATUS と ACK_FREQUENCY の古い新規通知を後から送らない
    /// (multipath-21 Section 4.3 / ack-frequency-14 Section 4)。
    fn refresh_queued_frames(&mut self, index: usize) -> Result<bool, Error> {
        let pending = &mut self.one_rtt_outputs[index];
        let mut rest = pending.payload.as_slice();
        let mut payload = Vec::new();
        let mut kept = Vec::new();
        let mut changed = false;
        while !rest.is_empty() {
            let (mut frame, consumed) = Frame::decode(rest)?;
            rest = &rest[consumed..];
            let obsolete = match &mut frame {
                Frame::Stream(stream) => {
                    let stream_id = stream.stream_id.as_u64();
                    let obsolete = stream_data_is_obsolete(&self.streams, stream_id);
                    if obsolete
                        && let Some(position) = pending.frames.iter().position(|info| {
                            matches!(info, SentFrameInfo::Stream { stream_id: id, offset, length, fin, .. }
                                if *id == stream_id && *offset == stream.offset.as_u64()
                                    && *length == stream.data.len() && *fin == stream.fin)
                        })
                    {
                        pending.frames.remove(position);
                        self.streams.release_queued_frame(stream_id);
                    }
                    // 冗長コピーは Other として追跡するため、所有メタデータの
                    // 有無にかかわらず、実際の STREAM 本文から終了状態を調べる。
                    obsolete
                }
                Frame::StreamDataBlocked(blocked) => {
                    stream_data_is_obsolete(&self.streams, blocked.stream_id.as_u64())
                }
                Frame::ResetStreamAt(reset) => {
                    let stream_id = reset.stream_id.as_u64();
                    let stream = self.streams.get_stream(stream_id);
                    let replacement = match stream.and_then(|stream| stream.send_state) {
                        Some(SendState::DataSent) => {
                            let stream = stream.expect("reset stream exists");
                            let previous = reset.reliable_size;
                            reset.reliable_size = VarInt::new(
                                stream.reset_at_reliable_size.expect("reliable size exists"),
                            )
                            .expect("reliable size fits in varint");
                            changed |= reset.reliable_size != previous;
                            Some(Frame::ResetStreamAt(*reset))
                        }
                        Some(SendState::ResetSent) => {
                            changed = true;
                            Some(Frame::ResetStream(frame::reset_stream::ResetStream {
                                stream_id: reset.stream_id,
                                application_protocol_error_code: reset
                                    .application_protocol_error_code,
                                final_size: reset.final_size,
                            }))
                        }
                        _ => None,
                    };
                    if let Some(replacement) = replacement {
                        // 同じストリームの複数の通知も、同じ現在値を記録する。
                        //
                        // `sent_frame_info_for_control` の送信パス引数は、
                        // OBSERVED_ADDRESS のようにフレーム自身が送信パスを
                        // 持たない制御フレームだけに使う。ここで置き換えるのは
                        // ResetStream / ResetStreamAt であり、どちらも送信パスに
                        // 依存しないため、`pending.path_id` は変換結果に影響しない。
                        for info in &mut pending.frames {
                            if matches!(info, SentFrameInfo::ResetStreamAt { stream_id: id, .. }
                                | SentFrameInfo::ResetStream { stream_id: id, .. } if *id == stream_id)
                            {
                                *info = sent_frame_info_for_control(&replacement, pending.path_id);
                            }
                        }
                        frame = replacement;
                        false
                    } else {
                        if let Some(position) = pending.frames.iter().position(|info| {
                            matches!(info, SentFrameInfo::ResetStreamAt { stream_id: id, .. } if *id == stream_id)
                        }) {
                            pending.frames.remove(position);
                            self.streams.release_queued_frame(stream_id);
                        }
                        true
                    }
                }
                Frame::PathStatusAvailable(status) => {
                    self.paths.get(PathId(status.path_id)).is_none_or(|path| {
                        status.path_status_sequence_number.as_u64()
                            < path.status_seq_send.saturating_sub(1)
                    })
                }
                Frame::PathStatusBackup(status) => {
                    self.paths.get(PathId(status.path_id)).is_none_or(|path| {
                        status.path_status_sequence_number.as_u64()
                            < path.status_seq_send.saturating_sub(1)
                    })
                }
                Frame::AckFrequency(frequency) => {
                    frequency.sequence_number.as_u64()
                        < self.ack_frequency_next_sequence_number.saturating_sub(1)
                }
                _ => false,
            };
            if obsolete {
                changed = true;
                // 同種の複数フレームを含む場合は、今回捨てる 1 件だけを外す。
                let position = pending.frames.iter().position(|info| match (&frame, info) {
                    (
                        Frame::PathStatusAvailable(status),
                        SentFrameInfo::PathStatus {
                            path_id,
                            status: value,
                            ..
                        },
                    ) => status.path_id == *path_id && *value == PathStatus::Available,
                    (
                        Frame::PathStatusBackup(status),
                        SentFrameInfo::PathStatus {
                            path_id,
                            status: value,
                            ..
                        },
                    ) => status.path_id == *path_id && *value == PathStatus::Backup,
                    (
                        Frame::AckFrequency(frequency),
                        SentFrameInfo::AckFrequency {
                            sequence_number, ..
                        },
                    ) => frequency.sequence_number.as_u64() == *sequence_number,
                    _ => false,
                });
                if let Some(position) = position {
                    pending.frames.remove(position);
                }
                continue;
            }
            frame.encode(&mut payload);
            kept.push(frame);
        }
        pending.payload = payload;
        pending.ack_eliciting = !frames_are_ack_only(&kept);
        Ok(changed)
    }

    /// ACK Delay は、生成後に出力を待った時間も含める (RFC 9000 Section 13.2.5)。
    ///
    /// ここで更新するのは 1-RTT のキューにある payload だけでよい。1-RTT の
    /// qlog は `prepare_one_rtt_output` が送信 payload をデコードして作るため、
    /// 1-RTT 空間の `SentFrameInfo::Ack` が持つ ACK Delay は qlog の入力に
    /// ならない (送信内容は payload を正とする)。一方、Initial / Handshake
    /// 空間の ACK Delay は `sent_frame_to_qlog` が読むが、それらはこの関数の
    /// 対象外である。
    fn refresh_queued_ack_delay(&mut self, index: usize, now: Timestamp) -> Result<(), Error> {
        // 指数の選択は ACK 生成と qlog 記録で共通のヘルパーに集約している。
        // `pending` を可変借用したまま self のメソッドを呼べないため先に求める。
        let ack_delay_exponent = self.local_ack_delay_exponent();
        let pending = &mut self.one_rtt_outputs[index];
        if pending.ack_eliciting || pending.prepared_at >= now {
            return Ok(());
        }
        let elapsed = now
            .saturating_duration_since(pending.prepared_at)
            .as_micros()
            >> ack_delay_exponent;
        let mut rest = pending.payload.as_slice();
        let mut payload = Vec::new();
        while !rest.is_empty() {
            let (mut frame, consumed) = Frame::decode(rest)?;
            rest = &rest[consumed..];
            let ack_delay = match &mut frame {
                Frame::Ack(ack) => Some(&mut ack.ack_delay),
                Frame::PathAck(ack) => Some(&mut ack.ack_delay),
                Frame::AckReceiveTimestamps(ack) => Some(&mut ack.ack.ack_delay),
                Frame::PathAckReceiveTimestamps(ack) => Some(&mut ack.ack.ack_delay),
                _ => None,
            };
            if let Some(delay) = ack_delay {
                *delay = VarInt::new(delay.as_u64().saturating_add(elapsed).min((1u64 << 62) - 1))
                    .expect("ACK delay fits in varint");
            }
            frame.encode(&mut payload);
        }
        pending.payload = payload;
        // 符号化単位未満の端数は次回へ残す。細かい poll でも待ち時間を失わない。
        pending.prepared_at =
            pending.prepared_at + Duration::from_micros(elapsed << ack_delay_exponent);
        Ok(())
    }

    /// 出力順を確定してから PN と現在の鍵を割り当てる。
    pub(super) fn poll_one_rtt_output(
        &mut self,
        now: Timestamp,
    ) -> Result<Option<ConnectionOutput>, Error> {
        loop {
            let mut changed = false;
            let mut index = 0;
            while index < self.one_rtt_outputs.len() {
                changed |= self.refresh_queued_frames(index)?;
                self.refresh_queued_ack_delay(index, now)?;
                let empty_or_invalid = self.one_rtt_outputs[index].payload.is_empty()
                    || !self.one_rtt_pending_valid(&self.one_rtt_outputs[index]);
                // ACK 専用の出力は再生成できないため、PMTU に収まるよう縮小する。
                // 縮小できない場合だけ通常の取り消し経路へ流す。
                let drop_for_pmtu = !empty_or_invalid
                    && self.pending_exceeds_pmtu(&self.one_rtt_outputs[index])
                    && !self.shrink_ack_pending_for_pmtu(index)?;
                if empty_or_invalid || drop_for_pmtu {
                    let pending = self
                        .one_rtt_outputs
                        .remove(index)
                        .expect("pending output exists");
                    changed = true;
                    // 接続終了時には再送先がない。パスだけの失効なら別パスへ戻す。
                    if self.state == ConnectionState::Connected {
                        self.restore_unsent_one_rtt(pending)?;
                    } else {
                        for info in &pending.frames {
                            if let Some(stream_id) = sent_frame_stream_id(info) {
                                self.streams.release_queued_frame(stream_id);
                            }
                        }
                        if let Some(path) = self.paths.get_mut(pending.path_id) {
                            path.validation.restart();
                        }
                    }
                } else {
                    index += 1;
                }
            }
            if !changed || self.state != ConnectionState::Connected || self.one_rtt_keys.is_none() {
                break;
            }
            // 取り消した予約を待って、最新の制御情報が生成待ちに残り得る。
            // 空いた枠で再生成し、新しく取り出した古い情報も送信前に点検する。
            self.emit_1rtt_data(now)?;
            self.emit_1rtt_datagrams(now)?;
        }
        // 4-tuple の変更直後は、PATH_CHALLENGE を最初のパケットにする。保留中の
        // PATH_CHALLENGE が無くなった場合は、他の出力を止め続けないよう解除する。
        if let Some(deferred) = self.defer_path_datagrams_until_challenge
            && !self.one_rtt_outputs.iter().any(|pending| {
                pending.path_id == deferred
                    && matches!(pending.purpose, OneRttPurpose::PathChallenge { .. })
            })
        {
            self.defer_path_datagrams_until_challenge = None;
        }
        let deferred_path = self.defer_path_datagrams_until_challenge;
        let mut order: Vec<usize> = (0..self.one_rtt_outputs.len()).collect();
        order.sort_by_key(|index| {
            !matches!(
                self.one_rtt_outputs[*index].purpose,
                OneRttPurpose::PathChallenge { .. }
            )
        });
        for index in order {
            let pending = &self.one_rtt_outputs[index];
            let path_id = pending.path_id;
            let is_challenge = matches!(pending.purpose, OneRttPurpose::PathChallenge { .. });
            if deferred_path == Some(path_id) && !is_challenge {
                // PATH_CHALLENGE より先に ACK などを送らない。
                continue;
            }
            let Some(size) = self.one_rtt_size(pending) else {
                continue;
            };
            if self.send_datagram_blocked(size as u64, path_id) {
                continue;
            }
            let path = self.paths.get(path_id).expect("output path exists");
            // RFC 9000 Section 9.6.2: サーバーの preferred_address からは、
            // ピアのアドレス検証が済むまで non-probing パケットを送らない。
            // PATH_CHALLENGE が pacing 待ちでも、ACK だけを先に通さない。
            let unvalidated_preferred =
                self.role == Role::Server
                    && !path.address_validated
                    && self.local_params.preferred_address.as_ref().is_some_and(
                        |address| match path.local_addr {
                            std::net::SocketAddr::V4(local) => {
                                local.ip().octets() == address.ipv4_address
                                    && local.port() == address.ipv4_port
                            }
                            std::net::SocketAddr::V6(local) => {
                                local.ip().octets() == address.ipv6_address
                                    && local.port() == address.ipv6_port
                            }
                        },
                    );
            if unvalidated_preferred
                && !matches!(
                    pending.purpose,
                    OneRttPurpose::PathChallenge { .. } | OneRttPurpose::PathResponse { .. }
                )
            {
                continue;
            }
            // 最小 MTU を確認する間は、旧 PMTU で作った大きい本文を保持する。
            // 1,200 バイト以内の応答・制御・データは増幅枠と cwnd の範囲で進める。
            if path.state == PathState::Validating
                && size > 1200
                && !matches!(pending.purpose, OneRttPurpose::PathChallenge { .. })
                && !pending
                    .frames
                    .iter()
                    .any(|info| matches!(info, SentFrameInfo::PathAbandon { .. }))
            {
                continue;
            }
            // 予約は生成数の上限であり、送信可否は現在の実際の窓だけで決める。
            //
            // 経路検証の PATH_CHALLENGE は輻輳制御の窓で止めない。旧 4-tuple へ
            // 送ったパケットがすべて失われた状態で NAT リバインディングが起きると、
            // 未確認の送信で窓が埋まったまま PATH_CHALLENGE を送れず、検証
            // タイマーだけが満了して旧アドレスへ戻る。その結果、ピアからの
            // 新しい経路のパケットも ACK できず、転送が再開しない。
            // RFC 9000 Section 9.4 は経路検証の probe を輻輳制御の例外に
            // できるとしている。
            let congestion_exempt = matches!(
                pending.purpose,
                OneRttPurpose::Pto | OneRttPurpose::PathChallenge { .. }
            );
            if pending.ack_eliciting
                && !congestion_exempt
                && size as u64 > path.congestion.available_window()
            {
                continue;
            }
            if pending.ack_eliciting {
                let burst = self
                    .one_rtt_bursts
                    .get(&path_id)
                    .filter(|(at, _)| *at == now)
                    .map_or(0, |(_, bytes)| *bytes);
                if self.pacing_blocked(path_id, now, burst) {
                    continue;
                }
            }
            let output = self.prepare_one_rtt_output(index, size, now)?;
            if is_challenge && deferred_path == Some(path_id) {
                // PATH_CHALLENGE を送信したので、保留していた出力を再開する。
                self.defer_path_datagrams_until_challenge = None;
            }
            return Ok(output);
        }
        Ok(None)
    }

    /// パケットに含まれる RETIRE が、そのパケットの DCID を退役させないかを返す
    ///
    /// RFC 9000 Section 19.16: RETIRE_CONNECTION_ID / PATH_RETIRE_CONNECTION_ID
    /// のシーケンス番号は、そのパケットの Destination Connection ID を指しては
    /// ならない (MUST NOT)。CID 選択の不整合を送信前に検出するための防御的な
    /// 検査であり、通常の経路では一致しない。
    ///
    /// DCID が有効なピア CID として登録されていない場合も、退役履歴の対応表から
    /// シーケンス番号を引く。送信先 CID の退役直後は、退役した CID がパスの現在の
    /// 送信先として残っていることがあり、その場合は有効な CID の集合だけを見ると
    /// RETIRE が DCID を指していることを検出できない。対応表は退役履歴と同じ上限を
    /// 持ち、上限を超えて捨てられた古い CID は引けない。CID を追跡できない場合は
    /// 対象外として送信を許可する。
    fn retires_packet_dcid(
        &self,
        path_id: PathId,
        dcid: &ConnectionId,
        frames: &[SentFrameInfo],
    ) -> bool {
        let dcid_sequence = self
            .peer_cid_entries
            .iter()
            .find(|entry| entry.path_id == path_id && &entry.connection_id == dcid)
            .map(|entry| entry.sequence_number)
            .or_else(|| {
                self.retired_peer_cid_identities
                    .iter()
                    .find(|((retired_path_id, _), retired_cid)| {
                        *retired_path_id == path_id.0 && *retired_cid == dcid
                    })
                    .map(|((_, sequence_number), _)| *sequence_number)
            });
        let Some(dcid_sequence) = dcid_sequence else {
            return false;
        };
        frames.iter().any(|info| {
            matches!(
                info,
                SentFrameInfo::RetireConnectionId {
                    path_id: frame_path_id,
                    sequence_number,
                } if *frame_path_id == path_id.0 && *sequence_number == dcid_sequence
            )
        })
    }

    /// 選択済みの内容を暗号化し、同じ時点で回復・輻輳・観測へ登録する。
    pub(super) fn prepare_one_rtt_output(
        &mut self,
        index: usize,
        size: usize,
        now: Timestamp,
    ) -> Result<Option<ConnectionOutput>, Error> {
        self.check_aead_limits(now)?;
        // 後続で self を可変借用するため、送信内容から必要な値を先に取り出す。
        let (path_id, dcid_override, remote_addr_override, local_addr_override, mut payload) = {
            let pending = &self.one_rtt_outputs[index];
            (
                pending.path_id,
                pending.dcid_override.clone(),
                pending.remote_addr,
                pending.local_addr,
                pending.payload.clone(),
            )
        };
        let Some(dcid) = dcid_override.clone().or_else(|| self.path_dcid(path_id)) else {
            return Ok(None);
        };
        // RFC 9000 Section 19.16: RETIRE_CONNECTION_ID / PATH_RETIRE_CONNECTION_ID
        // のシーケンス番号は、そのパケットの DCID を指してはならない (MUST NOT)。
        // CID の選択ロジックが壊れた場合に不正なパケットを送らないよう、
        // 送信直前に防御的に検査する。
        if self.retires_packet_dcid(path_id, &dcid, &self.one_rtt_outputs[index].frames) {
            return Err(Error::InvalidData(
                "RETIRE_CONNECTION_ID must not retire the packet's destination connection ID"
                    .into(),
            ));
        }
        let path = self.paths.get_mut(path_id).expect("selected path exists");
        let Some(pn) = path.next_pn() else {
            self.close_on_send_pn_limit();
            return Ok(None);
        };
        let pn_len = number::encode_length(pn, path.sent_packets.largest_acked);
        let remote_addr = remote_addr_override.unwrap_or(path.remote_addr);
        let local_addr = local_addr_override.unwrap_or(path.local_addr);
        let mut packet = vec![ShortHeader::build_first_byte_with_quic_bit(
            false,
            self.key_phase,
            pn_len,
            self.send_quic_bit_zero(),
        )];
        packet.extend_from_slice(dcid.as_bytes());
        let pn_offset = packet.len();
        let mut pn_bytes = [0; 4];
        number::encode(pn, pn_len, &mut pn_bytes)?;
        packet.extend_from_slice(&pn_bytes[..usize::from(pn_len)]);
        // 暗号化と HP が成功するまでは、キューに本文と所有情報を保持する。
        // qlog: packet_sent (1-RTT)。ここでデコードする payload は PADDING を
        // 付与する前のフレーム列である (後段でサイズ調整のために追加する
        // PADDING は qlog の frames に記録しない)。
        // ACK / PATH_ACK の ACK Delay は送信側であるローカルの
        // ack_delay_exponent で ms に変換する (RFC 9000 Section 19.3)。
        let mut qlog_frames = Vec::new();
        if self.qlog_writer.is_some() {
            let ack_delay_exponent = self.local_ack_delay_exponent();
            let mut remaining = payload.as_slice();
            while !remaining.is_empty() {
                let (frame, consumed) = Frame::decode(remaining)?;
                qlog_frames.push(qlog::QlogFrame::from_frame(&frame, ack_delay_exponent));
                remaining = &remaining[consumed..];
            }
        }
        payload.resize(size.saturating_sub(packet.len() + 16).max(payload.len()), 0);
        let keys = self
            .one_rtt_keys
            .as_ref()
            .ok_or_else(|| Error::InvalidData("no 1-RTT keys".into()))?;
        let tag = keys
            .local_packet
            .encrypt_in_place_for_path(path_id.0, pn, &packet, &mut payload)
            .map_err(|_| Error::InvalidData("1-RTT encryption failed".into()))?;
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(tag.as_ref());
        apply_hp_rustls(&mut packet, pn_offset, pn_len, &*keys.local_header, false)?;
        // RFC 9000 Section 9.5: 送信先に使った CID は、その時点で使用済みとして
        // 記録する。候補選択時に予約として `used` を立てているが、暗号化と
        // ヘッダ保護が成功して実際に送る段階で改めて記録し、移行の検証パケットの
        // 送信有無を確定する。送信前に取り消した場合は候補 CID を未使用へ戻せる。
        // 併せて実際に送った 4-tuple を記録し、同じ 4-tuple への再試行だけを
        // 許可する (RFC 9000 Section 9.5)。
        self.record_peer_cid_send_target(path_id, &dcid, remote_addr, local_addr);
        if let Some(cid) = &dcid_override
            && let Some(migration) = self.pending_migrations.get_mut(&path_id)
            && &migration.candidate_peer_cid == cid
        {
            migration.candidate_probe_sent = true;
        }
        let pending = self
            .one_rtt_outputs
            .remove(index)
            .expect("prepared output exists");
        let ecn = self.path_ecn_codepoint(path_id);
        let bytes = packet.len() as u64;
        let path = self.paths.get_mut(path_id).expect("selected path exists");
        if let OneRttPurpose::PathChallenge { data, generation } = pending.purpose {
            let sent = path
                .validation
                .challenge_sent(&data, generation, packet.len());
            debug_assert!(sent);
        }
        if pending.ack_eliciting {
            path.congestion.on_packet_sent(bytes);
            path.congestion
                .on_packet_sent_cc(PacketNumberSpace::ApplicationData, pn, bytes, now);
            let burst = self.one_rtt_bursts.entry(path_id).or_insert((now, 0));
            if burst.0 != now {
                *burst = (now, 0);
            }
            burst.1 = burst.1.saturating_add(bytes);
        }
        path.loss_detectors.on_packet_sent(
            PacketNumberSpace::ApplicationData,
            now,
            pending.ack_eliciting,
        );
        path.record_sent(now);
        if matches!(ecn, EcnCodepoint::Ect0) {
            path.record_ecn_ect0_sent();
        }
        for info in &pending.frames {
            // 実出力したフレームの未出力予約を解放する。
            if let Some(stream_id) = sent_frame_stream_id(info) {
                self.streams.release_queued_frame(stream_id);
            }
            if let SentFrameInfo::ResetStreamAt { stream_id, .. } = info {
                self.streams.mark_reset_stream_at_sent(*stream_id);
            }
            if let SentFrameInfo::AckFrequency {
                sequence_number,
                requested_max_ack_delay,
            } = info
            {
                self.ack_frequency_in_flight
                    .retain(|(sequence, _)| sequence != sequence_number);
                self.ack_frequency_in_flight
                    .push((*sequence_number, *requested_max_ack_delay));
            }
        }
        let completed_abandons: Vec<PathId> = pending
            .frames
            .iter()
            .filter_map(|info| {
                if let SentFrameInfo::PathAbandon { path_id, .. } = info {
                    Some(PathId(*path_id))
                } else {
                    None
                }
            })
            .collect();
        path.sent_packets.record(SentPacket {
            pn,
            time_sent: now,
            ack_eliciting: pending.ack_eliciting,
            in_flight: pending.ack_eliciting,
            sent_bytes: bytes,
            frames: pending.frames,
            ecn,
        });
        if pending.purpose == OneRttPurpose::Pmtu {
            path.sent_packets.mark_pmtu_probe(pn);
            path.mtu_controller.on_probe_sent(pn, now);
            let pto = path.rtt.pto();
            let deadline = now + self.pmtu_probe_timeout(path_id, pto);
            self.output_queue.push_back(ConnectionOutput::SetTimer {
                id: TimerId::PmtuProbe { path_id },
                deadline,
            });
            self.pmtu_probe_pns.push((path_id, pn));
        }
        self.one_rtt_packets_sent = self.one_rtt_packets_sent.saturating_add(1);
        let time_ms = self.qlog_time_ms();
        if let Some(writer) = self.qlog_writer.as_mut() {
            writer.on_packet_sent(
                time_ms,
                &qlog::PacketHeader {
                    packet_type: qlog::PacketType::OneRtt,
                    packet_number: pn,
                    dcid: qlog::cid_to_hex(&dcid),
                    scid: None,
                    version: None,
                    length: Some(packet.len()),
                },
                &qlog_frames,
                packet.len(),
            );
        }
        self.observe(ConnectionObservationEvent::PacketSent {
            path_id,
            packet_number: pn,
            size: packet.len(),
        });
        for abandoned in completed_abandons {
            if self.pending_abandon_completion.remove(&abandoned) {
                self.retire_peer_cids_for_path(abandoned, now)?;
                if let Some(path) = self.paths.get_mut(abandoned) {
                    path.peer_cid = None;
                }
                self.output_queue
                    .push_back(ConnectionOutput::PathClosed { path_id: abandoned });
            }
        }
        Ok(Some(ConnectionOutput::SendDatagram {
            data: packet,
            path_id,
            remote_addr,
            local_addr,
            ecn,
        }))
    }
}
