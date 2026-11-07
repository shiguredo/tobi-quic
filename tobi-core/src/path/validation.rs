// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! パス検証 (PATH_CHALLENGE / PATH_RESPONSE)

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::SocketAddr;

/// パスごとに保持する返送待ち PATH_RESPONSE の上限
///
/// ピアは 1 つのパケットに多数の PATH_CHALLENGE を詰められる。無制限に保持すると
/// メモリと応答パケット数を増幅させられるため、上限を超えた分は古いものから破棄する。
pub const MAX_PENDING_RESPONSES: usize = 32;

/// PATH_CHALLENGE の最大リトライ回数
///
/// RFC 9000 Section 8.2.4 は PTO ベースのタイマーで abandon する SHOULD と
/// 3 × max(現在パス, 新パス) PTO を RECOMMENDED とするが、本実装は
/// per-PTO リトライ + 指数バックオフ + 上限 2 の独自モデル (累積 ~7 × PTO) を採る。
const MAX_CHALLENGE_RETRIES: u32 = 2;

/// 返送待ちの PATH_RESPONSE
///
/// PATH_RESPONSE は PATH_CHALLENGE を受信したネットワークパスへ返さなければ
/// ならない (RFC 9000 Section 8.2.2 の MUST) ため、受信した 4-tuple を
/// チャレンジデータと組で保持する。`datagram_len` はチャレンジを運んだ
/// UDP payload の長さであり、応答先が未検証アドレスのときの拡張判定
/// (RFC 9000 Section 8.2.2) で増幅予算の計算に使う。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPathResponse {
    /// PATH_CHALLENGE のデータ
    pub data: [u8; 8],
    /// PATH_CHALLENGE を含むパケットを受信したリモートアドレス
    pub remote_addr: SocketAddr,
    /// PATH_CHALLENGE を含むパケットを受信したローカルアドレス
    pub local_addr: SocketAddr,
    /// PATH_CHALLENGE を含むデータグラムの UDP payload 長。不明な場合は 0。
    pub datagram_len: usize,
}

/// 生成待ち・出力待ちと、実際に送ったプローブを区別する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChallengeState {
    Pending,
    Queued,
    Sent,
}

/// 現在の検証で使うチャレンジ。
#[derive(Debug, Clone, Copy)]
struct PendingChallenge {
    data: [u8; 8],
    state: ChallengeState,
}

/// パス検証の状態
#[derive(Debug)]
pub struct PathValidation {
    /// 現在の PATH_CHALLENGE と送信状態
    challenge: Option<PendingChallenge>,
    /// 同じ検証段階で実出力したチャレンジとデータグラムサイズ
    sent_challenges: Vec<([u8; 8], usize)>,
    /// 出力待ちのプローブを失効させるための検証世代
    generation: u64,
    /// 受信した PATH_CHALLENGE データ (PATH_RESPONSE を返す必要あり)
    ///
    /// 受信した 4-tuple を組で保持する (RFC 9000 Section 8.2.2 の MUST)。
    /// 先頭から取り出すため `VecDeque` を使い、要素数に対して線形のコストにする。
    pending_responses: VecDeque<PendingPathResponse>,
    /// 検証が完了したか
    pub validated: bool,
    /// PATH_CHALLENGE のリトライ回数
    retry_count: u32,
}

impl Default for PathValidation {
    fn default() -> Self {
        Self::new()
    }
}

impl PathValidation {
    pub fn new() -> Self {
        Self {
            challenge: None,
            sent_challenges: Vec::new(),
            generation: 0,
            pending_responses: VecDeque::new(),
            validated: false,
            retry_count: 0,
        }
    }

    /// 進行中の検証を破棄してやり直す
    ///
    /// 4-tuple が変わったときは、以前の 4-tuple へ送った PATH_CHALLENGE の
    /// 応答で新しい 4-tuple が検証済みにならないようにする。リトライ回数も
    /// リセットし、新しい 4-tuple に検証の予算を割り当てる
    /// (RFC 9000 Section 9.3 / Section 9.3.2)。
    pub fn restart(&mut self) {
        self.challenge = None;
        self.sent_challenges.clear();
        self.generation = self.generation.wrapping_add(1);
        self.validated = false;
        self.retry_count = 0;
    }

    /// 新しい PATH_CHALLENGE を要求し、以前の未送信出力だけを失効させる
    ///
    /// 同じ段階の送信済み履歴と再試行回数は維持する。新しいアドレスや
    /// MTU 検証の開始時には先に `restart` を呼ぶ (RFC 9000 Section 8.2.3)。
    pub fn request_challenge(&mut self, data: [u8; 8]) {
        self.generation = self.generation.wrapping_add(1);
        self.challenge = Some(PendingChallenge {
            data,
            state: ChallengeState::Pending,
        });
        self.validated = false;
    }

    /// 現在の検証世代を返す
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// チャレンジをパケット化し、出力待ちにしたことを記録する
    pub fn challenge_queued(&mut self, data: &[u8; 8]) {
        if let Some(challenge) = self.challenge.as_mut()
            && challenge.data == *data
            && challenge.state == ChallengeState::Pending
        {
            challenge.state = ChallengeState::Queued;
        }
    }

    /// 指定世代のチャレンジが現在も出力待ちかを返す
    pub fn is_challenge_queued(&self, data: &[u8; 8], generation: u64) -> bool {
        self.generation == generation
            && self.challenge.is_some_and(|challenge| {
                challenge.data == *data && challenge.state == ChallengeState::Queued
            })
    }

    /// 出力待ちのチャレンジを I/O 層へ渡したときにサイズを記録する
    ///
    /// 出力待ちの世代とデータが一致しない場合は状態を変更せず false を返す。
    pub fn challenge_sent(
        &mut self,
        data: &[u8; 8],
        generation: u64,
        datagram_size: usize,
    ) -> bool {
        if !self.is_challenge_queued(data, generation) {
            return false;
        }
        self.challenge
            .as_mut()
            .expect("queued challenge exists")
            .state = ChallengeState::Sent;
        // 初回と上限までの再試行だけを保持し、入力回数による無制限の増加を防ぐ。
        if self.sent_challenges.len() == MAX_CHALLENGE_RETRIES as usize + 1 {
            self.sent_challenges.remove(0);
        }
        self.sent_challenges.push((*data, datagram_size));
        true
    }

    /// PATH_RESPONSE を受信した時に呼ぶ
    ///
    /// 実際に出力したチャレンジへの応答なら、そのデータグラムサイズを返す。
    /// 1,200 バイト未満ではアドレスだけを確認でき、MTU の検証は未完了とする
    /// (RFC 9000 Section 8.2.1。仕様変更時には二段階の検証条件を見直す)。
    pub fn response_received(&mut self, data: &[u8; 8]) -> Option<usize> {
        let datagram_size = self
            .sent_challenges
            .iter()
            .find(|(sent, _)| sent == data)
            .map(|(_, size)| *size)?;
        self.challenge = None;
        self.sent_challenges.clear();
        // 遅延応答を受け付けた場合も、その後に用意した未送信再試行を失効させる。
        self.generation = self.generation.wrapping_add(1);
        self.validated = datagram_size >= 1200;
        Some(datagram_size)
    }

    /// PATH_CHALLENGE を受信した時に呼ぶ
    ///
    /// `remote_addr` / `local_addr` は PATH_CHALLENGE を含むパケットを受信した
    /// 4-tuple。`datagram_len` はチャレンジを運んだデータグラムの UDP payload
    /// 長で、不明な場合は 0 を渡す。PATH_RESPONSE の送信先と拡張判定に使う。
    pub fn challenge_received(
        &mut self,
        data: [u8; 8],
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        datagram_len: usize,
    ) {
        // 1 パケットに大量の PATH_CHALLENGE を詰められても、保持量と応答数を
        // 上限内に抑える。溢れた分は古い応答から破棄する。
        if self.pending_responses.len() >= MAX_PENDING_RESPONSES {
            self.pending_responses.pop_front();
        }
        self.pending_responses.push_back(PendingPathResponse {
            data,
            remote_addr,
            local_addr,
            datagram_len,
        });
    }

    /// 送信すべき PATH_RESPONSE があるか
    pub fn has_pending_response(&self) -> bool {
        !self.pending_responses.is_empty()
    }

    /// 次に送信すべき PATH_RESPONSE を取得する
    pub fn take_pending_response(&mut self) -> Option<PendingPathResponse> {
        self.pending_responses.pop_front()
    }

    /// 次に送信すべき PATH_RESPONSE を削除せずに参照する
    ///
    /// パケット化に失敗した場合に応答を失わないよう、送信できると確定するまで
    /// キューに残す用途で使う。
    pub fn pending_response(&self) -> Option<&PendingPathResponse> {
        self.pending_responses.front()
    }

    /// 送信できなかった PATH_RESPONSE をキューの先頭へ戻す
    ///
    /// pacing や CID 待ちでパケットを生成できなかったときに使う。順序を保つため
    /// 先頭へ戻し、上限を超える場合は古いものから破棄する。
    pub fn requeue_pending_response(&mut self, pending: PendingPathResponse) {
        if self.pending_responses.len() >= MAX_PENDING_RESPONSES {
            self.pending_responses.pop_back();
        }
        self.pending_responses.push_front(pending);
    }

    /// 返送待ち PATH_RESPONSE の件数
    pub fn pending_response_count(&self) -> usize {
        self.pending_responses.len()
    }

    /// 未解決の PATH_CHALLENGE があるか
    pub fn has_pending_challenge(&self) -> bool {
        self.challenge.is_some()
    }

    /// CID や pacing、増幅制限で生成を保留しているチャレンジを返す
    pub fn unsent_challenge(&self) -> Option<[u8; 8]> {
        self.challenge
            .filter(|challenge| challenge.state == ChallengeState::Pending)
            .map(|challenge| challenge.data)
    }

    /// 送信済みのチャレンジを、同じデータで再送待ちへ戻す
    ///
    /// ハンドシェイク中に送った PATH_CHALLENGE は、ピアが 1-RTT 鍵を持たない
    /// ため処理されないことがある。ハンドシェイク完了後に同じデータで再送し、
    /// 応答を照合できるようにする。未送信 (Pending) や応答済みの場合は None を
    /// 返し、状態を変えない。
    pub fn resend_challenge(&mut self) -> Option<[u8; 8]> {
        let challenge = self.challenge.as_mut()?;
        if challenge.state != ChallengeState::Sent {
            return None;
        }
        // 送信済みの履歴は保持する。応答は同じデータで照合する。
        let data = challenge.data;
        challenge.state = ChallengeState::Pending;
        Some(data)
    }

    /// リトライ回数をインクリメントし、上限超過かを返す
    ///
    /// true の場合はパスを廃棄すべき。
    pub fn increment_retry(&mut self) -> bool {
        self.retry_count += 1;
        self.retry_count > MAX_CHALLENGE_RETRIES
    }

    /// リトライ回数を返す
    pub fn retry_count(&self) -> u32 {
        self.retry_count
    }
}
