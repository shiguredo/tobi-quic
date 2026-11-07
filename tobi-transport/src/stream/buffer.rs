// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! ストリーム送受信バッファ

use std::collections::BTreeMap;

use tobi_core::error::{Error, TransportErrorCode};
use tobi_core::path::PathId;
use tobi_core::scheduler::LossReason;

/// 再送対象のメタデータ
///
/// ロストした STREAM データを再送キューへ戻すとき、元の送信パスと
/// ロスト理由、これまでの再送回数を保持する。送信時に
/// `RetransmissionPolicy::decide_retx` へ渡す `RetxCtx` の組み立てに使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetxMeta {
    /// 元の送信パス
    pub original_path: PathId,
    /// ロスト理由
    pub loss_reason: LossReason,
    /// これまでに再送した回数 (初回ロストは 0)
    pub retransmission_count: u32,
}

impl RetxMeta {
    /// このデータをさらに 1 回再送したあとのメタデータを返す
    pub fn after_retransmit(&self) -> Self {
        Self {
            retransmission_count: self.retransmission_count.saturating_add(1),
            ..*self
        }
    }
}

/// 再送待ちの STREAM データ 1 件分の情報
///
/// データ本体は `SendBuffer::pending_retransmit` / `SendBuffer::data_at` で取得する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetransmitInfo {
    /// データオフセット
    pub offset: u64,
    /// 再送が必要な残りバイト数
    pub length: usize,
    /// この範囲の末尾が FIN で、FIN の再送も必要か
    pub fin: bool,
    /// 再送対象のメタデータ
    pub meta: RetxMeta,
}

/// 再送待ちのデータ範囲
#[derive(Debug, Clone, Copy)]
struct RetransmitRange {
    /// データオフセット
    offset: u64,
    /// 再送が必要な残りバイト数
    length: usize,
    /// 再送対象のメタデータ
    meta: RetxMeta,
}

/// ACK 済みのデータ範囲
///
/// 重複・隣接する範囲はマージして保持する。`data_start` より前になった
/// 範囲は解放時に削除するため、保持数は未解放の ACK 範囲に比例する。
/// 等値比較はテストで範囲のマージ結果を検証するために使う。
#[derive(Debug, PartialEq, Eq)]
struct AckedRange {
    /// 範囲の先頭オフセット (この値を含む)
    start: u64,
    /// 範囲の末尾オフセット (この値を含まない)
    end: u64,
}

/// 保持データを詰め直す最小の先頭消費バイト数
///
/// 小さなバッファで毎回詰め直すとコピー量が無駄になるため、これ未満の
/// 先頭消費では物理バッファの開始インデックスだけを進める。
const COMPACT_MIN_BYTES: usize = 4096;

/// 送信バッファ
///
/// アプリケーションが書き込んだデータを保持し、
/// STREAM フレームとして送信するデータを提供する。
/// ロスト時の再送範囲と ACK 済み範囲も管理する。
///
/// 保持データは絶対オフセット `[data_start, data_end)` に対応する。
/// ACK 済みの先頭連続範囲は `data_start` を進めて解放する。物理バッファ
/// (`data`) の先頭インデックス (`data_head`) を進めることで、ACK のたびに
/// 残り全データをコピーしない。一定量進んだ時点で詰め直して容量も返す。
/// `write_offset` と `send_offset` はストリームの絶対オフセットであり、
/// データの解放では変化しない。フロー制御の会計も `write_offset` を基準に
/// するため、解放の有無で変わらない。
///
/// # 不変条件
///
/// データとオフセットを変更する各操作 (`write` / `mark_sent` / `acknowledge` /
/// `release_all` / `mark_lost` / `mark_retransmit_sent` /
/// `trim_retransmit_for_reliable_size`) の末尾で、debug ビルドの不変条件検査が
/// 走る。
///
/// - `data.len() == data_head + (data_end - data_start)` である。物理バッファ
///   の有効領域 `data[data_head..]` が絶対オフセット `[data_start, data_end)`
///   にちょうど対応する。
/// - `data_start <= data_end <= write_offset` かつ `send_offset <= write_offset`。
/// - `acked_ranges` は昇順・非重複・非隣接で、すべて `[data_start, data_end)`
///   に収まる。
/// - `retransmit_ranges` は `[data_start, data_end)` に収まり、範囲同士は
///   重ならない。範囲の長さは 1 以上である。
/// - `fin_offset` は `write_offset` 以下で、設定後は変化しない。
/// - `fin_acked` は `fin_offset` が設定されていて、かつ FIN を送信済みの場合に
///   だけ真になる。
/// - `retransmit_fin` は FIN の再送が必要な場合にだけ設定され、`fin_acked` /
///   `fin_retransmit_disabled` / `fin_sent` のいずれとも同時に成立しない。
/// - `fin_retransmit_disabled` のとき `retransmit_fin` は設定されない。
#[derive(Debug, Default)]
pub struct SendBuffer {
    /// 保持データの物理バッファ
    ///
    /// 有効なデータは `data[data_head..]` であり、その先頭が `data_start`、
    /// 末尾が `data_end` に対応する。
    data: Vec<u8>,
    /// 物理バッファ内の有効データの開始インデックス
    data_head: usize,
    /// 保持データの先頭オフセット (data[data_head] の絶対オフセット)
    data_start: u64,
    /// 保持データの末尾オフセット
    data_end: u64,
    /// 書き込み済みオフセット (書き込みデータの末尾の絶対オフセット)
    write_offset: u64,
    /// 送信済みオフセット (次に送信すべきオフセット)
    send_offset: u64,
    /// FIN が設定されたオフセット (= 最終サイズ)
    fin_offset: Option<u64>,
    /// FIN を送信し、再送待ちが無いか
    ///
    /// FIN を運ぶ STREAM フレームを送信した時点で真になる。ロスト判定で
    /// 再送が必要になれば偽へ戻し、ACK で再送待ちが解消すれば再び真になる。
    /// RESET_STREAM / RESET_STREAM_AT で終端した場合は FIN を送らないため偽で
    /// ある。ただしリセット前に FIN を送信していた場合は、リセット後もその値を
    /// 保持する (リセット後の再送は `fin_retransmit_disabled` で判定する)。
    fin_sent: bool,
    /// FIN が ACK されたか
    fin_acked: bool,
    /// FIN の再送が不要になったか
    ///
    /// RESET_STREAM_AT / RESET_STREAM は Final Size を運ぶため FIN の再送は
    /// 不要である (draft-ietf-quic-reliable-stream-reset-11 Section 5)。
    /// また RESET_STREAM を送った後は STREAM フレームを再送する必要がない
    /// (RFC 9000 Section 3.3)。終端状態へ遷移してデータを解放した後も
    /// 遅延ロスト判定で FIN の再送待ちを復活させないために保持する。
    fin_retransmit_disabled: bool,
    /// ACK 済みのデータ範囲 (昇順・非重複・非隣接)
    acked_ranges: Vec<AckedRange>,
    /// ロストした再送待ちの範囲
    retransmit_ranges: Vec<RetransmitRange>,
    /// FIN の再送待ち情報
    retransmit_fin: Option<RetxMeta>,
}

impl SendBuffer {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            data_head: 0,
            data_start: 0,
            data_end: 0,
            write_offset: 0,
            send_offset: 0,
            fin_offset: None,
            fin_sent: false,
            fin_acked: false,
            fin_retransmit_disabled: false,
            acked_ranges: Vec::new(),
            retransmit_ranges: Vec::new(),
            retransmit_fin: None,
        }
    }

    /// データを書き込む。書き込んだバイト数を返す。
    ///
    /// # 前提条件
    ///
    /// `trim_retransmit_for_reliable_size` / `release_all` の後は追記できない。
    /// 前者は Reliable Size を超える保持データを解放して `data_end` を
    /// `write_offset` より前にし、後者は終端状態として以後の追記を禁止する。
    /// 追記すると保持範囲と絶対オフセットの対応が崩れるため、debug ビルドでは
    /// パニックする。
    pub fn write(&mut self, data: &[u8], fin: bool) -> usize {
        // 解放後の追記は保持範囲と絶対オフセットの対応を壊す。呼び出し側の
        // 誤用を実装バグとして早期に検出する。
        debug_assert!(
            self.data_end == self.write_offset && !self.fin_retransmit_disabled,
            "cannot write after trim or release (data_end {}, write_offset {}, fin_retransmit_disabled {})",
            self.data_end,
            self.write_offset,
            self.fin_retransmit_disabled,
        );
        let len = data.len();
        self.data.extend_from_slice(data);
        self.write_offset += len as u64;
        self.data_end += len as u64;
        if fin {
            self.fin_offset = Some(self.write_offset);
        }
        self.debug_assert_invariants();
        len
    }

    /// 送信可能なデータを取得する。
    /// (オフセット, データ, FIN フラグ) を返す。
    /// max_len はフロー制御の上限。
    ///
    /// 解放済みの範囲は保持していないため返さない。`send_offset` が保持範囲の
    /// 外にある場合は未送信データなしとして扱い、FIN の送信が必要な場合だけ
    /// 空データと FIN フラグを返す。
    pub fn pending_data(&self, max_len: usize) -> Option<(u64, &[u8], bool)> {
        let unsent = if self.send_offset >= self.data_start && self.send_offset < self.data_end {
            let start = self.data_head + (self.send_offset - self.data_start) as usize;
            // 不変条件が崩れた場合でもパニックせず未送信データなしとして扱う
            self.data.get(start..).unwrap_or(&[])
        } else {
            // 保持範囲外 (解放済み) のデータは送信しない
            &[]
        };

        if unsent.is_empty() && self.fin_offset.is_none() {
            return None;
        }
        if unsent.is_empty() && self.fin_sent {
            return None;
        }

        let len = unsent.len().min(max_len);
        let data_slice = &unsent[..len];
        // ACK 済みの FIN と、RESET_STREAM などで送信不要になった FIN は
        // 送信しない (RFC 9000 Section 3.3)。
        let fin = !self.fin_acked
            && !self.fin_retransmit_disabled
            && self.fin_offset == Some(self.send_offset + len as u64);

        if data_slice.is_empty() && !fin {
            return None;
        }

        Some((self.send_offset, data_slice, fin))
    }

    /// 新規送信した STREAM フレームの内容を記録する
    ///
    /// 送信した `len` バイト分だけ `send_offset` を進める。`fin` が真の場合は
    /// FIN を送信済みとして記録する。ACK 済みにする操作ではないため
    /// `fin_acked` は変更せず、保持データも解放しない。
    ///
    /// FIN 単独送信 (`len == 0`, `fin == true`) は、事前に [`Self::write`] を
    /// `fin == true` で呼んで `fin_offset` が設定され、未送信データが無く、
    /// `send_offset` が `fin_offset` の値と一致し、[`Self::pending_data`] が
    /// 空データと FIN を返す初回送信に限る (`fin_sent` が偽で FIN の再送待ちが
    /// 無い状態)。この呼び出しは `send_offset` / `write_offset` / `fin_offset`
    /// と保持データ量を変えず `fin_sent` だけを真にする。`fin_offset` を設定
    /// するのは [`Self::write`] であり、ここで終端位置を作ることはできない。
    /// `len > 0` で `fin` が真の場合も `send_offset + len` が `fin_offset` と
    /// 一致するときに限って呼び出す。実装はこの前提を検証せず、`fin` が真なら `fin_sent` を
    /// 立てる。FIN は追加のデータ 1 バイトとしては
    /// 数えない (RFC 9000 Section 4.5 / Section 19.8 の最終サイズは offset と
    /// length の和)。
    ///
    /// 再送の完了は [`Self::mark_retransmit_sent`] で記録する。ロスト後の
    /// 空 FIN 再送に `mark_sent` を使わない。
    pub fn mark_sent(&mut self, len: usize, fin: bool) {
        self.send_offset += len as u64;
        if fin {
            self.fin_sent = true;
        }
        self.debug_assert_invariants();
    }

    /// 書き込みオフセットを返す
    pub fn write_offset(&self) -> u64 {
        self.write_offset
    }

    /// 送信オフセットを返す
    pub fn send_offset(&self) -> u64 {
        self.send_offset
    }

    /// FIN が設定されているか
    pub fn has_fin(&self) -> bool {
        self.fin_offset.is_some()
    }

    /// FIN を送信済みで、再送待ちになっていないか
    ///
    /// FIN を運ぶ STREAM フレームを送信した時点で真になり、その再送が必要に
    /// なるロスト判定で偽へ戻る。ACK で再送待ちが解消すると再び真になる。
    /// RESET_STREAM / RESET_STREAM_AT で終端して FIN を送っていない場合は偽で
    /// ある。リセット後は FIN を再送しない (`fin_retransmit_disabled`) ため、
    /// リセット後の遅延ロスト判定では偽へ戻らない。これは「ロストしていないか」
    /// ではなく「FIN の再送待ちが無いか」を表す。
    pub fn is_fin_sent(&self) -> bool {
        self.fin_sent
    }

    /// 全データと FIN が送信済みか
    ///
    /// 再送待ちが無く、`send_offset` が `write_offset` に達し、FIN を送信済み
    /// の場合に真を返す。RESET_STREAM_AT / RESET_STREAM の後は FIN を送らない
    /// ため、全データを送信済みでも偽になり得る。終端判定には使わず、送信が
    /// 一巡したかを見る用途に限る。
    pub fn is_fully_sent(&self) -> bool {
        self.fin_sent && self.send_offset == self.write_offset && self.retransmit_ranges.is_empty()
    }

    /// FIN が ACK されたか
    ///
    /// FIN が ACK されていれば、その再送は不要である (RFC 9000 Section 13.3)。
    pub fn is_fin_acked(&self) -> bool {
        self.fin_acked
    }

    /// 保持している送信データのバイト数を返す
    ///
    /// ACK 済みで解放した範囲は含まない。ACK 済みの情報は再送しなくてよい
    /// (RFC 9000 Section 13.3)。フロー制御の会計には使わない (書き込み済み
    /// バイトは `write_offset` で別に管理する)。
    pub fn retained_len(&self) -> usize {
        (self.data_end - self.data_start) as usize
    }

    /// ACK された送信済み範囲を記録し、再送待ちと保持データから取り除く
    ///
    /// ACK された情報は再送しなくてよい (RFC 9000 Section 13.3)。重複・隣接する
    /// ACK 範囲はマージする。`fin` が ACK された場合は FIN の再送待ちを解除する。
    /// 先頭から連続して ACK された範囲は `data_start` を進めて解放し、ACK 範囲の
    /// 管理自体がメモリを増やし続けないようにする。再順序 ACK では先行する
    /// 未 ACK 範囲が ACK されるまで ACK 済みデータを保持する (正しさを優先する)。
    ///
    /// # 前提条件
    ///
    /// `offset` と `length` は、このバッファが実際に送信した STREAM フレームの
    /// 範囲を渡す。未送信の範囲 (offset + length > send_offset) を渡しては
    /// ならない。`fin` はそのフレームが FIN を運んだ場合にだけ真にする。
    /// 範囲外の値は保持範囲に切り詰めて扱うが、前提条件を満たさない呼び出しは
    /// ACK 済み範囲の会計を誤らせる。debug ビルドでは次の条件を検査する。
    ///
    /// - `offset + length <= send_offset` (未送信範囲を ACK しない)
    /// - `fin` が真なら `offset + length == fin_offset` (FIN を運ぶフレームの
    ///   末尾だけが FIN を ACK できる)
    pub fn acknowledge(&mut self, offset: u64, length: usize, fin: bool) {
        // 呼び出し側の会計ミスを ACK 済み範囲の破壊ではなくパニックとして
        // 早期に検出する。送信済みフレームの範囲と FIN の位置だけを検査し、
        // 解放済み範囲への遅延 ACK は許容する。
        debug_assert!(
            offset.saturating_add(length as u64) <= self.send_offset,
            "cannot acknowledge unsent range [{}, {}) after send_offset {}",
            offset,
            offset.saturating_add(length as u64),
            self.send_offset,
        );
        debug_assert!(
            !fin || self.fin_offset == Some(offset.saturating_add(length as u64)),
            "ACK with fin does not end at fin_offset {:?}: offset {}, length {}",
            self.fin_offset,
            offset,
            length,
        );
        if length > 0 {
            let end = offset.saturating_add(length as u64);
            self.add_acked_range(offset, end);
            self.remove_acked_from_retransmit(offset, end);
        }
        if fin {
            // FIN の ACK で FIN の再送待ちを解除する (RFC 9000 Section 13.3)
            self.fin_acked = true;
            self.retransmit_fin = None;
            // ロスト判定で偽になっていた場合も、ACK 済みなら再送は不要である。
            // 送信済みで再送待ちが無い状態に戻す。
            self.fin_sent = true;
        }
        self.trim_acked_prefix();
        self.prune_acked_ranges();
        self.compact();
        self.debug_assert_invariants();
    }

    /// 保持している送信データを全て解放する
    ///
    /// 送信側が Data Recvd / Reset Recvd へ遷移した時点で呼ぶ
    /// (RFC 9000 Section 3.1)。終端状態では STREAM データも FIN も再送しない
    /// ため (RFC 9000 Section 13.3)、保持データと再送待ちをすべて破棄する。
    /// `write_offset` / `send_offset` / `fin_offset` は状態判定とフロー制御の
    /// 会計のために保持し、FIN の ACK 済み / 再送不要の状態も保持する。
    pub fn release_all(&mut self) {
        // 保持データを使い切った後も容量を残さないよう、無条件にバッファを
        // 差し替えて容量も解放する。
        self.data = Vec::new();
        self.data_head = 0;
        self.data_start = self.write_offset;
        self.data_end = self.write_offset;
        self.acked_ranges.clear();
        self.retransmit_ranges.clear();
        self.retransmit_fin = None;
        // 終端状態では FIN の再送も不要である
        self.fin_retransmit_disabled = true;
        self.debug_assert_invariants();
    }

    /// ACK 範囲を昇順・非重複・非隣接の並びにマージして追加する
    fn add_acked_range(&mut self, start: u64, end: u64) {
        if end <= start {
            return;
        }
        // 末尾が start 未満の範囲は完全に前にある。末尾が start と等しい
        // 範囲は隣接するためマージ対象に含める。
        let first = self.acked_ranges.partition_point(|range| range.end < start);
        let mut new_start = start;
        let mut new_end = end;
        let mut last = first;
        while last < self.acked_ranges.len() && self.acked_ranges[last].start <= new_end {
            new_start = new_start.min(self.acked_ranges[last].start);
            new_end = new_end.max(self.acked_ranges[last].end);
            last += 1;
        }
        self.acked_ranges.splice(
            first..last,
            [AckedRange {
                start: new_start,
                end: new_end,
            }],
        );
    }

    /// 再送待ち範囲から ACK 済みの部分を取り除く
    fn remove_acked_from_retransmit(&mut self, start: u64, end: u64) {
        if end <= start || self.retransmit_ranges.is_empty() {
            return;
        }
        // 交差する範囲が 1 件も無ければ詰め直しを行わない。ACK のたびに
        // 再送キューの Vec を確保し直すのを避ける。
        let intersects = self.retransmit_ranges.iter().any(|range| {
            let range_end = range.offset.saturating_add(range.length as u64);
            range.offset < end && range_end > start
        });
        if !intersects {
            return;
        }
        let mut remaining = Vec::new();
        for range in self.retransmit_ranges.drain(..) {
            let range_end = range.offset.saturating_add(range.length as u64);
            if range_end <= start || range.offset >= end {
                remaining.push(range);
                continue;
            }
            // ACK 済み部分の前後だけを残す
            if range.offset < start {
                remaining.push(RetransmitRange {
                    offset: range.offset,
                    length: (start - range.offset) as usize,
                    meta: range.meta,
                });
            }
            if range_end > end {
                remaining.push(RetransmitRange {
                    offset: end,
                    length: (range_end - end) as usize,
                    meta: range.meta,
                });
            }
        }
        self.retransmit_ranges = remaining;
        self.retransmit_ranges.sort_by_key(|range| range.offset);
    }

    /// 先頭から連続して ACK された範囲まで保持データを解放する
    fn trim_acked_prefix(&mut self) {
        let mut consumed = 0;
        let mut new_start = self.data_start;
        for range in &self.acked_ranges {
            if range.end <= new_start {
                consumed += 1;
                continue;
            }
            if range.start > new_start {
                break;
            }
            new_start = range.end.min(self.data_end);
            consumed += 1;
            if new_start >= self.data_end {
                break;
            }
        }
        if consumed > 0 {
            self.acked_ranges.drain(..consumed);
        }
        if new_start > self.data_start {
            let advance = (new_start - self.data_start) as usize;
            self.data_head += advance;
            self.data_start = new_start;
        }
        if self.data_start >= self.data_end {
            // 保持データを全て解放した。Vec の容量も返す。
            self.data = Vec::new();
            self.data_head = 0;
            self.data_start = self.data_end;
        }
        self.clamp_retransmit_ranges();
    }

    /// 保持範囲外になった ACK 範囲を削除する
    fn prune_acked_ranges(&mut self) {
        let start = self.data_start;
        let end = self.data_end;
        self.acked_ranges.retain_mut(|range| {
            if range.end <= start || range.start >= end {
                return false;
            }
            range.start = range.start.max(start);
            range.end = range.end.min(end);
            range.end > range.start
        });
    }

    /// 再送待ち範囲を保持データの範囲内に収める
    ///
    /// ACK とロスト判定が同じ ACK 処理で同時に起きても、解放済みの範囲を
    /// `pending_retransmit` が読まないようにするための不変条件を保つ。
    fn clamp_retransmit_ranges(&mut self) {
        let start = self.data_start;
        let end = self.data_end;
        self.retransmit_ranges.retain_mut(|range| {
            let range_end = range.offset.saturating_add(range.length as u64);
            let new_start = range.offset.max(start);
            let new_end = range_end.min(end);
            if new_end <= new_start {
                return false;
            }
            range.offset = new_start;
            range.length = (new_end - new_start) as usize;
            true
        });
    }

    /// 物理バッファの先頭を詰め直して容量を返す
    ///
    /// ACK のたびに残り全データをコピーしないよう、先頭の消費がバッファの
    /// 半分以上になり、かつ一定量を超えたときだけ実行する。これにより
    /// 1 バイトあたりの償却コピー量は定数になる。
    fn compact(&mut self) {
        if self.data_head == 0 {
            return;
        }
        if self.data_head < COMPACT_MIN_BYTES || self.data_head * 2 < self.data.len() {
            return;
        }
        self.data.drain(..self.data_head);
        self.data_head = 0;
        if self.data.capacity() > self.data.len().saturating_mul(2) {
            self.data.shrink_to_fit();
        }
        self.debug_assert_invariants();
    }

    /// ロストしたデータ範囲を再送キューに追加する
    ///
    /// ACK 済み範囲は再送しない (RFC 9000 Section 13.3)。既に再送待ちにある
    /// 範囲とも重ならない部分だけを積む。PTO 発火では同じ未確認パケットの
    /// 内容を繰り返し再送キューへ戻すため、重複排除しないと再送キューが PTO の
    /// たびに増えてしまう。
    ///
    /// ACK 済みの FIN、または RESET_STREAM_AT / RESET_STREAM の終端後は FIN も
    /// 再送キューへ積まない。
    pub fn mark_lost(&mut self, offset: u64, length: usize, fin: bool, meta: RetxMeta) {
        if length > 0 {
            // 保持範囲 (解放済みを除く) のうち、ACK 済みと既存の再送待ちを
            // 差し引いた未修復部分だけを積む
            let lost_start = offset.max(self.data_start);
            let lost_end = offset.saturating_add(length as u64).min(self.data_end);
            if lost_end > lost_start {
                let mut segments = vec![(lost_start, lost_end)];
                // ACK 済み範囲は昇順で重ならず、すべて保持範囲内にある。
                // ロスト範囲と交差する範囲だけを差し引けばよい。
                for range in &self.acked_ranges {
                    if range.end <= lost_start {
                        continue;
                    }
                    if range.start >= lost_end {
                        break;
                    }
                    segments = subtract_segments(&segments, range.start, range.end);
                    if segments.is_empty() {
                        break;
                    }
                }
                // 既存の再送待ちも昇順で重ならないため、同様に交差する範囲だけを
                // 差し引く。
                for range in &self.retransmit_ranges {
                    if segments.is_empty() {
                        break;
                    }
                    let range_end = range.offset.saturating_add(range.length as u64);
                    if range_end <= lost_start {
                        continue;
                    }
                    if range.offset >= lost_end {
                        break;
                    }
                    segments = subtract_segments(&segments, range.offset, range_end);
                }
                if !segments.is_empty() {
                    for (start, end) in segments {
                        self.retransmit_ranges.push(RetransmitRange {
                            offset: start,
                            length: (end - start) as usize,
                            meta,
                        });
                    }
                    self.retransmit_ranges.sort_by_key(|range| range.offset);
                }
            }
        }
        if fin && !self.fin_acked && !self.fin_retransmit_disabled {
            // FIN の再送も同じデータの再送なので、既に再送待ちなら重複して積まない
            if self.retransmit_fin.is_none() {
                self.retransmit_fin = Some(meta);
            }
            self.fin_sent = false;
        }
        self.debug_assert_invariants();
    }

    /// 次に再送するデータ範囲の情報を返す (データ本体は返さない)
    ///
    /// 再送パス選択ポリシーに渡すメタデータ (元パス・ロスト理由・再送回数) を
    /// 含む。データ範囲が無く FIN のみ再送が必要な場合は `length` 0 かつ
    /// `fin` true の情報を返す。
    pub fn pending_retransmit_info(&self) -> Option<RetransmitInfo> {
        if let Some(range) = self.retransmit_ranges.first() {
            // 範囲の末尾が FIN オフセットと一致する場合のみ FIN も一緒に再送する
            let fin = self.fin_retransmit_needed()
                && self.fin_offset == Some(range.offset + range.length as u64);
            return Some(RetransmitInfo {
                offset: range.offset,
                length: range.length,
                fin,
                meta: range.meta,
            });
        }
        if self.fin_sent || !self.fin_retransmit_needed() {
            return None;
        }
        let meta = self.retransmit_fin?;
        Some(RetransmitInfo {
            offset: self.fin_offset?,
            length: 0,
            fin: true,
            meta,
        })
    }

    /// FIN の再送が必要か
    fn fin_retransmit_needed(&self) -> bool {
        self.retransmit_fin.is_some() && !self.fin_acked && !self.fin_retransmit_disabled
    }

    /// 再送待ちのデータを取得する
    /// 再送データを通常データより優先して返す。
    ///
    /// 保持範囲外 (解放済み) のデータは返さない。再送待ちの範囲の末尾が保持範囲を
    /// 超える場合 (不変条件が崩れた場合の防御) は、保持している部分までを
    /// 返す。その場合 `max_len` で途中まで返したときと同様に、範囲の末尾まで
    /// 送信していないため FIN は付けない。
    ///
    /// 再送待ちの範囲の先頭が `data_start` より前の場合も同じ不変条件違反で
    /// あり、解放済みのデータを返さないため `None` を返す。この場合、後続の
    /// 再送待ち範囲も処理しない。
    pub fn pending_retransmit(&self, max_len: usize) -> Option<(u64, &[u8], bool)> {
        let Some(range) = self.retransmit_ranges.first() else {
            // データ範囲の再送はないが、FIN のみの再送が必要な場合
            if self.fin_retransmit_needed() && !self.fin_sent {
                let fin_off = self.fin_offset?;
                return Some((fin_off, &[], true));
            }
            return None;
        };

        let relative = range.offset.checked_sub(self.data_start)?;
        let start = self.data_head + relative as usize;
        let available = self.data.len().saturating_sub(start);
        if available == 0 {
            return None;
        }
        let len = range.length.min(max_len).min(available);
        let data_slice = self.data.get(start..start.checked_add(len)?)?;

        // この範囲の末尾まで送信し、かつ末尾が FIN オフセットと一致し、
        // FIN の再送が必要な場合だけ FIN を付ける
        let fin = len == range.length
            && self.fin_retransmit_needed()
            && self.fin_offset == Some(range.offset + range.length as u64);

        Some((range.offset, data_slice, fin))
    }

    /// 指定オフセット・長さのデータを返す
    ///
    /// 再送済みデータの複製送信 (`RetxDecision::Duplicate`) で、送信済みの
    /// 範囲をもう一度別パスへ載せるために使う。解放済みの範囲や保持範囲外なら
    /// `None`。
    pub fn data_at(&self, offset: u64, length: usize) -> Option<&[u8]> {
        let end = offset.checked_add(length as u64)?;
        if offset < self.data_start || end > self.data_end {
            return None;
        }
        let start = self.data_head + (offset - self.data_start) as usize;
        self.data.get(start..start + length)
    }

    /// 再送データの送信完了を記録する
    pub fn mark_retransmit_sent(&mut self, offset: u64, len: usize, fin: bool) {
        if let Some(pos) = self
            .retransmit_ranges
            .iter()
            .position(|range| range.offset == offset)
        {
            let range = self.retransmit_ranges[pos];
            if len >= range.length {
                // 全範囲を送信した
                self.retransmit_ranges.remove(pos);
            } else {
                // 部分送信: 残りを更新する
                self.retransmit_ranges[pos] = RetransmitRange {
                    offset: range.offset + len as u64,
                    length: range.length - len,
                    meta: range.meta,
                };
            }
        }
        if fin {
            self.retransmit_fin = None;
            self.fin_sent = true;
        }
        self.debug_assert_invariants();
    }

    /// 再送待ちのデータがあるか
    pub fn has_pending_retransmit(&self) -> bool {
        !self.retransmit_ranges.is_empty() || (self.fin_retransmit_needed() && !self.fin_sent)
    }

    /// 再送範囲を Reliable Size を上限に切り詰め、超過分の保持データを解放する
    ///
    /// draft-ietf-quic-reliable-stream-reset-11 Section 5:
    /// 「Reliable Size を超えて送信したデータは再送すべきでない (SHOULD NOT)」。
    /// また RESET_STREAM_AT は Final Size を運ぶため、FIN の再送は不要になる。
    /// RESET_STREAM を送った後も STREAM フレームは不要である
    /// (RFC 9000 Section 3.3)。Reliable Size は減少方向にのみ更新できるため、
    /// この操作で失われる再送予定データは仕様上配信義務のない範囲だけである。
    ///
    /// Reliable Size までの未送信・再送対象データは保持する。
    pub fn trim_retransmit_for_reliable_size(&mut self, reliable_size: u64) {
        self.retransmit_ranges.retain_mut(|range| {
            if range.offset >= reliable_size {
                return false;
            }
            // 32 ビット環境で Reliable Size の差分が usize を超えても、
            // 保持データ長は usize に収まるため上限として扱う。
            let max_len = usize::try_from(reliable_size - range.offset).unwrap_or(usize::MAX);
            if range.length > max_len {
                range.length = max_len;
            }
            range.length > 0
        });
        // RESET_STREAM_AT が最終サイズを通知するため、FIN の再送は不要である。
        // RESET_STREAM (Reliable Size 0 相当) の場合もデータを再送しない。
        // 遅延ロスト判定で再送待ちを復活させないよう、不要であることを保持する。
        self.retransmit_fin = None;
        self.fin_retransmit_disabled = true;

        // Reliable Size を超える保持データは配信しないため解放する。
        // Reliable Size までの未 ACK データは再送が必要なので保持する。
        let keep_end = self.data_end.min(reliable_size);
        if keep_end <= self.data_start {
            // 保持データは全て Reliable Size を超えている
            self.data = Vec::new();
            self.data_head = 0;
            self.data_start = self.write_offset;
            self.data_end = self.write_offset;
        } else {
            let keep_len = (keep_end - self.data_start) as usize;
            self.data.truncate(self.data_head + keep_len);
            self.data_end = keep_end;
        }
        self.prune_acked_ranges();
        self.clamp_retransmit_ranges();
        // ACK と同じ基準で先頭を詰め直し、余剰な容量を返す。解放済みの
        // ACK 範囲と再送範囲を取り除いた後に実行し、不変条件を保つ。
        self.compact();
        // Reliable Size で末尾を切り詰めた場合、`compact` は先頭の消費が
        // 一定量を超えていなければ容量を返さない。末尾の切り詰めだけで
        // 保持量より容量が過大になった場合は、ここで明示的に解放する。
        // 容量が保持量の 2 倍以下なら、次回の書き込みや詰め直しで再利用する。
        if self.data.capacity() > self.data.len().saturating_mul(2) {
            self.data.shrink_to_fit();
        }
        self.debug_assert_invariants();
    }

    /// 構造の不変条件を debug ビルドで検査する
    ///
    /// オフセットと物理バッファの対応が崩れると `pending_retransmit` や
    /// `data_at` が誤った範囲を読むため、状態を変更する操作の末尾で検査する。
    /// 解放処理の追加や変更で対応関係がずれた場合に、テストで早期に検出する。
    fn debug_assert_invariants(&self) {
        debug_assert!(
            self.data_start <= self.data_end,
            "data_start {} exceeds data_end {}",
            self.data_start,
            self.data_end,
        );
        debug_assert!(
            self.data_head <= self.data.len(),
            "data_head {} exceeds physical buffer length {}",
            self.data_head,
            self.data.len(),
        );
        debug_assert!(
            self.data.len() as u64 == self.data_head as u64 + (self.data_end - self.data_start),
            "physical buffer length {} does not match data_head {} and range [{}, {})",
            self.data.len(),
            self.data_head,
            self.data_start,
            self.data_end,
        );
        debug_assert!(
            self.data_end <= self.write_offset,
            "data_end {} exceeds write_offset {}",
            self.data_end,
            self.write_offset,
        );
        debug_assert!(
            self.send_offset <= self.write_offset,
            "send_offset {} exceeds write_offset {}",
            self.send_offset,
            self.write_offset,
        );
        if let Some(fin_offset) = self.fin_offset {
            debug_assert!(
                fin_offset <= self.write_offset,
                "fin_offset {} exceeds write_offset {}",
                fin_offset,
                self.write_offset,
            );
        }
        if self.fin_acked {
            // FIN を ACK できるのは、FIN を設定して送信した場合だけである
            debug_assert!(
                self.fin_offset.is_some(),
                "FIN is acked without a fin_offset",
            );
            debug_assert!(self.fin_sent, "FIN is acked without being sent");
        }
        if self.retransmit_fin.is_some() {
            // FIN の再送待ちは、未 ACK かつ再送不要とされていない場合だけ立つ
            debug_assert!(
                !self.fin_acked,
                "FIN retransmit is pending after the FIN was acked",
            );
            debug_assert!(
                !self.fin_retransmit_disabled,
                "FIN retransmit is pending after it was disabled",
            );
            debug_assert!(
                !self.fin_sent,
                "FIN retransmit is pending while the FIN is marked as sent",
            );
        }
        if self.fin_retransmit_disabled {
            debug_assert!(
                self.retransmit_fin.is_none(),
                "FIN retransmit is pending after it was disabled",
            );
        }
        for (index, range) in self.acked_ranges.iter().enumerate() {
            debug_assert!(
                range.start < range.end,
                "acked range {index} is empty: [{}, {})",
                range.start,
                range.end,
            );
            debug_assert!(
                self.data_start <= range.start && range.end <= self.data_end,
                "acked range {index} [{}, {}) is outside retained range [{}, {})",
                range.start,
                range.end,
                self.data_start,
                self.data_end,
            );
            if index > 0 {
                // 隣接する範囲は add_acked_range がマージするため、前の範囲の
                // 末尾と次の範囲の先頭は必ず離れている。
                debug_assert!(
                    self.acked_ranges[index - 1].end < range.start,
                    "acked ranges are not disjoint and non-adjacent at index {index}",
                );
            }
        }
        for (index, range) in self.retransmit_ranges.iter().enumerate() {
            debug_assert!(
                range.length > 0,
                "retransmit range {index} is empty at offset {}",
                range.offset,
            );
            let range_end = range.offset.saturating_add(range.length as u64);
            debug_assert!(
                self.data_start <= range.offset && range_end <= self.data_end,
                "retransmit range {index} [{}, {}) is outside retained range [{}, {})",
                range.offset,
                range_end,
                self.data_start,
                self.data_end,
            );
            if index > 0 {
                // mark_lost / remove_acked_from_retransmit は範囲の重複を
                // 取り除くため、先頭オフセットの昇順に並び重ならない。
                debug_assert!(
                    self.retransmit_ranges[index - 1]
                        .offset
                        .saturating_add(self.retransmit_ranges[index - 1].length as u64)
                        <= range.offset,
                    "retransmit ranges overlap at index {index}",
                );
            }
        }
    }
}

/// 範囲の集合から指定範囲を取り除く
///
/// `segments` は重複しない昇順の範囲集合である。ACK 済み範囲と既存の再送待ちを
/// 差し引いて、まだ再送していない部分だけを取り出すために使う。
fn subtract_segments(segments: &[(u64, u64)], cut_start: u64, cut_end: u64) -> Vec<(u64, u64)> {
    let mut result = Vec::new();
    for &(start, end) in segments {
        if end <= cut_start || start >= cut_end {
            result.push((start, end));
            continue;
        }
        if start < cut_start {
            result.push((start, cut_start));
        }
        if end > cut_end {
            result.push((cut_end, end));
        }
    }
    result
}

/// 受信バッファ
///
/// 順序通りでないデータを受信し、リオーダリングして
/// アプリケーションに連続したデータを提供する。
#[derive(Debug, Default)]
pub struct RecvBuffer {
    /// 受信済みチャンク (オフセット → データ)
    chunks: BTreeMap<u64, Vec<u8>>,
    /// 次にアプリケーションが読むべきオフセット
    read_offset: u64,
    /// 最終サイズ (FIN または RESET_STREAM で確定)
    final_size: Option<u64>,
    /// 受信済みの最大オフセット + 長さ (フロー制御の計算用)
    max_recv_offset: u64,
}

impl RecvBuffer {
    pub fn new() -> Self {
        Self {
            chunks: BTreeMap::new(),
            read_offset: 0,
            final_size: None,
            max_recv_offset: 0,
        }
    }

    /// データを受信する。
    /// FIN フラグが立っている場合は最終サイズを記録する。
    pub fn receive(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<(), Error> {
        let end_offset = offset + data.len() as u64;

        // 最終サイズの整合性チェック (RFC 9000 Section 4.5)
        if fin {
            if end_offset < self.max_recv_offset {
                return Err(Error::Protocol {
                    code: TransportErrorCode::FINAL_SIZE_ERROR,
                    reason: format!(
                        "final size {end_offset} is below received offset {}",
                        self.max_recv_offset
                    ),
                });
            }
            if let Some(fs) = self.final_size {
                if fs != end_offset {
                    return Err(Error::Protocol {
                        code: TransportErrorCode::FINAL_SIZE_ERROR,
                        reason: format!("final size mismatch: previously {fs}, now {end_offset}"),
                    });
                }
            } else {
                self.final_size = Some(end_offset);
            }
        }

        // 最終サイズを超えるデータのチェック
        if let Some(fs) = self.final_size
            && end_offset > fs
        {
            return Err(Error::Protocol {
                code: TransportErrorCode::FINAL_SIZE_ERROR,
                reason: format!(
                    "data exceeds final size: offset {offset} + len {} > final size {fs}",
                    data.len()
                ),
            });
        }

        // 既に読み取り済みのデータは無視
        if end_offset <= self.read_offset {
            return Ok(());
        }

        // フロー制御用の最大受信オフセットを更新
        if end_offset > self.max_recv_offset {
            self.max_recv_offset = end_offset;
        }

        // RFC 9000 Section 2.2: 再送時の STREAM 境界は元の境界と一致しない。
        // 既存チャンクを置き換えると短い再送で末尾を失うため、未受信区間だけを
        // 保存する。チャンク同士を重ねないことで、部分読み取りの残余も他の
        // チャンクを上書きせずに戻せる。
        let start = offset.max(self.read_offset);
        let mut cursor = start;
        if let Some((&existing_offset, existing)) = self.chunks.range(..=start).next_back() {
            cursor = cursor.max(existing_offset + existing.len() as u64);
        }
        let mut missing = Vec::new();
        for (&existing_offset, existing) in self.chunks.range(start..end_offset) {
            if cursor >= end_offset {
                break;
            }
            if existing_offset > cursor {
                missing.push((cursor, existing_offset));
            }
            cursor = cursor.max(existing_offset + existing.len() as u64);
        }
        if cursor < end_offset {
            missing.push((cursor, end_offset));
        }
        for (begin, end) in missing {
            let begin_index = (begin - offset) as usize;
            let end_index = (end - offset) as usize;
            self.chunks
                .insert(begin, data[begin_index..end_index].to_vec());
        }

        Ok(())
    }

    /// 連続したデータをアプリケーションバッファに読み込む。
    /// (読み取りバイト数, FIN 到達フラグ) を返す。
    pub fn read(&mut self, buf: &mut [u8]) -> (usize, bool) {
        let mut total = 0;

        // 連続するチャンクをコピー
        while total < buf.len() {
            let Some((&chunk_offset, _)) = self.chunks.first_key_value() else {
                break;
            };

            if chunk_offset > self.read_offset {
                // ギャップがある
                break;
            }

            let Some(chunk) = self.chunks.remove(&chunk_offset) else {
                break;
            };
            let skip = (self.read_offset - chunk_offset) as usize;
            if skip >= chunk.len() {
                // 完全に読み取り済み
                continue;
            }

            let available = &chunk[skip..];
            let copy_len = available.len().min(buf.len() - total);
            buf[total..total + copy_len].copy_from_slice(&available[..copy_len]);
            total += copy_len;
            self.read_offset += copy_len as u64;

            // チャンクの残りを戻す
            if copy_len < available.len() {
                self.chunks
                    .insert(self.read_offset, available[copy_len..].to_vec());
            }
        }

        let fin = self.is_fully_read();
        (total, fin)
    }

    /// 最終サイズを設定する (RESET_STREAM 受信時)
    pub fn set_final_size(&mut self, final_size: u64) -> Result<(), Error> {
        if let Some(fs) = self.final_size {
            if fs != final_size {
                return Err(Error::Protocol {
                    code: TransportErrorCode::FINAL_SIZE_ERROR,
                    reason: format!("final size mismatch: previously {fs}, now {final_size}"),
                });
            }
        } else {
            self.final_size = Some(final_size);
        }
        Ok(())
    }

    /// 全データを受信済みか (最終サイズまでギャップなし)
    pub fn is_complete(&self) -> bool {
        match self.final_size {
            Some(fs) => self.contiguous_offset() >= fs,
            None => false,
        }
    }

    /// アプリケーションが全データを読み取り済みか
    pub fn is_fully_read(&self) -> bool {
        match self.final_size {
            Some(fs) => self.read_offset >= fs,
            None => false,
        }
    }

    /// 連続して受信済みのオフセットを返す
    pub fn contiguous_offset(&self) -> u64 {
        let mut offset = self.read_offset;
        for (&chunk_offset, chunk_data) in &self.chunks {
            if chunk_offset > offset {
                break;
            }
            let end = chunk_offset + chunk_data.len() as u64;
            if end > offset {
                offset = end;
            }
        }
        offset
    }

    /// 読み取りオフセットを返す
    pub fn read_offset(&self) -> u64 {
        self.read_offset
    }

    /// 最大受信オフセットを返す (フロー制御用)
    pub fn max_recv_offset(&self) -> u64 {
        self.max_recv_offset
    }

    /// フロー制御用の最大受信オフセットを指定値まで進める
    ///
    /// RESET_STREAM / RESET_STREAM_AT で final_size までを接続レベルで計上した際に
    /// 呼び出し、後続のリセットやリオーダした STREAM フレームで同じ領域を
    /// 二重計上しないようにする。
    pub fn advance_max_recv_offset(&mut self, offset: u64) {
        if offset > self.max_recv_offset {
            self.max_recv_offset = offset;
        }
    }

    /// 最終サイズを返す
    pub fn final_size(&self) -> Option<u64> {
        self.final_size
    }

    /// 指定オフセット以降の未読チャンクを破棄してメモリを返す。
    ///
    /// RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset-11) で reliable_size を
    /// 超える部分は配信されないため、その領域のバッファを解放する。オフセットより前の
    /// データ (reliable tail を含む) は保持する。`read_offset` は変更しない
    /// (既に消費済みのオフセットであり、切り詰め対象より前にある)。
    pub fn truncate(&mut self, offset: u64) {
        // offset をまたぐチャンクは前半だけ残す。
        if let Some((&chunk_offset, chunk)) = self.chunks.range(..offset).next_back()
            && chunk_offset + chunk.len() as u64 > offset
        {
            let keep = (offset - chunk_offset) as usize;
            let truncated = chunk[..keep].to_vec();
            self.chunks.insert(chunk_offset, truncated);
        }
        // offset 以降のチャンクを全て破棄する。
        let to_remove: Vec<u64> = self.chunks.range(offset..).map(|(&k, _)| k).collect();
        for key in to_remove {
            self.chunks.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests;
