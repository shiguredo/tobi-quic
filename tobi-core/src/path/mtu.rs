// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! DPLPMTUD (Datagram Packetization Layer PMTU Discovery)
//!
//! RFC 8899 に基づく Path MTU Discovery の状態機械。
//! パスごとに独立したインスタンスを持つ。
//! ICMP に依存せず、QUIC の ACK/Loss フィードバックで PMTU をプローブする。

use alloc::format;

use crate::error::Error;
use crate::time::{Duration, Timestamp};

/// DPLPMTUD の絶対下限 MTU (RFC 9000 Section 14: QUIC 最低保証)
///
/// RFC 9000 Section 14 は network path が 1200 バイト以上の最大 datagram size を
/// 支えられなければ QUIC を使ってはならない (MUST NOT) とする。`base_mtu` の
/// 下限として使う。
pub const BASE_MTU: u16 = 1200;

/// デフォルトの最大 MTU (Ethernet フレーム想定)
///
/// IPv6 40 + UDP 8 を引いた QUIC ペイロード上限相当。
pub const DEFAULT_MAX_MTU: u16 = 1452;

/// UDP ペイロードの最大サイズ (RFC 9000 Section 18.2)
///
/// `max_udp_payload_size` の既定値であり、UDP データグラムとして送受信できる
/// ペイロードの上限。IP ヘッダと UDP ヘッダは含まない。
pub const MAX_UDP_PAYLOAD: u16 = 65_527;

/// 探索停止条件: プローブサイズと現在 MTU の差がこの値未満なら探索完了
const SEARCH_THRESHOLD: u16 = 20;

/// 同一プローブサイズの最大リトライ回数
const MAX_PROBES: u8 = 3;

/// ブラックホール検出の連続ロスト閾値
const BLACK_HOLE_THRESHOLD: u8 = 3;

/// 再プローブ間隔 (秒)
const PMTU_RAISE_TIMER_SECS: u64 = 600;

/// BASE フェーズの確認プローブがロストした後の再試行間隔 (秒)
const BLACK_HOLE_COOLOFF_SECS: u64 = 60;

/// DPLPMTUD の状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtuState {
    /// 初期状態: プローブ未開始
    Disabled,
    /// プローブ送信待ち (次の emit_packets でプローブを送信する)
    SearchRequested,
    /// プローブ送信済み: ACK または Loss 待ち
    Searching {
        /// プローブパケットのパケット番号
        probe_pn: u64,
        /// プローブ送信時刻
        sent_at: Timestamp,
    },
    /// BASE フェーズ: ブラックホール検出後の base MTU 確認プローブ待ち
    ///
    /// `probe_size == base_mtu` で、確認プローブを即座に送る。
    BaseRequested,
    /// BASE フェーズ: base MTU 確認プローブ送信済み
    ///
    /// `probe_size == base_mtu`。確認プローブの ACK で探索を再開し、ロストで
    /// [`MtuState::BaseConfirmFailed`] へ遷移する。
    BaseSearching {
        /// プローブパケットのパケット番号
        probe_pn: u64,
        /// プローブ送信時刻
        sent_at: Timestamp,
    },
    /// BASE フェーズ: 確認プローブがロストし、再試行待ち
    ///
    /// `current_mtu` を `base_mtu` に維持し、探索を進めない。一定時間
    /// (実装は 60 秒) 後に base MTU の確認プローブからやり直す。
    /// RFC 8899 Section 5.2 の PROBE_COUNT / MAX_PROBES と ERROR 状態は実装
    /// していない簡略化であり、確認に失敗し続ける限り同じ再試行を繰り返す。
    BaseConfirmFailed,
    /// 探索完了: 確定 MTU で運用中
    SearchComplete,
}

/// DPLPMTUD コントローラ
///
/// パスごとに 1 インスタンス。Path 構造体に保持する。
///
/// 常に次の不変条件を保つ。
///
/// `base_mtu <= current_mtu <= max_mtu <= configured_max_mtu <= max_udp_payload_size <= MAX_UDP_PAYLOAD`
///
/// 探索中 (`MtuState::Searching` / `MtuState::SearchRequested`) と
/// BASE フェーズ (`MtuState::BaseSearching` / `MtuState::BaseRequested`) は、
/// 加えて `probe_size <= max_mtu` を保つ。`MtuState::BaseConfirmFailed` は
/// プローブを予約しないため `probe_size` は base MTU に置く。
///
/// 各 setter は変更したい値と状態遷移に固有の判断だけを行い、境界の整合は
/// `normalize_bounds` に一本化する。private フィールドの直接操作などで不整合が
/// 生じた場合も、`normalize_bounds` が上限を超える送信をしない側へ揃える。
#[derive(Debug)]
pub struct MtuController {
    /// 現在の状態
    state: MtuState,
    /// 確認済みの MTU (プローブ成功で更新)
    current_mtu: u16,
    /// 探索対象のプローブサイズ
    probe_size: u16,
    /// 設定された最大 MTU (ユーザー設定とピア上限の小さい方)
    ///
    /// 探索の失敗で一時的に縮小される場合は `max_mtu` を変更し、
    /// 再プローブ時はこの値へ戻す。
    configured_max_mtu: u16,
    /// 現在の探索上限 (探索の失敗で縮小され得る)
    max_mtu: u16,
    /// ピアが広告した受信上限
    ///
    /// RFC 9000 Section 18.2: ピアの `max_udp_payload_size` を超える UDP
    /// データグラムは受信されない可能性がある。値は引き下げのみ行う。
    max_udp_payload_size: u16,
    /// DPLPMTUD が下回らない最小 MTU (RFC 8899 Section 5.1.2 の MIN_PLPMTU 相当)
    base_mtu: u16,
    /// 現在のプローブサイズでの試行回数
    probe_count: u8,
    /// base_mtu 超のパケットの連続ロスト数 (ブラックホール検出)
    large_packet_loss_count: u8,
    /// 次の再プローブ時刻
    next_reprobe_at: Option<Timestamp>,
}

impl Default for MtuController {
    fn default() -> Self {
        Self::new()
    }
}

impl MtuController {
    /// 新しい MTU コントローラを作成する (既定設定)
    pub fn new() -> Self {
        Self {
            state: MtuState::Disabled,
            current_mtu: BASE_MTU,
            probe_size: 0,
            configured_max_mtu: DEFAULT_MAX_MTU,
            max_mtu: DEFAULT_MAX_MTU,
            max_udp_payload_size: MAX_UDP_PAYLOAD,
            base_mtu: BASE_MTU,
            probe_count: 0,
            large_packet_loss_count: 0,
            next_reprobe_at: None,
        }
    }

    /// 設定を指定して MTU コントローラを作成する
    ///
    /// - `initial_mtu`: 探索開始時点の確認済み MTU (RFC 8899 Section 4.4 の MPS 初期値)
    /// - `base_mtu`: 下回らない最小 MTU (RFC 8899 Section 5.1.2 の MIN_PLPMTU)
    /// - `max_mtu`: 探索の上限
    ///
    /// RFC 9000 Section 14 により `base_mtu` は 1200 以上でなければならない。
    /// `initial_mtu` は `base_mtu` 以上 `max_mtu` 以下でなければならない。
    /// RFC 9000 Section 18.2 により `max_mtu` は 65,527 以下でなければならない。
    pub fn new_with_config(initial_mtu: u16, base_mtu: u16, max_mtu: u16) -> Result<Self, Error> {
        if base_mtu < BASE_MTU {
            return Err(Error::InvalidData(format!(
                "base_mtu {base_mtu} is below the QUIC minimum MTU {BASE_MTU}"
            )));
        }
        if initial_mtu < base_mtu {
            return Err(Error::InvalidData(format!(
                "initial_mtu {initial_mtu} is below base_mtu {base_mtu}"
            )));
        }
        if max_mtu < initial_mtu {
            return Err(Error::InvalidData(format!(
                "max_mtu {max_mtu} is below initial_mtu {initial_mtu}"
            )));
        }
        if max_mtu > MAX_UDP_PAYLOAD {
            return Err(Error::InvalidData(format!(
                "max_mtu {max_mtu} exceeds the maximum UDP payload {MAX_UDP_PAYLOAD}"
            )));
        }
        Ok(Self {
            state: MtuState::Disabled,
            current_mtu: initial_mtu,
            probe_size: 0,
            configured_max_mtu: max_mtu,
            max_mtu,
            max_udp_payload_size: MAX_UDP_PAYLOAD,
            base_mtu,
            probe_count: 0,
            large_packet_loss_count: 0,
            next_reprobe_at: None,
        })
    }

    /// 設定された最大 MTU を返す
    ///
    /// ユーザー設定の `max_mtu` とピアの `max_udp_payload_size` の小さい方で
    /// ある。探索の失敗で一時的に縮小された現在の探索上限 (`max_mtu`) ではない。
    pub fn configured_max_mtu(&self) -> u16 {
        self.configured_max_mtu
    }

    /// DPLPMTUD が下回らない最小 MTU を返す
    ///
    /// ピアの `max_udp_payload_size` が設定された `base_mtu` を下回る場合は、
    /// 受信上限まで引き下げられた実効値を返す。
    pub fn base_mtu(&self) -> u16 {
        self.base_mtu
    }

    /// 探索上限を一時的に変更する
    ///
    /// 要求値は `base_mtu` と `current_mtu` 以上、`configured_max_mtu` 以下に
    /// 丸める。`current_mtu` は確認済みの MTU であるため、要求値が小さくても
    /// 引き下げない。これにより `current_mtu <= max_mtu` を維持し、二分探索の
    /// 減算が underflow しないようにする。
    pub fn set_max_mtu(&mut self, max_mtu: u16) {
        // 要求値をそのまま書き、丸めは `normalize_bounds` に委ねる。
        self.max_mtu = max_mtu;
        self.normalize_bounds();
        // 送信済みまたは予約済みのプローブサイズが新しい上限を超える場合は揃える。
        // 探索中に上限だけを下げても、次の二分探索の前提 (current <= probe <= max)
        // が崩れないようにするためである。ACK 時は `min(probe_size, max_mtu)` を
        // 採用するので、実際に送ったサイズより大きい MTU を確認済みにはしない。
        if self.probe_size > self.max_mtu {
            self.probe_size = self.max_mtu;
        }
    }

    /// ピアの受信上限 (`max_udp_payload_size`) を反映する
    ///
    /// RFC 9000 Section 18.2: ピアが広告した `max_udp_payload_size` を超える
    /// UDP データグラムは受信されない可能性がある。`limit` は `BASE_MTU` 未満を
    /// 引き上げ、現在値以下にのみ引き下げる。ピアの受信上限はハンドシェイクで
    /// 確定するため、後から大きい値を設定しても引き上げない。
    ///
    /// 上限の引き下げは `base_mtu` / `configured_max_mtu` / `current_mtu` /
    /// `max_mtu` のすべてに波及する。探索フェーズでは、送信済みのプローブが
    /// 新しい探索上限以下なら ACK を待ち続け、超える場合だけ探索をやり直す。
    /// BASE フェーズでは確認プローブのサイズを新しい base MTU に揃え、
    /// 確認をやり直す。
    pub fn set_max_udp_payload_size(&mut self, limit: u16) {
        // 保持値は `MAX_UDP_PAYLOAD` で初期化し、引き下げのみ行う。そのため
        // `u16` の入力が上限を超えても、現在値以下に丸めるだけで足りる。
        // 上限方向の clamp は不要である。`BASE_MTU` 未満は RFC 9000 Section 14
        // に反するため、下限まで引き上げてから比較する。
        let limit = limit.max(BASE_MTU);
        if limit >= self.max_udp_payload_size {
            return;
        }
        self.max_udp_payload_size = limit;
        // ピア上限は `base_mtu` (RFC 8899 Section 5.1.2 の MIN_PLPMTU) と
        // `configured_max_mtu` の上限でもあるため、不変条件に沿って波及させる。
        self.normalize_bounds();

        // BASE フェーズでは確認プローブのサイズを新しい base MTU に揃える。
        // 飛行中だった場合も、確認はやり直す必要があるため予約へ戻す。
        if matches!(
            self.state,
            MtuState::BaseRequested | MtuState::BaseSearching { .. } | MtuState::BaseConfirmFailed
        ) {
            self.probe_size = self.base_mtu;
            if matches!(self.state, MtuState::BaseSearching { .. }) {
                self.state = MtuState::BaseRequested;
            }
            self.probe_count = 0;
            return;
        }
        // 送信済みのプローブが新しい上限を超えている場合だけ探索を作り直す。
        // 上限以下なら送信済みの ACK を待ち、無駄な再送を避ける。
        if matches!(
            self.state,
            MtuState::Searching { .. } | MtuState::SearchRequested
        ) && self.probe_size > self.max_mtu
        {
            self.probe_count = 0;
            let next = self.next_probe_size();
            self.probe_size = next;
            if next.saturating_sub(self.current_mtu) < SEARCH_THRESHOLD {
                self.state = MtuState::SearchComplete;
            } else {
                self.state = MtuState::SearchRequested;
            }
        }
    }

    /// 不変条件に沿って各フィールドを整える
    ///
    /// 各 setter は変更したい値と状態遷移に固有の判断だけを行い、このメソッドが
    /// `base_mtu <= current_mtu <= max_mtu <= configured_max_mtu <=
    /// max_udp_payload_size <= MAX_UDP_PAYLOAD` を満たすように境界を揃える。
    /// 境界の正本はこのメソッドであり、各 setter の事前 clamp には依存しない。
    ///
    /// private フィールドの直接操作など、公開 API から到達しない不整合に対する
    /// 防御でもある。不整合時は、確認済み MTU と探索上限を
    /// `base_mtu..=configured_max_mtu` の範囲へ収める。上限を超える送信を続ける
    /// より、小さい MTU で送る方が安全である。
    fn normalize_bounds(&mut self) {
        // configured_max_mtu はユーザー設定とピア上限の小さい方である。
        self.configured_max_mtu = self.configured_max_mtu.min(self.max_udp_payload_size);
        // base_mtu は configured_max_mtu を超えない。
        self.base_mtu = self.base_mtu.min(self.configured_max_mtu);
        // current_mtu は base_mtu 以上 configured_max_mtu 以下に収める。
        self.current_mtu = self
            .current_mtu
            .clamp(self.base_mtu, self.configured_max_mtu);
        // max_mtu は current_mtu 以上 configured_max_mtu 以下に収める。
        self.max_mtu = self
            .max_mtu
            .clamp(self.current_mtu, self.configured_max_mtu);
    }

    /// DPLPMTUD を有効にして探索を開始する
    ///
    /// ハンドシェイク完了後に呼び出す。
    pub fn enable(&mut self) {
        if self.state != MtuState::Disabled {
            return;
        }
        // base_mtu == max_mtu なら探索不要
        if self.max_mtu <= self.base_mtu {
            return;
        }
        self.probe_size = self.next_probe_size();
        if self.probe_size.saturating_sub(self.current_mtu) < SEARCH_THRESHOLD {
            // 探索余地がなければ完了
            self.state = MtuState::SearchComplete;
        } else {
            self.state = MtuState::SearchRequested;
        }
    }

    /// 当該パスの MTU 状態を 4-tuple 移行に合わせて保守的な値へ戻す
    ///
    /// RFC 9000 Section 14.2 / Section 14.3: 最大データグラムサイズを IP ペアごと
    /// に維持することが求められる。新 4-tuple はまだ未確認であるため、旧 4-tuple
    /// で確認したサイズを確認済み値として引き継ぐべきではない。探索の上限
    /// (`configured_max_mtu` / `max_udp_payload_size`) と下限 (`base_mtu`) は
    /// 接続設定として維持し、確認済みサイズだけを `base_mtu` に戻す。
    ///
    /// draft-ietf-quic-multipath-21 Section 5.8: PMTU は IP ペアごとに扱う。
    /// RFC 8899 Section 5.2 の BASE 状態への再入と同様に、プローブサイズと
    /// プローブ回数は初期化する。旧 4-tuple でのプローブロスト回数を新 4-tuple
    /// へ持ち越さない。探索上限は旧 4-tuple での loss 履歴ではないため
    /// `configured_max_mtu` へ戻し、新 4-tuple で探索を再開する。
    pub fn reset_for_migration(&mut self) {
        self.current_mtu = self.base_mtu;
        // 探索を再開するまでの仮置き。探索を再開する場合は enable() が
        // `next_probe_size()` で上書きする。
        self.probe_size = self.base_mtu;
        self.probe_count = 0;
        self.large_packet_loss_count = 0;
        self.max_mtu = self.configured_max_mtu;
        self.next_reprobe_at = None;
        self.state = MtuState::Disabled;
        self.normalize_bounds();
        // base_mtu == max_mtu (探索余地なし) でも SearchComplete へ進め、
        // 将来の再探索 (`check_reprobe`) を可能にする。
        if self.max_mtu <= self.base_mtu {
            self.state = MtuState::SearchComplete;
            return;
        }
        self.enable();
    }

    /// 現在の状態を返す
    pub fn state(&self) -> MtuState {
        self.state
    }

    /// 確認済みの MTU を返す
    pub fn current_mtu(&self) -> u16 {
        self.current_mtu
    }

    /// プローブ送信が必要か
    pub fn needs_probe(&self) -> bool {
        matches!(
            self.state,
            MtuState::SearchRequested | MtuState::BaseRequested
        )
    }

    /// プローブパケットのサイズを返す
    pub fn probe_size(&self) -> u16 {
        self.probe_size
    }

    /// プローブパケットを送信したことを記録する
    ///
    /// `SearchRequested` / `BaseRequested` 以外の状態では何もしない。探索の
    /// 開始要求から送信記録までの間に状態が変わる呼び出し (探索の完了、
    /// リセットなど) では、送信済みのプローブを新しい探索へ計上しない。
    pub fn on_probe_sent(&mut self, pn: u64, now: Timestamp) {
        match self.state {
            MtuState::SearchRequested => {
                self.state = MtuState::Searching {
                    probe_pn: pn,
                    sent_at: now,
                };
                self.probe_count += 1;
            }
            MtuState::BaseRequested => {
                self.state = MtuState::BaseSearching {
                    probe_pn: pn,
                    sent_at: now,
                };
                self.probe_count += 1;
            }
            _ => {}
        }
    }

    /// プローブパケットが ACK された (MTU 確認成功)
    ///
    /// BASE フェーズの確認プローブなら探索を再開する。
    pub fn on_probe_acked(&mut self, pn: u64, now: Timestamp) {
        // BASE フェーズの確認プローブは、base MTU が経路で通ることを確認できた
        // ものとして探索を再開する (RFC 8899 Section 5.2)。
        if let MtuState::BaseSearching { probe_pn, .. } = self.state {
            if pn != probe_pn {
                return;
            }
            self.max_mtu = self.configured_max_mtu;
            self.apply_probe_acked(self.base_mtu, now);
            return;
        }
        if let MtuState::Searching { probe_pn, .. } = self.state {
            if pn != probe_pn {
                return;
            }
        } else {
            return;
        }

        let probe_size = self.probe_size;
        self.apply_probe_acked(probe_size, now);
    }

    /// プローブが確認できたときの探索状態の更新
    ///
    /// `probe_size` を確認済み MTU として採用し、次のプローブを予約するか
    /// 探索を完了する。BASE フェーズの確認成功からも同じ処理を通す。
    fn apply_probe_acked(&mut self, probe_size: u16, now: Timestamp) {
        // プローブサイズを確認済み MTU として採用する。通常は探索上限が
        // プローブサイズ以上なのでそのまま採用する。private フィールドの直接操作
        // などで探索上限がプローブサイズを下回る不整合状態になった場合は、上限で
        // clamp して上限を超える MTU を確認済みにしない。`probe_size` は常に
        // `current_mtu` 以上に保たれ、`base_mtu <= max_mtu` なので、この結果が
        // `base_mtu` を下回ることはない。
        self.current_mtu = probe_size.min(self.max_mtu);
        self.normalize_bounds();
        self.probe_count = 0;
        self.large_packet_loss_count = 0;

        // 次のプローブサイズを計算する
        let next = self.next_probe_size();
        if next.saturating_sub(self.current_mtu) < SEARCH_THRESHOLD {
            // 探索完了
            self.state = MtuState::SearchComplete;
            self.next_reprobe_at =
                Some(now + Duration::from_micros(PMTU_RAISE_TIMER_SECS * 1_000_000));
        } else {
            // 次のプローブを予約する
            self.probe_size = next;
            self.state = MtuState::SearchRequested;
        }
    }

    /// プローブパケットがロストした
    ///
    /// BASE フェーズの確認プローブなら PLPMTU を base MTU に維持し、探索を
    /// 進めずに再試行待ちへ遷移する。
    pub fn on_probe_lost(&mut self, pn: u64, now: Timestamp) {
        // BASE フェーズの確認プローブがロストした場合は、PLPMTU を base MTU に
        // 維持して探索を進めない (RFC 8899 Section 5.2 の Error 相当)。
        if let MtuState::BaseSearching { probe_pn, .. } = self.state {
            if pn != probe_pn {
                return;
            }
            self.current_mtu = self.base_mtu;
            self.max_mtu = self.base_mtu;
            self.probe_size = self.base_mtu;
            self.probe_count = 0;
            self.normalize_bounds();
            self.state = MtuState::BaseConfirmFailed;
            self.next_reprobe_at =
                Some(now + Duration::from_micros(BLACK_HOLE_COOLOFF_SECS * 1_000_000));
            return;
        }
        if let MtuState::Searching { probe_pn, .. } = self.state {
            if pn != probe_pn {
                return;
            }
        } else {
            return;
        }

        if self.probe_count >= MAX_PROBES {
            // 同一サイズでの最大リトライ到達: 探索範囲を縮小する。
            // `probe_size - 1` が確認済み MTU を下回る場合や設定上限を超える場合は、
            // `normalize_bounds` が `current_mtu..=configured_max_mtu` に丸める。
            self.max_mtu = self.probe_size.saturating_sub(1);
            self.normalize_bounds();
            self.probe_count = 0;

            let next = self.next_probe_size();
            if next.saturating_sub(self.current_mtu) < SEARCH_THRESHOLD {
                self.state = MtuState::SearchComplete;
                self.next_reprobe_at =
                    Some(now + Duration::from_micros(PMTU_RAISE_TIMER_SECS * 1_000_000));
            } else {
                self.probe_size = next;
                self.state = MtuState::SearchRequested;
            }
        } else {
            // 同一サイズでリトライする
            self.state = MtuState::SearchRequested;
        }
    }

    /// base_mtu 超のパケットのロストを通知する (ブラックホール検出)
    pub fn on_large_packet_lost(&mut self, _now: Timestamp) {
        if self.current_mtu <= self.base_mtu {
            return;
        }
        self.large_packet_loss_count += 1;
        if self.large_packet_loss_count >= BLACK_HOLE_THRESHOLD {
            // ブラックホール検出: MTU を base_mtu にリセットし、BASE フェーズへ
            // 遷移する。base MTU の確認プローブで経路が通ることを確認してから
            // 探索を再開する (RFC 8899 Section 5.2)。
            self.current_mtu = self.base_mtu;
            self.normalize_bounds();
            self.large_packet_loss_count = 0;
            self.probe_size = self.base_mtu;
            self.probe_count = 0;
            self.next_reprobe_at = None;
            self.state = MtuState::BaseRequested;
        }
    }

    /// base_mtu 超のパケットが ACK された (ブラックホールカウンタをリセット)
    pub fn on_large_packet_acked(&mut self) {
        self.large_packet_loss_count = 0;
    }

    /// 再プローブ時刻を確認し、必要なら探索を再開する
    ///
    /// BASE フェーズの確認に失敗している場合は、クールオフ後に base MTU の
    /// 確認プローブからやり直す。
    pub fn check_reprobe(&mut self, now: Timestamp) {
        // BASE フェーズの確認に失敗した場合は、クールオフ後に base MTU の
        // 確認プローブからやり直す (探索は進めない)。
        if let Some(reprobe_at) = self.next_reprobe_at
            && now.has_elapsed(reprobe_at)
            && self.state == MtuState::BaseConfirmFailed
        {
            self.next_reprobe_at = None;
            self.probe_size = self.base_mtu;
            self.probe_count = 0;
            self.state = MtuState::BaseRequested;
            return;
        }
        if let Some(reprobe_at) = self.next_reprobe_at
            && now.has_elapsed(reprobe_at)
            && self.state == MtuState::SearchComplete
        {
            self.next_reprobe_at = None;
            // 探索上限を設定上限 (ピア上限で引き下げ済み) に戻して再探索する。
            self.max_mtu = self.configured_max_mtu;
            // 防御的: `current_mtu` が設定上限を超える不整合状態では、
            // `normalize_bounds` が現在値と探索上限を揃える。
            self.normalize_bounds();
            let next = self.next_probe_size();
            if next.saturating_sub(self.current_mtu) >= SEARCH_THRESHOLD {
                self.probe_size = next;
                self.probe_count = 0;
                self.state = MtuState::SearchRequested;
            }
        }
    }

    /// 再プローブタイマーのデッドラインを返す
    pub fn reprobe_deadline(&self) -> Option<Timestamp> {
        self.next_reprobe_at
    }

    /// 二分探索で次のプローブサイズを計算する
    ///
    /// 不変条件 `current_mtu <= max_mtu` が成り立つ限り飽和は発生しないが、
    /// 不整合時にも panic しないよう減算と加算に飽和演算を使う。
    fn next_probe_size(&self) -> u16 {
        self.current_mtu
            .saturating_add(self.max_mtu.saturating_sub(self.current_mtu) / 2)
    }
}

#[cfg(test)]
mod tests;
