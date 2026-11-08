// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 0-RTT リプレイフィルターのデフォルト実装 (RFC 9001 Section 9.2)
//!
//! `tobi_core::token::ReplayFilter` トレイトの std 依存実装。
//! core 層は `std::time::Instant` / `std::sync::Mutex` を避けるため、
//! 具象実装は本体クレート側で提供する。

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tobi_core::token::ReplayFilter;

/// リプレイフィルターが保持するチケットハッシュの既定上限
///
/// 0-RTT を送れるチケットはハンドシェイクで発行されるため、上限に達するには
/// 多数の接続が必要になる。それでも時間窓内で無制限に増やされるとメモリを
/// 消費するため、エントリ数の上限を設ける。
pub const DEFAULT_MAX_REPLAY_ENTRIES: usize = 65_536;

/// リプレイフィルターの内部状態
///
/// `order` は挿入順を保持し、期限切れと上限超過の削除を先頭から O(1) で
/// 行えるようにする。`used` と `order` は同じロックで保護し、両者の件数を
/// 一致させる。
struct ReplayState {
    /// 使用済みチケットハッシュ (タイムスタンプ付き)
    used: HashMap<Vec<u8>, Instant>,
    /// チケットハッシュの挿入順
    order: VecDeque<Vec<u8>>,
}

/// 時間窓ベースのリプレイフィルター (デフォルト実装)
///
/// 指定された時間窓内で使用されたチケットハッシュを記録し、
/// 同一チケットの再利用を検知する。
///
/// チェックごとに全エントリを走査しない。期限切れと上限超過の削除は
/// 挿入順の先頭から行うため、保持件数に対して償却 O(1) で動作する。
pub struct TimeWindowReplayFilter {
    /// 使用済みチケットハッシュと挿入順
    state: Mutex<ReplayState>,
    /// 時間窓
    window: Duration,
    /// 保持するチケットハッシュの上限
    max_entries: usize,
}

impl TimeWindowReplayFilter {
    /// 新しい TimeWindowReplayFilter を作成する
    ///
    /// `window` はチケットハッシュを記録する時間窓。
    pub fn new(window: Duration) -> Self {
        Self {
            state: Mutex::new(ReplayState {
                used: HashMap::new(),
                order: VecDeque::new(),
            }),
            window,
            max_entries: DEFAULT_MAX_REPLAY_ENTRIES,
        }
    }

    /// 保持するチケットハッシュの上限を指定する
    ///
    /// 0 は 1 として扱う。上限を超えた場合は最も古いエントリを削除する。
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries.max(1);
        self
    }

    /// 現在記録しているチケットハッシュの件数
    ///
    /// 時間窓の掃除は `check()` で行うため、この値は最後の `check()` 時点の
    /// 件数である。上限が守られていることを観測するために使う。
    pub fn tracked_ticket_count(&self) -> usize {
        // Mutex が poison されても記録済みの値を読めるようにする
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.used.len()
    }
}

impl ReplayFilter for TimeWindowReplayFilter {
    fn check(&self, ticket_hash: &[u8]) -> bool {
        // Mutex が poison されても 0-RTT チェックを継続する。panic させると
        // 以後のすべての 0-RTT が接続を巻き込んで停止する。
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();

        // 挿入順の先頭から期限切れを削除する。Instant は単調増加なので、
        // 先頭が期限切れでなければ他のエントリも期限切れではない。
        while let Some(front) = state.order.front() {
            let Some(timestamp) = state.used.get(front).copied() else {
                // 防御的: 両者の不整合があれば order だけを捨てる
                state.order.pop_front();
                continue;
            };
            if now.duration_since(timestamp) < self.window {
                break;
            }
            let expired = state.order.pop_front().expect("front exists");
            state.used.remove(&expired);
        }

        // 同一チケットが既に使用されていた場合はリプレイ
        let key = ticket_hash.to_vec();
        if state.used.contains_key(&key) {
            return false;
        }

        // 上限に達している場合は最も古いエントリを削除してから記録する。
        // 上限を超えて保持すると、時間窓内に多数のチケットを発行させられて
        // メモリを消費する。
        if state.used.len() >= self.max_entries {
            if let Some(oldest) = state.order.pop_front() {
                state.used.remove(&oldest);
            } else if let Some(oldest) = state.used.keys().next().cloned() {
                // 防御的: order が空でも used に残っている場合に備える
                state.used.remove(&oldest);
            }
        }

        // 新規チケットとして記録する
        state.used.insert(key.clone(), now);
        state.order.push_back(key);
        true
    }
}
