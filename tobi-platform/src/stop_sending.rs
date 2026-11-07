// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! STOP_SENDING 通知キューの共通処理
//!
//! クライアントとサーバーの platform 接続は、アプリが `accept_stop_sending` を
//! 呼ばない場合に備えて専用キューに STOP_SENDING を積む。キューが溢れたときに
//! 通知を捨て、破棄件数を `ConnectionStats::stop_sending_dropped` で観測できる
//! ようにする。ここではキュー操作と警告状態の遷移だけを扱う。

use std::collections::VecDeque;

/// STOP_SENDING を専用キューへ積む
///
/// 積めたら `true`、容量に達していて捨てたら `false` を返す。容量は呼び出し側
/// が指定する。アプリが `accept_stop_sending` を呼ばずにキューが埋まった場合、
/// 通知は失われる。失われた件数は `ConnectionStats::stop_sending_dropped` で
/// 観測する。
pub(crate) fn push_stop_sending_event(
    queue: &mut VecDeque<(u64, u64)>,
    event: (u64, u64),
    capacity: usize,
) -> bool {
    if queue.len() >= capacity {
        return false;
    }
    queue.push_back(event);
    true
}

/// STOP_SENDING のイベント列をキューへ積み、捨てた件数を返す
///
/// 容量を超えた分は捨てる。戻り値は捨てた件数であり、呼び出し側はこれを
/// 接続の破棄カウンタに加算する。
pub(crate) fn enqueue_stop_sending_events(
    queue: &mut VecDeque<(u64, u64)>,
    events: impl IntoIterator<Item = (u64, u64)>,
    capacity: usize,
) -> u64 {
    let mut dropped = 0u64;
    for event in events {
        if !push_stop_sending_event(queue, event, capacity) {
            dropped = dropped.saturating_add(1);
        }
    }
    dropped
}

/// 破棄警告を出す状態の次の値を返す
///
/// 破棄が起きたら `true`、キューが空になったら `false`、それ以外は現状維持。
/// 初回の破棄でだけ警告を出し、キューが空になった後に再度溢れたらもう一度
/// 出すために使う。
pub(crate) fn next_stop_sending_warn_state(dropped: bool, queue_empty: bool, warned: bool) -> bool {
    if dropped {
        true
    } else if queue_empty {
        false
    } else {
        warned
    }
}

#[cfg(test)]
mod tests;
