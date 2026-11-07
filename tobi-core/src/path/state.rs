// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! パス状態定義

/// パスの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// CID 交換済み、検証前
    Pending,
    /// PATH_CHALLENGE 送信済み、PATH_RESPONSE 待ち
    Validating,
    /// 検証済み、利用可能
    Active,
    /// PATH_ABANDON 送信済み
    Abandoning,
    /// 廃棄完了
    Abandoned,
}
