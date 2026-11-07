// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

/// 接続のロール
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}
