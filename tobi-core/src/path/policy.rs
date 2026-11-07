// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Multipath ポリシー設定
//!
//! アプリケーションが接続時に渡すポリシー。
//! PathController のデフォルト実装がこれを参照してパスの開閉を判断する。

use alloc::string::String;
use alloc::vec::Vec;

/// Multipath のモード
///
/// パスの利用方法を指定する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultipathMode {
    /// 最良パスのみ使用し、障害時に切り替える
    ///
    /// 常に 1 パスが Available、他は Backup。Backup のパスは PING による
    /// keep-alive で到達性を維持し、切り替える前に PATH_CHALLENGE で
    /// 到達性を確認する。
    Handover,
    /// 全パスで同時送信して帯域を集約する
    ///
    /// 通常は全パスが Available。全パスを常時利用するため、パス単位の
    /// keep-alive は既定で無効。品質が最良値の 5 倍超まで劣化したパスは
    /// Backup へ降格して keep-alive を有効化し、4 倍以下へ回復したら
    /// Available へ戻す。
    Aggregate,
    /// プライマリを使い、セカンダリは待機させる
    ///
    /// 1 パスが Available、他は Backup。プライマリを最初に観測した利用可能な
    /// パスに固定し、待機パスの RTT が優れていても切り替えない。プライマリが
    /// 使えなくなったときだけ、検証済みの待機パスから代替を選ぶ (待機パスが
    /// 無ければ利用可能なパスを使う)。Backup の
    /// パスは PING による keep-alive で到達性を維持し、他に利用可能なパスが
    /// あり、候補をしばらく使っていない場合は切り替える前に PATH_CHALLENGE で
    /// 到達性を確認する。
    Backup,
}

/// ネットワークインターフェースのフィルタ
///
/// 利用するインターフェースを制限する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceFilter {
    /// 全インターフェースを使う
    All,
    /// 指定名のインターフェースのみ使う
    Allow(Vec<String>),
    /// 指定名のインターフェースを除外する
    Deny(Vec<String>),
}

impl InterfaceFilter {
    /// 指定のインターフェース名がフィルタを通過するか判定する
    pub fn accepts(&self, name: &str) -> bool {
        match self {
            Self::All => true,
            Self::Allow(names) => names.iter().any(|n| n == name),
            Self::Deny(names) => !names.iter().any(|n| n == name),
        }
    }
}

/// Multipath ポリシー設定
///
/// アプリケーションが接続時に渡す。PathController がパスの開閉を判断する際に参照する。
#[derive(Debug, Clone)]
pub struct MultipathPolicy {
    /// Multipath のモード
    pub mode: MultipathMode,
    /// インターフェースフィルタ
    pub interface_filter: InterfaceFilter,
    /// 同時に利用するパス数の上限
    pub max_paths: usize,
}

impl Default for MultipathPolicy {
    fn default() -> Self {
        Self {
            mode: MultipathMode::Handover,
            interface_filter: InterfaceFilter::All,
            max_paths: 2,
        }
    }
}
