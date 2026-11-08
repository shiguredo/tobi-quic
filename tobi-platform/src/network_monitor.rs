// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! ネットワークインターフェース変化の監視
//!
//! `getifaddrs` をポーリングしてインターフェース名と IP アドレスのスナップショットを取得し、
//! 差分を [`NetworkEvent`] として通知する。Linux / Android / macOS / iOS を対象とする。
//!
//! Android の `getifaddrs` / `freeifaddrs` は API 24 で追加されたため、
//! Android では API 24 以上が必要である。API 24 未満を指定するとリンクに失敗する。

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::path::NetworkEvent;

/// インターフェースの 1 アドレス
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InterfaceAddr {
    /// インターフェース名 (例: en0, eth0)
    pub name: String,
    /// インターフェースに割り当てられたアドレス
    pub addr: SocketAddr,
}

/// 現在のインターフェースアドレス一覧を取得する
///
/// `getifaddrs` を呼び出し、AF_INET / AF_INET6 のアドレスのみを返す。
/// 戻り値は名前とアドレスでソート済みかつ重複除去済みのため、
/// [`diff_interface_addrs`] の入力として安定した順序になる。
pub fn collect_interface_addrs() -> io::Result<Vec<InterfaceAddr>> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs は成功時に ifap に有効なリストを書き込み、
    // 失敗時は 0 以外を返す。失敗時は ifap を参照しない。
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut result = Vec::new();
    let mut cursor = ifap;
    while !cursor.is_null() {
        // SAFETY: cursor は getifaddrs が返したリストの有効なノード。
        let ifa = unsafe { &*cursor };
        if !ifa.ifa_addr.is_null() {
            // SAFETY: ifa_name は NUL 終端された C 文字列。
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: ifa_addr は有効な sockaddr を指す。
            if let Some(addr) = unsafe { sockaddr_to_socket_addr(ifa.ifa_addr) } {
                result.push(InterfaceAddr { name, addr });
            }
        }
        // 参照経由のフィールドアクセスは安全のため unsafe は不要
        cursor = ifa.ifa_next;
    }

    // SAFETY: ifap は getifaddrs が確保したリストで、freeifaddrs で解放する。
    unsafe { libc::freeifaddrs(ifap) };

    result.sort();
    result.dedup();
    Ok(result)
}

/// `sockaddr` を [`SocketAddr`] に変換する
///
/// AF_INET / AF_INET6 以外 (AF_LINK 等) は `None` を返す。
///
/// # Safety
///
/// `sa` は有効な `sockaddr` を指し、`sa_family` に対応する構造体
/// (`sockaddr_in` / `sockaddr_in6`) が読み取り可能でなければならない。
unsafe fn sockaddr_to_socket_addr(sa: *const libc::sockaddr) -> Option<SocketAddr> {
    match unsafe { (*sa).sa_family as libc::c_int } {
        libc::AF_INET => {
            // SAFETY: sa_family が AF_INET のため sockaddr_in として読める。
            let sin = unsafe { &*(sa as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Some(SocketAddr::new(IpAddr::V4(ip), u16::from_be(sin.sin_port)))
        }
        libc::AF_INET6 => {
            // SAFETY: sa_family が AF_INET6 のため sockaddr_in6 として読める。
            let sin6 = unsafe { &*(sa as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be(sin6.sin6_port),
                0,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// 2 つのスナップショットの差分から [`NetworkEvent`] を生成する
///
/// - 同一インターフェース内で消えたアドレスと現れたアドレスは 1 対 1 で
///   [`NetworkEvent::AddressChanged`] に対応付ける (順序はアドレス順)
/// - 対応が付かなかった消滅アドレスは [`NetworkEvent::InterfaceDown`]
/// - 対応が付かなかった出現アドレスは [`NetworkEvent::InterfaceUp`]
///
/// 純粋関数のため単体テストで網羅する。
pub fn diff_interface_addrs(
    previous: &[InterfaceAddr],
    current: &[InterfaceAddr],
) -> Vec<NetworkEvent> {
    let mut names: Vec<&str> = previous
        .iter()
        .chain(current.iter())
        .map(|i| i.name.as_str())
        .collect();
    names.sort_unstable();
    names.dedup();

    let mut events = Vec::new();
    for name in names {
        let old_addrs: Vec<SocketAddr> = {
            let mut addrs: Vec<SocketAddr> = previous
                .iter()
                .filter(|i| i.name == name)
                .map(|i| i.addr)
                .collect();
            addrs.sort_unstable();
            addrs.dedup();
            addrs
        };
        let new_addrs: Vec<SocketAddr> = {
            let mut addrs: Vec<SocketAddr> = current
                .iter()
                .filter(|i| i.name == name)
                .map(|i| i.addr)
                .collect();
            addrs.sort_unstable();
            addrs.dedup();
            addrs
        };

        let mut removed: Vec<SocketAddr> = old_addrs
            .iter()
            .filter(|a| !new_addrs.contains(a))
            .copied()
            .collect();
        let mut added: Vec<SocketAddr> = new_addrs
            .iter()
            .filter(|a| !old_addrs.contains(a))
            .copied()
            .collect();

        // 同一インターフェース内で消えたアドレスと現れたアドレスを 1 対 1 で
        // AddressChanged に対応付ける (残りは Up / Down として通知する)。
        while let (Some(old_addr), Some(new_addr)) =
            (removed.first().copied(), added.first().copied())
        {
            events.push(NetworkEvent::AddressChanged {
                name: name.to_string(),
                old_addr,
                new_addr,
            });
            removed.remove(0);
            added.remove(0);
        }

        for addr in removed {
            events.push(NetworkEvent::InterfaceDown {
                name: name.to_string(),
                addr,
            });
        }
        for addr in added {
            events.push(NetworkEvent::InterfaceUp {
                name: name.to_string(),
                addr,
            });
        }
    }
    events
}

/// `getifaddrs` ポーリングによるネットワーク監視
///
/// 一定間隔で [`collect_interface_addrs`] を呼び、前回スナップショットとの
/// 差分を [`NetworkEvent`] として通知する。
#[derive(Debug)]
pub struct NetworkMonitor {
    /// ポーリング間隔
    interval: Duration,
    /// 前回のスナップショット
    previous: Vec<InterfaceAddr>,
}

impl NetworkMonitor {
    /// 指定間隔で監視するモニタを作成する
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            previous: Vec::new(),
        }
    }

    /// ポーリング間隔を返す
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// 1 回ポーリングし、前回からの差分イベントを返す
    ///
    /// 初回呼び出しでは previous が空のため、現在の全アドレスが
    /// [`NetworkEvent::InterfaceUp`] として返る。
    pub fn poll(&mut self) -> io::Result<Vec<NetworkEvent>> {
        let current = collect_interface_addrs()?;
        let events = diff_interface_addrs(&self.previous, &current);
        self.previous = current;
        Ok(events)
    }

    /// ポーリングを継続し、イベントを `tx` へ送出する
    ///
    /// `tx` に対応する receiver が drop されたら終了する。監視の無効化や接続の
    /// drop で受信側が消えたときに、インターフェースの変化が無くてもポーリングを
    /// 続けない。ポーリング失敗時はログを出して継続する
    /// (インターフェースの一時的な取得失敗で監視を止めない)。
    pub async fn run(mut self, tx: mpsc::Sender<NetworkEvent>) {
        // tokio::time::interval は間隔 0 を許容しない。呼び出し側の設定ミスで
        // パニックしないよう、最低 1 ms に丸める。
        let interval = self.interval.max(Duration::from_millis(1));
        let mut ticker = tokio::time::interval(interval);
        loop {
            // 受信側の drop を ticker と同時に待つ。ticker だけで待つと、
            // 変化が無い間は receiver が閉じても次の tick までタスクが残る。
            // interval の初回 tick は即座に完了するため、初回ポーリングは
            // 従来どおり run の開始直後に行われる。
            tokio::select! {
                // 停止要求を優先するため closed() を先に評価する。
                biased;
                // receiver が既に閉じている場合はポーリングせずに終了する。
                _ = tx.closed() => return,
                _ = ticker.tick() => {}
            }
            match self.poll() {
                Ok(events) => {
                    for event in events {
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("network monitor poll failed: {e}");
                }
            }
        }
    }
}
