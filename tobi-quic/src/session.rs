// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! クライアントのセッションチケットストア
//!
//! rustls の `ClientSessionStore` をラップし、保存された TLS 1.3 チケットの
//! 観測手段を提供する。チケットのバイト列表現は rustls が公開しないため、
//! 再開に必要な情報はストア内に保持したまま、ストア自体を次の `ClientConfig`
//! へ引き継ぐ方式をとる。

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rustls::NamedGroup;
use rustls::client::{ClientSessionStore, Tls12ClientSessionValue, Tls13ClientSessionValue};
use rustls::pki_types::ServerName;

/// セッションチケットをメモリ内に保持するストア
///
/// 内部の保存先には rustls の `ClientSessionMemoryCache` を使う。複数の
/// `ClientConfig` で同一インスタンスを共有すると、プロセス内でセッションを
/// 再開できる。`ClientTlsConfig::with_session_store` に渡して使う。
///
/// チケットのバイト列は取得できない。rustls はクライアントセッションの
/// バイト列表現 (チケットと再開用の鍵素材) を公開していないため、
/// プロセス再起動をまたいだ永続化はできない。
#[derive(Debug)]
pub struct SessionTicketStore {
    /// 実際の保存先
    inner: Arc<dyn ClientSessionStore>,
    /// 保存された TLS 1.3 チケットの累計
    tls13_tickets_received: AtomicUsize,
    /// 再開に使用された TLS 1.3 チケットの累計
    tls13_tickets_taken: AtomicUsize,
}

impl Default for SessionTicketStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionTicketStore {
    /// 空のインメモリストアを作る
    pub fn new() -> Self {
        Self {
            inner: Arc::new(rustls::client::ClientSessionMemoryCache::new(256)),
            tls13_tickets_received: AtomicUsize::new(0),
            tls13_tickets_taken: AtomicUsize::new(0),
        }
    }

    /// これまでに保存された TLS 1.3 チケットの累計を返す
    ///
    /// セッション再開でチケットが取り出されても減らない。サーバーが複数の
    /// NewSessionTicket を送る場合は 1 接続で複数増えることがある。
    pub fn tls13_tickets_received(&self) -> usize {
        self.tls13_tickets_received.load(Ordering::Relaxed)
    }

    /// 再開に使用された TLS 1.3 チケットの累計を返す
    ///
    /// `take_tls13_ticket` がチケットを返した回数。別バージョンの接続で
    /// チケットが使われていないことの検証に使う。
    pub fn tls13_tickets_taken(&self) -> usize {
        self.tls13_tickets_taken.load(Ordering::Relaxed)
    }
}

impl ClientSessionStore for SessionTicketStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.inner.set_kx_hint(server_name, group);
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.inner.kx_hint(server_name)
    }

    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.inner.set_tls12_session(server_name, value);
    }

    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.inner.tls12_session(server_name)
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.inner.remove_tls12_session(server_name);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        // チケットのバイト列は rustls が公開していないため、保存された事実だけを
        // 数える。再開に必要な情報は inner のストアがそのまま保持する。
        self.tls13_tickets_received.fetch_add(1, Ordering::Relaxed);
        self.inner.insert_tls13_ticket(server_name, value);
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        let ticket = self.inner.take_tls13_ticket(server_name);
        if ticket.is_some() {
            self.tls13_tickets_taken.fetch_add(1, Ordering::Relaxed);
        }
        ticket
    }
}

/// QUIC バージョンごとにセッションチケットストアを分離する管理型
///
/// RFC 9369 Section 5: TLS セッションチケットは発行した QUIC バージョンに
/// 固有であり、クライアントは別バージョンの接続でチケットを使用してはならない
/// (MUST)。本型はバージョンごとに独立した [`SessionTicketStore`] を保持し、
/// 接続試行時にそのバージョン専用のストアを返す。
///
/// `ClientTlsConfig::with_versioned_session_store` に渡して使う。
#[derive(Debug)]
pub struct VersionedSessionStore {
    /// QUIC バージョン → そのバージョン専用のチケットストア
    ///
    /// 接続確立時にのみ参照する小さなマップで、保持時間も短い。チャネルで
    /// 単一所有者に集約するほどの競合が無いため `Mutex` を使う。
    stores: Mutex<HashMap<u32, Arc<SessionTicketStore>>>,
}

impl Default for VersionedSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl VersionedSessionStore {
    /// 空のバージョン分離ストアを作る
    pub fn new() -> Self {
        Self {
            stores: Mutex::new(HashMap::new()),
        }
    }

    /// 指定バージョン専用のチケットストアを返す
    ///
    /// 初回呼び出し時にそのバージョンのストアを作成する。同じバージョンに対しては
    /// 同じインスタンスを返すため、複数回の接続試行でチケットを再利用できる。
    pub fn store_for(&self, version: u32) -> Arc<SessionTicketStore> {
        // ロック保持中の panic で poison されても、保存済みのストアは
        // 引き続き利用できる。ここで panic すると、以後の接続試行がすべて
        // 巻き込まれるため、poison を回復して処理を継続する。
        let mut stores = self
            .stores
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(
            stores
                .entry(version)
                .or_insert_with(|| Arc::new(SessionTicketStore::new())),
        )
    }

    /// 全バージョンで保存された TLS 1.3 チケットの累計を返す
    pub fn tls13_tickets_received(&self) -> usize {
        self.stores
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(|store| store.tls13_tickets_received())
            .sum()
    }
}

#[cfg(test)]
mod tests;
