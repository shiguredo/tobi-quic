// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! アドレス検証トークン (RFC 9000 Section 8.1.3 / RFC 9369 Section 5)
//!
//! サーバーが NEW_TOKEN フレームで配布し、クライアントが将来の接続で
//! Initial パケットに含めるトークンの生成・検証を行う。
//!
//! RFC 9369 Section 5: トークンは発行した QUIC バージョンに固有であり、
//! クライアントは別バージョンの接続でトークンを使用してはならず、
//! サーバーはトークンの発行バージョンを検証しなければならない (MUST)。

use alloc::vec::Vec;
use core::net::SocketAddr;

/// トークンの生成と検証を行うトレイト
///
/// サーバーはこのトレイトを実装して NEW_TOKEN のトークン形式を定義する。
/// トークン形式は RFC 9000 で規定されておらず、サーバーの実装に委ねられている。
pub trait TokenProvider: Send + Sync {
    /// クライアントに配布するトークンを生成する
    ///
    /// `client_addr` はトークン発行時のクライアントアドレス。
    /// `version` はトークンを発行する接続の QUIC バージョンで、検証時に照合する
    /// (RFC 9369 Section 5 MUST)。
    fn generate_token(&self, client_addr: &SocketAddr, version: u32) -> Vec<u8>;

    /// 複数の検証済みアドレスを含むトークンを生成する
    ///
    /// RFC 10069 Section 3.1.3 SHOULD:
    /// Multipath 環境では同一クライアントから複数のアドレスで接続が試みられるため、
    /// サーバーは検証済みアドレスのいずれかで次回接続を許可できるトークンを発行すべき。
    ///
    /// デフォルト実装では `client_addrs[0]` のみを使って `generate_token()` を呼ぶため、
    /// 複数アドレス対応の実装は本メソッドをオーバーライドする必要がある。
    /// `client_addrs` が空の場合は空のトークンを返す。
    fn generate_token_multi(&self, client_addrs: &[SocketAddr], version: u32) -> Vec<u8> {
        match client_addrs.first() {
            Some(addr) => self.generate_token(addr, version),
            None => Vec::new(),
        }
    }

    /// Initial パケットで受信したトークンを検証する
    ///
    /// `client_addr` はトークンを送信したクライアントのアドレス。
    /// `version` はトークンを受け取った接続の QUIC バージョン。トークンの
    /// 発行バージョンと一致しない場合は `false` を返さなければならない
    /// (RFC 9369 Section 5 MUST)。
    /// 有効なトークンの場合は `true` を返し、アドレス検証済みとして扱う。
    /// 複数アドレス対応のトークンの場合、`client_addr` が格納アドレスのいずれかと
    /// 一致すれば有効とみなす。
    fn validate_token(&self, token: &[u8], client_addr: &SocketAddr, version: u32) -> bool;
}

/// 0-RTT リプレイフィルター (RFC 9001 Section 9.2)
///
/// サーバーが 0-RTT パケットを受理する際にリプレイ攻撃を検知する。
/// 同じセッションチケットが複数回使用されることを防ぐ。
pub trait ReplayFilter: Send + Sync {
    /// 0-RTT データを受理してよいかチェックする
    ///
    /// `ticket_hash` はセッションチケットのハッシュ値。
    /// 初回の呼び出しは `true` を返し、同じハッシュの 2 回目以降は `false` を返す。
    fn check(&self, ticket_hash: &[u8]) -> bool;
}
