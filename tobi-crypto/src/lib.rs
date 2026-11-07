// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! tobi-quic の aws-lc-rs 依存暗号プリミティブ
//!
//! - `packet`: QUIC パケット保護 (AEAD / Header Protection / Initial keys / Retry / Stateless Reset)
//! - `token`: HMAC ベースのアドレス検証トークン

// 自前コードに unsafe を入れない。暗号ライブラリ内部の unsafe は各ライブラリの
// 責任範囲であり、この属性は tobi-crypto のコードだけを対象にする。
#![forbid(unsafe_code)]
// 本番コードでは panic しやすい unwrap を禁止する。テストコードは対象外。
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

pub mod keys;
pub mod protection;
pub mod token;

pub use aws_lc_rs;
