// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

#![no_std]
// unsafe を使わないことを crate 全体で強制する。
#![forbid(unsafe_code)]
// 本番コードでは `.unwrap()` ではなく `.expect("MESSAGE")` を使う。
// テストコードは `cfg(test)` の間だけ許可する。
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

#[macro_use]
extern crate alloc;

pub mod connection;
pub mod connection_id;
pub mod error;
pub mod frame;
pub mod nonce;
pub mod packet;
pub mod path;
pub mod recovery;
pub mod role;
pub mod scheduler;
pub mod stats;
pub mod time;
pub mod token;
pub mod transport_params;
pub mod varint;
