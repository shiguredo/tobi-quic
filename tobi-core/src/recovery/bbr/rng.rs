// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! シンプルな xorshift64 PRNG
//!
//! BBR の帯域プローブタイミング分散に使用する。
//! 暗号学的安全性は不要。
//! Multipath QUIC では各パスの BBR インスタンスが異なるシード
//! (パス作成時刻) を持つため、自然に非同期化される。

/// xorshift64 PRNG
///
/// Marsaglia, G. (2003). "Xorshift RNGs" に基づく。
#[derive(Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// 初期シードで初期化する
    ///
    /// シードが 0 の場合は 1 に置換する (xorshift はゼロ状態を避ける必要がある)。
    pub fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    /// 0..n の範囲で乱数を返す
    ///
    /// n が 0 の場合は 0 を返す。
    pub fn gen_range(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.next() % n
    }

    /// 次の乱数値を生成する
    fn next(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }
}

#[cfg(test)]
mod tests;
