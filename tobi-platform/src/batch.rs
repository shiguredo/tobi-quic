// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! UDP のバッチ送受信で「どこまでまとめるか」を決めるロジック
//!
//! `sendmmsg` / GSO で 1 回のシステムコールにまとめられるのは、同じソケットで
//! 同じ 4-tuple へ送る同一 ECN コードポイントのデータグラムだけである。
//! システムコールの発行は `socket` モジュールが行い、ここではまとめる範囲の決定と、
//! GRO で結合されたデータグラムの分割だけを扱う。プラットフォームに依存しないため
//! Linux / Android 以外でもテストできる。

use std::net::SocketAddr;

use tobi_core::connection::EcnCodepoint;

use crate::config::UdpBatchConfig;

/// このプラットフォームで `sendmmsg` / `recvmmsg` / GSO / GRO が使えるか
///
/// macOS / iOS には同等の機能がない。設定で有効にしても単に従来の
/// 1 データグラム 1 システムコールになるだけだが、呼び出し側で無効化して
/// 無駄な分岐を避けるために公開する。
pub const SUPPORTED: bool = cfg!(any(target_os = "linux", target_os = "android"));

/// 送信 1 件分のまとめ判定に使うメタデータ
///
/// データ本体は含まない。同じキーの送信は 1 回のシステムコールにまとめられる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendKey {
    /// 送信に使うソケットの識別子
    ///
    /// `Arc<UdpSocket>` のポインタ値を渡す。プールがソケットを保持している間は
    /// アドレスが変わらないため、同一性の判定に使える。
    ///
    /// 同じ `SocketPool` のソケットでも、アドレスファミリが違えば別のソケットに
    /// なるため、まとめ判定にはソケットの同一性が要る。
    pub socket_id: usize,
    /// 送信元アドレス (pktinfo で指定する)
    pub local: SocketAddr,
    /// 宛先アドレス
    pub remote: SocketAddr,
    /// 送信するデータグラムの ECN コードポイント
    pub ecn: EcnCodepoint,
    /// 送信するデータグラムの長さ
    pub len: usize,
}

impl SendKey {
    /// `sendmmsg` で 1 つの呼び出しにまとめられるか
    ///
    /// 長さは問わない。`sendmmsg` はデータグラムごとに独立した `iov` を取る。
    fn same_endpoint(&self, other: &Self) -> bool {
        self.socket_id == other.socket_id
            && self.local == other.local
            && self.remote == other.remote
            && self.ecn == other.ecn
    }
}

/// まとめて送る範囲と、GSO を使うかどうか
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchPlan {
    /// まとめるデータグラム数
    ///
    /// 先頭の送信を含む件数であり、1 以上になる。キーが空のときだけ 0 を返す。
    pub count: usize,
    /// GSO で 1 つのデータグラムに連結して送るか
    ///
    /// `true` のときは `count` 件すべてが同じ長さであることが保証される。
    pub gso: bool,
}

impl BatchPlan {
    /// 1 件だけ送る計画
    const SINGLE: Self = Self {
        count: 1,
        gso: false,
    };
}

/// 先頭の送信から何件をまとめて送れるかを決める
///
/// GSO は同一サイズのセグメントのみを扱えるため、長さが異なるデータグラムが
/// 現れた時点で GSO の対象から外す (`sendmmsg` では引き続きまとめられる)。
/// `max_gso_bytes` は 1 データグラムの長さになるため、セグメント数で上限を決める。
pub fn plan_batch(keys: &[SendKey], config: &UdpBatchConfig) -> BatchPlan {
    let Some(head) = keys.first() else {
        return BatchPlan {
            count: 0,
            gso: false,
        };
    };
    if !config.is_enabled() {
        return BatchPlan::SINGLE;
    }

    // 同じソケット・4-tuple・ECN が連続する範囲を調べる
    let max_datagrams = config.max_datagrams.max(1);
    let mut run = 1;
    while run < keys.len() && run < max_datagrams && keys[run].same_endpoint(head) {
        run += 1;
    }

    if config.offload && head.len > 0 {
        // GSO は同一長のセグメントだけを扱える
        let same_len = keys[..run].iter().all(|k| k.len == head.len);
        if same_len {
            let max_segments = config.max_gso_bytes / head.len;
            let count = run.min(max_segments);
            if count >= 2 {
                return BatchPlan { count, gso: true };
            }
        }
    }

    if config.syscalls && run >= 2 {
        return BatchPlan {
            count: run,
            gso: false,
        };
    }
    BatchPlan::SINGLE
}

/// GRO のセグメントサイズで分割が必要かを判定し、分割の単位長を返す
///
/// セグメントサイズが未知 (`None`)、0、データグラム長以上であれば分割は不要で
/// ある。cmsg の値が 0 になる場合は `socket::decode_gro_segment_size` が `None` に
/// 落とすため、ここには正の値だけが渡る。
pub fn gro_segment_split_size(data_len: usize, segment_size: Option<usize>) -> Option<usize> {
    segment_size.filter(|size| *size > 0 && *size < data_len)
}
