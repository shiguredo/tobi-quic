// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! version_information トランスポートパラメータの検証 (RFC 9368 Section 4)
//!
//! 受信した Version Information が接続バージョンと一致するか、VN に反応して
//! 開始した接続試行でダウングレード攻撃を示す不整合が無いかを検証する。
//! 検証結果は QUIC の接続クローズにそのまま使える `Error::Protocol` で返す。

use alloc::format;
use alloc::vec::Vec;

use crate::error::{Error, TransportErrorCode};
use crate::packet::version_negotiation::select_compatible_version;
use crate::packet::{QUIC_VERSION_1, QUIC_VERSION_2};
use crate::role::Role;
use crate::transport_params::VersionInformation;

/// 受信した Version Information を検証する (RFC 9368 Section 4)
///
/// - `role`: 検証する endpoint のロール
/// - `version`: この接続で使用しているバージョン (サーバーは Initial で受信した
///   バージョン、クライアントは接続試行で使っているバージョン)
/// - `vn_retry`: VN に反応して開始した接続試行か (RFC 9368 Section 4 MUST)
/// - `local`: 自分が送信した Version Information (未送信なら `None`)
/// - `peer`: ピアから受信した Version Information (未送信なら `None`)
/// - `supported_versions`: クライアントの対応バージョン一覧 (優先順)。
///   クライアントの VN 提示一覧との整合検証に使う。
///
/// VN に反応した接続試行でサーバーの Version Information が欠落している場合や、
/// ダウングレード攻撃を示す Available Versions の不整合は
/// `VERSION_NEGOTIATION_ERROR` で接続を閉じる。サーバーがクライアントの
/// Chosen Version を Available Versions に含めない場合は、RFC 9368 Section 4 の
/// 解析失敗として `TRANSPORT_PARAMETER_ERROR` で閉じる。
pub fn validate_peer_version_information(
    role: Role,
    version: u32,
    vn_retry: bool,
    local: Option<&VersionInformation>,
    peer: Option<&VersionInformation>,
    supported_versions: &[u32],
) -> Result<(), Error> {
    let Some(peer) = peer else {
        // RFC 9368 Section 4: サーバーは Version Information が欠落していても
        // ハンドシェイクを完了してよい。クライアントは VN に反応した接続試行で
        // 欠落していれば VERSION_NEGOTIATION_ERROR で閉じなければならない。
        if role == Role::Client && vn_retry {
            return Err(version_negotiation_error(
                "missing version_information after version negotiation",
            ));
        }
        return Ok(());
    };

    match role {
        Role::Server => {
            // RFC 9368 Section 4: サーバーはクライアントの Chosen Version が
            // 接続で使用しているバージョンと一致することを検証する (MUST)。
            if peer.chosen_version != version {
                return Err(version_negotiation_error(&format!(
                    "client chosen version {:#010x} does not match connection version {:#010x}",
                    peer.chosen_version, version
                )));
            }
            // RFC 9368 Section 4: クライアントの Chosen Version が Available
            // Versions に含まれない場合は解析失敗とする (MUST)。
            if !peer.available_versions.contains(&peer.chosen_version) {
                return Err(Error::Protocol {
                    code: TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                    reason: format!(
                        "client chosen version {:#010x} is not included in its available versions",
                        peer.chosen_version
                    ),
                });
            }
        }
        Role::Client => {
            // RFC 9368 Section 4: クライアントはサーバーの Chosen Version が
            // 接続で使用している (交渉済みの) バージョンと一致することを
            // 検証する (MUST)。バージョン切り替えに対応していないため、
            // 接続バージョンと異なる値は不整合として扱う。
            if peer.chosen_version != version {
                return Err(version_negotiation_error(&format!(
                    "server chosen version {:#010x} does not match negotiated version {:#010x}",
                    peer.chosen_version, version
                )));
            }
            // RFC 9368 Section 4: サーバーの Chosen Version はクライアントが
            // Available Versions として送ったバージョンでなければならない。
            let offered_versions: Vec<u32> = match local {
                Some(local) => local.available_versions.clone(),
                // Version Information を送っていない場合は、クライアントの
                // 対応バージョン一覧を代わりに使う。
                None => supported_versions.to_vec(),
            };
            if !offered_versions.contains(&peer.chosen_version) {
                return Err(version_negotiation_error(&format!(
                    "server chosen version {:#010x} was not offered by the client",
                    peer.chosen_version
                )));
            }
            if vn_retry {
                // RFC 9368 Section 4: VN に反応した接続試行では、サーバーの
                // Available Versions が空なら VERSION_NEGOTIATION_ERROR (MUST)。
                if peer.available_versions.is_empty() {
                    return Err(version_negotiation_error(
                        "server available versions are empty after version negotiation",
                    ));
                }
                // RFC 9368 Section 4: サーバーが提示したバージョン一覧に
                // 交渉済みバージョンを加えた一覧を使って、クライアントが
                // 同じバージョンを選ぶか再計算する。異なる場合はダウングレード
                // 攻撃の可能性があるため VERSION_NEGOTIATION_ERROR (MUST)。
                let mut offered = peer.available_versions.clone();
                if !offered.contains(&version) {
                    offered.push(version);
                }
                let selected = select_compatible_version(&offered, supported_versions);
                if selected != Some(version) {
                    return Err(version_negotiation_error(&format!(
                        "version negotiation downgrade detected: would have selected {selected:?} instead of {version:#010x}"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// VERSION_NEGOTIATION_ERROR のプロトコルエラーを構築する
fn version_negotiation_error(reason: &str) -> Error {
    Error::Protocol {
        code: TransportErrorCode::VERSION_NEGOTIATION_ERROR,
        reason: format!("version information validation failed: {reason}"),
    }
}

/// バージョン A がバージョン B と互換かを返す (RFC 9368 Section 2.2)
///
/// QUIC v1 と v2 は相互に互換である (RFC 9369 Section 4)。同一バージョンも
/// 互換として扱う。それ以外の組み合わせは互換でない。
pub fn is_compatible_version(a: u32, b: u32) -> bool {
    a == b
        || matches!(
            (a, b),
            (QUIC_VERSION_1, QUIC_VERSION_2) | (QUIC_VERSION_2, QUIC_VERSION_1)
        )
}

/// サーバーが互換バージョン交渉で選択するバージョンを返す (RFC 9368 Section 2.3)
///
/// クライアントの Available Versions のうち、サーバーが対応し、かつクライアントの
/// Chosen Version と互換なものを、サーバーの優先順 (`server_preference`) で選ぶ。
/// 該当が無い場合は `None`。Chosen Version 自身も選択対象に含む。
///
/// 予約バージョン (0x?a?a?a?a) はサーバーの対応一覧に含まれないため、
/// 自然に選択対象から外れる (RFC 9368 Section 3)。
pub fn select_server_negotiated_version(
    client: &VersionInformation,
    server_versions: &[u32],
    server_preference: &[u32],
) -> Option<u32> {
    server_preference.iter().copied().find(|candidate| {
        server_versions.contains(candidate)
            && client.available_versions.contains(candidate)
            && is_compatible_version(client.chosen_version, *candidate)
    })
}
