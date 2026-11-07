// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Version Negotiation パケットのエンコード/デコードと応答生成 (RFC 9000 Section 17.2.1)
//!
//! Version Negotiation パケットは特定のバージョンに依存しない形式を持つ。
//! サーバーは未対応バージョンの Initial を受信したときにこのパケットを返し、
//! クライアントは受信したバージョン一覧から再試行するバージョンを選ぶ。

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::connection_id::MAX_CID_LENGTH;
use crate::error::Error;

/// Version Negotiation パケットを識別する Version フィールドの値
/// (RFC 9000 Section 17.2.1)
pub const VERSION_NEGOTIATION_VERSION: u32 = 0;

/// Initial パケットを含むデータグラムの最小長 (RFC 9000 Section 14.1)
///
/// サーバーはこれより小さい未対応バージョンのパケットを破棄する
/// (RFC 9000 Section 5.2.2)。
pub const MIN_INITIAL_DATAGRAM_SIZE: usize = crate::path::mtu::BASE_MTU as usize;

/// Version Negotiation パケットのデコード結果
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionNegotiation {
    /// 宛先 Connection ID (受信側の SCID をエコーした値)
    pub dcid: Vec<u8>,
    /// 送信元 Connection ID (受信側の DCID をエコーした値)
    pub scid: Vec<u8>,
    /// サーバーがサポートするバージョンの一覧
    pub versions: Vec<u32>,
}

impl VersionNegotiation {
    /// バッファから Version Negotiation パケットをデコードする
    ///
    /// Version フィールドが 0 でない場合や、バージョン一覧が 4 バイト単位で
    /// ない場合はエラーを返す。末尾に余分なバイトがある場合もエラーとする
    /// (Version Negotiation パケットは UDP データグラム全体を占める)。
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 7 {
            return Err(Error::Incomplete {
                needed: 7 - buf.len(),
            });
        }
        // 先頭ビットが 0 の場合は Short Header であり Version Negotiation ではない
        if buf[0] & 0x80 == 0 {
            return Err(Error::InvalidData(
                "expected long header for version negotiation packet".to_string(),
            ));
        }
        let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        if version != VERSION_NEGOTIATION_VERSION {
            return Err(Error::InvalidData(format!(
                "version negotiation packet must have version 0, got {version:#010x}"
            )));
        }

        // 未使用ビット (7 bit) の値は無視する (RFC 9000 Section 17.2.1)
        let dcid_len = buf[5] as usize;
        // RFC 9000 Section 17.2: Connection ID の長さは 0..=20 である。
        // Version Negotiation もこの上限を超えてはならない。
        if dcid_len > MAX_CID_LENGTH {
            return Err(Error::InvalidData(format!(
                "version negotiation DCID length {dcid_len} exceeds maximum {MAX_CID_LENGTH}"
            )));
        }
        let dcid_end = 6 + dcid_len;
        if buf.len() < dcid_end + 1 {
            return Err(Error::Incomplete {
                needed: dcid_end + 1 - buf.len(),
            });
        }
        let dcid = buf[6..dcid_end].to_vec();
        let scid_len = buf[dcid_end] as usize;
        if scid_len > MAX_CID_LENGTH {
            return Err(Error::InvalidData(format!(
                "version negotiation SCID length {scid_len} exceeds maximum {MAX_CID_LENGTH}"
            )));
        }
        let scid_start = dcid_end + 1;
        let scid_end = scid_start + scid_len;
        if buf.len() < scid_end {
            return Err(Error::Incomplete {
                needed: scid_end - buf.len(),
            });
        }
        let scid = buf[scid_start..scid_end].to_vec();

        let versions_bytes = &buf[scid_end..];
        if !versions_bytes.len().is_multiple_of(4) {
            return Err(Error::InvalidData(
                "supported version list length is not a multiple of 4".to_string(),
            ));
        }
        let mut versions = Vec::new();
        for chunk in versions_bytes.chunks_exact(4) {
            versions.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }

        Ok(Self {
            dcid,
            scid,
            versions,
        })
    }

    /// Version Negotiation パケットをエンコードする
    ///
    /// 未使用ビットは RFC 9000 Section 17.2.1 の SHOULD に従い、
    /// Fixed Bit に見えるよう 0x40 を立てる。
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header Form (1) = 1, Unused (7) は 0x40 を立てる
        buf.push(0x80 | 0x40);
        buf.extend_from_slice(&VERSION_NEGOTIATION_VERSION.to_be_bytes());
        buf.push(self.dcid.len() as u8);
        buf.extend_from_slice(&self.dcid);
        buf.push(self.scid.len() as u8);
        buf.extend_from_slice(&self.scid);
        for version in &self.versions {
            buf.extend_from_slice(&version.to_be_bytes());
        }
        buf
    }
}

/// 未対応バージョンのパケットに対する Version Negotiation 応答を生成する
///
/// `packet` は受信した UDP データグラム全体を渡す。以下の場合は応答しない
/// (`None` を返す)。
///
/// - Version Negotiation パケット (Version が 0) への応答
///   (RFC 9000 Section 6.1 MUST NOT)
/// - データグラムが 1200 バイト未満の場合
///   (RFC 9000 Section 5.2.2: サーバーは小さいパケットを破棄する)
/// - 既にサポート済みのバージョンの場合
/// - Long Header でない、またはヘッダが途中で切れている場合
///
/// Version Negotiation パケットの DCID には受信パケットの SCID を、
/// SCID には受信パケットの DCID をそのままコピーする
/// (RFC 9000 Section 17.2.1 MUST)。
pub fn build_response(packet: &[u8], supported_versions: &[u32]) -> Option<Vec<u8>> {
    // RFC 9000 Section 5.2.2: サーバーは未対応バージョンの小さいパケットを破棄する
    if packet.len() < MIN_INITIAL_DATAGRAM_SIZE {
        return None;
    }
    if packet.len() < 7 || packet[0] & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
    // Version Negotiation に応答してはならない (RFC 9000 Section 6.1)
    if version == VERSION_NEGOTIATION_VERSION {
        return None;
    }
    // サポート済みバージョンなら VN ではなく通常のハンドシェイクで処理する
    if supported_versions.contains(&version) {
        return None;
    }

    // 未対応バージョンでも Connection ID の配置は Long Header の不変部分
    // (RFC 8999 Section 5) なので、DCID / SCID はそのまま読み取れる。
    let dcid_len = packet[5] as usize;
    // RFC 9000 Section 17.2: Connection ID の長さは 0..=20 である。
    // 不正な長さのパケットには Version Negotiation を返さない。
    if dcid_len > MAX_CID_LENGTH {
        return None;
    }
    let dcid_end = 6 + dcid_len;
    if packet.len() < dcid_end + 1 {
        return None;
    }
    let dcid = packet[6..dcid_end].to_vec();
    let scid_len = packet[dcid_end] as usize;
    if scid_len > MAX_CID_LENGTH {
        return None;
    }
    let scid_start = dcid_end + 1;
    let scid_end = scid_start + scid_len;
    if packet.len() < scid_end {
        return None;
    }
    let scid = packet[scid_start..scid_end].to_vec();

    // 応答の DCID は受信パケットの SCID、SCID は受信パケットの DCID
    let response = VersionNegotiation {
        dcid: scid,
        scid: dcid,
        versions: supported_versions.to_vec(),
    };
    Some(response.encode())
}

/// サーバーが提示したバージョン一覧からクライアントの対応バージョンを選ぶ
///
/// `supported` の順序をクライアントの優先順として扱う。予約バージョン
/// (0x?a?a?a?a) など未知のバージョンは `supported` に含まれないため、
/// 一覧にあっても無視される (RFC 9000 Section 6.3)。
pub fn select_compatible_version(offered: &[u32], supported: &[u32]) -> Option<u32> {
    supported
        .iter()
        .copied()
        .find(|version| offered.contains(version))
}

/// 予約バージョン (0x?a?a?a?a) かを返す (RFC 9000 Section 15)
pub const fn is_reserved_version(version: u32) -> bool {
    version & 0x0f0f_0f0f == 0x0a0a_0a0a
}
