// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! IP_PKTINFO を利用した sendmsg/recvmsg ラッパー
//!
//! 同一アドレスファミリ内のパスは 1 本のソケットで扱い、Multipath QUIC の
//! パスごとに異なるローカル IP を sendmsg の cmsg で指定する。追加パス /
//! 移行で利用者が送信元ポートまで指定した場合だけ、そのアドレス専用の
//! ソケットを追加する。recvmsg の cmsg で受信先 IP を取得する。
//!
//! ECN はソケット単位の `setsockopt` ではなく、データグラムごとに sendmsg /
//! sendmmsg / GSO の cmsg で指定する。ソケットを複数の接続が共有しても、
//! あるデータグラムの送信待ちが別の接続の ECN で上書きされることはない。
//!
//! Linux / Android: IP_PKTINFO (IPv4) / IPV6_PKTINFO (IPv6)
//! macOS / iOS: IP_PKTINFO (送信) + IP_RECVDSTADDR (受信, IPv4) / IPV6_PKTINFO (IPv6)
//!
//! Android は Linux カーネル、iOS は macOS と同じ Darwin カーネルを使うため、
//! IPv4 の pktinfo はそれぞれ Linux / macOS と同じ扱いにする。ここを
//! `target_os = "linux"` / `target_os = "macos"` だけで分岐していると、
//! モバイルでは IPv4 の pktinfo が有効化されずマルチパスが成立しない。

use std::io;
use std::mem::{self, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::AsRawFd;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use socket2::{MaybeUninitSlice, MsgHdr, MsgHdrMut, SockAddr, SockRef};
use tobi_core::connection::EcnCodepoint;
use tokio::net::UdpSocket;

use crate::config::UdpBatchConfig;

/// 受信したデータグラム
///
/// 受信タスクから接続の処理ループへチャネルで渡すため、データ本体を所有する。
/// 受信ごとに 1 回のアロケーションが発生するが、QUIC の 1 データグラムは
/// 最大でも数 KB であり、コピーを避けるために受信バッファを共有するより
/// 構造が単純になることを優先する。
pub struct ReceivedDatagram {
    /// 受信データ
    pub data: Vec<u8>,
    /// 送信元アドレス
    pub remote: SocketAddr,
    /// 受信先アドレス (pktinfo の宛先 IP と受信ソケットのポート)
    ///
    /// パスごとに別のソケットで受信しうるため、ポートまで含めて返す。
    /// `Connection::receive` に渡すローカルアドレスはパスの 4-tuple と
    /// 一致している必要がある。IPv6 の link-local アドレスでは、pktinfo の
    /// 受信インターフェースを scope ID として含む。
    pub local_addr: SocketAddr,
    /// 受信パケットの ECN コードポイント (RFC 3168)
    ///
    /// `IP_RECVTOS` / `IPV6_RECVTCLASS` の cmsg から取得する。cmsg が無い場合や
    /// 取得できない場合は `NotEct` とする。
    pub ecn: EcnCodepoint,
    /// GRO で結合されたデータグラムのセグメントサイズ
    ///
    /// `UDP_GRO` を有効にしたソケット (Linux / Android) で、カーネルが複数の
    /// データグラムを 1 つに結合して返した場合に、その 1 セグメントの長さが入る。
    /// 結合されていない場合や GRO を使わない場合は `None` になる。
    pub segment_size: Option<usize>,
}

/// ソケットプール内でソケットを一意に識別する ID
///
/// アドレスや Vec の添字は削除後の再登録で再利用され得るため、識別子として
/// 使わない。プールへの登録ごとに新しい ID を払い出す。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketId(u64);

impl SocketId {
    /// 初期ソケットの ID
    pub const PRIMARY: Self = Self(0);

    /// 生の値を返す
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// データグラム 1 件の受信領域の長さ
///
/// 受信バッファの長さ。`UDP_GRO` で結合されたデータグラムも収まる必要がある。
///
/// UDP のデータグラムは 65507 バイト (IPv4 の UDP ペイロード上限) を超えない。
/// `UDP_GRO` を有効にするとカーネルは同じ 4-tuple のデータグラムを最大 64 個まで
/// 結合するが、カーネルの GRO 処理 (`skb_gro_receive_list`) は
/// `p->len + skb->len >= 65536` で結合を拒否するため、受け取る長さは 65536 未満に
/// 収まる。切り捨てが起きた場合は `MSG_TRUNC` を見て捨てる (下記 `try_recvmsg`)。
const MAX_DATAGRAM_SIZE: usize = 65536;

/// 受信タスクが所有して使い回す受信バッファ
///
/// 受信のたびに 64 KiB を確保するとピアの送信量に比例してアロケーションが
/// 増える。受信タスクが 1 つ保持して `recvmsg` に渡し、受信したデータは
/// 長さに合わせて複製して [`ReceivedDatagram`] として渡す。
pub struct RecvBuffer {
    /// データグラムの受信領域
    data: Vec<u8>,
    /// cmsg の受信領域
    ///
    /// `cmsghdr` は 8 バイト (32-bit では 4 バイト) のアラインメントを要求する。
    /// `Vec<u8>` / `Vec<MaybeUninit<u8>>` のアラインメントは 1 であり、
    /// `CMSG_FIRSTHDR` が返す `cmsghdr` を読むときに未定義動作になり得るため、
    /// `u64` の配列として確保してアラインメントを保証する。
    cmsg: Vec<u64>,
}

impl RecvBuffer {
    /// 最大長のデータグラムを受け取れる受信バッファを作る
    ///
    /// データ用に 64 KiB、制御メッセージ用に `CMSG_RECV_BUF_SIZE` バイトを
    /// `u64` 単位で切り上げて確保する。
    pub fn new() -> Self {
        Self {
            data: vec![0u8; MAX_DATAGRAM_SIZE],
            cmsg: vec![0u64; CMSG_RECV_BUF_WORDS],
        }
    }
}

impl Default for RecvBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// --- cmsg バッファサイズ ---

// IPv4 pktinfo の cmsg サイズ
const CMSG_SPACE_PKTINFO_V4: usize =
    unsafe { libc::CMSG_SPACE(mem::size_of::<libc::in_pktinfo>() as u32) as usize };

// IPv6 pktinfo の cmsg サイズ
const CMSG_SPACE_PKTINFO_V6: usize =
    unsafe { libc::CMSG_SPACE(mem::size_of::<libc::in6_pktinfo>() as u32) as usize };

// macOS / iOS の IP_RECVDSTADDR で返る in_addr の cmsg サイズ
#[cfg(any(target_os = "macos", target_os = "ios"))]
const CMSG_SPACE_RECVDSTADDR: usize =
    unsafe { libc::CMSG_SPACE(mem::size_of::<libc::in_addr>() as u32) as usize };

// 受信 ECN の cmsg サイズ
//
// 受信の IPv4 は `u8`、IPv6 は `int` で返るため、ファミリごとに大きさが違う。
// 送信の payload はどちらも `int` であり、この定数を受信バッファと送信バッファで
// 兼用してはならない (送信側は `CMSG_SPACE_SEND_ECN` を使う)。
const CMSG_SPACE_TOS_V4: usize = unsafe { libc::CMSG_SPACE(mem::size_of::<u8>() as u32) as usize };
const CMSG_SPACE_TCLASS_V6: usize =
    unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as u32) as usize };

// 受信用 cmsg バッファサイズ
//
// 1 つのデータグラムに対して複数の cmsg (宛先 IP と ECN) が返るため、
// 最大値ではなく合計を確保する。合計が不足するとカーネルが後続の cmsg を
// 切り捨て、ECN が観測できなくなる。
const CMSG_RECV_BUF_SIZE: usize = {
    // IPv6 ソケットは IPV6_PKTINFO + IPV6_TCLASS
    let mut total = CMSG_SPACE_PKTINFO_V6 + CMSG_SPACE_TCLASS_V6;
    // IPv4 ソケットは (Linux / Android: IP_PKTINFO |
    // macOS / iOS: IP_PKTINFO + IP_RECVDSTADDR) + IP_RECVTOS
    total += CMSG_SPACE_PKTINFO_V4 + CMSG_SPACE_TOS_V4;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        total += CMSG_SPACE_RECVDSTADDR;
    }
    total
};

/// cmsg 受信領域を `u64` 何個で確保するか
///
/// `cmsghdr` のアラインメントを満たすため、バイト数ではなく `u64` 単位で
/// 切り上げて確保する。
const CMSG_RECV_BUF_WORDS: usize = CMSG_RECV_BUF_SIZE.div_ceil(mem::size_of::<u64>());

/// cmsg 領域を `MaybeUninit<u8>` のスライスとして返す
///
/// `MsgHdrMut::with_control` は `&mut [MaybeUninit<u8>]` を要求する。
/// `u64` の配列は `MaybeUninit<u8>` としても有効な領域であり、
/// `cmsghdr` が要求するアラインメントを満たす。
fn cmsg_bytes_mut(cmsg: &mut [u64]) -> &mut [MaybeUninit<u8>] {
    // SAFETY: u64 の配列は MaybeUninit<u8> と同じサイズの領域を持ち、
    // MaybeUninit<u8> のアラインメント (1) を満たす。u64 のアラインメントは
    // cmsghdr の要求以上である。
    unsafe {
        std::slice::from_raw_parts_mut(
            cmsg.as_mut_ptr() as *mut MaybeUninit<u8>,
            std::mem::size_of_val(cmsg),
        )
    }
}

// --- ソケット設定 ---

/// setsockopt を呼ぶヘルパー
fn setsockopt_int(
    fd: i32,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const _ as *const libc::c_void,
            mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// ソケットに pktinfo を有効化する
///
/// これにより recvmsg で受信パケットの宛先 IP を取得でき、
/// sendmsg で送信元 IP を指定できるようになる。
pub fn enable_pktinfo(socket: &UdpSocket) -> io::Result<()> {
    let fd = SockRef::from(socket).as_raw_fd();
    enable_pktinfo_fd(fd)
}

/// socket2 の Socket に対して pktinfo を有効化する (tokio 変換前用)
pub fn enable_pktinfo_raw(socket: &socket2::Socket) -> io::Result<()> {
    enable_pktinfo_fd(socket.as_raw_fd())
}

fn enable_pktinfo_fd(fd: i32) -> io::Result<()> {
    // IPv4 オプションは AF_INET6 ソケットでは EINVAL になるため、
    // ソケットのアドレスファミリを見て必要な側だけを設定する。
    // 両方を無条件に設定すると、片方が必ず失敗して有効化全体が失敗する。
    let is_ipv6 = is_ipv6_socket(fd)?;

    if is_ipv6 {
        // IPv6: IPV6_PKTINFO を有効化して宛先 IP の受信と送信元 IP の指定を行う
        // (全プラットフォーム共通)
        setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1)?;
        // IPv6: 受信パケットの Traffic Class を cmsg で受け取る
        setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, 1)?;
    } else {
        // Linux / Android: IP_PKTINFO で送受信両方をカバーする
        // macOS / iOS: IP_PKTINFO (送信用) + IP_RECVDSTADDR (受信用) が必要
        #[cfg(any(target_os = "linux", target_os = "android"))]
        setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1)?;

        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1)?;
            setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_RECVDSTADDR, 1)?;
        }

        // IPv4: 受信パケットの TOS を cmsg で受け取る (全プラットフォーム共通)
        setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_RECVTOS, 1)?;
    }

    Ok(())
}

/// DPLPMTUD のプローブ向けに MTU 探索の socket option を設定する
///
/// RFC 8899 Section 3 は PLPMTU より大きいプローブの送信を求め、Section 4.5 は
/// カーネルによる経路 MTU の強制を止めることを求める。
///
/// - Linux / Android: `IP_PMTUDISC_PROBE` / `IPV6_PMTUDISC_PROBE` が DF を立てつつ
///   経路 MTU を無視する。`IP_PMTUDISC_DO` は経路 MTU を超えるデータグラムを
///   `EMSGSIZE` で拒否するためプローブが送れない。
/// - macOS / iOS: IPv4 の `IP_DONTFRAG` を設定する。IPv6 は相当する option を
///   libc が定義していないため設定しない (IPv6 は元々ルータがフラグメントしない)。
fn enable_mtu_discovery_probe(fd: i32, ipv6: bool) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if ipv6 {
            setsockopt_int(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                libc::IPV6_PMTUDISC_PROBE,
            )?;
        } else {
            setsockopt_int(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                libc::IP_PMTUDISC_PROBE,
            )?;
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        if !ipv6 {
            setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_DONTFRAG, 1)?;
        }
    }

    // 上記以外のターゲットでは何もしない
    let _ = (fd, ipv6);
    Ok(())
}

/// 受信側の GRO (`UDP_GRO`) を有効化する (Linux / Android)
///
/// 有効にすると、カーネルが同じ 4-tuple のデータグラムを結合して返すようになり、
/// セグメントサイズが `recvmsg` の cmsg で通知される。macOS / iOS には同等の
/// 機能がないため何もしない。
///
/// カーネルが対応していない場合は `setsockopt` が失敗する。設定で明示的に
/// 有効化した場合だけ呼ぶため、失敗は呼び出し元 (ソケット作成) のエラーにする。
fn enable_rx_offload(fd: i32) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    setsockopt_int(fd, libc::SOL_UDP, libc::UDP_GRO, 1)?;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = fd;
    Ok(())
}

/// ソケットのアドレスファミリが AF_INET6 かどうかを返す
///
/// `getsockname` で得た `sockaddr_storage` の `ss_family` を見る。
/// `SO_DOMAIN` は macOS で未対応のため、バインド済みソケットに対して
/// 確実に動く `getsockname` を使う。
fn is_ipv6_socket(fd: i32) -> io::Result<bool> {
    // SAFETY: storage は有効な領域で、getsockname が sockaddr を書き込む。
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockname(
            fd,
            &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(storage.ss_family as libc::c_int == libc::AF_INET6)
}

// --- 送信 ---

/// 送信に使う送信元 IP を決める
///
/// `local` の IP が unspecified (0.0.0.0 / ::) の場合はソケット自身の
/// バインドアドレスを使う。
/// 送信に使う送信元 IP と scope ID を決める
///
/// `local` の IP が unspecified でなければその IP を使い、unspecified なら
/// ソケットの bind 済みアドレスを使う。返り値の scope ID は IPv6 の
/// link-local アドレスでだけ非 0 になり、`IPV6_PKTINFO.ipi6_ifindex` に設定する。
fn resolve_local_ip(socket: &UdpSocket, local: SocketAddr) -> (IpAddr, u32) {
    // link-local アドレスでは scope ID を保持する。ワイルドカードで共有した
    // ソケットでは、カーネルが scope ID から出力インターフェースを決める
    // (RFC 4007 Section 6)。
    let scope_id = match local {
        SocketAddr::V6(v6) if v6.ip().is_unicast_link_local() => v6.scope_id(),
        _ => 0,
    };
    let link_local = matches!(local, SocketAddr::V6(v6) if v6.ip().is_unicast_link_local());
    if !local.ip().is_unspecified() {
        // bind 済みの link-local の scope を、scope 未指定の送信元で補完する
        if link_local
            && scope_id == 0
            && let Ok(SocketAddr::V6(bound)) = socket.local_addr()
            && bound.ip().is_unicast_link_local()
        {
            return (local.ip(), bound.scope_id());
        }
        return (local.ip(), scope_id);
    }
    match socket.local_addr() {
        Ok(bound) => {
            let bound_scope = match bound {
                SocketAddr::V6(v6) if v6.ip().is_unicast_link_local() => v6.scope_id(),
                _ => 0,
            };
            (bound.ip(), bound_scope)
        }
        Err(_) => (local.ip(), scope_id),
    }
}

/// ソケットのファミリに合わせて宛先アドレスの形式を整える
///
/// IPv6 ソケットから IPv4 宛に送るには v4-mapped 形式が必要。
/// IPv4 ソケットに IPv6 宛を渡すことはできない (呼び出し側の誤り)。
fn normalize_remote(socket: &UdpSocket, remote: SocketAddr) -> SocketAddr {
    match (socket.local_addr().ok(), remote) {
        (Some(bound), SocketAddr::V4(v4)) if bound.is_ipv6() => SocketAddr::V6(
            std::net::SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0),
        ),
        (_, addr) => addr,
    }
}

/// ECN の cmsg に使うレベルと type を、データグラムの宛先アドレスから決める
///
/// cmsg のレベルと type はソケットのファミリではなく、送信するデータグラムの
/// 宛先で決まる。IPv6 ソケットから v4-mapped の宛先へ送る場合も、データグラム
/// としては IPv4 なので `IPPROTO_IP` / `IP_TOS` を使う。
fn send_ecn_cmsg_kind(remote: &SocketAddr) -> (libc::c_int, libc::c_int) {
    match remote.ip() {
        IpAddr::V6(addr) if addr.to_ipv4_mapped().is_none() => {
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
        }
        _ => (libc::IPPROTO_IP, libc::IP_TOS),
    }
}

/// 送信するデータグラムの ECN コードポイントを cmsg に追加する
///
/// 送信の cmsg の payload は `libc::c_int` (4 バイト) である。受信側の IPv4 が
/// `u8` を返すのとは非対称だが、送信側はカーネルが `int` として読む。
/// 設定する値は RFC 3168 Section 5 が定義する IP ヘッダの 2 bit の ECN フィールド
/// (Not-ECT / ECT(0) / ECT(1) / CE) であり、同節は送信側がパケットごとに
/// ECT コードポイントを選べるとしている。したがって cmsg は送信のたびに組み立てる。
fn push_ecn_cmsg(cmsg: &mut CmsgBuffer, remote: &SocketAddr, ecn: EcnCodepoint) {
    let (level, ty) = send_ecn_cmsg_kind(remote);
    let value = libc::c_int::from(ecn.to_bits());
    cmsg.push(level, ty, &value.to_ne_bytes());
}

/// pktinfo の cmsg に送信元 IP を追加する
///
/// Linux / Android と macOS / iOS はどちらも、送信の送信元指定に
/// `IP_PKTINFO` / `IPV6_PKTINFO` を使う。
///
/// `scope_id` は IPv6 の link-local アドレスで使う (RFC 4007 Section 6)。
/// 複数インターフェースが同一 link-local アドレスを持つ場合、出力
/// インターフェースは scope ID で決まるため、`ipi6_ifindex` に設定する。
fn push_pktinfo_cmsg(cmsg: &mut CmsgBuffer, local_ip: IpAddr, scope_id: u32) {
    match local_ip {
        IpAddr::V4(addr) => {
            let pktinfo = libc::in_pktinfo {
                ipi_ifindex: 0,
                ipi_spec_dst: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.octets()),
                },
                ipi_addr: libc::in_addr { s_addr: 0 },
            };
            // SAFETY: in_pktinfo は POD であり、初期化済みの値をバイト列として渡す
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &pktinfo as *const libc::in_pktinfo as *const u8,
                    mem::size_of::<libc::in_pktinfo>(),
                )
            };
            cmsg.push(libc::IPPROTO_IP, libc::IP_PKTINFO, bytes);
        }
        IpAddr::V6(addr) => {
            let pktinfo = libc::in6_pktinfo {
                ipi6_ifindex: scope_id,
                ipi6_addr: libc::in6_addr {
                    s6_addr: addr.octets(),
                },
            };
            // SAFETY: in6_pktinfo は POD であり、初期化済みの値をバイト列として渡す
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &pktinfo as *const libc::in6_pktinfo as *const u8,
                    mem::size_of::<libc::in6_pktinfo>(),
                )
            };
            cmsg.push(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, bytes);
        }
    }
}

/// 送信 1 回分の pktinfo と ECN の cmsg を組み立てる
///
/// `local_ip` が unspecified (0.0.0.0 / ::) の場合は pktinfo を付けず、
/// ECN の cmsg だけを付ける。`scope_id` は IPv6 の link-local アドレスで使う
/// 出力インターフェースの識別子であり、`IPV6_PKTINFO.ipi6_ifindex` に設定する。
/// 1 データグラム送信とバッチ送信で共用する。
fn build_send_cmsg(
    local_ip: IpAddr,
    scope_id: u32,
    remote: &SocketAddr,
    ecn: EcnCodepoint,
) -> CmsgBuffer {
    let mut cmsg = CmsgBuffer::new();
    if !local_ip.is_unspecified() {
        push_pktinfo_cmsg(&mut cmsg, local_ip, scope_id);
    }
    push_ecn_cmsg(&mut cmsg, remote, ecn);
    cmsg
}

/// `socket.writable().await` が実際に待機した回数 (テスト専用)
#[cfg(test)]
static WRITABLE_WAIT_COUNT: AtomicUsize = AtomicUsize::new(0);

/// 待機回数を使うテストを直列化するロック (テスト専用)
///
/// カウンタはプロセス全体で 1 つなので、複数のテストが並行して送信すると
/// 互いの待機回数が混ざる。カウンタを読むテストと、送信によってカウンタを
/// 増やすテストはこのロックを取得してから実行する。
#[cfg(test)]
static WAIT_COUNTER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// 待機回数を使うテスト用のロックを取得する
///
/// `client` モジュールのテストも送信でカウンタを増やし得るため、クレート内の
/// テストから使えるようにしている。
#[cfg(test)]
pub(crate) async fn lock_wait_counter() -> tokio::sync::MutexGuard<'static, ()> {
    WAIT_COUNTER_LOCK.lock().await
}

/// `socket.writable().await` が待機するかを判定して数える (テスト専用)
///
/// tokio の `try_io` は readiness が残っていなければ closure を呼ばずに
/// `WouldBlock` を返す。この性質を使い、`writable()` が実際に待つ場面だけを
/// 数える。closure が `Ok` を返す場合、`try_io` は readiness を消さないため、
/// この判定は後続の `writable().await` の待機有無に影響しない。ソケットの状態も
/// 変えない。
#[cfg(test)]
fn note_writable_wait(socket: &UdpSocket) {
    if socket
        .try_io(tokio::io::Interest::WRITABLE, || Ok::<(), io::Error>(()))
        .is_err()
    {
        WRITABLE_WAIT_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// テストから `writable().await` の待機回数を読む
#[cfg(test)]
fn writable_wait_count() -> usize {
    WRITABLE_WAIT_COUNT.load(Ordering::Relaxed)
}

/// テストで `writable().await` の待機回数を 0 に戻す
#[cfg(test)]
fn reset_writable_wait_count() {
    WRITABLE_WAIT_COUNT.store(0, Ordering::Relaxed);
}

/// ソケットが送信可能になるまで待つ
///
/// テストビルドでは、実際に待機が発生したかを数える。
async fn wait_writable(socket: &UdpSocket) -> io::Result<()> {
    #[cfg(test)]
    note_writable_wait(socket);
    socket.writable().await
}

/// sendmsg + pktinfo + ECN の cmsg でデータグラムを 1 つ送信する
///
/// `local` の IP が unspecified (0.0.0.0 / ::) の場合は pktinfo の cmsg を
/// 付けず、ECN の cmsg だけを付けた sendmsg で送る。IPv6 の link-local
/// アドレスでは、`local` の scope ID を `ipi6_ifindex` に設定する。`send_to` へ逃げると
/// ECN を指定できず、wildcard bind のソケットでマーキングが失われる。
/// 送信元 IP はその場合カーネルが選ぶ。
///
/// RFC 9000 Section 13.4 は、ECN を使う QUIC エンドポイントが IP ヘッダの
/// ECN フィールドに ECT コードポイントを設定すると定める。`ecn` はデータグラム
/// 単位で cmsg に設定し、ソケット単位の `IP_TOS` / `IPV6_TCLASS` は変更しない。
/// 同じソケットを共有する複数の接続が並行して送っても、送信待ちの間に他の接続の
/// ECN へ書き換えられないようにするためである。
pub async fn send_with_local_addr(
    socket: &UdpSocket,
    data: &[u8],
    remote: SocketAddr,
    local: SocketAddr,
    ecn: EcnCodepoint,
) -> io::Result<usize> {
    let (local_ip, scope_id) = resolve_local_ip(socket, local);
    let remote = normalize_remote(socket, remote);
    let remote_sockaddr = SockAddr::from(remote);

    // 送信元 IP を指定できない場合も pktinfo を省くだけで、ECN の cmsg は付ける。
    let cmsg = build_send_cmsg(local_ip, scope_id, &remote, ecn);

    loop {
        wait_writable(socket).await?;
        match socket.try_io(tokio::io::Interest::WRITABLE, || {
            let sock_ref = SockRef::from(socket);
            let iov = [io::IoSlice::new(data)];
            let msg = MsgHdr::new()
                .with_addr(&remote_sockaddr)
                .with_buffers(&iov)
                .with_control(cmsg.as_bytes());
            sock_ref.sendmsg(&msg, 0)
        }) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

// --- バッチ送信 (sendmmsg / GSO) ---

/// `UDP_SEGMENT` の cmsg サイズ
///
/// `UDP_SEGMENT` の payload はセグメントサイズを表す `u16` (2 バイト) である。
const CMSG_SPACE_SEGMENT: usize =
    unsafe { libc::CMSG_SPACE(mem::size_of::<u16>() as u32) as usize };

/// 送信 ECN の cmsg サイズ
///
/// 送信の payload は IPv4 (`IP_TOS`) / IPv6 (`IPV6_TCLASS`) ともカーネルが
/// `libc::c_int` (4 バイト) として読む。受信の IPv4 が `u8` を返すのとは
/// 非対称であるため、受信用の `CMSG_SPACE_TOS_V4` は流用できない。
const CMSG_SPACE_SEND_ECN: usize =
    unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as u32) as usize };

/// 送信 1 回分の cmsg を収める固定長領域のサイズ
///
/// pktinfo (IPv4 / IPv6 の大きい方) と ECN、GSO のセグメントサイズの
/// 合計を確保する。cmsg の追加はこの範囲に収まる前提であり、超えた場合は
/// 実装バグとして panic する。
const CMSG_SEND_BUF_SIZE: usize = {
    let pktinfo = if CMSG_SPACE_PKTINFO_V6 > CMSG_SPACE_PKTINFO_V4 {
        CMSG_SPACE_PKTINFO_V6
    } else {
        CMSG_SPACE_PKTINFO_V4
    };
    pktinfo + CMSG_SPACE_SEND_ECN + CMSG_SPACE_SEGMENT
};

/// `CMSG_SEND_BUF_SIZE` を `u64` 何個で確保するか
const CMSG_SEND_BUF_WORDS: usize = CMSG_SEND_BUF_SIZE.div_ceil(mem::size_of::<u64>());

/// cmsghdr を並べた制御バッファ
///
/// `Vec<u8>` は 1 バイトアラインメントのため `cmsghdr` を置けない。`u64` の
/// 固定長配列として確保し、バイト列としてカーネルへ渡す。`cmsghdr` が要求する
/// アラインメントは `align_of::<cmsghdr>()` に従う。`u64` の配列は
/// `cmsghdr` の要求 (64 ビットで 8 バイト、32 ビットで 4 バイト以上) を
/// 満たす。通常送信 (`sendmsg`) と、Linux / Android の
/// `sendmmsg` / GSO で共用する。
///
/// 送信のたびに `Vec` を確保しないよう、要素数は実際に付ける cmsg の
/// 最大サイズから決めた固定長にしている。
struct CmsgBuffer {
    /// cmsg を格納する領域
    words: [u64; CMSG_SEND_BUF_WORDS],
    /// 有効なバイト数
    len: usize,
}

impl CmsgBuffer {
    fn new() -> Self {
        Self {
            words: [0; CMSG_SEND_BUF_WORDS],
            len: 0,
        }
    }

    /// cmsg を 1 つ追加する
    ///
    /// カーネルが読む `cmsghdr` とそのデータを、`CMSG_SPACE` の間隔で並べる。
    /// 追加のたびに次の `cmsghdr` のアラインメントまで詰め物をする。
    fn push(&mut self, level: libc::c_int, ty: libc::c_int, payload: &[u8]) {
        let align = mem::align_of::<libc::cmsghdr>();
        let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
        let data_len = unsafe { libc::CMSG_LEN(payload.len() as u32) } as usize;
        let space = unsafe { libc::CMSG_SPACE(payload.len() as u32) } as usize;

        self.len = self.len.div_ceil(align) * align;
        let need = self.len + space;
        // 固定長バッファの容量は付ける cmsg の最大サイズから決めている。
        // ここに来る追加はその範囲に収まる想定であり、超えたら実装バグである。
        assert!(
            need <= self.words.len() * mem::size_of::<u64>(),
            "cmsg buffer overflow: need {need} bytes"
        );

        // SAFETY: words は cmsghdr のアラインメントを満たし、need バイト以上ある。
        // payload は data_len - header_len バイトの領域に収まる。
        unsafe {
            let base = self.words.as_mut_ptr() as *mut u8;
            let hdr = base.add(self.len) as *mut libc::cmsghdr;
            (*hdr).cmsg_len = data_len as _;
            (*hdr).cmsg_level = level;
            (*hdr).cmsg_type = ty;
            std::ptr::copy_nonoverlapping(
                payload.as_ptr(),
                base.add(self.len + header_len),
                payload.len(),
            );
        }
        self.len += space;
    }

    /// Linux / Android の `sendmmsg` / GSO が制御バッファを指すために使う
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn as_ptr(&self) -> *mut libc::c_void {
        self.words.as_ptr() as *mut libc::c_void
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: words は初期化済みで、len は words が確保したバイト数以内
        unsafe { std::slice::from_raw_parts(self.words.as_ptr() as *const u8, self.len) }
    }

    /// Linux / Android の `sendmmsg` / GSO が制御バッファ長を設定するために使う
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn len(&self) -> usize {
        self.len
    }
}

/// `sendmmsg` / GSO で複数のデータグラムを 1 回のシステムコールで送る
///
/// 送信できたデータグラム数を返す。`sendmmsg` は送信バッファが埋まると残りを
/// 送らずに戻るため、戻り値が `datas.len()` より小さい場合は残りが送られていない。
/// UDP では送信できなかったデータグラムは損失として扱われ、QUIC の損失検出が
/// 再送する。
///
/// `gso` が `true` の場合は同じ長さのデータグラムだけを渡すこと。連結した
/// 1 つのデータグラムに `UDP_SEGMENT` の cmsg でセグメントサイズを設定する。
/// バッチ内のデータグラムは同じソケット・同じ 4-tuple・同じ ECN コードポイントで
/// あることを前提にする (呼び出し側の [`crate::batch::plan_batch`] が保証する)。
/// そのため ECN の cmsg は 1 つ組み立て、各 `mmsghdr` / `msghdr` で共有する。
#[cfg(any(target_os = "linux", target_os = "android"))]
fn try_send_batch(
    socket: &UdpSocket,
    datas: &[&[u8]],
    remote: SocketAddr,
    local: SocketAddr,
    ecn: EcnCodepoint,
    gso: bool,
) -> io::Result<usize> {
    let fd = SockRef::from(socket).as_raw_fd();
    let (local_ip, scope_id) = resolve_local_ip(socket, local);
    let remote = normalize_remote(socket, remote);
    let remote_sockaddr = SockAddr::from(remote);

    // バッチ内は同じ送信元アドレス・同じ ECN なので、cmsg は 1 つで足りる。
    // 各 mmsghdr / msghdr は同じ制御バッファを指す。sendmsg / sendmmsg は
    // 制御バッファを読むだけで書き換えない。
    let mut cmsg = build_send_cmsg(local_ip, scope_id, &remote, ecn);

    if gso {
        // セグメントサイズはデータグラム 1 件の長さ。`u16` で渡す (Linux の
        // `UDP_SEGMENT` は `int` ではなく `__u16` を取る)。
        let Some(segment_size) = datas.first().map(|d| d.len()) else {
            return Ok(0);
        };
        let segment_size = u16::try_from(segment_size)
            .map_err(|_| io::Error::other("GSO segment size exceeds u16::MAX"))?;
        cmsg.push(
            libc::SOL_UDP,
            libc::UDP_SEGMENT,
            &segment_size.to_ne_bytes(),
        );

        // 同一長のデータグラムを 1 つに連結して送る
        let mut joined = Vec::new();
        for data in datas {
            joined.extend_from_slice(data);
        }

        let mut iov = libc::iovec {
            iov_base: joined.as_ptr() as *mut libc::c_void,
            iov_len: joined.len(),
        };
        let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
        // SAFETY: sendmsg は msg_name を書き換えないため、共有参照から
        // 可変ポインタへキャストしても問題ない (POSIX の規定)。
        hdr.msg_name = remote_sockaddr.as_ptr() as *mut libc::c_void;
        hdr.msg_namelen = remote_sockaddr.len();
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = cmsg.as_ptr();
        hdr.msg_controllen = cmsg.len();

        let sent = unsafe { libc::sendmsg(fd, &hdr, 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        // UDP はデータグラム単位で送るため、成功時は連結した長さぶんがまとめて
        // 受理される。部分送信は起きない想定だが、起きた場合に取りこぼしを
        // 黙って隠さないようエラーにする。
        if sent as usize != joined.len() {
            return Err(io::Error::other(format!(
                "GSO sendmsg accepted {sent} of {} bytes",
                joined.len()
            )));
        }
        return Ok(datas.len());
    }

    // データグラムごとに iov を用意し、1 回の sendmmsg でまとめて送る
    let mut iovecs: Vec<libc::iovec> = datas
        .iter()
        .map(|data| libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        })
        .collect();
    let mut hdrs: Vec<libc::mmsghdr> = (0..datas.len()).map(|_| unsafe { mem::zeroed() }).collect();
    for (i, hdr) in hdrs.iter_mut().enumerate() {
        // SAFETY: sendmmsg は msg_name を書き換えないため、共有参照から
        // 可変ポインタへキャストしても問題ない (POSIX の規定)。
        hdr.msg_hdr.msg_name = remote_sockaddr.as_ptr() as *mut libc::c_void;
        hdr.msg_hdr.msg_namelen = remote_sockaddr.len();
        hdr.msg_hdr.msg_iov = &mut iovecs[i];
        hdr.msg_hdr.msg_iovlen = 1;
        hdr.msg_hdr.msg_control = cmsg.as_ptr();
        hdr.msg_hdr.msg_controllen = cmsg.len();
    }

    let sent = unsafe { libc::sendmmsg(fd, hdrs.as_mut_ptr(), datas.len() as libc::c_uint, 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sent as usize)
}

/// バッチ送信 (sendmmsg / GSO) を非同期で行う
///
/// 送信可能になるまで待ち、[`try_send_batch`] を呼ぶ。送信バッファが埋まると
/// `sendmmsg` は一部だけを送って戻るため、残りを送り切るまで繰り返す。
/// 1 データグラムずつの経路と同じく、送れるまで待ってから戻る。
///
/// `ecn` はバッチ内の全データグラムに cmsg で指定する。バッチにまとめるのは
/// 同じ ECN が連続する範囲だけであり ([`crate::batch::plan_batch`])、部分送信で
/// 呼び直す場合も毎回同じ値の cmsg を付ける。
#[cfg(any(target_os = "linux", target_os = "android"))]
async fn send_batch_with_local_addr(
    socket: &UdpSocket,
    datas: &[&[u8]],
    remote: SocketAddr,
    local: SocketAddr,
    ecn: EcnCodepoint,
    gso: bool,
) -> io::Result<usize> {
    let mut offset = 0;
    while offset < datas.len() {
        let remaining = &datas[offset..];
        // 残りが 1 件になったら GSO は使わない (セグメント 1 つでは意味がない)
        let use_gso = gso && remaining.len() > 1;
        wait_writable(socket).await?;
        match socket.try_io(tokio::io::Interest::WRITABLE, || {
            // 部分送信で呼び直す場合も、同じ ECN の cmsg を毎回付ける
            try_send_batch(socket, remaining, remote, local, ecn, use_gso)
        }) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "batch send made no progress",
                ));
            }
            Ok(sent) => offset += sent,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(datas.len())
}

// --- 送信待ちのデータグラム ---

/// 送信待ちとして溜めるデータグラム数の上限
///
/// 送信先や ECN が変わるたびに送るため通常はここまで溜まらないが、同じ条件の
/// 送信が続いたときに際限なく溜めないための上限。
pub(crate) const MAX_PENDING_SENDS: usize = 64;

/// 送信待ちのデータグラム
///
/// `flush_outputs` が `ConnectionOutput::SendDatagram` を溜めるために使う。
/// データ本体と送信先を保持し、まとめ判定に使うキーも併せて持つ。
pub struct PendingSend {
    /// 送信に使うソケット
    socket: Arc<UdpSocket>,
    /// 送信するデータグラム
    data: Vec<u8>,
    /// 宛先アドレス
    remote: SocketAddr,
    /// 送信元アドレス (pktinfo で指定する)
    local: SocketAddr,
    /// 送信するデータグラムの ECN コードポイント
    ecn: EcnCodepoint,
    /// まとめ判定に使うキー
    key: crate::batch::SendKey,
}

impl PendingSend {
    /// 送信待ちのデータグラムを作る
    pub fn new(
        socket: Arc<UdpSocket>,
        data: Vec<u8>,
        remote: SocketAddr,
        local: SocketAddr,
        ecn: EcnCodepoint,
    ) -> Self {
        let key = crate::batch::SendKey {
            // ソケットの同一性はポインタで判定する。プールが保持している間は
            // アドレスが変わらない。
            socket_id: Arc::as_ptr(&socket) as usize,
            local,
            remote,
            ecn,
            len: data.len(),
        };
        Self {
            socket,
            data,
            remote,
            local,
            ecn,
            key,
        }
    }
}

/// グループ内のデータグラムを 1 件ずつ送る
///
/// バッチを使わない経路と、GSO が `EMSGSIZE` で失敗したときのフォールバックが
/// 使う。ECN はグループの先頭ではなく、データグラムごとに [`PendingSend`] が
/// 保持する値を渡す。フォールバックで先頭の値や `NotEct` を使うと、GSO が通った
/// データグラムとフォールバックしたデータグラムでマーキングが食い違う。
///
/// 送信のたびに中間の `Vec` を確保しないよう、要素ごとの計画は作らず入力
/// スライスをそのままたどる。バッチを使わない経路では 1 件ずつここへ来るため、
/// 計画を作るとデータグラム 1 件につき 1 回のヒープ確保になる。
async fn send_per_datagram(group: &[PendingSend]) -> io::Result<()> {
    for send in group {
        send_with_local_addr(&send.socket, &send.data, send.remote, send.local, send.ecn).await?;
    }
    Ok(())
}

/// 溜めた送信がまだ 1 つのバッチにまとまるかを返す
///
/// `flush_outputs` が送信を溜め続けてよいかの判定に使う。`None` を渡した場合と、
/// このプラットフォームが `sendmmsg` / GSO を持たない場合は `false` を返す。
/// バッチが有効でも、溜めた送信が 1 つのグループにまとまらない (送信先や ECN が
/// 変わる) 場合は `false` を返すので、その時点で送る。
pub fn can_batch_all(pending: &[PendingSend], batch: Option<UdpBatchConfig>) -> bool {
    let Some(config) = batch.filter(|_| crate::batch::SUPPORTED) else {
        return false;
    };
    let keys: Vec<crate::batch::SendKey> = pending.iter().map(|send| send.key).collect();
    crate::batch::plan_batch(&keys, &config).count == keys.len()
}

/// 溜めた送信を、まとめられる範囲ごとに 1 回のシステムコールで送る
///
/// バッチが無効な場合や、このプラットフォームが `sendmmsg` / GSO を持たない
/// 場合は 1 データグラムずつ送る。送信できなかったデータグラムは残さず送り切る
/// まで待つため、送信経路による取りこぼしは増えない。
///
/// 各データグラムの `ecn` は [`PendingSend`] が保持する値を cmsg で指定する。
/// バッチにまとめるのは同じ ECN が連続する範囲だけであり、GSO が `EMSGSIZE` で
/// 失敗したフォールバックでもデータグラムごとの値を保つ。
pub async fn send_pending(
    pending: &mut Vec<PendingSend>,
    batch: Option<UdpBatchConfig>,
) -> io::Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    let sends = std::mem::take(pending);
    // macOS / iOS には sendmmsg も GSO もないため、設定によらず 1 件ずつ送る
    let config = batch.filter(|_| crate::batch::SUPPORTED);
    let mut index = 0;
    while index < sends.len() {
        let plan = match config {
            Some(config) => {
                let keys: Vec<crate::batch::SendKey> =
                    sends[index..].iter().map(|send| send.key).collect();
                crate::batch::plan_batch(&keys, &config)
            }
            None => crate::batch::BatchPlan {
                count: 1,
                gso: false,
            },
        };
        // まとめる件数は残りの件数を超えない
        let count = plan.count.clamp(1, sends.len() - index);
        let group = &sends[index..index + count];

        // sendmmsg / GSO が使えるプラットフォームでは、まとめられる範囲を
        // 1 回のシステムコールで送る。それ以外は 1 件ずつ送る。
        // ECN はグループ内で同一である (plan_batch / SendKey が保証する)。
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if group.len() > 1 {
            let datas: Vec<&[u8]> = group.iter().map(|send| send.data.as_slice()).collect();
            let result = send_batch_with_local_addr(
                &group[0].socket,
                &datas,
                group[0].remote,
                group[0].local,
                group[0].ecn,
                plan.gso,
            )
            .await;
            // GSO はセグメント長が経路の MTU を超えるとカーネルが EMSGSIZE で
            // 拒否する。1 件ずつ送れば送れるため、GSO を諦めて送り直す。
            // フォールバックでも各データグラムの ECN を保つ。
            if let Err(e) = result {
                if !plan.gso || e.raw_os_error() != Some(libc::EMSGSIZE) {
                    return Err(e);
                }
                tracing::debug!("GSO send failed, falling back to per-datagram sends: {e}");
                send_per_datagram(group).await?;
            }
            index += count;
            continue;
        }

        send_per_datagram(group).await?;
        index += count;
    }
    Ok(())
}

/// 送信待ちのデータグラムを溜めて、まとめられなくなった時点で送る
///
/// `flush_outputs` が `ConnectionOutput::SendDatagram` を溜めるために使う。
/// 溜めすぎ (内部の上限に到達) と、まとめられなくなった時点
/// ([`can_batch_all`] が偽) で送る。バッチが無効な場合は 1 件ずつ送る。
pub struct PendingSends {
    /// 送信待ちのデータグラム
    pending: Vec<PendingSend>,
}

impl PendingSends {
    /// 空の送信待ちを作る
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    /// 送信待ちを追加する。これ以上まとめられない場合は送る
    pub async fn push(
        &mut self,
        send: PendingSend,
        batch: Option<UdpBatchConfig>,
    ) -> io::Result<()> {
        self.pending.push(send);
        if self.pending.len() >= MAX_PENDING_SENDS || !can_batch_all(&self.pending, batch) {
            self.flush(batch).await?;
        }
        Ok(())
    }

    /// 溜めているデータグラムをすべて送る
    pub async fn flush(&mut self, batch: Option<UdpBatchConfig>) -> io::Result<()> {
        send_pending(&mut self.pending, batch).await
    }
}

impl Default for PendingSends {
    fn default() -> Self {
        Self::new()
    }
}

// --- 受信 ---

/// recvmsg + pktinfo cmsg で 1 データグラムを受信する
///
/// `buf` は呼び出し側 (受信タスク) が所有して使い回す。受信のたびに確保するのは
/// 受信した長さぶんの複製だけになる。
pub async fn recv_datagram(
    socket: &UdpSocket,
    buf: &mut RecvBuffer,
) -> io::Result<ReceivedDatagram> {
    loop {
        socket.readable().await?;
        match try_recvmsg(socket, buf) {
            Ok(Some(pkt)) => return Ok(pkt),
            // 切り捨てられたデータグラムは捨てて次の受信を待つ
            Ok(None) => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

/// 同期的に recvmsg を実行する (try_io 内で使用)
///
/// バッファに収まらずカーネルが切り捨てたデータグラムは `Ok(None)` を返して捨てる。
/// 壊れたデータグラムを接続へ渡さないためである (QUIC の損失検出が再送する)。
fn try_recvmsg(socket: &UdpSocket, buf: &mut RecvBuffer) -> io::Result<Option<ReceivedDatagram>> {
    let RecvBuffer { data, cmsg } = buf;
    let (len, remote, local_addr, ecn, segment_size, truncated) =
        socket.try_io(tokio::io::Interest::READABLE, || {
            let sock_ref = SockRef::from(socket);

            // msg_name の受け皿は sockaddr_in6 で初期化する。
            // socket2 の SockAddr は自身の sockaddr_storage を msg_name に渡し、
            // msg_namelen に自身のサイズを設定する。sockaddr_in (16 バイト) で
            // 初期化すると、カーネルは sockaddr_in6 (macOS では 28 バイト) を
            // 書き込めず切り詰めて送信元アドレスを返すため、IPv6 では送信元が
            // :: として観測される。sockaddr_in6 なら IPv4 / IPv6 のどちらも収まる。
            let mut addr = SockAddr::from(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0));

            // SAFETY: data はこの関数が所有する有効なバッファ
            let data_uninit =
                unsafe { &mut *(data.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
            let mut iov = [MaybeUninitSlice::new(data_uninit)];

            // cmsg のデコードは msg の借用が生きている間に行う。msg をブロックの
            // 内側で作ることで、ブロックを抜けた時点で addr の可変借用が解放される。
            let (len, local_ip, ecn, segment_size, truncated) = {
                let mut msg = MsgHdrMut::new()
                    .with_addr(&mut addr)
                    .with_buffers(&mut iov)
                    .with_control(cmsg_bytes_mut(cmsg));

                let len = sock_ref.recvmsg(&mut msg, 0)?;

                let socket_local = socket.local_addr().ok();
                let local_ip = decode_pktinfo(msg_header(&msg))
                    .or_else(|| socket_local.map(LocalIp::from_socket_addr))
                    .unwrap_or(LocalIp::V4(Ipv4Addr::UNSPECIFIED));
                let ecn = decode_ecn(msg_header(&msg)).unwrap_or(EcnCodepoint::NotEct);
                let segment_size = decode_gro_segment_size(msg_header(&msg));
                // MSG_CTRUNC は補助データ (cmsg) がバッファに収まらず切り捨てられた
                // ことを示す。cmsg が欠けたデータグラムは宛先アドレスや ECN を
                // 誤って解釈するため、データグラムごと破棄する。
                let truncated =
                    msg_header(&msg).msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0;

                (len, local_ip, ecn, segment_size, truncated)
            };

            // 受信ソケットのローカルアドレス。ポートはパスごとに異なるソケットを
            // 使い分けるため、受信ソケットのものをそのまま使う。
            let socket_local = socket.local_addr().ok();

            let remote = addr.as_socket().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid remote address")
            })?;
            let local_addr = local_ip.to_socket_addr(socket_local.map_or(0, |a| a.port()));

            Ok((len, remote, local_addr, ecn, segment_size, truncated))
        })?;

    if truncated {
        tracing::debug!("dropping truncated datagram ({len} bytes)");
        return Ok(None);
    }

    Ok(Some(ReceivedDatagram {
        // 受信した長さだけを複製する。RecvBuffer は次の受信に使い回す。
        data: data[..len.min(data.len())].to_vec(),
        remote,
        local_addr,
        ecn,
        segment_size,
    }))
}

/// 受信したデータグラムを配送単位に分ける
///
/// `UDP_GRO` を有効にしたソケット (Linux / Android) では、カーネルが同じ 4-tuple の
/// データグラムを結合して返す。1-RTT の Short Header は Length を持たず、パケット長は
/// データグラム境界で決まるため (RFC 9000 Section 12.2 / 17.3)、結合されたまま
/// `Connection::receive` に渡すと 2 個目以降のパケットが 1 個目の暗号文に混入して
/// 復号に失敗する。受信側でセグメント単位に分けてから渡す。
///
/// 分割が不要な場合は受け取ったデータをそのまま返し、余分なコピーを作らない。
pub fn split_received(datagram: ReceivedDatagram) -> Vec<ReceivedDatagram> {
    let ReceivedDatagram {
        data,
        remote,
        local_addr,
        ecn,
        segment_size,
    } = datagram;
    let Some(size) = crate::batch::gro_segment_split_size(data.len(), segment_size) else {
        return vec![ReceivedDatagram {
            data,
            remote,
            local_addr,
            ecn,
            segment_size: None,
        }];
    };
    data.chunks(size)
        .map(|segment| ReceivedDatagram {
            data: segment.to_vec(),
            remote,
            local_addr,
            ecn,
            segment_size: None,
        })
        .collect()
}

/// 受信タスクが使うデータグラム受信の手順
///
/// 「バッチ受信 (`recvmmsg`) を試す → 取れなければ単発受信 (`recvmsg`) → `UDP_GRO`
/// で結合されたデータグラムをセグメント単位に分ける」という手順を 1 箇所にまとめる。
/// クライアントとサーバーの受信タスクは、得られたデータグラムを自分のチャネルへ
/// 流すだけでよくなる。
///
/// 受信バッファはこの型が所有して使い回す。バッチ受信を使う場合は単発受信用の
/// バッファを遅延確保し、使わないプラットフォームでは常に 1 つだけ持つ。
pub struct DatagramReceiver {
    /// 単発受信用のバッファ
    buffer: Option<RecvBuffer>,
    /// `recvmmsg` 用のバッファ群 (Linux / Android のみ)
    #[cfg(any(target_os = "linux", target_os = "android"))]
    batch: Option<RecvBatch>,
    /// 受信済みのデータグラム
    received: Vec<ReceivedDatagram>,
}

impl DatagramReceiver {
    /// 設定に応じた受信手順を作る
    pub fn new(udp_batch: Option<UdpBatchConfig>) -> Self {
        // macOS / iOS には recvmmsg がないため、バッチ受信は Linux / Android だけで使う
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let batch = udp_batch
            .filter(|config| config.syscalls)
            .map(|config| RecvBatch::new(config.max_datagrams));
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let _ = udp_batch;

        Self {
            buffer: None,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            batch,
            received: Vec::new(),
        }
    }

    /// データグラムを 1 回分受信する
    ///
    /// 受信したデータグラムは [`DatagramReceiver::drain`] で取り出す。
    pub async fn recv(&mut self, socket: &UdpSocket) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(ref mut batch) = self.batch {
            recv_datagram_batch(socket, batch, &mut self.received).await?;
        }

        if self.received.is_empty() {
            // バッチ受信を使わない場合はこちらだけを使う
            let buffer = self.buffer.get_or_insert_with(RecvBuffer::new);
            let datagram = recv_datagram(socket, buffer).await?;
            self.received.extend(split_received(datagram));
            return Ok(());
        }

        // バッチ受信で得た分も GRO の分割を通す
        let datagrams = std::mem::take(&mut self.received);
        for datagram in datagrams {
            self.received.extend(split_received(datagram));
        }
        Ok(())
    }

    /// 受信済みのデータグラムを取り出す
    pub fn drain(&mut self) -> impl Iterator<Item = ReceivedDatagram> + '_ {
        self.received.drain(..)
    }
}

impl Default for DatagramReceiver {
    fn default() -> Self {
        Self::new(None)
    }
}

// --- バッチ受信 (recvmmsg) ---

/// `recvmmsg` 用の受信バッファ群
///
/// `recvmmsg` は 1 回の呼び出しで複数のデータグラムを受け取るため、メッセージ
/// ごとにデータ領域と cmsg 領域が要る。受信タスクが保持して呼び出しごとに
/// 使い回すことで、受信のたびの確保をなくす。
///
/// 受信タスク 1 本あたりのメモリ使用量は `capacity × 64 KiB` になる。
/// `recvmmsg` を持つ Linux / Android でのみ使う。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub struct RecvBatch {
    /// メッセージごとの受信バッファ
    buffers: Vec<RecvBuffer>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl RecvBatch {
    /// `capacity` 件までまとめて受信できるバッファ群を作る
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            buffers: (0..capacity).map(|_| RecvBuffer::new()).collect(),
        }
    }

    /// まとめて受信できる最大件数
    fn capacity(&self) -> usize {
        self.buffers.len()
    }
}

/// `recvmmsg` で複数のデータグラムを受信する (Linux / Android)
///
/// 受信したデータグラムを `out` に追加し、追加した件数を返す。`recvmmsg` は
/// 到着済みのデータグラムだけを返すため、`capacity` 件に満たない場合も
/// 正常終了として扱う。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub async fn recv_datagram_batch(
    socket: &UdpSocket,
    batch: &mut RecvBatch,
    out: &mut Vec<ReceivedDatagram>,
) -> io::Result<usize> {
    loop {
        socket.readable().await?;
        match try_recvmmsg(socket, batch, out) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

/// 同期的に recvmmsg を実行する (try_io 内で使用)
#[cfg(any(target_os = "linux", target_os = "android"))]
fn try_recvmmsg(
    socket: &UdpSocket,
    batch: &mut RecvBatch,
    out: &mut Vec<ReceivedDatagram>,
) -> io::Result<usize> {
    let count = batch.capacity();
    let fd = SockRef::from(socket).as_raw_fd();
    let socket_local = socket.local_addr().ok();

    // msg_name の受け皿・iovec・msghdr は recvmmsg の間ずっと有効でなければ
    // ならないため、呼び出しの先頭でまとめて用意する。
    let mut addrs: Vec<libc::sockaddr_storage> =
        (0..count).map(|_| unsafe { mem::zeroed() }).collect();
    let mut iovecs: Vec<libc::iovec> = (0..count).map(|_| unsafe { mem::zeroed() }).collect();
    let mut hdrs: Vec<libc::mmsghdr> = (0..count).map(|_| unsafe { mem::zeroed() }).collect();

    for (i, hdr) in hdrs.iter_mut().enumerate() {
        // SAFETY: buffers は count 件あり、i はその範囲内。data と cmsg は
        // recvmmsg の間、他から借用しない。
        let buffer = &mut batch.buffers[i];
        let data_uninit =
            unsafe { &mut *(buffer.data.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        iovecs[i] = libc::iovec {
            iov_base: data_uninit.as_mut_ptr() as *mut libc::c_void,
            iov_len: data_uninit.len(),
        };

        hdr.msg_hdr.msg_name = &mut addrs[i] as *mut libc::sockaddr_storage as *mut libc::c_void;
        hdr.msg_hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        hdr.msg_hdr.msg_iov = &mut iovecs[i];
        hdr.msg_hdr.msg_iovlen = 1;
        hdr.msg_hdr.msg_control = buffer.cmsg.as_mut_ptr() as *mut libc::c_void;
        hdr.msg_hdr.msg_controllen = buffer.cmsg.len() * mem::size_of::<u64>();
    }

    // try_io を通すことで、EAGAIN (WouldBlock) のときに tokio の readiness が
    // クリアされ、readable() が即座に解決し続けるビジースピンを避ける。
    let received = socket.try_io(tokio::io::Interest::READABLE, || {
        let received = unsafe {
            libc::recvmmsg(
                fd,
                hdrs.as_mut_ptr(),
                count as libc::c_uint,
                0,
                std::ptr::null_mut(),
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(received)
    })?;
    let received = received as usize;

    for i in 0..received {
        let hdr = &hdrs[i].msg_hdr;
        // バッファに収まらずカーネルが切り捨てたデータグラムと、cmsg が
        // 切り捨てられたデータグラムは捨てる。
        if hdr.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            tracing::debug!("dropping truncated datagram ({} bytes)", hdrs[i].msg_len);
            continue;
        }
        let len = (hdrs[i].msg_len as usize).min(batch.buffers[i].data.len());
        let local_ip = decode_pktinfo(hdr)
            .or_else(|| socket_local.map(LocalIp::from_socket_addr))
            .unwrap_or(LocalIp::V4(Ipv4Addr::UNSPECIFIED));
        let remote = sockaddr_storage_to_socket_addr(&addrs[i], hdr.msg_namelen as usize)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid remote address"))?;
        out.push(ReceivedDatagram {
            data: batch.buffers[i].data[..len].to_vec(),
            remote,
            local_addr: local_ip.to_socket_addr(socket_local.map_or(0, |a| a.port())),
            ecn: decode_ecn(hdr).unwrap_or(EcnCodepoint::NotEct),
            segment_size: decode_gro_segment_size(hdr),
        });
    }

    Ok(received)
}

/// `recvmmsg` が書き込んだ送信元アドレスを `SocketAddr` に変換する
///
/// `namelen` はカーネルが `msg_namelen` に書き戻した実際の sockaddr 長。
/// 構造体のサイズより小さい場合は、未初期化領域を読まないように `None` を返す。
#[cfg(any(target_os = "linux", target_os = "android"))]
fn sockaddr_storage_to_socket_addr(
    storage: &libc::sockaddr_storage,
    namelen: usize,
) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            if namelen < mem::size_of::<libc::sockaddr_in>() {
                return None;
            }
            // SAFETY: ss_family が AF_INET で、namelen が sockaddr_in 以上なので読める
            let addr =
                unsafe { &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes())),
                u16::from_be(addr.sin_port),
            ))
        }
        libc::AF_INET6 => {
            if namelen < mem::size_of::<libc::sockaddr_in6>() {
                return None;
            }
            // SAFETY: ss_family が AF_INET6 で、namelen が sockaddr_in6 以上なので読める
            let addr = unsafe {
                &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in6)
            };
            // link-local アドレスなどの scope を必要とするアドレスは
            // `sin6_scope_id` を保持する。グローバルアドレスでは scope 0 のため
            // 結果は変わらない。
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(addr.sin6_addr.s6_addr),
                u16::from_be(addr.sin6_port),
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

// --- cmsg デコード ---

/// `MsgHdrMut` がラップしている `msghdr` を取り出す
///
/// `MsgHdrMut` は `#[repr(transparent)]` で `msghdr` をラップしているため、
/// ポインタキャストで内部にアクセスできる。cmsg のデコードは `recvmsg` と
/// `recvmmsg` の両方から使うため、`msghdr` を直接受ける形に揃える。
fn msg_header<'a>(msg: &'a MsgHdrMut<'_, '_, '_>) -> &'a libc::msghdr {
    // SAFETY: MsgHdrMut は #[repr(transparent)] で libc::msghdr をラップしている
    unsafe { &*(msg as *const MsgHdrMut<'_, '_, '_> as *const libc::msghdr) }
}

/// cmsg のデータ部の長さを返す
///
/// `cmsg_len` はカーネルが書き込む値だが、壊れた値や切り捨てられた cmsg で
/// 構造体サイズより小さい場合がある。`CMSG_DATA` を読む前に必ず確認する。
fn cmsg_payload_len(cmsg: &libc::cmsghdr) -> usize {
    // SAFETY: CMSG_LEN(0) は定数計算であり、ポインタを参照しない。
    let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
    // cmsg_len はターゲット依存の型なので、計算先の usize へ揃える。
    let total_len: usize = cmsg.cmsg_len as _;
    total_len.saturating_sub(header_len)
}

fn decode_pktinfo(hdr: &libc::msghdr) -> Option<LocalIp> {
    if hdr.msg_controllen == 0 {
        return None;
    }

    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(hdr);

        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let ty = (*cmsg).cmsg_type;

            // Linux / Android: IP_PKTINFO で in_pktinfo が返る
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if level == libc::IPPROTO_IP && ty == libc::IP_PKTINFO {
                if cmsg_payload_len(&*cmsg) < mem::size_of::<libc::in_pktinfo>() {
                    return None;
                }
                let pktinfo = libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo;
                let addr = Ipv4Addr::from((*pktinfo).ipi_spec_dst.s_addr.to_ne_bytes());
                return Some(LocalIp::V4(addr));
            }

            // macOS / iOS: IP_RECVDSTADDR で in_addr が返る
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            if level == libc::IPPROTO_IP && ty == libc::IP_RECVDSTADDR {
                if cmsg_payload_len(&*cmsg) < mem::size_of::<libc::in_addr>() {
                    return None;
                }
                let in_addr = libc::CMSG_DATA(cmsg) as *const libc::in_addr;
                let addr = Ipv4Addr::from((*in_addr).s_addr.to_ne_bytes());
                return Some(LocalIp::V4(addr));
            }

            // IPv6: IPV6_PKTINFO で in6_pktinfo が返る (全プラットフォーム共通)。
            // ipi6_ifindex は受信インターフェースを表し、link-local アドレスの
            // scope ID として返すことで、受信先のインターフェース識別を保持する。
            if level == libc::IPPROTO_IPV6 && ty == libc::IPV6_PKTINFO {
                if cmsg_payload_len(&*cmsg) < mem::size_of::<libc::in6_pktinfo>() {
                    return None;
                }
                let pktinfo = libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo;
                let addr = Ipv6Addr::from((*pktinfo).ipi6_addr.s6_addr);
                return Some(LocalIp::V6(addr, (*pktinfo).ipi6_ifindex));
            }

            cmsg = libc::CMSG_NXTHDR(hdr, cmsg);
        }
    }

    None
}

/// 受信したパケットの宛先 IP と IPv6 のインターフェース識別
///
/// IPv4 は scope を持たないため `LocalIp::V4` のみである。IPv6 は pktinfo の
/// `ipi6_ifindex` を `scope_id` として保持する。`scope_id` が 0 の場合
/// (グローバルアドレスや scope を必要としないアドレス) は、`SocketAddr`
/// への再構成時に付与しない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalIp {
    V4(Ipv4Addr),
    V6(Ipv6Addr, libc::c_uint),
}

impl LocalIp {
    /// [`SocketAddr`] から [`LocalIp`] を構築する
    ///
    /// pktinfo が得られなかった場合のフォールバックで使う。link-local に
    /// bind 済みのソケットでは `local_addr` が scope ID を持つため、それを
    /// 引き継ぐ。scope を持たないアドレスでは 0 になる。
    fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => LocalIp::V4(*addr.ip()),
            SocketAddr::V6(addr) => {
                let scope_id = if addr.ip().is_unicast_link_local() {
                    addr.scope_id()
                } else {
                    0
                };
                LocalIp::V6(*addr.ip(), scope_id)
            }
        }
    }

    /// ポートを付けて [`SocketAddr`] を返す
    ///
    /// pktinfo の `ipi6_ifindex` を scope ID とする。link-local (fe80::/10、
    /// RFC 4291 Section 2.4) で `scope_id` が非 0 のときだけ `SocketAddrV6` の
    /// scope_id に設定する。グローバルアドレスや loopback に不要な scope を
    /// 付与しないため、従来の `SocketAddr::new` と同じ結果になる。
    fn to_socket_addr(self, port: u16) -> SocketAddr {
        match self {
            LocalIp::V4(addr) => SocketAddr::new(IpAddr::V4(addr), port),
            LocalIp::V6(addr, scope_id) => {
                if scope_id == 0 || !addr.is_unicast_link_local() {
                    return SocketAddr::new(IpAddr::V6(addr), port);
                }
                SocketAddr::V6(SocketAddrV6::new(addr, port, 0, scope_id))
            }
        }
    }
}

/// recvmsg の cmsg から受信パケットの ECN コードポイントを取り出す
///
/// - IPv4: `IP_TOS` (u8。ECN は下位 2 bit)
/// - IPv6: `IPV6_TCLASS` (int。ECN は下位 2 bit)
///
/// どちらも `IP_RECVTOS` / `IPV6_RECVTCLASS` が有効なソケットでのみ返る。
fn decode_ecn(hdr: &libc::msghdr) -> Option<EcnCodepoint> {
    if hdr.msg_controllen == 0 {
        return None;
    }

    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(hdr);

        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let ty = (*cmsg).cmsg_type;

            // IPv4: TOS の下位 2 bit が ECN
            // Linux は IP_TOS (3)、macOS は IP_RECVTOS (27) の type で返る。
            if level == libc::IPPROTO_IP && (ty == libc::IP_TOS || ty == libc::IP_RECVTOS) {
                if cmsg_payload_len(&*cmsg) < mem::size_of::<u8>() {
                    return None;
                }
                let tos = *(libc::CMSG_DATA(cmsg) as *const u8);
                return Some(EcnCodepoint::from_bits(tos));
            }

            // IPv6: Traffic Class の下位 2 bit が ECN
            if level == libc::IPPROTO_IPV6 && ty == libc::IPV6_TCLASS {
                if cmsg_payload_len(&*cmsg) < mem::size_of::<libc::c_int>() {
                    return None;
                }
                let tclass = *(libc::CMSG_DATA(cmsg) as *const libc::c_int);
                return Some(EcnCodepoint::from_bits(tclass as u8));
            }

            cmsg = libc::CMSG_NXTHDR(hdr, cmsg);
        }
    }

    None
}

/// recvmsg の cmsg から GRO で結合されたデータグラムのセグメントサイズを取り出す
///
/// `UDP_GRO` を有効にしたソケット (Linux / Android) では、結合されたデータグラムの
/// 1 セグメントの長さが `SOL_UDP` レベルの `UDP_GRO` cmsg で `int` として返る。
#[cfg(any(target_os = "linux", target_os = "android"))]
fn decode_gro_segment_size(hdr: &libc::msghdr) -> Option<usize> {
    if hdr.msg_controllen == 0 {
        return None;
    }

    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(hdr);

        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_UDP && (*cmsg).cmsg_type == libc::UDP_GRO {
                if cmsg_payload_len(&*cmsg) < mem::size_of::<libc::c_int>() {
                    return None;
                }
                let size = *(libc::CMSG_DATA(cmsg) as *const libc::c_int);
                if size > 0 {
                    return Some(size as usize);
                }
                return None;
            }

            cmsg = libc::CMSG_NXTHDR(hdr, cmsg);
        }
    }

    None
}

/// GRO は Linux / Android にしかないため、それ以外では常に `None` を返す
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn decode_gro_segment_size(_hdr: &libc::msghdr) -> Option<usize> {
    None
}

// --- ソケットプール ---

/// アドレスファミリごとの UDP ソケットをまとめて管理する
///
/// QUIC の 1 接続は複数のパスを持ち、パスごとにローカルアドレスが異なる。
/// 同一アドレスファミリ内のアドレスは `IP_PKTINFO` / `IPV6_PKTINFO` の cmsg で
/// 送信元 IP を指定できるため 1 本のソケットで扱えるが、アドレスファミリをまたぐ
/// 場合は別のソケットが必要になる。IPv6 ソケットで v4-mapped アドレスを
/// `IPV6_PKTINFO` の送信元に指定すると `EINVAL` になるため、デュアルスタックの
/// ソケット 1 本で代用することもできない。
///
/// 初期ソケットは利用者が指定したバインドアドレスで作成し、別ファミリの
/// ローカルアドレスが要求された時点でファミリ用の追加ソケットを遅延作成する。
/// ファミリ用の追加ソケットのポートは初期ソケットに合わせる。サーバーは
/// 待ち受けポートを変えるとクライアントから到達できず、クライアントは接続中に
/// ポートが変わるとピアから別の 4-tuple として観測されるため。
///
/// 追加パス / 移行で利用者が具体的なローカルアドレスを指定した場合は、送信元
/// ポートまで一致させるため、そのアドレス専用のソケットを指定ポートで
/// バインドする。専用ソケットを作るのはクライアントだけで、パスを閉じても
/// 接続の終了まで保持する。
pub struct SocketPool {
    /// 初期ソケット (初期パスと pktinfo による送信元指定で共用する)
    primary: Arc<UdpSocket>,
    /// 追加ソケットの一覧
    ///
    /// パスの追加時にしか増えないが、パス追加は接続の driver タスクから、
    /// 送信・受信は複数のタスクから並行に参照される。チャネルで単一所有者に
    /// 集約する構成も検討したが、ソケットは `SendDatagram` ごとに引く必要があり、
    /// そのたびに往復が発生するため、読み取りが大多数であるこの構造に限り
    /// `Mutex` で保護する。
    additional: Mutex<Vec<Arc<UdpSocket>>>,
    /// 追加ソケットの ID とローカルアドレスの対応
    ///
    /// `additional` と同じ順序で管理する。削除後の再登録で ID を再利用しない。
    additional_ids: Mutex<Vec<(SocketId, SocketAddr)>>,
    /// 次に払い出すソケット ID
    next_socket_id: Mutex<u64>,
    /// 追加ソケットを作るときにも適用する UDP バッチ I/O の設定
    batch: Option<UdpBatchConfig>,
    /// 初期ソケットと異なるアドレスファミリの wildcard ソケットを作ってよいか
    ///
    /// `false` の場合、特定アドレス (loopback やインターフェースアドレス) への
    /// bind を越えて別ファミリの wildcard で待ち受けることはない。初期ソケットが
    /// unspecified の場合と、明示的に opt-in した場合だけ true になる。
    allow_dual_stack: bool,
    /// アドレスファミリ共有ソケットに `SO_REUSEPORT` を設定するか
    ///
    /// サーバーの `BindOptions::reuse_port` を反映する。クライアントは常に
    /// `true` を使う。初期ソケットの設定はバインド時に決まるため、ここでは
    /// 追加ソケットだけを制御する。
    reuse_port: bool,
}

/// プールへ登録する前の追加ソケット
///
/// 追加パスのパス作成が transport に拒否された場合に、ソケットをプールへ
/// 登録せずに破棄できるようにするための仮確保の状態を表す。
///
/// 新しくバインドしたソケットを drop した場合は、保持する [`Arc<UdpSocket>`]
/// の参照が無くなった時点で FD が閉じ、このソケットのバインドが解放される
/// (`SO_REUSEPORT` で同じポートを共有するソケットが他にあれば、ポート自体は
/// 残る)。既にプールにあるソケットを再利用した場合はプールが参照を保持し続ける
/// ため、drop しても解放されない。
pub(crate) struct PreparedSocket {
    /// 仮確保したソケット
    socket: Arc<UdpSocket>,
    /// ソケットのローカルアドレス
    ///
    /// 登録の確定時に `local_addr` を呼ばない (新たな I/O を行わない) ために、
    /// 仮確保の時点で取得した値を保持する。
    local_addr: SocketAddr,
    /// 新しくバインドしたソケットか
    ///
    /// 完全一致する既存ソケットを再利用した場合は、登録の確定でプールへ
    /// 追加しない。
    is_new: bool,
}

impl PreparedSocket {
    /// 仮確保したソケットのローカルアドレスを返す
    ///
    /// 非 0 ポートを指定した場合は指定値と一致する。ポート 0 を指定した場合は
    /// OS が選んだエフェメラルポートになる。
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl SocketPool {
    /// 初期ソケットを持つプールを作成する
    ///
    /// `batch` は追加ソケットを作るときにも使う (受信側の GRO の有効化)。
    pub fn new(primary: Arc<UdpSocket>, batch: Option<UdpBatchConfig>) -> Self {
        // 初期ソケットが wildcard ならデュアルスタックが意図されているとみなす。
        // 特定アドレスへの bind では、別ファミリの wildcard を追加しない。
        let allow_dual_stack = primary
            .local_addr()
            .map(|addr| addr.ip().is_unspecified())
            .unwrap_or(false);
        Self {
            primary,
            additional: Mutex::new(Vec::new()),
            additional_ids: Mutex::new(Vec::new()),
            next_socket_id: Mutex::new(1),
            batch,
            allow_dual_stack,
            reuse_port: true,
        }
    }

    /// 別アドレスファミリの wildcard 待ち受けを許可する
    ///
    /// 特定アドレスへ bind した状態でデュアルスタックを明示的に要求する場合に
    /// 使う。初期ソケットが unspecified の場合は既に許可されているため、
    /// `false` を渡しても無効化されない。
    pub fn with_dual_stack(mut self, allow: bool) -> Self {
        if allow {
            self.allow_dual_stack = true;
        }
        self
    }

    /// アドレスファミリ共有ソケットに `SO_REUSEPORT` を設定するかを指定する
    ///
    /// アドレスファミリを共有する追加ソケットの `SO_REUSEPORT` を指定する。
    /// 追加パス / 移行専用のソケットはこの設定を使わず、常に無効にする。
    /// 初期ソケットの `SO_REUSEPORT` はバインド時に決まるため、ここでは
    /// 追加ソケットの設定だけを変更する。既定は `true`。
    pub fn with_reuse_port(mut self, reuse_port: bool) -> Self {
        self.reuse_port = reuse_port;
        self
    }

    /// 別アドレスファミリの wildcard 待ち受けが許可されているか
    pub fn allows_dual_stack(&self) -> bool {
        self.allow_dual_stack
    }

    /// プールが保持する全ソケットのローカルアドレスを返す
    ///
    /// 初期ソケットと追加ソケットを合わせた、実際に待ち受けているアドレスの一覧。
    /// `local_addr()` だけでは追加の待ち受けを確認できないため、公開範囲の
    /// 確認に使う。
    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        let mut addrs = vec![self.primary.local_addr()?];
        let additional = self
            .additional
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for socket in additional.iter() {
            addrs.push(socket.local_addr()?);
        }
        Ok(addrs)
    }

    /// 初期ソケットを返す
    pub fn primary(&self) -> &Arc<UdpSocket> {
        &self.primary
    }

    /// 追加ソケットをプールに登録する
    ///
    /// 追加ソケットの受信タスクは呼び出し側が起動する。既に同じローカルアドレスの
    /// ソケットが登録されている場合は何もしない。
    pub fn add_socket(&self, socket: Arc<UdpSocket>) -> io::Result<()> {
        let local = socket.local_addr()?;
        let additional = self
            .additional
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if additional
            .iter()
            .any(|s| s.local_addr().ok() == Some(local))
        {
            return Ok(());
        }
        drop(additional);
        self.register_additional_socket(socket, local);
        Ok(())
    }

    /// 追加ソケットを ID 付きでプールへ登録する
    fn register_additional_socket(&self, socket: Arc<UdpSocket>, local: SocketAddr) -> SocketId {
        let id = {
            let mut next = self
                .next_socket_id
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let id = SocketId(*next);
            *next = next.saturating_add(1);
            id
        };
        self.additional
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(socket);
        self.additional_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((id, local));
        id
    }

    /// ソケットに対応する ID を返す
    pub fn socket_id_for(&self, socket: &Arc<UdpSocket>) -> Option<SocketId> {
        if Arc::ptr_eq(socket, &self.primary) {
            return Some(SocketId::PRIMARY);
        }
        let additional = self
            .additional
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let ids = self
            .additional_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        additional.iter().enumerate().find_map(|(index, entry)| {
            if Arc::ptr_eq(entry, socket) {
                ids.get(index).map(|(id, _)| *id)
            } else {
                None
            }
        })
    }

    /// ソケット ID とソケットの一覧を返す
    pub fn sockets_with_ids(&self) -> Vec<(SocketId, Arc<UdpSocket>)> {
        let additional = self
            .additional
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let ids = self
            .additional_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut sockets = vec![(SocketId::PRIMARY, Arc::clone(&self.primary))];
        for (index, socket) in additional.iter().enumerate() {
            if let Some((id, _)) = ids.get(index) {
                sockets.push((*id, Arc::clone(socket)));
            }
        }
        sockets
    }

    /// 追加ソケットをプールから削除する
    ///
    /// 初期ソケット (`SocketId::PRIMARY`) は削除できない。削除したソケットの
    /// `Arc` を返す。呼び出し側が最後の参照を drop すると FD が閉じる。
    pub fn remove_socket(&self, id: SocketId) -> Option<Arc<UdpSocket>> {
        if id == SocketId::PRIMARY {
            return None;
        }
        let local = {
            let mut ids = self
                .additional_ids
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let position = ids.iter().position(|(socket_id, _)| *socket_id == id)?;
            let (_, local) = ids.remove(position);
            local
        };
        let mut additional = self
            .additional
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let position = additional
            .iter()
            .position(|socket| socket.local_addr().ok() == Some(local))?;
        Some(additional.remove(position))
    }

    /// 指定したローカルアドレスで送信するソケットを選ぶ
    ///
    /// `local` が unspecified (0.0.0.0 / ::) の場合は初期ソケットを返す。
    /// 具体 IP の場合はその IP に一致するソケット、なければ同じアドレスファミリの
    /// ワイルドカードバインドソケットを返す。同じファミリのソケットがまだない場合は
    /// 追加ソケットを作成して登録する。
    ///
    /// アドレスファミリが異なる初期ソケットは返さない。IPv4 ソケットに IPv6 宛の
    /// パケットは送れず、IPv6 ソケットでは v4-mapped の送信元 IP を
    /// `IPV6_PKTINFO` に指定できないため、別ファミリのパスには専用のソケットが要る。
    pub fn socket_for_local(&self, local: SocketAddr) -> io::Result<Arc<UdpSocket>> {
        // 専用にバインドしたソケットがあれば、送信元ポートまで一致させるため
        // それを優先する。
        if let Some(socket) = self.find_socket_exact(local) {
            return Ok(socket);
        }
        let ip = local.ip();
        if ip.is_unspecified() {
            return Ok(Arc::clone(&self.primary));
        }
        if self.primary.local_addr().is_ok_and(|a| a.ip() == ip)
            || self
                .primary
                .local_addr()
                .is_ok_and(|a| a.is_ipv6() == ip.is_ipv6())
        {
            // 初期ソケットで扱える (同じファミリ)。具体 IP の指定は pktinfo で行う。
            return Ok(Arc::clone(&self.primary));
        }
        if let Some(socket) = self.find_socket(local) {
            return Ok(socket);
        }
        // 同じファミリのソケットがまだないため追加する。ポートは初期ソケットに
        // 合わせる。サーバーは待ち受けポートを変えるとクライアントから到達できず、
        // クライアントは接続中にポートが変わるとピアから別の 4-tuple として
        // 観測されるため、初期ソケットと同じポートに揃える。
        self.ensure_family_socket(ip.is_ipv6())
    }

    /// 指定したローカルアドレスを扱えるソケットを返す
    ///
    /// アドレスファミリが一致するソケットだけを対象にする。ファミリが違う
    /// ソケットでは、たとえワイルドカードバインドでもそのアドレスを扱えない。
    /// 具体 IP に一致するソケットがなければ、同じファミリのワイルドカード
    /// バインドソケットを返す (pktinfo で送信元 IP を指定できるため)。
    pub fn find_socket(&self, local: SocketAddr) -> Option<Arc<UdpSocket>> {
        let ip = local.ip();
        let socket_ip_matches = |a: SocketAddr| {
            a.is_ipv6() == ip.is_ipv6() && (a.ip() == ip || a.ip().is_unspecified())
        };
        if self.primary.local_addr().is_ok_and(socket_ip_matches) {
            return Some(Arc::clone(&self.primary));
        }
        let additional = self
            .additional
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        additional
            .iter()
            .find(|s| s.local_addr().is_ok_and(socket_ip_matches))
            .map(Arc::clone)
    }

    /// 指定アドレスに完全一致 (IP とポートの両方) するソケットを返す
    ///
    /// 追加パスと 4-tuple 移行の検証では、指定されたローカルアドレス専用に
    /// バインドしたソケットを使う必要がある。IP だけの一致で初期ソケットを
    /// 選ぶと、送信元ポートが指定値と一致しない (移行では 4-tuple が変化しない)。
    pub fn find_socket_exact(&self, local: SocketAddr) -> Option<Arc<UdpSocket>> {
        if self.primary.local_addr().is_ok_and(|a| a == local) {
            return Some(Arc::clone(&self.primary));
        }
        let additional = self
            .additional
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        additional
            .iter()
            .find(|s| s.local_addr().is_ok_and(|a| a == local))
            .map(Arc::clone)
    }

    /// 4-tuple 移行の移行先ローカルアドレス用ソケットを用意する
    ///
    /// 指定アドレスに完全一致するソケットが既にあればそれを返す。無ければ
    /// そのアドレスにバインドしてプールへ登録する。ポート 0 を指定した場合は
    /// 完全一致するソケットが存在しないため OS が選んだエフェメラルポートに
    /// 新しくバインドされ、実際のアドレスは返されたソケットの `local_addr` で
    /// 確認できる。追加ソケットの受信タスクの起動は呼び出し側が行う。
    pub fn ensure_socket_for_local_addr(&self, local: SocketAddr) -> io::Result<Arc<UdpSocket>> {
        let prepared = self.prepare_socket_for_local_addr(local)?;
        Ok(self.register_prepared_socket(prepared))
    }

    /// 追加パス / 移行用のソケットを、プールへ登録せずに仮確保する
    ///
    /// `local` に完全一致するソケットが既にプールにあればそれを再利用する。
    /// 無ければ `local` にバインドしたソケットを新しく作る。新しく作った
    /// ソケットはプールへ登録しないため、パス作成 / 移行が失敗した場合は
    /// [`PreparedSocket`] を drop してこのソケットのバインドを解放できる。
    /// 再利用した場合はプールが保持し続けるため、drop しても解放されない。
    ///
    /// ポート 0 を指定した場合は完全一致するソケットが存在しないため、
    /// OS が選んだエフェメラルポートに新しくバインドする。実際のアドレスは
    /// [`PreparedSocket::local_addr`] で確認できる。
    ///
    /// IPv4-mapped IPv6 アドレス (`::ffff:a.b.c.d`) は IPv6 アドレスとして
    /// 扱われ、`IPV6_V6ONLY` を立てたソケットへのバインドになる。Linux では
    /// このバインドが `EINVAL` で失敗するため、IPv4 のアドレスで指定すること。
    ///
    /// 完全一致するソケットの探索とバインドは仮確保の段階で行い、登録の
    /// 確定 ([`Self::register_prepared_socket`]) では新たな I/O を行わない。
    ///
    /// 新しく作るソケットは `SO_REUSEADDR` と `SO_REUSEPORT` を設定しない。
    /// 指定アドレスが既存ソケットの受信範囲と重なる場合 (`0.0.0.0` の初期
    /// ソケットと同じポートに具体 IP を指定する等) は、ポート共有で回避せず
    /// bind のエラーを返す。
    pub(crate) fn prepare_socket_for_local_addr(
        &self,
        local: SocketAddr,
    ) -> io::Result<PreparedSocket> {
        if let Some(socket) = self.find_socket_exact(local) {
            return Ok(PreparedSocket {
                socket,
                local_addr: local,
                is_new: false,
            });
        }
        let socket = Arc::new(bind_dedicated_socket(local, self.batch)?);
        let local_addr = socket.local_addr()?;
        Ok(PreparedSocket {
            socket,
            local_addr,
            is_new: true,
        })
    }

    /// 仮確保したソケットをプールへ登録する
    ///
    /// 新しくバインドしたソケットだけを一覧へ加え、再利用した既存ソケットは
    /// そのまま返す。仮確保の時点で完全一致するソケットの有無を確認して
    /// いるため、重複確認のための I/O は本番ビルドでは行わない (debug ビルド
    /// では `debug_assert!` が登録済みソケットの `local_addr()` を呼ぶ)。同じ
    /// アドレスのソケットが仮確保後かつ登録前に外部から加わった場合は、プールの
    /// 前提が壊れているためデバッグビルドではパニックする。追加したソケットの
    /// 受信タスクの起動は呼び出し側が行う。
    pub(crate) fn register_prepared_socket(&self, prepared: PreparedSocket) -> Arc<UdpSocket> {
        if prepared.is_new {
            let additional = self
                .additional
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // 仮確保では完全一致するソケットが無いことを確認している。登録まで
            // の間に同じアドレスが加わっていれば、同じアドレスへ二重に bind して
            // いることになり、受信範囲の前提が壊れる。
            debug_assert!(
                !additional.iter().any(|socket| socket
                    .local_addr()
                    .is_ok_and(|addr| addr == prepared.local_addr)),
                "socket {} is already registered in the pool",
                prepared.local_addr
            );
            drop(additional);
            self.register_additional_socket(Arc::clone(&prepared.socket), prepared.local_addr);
        }
        prepared.socket
    }

    /// パスの送信に使うソケットを選ぶ
    ///
    /// パスの 4-tuple の両方を見て、送受信の両方で使えるソケットを返す。
    /// パスは migration でアドレスファミリが変わりうるため、一方だけを見ると
    /// ファミリの合わないソケットを選んでしまう。IPv4 ソケットでは IPv6 宛の
    /// パケットを送れず、`No route to host` になる。
    ///
    /// - `local` が unspecified でない場合は、IP とポートが完全一致する
    ///   ソケット (明示追加パス / 移行用) を最優先にし、無ければその
    ///   ローカルアドレスを扱えるソケットを選ぶ (送信元 IP を pktinfo で
    ///   指定するため)
    /// - `local` が unspecified の場合は、リモートアドレスのファミリで選ぶ
    /// - ローカルアドレスで選べない場合は、リモートアドレスのファミリに
    ///   合うソケットへフォールバックする (4-tuple の反映が遅れたパスでも
    ///   ファミリの合わないソケットを掴まないため)
    ///
    /// どちらのファミリのソケットも無ければ、初期ソケットと同じポートで
    /// 追加ソケットを作成する。
    pub fn socket_for_path(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> io::Result<Arc<UdpSocket>> {
        if !local.ip().is_unspecified() {
            // 追加パス / 4-tuple 移行で専用にバインドしたソケットは IP と
            // ポートの両方が一致するため、初期ソケットより優先する。
            // ただしリモートのアドレスファミリを扱えないソケットは選ばない
            // (IPv4 ソケットに IPv6 宛を渡すと送信できない)。
            if let Some(socket) = self.find_socket_exact(local)
                && Self::socket_can_reach(&socket, remote)
            {
                return Ok(socket);
            }
            if local.port() == 0
                && let Some(socket) = self.find_socket(local)
                && Self::socket_can_reach(&socket, remote)
            {
                return Ok(socket);
            }
        }
        self.socket_for_remote(remote)
    }

    /// ソケットがリモートアドレスのアドレスファミリを扱えるかを返す
    ///
    /// アドレスファミリが異なるソケットでは送信できない。IPv6 ソケットから
    /// IPv4 宛に送る場合は v4-mapped に変換できるが、`IPV6_V6ONLY` の設定に
    /// 依存するため、ここでは保守的にファミリの一致だけを認める。
    fn socket_can_reach(socket: &Arc<UdpSocket>, remote: SocketAddr) -> bool {
        socket
            .local_addr()
            .is_ok_and(|bound| bound.is_ipv6() == remote.is_ipv6())
    }

    /// 現在の全ソケットを返す
    ///
    /// 受信タスクの起動に使う。登録済みの追加ソケットの受信タスクが未起動の場合は
    /// 呼び出し側で起動すること。
    pub fn sockets(&self) -> Vec<Arc<UdpSocket>> {
        let additional = self
            .additional
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut sockets = vec![Arc::clone(&self.primary)];
        sockets.extend(additional.iter().cloned());
        sockets
    }

    /// リモートアドレスに送信するためのソケットを選ぶ
    ///
    /// ローカルアドレスが unspecified のとき、またはローカルアドレスを扱える
    /// ソケットが無いときに使う。宛先アドレスと同じアドレスファミリを扱える
    /// ソケットを返し、無ければ初期ソケットと同じポートで追加ソケットを作成する。
    fn socket_for_remote(&self, remote: SocketAddr) -> io::Result<Arc<UdpSocket>> {
        if let Some(socket) = self.find_socket(remote) {
            return Ok(socket);
        }
        self.ensure_family_socket(remote.is_ipv6())
    }

    /// 指定したアドレスファミリのソケットを、初期ソケットと同じポートで追加する
    ///
    /// まだ追加されていない場合だけバインドする。サーバーが両ファミリで
    /// 待ち受けるために起動時に呼ぶ。追加した IPv6 ソケットは常に
    /// `IPV6_V6ONLY` である (両ファミリを別ソケットで待ち受けるため、
    /// v4-mapped を受け入れる必要がない)。
    ///
    /// 同じポートを他プロセスが使っているなど、バインドできない場合は
    /// エラーを返す。サーバーはそのファミリを提供しない縮退動作を選べる。
    pub fn bind_family(&self, ipv6: bool) -> io::Result<Arc<UdpSocket>> {
        self.ensure_family_socket(ipv6)
    }

    /// 指定したアドレスファミリのソケットを返す (無ければ初期ソケットと同じポートで作成する)
    fn ensure_family_socket(&self, ipv6: bool) -> io::Result<Arc<UdpSocket>> {
        let primary_addr = self.primary.local_addr()?;
        // 特定アドレスへの bind を越えて、別ファミリの wildcard で待ち受けない。
        // 利用者が指定した公開範囲を広げないための境界。
        if ipv6 != primary_addr.is_ipv6() && !self.allow_dual_stack {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "refusing to bind {} wildcard for a socket bound to {primary_addr}",
                    if ipv6 { "IPv6" } else { "IPv4" }
                ),
            ));
        }
        let port = primary_addr.port();
        let unspecified = if ipv6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        let addr = SocketAddr::new(unspecified, port);
        // ワイルドカードアドレスは find_socket が同じファミリのソケットに
        // 一致するため、既存ソケットがあればそれが返る。
        if let Some(socket) = self.find_socket(addr) {
            return Ok(socket);
        }
        // 追加する IPv6 ソケットは必ず `IPV6_V6ONLY` にする。v4-mapped を
        // 受け入れる IPv6 ソケットは同じポートの IPv4 ソケットと受信範囲が
        // 重なるため、IPv4 パケットがどちらのソケットに届くか決まらなくなる。
        // さらに Linux は、同じポートを既に使っている IPv4 ソケットが
        // `SO_REUSEADDR` を持たない場合、重なる IPv6 ワイルドカードの
        // バインドを `EADDRINUSE` で拒否する。IPv4 宛の送信は IPv4 ソケットが
        // 担うため、v6only でもデュアルスタックのパスは扱える。
        let socket = Arc::new(bind_additional_socket_with_reuse_port(
            addr,
            ipv6,
            ipv6,
            self.batch,
            self.reuse_port,
        )?);
        self.add_socket(Arc::clone(&socket))?;
        Ok(socket)
    }
}

/// プールの初期ソケットをバインドして pktinfo を有効化する
///
/// クライアントとサーバーの初期ソケットで使う。`SO_REUSEADDR` と
/// `SO_REUSEPORT` を設定するのは、同じポートを別のアドレスファミリの
/// ソケット (追加パス用) と共有するためである。Linux では、初期ソケットが
/// `SO_REUSEADDR` を持たないと、同じポートを覆うもう一方のファミリの
/// バインドが `EADDRINUSE` になる。
///
/// `IPV6_V6ONLY` は OS の既定値に任せる。初期ソケットは接続に使うアドレス
/// そのものなので、利用者が指定した待ち受けアドレスの意味を変えないためである。
///
/// 初期ソケットと同じ条件のプールを作るテストからも使うため公開している。
/// 通常は `Client` / `Server` 経由で使う。
pub fn bind_primary_socket(
    addr: SocketAddr,
    batch: Option<UdpBatchConfig>,
) -> io::Result<UdpSocket> {
    bind_primary_socket_with_reuse_port(addr, batch, true)
}

/// `SO_REUSEPORT` の有無を指定して初期ソケットをバインドする
///
/// `SO_REUSEPORT` を無効にすると、同じポートへの別プロセスの bind を OS が
/// 拒否する。信頼できないローカルユーザーがいる環境で、ポートの共有を
/// 避けたい場合に使う。デュアルスタックの追加ソケットは同じポートを共有する
/// ため、無効にすると別アドレスファミリの待ち受けを作れないことがある。
pub fn bind_primary_socket_with_reuse_port(
    addr: SocketAddr,
    batch: Option<UdpBatchConfig>,
    reuse_port: bool,
) -> io::Result<UdpSocket> {
    bind_udp_socket(addr, addr.is_ipv6(), None, batch, reuse_port, true)
}

/// SO_REUSEPORT + SO_REUSEADDR を設定した UDP ソケットをバインドして pktinfo を有効化する
///
/// アドレスファミリを共有する追加ソケットで使う。`SO_REUSEPORT` を設定しないと、
/// 同じポートで別ファミリのソケットを追加バインドできない環境がある。
/// 追加パス / 移行専用のソケットはこの関数ではなく、reuse を無効にした
/// 専用ソケットとしてバインドする。
///
/// `v6only` は呼び出し側が指定する。`SocketPool` は同じポートを両ファミリの
/// 別ソケットで待ち受けるため IPv6 ソケットには常に true を渡す。v4-mapped を
/// 受け入れると、IPv4 のパケットが IPv4 ソケットと IPv6 ソケットの
/// どちらでも受信できてしまい、かつ Linux では同じポートを既に使っている
/// IPv4 ソケットが `SO_REUSEADDR` を持たない場合にバインド自体が
/// `EADDRINUSE` で失敗する。
///
/// 同じポートで 2 つのアドレスファミリのソケットを用意するデュアルスタックの
/// テストからも使うため公開している。通常は `SocketPool` 経由で使う。
pub fn bind_additional_socket(
    addr: SocketAddr,
    ipv6: bool,
    v6only: bool,
    batch: Option<UdpBatchConfig>,
) -> io::Result<UdpSocket> {
    bind_additional_socket_with_reuse_port(addr, ipv6, v6only, batch, true)
}

/// `SO_REUSEPORT` の有無を指定して追加ソケットをバインドする
///
/// `SocketPool` がサーバーの `reuse_port` 設定を反映するために使う。
/// 公開 API の [`bind_additional_socket`] は常に `SO_REUSEPORT` を設定する。
fn bind_additional_socket_with_reuse_port(
    addr: SocketAddr,
    ipv6: bool,
    v6only: bool,
    batch: Option<UdpBatchConfig>,
    reuse_port: bool,
) -> io::Result<UdpSocket> {
    bind_udp_socket(addr, ipv6, ipv6.then_some(v6only), batch, reuse_port, true)
}

/// 追加パス / 移行専用のソケットをバインドする
///
/// `SO_REUSEADDR` と `SO_REUSEPORT` を設定しない。指定したローカルアドレスが
/// 既存ソケットと受信範囲で重なる場合は bind の失敗として返し、ポート共有で
/// 重複 bind を成功させない。IPv6 ソケットでは `IPV6_V6ONLY` を立てる。
/// 完全一致する既存ソケットの再利用は呼び出し側が先に行うため、ここへは
/// 新規に確保する場合だけ到達する。
fn bind_dedicated_socket(addr: SocketAddr, batch: Option<UdpBatchConfig>) -> io::Result<UdpSocket> {
    bind_udp_socket(
        addr,
        addr.is_ipv6(),
        addr.is_ipv6().then_some(true),
        batch,
        false,
        false,
    )
}

/// UDP ソケットをバインドして pktinfo を有効化する
///
/// `v6only` が `None` の場合は `IPV6_V6ONLY` を設定せず OS の既定値に任せる。
/// `set_only_v6` は IPv6 ソケットでのみ有効なため、IPv4 ソケットでは呼ばない。
fn bind_udp_socket(
    addr: SocketAddr,
    ipv6: bool,
    v6only: Option<bool>,
    batch: Option<UdpBatchConfig>,
    reuse_port: bool,
    reuse_address: bool,
) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if reuse_address {
        socket.set_reuse_address(true)?;
    }
    #[cfg(unix)]
    if reuse_port {
        socket.set_reuse_port(true)?;
    }
    if let Some(v6only) = v6only {
        socket.set_only_v6(v6only)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    enable_pktinfo_raw(&socket)?;
    // 設定で有効にした場合だけ受信側の GRO を有効化する
    if batch.is_some_and(|config| config.offload) {
        enable_rx_offload(socket.as_raw_fd())?;
    }
    // DPLPMTUD のプローブは現在の PMTU より大きいデータグラムを送るため、
    // カーネルによる経路 MTU の強制を止めて DF を立てる
    // (RFC 8899 Section 3 / Section 4.5)。プローブかどうかで option を
    // 切り替えると送信ごとに setsockopt が必要になるため、ソケット生成時に
    // 一度だけ設定する。
    enable_mtu_discovery_probe(socket.as_raw_fd(), ipv6)?;
    UdpSocket::from_std(socket.into())
}

#[cfg(test)]
mod tests;
