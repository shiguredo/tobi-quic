// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! ストリーム状態マシン (RFC 9000 Section 3)

use tobi_core::error::{Error, TransportErrorCode};

/// 送信状態 (RFC 9000 Section 3.1)
///
/// Ready → Send → DataSent → DataRecvd (終端)
/// Ready|Send|DataSent → ResetSent → ResetRecvd (終端)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendState {
    /// 初期状態: アプリケーションからデータを受け付ける
    Ready,
    /// STREAM フレーム送信中
    Send,
    /// FIN 付き STREAM フレームを送信済み、ACK 待ち
    DataSent,
    /// 全データが ACK された (終端)
    DataRecvd,
    /// RESET_STREAM を送信済み、ACK 待ち
    ResetSent,
    /// RESET_STREAM が ACK された (終端)
    ResetRecvd,
}

impl SendState {
    /// 終端状態かどうか
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::DataRecvd | Self::ResetRecvd)
    }

    /// Send 状態へ遷移する (最初の STREAM フレーム送信時)
    pub fn transition_to_send(self) -> Result<Self, Error> {
        match self {
            Self::Ready => Ok(Self::Send),
            _ => Err(stream_state_error("transition_to_send", self)),
        }
    }

    /// DataRecvd 状態へ遷移する (全データ ACK 時)
    pub fn transition_to_data_recvd(self) -> Result<Self, Error> {
        match self {
            Self::DataSent => Ok(Self::DataRecvd),
            _ => Err(stream_state_error("transition_to_data_recvd", self)),
        }
    }

    /// ResetSent 状態へ遷移する (RESET_STREAM 送信時)
    pub fn transition_to_reset_sent(self) -> Result<Self, Error> {
        match self {
            Self::Ready | Self::Send | Self::DataSent => Ok(Self::ResetSent),
            _ => Err(stream_state_error("transition_to_reset_sent", self)),
        }
    }

    /// ResetRecvd 状態へ遷移する (RESET_STREAM の ACK 受信時)
    pub fn transition_to_reset_recvd(self) -> Result<Self, Error> {
        match self {
            Self::ResetSent => Ok(Self::ResetRecvd),
            _ => Err(stream_state_error("transition_to_reset_recvd", self)),
        }
    }
}

/// 受信状態 (RFC 9000 Section 3.2)
///
/// Recv → SizeKnown → DataRecvd → DataRead (終端)
/// Recv|SizeKnown → ResetRecvd → ResetRead (終端)
/// DataRecvd → ResetRecvd も可 (任意)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvState {
    /// 初期状態: STREAM フレームを受信中
    Recv,
    /// FIN を受信し、最終サイズが確定
    SizeKnown,
    /// 全データを受信済み、アプリケーション読み取り待ち
    DataRecvd,
    /// アプリケーションが全データを読み取った (終端)
    DataRead,
    /// RESET_STREAM を受信
    ResetRecvd,
    /// アプリケーションがリセットを確認した (終端)
    ResetRead,
}

impl RecvState {
    /// 終端状態かどうか
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::DataRead | Self::ResetRead)
    }

    /// SizeKnown 状態へ遷移する (FIN 受信時)
    pub fn transition_to_size_known(self) -> Result<Self, Error> {
        match self {
            Self::Recv => Ok(Self::SizeKnown),
            _ => Err(stream_state_error("transition_to_size_known", self)),
        }
    }

    /// DataRecvd 状態へ遷移する (全データ受信時)
    pub fn transition_to_data_recvd(self) -> Result<Self, Error> {
        match self {
            Self::SizeKnown => Ok(Self::DataRecvd),
            _ => Err(stream_state_error("transition_to_data_recvd", self)),
        }
    }

    /// DataRead 状態へ遷移する (アプリケーションが全データ読み取り時)
    pub fn transition_to_data_read(self) -> Result<Self, Error> {
        match self {
            Self::DataRecvd => Ok(Self::DataRead),
            _ => Err(stream_state_error("transition_to_data_read", self)),
        }
    }

    /// ResetRecvd 状態へ遷移する (RESET_STREAM 受信時)
    pub fn transition_to_reset_recvd(self) -> Result<Self, Error> {
        match self {
            Self::Recv | Self::SizeKnown | Self::DataRecvd => Ok(Self::ResetRecvd),
            _ => Err(stream_state_error("transition_to_reset_recvd", self)),
        }
    }

    /// ResetRead 状態へ遷移する (アプリケーションがリセット確認時)
    pub fn transition_to_reset_read(self) -> Result<Self, Error> {
        match self {
            Self::ResetRecvd => Ok(Self::ResetRead),
            _ => Err(stream_state_error("transition_to_reset_read", self)),
        }
    }
}

/// 不正な状態遷移エラーを生成する
fn stream_state_error(transition: &str, state: impl core::fmt::Debug) -> Error {
    Error::Protocol {
        code: TransportErrorCode::STREAM_STATE_ERROR,
        reason: format!("{transition} called in invalid state {state:?}"),
    }
}
