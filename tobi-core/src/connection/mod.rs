// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 接続に関する型定義

mod config;
mod event;
mod observation;
mod output;
mod state;
mod version_information;

pub use config::{
    ConnectionCloseFormatter, ConnectionConfig, ConnectionIdGenerator, EndpointLimits, MtuConfig,
    SilentConnectionCloseFormatter, StatelessResetTokenGenerator,
};
pub use event::{ConnectionCloseKind, ConnectionEvent};
pub use observation::ConnectionObservationEvent;
pub use output::{ConnectionOutput, EcnCodepoint};
pub use state::{ConnectionState, TimerId};
pub use version_information::{
    is_compatible_version, select_server_negotiated_version, validate_peer_version_information,
};
