// Copyright 2026 Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! qlog JSON-SEQ writer (draft-ietf-quic-qlog-main-schema-14)
//!
//! `tobi_qlog::QlogWriter` トレイトの std 依存実装。
//! `std::io::Write` を受け取る writer 実体は本体クレート側で提供する。

use std::io::Write;

use tobi_qlog::{
    PacketHeader, ParametersSet, QlogFrame, QlogFrames, QlogWriter, TransportParametersSet,
};

/// JSON-SEQ (RFC 7464) 形式で qlog を出力する
///
/// draft-ietf-quic-qlog-main-schema-14 の QlogFileSeq スキーマに準拠。
///
/// 各イベントは `writer` へ同期的に書き込む。`writer` がブロッキングすると
/// 接続処理が遅延するため、ファイルやパイプにはバッファリングや別スレッド
/// への委譲を検討すること (tobi_qlog::QlogWriter の実装上の注意を参照)。
pub struct JsonSeqQlogWriter {
    writer: Box<dyn Write + Send>,
}

impl JsonSeqQlogWriter {
    /// 新しい JsonSeqQlogWriter を作成し、ヘッダーを出力する
    pub fn new(
        mut writer: Box<dyn Write + Send>,
        title: &str,
        vantage_type: &str,
    ) -> std::io::Result<Self> {
        // JSON-SEQ ヘッダー (最初のレコード)
        let header = nojson::object(|f| {
            // ファイルスキーマとシリアライズ形式は
            // draft-ietf-quic-qlog-main-schema-14 に従う
            // (Section 5 の JSON-SEQ 例、Section 15.1.2 の Media Type)
            f.member("file_schema", "urn:ietf:params:qlog:file:sequential")?;
            f.member("serialization_format", "application/qlog+json-seq")?;
            f.member("title", title)?;
            f.member(
                "trace",
                nojson::object(|f| {
                    f.member(
                        "vantage_point",
                        nojson::object(|f| f.member("type", vantage_type)),
                    )?;
                    // draft 版のイベントスキーマ URI は URI の末尾に draft 番号を
                    // 付ける MUST がある
                    // (draft-ietf-quic-qlog-quic-events-13 Section 2.1)。
                    // 本実装はイベント定義の draft 13 に対応している。
                    f.member(
                        "event_schemas",
                        nojson::array(|f| f.element("urn:ietf:params:qlog:events:quic-13")),
                    )
                }),
            )
        });
        writeln!(writer, "\x1e{header}")?;
        Ok(Self { writer })
    }

    /// イベントを JSON-SEQ レコードとして出力する
    fn write_event(&mut self, time_ms: f64, name: &str, data: impl nojson::DisplayJson) {
        let event = nojson::object(|f| {
            f.member("time", time_ms)?;
            f.member("name", name)?;
            f.member("data", &data)
        });
        let _ = writeln!(self.writer, "\x1e{event}");
    }

    /// writer をフラッシュする
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

impl QlogWriter for JsonSeqQlogWriter {
    fn on_packet_sent(
        &mut self,
        time_ms: f64,
        header: &PacketHeader,
        frames: &[QlogFrame],
        raw_length: usize,
    ) {
        self.write_event(
            time_ms,
            "quic:packet_sent",
            nojson::object(|f| {
                f.member("header", header)?;
                f.member("frames", QlogFrames(frames))?;
                f.member("raw", nojson::object(|f| f.member("length", raw_length)))
            }),
        );
    }

    fn on_packet_received(
        &mut self,
        time_ms: f64,
        header: &PacketHeader,
        frames: &[QlogFrame],
        raw_length: usize,
    ) {
        self.write_event(
            time_ms,
            "quic:packet_received",
            nojson::object(|f| {
                f.member("header", header)?;
                f.member("frames", QlogFrames(frames))?;
                f.member("raw", nojson::object(|f| f.member("length", raw_length)))
            }),
        );
    }

    fn on_connection_state_updated(&mut self, time_ms: f64, old: &str, new: &str) {
        self.write_event(
            time_ms,
            "quic:connection_state_updated",
            nojson::object(|f| {
                f.member("old", old)?;
                f.member("new", new)
            }),
        );
    }

    fn on_parameters_set(
        &mut self,
        time_ms: f64,
        initiator: &str,
        params: &TransportParametersSet,
    ) {
        // qlog-quic-events-13 Section 5.3: initiator とパラメータを同じ階層に置く。
        self.write_event(
            time_ms,
            "quic:parameters_set",
            ParametersSet {
                initiator,
                transport_parameters: params,
            },
        );
    }

    fn on_packet_lost(&mut self, time_ms: f64, header: &PacketHeader) {
        self.write_event(
            time_ms,
            "quic:packet_lost",
            nojson::object(|f| f.member("header", header)),
        );
    }

    fn on_recovery_metrics_updated(
        &mut self,
        time_ms: f64,
        min_rtt_ms: f64,
        smoothed_rtt_ms: f64,
        latest_rtt_ms: f64,
        congestion_window: u64,
    ) {
        self.write_event(
            time_ms,
            "quic:recovery_metrics_updated",
            nojson::object(|f| {
                f.member("min_rtt", min_rtt_ms)?;
                f.member("smoothed_rtt", smoothed_rtt_ms)?;
                f.member("latest_rtt", latest_rtt_ms)?;
                f.member("congestion_window", congestion_window)
            }),
        );
    }

    fn on_key_updated(
        &mut self,
        time_ms: f64,
        key_type: &str,
        key_phase: Option<u64>,
        trigger: &str,
    ) {
        self.write_event(
            time_ms,
            "quic:key_updated",
            nojson::object(|f| {
                f.member("key_type", key_type)?;
                if let Some(key_phase) = key_phase {
                    f.member("key_phase", key_phase)?;
                }
                f.member("trigger", trigger)
            }),
        );
    }

    fn on_ecn_state_updated(&mut self, time_ms: f64, old: &str, new: &str) {
        self.write_event(
            time_ms,
            "quic:ecn_state_updated",
            nojson::object(|f| {
                f.member("old", old)?;
                f.member("new", new)
            }),
        );
    }

    fn on_mtu_updated(&mut self, time_ms: f64, old: u32, new: u32, done: bool) {
        self.write_event(
            time_ms,
            "quic:mtu_updated",
            nojson::object(|f| {
                f.member("old", old)?;
                f.member("new", new)?;
                f.member("done", done)
            }),
        );
    }

    fn on_version_information(
        &mut self,
        time_ms: f64,
        client_versions: &[u32],
        server_versions: &[u32],
        chosen_version: Option<u32>,
    ) {
        // QuicVersion は hexstring なので 8 桁の 16 進で出力する
        let to_hex = |v: u32| format!("{v:08x}");
        self.write_event(
            time_ms,
            "quic:version_information",
            nojson::object(|f| {
                f.member(
                    "client_versions",
                    nojson::array(|f| {
                        for v in client_versions {
                            f.element(to_hex(*v))?;
                        }
                        Ok(())
                    }),
                )?;
                f.member(
                    "server_versions",
                    nojson::array(|f| {
                        for v in server_versions {
                            f.element(to_hex(*v))?;
                        }
                        Ok(())
                    }),
                )?;
                if let Some(chosen) = chosen_version {
                    f.member("chosen_version", to_hex(chosen))?;
                }
                Ok(())
            }),
        );
    }

    fn on_connection_closed(
        &mut self,
        time_ms: f64,
        error_code: Option<u64>,
        reason: Option<&str>,
        trigger: &str,
    ) {
        self.write_event(
            time_ms,
            "quic:connection_closed",
            nojson::object(|f| {
                if let Some(error_code) = error_code {
                    f.member("error_code", error_code)?;
                }
                if let Some(reason) = reason {
                    f.member("reason", reason)?;
                }
                f.member("trigger", trigger)
            }),
        );
    }

    fn on_packet_dropped(&mut self, time_ms: f64, trigger: &str, details: Option<&str>) {
        self.write_event(
            time_ms,
            "quic:packet_dropped",
            nojson::object(|f| {
                if let Some(details) = details {
                    f.member("details", nojson::object(|f| f.member("reason", details)))?;
                }
                f.member("trigger", trigger)
            }),
        );
    }
}
