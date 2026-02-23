//! Metrics module for recording I/O events via OpenTelemetry.
//!
//! Provides [`MetricsRecorder`] for translating [`VfsEvent`]s into OTel
//! metrics and [`init_otlp_metrics`] for bootstrapping the OTLP gRPC
//! export pipeline.

use meridian_common::VfsEvent;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry::KeyValue;

/// Get the system hostname.
fn get_hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Records I/O metrics from VFS events using OpenTelemetry instruments.
///
/// Two instruments are maintained:
///
/// | Metric                      | Type      | Unit | Description                  |
/// |-----------------------------|-----------|------|------------------------------|
/// | `meridian.io.bytes`         | Counter   | By   | Total bytes transferred      |
/// | `meridian.io.latency`       | Histogram | ns   | Per-operation I/O latency    |
///
/// Every data-point carries the following attributes:
/// `comm`, `op`, `cache_hit`, `hostname`.
pub struct MetricsRecorder {
    io_bytes: Counter<u64>,
    io_latency: Histogram<f64>,
    hostname: String,
}

impl MetricsRecorder {
    /// Create a new `MetricsRecorder` using the system hostname.
    pub fn new(meter: &Meter) -> Self {
        Self::with_hostname(meter, get_hostname())
    }

    /// Create a new `MetricsRecorder` with an explicit hostname.
    ///
    /// This is primarily useful for testing where a deterministic hostname
    /// is desirable.
    pub fn with_hostname(meter: &Meter, hostname: String) -> Self {
        let io_bytes = meter
            .u64_counter("meridian.io.bytes")
            .with_description("Total bytes transferred")
            .with_unit("By")
            .build();

        let io_latency = meter
            .f64_histogram("meridian.io.latency")
            .with_description("I/O operation latency")
            .with_unit("ns")
            .build();

        Self {
            io_bytes,
            io_latency,
            hostname,
        }
    }

    /// Record metrics for a single VFS I/O event.
    pub fn record_event(&self, event: &VfsEvent) {
        let comm = crate::comm_to_string(&event.comm);
        let op = crate::op_to_str(event.op);
        let cache_hit = event.cache_hit != 0;

        let attrs = [
            KeyValue::new("comm", comm),
            KeyValue::new("op", op),
            KeyValue::new("cache_hit", cache_hit),
            KeyValue::new("hostname", self.hostname.clone()),
        ];

        self.io_bytes.add(event.bytes, &attrs);
        self.io_latency.record(event.latency_ns as f64, &attrs);
    }
}

/// Initialise an OTLP gRPC metrics export pipeline.
///
/// Returns a [`SdkMeterProvider`](opentelemetry_sdk::metrics::SdkMeterProvider)
/// that **must** be kept alive for the duration of the program.  Call
/// [`shutdown()`](opentelemetry_sdk::metrics::SdkMeterProvider::shutdown)
/// before dropping to flush any remaining data.
pub fn init_otlp_metrics(
    endpoint: &str,
) -> anyhow::Result<opentelemetry_sdk::metrics::SdkMeterProvider> {
    use opentelemetry_otlp::{MetricExporter, WithExportConfig};
    use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};

    let exporter = MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    let reader = PeriodicReader::builder(exporter).build();

    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .build();

    Ok(provider)
}
