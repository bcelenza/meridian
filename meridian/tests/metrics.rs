//! Integration tests for the meridian metrics module.
//!
//! These tests verify that [`VfsEvent`]s are correctly translated into
//! OpenTelemetry metrics using an in-memory exporter.  No eBPF probes or
//! root privileges are required.
//!
//! Run with: `cargo test --test metrics`

use meridian::metrics::MetricsRecorder;
use meridian_common::{IoOp, VfsEvent, COMM_LEN};
use opentelemetry::metrics::MeterProvider;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a synthetic [`VfsEvent`].
fn make_event(op: u8, bytes: u64, latency_ns: u64, cache_hit: u8, comm: &str) -> VfsEvent {
    let mut c = [0u8; COMM_LEN];
    let b = comm.as_bytes();
    let len = b.len().min(COMM_LEN - 1);
    c[..len].copy_from_slice(&b[..len]);
    VfsEvent {
        pid: 1234,
        comm: c,
        op,
        cache_hit,
        _pad: [0; 2],
        bytes,
        latency_ns,
        timestamp_ns: 1_000_000_000,
    }
}

/// Create a `SdkMeterProvider` backed by an [`InMemoryMetricExporter`].
fn setup() -> (SdkMeterProvider, InMemoryMetricExporter) {
    let exporter = InMemoryMetricExporter::default();
    let reader = PeriodicReader::builder(exporter.clone()).build();
    let provider = SdkMeterProvider::builder().with_reader(reader).build();
    (provider, exporter)
}

/// Locate metric data by name inside exported [`ResourceMetrics`].
fn find_metric_data<'a>(
    resource_metrics: &'a [ResourceMetrics],
    name: &str,
) -> Option<&'a AggregatedMetrics> {
    for rm in resource_metrics {
        for sm in rm.scope_metrics() {
            for m in sm.metrics() {
                if m.name() == name {
                    return Some(m.data());
                }
            }
        }
    }
    None
}

/// Extract the total value from a `Sum<u64>` metric (summing across all
/// data-points / attribute combinations).
fn sum_u64_total(resource_metrics: &[ResourceMetrics], name: &str) -> u64 {
    let data = find_metric_data(resource_metrics, name)
        .unwrap_or_else(|| panic!("metric {name} not found"));
    match data {
        AggregatedMetrics::U64(MetricData::Sum(sum)) => {
            sum.data_points().map(|dp| dp.value()).sum()
        }
        other => panic!("expected Sum<u64> for {name}, got {other:?}"),
    }
}

/// Count data-points in a `Sum<u64>` metric.
fn sum_u64_dp_count(resource_metrics: &[ResourceMetrics], name: &str) -> usize {
    let data = find_metric_data(resource_metrics, name)
        .unwrap_or_else(|| panic!("metric {name} not found"));
    match data {
        AggregatedMetrics::U64(MetricData::Sum(sum)) => sum.data_points().count(),
        other => panic!("expected Sum<u64> for {name}, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Both metric instruments should be emitted after recording a single event.
#[test]
fn test_all_metrics_emitted() {
    let (provider, exporter) = setup();
    let meter = provider.meter("test");
    let recorder = MetricsRecorder::with_hostname(&meter, "test-host".into());

    recorder.record_event(&make_event(IoOp::Read as u8, 1024, 5_000, 1, "myapp"));

    provider.force_flush().unwrap();
    let metrics = exporter.get_finished_metrics().unwrap();

    assert!(
        find_metric_data(&metrics, "meridian.io.bytes").is_some(),
        "missing meridian.io.bytes"
    );
    assert!(
        find_metric_data(&metrics, "meridian.io.latency").is_some(),
        "missing meridian.io.latency"
    );

    let _ = provider.shutdown();
}

/// The bytes counter should accumulate the exact byte counts from all events.
#[test]
fn test_byte_counts() {
    let (provider, exporter) = setup();
    let meter = provider.meter("test");
    let recorder = MetricsRecorder::with_hostname(&meter, "test-host".into());

    recorder.record_event(&make_event(IoOp::Read as u8, 1024, 1_000, 1, "app"));
    recorder.record_event(&make_event(IoOp::Write as u8, 2048, 2_000, 0, "app"));

    provider.force_flush().unwrap();
    let metrics = exporter.get_finished_metrics().unwrap();

    assert_eq!(
        sum_u64_total(&metrics, "meridian.io.bytes"),
        3072,
        "expected 1024 + 2048 = 3072 bytes"
    );

    let _ = provider.shutdown();
}

/// The latency histogram should record the correct count and sum.
#[test]
fn test_latency_histogram_values() {
    let (provider, exporter) = setup();
    let meter = provider.meter("test");
    let recorder = MetricsRecorder::with_hostname(&meter, "test-host".into());

    // 5 000 000 ns = 0.005 s
    recorder.record_event(&make_event(IoOp::Read as u8, 100, 5_000_000, 1, "app"));

    provider.force_flush().unwrap();
    let metrics = exporter.get_finished_metrics().unwrap();

    let data = find_metric_data(&metrics, "meridian.io.latency")
        .expect("missing meridian.io.latency");

    match data {
        AggregatedMetrics::F64(MetricData::Histogram(hist)) => {
            let dps: Vec<_> = hist.data_points().collect();
            assert!(!dps.is_empty(), "no histogram data points");
            let dp = dps[0];
            assert_eq!(dp.count(), 1, "expected 1 recorded sample");
            let expected_sum = 5_000_000.0;
            assert!(
                (dp.sum() - expected_sum).abs() < 1e-6,
                "expected latency sum ≈ {expected_sum} ns, got {}",
                dp.sum()
            );
        }
        other => panic!("expected Histogram<f64>, got {other:?}"),
    }

    let _ = provider.shutdown();
}

/// Every data-point must carry the four required attributes:
/// `comm`, `op`, `cache_hit`, `hostname`.
#[test]
fn test_attributes_present() {
    let (provider, exporter) = setup();
    let meter = provider.meter("test");
    let recorder = MetricsRecorder::with_hostname(&meter, "test-host".into());

    recorder.record_event(&make_event(IoOp::Read as u8, 512, 1_000, 1, "myapp"));

    provider.force_flush().unwrap();
    let metrics = exporter.get_finished_metrics().unwrap();

    let data = find_metric_data(&metrics, "meridian.io.bytes")
        .expect("missing meridian.io.bytes");

    match data {
        AggregatedMetrics::U64(MetricData::Sum(sum)) => {
            let dps: Vec<_> = sum.data_points().collect();
            assert_eq!(dps.len(), 1);
            let dp = dps[0];
            let keys: Vec<String> = dp.attributes().map(|kv| kv.key.to_string()).collect();
            for expected in &["comm", "op", "cache_hit", "hostname"] {
                assert!(
                    keys.contains(&expected.to_string()),
                    "missing attribute '{expected}'; present: {keys:?}"
                );
            }
        }
        other => panic!("expected Sum<u64>, got {other:?}"),
    }

    let _ = provider.shutdown();
}

/// Reads and writes with different attribute sets must produce separate
/// data-points in the aggregation.
#[test]
fn test_read_write_separated_by_op() {
    let (provider, exporter) = setup();
    let meter = provider.meter("test");
    let recorder = MetricsRecorder::with_hostname(&meter, "test-host".into());

    recorder.record_event(&make_event(IoOp::Read as u8, 100, 1_000, 0, "app"));
    recorder.record_event(&make_event(IoOp::Write as u8, 200, 2_000, 0, "app"));

    provider.force_flush().unwrap();
    let metrics = exporter.get_finished_metrics().unwrap();

    let count = sum_u64_dp_count(&metrics, "meridian.io.bytes");
    assert_eq!(count, 2, "expected 2 data-points (read + write), got {count}");

    // 100 + 200
    assert_eq!(
        sum_u64_total(&metrics, "meridian.io.bytes"),
        300,
        "expected total of 300 bytes"
    );

    let _ = provider.shutdown();
}

/// Cache-hit vs cache-miss for the same operation type must produce
/// distinct data-points.
#[test]
fn test_cache_hit_attribute_splits_datapoints() {
    let (provider, exporter) = setup();
    let meter = provider.meter("test");
    let recorder = MetricsRecorder::with_hostname(&meter, "test-host".into());

    // Two reads from the same comm — one cached, one not.
    recorder.record_event(&make_event(IoOp::Read as u8, 100, 1_000, 1, "app"));
    recorder.record_event(&make_event(IoOp::Read as u8, 200, 2_000, 0, "app"));

    provider.force_flush().unwrap();
    let metrics = exporter.get_finished_metrics().unwrap();

    let count = sum_u64_dp_count(&metrics, "meridian.io.bytes");
    assert_eq!(
        count, 2,
        "expected 2 data-points (cache_hit true + false), got {count}"
    );

    let _ = provider.shutdown();
}

/// Multiple events from different commands should produce separate
/// data-points per comm.
#[test]
fn test_multiple_comms_separated() {
    let (provider, exporter) = setup();
    let meter = provider.meter("test");
    let recorder = MetricsRecorder::with_hostname(&meter, "test-host".into());

    recorder.record_event(&make_event(IoOp::Read as u8, 100, 1_000, 0, "app_a"));
    recorder.record_event(&make_event(IoOp::Read as u8, 200, 2_000, 0, "app_b"));

    provider.force_flush().unwrap();
    let metrics = exporter.get_finished_metrics().unwrap();

    let count = sum_u64_dp_count(&metrics, "meridian.io.bytes");
    assert_eq!(
        count, 2,
        "expected 2 data-points (app_a + app_b), got {count}"
    );

    let _ = provider.shutdown();
}
