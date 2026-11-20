// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use iota_sdk_grpc_client::GrpcClient;
use tracing_subscriber::layer::{Context, SubscriberExt};

/// Collects span names, and span and event fields as `name=value`.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);

impl tracing::field::Visit for Capture {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.lock().unwrap().push(format!("{field}={value:?}"));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.lock().unwrap().push(format!("{field}={value}"));
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _: &tracing::span::Id,
        _: Context<'_, S>,
    ) {
        let name = attrs.metadata().name();
        self.0.lock().unwrap().push(format!("span={name}"));
        attrs.record(&mut self.clone());
    }

    fn on_record(
        &self,
        _: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        _: Context<'_, S>,
    ) {
        values.record(&mut self.clone());
    }

    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        event.record(&mut self.clone());
    }
}

// The subscriber is only the default on this thread, and a callsite first
// reached from another test's thread would be cached as disabled, so this
// stays the only test in the file.
#[tokio::test]
async fn rpc_emits_a_span_with_its_fields() {
    let capture = Capture::default();
    let _guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));

    // Nothing listens on this port, so the call fails as unavailable.
    let client = GrpcClient::new("http://127.0.0.1:1").unwrap();
    client.health().await.unwrap_err();

    let captured = capture.0.lock().unwrap();
    for expected in [
        "span=grpc_request",
        "rpc.system=grpc",
        "rpc.service=iota.grpc.v1.ledger_service.LedgerService",
        "rpc.method=GetHealth",
        "server.address=127.0.0.1",
        "rpc.grpc.status_code=14",
        "message=rpc failed",
    ] {
        assert!(
            captured.iter().any(|c| c == expected),
            "{expected}: {captured:?}"
        );
    }
    assert!(
        captured.iter().any(|c| c.starts_with("elapsed_ms=")),
        "{captured:?}"
    );
}
