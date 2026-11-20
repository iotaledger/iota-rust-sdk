// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(not(target_arch = "wasm32"))]

use std::sync::{Arc, Mutex};

use iota_sdk_graphql_client::GraphQLClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
async fn request_emits_a_span_with_its_fields() {
    let capture = Capture::default();
    let _guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"}") {
            let mut chunk = [0; 4096];
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0, "connection closed before the request body");
            request.extend_from_slice(&chunk[..read]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 23\r\nconnection: close\r\n\r\n{\"data\":{\"epoch\":null}}")
            .await
            .unwrap();
    };
    let client =
        GraphQLClient::new(&format!("http://user:secret@{address}/graphql?key=secret")).unwrap();
    let query = serde_json::json!({ "operationName": "Test", "query": "{ epoch { epochId } }" });
    let (_, response) = tokio::join!(
        server,
        client.run_query_from_json(query.as_object().unwrap().clone())
    );
    response.unwrap();

    let captured = capture.0.lock().unwrap();
    for expected in [
        "span=graphql_request",
        "graphql.operation.name=Test",
        &format!("url.full=http://{address}/graphql"),
        "http.response.status_code=200",
        "message=request completed",
        "message=request body",
        "body={\"data\":{\"epoch\":null}}",
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
    assert!(
        !captured.iter().any(|c| c.contains("secret")),
        "{captured:?}"
    );
}
