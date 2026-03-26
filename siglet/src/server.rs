//  Copyright (c) 2026 Metaform Systems, Inc
//
//  This program and the accompanying materials are made available under the
//  terms of the Apache License, Version 2.0 which is available at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  SPDX-License-Identifier: Apache-2.0
//
//  Contributors:
//       Metaform Systems, Inc. - initial API and implementation
//

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::{
    Extension, Router,
    response::{IntoResponse, Json},
    routing::get,
};
use dataplane_sdk::{
    core::{db::memory::MemoryContext, model::participant::ParticipantContext},
    sdk::DataPlaneSdk,
};
use dataplane_sdk_axum::router::router as signaling_router;
use serde_json::json;
use tokio::{signal, sync::Barrier};
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::error::SigletError;

/// Run both signaling and siglet APIs
pub async fn run_server(
    bind: IpAddr,
    signaling_port: u16,
    siglet_api_port: u16,
    sdk: DataPlaneSdk<MemoryContext>,
) -> Result<(), SigletError> {
    let barrier = Arc::new(Barrier::new(3));
    start_signaling_api(bind, signaling_port, sdk.clone(), barrier.clone()).await?;
    start_siglet_api(bind, siglet_api_port, barrier.clone()).await?;

    info!("Ready");

    barrier.wait().await;

    Ok(())
}

/// Start the DataPlane SDK signaling API
async fn start_signaling_api(
    bind: IpAddr,
    port: u16,
    sdk: DataPlaneSdk<MemoryContext>,
    barrier: Arc<Barrier>,
) -> Result<(), SigletError> {
    let addr: SocketAddr = format!("{}:{}", bind, port)
        .parse()
        .map_err(|e: std::net::AddrParseError| {
            SigletError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

    let p_context = ParticipantContext::builder().id("siglet-participant").build();

    let router = signaling_router().layer(Extension(p_context));

    info!("Signaling API {}", addr);

    tokio::task::spawn(async move {
        let app = router.layer(TraceLayer::new_for_http()).with_state(sdk);

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("Failed to bind signaling API");

        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(wait_for_shutdown())
            .await;

        barrier.wait().await;
    });

    Ok(())
}

/// Start the Siglet management API
async fn start_siglet_api(bind: IpAddr, port: u16, barrier: Arc<Barrier>) -> Result<(), SigletError> {
    let addr: SocketAddr = format!("{}:{}", bind, port)
        .parse()
        .map_err(|e: std::net::AddrParseError| {
            SigletError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

    let app = create_router();

    info!("Siglet API {}", addr);

    tokio::task::spawn(async move {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("Failed to bind Siglet API");

        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(wait_for_shutdown())
            .await;

        barrier.wait().await;
    });

    Ok(())
}

/// Create the Siglet management API router
fn create_router() -> Router {
    Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
}

/// Root endpoint handler
async fn root() -> impl IntoResponse {
    Json(json!({
        "name": "Siglet",
        "version": env!("CARGO_PKG_VERSION"),
        "status": "running"
    }))
}

/// Health check endpoint handler
async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "healthy"
    }))
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM)
async fn wait_for_shutdown() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
