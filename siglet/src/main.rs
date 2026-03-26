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

use std::sync::Arc;

use dataplane_sdk::{
    core::{db::data_flow::memory::MemoryDataFlowRepo, db::memory::MemoryContext},
    sdk::DataPlaneSdk,
};
use dsdk_facet_core::token::MemoryTokenStore;
use siglet::{
    config::{SigletConfig, StorageBackend, load_config},
    error::SigletError,
    handler::SigletDataFlowHandler,
    server::run_server,
};
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    // Initialize tracing subscriber with info level default
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let cfg = load_config().unwrap_or_else(|e| {
        error!("Failed to load configuration: {}", e);
        SigletConfig::default()
    });

    match run(cfg).await {
        Ok(_) => info!("Shutdown"),
        Err(e) => {
            error!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

async fn run(cfg: SigletConfig) -> Result<(), SigletError> {
    match cfg.storage_backend {
        StorageBackend::Memory => {
            let ctx = MemoryContext;
            let flow_repo = MemoryDataFlowRepo::default();
            let token_store = Arc::new(MemoryTokenStore::default());
            let handler = SigletDataFlowHandler::new(token_store);

            let sdk = DataPlaneSdk::builder(ctx)
                .with_repo(flow_repo)
                .with_handler(handler)
                .build()
                .map_err(|e| SigletError::DataPlane(e.to_string()))?;

            run_server(cfg.bind, cfg.signaling_port, cfg.siglet_api_port, sdk).await
        }
        StorageBackend::Postgres => {
            todo!("Postgres storage backend not yet implemented")
        }
    }
}
