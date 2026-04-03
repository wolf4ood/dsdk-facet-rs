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

use crate::config::{SigletConfig, TransferType};
use crate::error::SigletError;
use crate::handler::SigletDataFlowHandler;
use dataplane_sdk::core::db::data_flow::memory::MemoryDataFlowRepo;
use dataplane_sdk::core::db::memory::MemoryContext;
use dataplane_sdk::sdk::DataPlaneSdk;
use dsdk_facet_core::jwt::{
    DidWebVerificationKeyResolver, JwtGenerator, JwtVerifier, LocalJwtVerifier, SigningAlgorithm, VaultJwtGenerator,
};
use dsdk_facet_core::token::client::MemoryTokenStore;
use dsdk_facet_core::token::manager::{JwtTokenManager, MemoryRenewableTokenStore, TokenManager};
use dsdk_facet_core::vault::VaultSigningClient;
use dsdk_facet_hashicorp_vault::{HashicorpVaultClient, HashicorpVaultConfig, VaultAuthConfig};
use rand::Rng;
use rand::thread_rng;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::warn;

#[cfg(test)]
mod tests;

// ============================================================================
// System Default Constants
// ============================================================================

/// Default JWT token issuer identifier
pub const DEFAULT_TOKEN_ISSUER: &str = "siglet";

/// Default data plane identifier
pub const DEFAULT_DATAPLANE_ID: &str = "dataplane-1";

/// Default participant identifier for the signaling API
pub const DEFAULT_PARTICIPANT_ID: &str = "siglet-participant";

/// Token refresh endpoint path
pub const TOKEN_REFRESH_PATH: &str = "/token/refresh";

/// Temporary file name for vault token (used in testing)
pub const VAULT_TOKEN_TEMP_FILE: &str = "siglet_vault_token";

/// Random server secret size in bytes (256 bits)
pub const RANDOM_SECRET_SIZE_BYTES: usize = 32;

// ============================================================================
// Assembly Functions
// ============================================================================

/// Assembles a memory-based SDK for data plane operations.
///
/// This function initializes and configures an in-memory implementation of the data
/// plane SDK using the provided configuration. The SDK handles token management,
/// secure flow processing, and context management for in-memory operation.
pub async fn assemble_memory_sdk(cfg: &SigletConfig) -> Result<DataPlaneSdk<MemoryContext>, SigletError> {
    let ctx = MemoryContext;
    let flow_repo = MemoryDataFlowRepo::default();

    let vault_client = create_vault_client(cfg).await?;

    let (jwt_generator, jwt_verifier) = create_jwt_components(vault_client);

    let token_store = Arc::new(MemoryTokenStore::default());
    let renewable_token_store = Arc::new(MemoryRenewableTokenStore::default());

    let server_secret = generate_server_secret(cfg)?;

    let token_manager = create_token_manager(cfg, jwt_generator, jwt_verifier, server_secret, renewable_token_store);

    let handler = create_handler(cfg, token_store, token_manager);

    let sdk = DataPlaneSdk::builder(ctx)
        .with_repo(flow_repo)
        .with_handler(handler)
        .build()
        .map_err(|e| SigletError::DataPlane(anyhow::anyhow!(e)))?;

    Ok(sdk)
}

/// Creates JWT generator and verifier components
fn create_jwt_components(vault_client: Arc<HashicorpVaultClient>) -> (Arc<dyn JwtGenerator>, Arc<dyn JwtVerifier>) {
    let jwt_generator = Arc::new(
        VaultJwtGenerator::builder()
            .signing_client(vault_client.clone() as Arc<dyn VaultSigningClient>)
            .build(),
    );

    let verification_key_resolver = Arc::new(DidWebVerificationKeyResolver::builder().build());

    let jwt_verifier = Arc::new(
        LocalJwtVerifier::builder()
            .verification_key_resolver(verification_key_resolver)
            .signing_algorithm(SigningAlgorithm::EdDSA)
            .build(),
    );

    (jwt_generator, jwt_verifier)
}

/// Generates or decodes the server secret for token signing
///
/// # Arguments
/// * `cfg` - Configuration containing optional hex-encoded secret
///
/// # Returns
/// * `Vec<u8>` - The server secret (32 bytes if randomly generated)
///
/// # Errors
/// * Returns error if provided hex secret is invalid
///
/// # Security
/// If no secret is provided in config, generates a random 256-bit (32 byte) secret.
/// This is acceptable for development/testing but NOT recommended for production.
fn generate_server_secret(cfg: &SigletConfig) -> Result<Vec<u8>, SigletError> {
    cfg.token_server_secret.as_ref().map_or_else(
        || {
            // Default: generate a random secret for dev/test
            let mut secret = vec![0u8; RANDOM_SECRET_SIZE_BYTES];
            thread_rng().fill(&mut secret[..]);
            warn!("Generated random secret for token signing - Do not use in production");
            Ok(secret)
        },
        |secret_hex| {
            // Provided: decode hex string
            hex::decode(secret_hex)
                .map_err(|e| SigletError::InvalidConfiguration(format!("Invalid server secret hex: {}", e)))
        },
    )
}

/// Creates the token manager with all dependencies
///
/// # Arguments
/// * `cfg` - Configuration for issuer, refresh endpoint
/// * `jwt_generator` - JWT generator for creating tokens
/// * `jwt_verifier` - JWT verifier for validating tokens
/// * `server_secret` - Secret for signing tokens
/// * `renewable_token_store` - Store for renewable tokens
///
/// # Returns
/// Arc-wrapped token manager
fn create_token_manager(
    cfg: &SigletConfig,
    jwt_generator: Arc<dyn JwtGenerator>,
    jwt_verifier: Arc<dyn JwtVerifier>,
    server_secret: Vec<u8>,
    renewable_token_store: Arc<MemoryRenewableTokenStore>,
) -> Arc<dyn TokenManager> {
    let issuer = cfg
        .token_issuer
        .clone()
        .unwrap_or_else(|| DEFAULT_TOKEN_ISSUER.to_string());
    let refresh_endpoint = cfg
        .token_refresh_endpoint
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}{}", cfg.bind, cfg.siglet_api_port, TOKEN_REFRESH_PATH));

    Arc::new(
        JwtTokenManager::builder()
            .issuer(issuer)
            .refresh_endpoint(refresh_endpoint)
            .server_secret(server_secret)
            .token_store(renewable_token_store)
            .token_generator(jwt_generator)
            .token_verifier(jwt_verifier)
            .build(),
    )
}

/// Builds the data flow handler with token management
///
/// # Arguments
/// * `cfg` - Configuration (for future extensibility)
/// * `token_store` - Store for client tokens
/// * `token_manager` - Manager for token operations
///
/// # Returns
/// Configured SigletDataFlowHandler
fn create_handler(
    cfg: &SigletConfig,
    token_store: Arc<MemoryTokenStore>,
    token_manager: Arc<dyn TokenManager>,
) -> SigletDataFlowHandler {
    let transfer_type_mappings: HashMap<String, TransferType> = cfg
        .transfer_types
        .iter()
        .map(|tt| (tt.transfer_type.clone(), tt.clone()))
        .collect();

    SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id(DEFAULT_DATAPLANE_ID)
        .transfer_type_mappings(transfer_type_mappings)
        .build()
}

/// Creates and initializes a Vault client for JWT signing
async fn create_vault_client(cfg: &SigletConfig) -> Result<Arc<HashicorpVaultClient>, SigletError> {
    let vault_url = cfg
        .vault_url
        .as_ref()
        .ok_or_else(|| SigletError::InvalidConfiguration("vault_url is required".to_string()))?;

    // Determine token file path using pattern matching
    let token_file = match (&cfg.vault_token_file, &cfg.vault_token) {
        // Use provided token file path (K8s Vault Agent sidecar)
        (Some(token_file_path), _) => std::path::PathBuf::from(token_file_path),

        // Write token to a temporary file (for testing)
        (None, Some(vault_token)) => {
            let token_file = std::env::temp_dir().join(VAULT_TOKEN_TEMP_FILE);
            std::fs::write(&token_file, vault_token)?;
            token_file
        }

        // Neither provided - error
        (None, None) => {
            return Err(SigletError::InvalidConfiguration(
                "Either vault_token or vault_token_file is required".to_string(),
            ));
        }
    };

    let vault_config = HashicorpVaultConfig::builder()
        .vault_url(vault_url)
        .auth_config(VaultAuthConfig::KubernetesServiceAccount {
            token_file_path: token_file,
        })
        .signing_key_name(cfg.vault_signing_key_name.clone())
        .build();

    let mut vault_client = HashicorpVaultClient::new(vault_config).map_err(|e| SigletError::Vault(Box::new(e)))?;

    vault_client
        .initialize()
        .await
        .map_err(|e| SigletError::Vault(Box::new(e)))?;

    Ok(Arc::new(vault_client))
}
