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
use bon::Builder;
use config::{Config, Environment, File};
use serde::Deserialize;
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

#[cfg(test)]
mod tests;

// ============================================================================
// Configuration Constants
// ============================================================================

/// Default port for the Siglet management API
pub const DEFAULT_SIGLET_API_PORT: u16 = 8080;

/// Default port for the DataPlane signaling API
pub const DEFAULT_SIGNALING_PORT: u16 = 8081;

/// Default bind address (0.0.0.0 - listen on all interfaces)
pub const DEFAULT_BIND_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

/// Default name for the Vault signing key
pub const DEFAULT_VAULT_SIGNING_KEY_NAME: &str = "siglet-signing-key";

/// Minimum server secret length in bytes (128 bits)
pub const MIN_SERVER_SECRET_BYTES: usize = 16;

/// Minimum server secret length in hex characters (32 hex chars = 16 bytes)
pub const MIN_SERVER_SECRET_HEX_CHARS: usize = MIN_SERVER_SECRET_BYTES * 2;

/// Environment variable name for the configuration file path
pub const ENV_CONFIG_FILE: &str = "SIGLET_CONFIG_FILE";

// ============================================================================
// Type Definitions
// ============================================================================

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackend {
    #[default]
    Memory,
    Postgres,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TokenSource {
    Client,
    Provider,
}

#[derive(Builder, Deserialize, Clone, Debug)]
pub struct TransferType {
    pub transfer_type: String,
    pub endpoint_type: String,
    pub endpoint: Option<String>,
    pub token_source: TokenSource,
    #[serde(default)]
    #[builder(default)]
    pub endpoint_mappings: Vec<EndpointMapping>,
}

#[derive(Builder, Deserialize, Clone, Debug)]
pub struct EndpointMapping {
    /// A key in `DataFlow.metadata` to match on.
    pub key: String,
    /// The expected string value of the metadata entry identified by `key`.
    pub value: String,
    pub endpoint: String,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct SigletConfig {
    #[serde(default = "default_siglet_api_port")]
    pub siglet_api_port: u16,
    #[serde(default = "default_signaling_port")]
    pub signaling_port: u16,
    #[serde(default = "default_bind")]
    pub bind: IpAddr,
    #[serde(default)]
    pub storage_backend: StorageBackend,
    #[serde(default)]
    pub transfer_types: Vec<TransferType>,

    // Vault configuration
    pub vault_url: Option<String>,
    pub vault_token: Option<String>,
    pub vault_token_file: Option<String>,
    #[serde(default = "default_vault_signing_key_name")]
    pub vault_signing_key_name: String,
    pub token_issuer: Option<String>,
    pub token_refresh_endpoint: Option<String>,
    pub token_server_secret: Option<String>,
}

impl Default for SigletConfig {
    fn default() -> Self {
        Self {
            siglet_api_port: DEFAULT_SIGLET_API_PORT,
            signaling_port: DEFAULT_SIGNALING_PORT,
            bind: DEFAULT_BIND_ADDRESS,
            storage_backend: StorageBackend::Memory,
            transfer_types: Vec::new(),
            vault_url: None,
            vault_token: None,
            vault_token_file: None,
            vault_signing_key_name: DEFAULT_VAULT_SIGNING_KEY_NAME.to_string(),
            token_issuer: None,
            token_refresh_endpoint: None,
            token_server_secret: None,
        }
    }
}

impl SigletConfig {
    /// Validates the configuration and returns detailed errors if invalid
    ///
    /// This should be called immediately after loading the config to fail fast
    /// before starting any services.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let mut errors = Vec::new();

        // Validate Vault URL is provided
        if self.vault_url.is_none() {
            errors.push("vault_url is required".to_string());
        }

        // Validate Vault URL format
        if let Some(url) = &self.vault_url
            && url.parse::<reqwest::Url>().is_err()
        {
            errors.push(format!("vault_url is not a valid URL: '{}'", url));
        }

        // Validate Vault authentication is provided
        if self.vault_token.is_none() && self.vault_token_file.is_none() {
            errors.push("Either vault_token or vault_token_file is required".to_string());
        }

        // Validate server secret format (if provided)
        if let Some(secret_hex) = &self.token_server_secret {
            if secret_hex.is_empty() {
                errors.push("token_server_secret cannot be empty".to_string());
            } else if let Ok(decoded) = hex::decode(secret_hex) {
                // Check length (should be at least MIN_SERVER_SECRET_BYTES for security)
                if decoded.len() < MIN_SERVER_SECRET_BYTES {
                    errors.push(format!(
                        "token_server_secret should be at least {} hex characters ({} bytes), got {} bytes",
                        MIN_SERVER_SECRET_HEX_CHARS,
                        MIN_SERVER_SECRET_BYTES,
                        decoded.len()
                    ));
                }
            } else {
                errors.push(format!(
                    "token_server_secret must be a valid hex-encoded string, got: '{}'",
                    secret_hex
                ));
            }
        }

        // Validate port numbers don't conflict
        if self.siglet_api_port == self.signaling_port {
            errors.push(format!(
                "siglet_api_port and signaling_port cannot be the same (both are {})",
                self.siglet_api_port
            ));
        }

        // Validate port numbers are not 0 (system-assigned)
        if self.siglet_api_port == 0 {
            errors.push("siglet_api_port cannot be 0".to_string());
        }
        if self.signaling_port == 0 {
            errors.push("signaling_port cannot be 0".to_string());
        }

        // Validate transfer types
        for (idx, tt) in self.transfer_types.iter().enumerate() {
            if tt.transfer_type.is_empty() {
                errors.push(format!("transfer_types[{}]: transfer_type cannot be empty", idx));
            }
            if tt.endpoint_type.is_empty() {
                errors.push(format!("transfer_types[{}]: endpoint_type cannot be empty", idx));
            }

            if tt.endpoint_mappings.is_empty() {
                // No mappings: static endpoint is required
                match &tt.endpoint {
                    None => errors.push(format!(
                        "transfer_types[{}]: endpoint is required when no endpoint_mappings are configured",
                        idx
                    )),
                    Some(e) if e.is_empty() => {
                        errors.push(format!("transfer_types[{}]: endpoint cannot be empty", idx))
                    }
                    _ => {}
                }
            } else {
                // Validate each mapping entry
                for (midx, mapping) in tt.endpoint_mappings.iter().enumerate() {
                    if mapping.key.is_empty() {
                        errors.push(format!(
                            "transfer_types[{}].endpoint_mappings[{}]: key cannot be empty",
                            idx, midx
                        ));
                    }
                    if mapping.value.is_empty() {
                        errors.push(format!(
                            "transfer_types[{}].endpoint_mappings[{}]: value cannot be empty",
                            idx, midx
                        ));
                    }
                    if mapping.endpoint.is_empty() {
                        errors.push(format!(
                            "transfer_types[{}].endpoint_mappings[{}]: endpoint cannot be empty",
                            idx, midx
                        ));
                    }
                }
            }
        }

        // Validate vault signing key name
        if self.vault_signing_key_name.is_empty() {
            errors.push("vault_signing_key_name cannot be empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::Multiple(errors))
        }
    }
}

const fn default_siglet_api_port() -> u16 {
    DEFAULT_SIGLET_API_PORT
}

const fn default_signaling_port() -> u16 {
    DEFAULT_SIGNALING_PORT
}

fn default_bind() -> IpAddr {
    DEFAULT_BIND_ADDRESS
}

fn default_vault_signing_key_name() -> String {
    DEFAULT_VAULT_SIGNING_KEY_NAME.to_string()
}

pub fn load_config() -> anyhow::Result<SigletConfig> {
    let path = std::env::args().nth(1);
    let config_file = std::env::var(ENV_CONFIG_FILE)
        .map(PathBuf::from)
        .ok()
        .or_else(|| path.map(PathBuf::from));

    let mut config_builder = Config::builder();
    if let Some(path) = config_file {
        config_builder = config_builder.add_source(File::from(path.clone()));
    }

    config_builder
        .add_source(Environment::with_prefix("SIGLET"))
        .build()?
        .try_deserialize()
        .map_err(Into::into)
}

/// Error type for configuration validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    Single(String),
    Multiple(Vec<String>),
}

impl ValidationError {
    /// Creates a single validation error
    pub fn single(msg: impl Into<String>) -> Self {
        ValidationError::Single(msg.into())
    }

    /// Returns the number of validation errors
    pub fn error_count(&self) -> usize {
        match self {
            ValidationError::Single(_) => 1,
            ValidationError::Multiple(errors) => errors.len(),
        }
    }

    /// Returns all error messages
    pub fn messages(&self) -> Vec<&str> {
        match self {
            ValidationError::Single(msg) => vec![msg.as_str()],
            ValidationError::Multiple(errors) => errors.iter().map(|s| s.as_str()).collect(),
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::Single(msg) => write!(f, "Configuration validation failed: {}", msg),
            ValidationError::Multiple(errors) => {
                writeln!(f, "Configuration validation failed with {} error(s):", errors.len())?;
                for (i, error) in errors.iter().enumerate() {
                    writeln!(f, "  {}. {}", i + 1, error)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ValidationError {}
