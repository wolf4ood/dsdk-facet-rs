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

use crate::context::ParticipantContext;
use crate::jwt::{JwtGenerationError, JwtGenerator, KeyFormat, SigningAlgorithm, SigningKeyResolver, TokenClaims};
use crate::util::clock::{Clock, default_clock};
use crate::vault::{PublicKeyFormat, VaultSigningClient};
use async_trait::async_trait;
use base64::Engine;
use bon::Builder;
use jsonwebtoken::{EncodingKey, Header, encode};
use std::sync::Arc;

/// JWT generator for creating and verifying JWTs in-process.
#[derive(Builder)]
pub struct LocalJwtGenerator {
    signing_key_resolver: Arc<dyn SigningKeyResolver>,

    #[builder(default = SigningAlgorithm::EdDSA)]
    signing_algorithm: SigningAlgorithm,

    #[builder(default = default_clock())]
    clock: Arc<dyn Clock>,
}

impl LocalJwtGenerator {
    fn load_encoding_key(&self, key_format: &KeyFormat, key_bytes: &[u8]) -> Result<EncodingKey, JwtGenerationError> {
        match (&self.signing_algorithm, key_format) {
            (SigningAlgorithm::EdDSA, KeyFormat::PEM) => EncodingKey::from_ed_pem(key_bytes)
                .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to load Ed25519 PEM key: {}", e))),
            (SigningAlgorithm::EdDSA, KeyFormat::DER) => Ok(EncodingKey::from_ed_der(key_bytes)),
            (SigningAlgorithm::RS256, KeyFormat::PEM) => EncodingKey::from_rsa_pem(key_bytes)
                .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to load RSA PEM key: {}", e))),
            (SigningAlgorithm::RS256, KeyFormat::DER) => Ok(EncodingKey::from_rsa_der(key_bytes)),
        }
    }
}

#[async_trait]
impl JwtGenerator for LocalJwtGenerator {
    async fn generate_token(
        &self,
        participant_context: &ParticipantContext,
        mut claims: TokenClaims,
    ) -> Result<String, JwtGenerationError> {
        let key_result = self.signing_key_resolver.resolve_key(participant_context).await?;

        let algorithm = self.signing_algorithm.into();
        let encoding_key = self.load_encoding_key(&key_result.key_format, &key_result.key)?;
        let mut header = Header::new(algorithm);
        header.kid = Some(key_result.kid);
        claims.iss = key_result.iss;
        claims.iat = self.clock.now().timestamp();
        encode(&header, &claims, &encoding_key)
            .map_err(|e| JwtGenerationError::GenerationError(format!("JWT encoding failed: {}", e)))
    }
}

/// JWT generator that delegates signing to a vault SigningClient.
#[derive(Builder)]
pub struct VaultJwtGenerator {
    signing_client: Arc<dyn VaultSigningClient>,

    #[builder(default = default_clock())]
    clock: Arc<dyn Clock>,
}

#[async_trait]
impl JwtGenerator for VaultJwtGenerator {
    async fn generate_token(
        &self,
        _participant_context: &ParticipantContext,
        mut claims: TokenClaims,
    ) -> Result<String, JwtGenerationError> {
        // Get key metadata to calculate kid (using Multibase format for DID compatibility)
        let metadata = self.signing_client.get_key_metadata(PublicKeyFormat::Multibase).await?;
        let kid = format!("{}-{}", metadata.key_name, metadata.current_version);

        // Set timestamp claims (overwrites any existing iat)
        claims.iat = self.clock.now().timestamp();

        // Serialize payload
        let payload_bytes = serde_json::to_vec(&claims)
            .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to serialize claims: {}", e)))?;

        // Create JWT header with kid and algorithm
        let header = serde_json::json!({
            "alg": "EdDSA", // Only supports Ed25519
            "typ": "JWT",
            "kid": kid
        });

        let header_bytes = serde_json::to_vec(&header)
            .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to serialize header: {}", e)))?;

        // Base64url encode header and payload
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&header_bytes);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_bytes);

        // Create signing input (header.payload)
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // Sign the input using the vault (returns raw signature bytes)
        let signature_bytes = self.signing_client.sign_content(signing_input.as_bytes()).await?;

        // Encode signature as base64url for JWT
        let signature_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature_bytes);

        // Return complete JWT
        Ok(format!("{}.{}", signing_input, signature_b64url))
    }
}
