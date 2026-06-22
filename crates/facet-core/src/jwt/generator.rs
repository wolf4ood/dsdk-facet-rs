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
use crate::jwt::{JwtGenerationError, JwtGenerator, TokenClaims};
use crate::util::clock::{Clock, default_clock};
use crate::vault::{PublicKeyFormat, VaultSigningClient};
use async_trait::async_trait;
use base64::Engine;
use bon::Builder;
use std::sync::Arc;

/// JWT generator that delegates signing to a participant-context Vault transit key.
///
/// Each PC's proof JWT is signed with a dedicated transit key named `{key_name_prefix}-{pc.id}`.
/// The provisioner is responsible for creating the transit key and publishing the corresponding
/// public key in the PC's DID document.
#[derive(Builder)]
pub struct VaultJwtGenerator {
    signing_client: Arc<dyn VaultSigningClient>,

    /// Prefix used to derive the per-PC transit key name: `{key_name_prefix}-{pc.id}`.
    #[builder(into)]
    key_name_prefix: String,

    #[builder(default = default_clock())]
    clock: Arc<dyn Clock>,
}

#[async_trait]
impl JwtGenerator for VaultJwtGenerator {
    async fn generate_token(
        &self,
        participant_context: &ParticipantContext,
        mut claims: TokenClaims,
    ) -> Result<String, JwtGenerationError> {
        let key_name = format!("{}-{}", self.key_name_prefix, participant_context.id);

        let metadata = self
            .signing_client
            .get_key_metadata(&key_name, PublicKeyFormat::Multibase)
            .await?;
        let kid = format!(
            "{}#{}-{}",
            participant_context.identifier, metadata.key_name, metadata.current_version
        );

        claims.iat = self.clock.now().timestamp();

        let payload_bytes = serde_json::to_vec(&claims)
            .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to serialize claims: {}", e)))?;

        let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid });
        let header_bytes = serde_json::to_vec(&header)
            .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to serialize header: {}", e)))?;

        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&header_bytes);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_bytes);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let signature_bytes = self
            .signing_client
            .sign_content(&key_name, signing_input.as_bytes())
            .await?;
        let signature_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature_bytes);

        Ok(format!("{}.{}", signing_input, signature_b64url))
    }
}
