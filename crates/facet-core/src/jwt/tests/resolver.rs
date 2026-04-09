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

use crate::jwt::{
    JwkKeyType, JwkSetProvider, JwtVerificationError, KeyFormat, VaultVerificationKeyResolver, VerificationKeyResolver,
};
use crate::vault::{KeyMetadata, PublicKeyFormat, VaultError, VaultSigningClient};
use async_trait::async_trait;
use base64::Engine;
use dsdk_facet_test_utils::wait_until;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

#[tokio::test]
async fn initialize_fails_when_vault_errors() {
    let resolver = make_resolver(Arc::new(MockVaultSigningClient::failing()));

    let result = resolver.initialize().await;

    assert!(matches!(result, Err(JwtVerificationError::GeneralError(_))));
}

#[tokio::test]
async fn resolve_key_returns_correct_key_bytes_for_version_1() {
    let raw = test_key(0xAB);
    let client = Arc::new(MockVaultSigningClient::new("my-key", &[raw.clone()]));
    let resolver = make_resolver(client);

    let material = resolver.resolve_key("issuer", "my-key-1").await.unwrap();

    assert_eq!(material.key, raw);
}

#[tokio::test]
async fn resolve_key_returns_correct_key_bytes_for_version_2() {
    let key1 = test_key(0x01);
    let key2 = test_key(0x02);
    let client = Arc::new(MockVaultSigningClient::new("my-key", &[key1, key2.clone()]));
    let resolver = make_resolver(client);

    let material = resolver.resolve_key("issuer", "my-key-2").await.unwrap();

    assert_eq!(material.key, key2);
}

#[tokio::test]
async fn resolve_key_propagates_iss_and_kid() {
    let client = Arc::new(MockVaultSigningClient::new("my-key", &[test_key(1)]));
    let resolver = make_resolver(client);

    let material = resolver.resolve_key("https://example.com", "my-key-1").await.unwrap();

    assert_eq!(material.iss, "https://example.com");
    assert_eq!(material.kid, "my-key-1");
}

#[tokio::test]
async fn resolve_key_returns_der_format() {
    let client = Arc::new(MockVaultSigningClient::new("my-key", &[test_key(1)]));
    let resolver = make_resolver(client);

    let material = resolver.resolve_key("iss", "my-key-1").await.unwrap();

    assert_eq!(material.key_format, KeyFormat::DER);
}

#[tokio::test]
async fn resolve_key_fails_for_kid_with_no_dash() {
    let client = Arc::new(MockVaultSigningClient::new("key", &[test_key(1)]));
    let resolver = make_resolver(client);

    let result = resolver.resolve_key("iss", "nodash").await;

    assert!(matches!(result, Err(JwtVerificationError::VerificationFailed(_))));
}

#[tokio::test]
async fn resolve_key_fails_for_non_numeric_version() {
    let client = Arc::new(MockVaultSigningClient::new("my-key", &[test_key(1)]));
    let resolver = make_resolver(client);

    let result = resolver.resolve_key("iss", "my-key-abc").await;

    assert!(matches!(result, Err(JwtVerificationError::VerificationFailed(_))));
}

#[tokio::test]
async fn resolve_key_fails_for_version_out_of_range() {
    let client = Arc::new(MockVaultSigningClient::new("my-key", &[test_key(1)]));
    let resolver = make_resolver(client);

    let result = resolver.resolve_key("iss", "my-key-99").await;

    assert!(matches!(result, Err(JwtVerificationError::VerificationFailed(_))));
}

#[tokio::test]
async fn resolve_key_fails_when_vault_errors() {
    let resolver = make_resolver(Arc::new(MockVaultSigningClient::failing()));

    let result = resolver.resolve_key("iss", "my-key-1").await;

    assert!(matches!(result, Err(JwtVerificationError::VerificationFailed(_))));
}

#[tokio::test]
async fn resolve_key_fails_for_invalid_base64_key_data() {
    let client = Arc::new(MockVaultSigningClient::with_raw_key_strings(
        "my-key",
        vec!["!!!not-valid-base64!!!".to_string()],
    ));
    let resolver = make_resolver(client);

    let result = resolver.resolve_key("iss", "my-key-1").await;

    assert!(matches!(result, Err(JwtVerificationError::VerificationFailed(_))));
}

#[tokio::test]
async fn periodic_refresh_repeatedly_calls_load_keys() {
    let client = Arc::new(MockVaultSigningClient::new("my-key", &[test_key(1)]));
    let call_count = Arc::clone(&client.call_count);

    let resolver = Arc::new(
        VaultVerificationKeyResolver::builder()
            .vault_client(client)
            .refresh_interval(Duration::from_millis(100))
            .build(),
    );
    resolver.initialize().await.unwrap();
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "Expected exactly 1 call on initialize"
    );

    wait_until(|| call_count.load(Ordering::SeqCst) >= 3, Duration::from_secs(2)).await;
}

#[tokio::test]
async fn background_task_stops_when_resolver_is_dropped() {
    let client = Arc::new(MockVaultSigningClient::new("my-key", &[test_key(1)]));
    let call_count = Arc::clone(&client.call_count);

    let resolver = Arc::new(
        VaultVerificationKeyResolver::builder()
            .vault_client(client)
            .refresh_interval(Duration::from_millis(50))
            .build(),
    );
    resolver.initialize().await.unwrap();
    wait_until(|| call_count.load(Ordering::SeqCst) >= 3, Duration::from_secs(2)).await;
    let count_before_drop = call_count.load(Ordering::SeqCst);

    drop(resolver);

    // Poll until the count stops changing — the aborted task should quiesce quickly.
    // Allow at most 1 in-flight call that started just before the drop.
    let stable_count = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let before = call_count.load(Ordering::SeqCst);
            tokio::task::yield_now().await;
            if call_count.load(Ordering::SeqCst) == before {
                return before;
            }
        }
    })
    .await
    .expect("Count should stabilize after resolver is dropped");

    assert!(
        stable_count <= count_before_drop + 1,
        "Background task should stop after drop; count went from {} to {}",
        count_before_drop,
        stable_count
    );
}

#[tokio::test]
async fn initialize_loads_keys_on_startup() {
    let client = Arc::new(MockVaultSigningClient::new("my-key", &[test_key(1)]));
    let call_count = Arc::clone(&client.call_count);
    let resolver = make_resolver(client);

    resolver.initialize().await.unwrap();

    assert_eq!(call_count.load(Ordering::SeqCst), 1);
}

/// Simulates a key rotation that occurs after the cache was last populated.
/// The first call to `get_key_metadata` returns only v1; all subsequent calls
/// return both v1 and v2, as if a rotation happened between calls.
struct RotatingMockVaultSigningClient {
    key_name: String,
    initial_keys: Vec<Vec<u8>>,
    rotated_keys: Vec<Vec<u8>>,
    call_count: Arc<AtomicU32>,
}

impl RotatingMockVaultSigningClient {
    fn new(key_name: &str, initial_keys: &[Vec<u8>], rotated_keys: &[Vec<u8>]) -> Self {
        Self {
            key_name: key_name.to_string(),
            initial_keys: initial_keys.to_vec(),
            rotated_keys: rotated_keys.to_vec(),
            call_count: Arc::new(AtomicU32::new(0)),
        }
    }
}

#[async_trait]
impl VaultSigningClient for RotatingMockVaultSigningClient {
    async fn get_key_metadata(&self, _format: PublicKeyFormat) -> Result<KeyMetadata, VaultError> {
        let count = self.call_count.fetch_add(1, Ordering::SeqCst);
        let keys = if count == 0 {
            &self.initial_keys
        } else {
            &self.rotated_keys
        };
        let key_strings = keys
            .iter()
            .map(|k| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(k))
            .collect::<Vec<_>>();
        Ok(KeyMetadata {
            key_name: self.key_name.clone(),
            current_version: key_strings.len(),
            keys: key_strings,
        })
    }

    async fn sign_content(&self, _content: &[u8]) -> Result<Vec<u8>, VaultError> {
        Ok(vec![])
    }
}

#[tokio::test]
async fn resolve_key_refreshes_on_cache_miss_after_rotation() {
    let key_v1 = test_key(0x01);
    let key_v2 = test_key(0x02);
    let client = Arc::new(RotatingMockVaultSigningClient::new(
        "my-key",
        &[key_v1.clone()],
        &[key_v1, key_v2.clone()],
    ));

    // Initialize with only v1 in cache.
    let resolver = Arc::new(VaultVerificationKeyResolver::builder().vault_client(client).build());
    resolver.initialize().await.unwrap();

    // Requesting v2 (not yet cached) should trigger an immediate refresh and succeed.
    let material = resolver.resolve_key("iss", "my-key-2").await.unwrap();

    assert_eq!(material.key, key_v2);
}

struct MockVaultSigningClient {
    call_count: Arc<AtomicU32>,
    key_name: String,
    /// Pre-formatted strings placed verbatim in `KeyMetadata::keys`. Allows
    /// injecting invalid base64 without going through an encoder.
    key_strings: Vec<String>,
    current_version: usize,
    fail: bool,
}

impl MockVaultSigningClient {
    fn new(key_name: &str, keys: &[Vec<u8>]) -> Self {
        let key_strings = keys
            .iter()
            .map(|k| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(k))
            .collect();
        Self {
            call_count: Arc::new(AtomicU32::new(0)),
            key_name: key_name.to_string(),
            key_strings,
            current_version: keys.len(),
            fail: false,
        }
    }

    fn failing() -> Self {
        Self {
            call_count: Arc::new(AtomicU32::new(0)),
            key_name: "key".to_string(),
            key_strings: vec![],
            current_version: 0,
            fail: true,
        }
    }

    fn with_raw_key_strings(key_name: &str, key_strings: Vec<String>) -> Self {
        let current_version = key_strings.len();
        Self {
            call_count: Arc::new(AtomicU32::new(0)),
            key_name: key_name.to_string(),
            key_strings,
            current_version,
            fail: false,
        }
    }
}

#[async_trait]
impl VaultSigningClient for MockVaultSigningClient {
    async fn get_key_metadata(&self, _format: PublicKeyFormat) -> Result<KeyMetadata, VaultError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(VaultError::NetworkError("simulated vault error".to_string()));
        }
        Ok(KeyMetadata {
            key_name: self.key_name.clone(),
            keys: self.key_strings.clone(),
            current_version: self.current_version,
        })
    }

    async fn sign_content(&self, _content: &[u8]) -> Result<Vec<u8>, VaultError> {
        Ok(vec![])
    }
}

fn test_key(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn make_resolver(client: Arc<MockVaultSigningClient>) -> Arc<VaultVerificationKeyResolver> {
    Arc::new(VaultVerificationKeyResolver::builder().vault_client(client).build())
}

#[tokio::test]
async fn jwk_set_is_empty_before_initialize() {
    let client = Arc::new(MockVaultSigningClient::new("my-key", &[test_key(1)]));
    let resolver = make_resolver(client);

    assert!(
        resolver.jwk_set().await.keys.is_empty(),
        "JWK set should be empty before initialize()"
    );
}

#[tokio::test]
async fn jwk_set_contains_one_entry_per_cached_key() {
    let client = Arc::new(MockVaultSigningClient::new("my-key", &[test_key(1), test_key(2)]));
    let resolver = make_resolver(client);
    resolver.initialize().await.unwrap();

    assert_eq!(
        resolver.jwk_set().await.keys.len(),
        2,
        "JWK set should have one entry per cached key"
    );
}

#[tokio::test]
async fn jwk_set_entries_are_okp_eddsa() {
    let client = Arc::new(MockVaultSigningClient::new("my-key", &[test_key(0xAB)]));
    let resolver = make_resolver(client);
    resolver.initialize().await.unwrap();

    let jwk = &resolver.jwk_set().await.keys[0];

    assert_eq!(jwk.kty, JwkKeyType::Okp, "key type should be OKP");
    assert_eq!(jwk.crv.as_deref(), Some("Ed25519"), "curve should be Ed25519");
    assert_eq!(jwk.alg.as_deref(), Some("EdDSA"), "algorithm should be EdDSA");
}

#[tokio::test]
async fn jwk_set_x_parameter_is_base64url_of_raw_key() {
    let raw = test_key(0xAB);
    let client = Arc::new(MockVaultSigningClient::new("my-key", &[raw.clone()]));
    let resolver = make_resolver(client);
    resolver.initialize().await.unwrap();

    let x = resolver.jwk_set().await.keys[0]
        .x
        .clone()
        .expect("x parameter must be present");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&x).unwrap();

    assert_eq!(decoded, raw, "x should be the base64url-encoded raw key bytes");
}

#[tokio::test]
async fn jwk_set_kid_matches_resolver_kid_format() {
    let client = Arc::new(MockVaultSigningClient::new("signing-key", &[test_key(1), test_key(2)]));
    let resolver = make_resolver(client);
    resolver.initialize().await.unwrap();

    let mut kids: Vec<_> = resolver
        .jwk_set()
        .await
        .keys
        .into_iter()
        .filter_map(|k| k.kid)
        .collect();
    kids.sort();

    assert_eq!(kids, vec!["signing-key-1", "signing-key-2"]);
}

#[tokio::test]
async fn test_vault_signing_key_resolver_successful_resolution() {
    use super::common::create_test_verifier;
    use crate::jwt::jwtutils::{SigningKeyRecord, VaultSigningKeyResolver, generate_ed25519_keypair_pem};
    use crate::jwt::{JwtGenerator, JwtVerifier, LocalJwtGenerator, SigningAlgorithm, TokenClaims};
    use crate::vault::{MemoryVaultClient, VaultClient};
    use chrono::Utc;

    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate keypair");
    let vault_client = Arc::new(MemoryVaultClient::new());

    let pc = crate::context::ParticipantContext::builder()
        .id("test-participant")
        .identifier("did:web:example.com")
        .audience("test-audience")
        .build();

    let key_record = SigningKeyRecord::builder()
        .private_key(std::str::from_utf8(&keypair.private_key).unwrap())
        .kid("did:web:example.com#key-1")
        .key_format(KeyFormat::PEM)
        .build();

    vault_client
        .store_secret(&pc, "signing-key", &serde_json::to_string(&key_record).unwrap())
        .await
        .expect("Failed to store secret");

    let vault_resolver = Arc::new(
        VaultSigningKeyResolver::builder()
            .vault_client(vault_client)
            .base_path("signing-key")
            .build(),
    );

    let generator = LocalJwtGenerator::builder()
        .signing_key_resolver(vault_resolver)
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .exp(now + 10000)
        .build();

    let token = generator
        .generate_token(&pc, claims)
        .await
        .expect("Token generation should succeed");

    let verifier = create_test_verifier(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);
    let verified = verifier
        .verify_token("test-audience", &token)
        .await
        .expect("Token verification should succeed");

    assert_eq!(verified.sub, "user-123");
    assert_eq!(verified.iss, "did:web:example.com");
}

#[tokio::test]
async fn test_vault_signing_key_resolver_missing_key() {
    use crate::jwt::jwtutils::VaultSigningKeyResolver;
    use crate::jwt::{JwtGenerator, LocalJwtGenerator, SigningAlgorithm, TokenClaims};
    use crate::vault::MemoryVaultClient;
    use chrono::Utc;

    let vault_client = Arc::new(MemoryVaultClient::new());

    let pc = crate::context::ParticipantContext::builder()
        .id("test-participant")
        .identifier("did:web:example.com")
        .audience("test-audience")
        .build();

    let vault_resolver = Arc::new(
        VaultSigningKeyResolver::builder()
            .vault_client(vault_client)
            .base_path("missing-key")
            .build(),
    );

    let generator = LocalJwtGenerator::builder()
        .signing_key_resolver(vault_resolver)
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .exp(now + 10000)
        .build();

    let result = generator.generate_token(&pc, claims).await;

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("Failed to resolve signing key from vault"),
        "Error message should mention vault resolution failure"
    );
}

#[tokio::test]
async fn test_vault_signing_key_resolver_different_participants() {
    use super::common::create_test_verifier;
    use crate::jwt::jwtutils::{SigningKeyRecord, VaultSigningKeyResolver, generate_ed25519_keypair_pem};
    use crate::jwt::{JwtGenerator, JwtVerifier, LocalJwtGenerator, SigningAlgorithm, TokenClaims};
    use crate::vault::{MemoryVaultClient, VaultClient};
    use chrono::Utc;

    let keypair1 = generate_ed25519_keypair_pem().expect("Failed to generate keypair 1");
    let keypair2 = generate_ed25519_keypair_pem().expect("Failed to generate keypair 2");
    let vault_client = Arc::new(MemoryVaultClient::new());

    let pc1 = crate::context::ParticipantContext::builder()
        .id("participant-1")
        .identifier("did:web:example.com")
        .audience("audience-1")
        .build();
    let pc2 = crate::context::ParticipantContext::builder()
        .id("participant-2")
        .identifier("did:web:example.com")
        .audience("audience-2")
        .build();

    let record1 = SigningKeyRecord::builder()
        .private_key(std::str::from_utf8(&keypair1.private_key).unwrap())
        .kid("did:web:example.com#key-1")
        .key_format(KeyFormat::PEM)
        .build();
    vault_client
        .store_secret(&pc1, "signing-key", &serde_json::to_string(&record1).unwrap())
        .await
        .expect("Failed to store secret for participant 1");

    let record2 = SigningKeyRecord::builder()
        .private_key(std::str::from_utf8(&keypair2.private_key).unwrap())
        .kid("did:web:example.com#key-2")
        .key_format(KeyFormat::PEM)
        .build();
    vault_client
        .store_secret(&pc2, "signing-key", &serde_json::to_string(&record2).unwrap())
        .await
        .expect("Failed to store secret for participant 2");

    let vault_resolver = Arc::new(
        VaultSigningKeyResolver::builder()
            .vault_client(vault_client)
            .base_path("signing-key")
            .build(),
    );
    let generator = LocalJwtGenerator::builder()
        .signing_key_resolver(vault_resolver)
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let now = Utc::now().timestamp();

    let token1 = generator
        .generate_token(
            &pc1,
            TokenClaims::builder()
                .sub("user-123")
                .aud("audience-1")
                .exp(now + 10000)
                .build(),
        )
        .await
        .expect("Token 1 generation should succeed");

    let token2 = generator
        .generate_token(
            &pc2,
            TokenClaims::builder()
                .sub("user-456")
                .aud("audience-2")
                .exp(now + 10000)
                .build(),
        )
        .await
        .expect("Token 2 generation should succeed");

    let verifier1 = create_test_verifier(keypair1.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);
    let claims1 = verifier1
        .verify_token("audience-1", &token1)
        .await
        .expect("Token 1 verification should succeed");
    assert_eq!(claims1.sub, "user-123");

    let verifier2 = create_test_verifier(keypair2.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);
    let claims2 = verifier2
        .verify_token("audience-2", &token2)
        .await
        .expect("Token 2 verification should succeed");
    assert_eq!(claims2.sub, "user-456");

    // Cross-keypair verification must fail
    assert!(verifier2.verify_token("audience-1", &token1).await.is_err());
}

#[test]
fn test_signing_key_record_serialization() {
    use crate::jwt::jwtutils::SigningKeyRecord;

    let record = SigningKeyRecord::builder()
        .private_key("test-private-key-content")
        .kid("did:web:example.com#key-123")
        .key_format(KeyFormat::PEM)
        .build();

    let json = serde_json::to_string(&record).expect("Failed to serialize");
    assert!(json.contains("private_key"));
    assert!(json.contains("test-private-key-content"));
    assert!(json.contains("kid"));
    assert!(json.contains("did:web:example.com#key-123"));
    assert!(json.contains("key_format"));
    assert!(json.contains("PEM"));

    let deserialized: SigningKeyRecord = serde_json::from_str(&json).expect("Failed to deserialize");
    assert_eq!(deserialized.private_key, "test-private-key-content");
    assert_eq!(deserialized.kid, "did:web:example.com#key-123");
    assert_eq!(deserialized.key_format, KeyFormat::PEM);
}

#[test]
fn test_signing_key_record_round_trip() {
    use crate::jwt::jwtutils::SigningKeyRecord;

    let pem_key = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAbcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP\n-----END PRIVATE KEY-----";

    let original = SigningKeyRecord::builder()
        .private_key(pem_key)
        .kid("did:web:example.org#signing-key-1")
        .key_format(KeyFormat::DER)
        .build();

    let json = serde_json::to_string(&original).expect("Failed to serialize");
    let roundtrip: SigningKeyRecord = serde_json::from_str(&json).expect("Failed to deserialize");

    assert_eq!(original.private_key, roundtrip.private_key);
    assert_eq!(original.kid, roundtrip.kid);
    assert_eq!(original.key_format, roundtrip.key_format);
}

#[test]
fn test_signing_key_record_pretty_json() {
    use crate::jwt::jwtutils::SigningKeyRecord;

    let record = SigningKeyRecord::builder()
        .private_key("my-private-key")
        .kid("my-kid")
        .key_format(KeyFormat::PEM)
        .build();

    let pretty_json = serde_json::to_string_pretty(&record).expect("Failed to serialize");
    assert!(pretty_json.contains('\n'));

    let deserialized: SigningKeyRecord = serde_json::from_str(&pretty_json).expect("Failed to deserialize");
    assert_eq!(deserialized.private_key, "my-private-key");
    assert_eq!(deserialized.kid, "my-kid");
    assert_eq!(deserialized.key_format, KeyFormat::PEM);
}

#[test]
fn test_signing_key_record_default_key_format() {
    use crate::jwt::jwtutils::SigningKeyRecord;

    let record = SigningKeyRecord::builder()
        .private_key("test-key")
        .kid("test-kid")
        .build();
    assert_eq!(record.key_format, KeyFormat::PEM);
}

#[test]
fn test_signing_key_record_with_der_format() {
    use crate::jwt::jwtutils::SigningKeyRecord;

    let record = SigningKeyRecord::builder()
        .private_key("der-key-content")
        .kid("did:web:test.com#key-der")
        .key_format(KeyFormat::DER)
        .build();

    let json = serde_json::to_string(&record).expect("Failed to serialize");
    assert!(json.contains("DER"));

    let deserialized: SigningKeyRecord = serde_json::from_str(&json).expect("Failed to deserialize");
    assert_eq!(deserialized.key_format, KeyFormat::DER);
    assert_eq!(deserialized.private_key, "der-key-content");
}
