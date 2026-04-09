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

//! Tests for LocalJwtVerifier

use super::common::*;
use crate::context::ParticipantContext;
use crate::jwt::jwtutils::generate_ed25519_keypair_der;
use crate::jwt::jwtutils::{generate_ed25519_keypair_pem, generate_rsa_keypair_pem};
use crate::jwt::{JwtGenerator, JwtVerificationError, JwtVerifier, KeyFormat, SigningAlgorithm, TokenClaims};
use chrono::Utc;

#[tokio::test]
async fn test_expired_token_validation_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .exp(now - 10000) // Expired 10,000 seconds ago
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(&pc, claims)
        .await
        .expect("Token generation should succeed");

    let verifier = create_test_verifier(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);
    let result = verifier.verify_token(&pc.audience, &token).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtVerificationError::TokenExpired));
}

#[tokio::test]
async fn test_leeway_allows_recently_expired_token_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "issuer-leeway",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-789")
        .aud("audience1")
        .exp(now - 20) // Expired 20 seconds ago
        .build();

    let pc = ParticipantContext::builder()
        .id("participant1")
        .audience("audience1")
        .build();

    let token = generator
        .generate_token(&pc, claims)
        .await
        .expect("Token generation should succeed");

    // 30-second leeway should accept a token expired 20 seconds ago
    let verifier = create_test_verifier_with_leeway(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA, 30);
    let verified_claims = verifier
        .verify_token(&pc.audience, &token)
        .await
        .expect("Token should be valid with leeway");

    assert_eq!(verified_claims.sub, "user-id-789");
    assert_eq!(verified_claims.iss, "issuer-leeway");
}

#[tokio::test]
async fn test_leeway_rejects_token_expired_beyond_leeway_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-999")
        .iss("issuer-expired")
        .aud("audience-123")
        .exp(now - 100) // Expired 100 seconds ago
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(&pc, claims)
        .await
        .expect("Token generation should succeed");

    // 30-second leeway should reject a token expired 100 seconds ago
    let verifier = create_test_verifier_with_leeway(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA, 30);
    let result = verifier.verify_token(&pc.audience, &token).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtVerificationError::TokenExpired));
}

#[tokio::test]
async fn test_invalid_signature_pem_eddsa() {
    let keypair1 = generate_ed25519_keypair_pem().expect("Failed to generate keypair 1");
    let keypair2 = generate_ed25519_keypair_pem().expect("Failed to generate keypair 2");

    let generator = create_test_generator(
        keypair1.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .exp(now + 10000)
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(&pc, claims)
        .await
        .expect("Token generation should succeed");

    // Verify with a different public key — should fail
    let verifier = create_test_verifier(keypair2.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);
    let result = verifier.verify_token(&pc.audience, &token).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtVerificationError::InvalidSignature));
}

#[tokio::test]
async fn test_malformed_token_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");
    let verifier = create_test_verifier(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);

    let pc = ParticipantContext::builder()
        .id("participant1")
        .audience("audience1")
        .build();

    let result = verifier.verify_token(&pc.audience, "").await;
    assert!(result.is_err(), "Empty token should fail validation");
    assert!(matches!(result.unwrap_err(), JwtVerificationError::InvalidFormat));

    let result = verifier.verify_token(&pc.audience, "header.payload").await;
    assert!(result.is_err(), "Token missing signature should fail validation");
    assert!(matches!(result.unwrap_err(), JwtVerificationError::InvalidFormat));

    let result = verifier.verify_token(&pc.audience, "not.a.token").await;
    assert!(result.is_err(), "Token with invalid base64 should fail validation");
    match result.unwrap_err() {
        JwtVerificationError::InvalidFormat | JwtVerificationError::VerificationFailed(_) => {}
        other => panic!("Expected InvalidFormat or VerificationFailed, got {:?}", other),
    }

    let result = verifier.verify_token(&pc.audience, "invalid-token").await;
    assert!(result.is_err(), "Token with no dots should fail validation");
    assert!(matches!(result.unwrap_err(), JwtVerificationError::InvalidFormat));
}

#[tokio::test]
async fn test_mismatched_key_format_pem_eddsa() {
    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let keypair_pem = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");
    let generator = create_test_generator(
        keypair_pem.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .exp(now + 10000)
        .build();

    let token = generator
        .generate_token(&pc, claims)
        .await
        .expect("Token generation should succeed");

    let keypair_der = generate_ed25519_keypair_der().expect("Failed to generate DER keypair");
    let verifier = create_test_verifier(keypair_der.public_key, KeyFormat::DER, SigningAlgorithm::EdDSA);
    let result = verifier.verify_token(&pc.audience, &token).await;

    // Different keypair — verification must fail
    assert!(result.is_err());
}

#[tokio::test]
async fn test_audience_mismatch_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .exp(now + 10000)
        .build();

    let pc_generate = ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(&pc_generate, claims)
        .await
        .expect("Token generation should succeed");

    let verifier = create_test_verifier(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);
    let result = verifier.verify_token("different-audience", &token).await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        JwtVerificationError::VerificationFailed(_)
    ));
}

#[tokio::test]
async fn test_algorithm_mismatch_pem() {
    let keypair_eddsa = generate_ed25519_keypair_pem().expect("Failed to generate EdDSA keypair");
    let keypair_rsa = generate_rsa_keypair_pem().expect("Failed to generate RSA keypair");

    let generator = create_test_generator(
        keypair_eddsa.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .exp(now + 10000)
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(&pc, claims)
        .await
        .expect("Token generation should succeed");

    // Verify EdDSA token with an RS256 verifier — should fail
    let verifier = create_test_verifier(keypair_rsa.public_key, KeyFormat::PEM, SigningAlgorithm::RS256);
    let result = verifier.verify_token(&pc.audience, &token).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_not_before_validation_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .nbf(now + 10000) // Not valid for another 10,000 seconds
        .exp(now + 20000)
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(&pc, claims)
        .await
        .expect("Token generation should succeed");

    let verifier = create_test_verifier(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);
    let result = verifier.verify_token(&pc.audience, &token).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtVerificationError::TokenNotYetValid));
}

#[tokio::test]
async fn test_not_before_with_leeway_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-456")
        .iss("user-id-123")
        .aud("audience-123")
        .nbf(now + 20) // Not valid for another 20 seconds
        .exp(now + 10000)
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(&pc, claims)
        .await
        .expect("Token generation should succeed");

    // 30-second leeway should accept a token with nbf 20 seconds in the future
    let verifier = create_test_verifier_with_leeway(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA, 30);
    let verified_claims = verifier
        .verify_token(&pc.audience, &token)
        .await
        .expect("Token should be valid with leeway");

    assert_eq!(verified_claims.sub, "user-id-456");
    assert_eq!(verified_claims.nbf, Some(now + 20));
}

#[tokio::test]
async fn test_not_before_beyond_leeway_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-789")
        .iss("user-id-123")
        .aud("audience-123")
        .nbf(now + 100) // Not valid for another 100 seconds
        .exp(now + 10000)
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(&pc, claims)
        .await
        .expect("Token generation should succeed");

    // 30-second leeway should reject a token with nbf 100 seconds in the future
    let verifier = create_test_verifier_with_leeway(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA, 30);
    let result = verifier.verify_token(&pc.audience, &token).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtVerificationError::TokenNotYetValid));
}
