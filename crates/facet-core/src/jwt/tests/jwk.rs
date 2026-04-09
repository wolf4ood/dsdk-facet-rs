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

use crate::jwt::{Jwk, JwkKeyOperation, JwkKeyType, JwkPublicKeyUse, JwkSet};

#[test]
fn jwk_key_type_rsa_serializes_to_uppercase() {
    let json = serde_json::to_string(&JwkKeyType::Rsa).unwrap();
    assert_eq!(json, r#""RSA""#);
}

#[test]
fn jwk_key_type_ec_serializes_to_uppercase() {
    let json = serde_json::to_string(&JwkKeyType::Ec).unwrap();
    assert_eq!(json, r#""EC""#);
}

#[test]
fn jwk_key_type_oct_serializes_to_lowercase() {
    let json = serde_json::to_string(&JwkKeyType::Oct).unwrap();
    assert_eq!(json, r#""oct""#);
}

#[test]
fn jwk_key_type_okp_serializes_to_uppercase() {
    let json = serde_json::to_string(&JwkKeyType::Okp).unwrap();
    assert_eq!(json, r#""OKP""#);
}

#[test]
fn jwk_key_type_round_trips() {
    for kty in [JwkKeyType::Rsa, JwkKeyType::Ec, JwkKeyType::Oct, JwkKeyType::Okp] {
        let json = serde_json::to_string(&kty).unwrap();
        let parsed: JwkKeyType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, kty);
    }
}

#[test]
fn jwk_public_key_use_sig_serializes_to_lowercase() {
    let json = serde_json::to_string(&JwkPublicKeyUse::Sig).unwrap();
    assert_eq!(json, r#""sig""#);
}

#[test]
fn jwk_public_key_use_enc_serializes_to_lowercase() {
    let json = serde_json::to_string(&JwkPublicKeyUse::Enc).unwrap();
    assert_eq!(json, r#""enc""#);
}

#[test]
fn jwk_public_key_use_round_trips() {
    for key_use in [JwkPublicKeyUse::Sig, JwkPublicKeyUse::Enc] {
        let json = serde_json::to_string(&key_use).unwrap();
        let parsed: JwkPublicKeyUse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, key_use);
    }
}

#[test]
fn jwk_key_operation_serializes_camel_case() {
    assert_eq!(serde_json::to_string(&JwkKeyOperation::Sign).unwrap(), r#""sign""#);
    assert_eq!(serde_json::to_string(&JwkKeyOperation::Verify).unwrap(), r#""verify""#);
    assert_eq!(
        serde_json::to_string(&JwkKeyOperation::WrapKey).unwrap(),
        r#""wrapKey""#
    );
    assert_eq!(
        serde_json::to_string(&JwkKeyOperation::UnwrapKey).unwrap(),
        r#""unwrapKey""#
    );
    assert_eq!(
        serde_json::to_string(&JwkKeyOperation::DeriveKey).unwrap(),
        r#""deriveKey""#
    );
    assert_eq!(
        serde_json::to_string(&JwkKeyOperation::DeriveBits).unwrap(),
        r#""deriveBits""#
    );
}

#[test]
fn jwk_key_operation_round_trips() {
    for op in [
        JwkKeyOperation::Sign,
        JwkKeyOperation::Verify,
        JwkKeyOperation::Encrypt,
        JwkKeyOperation::Decrypt,
        JwkKeyOperation::WrapKey,
        JwkKeyOperation::UnwrapKey,
        JwkKeyOperation::DeriveKey,
        JwkKeyOperation::DeriveBits,
    ] {
        let json = serde_json::to_string(&op).unwrap();
        let parsed: JwkKeyOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, op);
    }
}

#[test]
fn jwk_builder_minimal_rsa_key() {
    let jwk = Jwk::builder().kty(JwkKeyType::Rsa).build();

    assert_eq!(jwk.kty, JwkKeyType::Rsa);
    assert!(jwk.key_use.is_none());
    assert!(jwk.alg.is_none());
    assert!(jwk.kid.is_none());
    assert!(jwk.key_ops.is_empty());
}

#[test]
fn jwk_builder_okp_ed25519_key() {
    let jwk = Jwk::builder()
        .kty(JwkKeyType::Okp)
        .crv("Ed25519")
        .x("base64url-encoded-public-key")
        .kid("key-1")
        .key_use(JwkPublicKeyUse::Sig)
        .alg("EdDSA")
        .build();

    assert_eq!(jwk.kty, JwkKeyType::Okp);
    assert_eq!(jwk.crv.as_deref(), Some("Ed25519"));
    assert_eq!(jwk.x.as_deref(), Some("base64url-encoded-public-key"));
    assert_eq!(jwk.kid.as_deref(), Some("key-1"));
    assert_eq!(jwk.key_use, Some(JwkPublicKeyUse::Sig));
    assert_eq!(jwk.alg.as_deref(), Some("EdDSA"));
}

#[test]
fn jwk_optional_fields_omitted_from_json_when_absent() {
    let jwk = Jwk::builder().kty(JwkKeyType::Okp).build();
    let json = serde_json::to_string(&jwk).unwrap();

    assert!(!json.contains("\"use\""));
    assert!(!json.contains("\"key_ops\""));
    assert!(!json.contains("\"alg\""));
    assert!(!json.contains("\"kid\""));
    assert!(!json.contains("\"n\""));
    assert!(!json.contains("\"crv\""));
    assert!(!json.contains("\"x\""));
}

#[test]
fn jwk_serializes_use_field_with_correct_name() {
    let jwk = Jwk::builder()
        .kty(JwkKeyType::Rsa)
        .key_use(JwkPublicKeyUse::Sig)
        .build();
    let json = serde_json::to_string(&jwk).unwrap();

    assert!(json.contains(r#""use":"sig""#));
}

#[test]
fn jwk_serializes_key_ops_field() {
    let jwk = Jwk::builder()
        .kty(JwkKeyType::Rsa)
        .key_ops(vec![JwkKeyOperation::Sign, JwkKeyOperation::Verify])
        .build();
    let json = serde_json::to_string(&jwk).unwrap();

    assert!(json.contains(r#""key_ops""#));
    assert!(json.contains(r#""sign""#));
    assert!(json.contains(r#""verify""#));
}

#[test]
fn jwk_empty_key_ops_omitted_from_json() {
    let jwk = Jwk::builder().kty(JwkKeyType::Rsa).build();
    let json = serde_json::to_string(&jwk).unwrap();

    assert!(!json.contains("key_ops"));
}

#[test]
fn jwk_x5t_s256_uses_correct_json_field_name() {
    let jwk = Jwk::builder().kty(JwkKeyType::Rsa).x5t_s256("thumbprint-value").build();
    let json = serde_json::to_string(&jwk).unwrap();

    assert!(json.contains(r#""x5t#S256":"thumbprint-value""#));
}

#[test]
fn jwk_round_trips_via_json() {
    let original = Jwk::builder()
        .kty(JwkKeyType::Okp)
        .crv("Ed25519")
        .x("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .kid("my-key")
        .key_use(JwkPublicKeyUse::Sig)
        .alg("EdDSA")
        .build();

    let json = serde_json::to_string(&original).unwrap();
    let parsed: Jwk = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed, original);
}

#[test]
fn jwk_rsa_parameters_round_trip() {
    let original = Jwk::builder()
        .kty(JwkKeyType::Rsa)
        .n("modulus")
        .e("AQAB")
        .kid("rsa-key-1")
        .alg("RS256")
        .key_use(JwkPublicKeyUse::Sig)
        .build();

    let json = serde_json::to_string(&original).unwrap();
    let parsed: Jwk = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.n.as_deref(), Some("modulus"));
    assert_eq!(parsed.e.as_deref(), Some("AQAB"));
    assert_eq!(parsed, original);
}

#[test]
fn jwk_set_empty_serializes_correctly() {
    let set = JwkSet { keys: vec![] };
    let json = serde_json::to_string(&set).unwrap();

    assert_eq!(json, r#"{"keys":[]}"#);
}

#[test]
fn jwk_set_with_keys_round_trips() {
    let key1 = Jwk::builder()
        .kty(JwkKeyType::Okp)
        .crv("Ed25519")
        .x("key1-x-value")
        .kid("key-1")
        .key_use(JwkPublicKeyUse::Sig)
        .alg("EdDSA")
        .build();
    let key2 = Jwk::builder()
        .kty(JwkKeyType::Okp)
        .crv("Ed25519")
        .x("key2-x-value")
        .kid("key-2")
        .key_use(JwkPublicKeyUse::Sig)
        .alg("EdDSA")
        .build();

    let original = JwkSet { keys: vec![key1, key2] };
    let json = serde_json::to_string(&original).unwrap();
    let parsed: JwkSet = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed, original);
    assert_eq!(parsed.keys.len(), 2);
    assert_eq!(parsed.keys[0].kid.as_deref(), Some("key-1"));
    assert_eq!(parsed.keys[1].kid.as_deref(), Some("key-2"));
}

#[test]
fn jwk_set_json_has_keys_field() {
    let set = JwkSet {
        keys: vec![Jwk::builder().kty(JwkKeyType::Rsa).build()],
    };
    let json = serde_json::to_string(&set).unwrap();

    assert!(json.starts_with(r#"{"keys":"#));
}

#[test]
fn jwk_set_deserialized_from_rfc_example() {
    // Minimal JWKS JSON as would be returned by a JWKS endpoint
    let json = r#"{"keys":[{"kty":"OKP","use":"sig","alg":"EdDSA","kid":"key-1","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}"#;
    let set: JwkSet = serde_json::from_str(json).unwrap();

    assert_eq!(set.keys.len(), 1);
    let key = &set.keys[0];
    assert_eq!(key.kty, JwkKeyType::Okp);
    assert_eq!(key.key_use, Some(JwkPublicKeyUse::Sig));
    assert_eq!(key.alg.as_deref(), Some("EdDSA"));
    assert_eq!(key.kid.as_deref(), Some("key-1"));
    assert_eq!(key.crv.as_deref(), Some("Ed25519"));
}
