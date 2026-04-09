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
use serde::{Deserialize, Serialize};

/// Cryptographic algorithm family of a JWK (`kty` parameter, RFC 7517 §4.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JwkKeyType {
    #[serde(rename = "RSA")]
    Rsa,
    #[serde(rename = "EC")]
    Ec,
    /// Octet sequence (symmetric key)
    #[serde(rename = "oct")]
    Oct,
    /// Octet key pair (Ed25519, RFC 8037)
    #[serde(rename = "OKP")]
    Okp,
}

/// Intended use of a public key (`use` parameter, RFC 7517 §4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JwkPublicKeyUse {
    /// Digital signature or MAC
    Sig,
    /// Encryption
    Enc,
}

/// Key operation (`key_ops` values, RFC 7517 §4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JwkKeyOperation {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    WrapKey,
    UnwrapKey,
    DeriveKey,
    DeriveBits,
}

/// A JSON Web Key (JWK) as defined by RFC 7517.
///
/// Common parameters are defined in RFC 7517 §4. Key-type-specific parameters
/// (`n`, `e`, `crv`, `x`, `y`, `d`, `k`, etc.) follow RFC 7518 §6 and RFC 8037.
/// All key material is base64url-encoded per the respective RFC sections.
#[derive(Debug, Clone, Builder, Serialize, Deserialize, PartialEq)]
#[builder(on(String, into))]
pub struct Jwk {
    /// Key Type — identifies the cryptographic algorithm family (REQUIRED).
    pub kty: JwkKeyType,

    /// Public Key Use — intended use of the public key (OPTIONAL).
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<JwkPublicKeyUse>,

    /// Key Operations — operations for which the key is intended (OPTIONAL).
    #[builder(default)]
    #[serde(default, rename = "key_ops", skip_serializing_if = "Vec::is_empty")]
    pub key_ops: Vec<JwkKeyOperation>,

    /// Algorithm intended for use with the key (OPTIONAL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// Key ID — used to match a specific key (OPTIONAL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// X.509 URL — URI for the key's X.509 certificate (OPTIONAL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    /// X.509 Certificate Chain (OPTIONAL).
    #[builder(default)]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub x5c: Vec<String>,

    /// X.509 Certificate SHA-1 Thumbprint (OPTIONAL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    /// X.509 Certificate SHA-256 Thumbprint (OPTIONAL).
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,

    // --- RSA parameters (RFC 7518 §6.3) ---
    /// Modulus (RSA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// Exponent (RSA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// Private Exponent (RSA) / Private Key (EC, OKP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    /// First Prime Factor (RSA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    /// Second Prime Factor (RSA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    /// First Factor CRT Exponent (RSA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dp: Option<String>,
    /// Second Factor CRT Exponent (RSA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dq: Option<String>,
    /// First CRT Coefficient (RSA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qi: Option<String>,

    // --- EC / OKP parameters (RFC 7518 §6.2, RFC 8037) ---
    /// Curve name, e.g. "P-256", "Ed25519".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// X Coordinate (EC) or Public Key bytes (OKP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Y Coordinate (EC only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    // --- Symmetric key parameter (RFC 7518 §6.4) ---
    /// Key Value (oct).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k: Option<String>,
}

/// A JSON Web Key Set (JWKS) as defined by RFC 7517 §5.
#[derive(Debug, Clone, Builder, Serialize, Deserialize, PartialEq)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}
