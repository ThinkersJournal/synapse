// SPDX-License-Identifier: MIT OR Apache-2.0
//! The JWT dependency has a crypto backend.
//!
//! From 10.x, `jsonwebtoken` ships no crypto by default: with neither `rust_crypto` nor
//! `aws_lc_rs` enabled it **compiles**, then panics the first time anything signs or verifies
//! ("Could not automatically determine the process-level CryptoProvider"). Synapse validates
//! email-verification tokens with it (`src/synapse/auth/mod.rs`), so a version bump that forgets
//! the feature would build, pass every test that never decodes a token, and crash in use.
//! `aws_lc_rs` is chosen because `rust_crypto` pulls `rsa` (RUSTSEC-2023-0071, no fix) and
//! `aws-lc-rs` is already in the tree through rustls.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: u64,
}

#[test]
fn an_hs256_token_round_trips_through_the_jwt_dependency() {
    let claims = Claims {
        sub: "assistant@ai-lab.example.com".into(),
        exp: 4_102_444_800, // 2100-01-01
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(b"test-secret").unwrap(),
    )
    .expect("sign");
    let decoded = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(b"test-secret").unwrap(),
        &Validation::new(Algorithm::HS256),
    )
    .expect("verify");
    assert_eq!(decoded.claims, claims);

    let forged = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(b"another-secret").unwrap(),
        &Validation::new(Algorithm::HS256),
    );
    assert!(
        forged.is_err(),
        "a token signed with another secret must not verify"
    );
}
