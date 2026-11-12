// SPDX-License-Identifier: MIT OR Apache-2.0
use std::collections::HashMap;
// Authentication utilities for Synapse
// Provides WebCrypto integration, key management, and cryptographic helpers

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ring::{
    pbkdf2,
    rand::SystemRandom,
    signature::{self, KeyPair as RingKeyPair},
};
use serde::{Deserialize, Serialize};

// Define simplified key types for our use case
#[derive(Debug, Clone)]
pub enum KeyType {
    RSA2048,
    RSA4096,
    EC256,
    EC384,
}

#[derive(Debug, Clone)]
pub enum KeyAlgorithm {
    RSA,
    ECDSA,
    Ed25519,
}

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub algorithm: KeyAlgorithm,
}

pub struct KeyManager {
    keys: HashMap<String, KeyPair>,
}

impl KeyManager {
    /// Create a new KeyManager instance
    pub async fn new() -> anyhow::Result<Self> {
        Ok(Self {
            keys: HashMap::new(),
        })
    }

    /// Generate a new keypair with the specified algorithm and store it
    pub async fn generate_and_store_keypair(
        &mut self,
        key_id: &str,
        algorithm: KeyAlgorithm,
    ) -> anyhow::Result<KeyPair> {
        // Use ring's secure random number generator for all key generation
        let rng = SystemRandom::new();

        let keypair = match algorithm {
            KeyAlgorithm::RSA => return Err(rsa_not_implemented()),
            KeyAlgorithm::ECDSA => {
                // Generate P-256 ECDSA key with ring - this is production ready
                let private_key_doc = signature::EcdsaKeyPair::generate_pkcs8(
                    &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    &rng,
                )?;
                let key_pair = signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    private_key_doc.as_ref(),
                    &rng,
                )?;

                KeyPair {
                    public_key: key_pair.public_key().as_ref().to_vec(),
                    private_key: private_key_doc.as_ref().to_vec(),
                    algorithm: algorithm.clone(),
                }
            }
            KeyAlgorithm::Ed25519 => {
                // Generate 32 secure random bytes for Ed25519 private key
                let mut private_key_bytes = [0u8; 32];
                ring::rand::SecureRandom::fill(&rng, &mut private_key_bytes)
                    .map_err(|_| anyhow::anyhow!("Secure random generation failed"))?;

                let signing_key = SigningKey::from_bytes(&private_key_bytes);
                let verifying_key = signing_key.verifying_key();

                KeyPair {
                    public_key: verifying_key.to_bytes().to_vec(),
                    private_key: signing_key.to_bytes().to_vec(),
                    algorithm: algorithm.clone(),
                }
            }
        };

        // Store the keypair
        self.keys.insert(key_id.to_string(), keypair.clone());

        Ok(keypair)
    }

    /// Load a keypair by ID
    pub async fn load_keypair(&self, key_id: &str) -> anyhow::Result<Option<KeyPair>> {
        Ok(self.keys.get(key_id).cloned())
    }

    /// Derive a key from a password
    pub async fn derive_key_from_password(
        &self,
        password: &str,
        params: &KeyDerivationParams,
    ) -> anyhow::Result<Vec<u8>> {
        // Use PBKDF2 with SHA-256
        let mut derived_key = vec![0u8; 32]; // 256-bit key
        let salt = params.salt.as_bytes();

        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(params.iterations).unwrap(),
            salt,
            password.as_bytes(),
            &mut derived_key,
        );

        Ok(derived_key)
    }

    /// Sign data with a keypair
    pub async fn sign(&self, keypair: &KeyPair, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        match keypair.algorithm {
            KeyAlgorithm::RSA => Err(rsa_not_implemented()),
            KeyAlgorithm::ECDSA => {
                // Use ring for ECDSA signing
                let rng = SystemRandom::new();
                let key_pair = signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    &keypair.private_key,
                    &rng,
                )?;

                let signature = key_pair.sign(&rng, data)?;
                Ok(signature.as_ref().to_vec())
            }
            KeyAlgorithm::Ed25519 => {
                // Use ed25519-dalek for signing
                let private_key_array: [u8; 32] = keypair
                    .private_key
                    .clone()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid Ed25519 private key length"))?;
                let signing_key = SigningKey::from_bytes(&private_key_array);

                let signature: Signature = signing_key.sign(data);
                Ok(signature.to_bytes().to_vec())
            }
        }
    }

    /// Verify a signature.
    ///
    /// The algorithm is chosen from the public key's length: 32 bytes is Ed25519,
    /// 65 bytes is an uncompressed ECDSA P-256 point. `Ok(false)` means the
    /// signature does not verify; any other key length is an `Err`, because it
    /// names no algorithm this function can check. A 33-byte compressed P-256
    /// key is refused by name: ring parses only uncompressed points, and an
    /// `Ok(false)` would read as a forged signature.
    pub async fn verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> anyhow::Result<bool> {
        match public_key.len() {
            32 => {
                let key: [u8; 32] = public_key.try_into()?;
                let Ok(verifying_key) = VerifyingKey::from_bytes(&key) else {
                    return Ok(false);
                };
                let Ok(sig_array) = <[u8; 64]>::try_from(signature) else {
                    return Ok(false);
                };
                let sig = Signature::from_bytes(&sig_array);
                Ok(verifying_key.verify(data, &sig).is_ok())
            }
            33 => Err(anyhow::anyhow!(
                "compressed P-256 public keys (33 bytes) are not supported: give the uncompressed point (65 bytes)"
            )),
            65 => {
                let public_key_input = signature::UnparsedPublicKey::new(
                    &signature::ECDSA_P256_SHA256_FIXED,
                    public_key,
                );
                Ok(public_key_input.verify(data, signature).is_ok())
            }
            n => Err(anyhow::anyhow!(
                "unsupported public key format ({n} bytes): expected Ed25519 (32) or uncompressed ECDSA P-256 (65)"
            )),
        }
    }
}

/// RSA appears in [`KeyAlgorithm`] but has no implementation in this crate.
fn rsa_not_implemented() -> anyhow::Error {
    anyhow::anyhow!("RSA is not implemented; use Ed25519 or ECDSA")
}

/// Key derivation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationParams {
    pub iterations: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
    pub salt: String,
}

impl Default for KeyDerivationParams {
    fn default() -> Self {
        // Generate cryptographically secure random salt
        let rng = SystemRandom::new();
        let mut salt_bytes = [0u8; 16];
        ring::rand::SecureRandom::fill(&rng, &mut salt_bytes).unwrap();
        let salt = BASE64_STANDARD.encode(salt_bytes);

        Self {
            iterations: 100000, // OWASP recommended minimum
            memory_cost: 65536,
            parallelism: 4,
            salt,
        }
    }
}

/// WebCrypto key operations for Synapse
pub struct SynapseKeyManager {
    /// Key manager from auth-framework
    key_manager: KeyManager,

    /// Cache of derived keys
    key_cache: HashMap<String, KeyPair>,
}

impl SynapseKeyManager {
    /// Create a new key manager
    pub async fn new() -> anyhow::Result<Self> {
        let key_manager = KeyManager::new().await?;

        Ok(Self {
            key_manager,
            key_cache: HashMap::new(),
        })
    }

    /// Generate a new key pair
    pub async fn generate_keypair(
        &mut self,
        key_id: &str,
        algorithm: KeyAlgorithm,
    ) -> anyhow::Result<KeyPair> {
        let keypair = self
            .key_manager
            .generate_and_store_keypair(key_id, algorithm)
            .await?;

        // Store in cache as well
        self.key_cache.insert(key_id.to_string(), keypair.clone());

        Ok(keypair)
    }

    /// Get a key pair from cache or storage
    pub async fn get_keypair(&self, _key_id: &str) -> anyhow::Result<Option<KeyPair>> {
        // Check cache first
        if let Some(keypair) = self.key_cache.get(_key_id) {
            return Ok(Some(keypair.clone()));
        }

        // Try to load from storage
        let keypair = self.key_manager.load_keypair(_key_id).await?;

        Ok(keypair)
    }

    /// Derive a key from a password
    pub async fn derive_key_from_password(
        &self,
        password: &str,
        params: &KeyDerivationParams,
    ) -> anyhow::Result<Vec<u8>> {
        // This would delegate to auth-framework's key derivation
        let key = self
            .key_manager
            .derive_key_from_password(password, params)
            .await?;

        Ok(key)
    }

    /// Sign data with a private key
    pub async fn sign(&self, key_id: &str, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        // Get the key pair
        let keypair = match self.get_keypair(key_id).await? {
            Some(keypair) => keypair,
            None => return Err(anyhow::anyhow!("Key not found")),
        };

        let signature = self.key_manager.sign(&keypair, data).await?;

        Ok(signature)
    }

    /// Verify a signature with a public key
    pub async fn verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> anyhow::Result<bool> {
        let is_valid = self.key_manager.verify(public_key, data, signature).await?;

        Ok(is_valid)
    }
}

/// Simulated JsValue for example purposes
/// In a real implementation, this would be from wasm-bindgen
#[derive(Debug, Clone)]
pub struct JsValue;

impl Default for JsValue {
    fn default() -> Self {
        Self
    }
}
