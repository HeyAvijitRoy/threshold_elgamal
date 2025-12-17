use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

pub mod params;
pub mod shamir;
pub mod elgamal;
pub mod vandermonde;

use params::SystemParams;

// Modular exponentiation: base^exp mod modulus
pub fn mod_pow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus.is_one() {
        return BigUint::zero();
    }
    
    let mut result = BigUint::one();
    let mut base = base.clone() % modulus;
    let mut exp = exp.clone();
    
    while exp > BigUint::zero() {
        if &exp % 2u32 == BigUint::one() {
            result = (result * &base) % modulus;
        }
        exp >>= 1;
        base = (&base * &base) % modulus;
    }
    
    result
}

// Modular inverse using extended Euclidean algorithm
pub fn mod_inverse(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    let (mut t, mut newt) = (BigInt::zero(), BigInt::one());
    let (mut r, mut newr) = (m.clone(), a.clone());
    
    while !newr.is_zero() {
        let quotient = &r / &newr;
        (t, newt) = (newt.clone(), t - &quotient * &newt);
        (r, newr) = (newr.clone(), r - quotient * newr);
    }
    
    if r > BigInt::one() {
        return None;
    }
    
    if t < BigInt::zero() {
        t += m;
    }
    
    Some(t)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKey {
    pub g: BigUint,
    pub p: BigUint,
    pub q: BigUint,
    pub a_pub: BigUint, // A = g^a
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecretKeyShare {
    pub player_id: usize,
    pub share: BigUint,
    pub public_key: PublicKey,
    pub player_public_key: BigUint, // A_i = g^{a_i}
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Ciphertext {
    pub b_component: BigUint, // B = g^b
    pub encrypted_message: Vec<u8>, // AES ciphertext
    pub nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DecryptionShare {
    pub player_id: usize,
    pub share_value: BigUint, // B^{w_k * a_{p_k}}
}

// Hash function to derive AES key from group element
pub fn hash_to_key(element: &BigUint) -> [u8; 32] {
    let bytes = element.to_bytes_be();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher.finalize().into()
}

// AES encryption
pub fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption error: {}", e))?;
    
    Ok((ciphertext, nonce_bytes.to_vec()))
}

// AES decryption
pub fn aes_decrypt(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption error: {}", e))
}