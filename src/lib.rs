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
pub struct DecryptionShareProof {
    pub commitment: BigUint,  // R = B^r
    pub response: BigUint,     // z = r + c * (w_k * a_pk) mod q
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DecryptionShare {
    pub player_id: usize,
    pub share_value: BigUint, // B^{w_k * a_{p_k}}
    pub proof: DecryptionShareProof, // ZKP that share_value is correctly computed
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

// Hash function to derive challenge for Fiat-Shamir heuristic
// Hash(B || share_value || R) -> challenge
// Note: We include share_value to bind the proof to the specific claim
// The challenge doesn't need to be reduced - we just use the hash output
pub fn hash_to_challenge(
    b_component: &BigUint,
    share_value: &BigUint,
    commitment: &BigUint,
) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(b_component.to_bytes_be());
    hasher.update(share_value.to_bytes_be());
    hasher.update(commitment.to_bytes_be());
    let hash = hasher.finalize();
    
    // Convert hash to BigUint (256 bits)
    // No reduction needed - the challenge is just the hash value
    BigUint::from_bytes_be(&hash)
}

// Generate ZKP for decryption share
// Proves knowledge of (w_k * a_pk) such that share_value = B^(w_k * a_pk)
// Using Schnorr-like protocol:
// 1. Choose random r
// 2. Compute R = B^r
// 3. Compute challenge c = H(B || share_value || R)
// 4. Compute response z = r + c * (w_k * a_pk) mod q
pub fn generate_decryption_proof(
    b_component: &BigUint,
    share_value: &BigUint,
    exponent: &BigUint,  // w_k * a_pk mod q
    p: &BigUint,
    q: &BigUint,
) -> DecryptionShareProof {
    use rand::thread_rng;
    
    let mut rng = thread_rng();
    
    // 1. Choose random r ← Z_q
    let r = rng.gen_biguint_below(q);
    
    // 2. Compute commitment R = B^r mod p
    let commitment = mod_pow(b_component, &r, p);
    
    // 3. Compute challenge c = H(B || share_value || R)
    let challenge = hash_to_challenge(b_component, share_value, &commitment);
    
    // 4. Compute response z = r + c * exponent
    // Note: We don't reduce mod q because B = g^b might not have order q
    // Instead, we work mod (p-1) since that's the order of the multiplicative group
    // By Fermat's Little Theorem: a^x ≡ a^(x mod (p-1)) (mod p)
    let p_minus_1 = p - BigUint::one();
    let response = (&r + &challenge * exponent) % &p_minus_1;
    
    DecryptionShareProof {
        commitment,
        response,
    }
}

// Verify ZKP for decryption share
// Verifies that share_value = B^(w_k * a_pk) for some secret (w_k * a_pk)
// Check: B^z == R * share_value^c mod p
// where c = H(B || share_value || R)
pub fn verify_decryption_proof(
    b_component: &BigUint,
    share_value: &BigUint,
    proof: &DecryptionShareProof,
    p: &BigUint,
    q: &BigUint,
) -> bool {
    // Recompute challenge c = H(B || share_value || R)
    let challenge = hash_to_challenge(b_component, share_value, &proof.commitment);
    
    // Compute left side: B^z mod p
    let left = mod_pow(b_component, &proof.response, p);
    
    // Compute right side: R * share_value^c mod p
    let share_to_c = mod_pow(share_value, &challenge, p);
    let right = (&proof.commitment * share_to_c) % p;
    
    // Verify equality
    left == right
}