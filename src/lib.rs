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

/// Computes modular exponentiation: base^exp mod modulus
/// Uses binary exponentiation for efficiency - O(log exp) multiplications
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

/// Computes modular multiplicative inverse using Extended Euclidean Algorithm
/// Returns Some(a^-1 mod m) if it exists, None otherwise
/// The inverse exists iff gcd(a, m) = 1
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
    pub a_pub: BigUint, // Public key: A = g^a where a is the secret
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecretKeyShare {
    pub player_id: usize,
    pub share: BigUint,
    pub public_key: PublicKey,
    pub player_public_key: BigUint, // Individual public key: A_i = g^{a_i}
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Ciphertext {
    pub b_component: BigUint, // ElGamal component: B = g^b where b is ephemeral
    pub encrypted_message: Vec<u8>, // Hybrid: message encrypted with AES
    pub nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DecryptionShareProof {
    pub commitment: BigUint,  // Schnorr commitment: R = B^r for random r
    pub response: BigUint,     // Schnorr response: z = r + c*(w_k * a_pk) mod (p-1)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DecryptionShare {
    pub player_id: usize,
    pub share_value: BigUint, // Decryption contribution: B^{w_k * a_{p_k}}
    pub proof: DecryptionShareProof, // Zero-knowledge proof of correct computation
}

/// Derives AES-256 key from a group element using SHA-256
/// Used to convert ElGamal shared secret into symmetric encryption key
pub fn hash_to_key(element: &BigUint) -> [u8; 32] {
    let bytes = element.to_bytes_be();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher.finalize().into()
}

/// Encrypts plaintext using AES-256-GCM with a random nonce
/// Returns (ciphertext, nonce) tuple for authenticated encryption
pub fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption error: {}", e))?;
    
    Ok((ciphertext, nonce_bytes.to_vec()))
}

/// Decrypts ciphertext using AES-256-GCM with the provided nonce
/// Verifies authenticity and returns plaintext on success
pub fn aes_decrypt(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption error: {}", e))
}

/// Derives challenge for Fiat-Shamir heuristic using SHA-256
/// 
/// Computes: c = H(B || share_value || R)
/// 
/// Including all three values binds the challenge to:
/// - The ciphertext component B
/// - The claimed share value
/// - The proof commitment R
/// 
/// This makes the proof non-interactive and secure in the random oracle model.
/// The 256-bit hash output provides sufficient challenge space.
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
    
    BigUint::from_bytes_be(&hash)
}

/// Generates a zero-knowledge proof for a decryption share
/// 
/// Proves knowledge of exponent x = (w_k * a_pk) such that share_value = B^x,
/// without revealing x itself. Based on Schnorr's identification protocol.
/// 
/// Protocol steps:
/// 1. Choose random r ← Z_q
/// 2. Compute commitment: R = B^r mod p
/// 3. Compute challenge: c = H(B || share_value || R)  [Fiat-Shamir]
/// 4. Compute response: z = r + c*x mod (p-1)
/// 
/// The verifier can check: B^z = R * share_value^c (mod p)
/// 
/// Important: We reduce the response modulo (p-1) rather than q because:
/// - B = g^b has unknown order (not necessarily q)
/// - The full multiplicative group mod p has order (p-1)
/// - By Fermat's Little Theorem: a^x ≡ a^(x mod (p-1)) (mod p)
pub fn generate_decryption_proof(
    b_component: &BigUint,
    share_value: &BigUint,
    exponent: &BigUint,  // w_k * a_pk mod q
    p: &BigUint,
    q: &BigUint,
) -> DecryptionShareProof {
    use rand::thread_rng;
    
    let mut rng = thread_rng();
    
    let r = rng.gen_biguint_below(q);
    let commitment = mod_pow(b_component, &r, p);
    let challenge = hash_to_challenge(b_component, share_value, &commitment);
    
    let p_minus_1 = p - BigUint::one();
    let response = (&r + &challenge * exponent) % &p_minus_1;
    
    DecryptionShareProof {
        commitment,
        response,
    }
}

/// Verifies a zero-knowledge proof for a decryption share
/// 
/// Checks that the prover knows x such that share_value = B^x,
/// without learning anything about x itself.
/// 
/// Verification equation: B^z ≟ R * share_value^c (mod p)
/// where c = H(B || share_value || R) is recomputed
/// 
/// This works because:
/// - If share_value = B^x and z = r + c*x, then:
/// - B^z = B^(r + c*x) = B^r * B^(c*x) = R * (B^x)^c = R * share_value^c
/// 
/// Soundness: A cheating prover cannot forge a valid proof without knowing x
/// Zero-knowledge: The proof reveals nothing about x beyond the validity of the claim
pub fn verify_decryption_proof(
    b_component: &BigUint,
    share_value: &BigUint,
    proof: &DecryptionShareProof,
    p: &BigUint,
    q: &BigUint,
) -> bool {
    let challenge = hash_to_challenge(b_component, share_value, &proof.commitment);
    
    let left = mod_pow(b_component, &proof.response, p);
    
    let share_to_c = mod_pow(share_value, &challenge, p);
    let right = (&proof.commitment * share_to_c) % p;
    
    left == right
}