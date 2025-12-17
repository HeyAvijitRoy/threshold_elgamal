use num_bigint::RandBigInt;
use rand::thread_rng;
use crate::{PublicKey, Ciphertext, mod_pow, hash_to_key, aes_encrypt};

// Encrypt a message using hybrid ElGamal
pub fn encrypt(public_key: &PublicKey, message: &[u8]) -> Result<Ciphertext, String> {
    let mut rng = thread_rng();
    
    // Choose random b
    let b = rng.gen_biguint_below(&public_key.q);
    
    // Compute B = g^b mod p
    let b_component = mod_pow(&public_key.g, &b, &public_key.p);
    
    // Compute shared secret: A^b mod p (where A = g^a)
    let shared_secret = mod_pow(&public_key.a_pub, &b, &public_key.p);
    
    // Derive AES key from shared secret
    let aes_key = hash_to_key(&shared_secret);
    
    // Encrypt message with AES
    let (encrypted_message, nonce) = aes_encrypt(&aes_key, message)?;
    
    Ok(Ciphertext {
        b_component,
        encrypted_message,
        nonce,
    })
}