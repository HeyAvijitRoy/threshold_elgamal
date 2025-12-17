use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_traits::One;
use rand::thread_rng;
use threshold_elgamal::*;
use threshold_elgamal::elgamal::encrypt;
use threshold_elgamal::params::SystemParams;
use threshold_elgamal::shamir::generate_shares;
use threshold_elgamal::vandermonde::compute_lagrange_coefficients;

fn main() {
    println!("Testing Threshold ElGamal Implementation\n");
    
    // Test parameters
    let num_players = 5;
    let threshold = 1; // need 2 players to decrypt
    let message = b"Hey Proma! You are amazing.";
    let player_ids = vec![1, 3, 5]; // Using players 1, 3, 5
    
    println!("Configuration:");
    println!("  Players: {}", num_players);
    println!("  Threshold: {} (need {} to decrypt)", threshold, threshold + 1);
    println!("  Using players: {:?}", player_ids);
    println!("  Message: {}", String::from_utf8_lossy(message));
    
    // Load system parameters
    let g = SystemParams::g();
    let p = SystemParams::p();
    let q = SystemParams::q();
    
    println!("\nStep 1: Key Generation");
    let mut rng = thread_rng();
    let secret_key = rng.gen_biguint_below(&q);
    let a_pub = mod_pow(&g, &secret_key, &p);
    
    let public_key = PublicKey {
        g: g.clone(),
        p: p.clone(),
        q: q.clone(),
        a_pub: a_pub.clone(),
    };
    
    println!("  Secret key bits: {}", secret_key.bits());
    println!("  Public key bits: {}", a_pub.bits());
    
    // Generate Shamir shares
    let (shares, coefficients) = generate_shares(&secret_key, threshold, num_players, &q);
    println!("  Generated {} shares", shares.len());
    
    // Verify shares by reconstructing secret (just for testing)
    println!("\nStep 2: Verify Shamir Sharing");
    let q_bigint = q.to_bigint().unwrap();
    let lagrange_coeffs = compute_lagrange_coefficients(&player_ids, &q_bigint);
    
    let mut reconstructed = BigInt::from(0);
    for (i, &player_id) in player_ids.iter().enumerate() {
        let share = &shares.iter().find(|(id, _)| *id == player_id).unwrap().1;
        let share_bigint = share.to_bigint().unwrap();
        reconstructed = (reconstructed + &lagrange_coeffs[i] * share_bigint) % &q_bigint;
    }
    
    let reconstructed_uint = reconstructed.to_biguint().unwrap();
    let matches = reconstructed_uint == secret_key;
    println!("  Secret reconstruction: {}", if matches { "✓ SUCCESS" } else { "✗ FAILED" });
    
    if !matches {
        println!("    Original: {} bits", secret_key.bits());
        println!("    Reconstructed: {} bits", reconstructed_uint.bits());
        println!("  ERROR: Secret key reconstruction failed!");
        return;
    }
    
    println!("\nStep 3: Encryption");
    let ciphertext = encrypt(&public_key, message).unwrap();
    println!("  Ciphertext B component bits: {}", ciphertext.b_component.bits());
    println!("  Encrypted message length: {} bytes", ciphertext.encrypted_message.len());
    
    println!("\nStep 4: Decryption Phase 1 (Generate Shares)");
    let mut decryption_shares = Vec::new();
    
    for &player_id in &player_ids {
        let share = &shares.iter().find(|(id, _)| *id == player_id).unwrap().1;
        let player_index = player_ids.iter().position(|&id| id == player_id).unwrap();
        let w_k = &lagrange_coeffs[player_index];
        
        // Compute exponent: w_k * a_{p_k} mod q
        let share_bigint = share.to_bigint().unwrap();
        let exponent = (w_k * share_bigint) % &q_bigint;
        let exponent = if exponent < BigInt::from(0) {
            exponent + &q_bigint
        } else {
            exponent
        };
        let exponent_uint = exponent.to_biguint().unwrap();
        
        // Compute B^{w_k * a_{p_k}} mod p
        let share_value = mod_pow(&ciphertext.b_component, &exponent_uint, &p);
        
        println!("  Player {}: share value bits = {}", player_id, share_value.bits());
        
        decryption_shares.push(DecryptionShare {
            player_id,
            share_value,
        });
    }
    
    println!("\nStep 5: Decryption Phase 2 (Combine Shares)");
    let mut b_to_a = BigUint::one();
    for share in &decryption_shares {
        b_to_a = (&b_to_a * &share.share_value) % &p;
        println!("  After player {}: combined bits = {}", share.player_id, b_to_a.bits());
    }
    
    println!("  Combined B^a bits: {}", b_to_a.bits());
    
    // Derive AES key
    let aes_key = hash_to_key(&b_to_a);
    println!("  AES key (first 8 bytes): {:02x?}", &aes_key[..8]);
    
    // Decrypt
    match aes_decrypt(&aes_key, &ciphertext.encrypted_message, &ciphertext.nonce) {
        Ok(plaintext) => {
            let decrypted_text = String::from_utf8_lossy(&plaintext);
            println!("\nStep 6: Result");
            println!("  Decrypted: {}", decrypted_text);
            
            if plaintext == message {
                println!("\n✅ SUCCESS! Decryption matches original message!");
            } else {
                println!("\n❌ FAILED! Decrypted message doesn't match!");
            }
        }
        Err(e) => {
            println!("\n❌ Decryption failed: {}", e);
            
            // Debug: try to compute what the correct shared secret should be
            println!("\nDebug: Computing expected shared secret...");
            let expected_shared = mod_pow(&ciphertext.b_component, &secret_key, &p);
            println!("  Expected B^a bits: {}", expected_shared.bits());
            println!("  Got B^a bits: {}", b_to_a.bits());
            println!("  Match: {}", expected_shared == b_to_a);
        }
    }
}