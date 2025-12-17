use clap::Parser;
use num_bigint::BigUint;
use num_traits::One;
use std::fs;
use threshold_elgamal::*;

#[derive(Parser, Debug)]
#[command(name = "decrypt_phase2")]
#[command(about = "Phase 2: Combine shares and decrypt", long_about = None)]
struct Args {
    /// Ciphertext file
    #[arg(short, long)]
    ciphertext: String,
    
    /// Public key file
    #[arg(short, long)]
    public_key: String,
    
    /// Decryption share files (comma-separated)
    #[arg(short, long)]
    shares: String,
    
    /// Output file for decrypted message
    #[arg(short, long, default_value = "decrypted.txt")]
    output: String,
    
    /// Enable debug output
    #[arg(short, long)]
    debug: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Load public key
    println!("Loading public key from {}...", args.public_key);
    let public_key_json = fs::read_to_string(&args.public_key)?;
    let public_key: PublicKey = serde_json::from_str(&public_key_json)?;
    
    // Load ciphertext
    println!("Loading ciphertext from {}...", args.ciphertext);
    let ciphertext_json = fs::read_to_string(&args.ciphertext)?;
    let ciphertext: Ciphertext = serde_json::from_str(&ciphertext_json)?;
    
    // Load all decryption shares
    let share_files: Vec<&str> = args.shares.split(',').map(|s| s.trim()).collect();
    println!("Loading {} decryption shares...", share_files.len());
    
    let mut decryption_shares = Vec::new();
    for file in &share_files {
        let share_json = fs::read_to_string(file)?;
        let share: DecryptionShare = serde_json::from_str(&share_json)?;
        println!("  Loaded share from player {}", share.player_id);
        decryption_shares.push(share);
    }
    
    if decryption_shares.is_empty() {
        return Err("No decryption shares provided".into());
    }
    
    // Verify all ZKPs before combining shares
    println!("Verifying Zero-Knowledge Proofs...");
    for share in &decryption_shares {
        let is_valid = threshold_elgamal::verify_decryption_proof(
            &ciphertext.b_component,
            &share.share_value,
            &share.proof,
            &public_key.p,
            &public_key.q,
        );
        
        if !is_valid {
            return Err(format!(
                "❌ ZKP verification failed for player {}! Share may be invalid or malicious.",
                share.player_id
            ).into());
        }
        
        println!("  ✓ Player {} proof verified", share.player_id);
    }
    
    println!("✓ All proofs verified successfully!");
    
    // Combine shares: B^a = ∏ B^{w_k * a_{p_k}}
    println!("Combining decryption shares...");
    let mut b_to_a = BigUint::one();
    
    for share in &decryption_shares {
        b_to_a = (&b_to_a * &share.share_value) % &public_key.p;
        
        if args.debug {
            println!("  After player {}: B^a mod p has {} bits", 
                     share.player_id, b_to_a.bits());
        }
    }
    
    if args.debug {
        println!("Combined B^a: {} bits", b_to_a.bits());
        println!("B component: {} bits", ciphertext.b_component.bits());
    }
    
    println!("Computing AES key...");
    // Derive AES key from B^a
    let aes_key = hash_to_key(&b_to_a);
    
    if args.debug {
        println!("AES key (first 8 bytes): {:02x?}", &aes_key[..8]);
    }
    
    // Decrypt the AES ciphertext
    println!("Decrypting message...");
    let plaintext = aes_decrypt(&aes_key, &ciphertext.encrypted_message, &ciphertext.nonce)?;
    
    // Save decrypted message
    fs::write(&args.output, &plaintext)?;
    
    println!("✓ Decryption complete!");
    println!("  Decrypted message saved to: {}", args.output);
    
    // Try to print message if it's valid UTF-8
    if let Ok(text) = String::from_utf8(plaintext.clone()) {
        println!("\nDecrypted message:");
        println!("---");
        println!("{}", text);
        println!("---");
    } else {
        println!("\nDecrypted {} bytes (binary data)", plaintext.len());
    }
    
    Ok(())
}