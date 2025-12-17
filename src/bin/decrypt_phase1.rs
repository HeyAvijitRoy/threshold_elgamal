use clap::Parser;
use num_bigint::{BigInt, BigUint, ToBigInt};
use std::fs;
use threshold_elgamal::*;
use threshold_elgamal::vandermonde::compute_lagrange_coefficients;

#[derive(Parser, Debug)]
#[command(name = "decrypt_phase1")]
#[command(about = "Phase 1: Generate decryption share", long_about = None)]
struct Args {
    /// Player's secret key file
    #[arg(short, long)]
    key_file: String,
    
    /// Ciphertext file
    #[arg(short, long)]
    ciphertext: String,
    
    /// List of participating player IDs (comma-separated)
    #[arg(short, long)]
    players: String,
    
    /// Output file for decryption share
    #[arg(short, long)]
    output: String,
    
    /// Enable debug output
    #[arg(short, long)]
    debug: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Load this player's secret key share from file
    println!("Loading secret key from {}...", args.key_file);
    let key_json = fs::read_to_string(&args.key_file)?;
    let secret_share: SecretKeyShare = serde_json::from_str(&key_json)?;
    
    println!("Player ID: {}", secret_share.player_id);
    
    // Load the ciphertext to be decrypted
    println!("Loading ciphertext from {}...", args.ciphertext);
    let ciphertext_json = fs::read_to_string(&args.ciphertext)?;
    let ciphertext: Ciphertext = serde_json::from_str(&ciphertext_json)?;
    
    // Parse the list of players participating in this decryption
    let player_ids: Vec<usize> = args.players
        .split(',')
        .map(|s| s.trim().parse())
        .collect::<Result<Vec<_>, _>>()?;
    
    println!("Participating players: {:?}", player_ids);
    
    // Validate that this player is authorized to participate
    if !player_ids.contains(&secret_share.player_id) {
        return Err(format!(
            "Player {} is not in the participating players list",
            secret_share.player_id
        ).into());
    }
    
    if player_ids.len() < 2 {
        return Err("Need at least 2 players for threshold decryption".into());
    }
    
    // Compute Lagrange coefficients for polynomial interpolation
    // These allow reconstructing the secret from the participating subset of shares
    println!("Computing Lagrange coefficients...");
    let q_bigint = secret_share.public_key.q.to_bigint().unwrap();
    let coefficients = compute_lagrange_coefficients(&player_ids, &q_bigint);
    
    if args.debug {
        println!("All Lagrange coefficients:");
        for (i, coeff) in coefficients.iter().enumerate() {
            println!("  Player {} (ID {}): coefficient bits = {}", i, player_ids[i], coeff.bits());
        }
    }
    
    // Extract the Lagrange coefficient for this player
    let player_index = player_ids
        .iter()
        .position(|&id| id == secret_share.player_id)
        .unwrap();
    let w_k = &coefficients[player_index];
    
    println!("Player's Lagrange coefficient computed (index {})", player_index);
    
    if args.debug {
        println!("  w_k bits: {}", w_k.bits());
        println!("  a_pk bits: {}", secret_share.share.bits());
    }
    
    // Compute the weighted exponent: w_k * a_{p_k} mod q
    // This combines the player's share with their Lagrange coefficient
    let share_bigint = secret_share.share.to_bigint().unwrap();
    let exponent = (w_k * share_bigint) % &q_bigint;
    
    // Ensure the result is positive (mod q can return negative in BigInt)
    let exponent = if exponent < BigInt::from(0) {
        exponent + &q_bigint
    } else {
        exponent
    };
    
    let exponent_uint = exponent.to_biguint().unwrap();
    
    if args.debug {
        println!("  Exponent (w_k * a_pk mod q) bits: {}", exponent_uint.bits());
    }
    
    // Compute the decryption share: B^{w_k * a_{p_k}} mod p
    // This is this player's contribution to the joint decryption
    println!("Computing decryption share...");
    let share_value = mod_pow(
        &ciphertext.b_component,
        &exponent_uint,
        &secret_share.public_key.p,
    );
    
    if args.debug {
        println!("  B component bits: {}", ciphertext.b_component.bits());
        println!("  Share value bits: {}", share_value.bits());
    }
    
    // Generate a zero-knowledge proof that this share was computed correctly
    // This allows other players to verify honesty without revealing the secret
    println!("Generating Zero-Knowledge Proof...");
    let proof = threshold_elgamal::generate_decryption_proof(
        &ciphertext.b_component,
        &share_value,
        &exponent_uint,
        &secret_share.public_key.p,
        &secret_share.public_key.q,
    );
    
    if args.debug {
        println!("  Proof commitment bits: {}", proof.commitment.bits());
        println!("  Proof response bits: {}", proof.response.bits());
    }
    
    let decryption_share = DecryptionShare {
        player_id: secret_share.player_id,
        share_value,
        proof,
    };
    
    // Save decryption share
    let share_json = serde_json::to_string_pretty(&decryption_share)?;
    fs::write(&args.output, share_json)?;
    
    println!("✓ Decryption share generated!");
    println!("  Share saved to: {}", args.output);
    println!("\nShare this file with other participating players for Phase 2.");
    
    Ok(())
}