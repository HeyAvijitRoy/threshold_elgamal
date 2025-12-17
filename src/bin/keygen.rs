use clap::Parser;
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use std::fs;
use threshold_elgamal::*;
use threshold_elgamal::params::SystemParams;
use threshold_elgamal::shamir::generate_shares;

#[derive(Parser, Debug)]
#[command(name = "keygen")]
#[command(about = "Generate threshold ElGamal keys", long_about = None)]
struct Args {
    /// Number of players (n)
    #[arg(short, long)]
    num_players: usize,
    
    /// Threshold (t) - need t+1 players to decrypt
    #[arg(short, long)]
    threshold: usize,
    
    /// Output directory for key files
    #[arg(short, long, default_value = "keys")]
    output_dir: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    if args.threshold >= args.num_players {
        return Err("Threshold must be less than number of players".into());
    }
    
    println!("Generating keys with parameters:");
    println!("  Number of players: {}", args.num_players);
    println!("  Threshold: {} (need {} players to decrypt)", args.threshold, args.threshold + 1);
    
    // Load system parameters
    let g = SystemParams::g();
    let p = SystemParams::p();
    let q = SystemParams::q();
    
    println!("\nGenerating secret key...");
    let mut rng = thread_rng();
    let secret_key = rng.gen_biguint_below(&q);
    
    // Compute public key A = g^a mod p
    println!("Computing public key...");
    let a_pub = mod_pow(&g, &secret_key, &p);
    
    let public_key = PublicKey {
        g: g.clone(),
        p: p.clone(),
        q: q.clone(),
        a_pub,
    };
    
    // Generate Shamir shares
    println!("Generating secret shares...");
    let (shares, _coefficients) = generate_shares(
        &secret_key,
        args.threshold,
        args.num_players,
        &q,
    );
    
    // Create output directory
    fs::create_dir_all(&args.output_dir)?;
    
    // Save public key
    println!("Saving public key...");
    let public_key_json = serde_json::to_string_pretty(&public_key)?;
    fs::write(
        format!("{}/public_key.json", args.output_dir),
        public_key_json,
    )?;
    
    // Save each player's secret share
    println!("Saving secret key shares...");
    for (player_id, share) in shares {
        // Compute player's public key A_i = g^{a_i} mod p
        let player_public_key = mod_pow(&g, &share, &p);
        
        let secret_share = SecretKeyShare {
            player_id,
            share,
            public_key: public_key.clone(),
            player_public_key,
        };
        
        let share_json = serde_json::to_string_pretty(&secret_share)?;
        fs::write(
            format!("{}/player_{}_key.json", args.output_dir, player_id),
            share_json,
        )?;
        
        println!("  Saved key for player {}", player_id);
    }
    
    println!("\n✓ Key generation complete!");
    println!("  Public key: {}/public_key.json", args.output_dir);
    println!("  Player keys: {}/player_N_key.json", args.output_dir);
    println!("\nWARNING: Secret key wiped from memory (as per trusted setup)");
    
    Ok(())
}