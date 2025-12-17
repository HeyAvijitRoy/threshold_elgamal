use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_traits::One;
use rand::thread_rng;
use std::fs;
use std::io::{self, Write};
use threshold_elgamal::*;
use threshold_elgamal::elgamal::encrypt;
use threshold_elgamal::params::SystemParams;
use threshold_elgamal::shamir::generate_shares;
use threshold_elgamal::vandermonde::compute_lagrange_coefficients;

fn read_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn read_number(prompt: &str) -> usize {
    loop {
        let input = read_input(prompt);
        match input.parse() {
            Ok(num) => return num,
            Err(_) => println!("Invalid number. Please try again."),
        }
    }
}

fn main_menu() {
    loop {
        println!("\n╔════════════════════════════════════════════╗");
        println!("║   THRESHOLD ELGAMAL ENCRYPTION SYSTEM      ║");
        println!("╚════════════════════════════════════════════╝");
        println!("\nMain Menu:");
        println!("  1. Generate Keys");
        println!("  2. Encrypt Message");
        println!("  3. Decrypt Message (Phase 1 - Generate Share)");
        println!("  4. Decrypt Message (Phase 2 - Combine Shares)");
        println!("  5. Exit");
        
        let choice = read_input("\nEnter your choice (1-5): ");
        
        match choice.as_str() {
            "1" => generate_keys_interactive(),
            "2" => encrypt_interactive(),
            "3" => decrypt_phase1_interactive(),
            "4" => decrypt_phase2_interactive(),
            "5" => {
                println!("\nGoodbye!");
                break;
            }
            _ => println!("\nInvalid choice. Please try again."),
        }
    }
}

fn generate_keys_interactive() {
    println!("\n═══════════════════════════════════════");
    println!("         KEY GENERATION");
    println!("═══════════════════════════════════════");
    
    let num_players = read_number("\nEnter number of players (n): ");
    
    if num_players < 2 {
        println!("❌ Error: Need at least 2 players");
        return;
    }
    
    let threshold = read_number(&format!("Enter threshold (t) - need t+1 players to decrypt (0 to {}): ", num_players - 1));
    
    if threshold >= num_players {
        println!("❌ Error: Threshold must be less than number of players");
        return;
    }
    
    let output_dir = read_input("\nEnter output directory [keys]: ");
    let output_dir = if output_dir.is_empty() { "keys".to_string() } else { output_dir };
    
    println!("\n📊 Configuration:");
    println!("   Players: {}", num_players);
    println!("   Threshold: {} (need {} to decrypt)", threshold, threshold + 1);
    println!("   Output: {}/", output_dir);
    
    let confirm = read_input("\nProceed? (y/n): ");
    if confirm.to_lowercase() != "y" {
        println!("Cancelled.");
        return;
    }
    
    println!("\n⚙️  Generating keys...");
    
    // Load system parameters
    let g = SystemParams::g();
    let p = SystemParams::p();
    let q = SystemParams::q();
    
    // Generate secret key
    let mut rng = thread_rng();
    let secret_key = rng.gen_biguint_below(&q);
    
    // Compute public key
    let a_pub = mod_pow(&g, &secret_key, &p);
    
    let public_key = PublicKey {
        g: g.clone(),
        p: p.clone(),
        q: q.clone(),
        a_pub,
    };
    
    // Generate Shamir shares
    let (shares, _coefficients) = generate_shares(&secret_key, threshold, num_players, &q);
    
    // Create output directory
    if let Err(e) = fs::create_dir_all(&output_dir) {
        println!("❌ Error creating directory: {}", e);
        return;
    }
    
    // Save public key
    let public_key_json = serde_json::to_string_pretty(&public_key).unwrap();
    if let Err(e) = fs::write(format!("{}/public_key.json", output_dir), public_key_json) {
        println!("❌ Error saving public key: {}", e);
        return;
    }
    
    // Save each player's secret share
    for (player_id, share) in shares {
        let player_public_key = mod_pow(&g, &share, &p);
        
        let secret_share = SecretKeyShare {
            player_id,
            share,
            public_key: public_key.clone(),
            player_public_key,
        };
        
        let share_json = serde_json::to_string_pretty(&secret_share).unwrap();
        if let Err(e) = fs::write(
            format!("{}/player_{}_key.json", output_dir, player_id),
            share_json,
        ) {
            println!("❌ Error saving player {} key: {}", player_id, e);
            return;
        }
    }
    
    println!("\n✅ Key generation complete!");
    println!("   Public key: {}/public_key.json", output_dir);
    println!("   Player keys: {}/player_N_key.json (N=1 to {})", output_dir, num_players);
    println!("\n⚠️  Secret key has been wiped from memory (trusted setup)");
}

fn encrypt_interactive() {
    println!("\n═══════════════════════════════════════");
    println!("         ENCRYPT MESSAGE");
    println!("═══════════════════════════════════════");
    
    let public_key_path = read_input("\nEnter public key file path [keys/public_key.json]: ");
    let public_key_path = if public_key_path.is_empty() {
        "keys/public_key.json".to_string()
    } else {
        public_key_path
    };
    
    // Load public key
    let public_key_json = match fs::read_to_string(&public_key_path) {
        Ok(content) => content,
        Err(e) => {
            println!("❌ Error reading public key: {}", e);
            return;
        }
    };
    
    let public_key: PublicKey = match serde_json::from_str(&public_key_json) {
        Ok(key) => key,
        Err(e) => {
            println!("❌ Error parsing public key: {}", e);
            return;
        }
    };
    
    println!("\nChoose input method:");
    println!("  1. Type message");
    println!("  2. Read from file");
    
    let choice = read_input("\nEnter choice (1-2): ");
    
    let message = match choice.as_str() {
        "1" => {
            let msg = read_input("\nEnter message to encrypt: ");
            if msg.is_empty() {
                println!("❌ Error: Message cannot be empty");
                return;
            }
            msg.into_bytes()
        }
        "2" => {
            let file_path = read_input("Enter file path: ");
            match fs::read(&file_path) {
                Ok(content) => content,
                Err(e) => {
                    println!("❌ Error reading file: {}", e);
                    return;
                }
            }
        }
        _ => {
            println!("❌ Invalid choice");
            return;
        }
    };
    
    let output_path = read_input("\nEnter output file path [ciphertext.json]: ");
    let output_path = if output_path.is_empty() {
        "ciphertext.json".to_string()
    } else {
        output_path
    };
    
    println!("\n⚙️  Encrypting {} bytes...", message.len());
    
    let ciphertext = match encrypt(&public_key, &message) {
        Ok(ct) => ct,
        Err(e) => {
            println!("❌ Encryption error: {}", e);
            return;
        }
    };
    
    let ciphertext_json = serde_json::to_string_pretty(&ciphertext).unwrap();
    if let Err(e) = fs::write(&output_path, ciphertext_json) {
        println!("❌ Error saving ciphertext: {}", e);
        return;
    }
    
    println!("\n✅ Encryption complete!");
    println!("   Ciphertext saved to: {}", output_path);
}

fn decrypt_phase1_interactive() {
    println!("\n═══════════════════════════════════════");
    println!("    DECRYPT - PHASE 1 (Generate Share)");
    println!("═══════════════════════════════════════");
    
    let key_file = read_input("\nEnter player's key file path (e.g., keys/player_1_key.json): ");
    
    // Load player's secret key
    let key_json = match fs::read_to_string(&key_file) {
        Ok(content) => content,
        Err(e) => {
            println!("❌ Error reading key file: {}", e);
            return;
        }
    };
    
    let secret_share: SecretKeyShare = match serde_json::from_str(&key_json) {
        Ok(share) => share,
        Err(e) => {
            println!("❌ Error parsing key file: {}", e);
            return;
        }
    };
    
    println!("\n✓ Loaded key for Player {}", secret_share.player_id);
    
    let ciphertext_path = read_input("\nEnter ciphertext file path [ciphertext.json]: ");
    let ciphertext_path = if ciphertext_path.is_empty() {
        "ciphertext.json".to_string()
    } else {
        ciphertext_path
    };
    
    // Load ciphertext
    let ciphertext_json = match fs::read_to_string(&ciphertext_path) {
        Ok(content) => content,
        Err(e) => {
            println!("❌ Error reading ciphertext: {}", e);
            return;
        }
    };
    
    let ciphertext: Ciphertext = match serde_json::from_str(&ciphertext_json) {
        Ok(ct) => ct,
        Err(e) => {
            println!("❌ Error parsing ciphertext: {}", e);
            return;
        }
    };
    
    let players_input = read_input("\nEnter participating player IDs (comma-separated, e.g., 1,2,3): ");
    
    let player_ids: Vec<usize> = match players_input
        .split(',')
        .map(|s| s.trim().parse())
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(ids) => ids,
        Err(_) => {
            println!("❌ Error: Invalid player IDs format");
            println!("   Example: 1,2,3 or 1,3,5");
            return;
        }
    };
    
    if player_ids.is_empty() {
        println!("❌ Error: No player IDs provided");
        return;
    }
    
    // Sort for consistency
    let mut player_ids = player_ids;
    player_ids.sort();
    player_ids.dedup();
    
    println!("   Parsed as: {:?}", player_ids);
    
    if !player_ids.contains(&secret_share.player_id) {
        println!("❌ Error: Player {} is not in the participating players list", secret_share.player_id);
        return;
    }
    
    println!("\n📊 Participating players: {:?}", player_ids);
    
    let output_path = read_input(&format!("\nEnter output file path [share_player_{}.json]: ", secret_share.player_id));
    let output_path = if output_path.is_empty() {
        format!("share_player_{}.json", secret_share.player_id)
    } else {
        output_path
    };
    
    println!("\n⚙️  Computing Lagrange coefficients...");
    
    // Compute Lagrange coefficients
    let q_bigint = secret_share.public_key.q.to_bigint().unwrap();
    let coefficients = compute_lagrange_coefficients(&player_ids, &q_bigint);
    
    let player_index = player_ids.iter().position(|&id| id == secret_share.player_id).unwrap();
    let w_k = &coefficients[player_index];
    
    // Compute exponent
    let share_bigint = secret_share.share.to_bigint().unwrap();
    let exponent = (w_k * share_bigint) % &q_bigint;
    let exponent = if exponent < BigInt::from(0) {
        exponent + &q_bigint
    } else {
        exponent
    };
    let exponent_uint = exponent.to_biguint().unwrap();
    
    println!("⚙️  Computing decryption share...");
    
    // Compute B^{w_k * a_{p_k}} mod p
    let share_value = mod_pow(&ciphertext.b_component, &exponent_uint, &secret_share.public_key.p);
    
    let decryption_share = DecryptionShare {
        player_id: secret_share.player_id,
        share_value,
    };
    
    let share_json = serde_json::to_string_pretty(&decryption_share).unwrap();
    if let Err(e) = fs::write(&output_path, share_json) {
        println!("❌ Error saving decryption share: {}", e);
        return;
    }
    
    println!("\n✅ Decryption share generated!");
    println!("   Share saved to: {}", output_path);
    println!("\n📤 Share this file with other participating players for Phase 2.");
}

fn decrypt_phase2_interactive() {
    println!("\n═══════════════════════════════════════");
    println!("   DECRYPT - PHASE 2 (Combine Shares)");
    println!("═══════════════════════════════════════");
    
    let ciphertext_path = read_input("\nEnter ciphertext file path [ciphertext.json]: ");
    let ciphertext_path = if ciphertext_path.is_empty() {
        "ciphertext.json".to_string()
    } else {
        ciphertext_path
    };
    
    // Load ciphertext
    let ciphertext_json = match fs::read_to_string(&ciphertext_path) {
        Ok(content) => content,
        Err(e) => {
            println!("❌ Error reading ciphertext: {}", e);
            return;
        }
    };
    
    let ciphertext: Ciphertext = match serde_json::from_str(&ciphertext_json) {
        Ok(ct) => ct,
        Err(e) => {
            println!("❌ Error parsing ciphertext: {}", e);
            return;
        }
    };
    
    let public_key_path = read_input("\nEnter public key file path [keys/public_key.json]: ");
    let public_key_path = if public_key_path.is_empty() {
        "keys/public_key.json".to_string()
    } else {
        public_key_path
    };
    
    // Load public key
    let public_key_json = match fs::read_to_string(&public_key_path) {
        Ok(content) => content,
        Err(e) => {
            println!("❌ Error reading public key: {}", e);
            return;
        }
    };
    
    let public_key: PublicKey = match serde_json::from_str(&public_key_json) {
        Ok(key) => key,
        Err(e) => {
            println!("❌ Error parsing public key: {}", e);
            return;
        }
    };
    
    let shares_input = read_input("\nEnter decryption share files (comma-separated):\n  Example: share_player_1.json,share_player_2.json,share_player_3.json\n> ");
    
    let share_files: Vec<&str> = shares_input.split(',').map(|s| s.trim()).collect();
    
    println!("\n📥 Loading {} decryption shares...", share_files.len());
    
    let mut decryption_shares = Vec::new();
    for file in &share_files {
        let share_json = match fs::read_to_string(file) {
            Ok(content) => content,
            Err(e) => {
                println!("❌ Error reading {}: {}", file, e);
                return;
            }
        };
        
        let share: DecryptionShare = match serde_json::from_str(&share_json) {
            Ok(s) => s,
            Err(e) => {
                println!("❌ Error parsing {}: {}", file, e);
                return;
            }
        };
        
        println!("   ✓ Loaded share from player {}", share.player_id);
        decryption_shares.push(share);
    }
    
    if decryption_shares.is_empty() {
        println!("❌ Error: No decryption shares provided");
        return;
    }
    
    let output_path = read_input("\nEnter output file path [decrypted.txt]: ");
    let output_path = if output_path.is_empty() {
        "decrypted.txt".to_string()
    } else {
        output_path
    };
    
    println!("\n⚙️  Combining decryption shares...");
    
    // Combine shares: B^a = ∏ B^{w_k * a_{p_k}}
    let mut b_to_a = BigUint::one();
    for share in &decryption_shares {
        b_to_a = (&b_to_a * &share.share_value) % &public_key.p;
    }
    
    println!("⚙️  Computing AES key...");
    let aes_key = hash_to_key(&b_to_a);
    
    println!("⚙️  Decrypting message...");
    
    let plaintext = match aes_decrypt(&aes_key, &ciphertext.encrypted_message, &ciphertext.nonce) {
        Ok(pt) => pt,
        Err(e) => {
            println!("❌ Decryption error: {}", e);
            println!("\n⚠️  This could mean:");
            println!("   - Not enough shares provided");
            println!("   - Wrong shares or wrong player combination");
            println!("   - Players used different player lists in Phase 1");
            return;
        }
    };
    
    if let Err(e) = fs::write(&output_path, &plaintext) {
        println!("❌ Error saving decrypted message: {}", e);
        return;
    }
    
    println!("\n✅ Decryption complete!");
    println!("   Decrypted message saved to: {}", output_path);
    
    // Try to print message if it's valid UTF-8
    if let Ok(text) = String::from_utf8(plaintext.clone()) {
        println!("\n📨 Decrypted message:");
        println!("┌─────────────────────────────────────────┐");
        println!("│ {:<39} │", text);
        println!("└─────────────────────────────────────────┘");
    } else {
        println!("\n📦 Decrypted {} bytes (binary data)", plaintext.len());
    }
}

fn main() {
    main_menu();
}