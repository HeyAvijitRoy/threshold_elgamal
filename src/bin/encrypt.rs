use clap::Parser;
use std::fs;
use std::io::{self, Write};
use threshold_elgamal::*;
use threshold_elgamal::elgamal::encrypt;

#[derive(Parser, Debug)]
#[command(name = "encrypt")]
#[command(about = "Encrypt a message using ElGamal", long_about = None)]
struct Args {
    /// Public key file
    #[arg(short, long)]
    public_key: String,
    
    /// Message to encrypt (or use --input-file, or leave empty for interactive input)
    #[arg(short, long, conflicts_with = "input_file")]
    message: Option<String>,
    
    /// Input file to encrypt
    #[arg(short, long)]
    input_file: Option<String>,
    
    /// Output file for ciphertext
    #[arg(short, long, default_value = "ciphertext.json")]
    output: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Load public key
    println!("Loading public key from {}...", args.public_key);
    let public_key_json = fs::read_to_string(&args.public_key)?;
    let public_key: PublicKey = serde_json::from_str(&public_key_json)?;
    
    // Get message to encrypt
    let message = if let Some(msg) = args.message {
        msg.into_bytes()
    } else if let Some(file) = args.input_file {
        println!("Reading message from {}...", file);
        fs::read(&file)?
    } else {
        // Interactive input
        print!("Enter message to encrypt: ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        // Remove trailing newline
        input.trim_end().to_string().into_bytes()
    };
    
    if message.is_empty() {
        return Err("Message cannot be empty".into());
    }
    
    println!("Encrypting {} bytes...", message.len());
    
    // Encrypt the message
    let ciphertext = encrypt(&public_key, &message)?;
    
    // Save ciphertext
    let ciphertext_json = serde_json::to_string_pretty(&ciphertext)?;
    fs::write(&args.output, ciphertext_json)?;
    
    println!("✓ Encryption complete!");
    println!("  Ciphertext saved to: {}", args.output);
    
    Ok(())
}