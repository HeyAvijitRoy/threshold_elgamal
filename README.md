# Threshold ElGamal Cryptosystem with Zero-Knowledge Proofs

A Rust implementation of a threshold ElGamal encryption scheme with cryptographic zero-knowledge proofs for verifiable decryption. This system enables distributed decryption where multiple parties must collaborate to decrypt a message, with mathematical guarantees that each party computes their share correctly.

## Features

- **Threshold Cryptography**: Secret sharing using Shamir's Secret Sharing scheme with Lagrange interpolation
- **Hybrid Encryption**: ElGamal for key encapsulation + AES-256-GCM for efficient message encryption
- **Zero-Knowledge Proofs**: Schnorr-based proofs ensure honest decryption share computation without revealing secrets
- **Verifiable Decryption**: Each player's contribution is cryptographically verified before combining shares
- **Command-Line Tools**: Complete workflow from key generation to decryption
- **Security**: Protection against malicious players through ZKP verification

## Mathematical Foundation

### Threshold ElGamal

The system uses ElGamal encryption in a multiplicative group modulo a large prime `p`:
- **Public Parameters**: `(g, p, q, A)` where `g` is a generator, `q` is the group order, and `A = g^a`
- **Secret Key**: `a` is shared using Shamir's Secret Sharing into `n` shares with threshold `t`
- **Encryption**: Message encrypted with ephemeral key `b`, producing `(B, E)` where `B = g^b` and `E = AES(K, m)` with `K = H(A^b)`
- **Decryption**: Requires `t+1` players to compute shares `B^(w_k * a_k)` using Lagrange coefficients `w_k`

### Zero-Knowledge Proofs

Each decryption share includes a Schnorr-like proof demonstrating correct computation:

**Prover** (knows `x = w_k * a_k` such that `share_value = B^x`):
1. Choose random `r ← Z_q`
2. Compute commitment: `R = B^r mod p`
3. Compute challenge: `c = H(B || share_value || R)` (Fiat-Shamir heuristic)
4. Compute response: `z = r + c*x mod (p-1)`

**Verifier** checks: `B^z ≟ R * share_value^c (mod p)`

The proof is:
- **Sound**: A malicious prover cannot forge a valid proof without knowing `x`
- **Zero-Knowledge**: The proof reveals nothing about `x` beyond the validity of the claim
- **Non-Interactive**: Uses Fiat-Shamir heuristic for convenience

## Installation

### Prerequisites

- Rust 1.70 or higher
- Cargo (comes with Rust)

### Building

```bash
cargo build --release
```

The compiled binaries will be in `target/release/`:
- `keygen` - Generate keys and shares
- `encrypt` - Encrypt messages
- `decrypt_phase1` - Generate decryption shares with ZKP
- `decrypt_phase2` - Verify shares and decrypt
- `test_zkp` - Test zero-knowledge proof system
- `test` - Full system test

## Usage

### 1. Key Generation

Generate a public key and distribute secret shares to players:

```bash
./target/release/keygen \
  --threshold 1 \
  --players 5 \
  --output-dir keys/
```

This creates:
- `keys/public_key.json` - Public key (share with everyone)
- `keys/player_1.json` through `keys/player_5.json` - Secret shares (one per player)

### 2. Encryption

Encrypt a message using the public key:

```bash
./target/release/encrypt \
  --public-key keys/public_key.json \
  --message "Secret message" \
  --output ciphertext.json
```

### 3. Decryption Phase 1 (Each Player)

Each participating player generates their decryption share with a zero-knowledge proof:

```bash
# Player 1
./target/release/decrypt_phase1 \
  --key-file keys/player_1.json \
  --ciphertext ciphertext.json \
  --players 1,3,5 \
  --output share_1.json

# Player 3
./target/release/decrypt_phase1 \
  --key-file keys/player_3.json \
  --ciphertext ciphertext.json \
  --players 1,3,5 \
  --output share_3.json

# Player 5
./target/release/decrypt_phase1 \
  --key-file keys/player_5.json \
  --ciphertext ciphertext.json \
  --players 1,3,5 \
  --output share_5.json
```

### 4. Decryption Phase 2 (Combiner)

Collect all shares, verify ZKPs, and decrypt:

```bash
./target/release/decrypt_phase2 \
  --ciphertext ciphertext.json \
  --public-key keys/public_key.json \
  --shares share_1.json,share_3.json,share_5.json \
  --output decrypted.txt
```

The system will:
1. ✓ Verify each player's zero-knowledge proof
2. ✓ Combine verified shares using Lagrange interpolation
3. ✓ Recover the shared secret and decrypt the message

If any proof fails, decryption is aborted to prevent corruption from malicious players.

## Testing

### Full System Test

```bash
cargo run --bin test
```

Tests the complete workflow: key generation, encryption, threshold decryption with ZKP verification.

### Zero-Knowledge Proof Test

```bash
cargo run --bin test_zkp
```

Tests the ZKP system specifically:
- Valid proof generation and verification
- Rejection of invalid proofs
- Zero-knowledge property (multiple valid proofs for same statement)

## Project Structure

```
src/
├── lib.rs              # Core cryptographic primitives and ZKP implementation
├── params.rs           # System parameters (p, q, g)
├── shamir.rs           # Shamir's Secret Sharing
├── vandermonde.rs      # Lagrange interpolation for reconstruction
├── elgamal.rs          # ElGamal encryption
└── bin/
    ├── keygen.rs       # Key generation and distribution
    ├── encrypt.rs      # Message encryption
    ├── decrypt_phase1.rs  # Decryption share generation with ZKP
    ├── decrypt_phase2.rs  # Share verification and final decryption
    ├── test.rs         # Integration tests
    └── test_zkp.rs     # Zero-knowledge proof tests
```

## Security Considerations

### Implemented Protections

- **Zero-Knowledge Proofs**: Each decryption share is cryptographically verified, preventing malicious players from corrupting the decryption
- **Authenticated Encryption**: AES-256-GCM provides confidentiality and authenticity
- **Strong Parameters**: 4096-bit prime modulus, 512-bit group order
- **Non-Interactive Proofs**: Fiat-Shamir heuristic in the random oracle model

### Important Notes

- **Secure Channel Required**: Share distribution should use secure channels (not implemented here)
- **No Forward Secrecy**: ElGamal alone doesn't provide forward secrecy
- **Parameters**: The security relies on the discrete logarithm problem in the chosen group
- **Random Number Generation**: Uses system randomness; ensure your OS provides secure entropy

## Technical Details

### Dependencies

- `num-bigint`: Arbitrary precision arithmetic
- `sha2`: SHA-256 hashing for Fiat-Shamir and key derivation
- `aes-gcm`: Authenticated encryption
- `serde` / `serde_json`: Serialization
- `clap`: Command-line parsing
- `rand`: Secure random number generation

### Cryptographic Choices

- **Group**: Schnorr group (safe prime `p = 2q + 1`)
- **Hash**: SHA-256 for challenge generation and key derivation
- **Symmetric Cipher**: AES-256-GCM
- **Response Reduction**: mod (p-1) to handle arbitrary base elements

## Performance

- Key generation: ~1 second for 5 players
- Encryption: ~50ms
- Decryption share generation (with ZKP): ~100ms per player
- Share verification and decryption: ~150ms for 3 shares

## Future Enhancements

- [ ] Distributed key generation (DKG)
- [ ] Proactive secret sharing
- [ ] Support for more complex access structures
- [ ] Network protocol for share distribution
- [ ] Hardware security module (HSM) integration

## References

- Shamir, A. (1979). "How to share a secret"
- Pedersen, T. P. (1991). "A threshold cryptosystem without a trusted party"
- Schnorr, C. P. (1990). "Efficient signature generation by smart cards"
- Fiat, A., & Shamir, A. (1986). "How to prove yourself: Practical solutions to identification and signature problems"

## License

[Add your license here]

## Author

Avijit Roy

## Acknowledgments

Built as part of a cryptography project exploring threshold encryption and zero-knowledge proofs.
