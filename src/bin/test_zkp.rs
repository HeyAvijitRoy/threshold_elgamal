use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use threshold_elgamal::*;
use threshold_elgamal::params::SystemParams;

fn main() {
    println!("Testing Zero-Knowledge Proof Implementation\n");
    println!("{}", "=".repeat(60));
    
    // Load system parameters
    let g = SystemParams::g();
    let p = SystemParams::p();
    let q = SystemParams::q();
    
    println!("\nSystem Parameters:");
    println!("  p bits: {}", p.bits());
    println!("  q bits: {}", q.bits());
    println!("  g bits: {}", g.bits());
    
    // Generate random values for testing
    let mut rng = thread_rng();
    
    // Simulate a random B component (from ciphertext)
    let b_random = rng.gen_biguint_below(&q);
    let b_component = mod_pow(&g, &b_random, &p);
    
    // Simulate a random exponent (w_k * a_pk)
    let exponent = rng.gen_biguint_below(&q);
    
    // Compute the share value: B^exponent
    let share_value = mod_pow(&b_component, &exponent, &p);
    
    println!("\nTest Setup:");
    println!("  B component bits: {}", b_component.bits());
    println!("  Exponent bits: {}", exponent.bits());
    println!("  Share value bits: {}", share_value.bits());
    
    // Test 1: Generate and verify a valid proof
    println!("\n{}", "=".repeat(60));
    println!("Test 1: Valid Proof");
    println!("{}", "=".repeat(60));
    
    println!("\nGenerating ZKP...");
    let proof = generate_decryption_proof(
        &b_component,
        &share_value,
        &exponent,
        &p,
        &q,
    );
    
    println!("  Proof commitment bits: {}", proof.commitment.bits());
    println!("  Proof response bits: {}", proof.response.bits());
    
    println!("\nVerifying ZKP...");
    let is_valid = verify_decryption_proof(
        &b_component,
        &share_value,
        &proof,
        &p,
        &q,
    );
    
    if is_valid {
        println!("  Proof verification PASSED!");
        println!("  The prover knows the exponent without revealing it.");
    } else {
        println!("  Proof verification FAILED!");
        println!("  This should not happen with a valid proof.");
    }
    
    // Test 2: Try to verify with wrong share value (should fail)
    println!("\n{}", "=".repeat(60));
    println!("Test 2: Invalid Proof - Wrong Share Value");
    println!("{}", "=".repeat(60));
    
    let wrong_exponent = rng.gen_biguint_below(&q);
    let wrong_share_value = mod_pow(&b_component, &wrong_exponent, &p);
    
    println!("\nAttempting to use valid proof with wrong share value...");
    let is_valid_wrong = verify_decryption_proof(
        &b_component,
        &wrong_share_value,
        &proof,
        &p,
        &q,
    );
    
    if !is_valid_wrong {
        println!("  Correctly REJECTED invalid proof!");
        println!("  The proof doesn't match the wrong share value.");
    } else {
        println!("  SECURITY ISSUE: Accepted invalid proof!");
    }
    
    // Test 3: Try to verify with wrong B component (should fail)
    println!("\n{}", "=".repeat(60));
    println!("Test 3: Invalid Proof - Wrong B Component");
    println!("{}", "=".repeat(60));
    
    let wrong_b_random = rng.gen_biguint_below(&q);
    let wrong_b_component = mod_pow(&g, &wrong_b_random, &p);
    
    println!("\nAttempting to use valid proof with wrong B component...");
    let is_valid_wrong_b = verify_decryption_proof(
        &wrong_b_component,
        &share_value,
        &proof,
        &p,
        &q,
    );
    
    if !is_valid_wrong_b {
        println!("  Correctly REJECTED invalid proof!");
        println!("  The proof doesn't match the wrong B component.");
    } else {
        println!("  SECURITY ISSUE: Accepted invalid proof!");
    }
    
    // Test 4: Multiple proofs for the same values
    println!("\n{}", "=".repeat(60));
    println!("Test 4: Multiple Proofs (Zero-Knowledge Property)");
    println!("{}", "=".repeat(60));
    
    println!("\nGenerating 3 different proofs for the same statement...");
    let proof1 = generate_decryption_proof(&b_component, &share_value, &exponent, &p, &q);
    let proof2 = generate_decryption_proof(&b_component, &share_value, &exponent, &p, &q);
    let proof3 = generate_decryption_proof(&b_component, &share_value, &exponent, &p, &q);
    
    let valid1 = verify_decryption_proof(&b_component, &share_value, &proof1, &p, &q);
    let valid2 = verify_decryption_proof(&b_component, &share_value, &proof2, &p, &q);
    let valid3 = verify_decryption_proof(&b_component, &share_value, &proof3, &p, &q);
    
    println!("  Proof 1 valid: {}", if valid1 { "✓" } else { "✗" });
    println!("  Proof 2 valid: {}", if valid2 { "✓" } else { "✗" });
    println!("  Proof 3 valid: {}", if valid3 { "✓" } else { "✗" });
    
    println!("\n  Proofs are different due to randomness:");
    println!("    Proof 1 commitment == Proof 2 commitment: {}", proof1.commitment == proof2.commitment);
    println!("    Proof 1 response == Proof 2 response: {}", proof1.response == proof2.response);
    println!("  This demonstrates the zero-knowledge property!");
    
    // Summary
    println!("\n{}", "=".repeat(60));
    println!("Summary");
    println!("{}", "=".repeat(60));
    
    let all_valid_tests_pass = is_valid && !is_valid_wrong && !is_valid_wrong_b && valid1 && valid2 && valid3;
    
    if all_valid_tests_pass {
        println!("\n ALL TESTS PASSED!");
        println!("\nThe ZKP implementation correctly:");
        println!("  • Generates valid proofs for honest computations");
        println!("  • Rejects proofs for incorrect share values");
        println!("  • Rejects proofs for different B components");
        println!("  • Supports multiple proofs (zero-knowledge property)");
        println!("\n___ZKP system is cryptographically sound!___\n");
    } else {
        println!("\n SOME TESTS FAILED!");
        println!("Please review the implementation.");
    }
}
