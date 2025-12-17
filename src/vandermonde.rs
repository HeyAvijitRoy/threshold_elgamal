use num_bigint::BigInt;
use num_traits::{Zero, One};
use crate::mod_inverse;

// Compute Lagrange coefficients for threshold decryption
// Given player IDs, compute coefficients for interpolation at x=0
pub fn compute_lagrange_coefficients(
    player_ids: &[usize],
    modulus: &BigInt,
) -> Vec<BigInt> {
    let t = player_ids.len();
    let mut coefficients = Vec::new();
    
    // For each player j in the subset
    for j in 0..t {
        let x_j = BigInt::from(player_ids[j]);
        
        // Compute Lagrange basis polynomial L_j(0)
        // L_j(0) = ∏(k≠j) (0 - x_k) / (x_j - x_k)
        //        = ∏(k≠j) (-x_k) / (x_j - x_k)
        let mut numerator = BigInt::one();
        let mut denominator = BigInt::one();
        
        for k in 0..t {
            if k != j {
                let x_k = BigInt::from(player_ids[k]);
                // numerator *= -x_k
                numerator = (numerator * (-&x_k)) % modulus;
                // denominator *= (x_j - x_k)
                denominator = (denominator * (&x_j - &x_k)) % modulus;
            }
        }
        
        // Ensure positive modulus
        while numerator < BigInt::zero() {
            numerator += modulus;
        }
        while denominator < BigInt::zero() {
            denominator += modulus;
        }
        
        // Compute coefficient as numerator / denominator mod modulus
        let denom_inv = mod_inverse(&denominator, modulus)
            .expect("Denominator should be invertible");
        
        let mut coeff = (numerator * denom_inv) % modulus;
        
        // Ensure positive result
        while coeff < BigInt::zero() {
            coeff += modulus;
        }
        
        coefficients.push(coeff);
    }
    
    coefficients
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;
    
    #[test]
    fn test_lagrange_coefficients() {
        // Simple test with small modulus
        let modulus = BigInt::from(23);
        let players = vec![1, 2, 3];
        
        let coeffs = compute_lagrange_coefficients(&players, &modulus);
        
        // Coefficients should sum to 1 mod modulus when evaluating at 0
        assert_eq!(coeffs.len(), 3);
        
        // Verify that the interpolation property holds
        // L_1(0) + L_2(0) + L_3(0) = 1 (for constant polynomial)
        let sum: BigInt = coeffs.iter().sum();
        assert_eq!(sum % &modulus, BigInt::one());
    }
    
    #[test]
    fn test_lagrange_non_sequential() {
        // Test with non-sequential player IDs
        let modulus = BigInt::from(23);
        let players = vec![1, 3, 5];
        
        let coeffs = compute_lagrange_coefficients(&players, &modulus);
        
        // Should still sum to 1
        let sum: BigInt = coeffs.iter().sum();
        assert_eq!(sum % &modulus, BigInt::one());
    }
}