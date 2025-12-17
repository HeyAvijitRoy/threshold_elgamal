use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

// Generate Shamir secret shares
// Returns (shares, polynomial_coefficients)
pub fn generate_shares(
    secret: &BigUint,
    threshold: usize,
    num_players: usize,
    modulus: &BigUint,
) -> (Vec<(usize, BigUint)>, Vec<BigUint>) {
    let mut rng = thread_rng();
    
    // Generate random polynomial coefficients r_1, ..., r_t
    let mut coefficients = vec![secret.clone()]; // a_0 = secret
    for _ in 0..threshold {
        coefficients.push(rng.gen_biguint_below(modulus));
    }
    
    // Evaluate polynomial at points 1, 2, ..., n
    let mut shares = Vec::new();
    for i in 1..=num_players {
        let share = evaluate_polynomial(&coefficients, i, modulus);
        shares.push((i, share));
    }
    
    (shares, coefficients)
}

// Evaluate polynomial f(x) = a_0 + a_1*x + a_2*x^2 + ... at point x
fn evaluate_polynomial(coefficients: &[BigUint], x: usize, modulus: &BigUint) -> BigUint {
    let x_big = BigUint::from(x);
    let mut result = BigUint::from(0u32);
    let mut x_power = BigUint::from(1u32);
    
    for coeff in coefficients {
        result = (result + (coeff * &x_power) % modulus) % modulus;
        x_power = (&x_power * &x_big) % modulus;
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_polynomial_evaluation() {
        let modulus = BigUint::from(23u32);
        let coefficients = vec![BigUint::from(5u32), BigUint::from(3u32), BigUint::from(2u32)];
        
        // f(1) = 5 + 3*1 + 2*1^2 = 10
        let result = evaluate_polynomial(&coefficients, 1, &modulus);
        assert_eq!(result, BigUint::from(10u32));
        
        // f(2) = 5 + 3*2 + 2*4 = 19
        let result = evaluate_polynomial(&coefficients, 2, &modulus);
        assert_eq!(result, BigUint::from(19u32));
    }
}