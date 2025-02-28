use anyhow::Result;
use epic_node::attestor::KeyGeneration;
use epic_node::homomorphic::{SimpleHomomorphic, PublicKey, PrivateKey, Ciphertext, sp1_helpers};
use fibonacci_lib::{Attestation as FibAttestation, Rule, OperationStep, Operation, EncryptionKey};
use std::path::Path;
use std::fs;

fn main() -> Result<()> {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 3 {
        println!("Usage: {} <output_dir>", args[0]);
        return Ok(());
    }
    
    let output_dir = &args[1];
    prepare_fibonacci_inputs(output_dir)?;
    
    Ok(())
}

fn prepare_fibonacci_inputs(output_dir: &str) -> Result<()> {
    println!("Preparing Fibonacci demonstration inputs...");
    
    // Create output directory if it doesn't exist
    fs::create_dir_all(output_dir)?;
    
    // Generate a deterministic key pair
    let seed = b"fibonacci-deterministic-seed";
    let (public_key, _private_key) = KeyGeneration::generate_key_pair(1024, seed);
    
    // Create SP1-compatible encryption key
    let encryption_key = EncryptionKey {
        n: public_key.n.to_bytes(),
        nn: public_key.nn.to_bytes(),
    };
    
    // Serialize and save the encryption key
    let ek_path = Path::new(output_dir).join("encryption_key.bin");
    fs::write(&ek_path, bincode::serialize(&encryption_key)?)?;
    println!("Encryption key saved to: {}", ek_path.display());
    
    // Create attestations for Fibonacci inputs: 0 and 1
    let attestations = create_fibonacci_attestations(&public_key)?;
    
    // Serialize and save the attestations
    let att_path = Path::new(output_dir).join("attestations.bin");
    fs::write(&att_path, bincode::serialize(&attestations)?)?;
    println!("Attestations saved to: {}", att_path.display());
    
    // Create rule for Fibonacci computation
    let rule = create_fibonacci_rule()?;
    
    // Serialize and save the rule
    let rule_path = Path::new(output_dir).join("rule.bin");
    fs::write(&rule_path, bincode::serialize(&rule)?)?;
    println!("Rule saved to: {}", rule_path.display());
    
    println!("All inputs prepared successfully!");
    
    Ok(())
}

fn create_fibonacci_attestations(public_key: &PublicKey) -> Result<Vec<FibAttestation>> {
    // Create encrypted values for 0 and 1 (initial Fibonacci values)
    let fib0 = sp1_helpers::encrypt_for_sp1(public_key, 0, 0);
    let fib1 = sp1_helpers::encrypt_for_sp1(public_key, 1, 1);
    
    // Convert to serialized form
    let fib0_bytes = fib0.to_bytes();
    let fib1_bytes = fib1.to_bytes();
    
    // Create attestations
    let attestations = vec![
        FibAttestation {
            attestor_id: "attestor_0".to_string(),
            encrypted_value: fib0_bytes,
        },
        FibAttestation {
            attestor_id: "attestor_1".to_string(),
            encrypted_value: fib1_bytes,
        },
    ];
    
    Ok(attestations)
}

fn create_fibonacci_rule() -> Result<Rule> {
    // Create a rule to compute 10 steps of Fibonacci
    let mut steps = Vec::new();
    
    // Fibonacci sequence: Each number is the sum of the two preceding ones
    // Start with F(0) = 0, F(1) = 1
    // We'll compute F(2) through F(9)
    
    // For each step, add the two previous numbers
    // In the first step, we add F(0) and F(1) to get F(2)
    // In subsequent steps, we add the most recent two values
    for i in 0..8 {
        // For the first step, operands are the initial attestations (indices 0 and 1)
        // For subsequent steps, one operand is from the previous step's result
        let left_idx = if i == 0 { 0 } else { i + 1 };
        let right_idx = if i == 0 { 1 } else { i + 2 };
        
        steps.push(OperationStep {
            operation: Operation::Add,
            operands: vec![left_idx, right_idx],
            scalar: None,
        });
    }
    
    // Create the rule
    let rule = Rule {
        rule_id: "fibonacci_sequence".to_string(),
        steps,
    };
    
    Ok(rule)
}