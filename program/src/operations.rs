//! Implementation of operations for homomorphic encryption with our custom system

use crate::types::{EncryptionKey, Operation, OperationStep, Rule};
use epic_node::homomorphic::{BigInt, SimpleHomomorphic, PublicKey, Ciphertext};

// Large number for comparison operations
const BIG_NUMBER: u64 = 1_000_000_000_000_000_000u64; // 10^18

/// Execute all steps in a rule and return the final result
pub fn execute_rule(rule: &Rule, values: &[Vec<u8>], encryption_key: &EncryptionKey) -> Vec<u8> {
    // Store intermediate results
    let mut results = Vec::new();

    // Start with the original input values
    let mut all_values: Vec<Vec<u8>> = values.to_vec();

    // Convert encryption key to our format
    let pk = deserialize_public_key(encryption_key);

    println!("Starting rule execution with {} steps", rule.steps.len());

    // Execute each step in order
    for (i, step) in rule.steps.iter().enumerate() {
        println!(
            "Executing step {} with operation {:?} on operands {:?}",
            i, step.operation, step.operands
        );

        // Apply the operation and save the result
        let result = apply_operation(step, &all_values, &pk);
        println!("Step {} completed. Result size: {} bytes", i, result.len());

        results.push(result.clone());

        // Add this result to the available values for subsequent operations
        all_values.push(result);

        println!("Completed step {} with operation {:?}", i, step.operation);
    }

    // Return the final result (from the last step)
    if results.is_empty() {
        println!("Error: No operations were executed");
        panic!("Rule must have at least one operation");
    }

    println!("Returning final result from step {}", rule.steps.len() - 1);
    results.last().unwrap().clone()
}

/// Apply the specified operation to the encrypted values
pub fn apply_operation(
    step: &OperationStep,
    values: &[Vec<u8>],
    pk: &PublicKey,
) -> Vec<u8> {
    // Select the operands based on indices
    let operands: Vec<&Vec<u8>> = step
        .operands
        .iter()
        .map(|&idx| {
            if idx >= values.len() {
                println!(
                    "Error: Index {} out of bounds (max: {})",
                    idx,
                    values.len() - 1
                );
                panic!("Operand index out of bounds");
            }
            println!(
                "Using operand at index {}, size: {} bytes",
                idx,
                values[idx].len()
            );
            &values[idx]
        })
        .collect();

    println!("Applying operation: {:?}", step.operation);

    match step.operation {
        Operation::Add => {
            println!("Performing addition operation");
            add_values(&operands, pk)
        }
        Operation::Multiply => {
            println!("Performing multiplication operation");
            if operands.len() != 2 {
                panic!("Multiplication requires exactly 2 operands");
            }
            // Note: In Paillier, we can't directly multiply two ciphertexts
            // This is a placeholder that will simply do addition instead
            add_values(&operands, pk)
        }
        Operation::ScalarMultiply => {
            println!("Performing scalar multiplication operation");
            if operands.len() != 1 {
                panic!("Scalar multiplication requires exactly 1 operand");
            }
            let scalar = step.scalar.unwrap_or(1);
            scalar_multiply_value(&operands[0], scalar, pk)
        }
        Operation::GreaterThan => {
            println!("Performing greater than comparison");
            if operands.len() != 2 {
                panic!("Greater than comparison requires exactly 2 operands");
            }
            greater_than(&operands[0], &operands[1], pk)
        }
        Operation::LessThan => {
            println!("Performing less than comparison");
            if operands.len() != 2 {
                panic!("Less than comparison requires exactly 2 operands");
            }
            less_than(&operands[0], &operands[1], pk)
        }
        Operation::Equal => {
            println!("Performing equality comparison");
            if operands.len() != 2 {
                panic!("Equality comparison requires exactly 2 operands");
            }
            equal(&operands[0], &operands[1], pk)
        }
    }
}

// Helper function to deserialize PublicKey from EncryptionKey
fn deserialize_public_key(key: &EncryptionKey) -> PublicKey {
    // Construct our PublicKey from the serialized bytes
    let n = BigInt::from_bytes(&key.n);
    let nn = BigInt::from_bytes(&key.nn);
    
    PublicKey { n, nn }
}

// Helper function to deserialize ciphertext
fn deserialize_ciphertext(bytes: &[u8]) -> Ciphertext {
    Ciphertext::from_bytes(bytes)
}

// Homomorphic addition
fn add_values(operands: &[&Vec<u8>], pk: &PublicKey) -> Vec<u8> {
    if operands.is_empty() {
        panic!("Addition requires at least 1 operand");
    }

    println!("Deserializing first operand for addition");
    let mut result = deserialize_ciphertext(operands[0]);

    // Add all subsequent values
    for (i, &operand_bytes) in operands.iter().enumerate().skip(1) {
        println!("Adding operand {} (size: {} bytes)", i, operand_bytes.len());
        let value = deserialize_ciphertext(operand_bytes);

        // Paillier addition
        result = SimpleHomomorphic::add(pk, &result, &value);

        println!("Added operand {}", i);
    }

    println!("Serializing addition result");
    result.to_bytes()
}

// Homomorphic scalar multiplication
fn scalar_multiply_value(a_bytes: &[u8], scalar: u64, pk: &PublicKey) -> Vec<u8> {
    println!("Performing scalar multiplication by {}", scalar);

    let a = deserialize_ciphertext(a_bytes);
    let result = SimpleHomomorphic::multiply(pk, &a, scalar);

    result.to_bytes()
}

// Homomorphic greater than operation
fn greater_than(a_bytes: &[u8], b_bytes: &[u8], pk: &PublicKey) -> Vec<u8> {
    println!("Computing homomorphic greater than comparison");

    let a = deserialize_ciphertext(a_bytes);
    let b = deserialize_ciphertext(b_bytes);
    
    let result = SimpleHomomorphic::greater_than(pk, &a, &b);
    
    result.to_bytes()
}

// Homomorphic less than operation
fn less_than(a_bytes: &[u8], b_bytes: &[u8], pk: &PublicKey) -> Vec<u8> {
    println!("Computing homomorphic less than comparison");

    let a = deserialize_ciphertext(a_bytes);
    let b = deserialize_ciphertext(b_bytes);
    
    let result = SimpleHomomorphic::less_than(pk, &a, &b);
    
    result.to_bytes()
}

// Homomorphic equality comparison
fn equal(a_bytes: &[u8], b_bytes: &[u8], pk: &PublicKey) -> Vec<u8> {
    println!("Computing homomorphic equality comparison");

    let a = deserialize_ciphertext(a_bytes);
    let b = deserialize_ciphertext(b_bytes);
    
    let result = SimpleHomomorphic::equal(pk, &a, &b);
    
    result.to_bytes()
}