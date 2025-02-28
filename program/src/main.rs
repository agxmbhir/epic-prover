//! A simple rule-based prover that applies operations on encrypted values.
#![no_main]
sp1_zkvm::entrypoint!(main);

pub mod operations;
pub mod types;

use operations::execute_rule;
use types::{Attestation, Rule, EncryptionKey};
use epic_node::homomorphic::SimpleHomomorphic;

pub fn main() {
    // Read inputs to the program
    println!("Reading rule...");
    let rule = sp1_zkvm::io::read::<Rule>();
    println!("Rule ID: {}", rule.rule_id);
    println!("Number of operation steps: {}", rule.steps.len());

    println!("Reading attestations...");
    let attestations = sp1_zkvm::io::read::<Vec<Attestation>>();
    println!("Number of attestations: {}", attestations.len());

    // Read the encryption key for homomorphic operations
    println!("Reading encryption key...");
    let encryption_key = sp1_zkvm::io::read::<EncryptionKey>();
    println!("Encryption key received: modulus size {} bytes", encryption_key.n.len());

    // Commit the rule ID to make it publicly verifiable
    println!("Committing rule ID: {}", rule.rule_id);
    sp1_zkvm::io::commit(&rule.rule_id);

    // Get the values from attestations
    println!("Processing attestation values...");
    let values: Vec<Vec<u8>> = attestations
        .iter()
        .map(|att| {
            println!("Using attestation from: {}", att.attestor_id);
            att.encrypted_value.clone()
        })
        .collect();

    // Execute all steps in the rule
    println!("Executing rule steps...");
    let result = execute_rule(&rule, &values, &encryption_key);
    println!(
        "Rule execution completed. Result size: {} bytes",
        result.len()
    );

    // Commit the final result as output
    println!("Committing result...");
    sp1_zkvm::io::commit(&result);
    println!("Execution completed successfully");
}