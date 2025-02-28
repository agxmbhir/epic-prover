//! Type definitions for the rule-based prover
use serde::{Deserialize, Serialize};

/// Supported operations for homomorphic encryption
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Operation {
    // Integer operations
    Add,
    Multiply,
    ScalarMultiply, // Multiply by a constant value
    GreaterThan,
    LessThan,
    Equal,
}

/// A definition for a single operation with its operands
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationStep {
    pub operation: Operation,
    pub operands: Vec<usize>, // Indices of attestations or previous results to use
    pub scalar: Option<u64>,  // Optional scalar value for ScalarMultiply operation
}

/// A rule that defines a sequence of operations to perform
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub rule_id: String,
    pub steps: Vec<OperationStep>, // Multiple operations can be defined
}

/// An attestation with an encrypted value
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    pub attestor_id: String,
    pub encrypted_value: Vec<u8>, // Paillier encrypted value
}

/// Encryption key for homomorphic operations (public key)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptionKey {
    pub n: Vec<u8>,  // The modulus as serialized bytes
    pub nn: Vec<u8>, // n squared as serialized bytes
}
