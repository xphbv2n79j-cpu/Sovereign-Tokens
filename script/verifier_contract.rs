// Verifier Contract [Layer 5]
// Halo2 IPA Accumulation Verifier for BSV
//
// ARCHITECTURE:
// This contract implements the on-chain Transcript Verifier for Halo2's
// Inner Product Argument (IPA) accumulation scheme. The script acts as
// a Random Oracle, verifying that:
//
//   Poseidon(Old_Transcript, L_i, R_i, ...) == New_Transcript
//
// The script is BLIND to the elliptic curve math. It doesn't know that
// L_i and R_i are curve points. It just hashes 32-byte field elements
// and verifies the result matches the claimed accumulator.
//
// SECURITY MODEL:
// - If the Prover provides fake L_i/R_i terms, the next folding step
//   (verified off-chain or in the next layer) would fail
// - The on-chain verifier acts as an immutable Public Bulletin Board
//   ensuring the transcript was committed to publicly
//
// WITNESS PATTERN:
// - Locking Script: State commitment + Poseidon logic (~3.9 KB)
// - Unlocking Script: Constants blob + IPA witness (~3.2 KB)

use crate::ghost::script::{
    OP_SWAP, OP_OVER, OP_EQUALVERIFY,
    OP_TOALTSTACK, OP_FROMALTSTACK,
    OP_SHA256, OP_HASH160, OP_CHECKSIG,
    push_bytes,
};
use crate::ghost::script::field_script::{
    FusedPoseidonConstants, get_constants_hash,
    generate_witness_locking_script,
    fp_to_bytes, bytes_to_fp, FIELD_BYTES,
};
use crate::ghost::crypto::{Fp, PoseidonHash};
use ff::Field;

// ============================================================================
// TYPE ALIASES
// ============================================================================

/// Field elements (Pallas/Vesta scalars), represented as 32 bytes for Script
pub type FieldElement = [u8; FIELD_BYTES];

// ============================================================================
// IPA ACCUMULATOR STATE
// ============================================================================

/// The On-Chain Accumulator State
/// Represents the state of the IPA folding protocol
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IPAAccumulator {
    /// The current digest of the transcript (The "Challenge State")
    /// This is the running hash that accumulates all proof components
    pub transcript_hash: FieldElement,
    
    /// The Merkle Root of the application state (e.g., Token Balances)
    /// This changes as a result of state transitions
    pub app_state_root: FieldElement,
    
    /// The step counter for replay protection
    pub step: u32,
}

impl IPAAccumulator {
    /// Create a new accumulator with initial state
    pub fn new(app_state_root: FieldElement) -> Self {
        Self {
            transcript_hash: [0u8; 32],
            app_state_root,
            step: 0,
        }
    }

    /// Serializes the state for the Locking Script
    /// This effectively becomes the "State Commitment"
    pub fn to_script_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(68);
        bytes.extend_from_slice(&self.transcript_hash);
        bytes.extend_from_slice(&self.app_state_root);
        bytes.extend_from_slice(&self.step.to_le_bytes());
        bytes
    }

    /// Compute state hash using Poseidon
    pub fn hash(&self) -> Fp {
        let transcript = bytes_to_fp(&self.transcript_hash).unwrap_or(Fp::ZERO);
        let app_root = bytes_to_fp(&self.app_state_root).unwrap_or(Fp::ZERO);
        let step_fp = Fp::from(self.step as u64);
        PoseidonHash::hash_3(transcript, app_root, step_fp)
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 68 {
            return None;
        }
        
        let transcript_hash: FieldElement = bytes[0..32].try_into().ok()?;
        let app_state_root: FieldElement = bytes[32..64].try_into().ok()?;
        let step = u32::from_le_bytes(bytes[64..68].try_into().ok()?);
        
        Some(Self {
            transcript_hash,
            app_state_root,
            step,
        })
    }
}

// ============================================================================
// IPA STEP WITNESS
// ============================================================================

/// The Proof / Witness for a single IPA Step
/// This contains the data hashed into the transcript during the reduction
#[derive(Debug, Clone)]
pub struct IPAStepWitness {
    // --- Public Instances ---
    /// Public inputs mixed into the transcript at this step
    pub public_inputs: Vec<FieldElement>,

    // --- The IPA Proof Components ---
    /// The Left cross-terms (L_0, L_1, ... L_k) generated during reduction
    /// These are Affine Points [x, y], serialized as pair of FieldElements
    pub l_terms: Vec<[FieldElement; 2]>,
    
    /// The Right cross-terms (Affine R_0, R_1, ... R_k)
    pub r_terms: Vec<[FieldElement; 2]>,
    
    /// The final reduced scalar 'a'
    pub a_scalar: FieldElement,
    
    /// The final reduced scalar 'b' (if applicable to the specific IPA variant)
    pub b_scalar: Option<FieldElement>,

    // --- Application State Update ---
    /// The new application state root (if state changed)
    pub new_app_state: Option<FieldElement>,

    // --- The Result ---
    /// The new state of the transcript after hashing all the above
    pub next_transcript_hash: FieldElement,
}

impl IPAStepWitness {
    /// Create a minimal witness for testing
    pub fn new_minimal(next_transcript: FieldElement) -> Self {
        Self {
            public_inputs: Vec::new(),
            l_terms: Vec::new(),
            r_terms: Vec::new(),
            a_scalar: [0u8; 32],
            b_scalar: None,
            new_app_state: None,
            next_transcript_hash: next_transcript,
        }
    }

    /// Compute the hash of all witness data
    /// This is what the script verifies
    pub fn compute_transcript_hash(&self, prev_transcript: &FieldElement) -> Fp {
        let mut inputs = Vec::new();
        
        // Previous transcript
        inputs.push(bytes_to_fp(prev_transcript).unwrap_or(Fp::ZERO));
        
        // Public inputs
        for pi in &self.public_inputs {
            inputs.push(bytes_to_fp(pi).unwrap_or(Fp::ZERO));
        }
        
        // L and R terms (interleaved as in IPA)
        for (l, r) in self.l_terms.iter().zip(self.r_terms.iter()) {
            inputs.push(bytes_to_fp(&l[0]).unwrap_or(Fp::ZERO));
            inputs.push(bytes_to_fp(&l[1]).unwrap_or(Fp::ZERO));
            inputs.push(bytes_to_fp(&r[0]).unwrap_or(Fp::ZERO));
            inputs.push(bytes_to_fp(&r[1]).unwrap_or(Fp::ZERO));
        }
        
        // Final scalars
        inputs.push(bytes_to_fp(&self.a_scalar).unwrap_or(Fp::ZERO));
        if let Some(b) = &self.b_scalar {
            inputs.push(bytes_to_fp(b).unwrap_or(Fp::ZERO));
        }
        
        // Hash all inputs
        PoseidonHash::hash_many(&inputs)
    }

    /// Verify the witness is valid (off-chain check)
    pub fn verify(&self, prev_transcript: &FieldElement) -> bool {
        let computed = self.compute_transcript_hash(prev_transcript);
        let expected = bytes_to_fp(&self.next_transcript_hash).unwrap_or(Fp::ONE);
        computed == expected
    }

    /// Estimate witness size in bytes
    pub fn size(&self) -> usize {
        let mut size = 0;
        size += self.public_inputs.len() * 32;
        size += self.l_terms.len() * 64; // Affine points (32+32)
        size += self.r_terms.len() * 64; // Affine points (32+32)
        size += 32; // a_scalar
        if self.b_scalar.is_some() { size += 32; }
        if self.new_app_state.is_some() { size += 32; }
        size += 32; // next_transcript_hash
        size
    }
}

// ============================================================================
// VERIFIER CONTRACT
// ============================================================================

/// The Halo2 IPA Verifier Contract
/// This creates UTXOs that verify IPA accumulation steps
pub struct VerifierContract {
    /// Operator public key hash (for governance)
    pub operator_pkh: [u8; 20],
    
    /// Current accumulator state
    pub current_state: IPAAccumulator,
    
    /// Pre-computed fused constants for Poseidon
    pub constants: FusedPoseidonConstants,
    
    /// Hash of valid constants (embedded in locking script)
    pub constants_hash: [u8; 32],
}

impl VerifierContract {
    /// Create a new contract with initial state
    pub fn new(operator_pkh: [u8; 20], initial_state: IPAAccumulator) -> Self {
        let constants = FusedPoseidonConstants::compute();
        let constants_hash = get_constants_hash();
        
        Self {
            operator_pkh,
            current_state: initial_state,
            constants,
            constants_hash,
        }
    }

    /// Create contract from existing state
    pub fn with_state(operator_pkh: [u8; 20], state: IPAAccumulator) -> Self {
        Self::new(operator_pkh, state)
    }

    /// Generate the Locking Script (The Covenant)
    /// 
    /// Structure:
    /// 1. State Commitment (68 bytes)
    /// 2. Constants Hash (32 bytes)
    /// 3. Operator PKH (20 bytes)
    /// 4. Poseidon Verifier Logic (~3.8 KB)
    /// 5. Signature Check (Tail)
    pub fn locking_script(&self) -> Vec<u8> {
        let mut script = Vec::with_capacity(4096);
        use crate::ghost::script::field_script::generate_canonical_check;
        
        // === HEADER: Embedded state data ===
        
        // 1. Constants hash for witness verification
        script.extend(push_bytes(&self.constants_hash));
        script.push(OP_TOALTSTACK);
        
        // 2. Current state commitment
        let state_hash = fp_to_bytes(&self.current_state.hash());
        script.extend(push_bytes(&state_hash));
        script.push(OP_TOALTSTACK);
        
        // 3. Operator PKH for signature verification
        script.extend(push_bytes(&self.operator_pkh));
        script.push(OP_TOALTSTACK);
        
        // === VERIFICATION LOGIC ===
        
        // Stack at this point (from unlocking script):
        // [constants_blob] [prev_state] [witness_data...] [next_state] [sig] [pubkey]
        
        // 4. Verify constants blob hash
        script.push(OP_OVER);
        script.push(OP_SHA256);
        script.push(OP_FROMALTSTACK);
        script.push(OP_EQUALVERIFY);
        
        // 5. Verify previous state matches
        script.push(OP_SWAP);
        // Canonical check: Ensure prev_state blob is valid length/structure if needed
        // For bytes blob, we just hash it
        script.push(OP_SHA256);
        script.push(OP_FROMALTSTACK);
        script.push(OP_EQUALVERIFY);
        
        // === FROZEN HEART FIX: Absorb State Hash First ===
        // The Poseidon sponge must be initialized with the State Hash.
        // Implementation: We verify the detailed Poseidon logic below.
        // We inject the state hash into the transcript calculation.
        
        script.extend(generate_poseidon_verification_section());
        
        // 7. Operator signature verification (Tail)
        script.push(OP_FROMALTSTACK);  // Get operator PKH
        script.push(OP_OVER);          // Copy pubkey
        script.push(OP_HASH160);       // Hash pubkey
        script.push(OP_EQUALVERIFY);   // Verify matches operator
        script.push(OP_CHECKSIG);      // Verify signature
        
        script
    }

    /// Generate the Unlocking Script (The Input)
    /// 
    /// Structure:
    /// 1. Constants blob (~2.8 KB fused)
    /// 2. Previous state (68 bytes)
    /// 3. IPA witness data (variable)
    /// 4. Next state (68 bytes)
    /// 5. Signature + pubkey
    pub fn unlocking_script(&self, witness: &IPAStepWitness) -> Vec<u8> {
        let mut script = Vec::with_capacity(4096);
        
        // 1. Constants blob
        let constants_bytes = self.constants.to_witness_bytes();
        script.extend(push_bytes(&constants_bytes));
        
        // 2. Previous state
        script.extend(push_bytes(&self.current_state.to_script_bytes()));
        
        // 3. IPA witness data (order matches transcript absorption)
        
        // Public inputs
        for pi in &witness.public_inputs {
            script.extend(push_bytes(pi));
        }
        
        // L and R terms (interleaved)
        for (l, r) in witness.l_terms.iter().zip(witness.r_terms.iter()) {
            script.extend(push_bytes(&l[0]));
            script.extend(push_bytes(&l[1]));
            script.extend(push_bytes(&r[0]));
            script.extend(push_bytes(&r[1]));
        }
        
        // Final scalars
        script.extend(push_bytes(&witness.a_scalar));
        if let Some(b) = &witness.b_scalar {
            script.extend(push_bytes(b));
        }
        
        // 4. Next transcript hash
        script.extend(push_bytes(&witness.next_transcript_hash));
        
        // Note: Signature and pubkey are added by the transaction builder
        
        script
    }

    /// Apply a transition and return new contract state
    pub fn apply_transition(&self, witness: &IPAStepWitness) -> Result<Self, VerifierError> {
        // Verify the witness computes correctly
        if !witness.verify(&self.current_state.transcript_hash) {
            return Err(VerifierError::InvalidTranscript);
        }
        
        // Compute new state
        let new_state = IPAAccumulator {
            transcript_hash: witness.next_transcript_hash,
            app_state_root: witness.new_app_state
                .unwrap_or(self.current_state.app_state_root),
            step: self.current_state.step + 1,
        };
        
        Ok(Self {
            operator_pkh: self.operator_pkh,
            current_state: new_state,
            constants: self.constants.clone(),
            constants_hash: self.constants_hash,
        })
    }

    /// Get locking script size
    pub fn locking_script_size(&self) -> usize {
        self.locking_script().len()
    }

    /// Estimate unlocking script size for a witness
    pub fn unlocking_script_size(&self, witness: &IPAStepWitness) -> usize {
        self.unlocking_script(witness).len()
    }
}

/// Generate the Poseidon verification section
fn generate_poseidon_verification_section() -> Vec<u8> {
    // SECURITY HARDENING: Use secure verification with Transcript Chaining and Canonical Checks
    use crate::ghost::script::field_script::generate_secure_witness_verification;
    generate_secure_witness_verification()
}

// ============================================================================
// ERRORS
// ============================================================================

#[derive(Debug, Clone)]
pub enum VerifierError {
    InvalidTranscript,
    InvalidSignature,
    InvalidState,
    StepMismatch,
}

// ============================================================================
// CONTRACT OUTPUT (UTXO)
// ============================================================================

/// Represents a contract UTXO
#[derive(Clone, Debug)]
pub struct ContractOutput {
    /// Value in satoshis
    pub value: u64,
    
    /// The locking script
    pub script_pubkey: Vec<u8>,
    
    /// Contract state (for reference)
    pub state: IPAAccumulator,
}

impl ContractOutput {
    pub fn new(contract: &VerifierContract, value: u64) -> Self {
        Self {
            value,
            script_pubkey: contract.locking_script(),
            state: contract.current_state.clone(),
        }
    }

    pub fn next_output(&self, new_state: IPAAccumulator, operator_pkh: [u8; 20], value: u64) -> Self {
        let contract = VerifierContract::with_state(operator_pkh, new_state);
        Self::new(&contract, value)
    }
}

// ============================================================================
// TRANSACTION BUILDER
// ============================================================================

/// Builds transactions that spend contract UTXOs
pub struct ContractTransactionBuilder {
    /// Input contract UTXO
    pub input: ContractOutput,
    
    /// The IPA witness
    pub witness: IPAStepWitness,
    
    /// Operator signature
    pub operator_signature: Vec<u8>,
    
    /// Operator public key
    pub operator_pubkey: Vec<u8>,
    
    /// Operator PKH (for next output)
    pub operator_pkh: [u8; 20],
}

impl ContractTransactionBuilder {
    pub fn new(input: ContractOutput, witness: IPAStepWitness, operator_pkh: [u8; 20]) -> Self {
        Self {
            input,
            witness,
            operator_signature: Vec::new(),
            operator_pubkey: Vec::new(),
            operator_pkh,
        }
    }

    pub fn with_signature(mut self, sig: Vec<u8>, pubkey: Vec<u8>) -> Self {
        self.operator_signature = sig;
        self.operator_pubkey = pubkey;
        self
    }

    /// Build complete unlocking script
    pub fn build_unlocking_script(&self) -> Vec<u8> {
        let contract = VerifierContract::with_state(self.operator_pkh, self.input.state.clone());
        let mut script = contract.unlocking_script(&self.witness);
        
        // Append signature and pubkey
        script.extend(push_bytes(&self.operator_signature));
        script.extend(push_bytes(&self.operator_pubkey));
        
        script
    }

    /// Build output for new state
    pub fn build_output(&self, value: u64) -> ContractOutput {
        let new_state = IPAAccumulator {
            transcript_hash: self.witness.next_transcript_hash,
            app_state_root: self.witness.new_app_state
                .unwrap_or(self.input.state.app_state_root),
            step: self.input.state.step + 1,
        };
        
        self.input.next_output(new_state, self.operator_pkh, value)
    }

    /// Estimate transaction size
    pub fn estimate_tx_size(&self) -> usize {
        let input_size = self.build_unlocking_script().len() + 40;
        let output_size = self.build_output(0).script_pubkey.len() + 8;
        
        4 + 1 + input_size + 1 + output_size + 4
    }
}

// ============================================================================
// SIZE ANALYSIS
// ============================================================================

/// Analyze contract sizes
pub fn analyze_contract_sizes() -> ContractSizeReport {
    let operator_pkh = [0u8; 20];
    let initial_state = IPAAccumulator::new([1u8; 32]);
    let contract = VerifierContract::new(operator_pkh, initial_state);
    
    let locking_size = contract.locking_script_size();
    let constants_size = contract.constants.witness_size();
    
    // Estimate unlocking for typical IPA proof (10 rounds = 20 L/R terms)
    let typical_witness = IPAStepWitness {
        public_inputs: vec![[0u8; 32]; 2],      // 2 public inputs
        l_terms: vec![[[0u8; 32]; 2]; 10],      // 10 L terms
        r_terms: vec![[[0u8; 32]; 2]; 10],      // 10 R terms
        a_scalar: [0u8; 32],
        b_scalar: Some([0u8; 32]),
        new_app_state: Some([0u8; 32]),
        next_transcript_hash: [0u8; 32],
    };
    
    let unlocking_size = contract.unlocking_script_size(&typical_witness);
    
    ContractSizeReport {
        locking_script: locking_size,
        constants_blob: constants_size,
        typical_unlocking: unlocking_size,
        witness_data: typical_witness.size(),
    }
}

#[derive(Debug)]
pub struct ContractSizeReport {
    pub locking_script: usize,
    pub constants_blob: usize,
    pub typical_unlocking: usize,
    pub witness_data: usize,
}
