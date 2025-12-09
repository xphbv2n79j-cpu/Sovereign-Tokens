// Proof Generator [Layer 6]
// Halo2 IPA Proof → Bitcoin Script Witness Converter
//
// ARCHITECTURE:
// This module bridges the Halo2 prover and the on-chain verifier.
// It takes Halo2 proof components and generates the witness data
// that the Bitcoin script expects.
//
// FLOW:
// 1. Halo2 Prover generates: L_i, R_i, a, b (IPA components)
// 2. ProofGenerator computes: Poseidon(transcript, L_i, R_i, ...) = new_transcript
// 3. WitnessBuilder serializes: [constants_blob, witness_data, next_hash]
// 4. Bitcoin Script verifies: re-computes hash and checks equality
//
// KEY INSIGHT:
// The Bitcoin script is "blind" to EC math. It just verifies that the
// hash was computed correctly. The security comes from the fact that
// invalid L_i/R_i would cause the next folding step to fail.

use crate::ghost::script::field_script::{
    FusedPoseidonConstants, fp_to_bytes, bytes_to_fp,
};
use crate::ghost::script::verifier_contract::{
    IPAStepWitness, VerifierContract, FieldElement,
};
use crate::ghost::crypto::{Fp, PoseidonHash};
use ff::Field;

// ============================================================================
// TRANSCRIPT BUILDER
// ============================================================================

/// Builds transcripts for IPA verification
/// This simulates the Fiat-Shamir transform used in Halo2
pub struct TranscriptBuilder {
    /// Current transcript state (running hash)
    state: Fp,
    
    /// All absorbed elements (for debugging)
    absorbed: Vec<Fp>,
}

impl TranscriptBuilder {
    /// Create a new transcript with initial state
    pub fn new(initial_state: &FieldElement) -> Self {
        let state = bytes_to_fp(initial_state).unwrap_or(Fp::ZERO);
        Self {
            state,
            absorbed: vec![state],
        }
    }

    /// Create transcript from zero state
    pub fn new_empty() -> Self {
        Self {
            state: Fp::ZERO,
            absorbed: vec![Fp::ZERO],
        }
    }

    /// Absorb a single field element into the transcript
    pub fn absorb(&mut self, element: &FieldElement) {
        let fp = bytes_to_fp(element).unwrap_or(Fp::ZERO);
        self.state = PoseidonHash::hash(self.state, fp);
        self.absorbed.push(fp);
    }

    /// Absorb a field element directly
    pub fn absorb_fp(&mut self, element: Fp) {
        self.state = PoseidonHash::hash(self.state, element);
        self.absorbed.push(element);
    }

    /// Absorb multiple elements
    pub fn absorb_many(&mut self, elements: &[FieldElement]) {
        for elem in elements {
            self.absorb(elem);
        }
    }

    /// Absorb L and R terms (interleaved Affine points)
    pub fn absorb_lr_terms(&mut self, l_terms: &[[FieldElement; 2]], r_terms: &[[FieldElement; 2]]) {
        for (l, r) in l_terms.iter().zip(r_terms.iter()) {
            // Absorb L(x, y)
            self.absorb(&l[0]);
            self.absorb(&l[1]);
            // Absorb R(x, y)
            self.absorb(&r[0]);
            self.absorb(&r[1]);
        }
    }

    /// Squeeze a challenge from the transcript
    pub fn squeeze(&self) -> Fp {
        self.state
    }

    /// Get current state as bytes
    pub fn state_bytes(&self) -> FieldElement {
        fp_to_bytes(&self.state)
    }

    /// Get number of absorbed elements
    pub fn absorption_count(&self) -> usize {
        self.absorbed.len()
    }
}

// ============================================================================
// IPA PROOF COMPONENTS
// ============================================================================

/// Raw IPA proof components from Halo2
#[derive(Clone, Debug)]
pub struct IPAProofComponents {
    /// Left cross-terms (Affine points [x, y])
    pub l_commitments: Vec<[FieldElement; 2]>,
    
    /// Right cross-terms (Affine points [x, y])
    pub r_commitments: Vec<[FieldElement; 2]>,
    
    /// Final reduced scalar 'a'
    pub a: FieldElement,
    
    /// Final reduced scalar 'b' (optional)
    pub b: Option<FieldElement>,
}

impl IPAProofComponents {
    /// Create from raw bytes
    pub fn from_bytes(
        l_bytes: Vec<[u8; 64]>, // Expecting 64 bytes (Affine x,y) per point
        r_bytes: Vec<[u8; 64]>,
        a_bytes: [u8; 32],
        b_bytes: Option<[u8; 32]>,
    ) -> Self {
        let to_affine = |bytes: Vec<[u8; 64]>| -> Vec<[FieldElement; 2]> {
            bytes.into_iter().map(|b| {
                let mut x = [0u8; 32];
                let mut y = [0u8; 32];
                x.copy_from_slice(&b[0..32]);
                y.copy_from_slice(&b[32..64]);
                [x, y]
            }).collect()
        };

        Self {
            l_commitments: to_affine(l_bytes),
            r_commitments: to_affine(r_bytes),
            a: a_bytes,
            b: b_bytes,
        }
    }

    /// Get the number of reduction rounds (log2 of vector size)
    pub fn num_rounds(&self) -> usize {
        self.l_commitments.len()
    }

    /// Validate that L and R have the same length
    pub fn validate(&self) -> Result<(), ProofError> {
        if self.l_commitments.len() != self.r_commitments.len() {
            return Err(ProofError::LRLengthMismatch);
        }
        Ok(())
    }
}

// ============================================================================
// PROOF GENERATOR
// ============================================================================

/// Generates Bitcoin script witnesses from Halo2 proofs
pub struct ProofGenerator {
    /// Fused constants for Poseidon
    pub constants: FusedPoseidonConstants,
}

impl ProofGenerator {
    pub fn new() -> Self {
        Self {
            constants: FusedPoseidonConstants::compute(),
        }
    }

    /// Generate a witness for an IPA step
    /// 
    /// This is the main entry point. It takes:
    /// - The current transcript state (from the previous step)
    /// - Public inputs for this step
    /// - The IPA proof components
    /// - Optional new application state
    /// 
    /// And produces a witness that the Bitcoin script can verify.
    pub fn generate_ipa_witness(
        &self,
        current_transcript: &FieldElement,
        public_inputs: Vec<FieldElement>,
        proof: &IPAProofComponents,
        new_app_state: Option<FieldElement>,
    ) -> Result<IPAStepWitness, ProofError> {
        proof.validate()?;

        // Build the transcript
        let mut transcript = TranscriptBuilder::new(current_transcript);

        // Absorb public inputs
        transcript.absorb_many(&public_inputs);

        // Absorb L/R terms (interleaved)
        transcript.absorb_lr_terms(&proof.l_commitments, &proof.r_commitments);

        // Absorb final scalars
        transcript.absorb(&proof.a);
        if let Some(b) = &proof.b {
            transcript.absorb(b);
        }

        // Compute the new transcript hash
        let next_transcript_hash = transcript.state_bytes();

        Ok(IPAStepWitness {
            public_inputs,
            l_terms: proof.l_commitments.clone(),
            r_terms: proof.r_commitments.clone(),
            a_scalar: proof.a,
            b_scalar: proof.b,
            new_app_state,
            next_transcript_hash,
        })
    }

    /// Generate a witness for a state transition (application-level)
    /// 
    /// This wraps generate_ipa_witness with additional application logic
    pub fn generate_state_transition(
        &self,
        contract: &VerifierContract,
        proof: &IPAProofComponents,
        new_app_state: FieldElement,
        public_inputs: Vec<FieldElement>,
    ) -> Result<IPAStepWitness, ProofError> {
        self.generate_ipa_witness(
            &contract.current_state.transcript_hash,
            public_inputs,
            proof,
            Some(new_app_state),
        )
    }

    /// Verify a witness matches the expected transcript hash
    pub fn verify_witness(&self, witness: &IPAStepWitness, prev_transcript: &FieldElement) -> bool {
        witness.verify(prev_transcript)
    }
}

impl Default for ProofGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// WITNESS SERIALIZER
// ============================================================================

/// Serializes witnesses for the Bitcoin script
pub struct WitnessSerializer;

impl WitnessSerializer {
    /// Serialize witness to bytes for the unlocking script
    pub fn serialize(witness: &IPAStepWitness) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Public inputs
        for pi in &witness.public_inputs {
            bytes.extend_from_slice(pi);
        }

        // L and R terms (interleaved)
        for (l, r) in witness.l_terms.iter().zip(witness.r_terms.iter()) {
            // L(x, y)
            bytes.extend_from_slice(&l[0]);
            bytes.extend_from_slice(&l[1]);
            // R(x, y)
            bytes.extend_from_slice(&r[0]);
            bytes.extend_from_slice(&r[1]);
        }

        // Final scalars
        bytes.extend_from_slice(&witness.a_scalar);
        if let Some(b) = &witness.b_scalar {
            bytes.extend_from_slice(b);
        }

        // New app state (if present)
        if let Some(app_state) = &witness.new_app_state {
            bytes.extend_from_slice(app_state);
        }

        // Next transcript hash
        bytes.extend_from_slice(&witness.next_transcript_hash);

        bytes
    }

    /// Deserialize witness from bytes
    pub fn deserialize(bytes: &[u8], num_public_inputs: usize, num_rounds: usize, has_b: bool, has_app_state: bool) -> Option<IPAStepWitness> {
        let mut offset = 0;

        // Public inputs
        let mut public_inputs = Vec::with_capacity(num_public_inputs);
        for _ in 0..num_public_inputs {
            if offset + 32 > bytes.len() { return None; }
            let elem: FieldElement = bytes[offset..offset+32].try_into().ok()?;
            public_inputs.push(elem);
            offset += 32;
        }

        // L and R terms
        let mut l_terms = Vec::with_capacity(num_rounds);
        let mut r_terms = Vec::with_capacity(num_rounds);
        for _ in 0..num_rounds {
            // Each round has L(x,y) and R(x,y). 4 elements = 128 bytes.
            if offset + 128 > bytes.len() { return None; }
            
            let lx: FieldElement = bytes[offset..offset+32].try_into().ok()?;
            let ly: FieldElement = bytes[offset+32..offset+64].try_into().ok()?;
            
            let rx: FieldElement = bytes[offset+64..offset+96].try_into().ok()?;
            let ry: FieldElement = bytes[offset+96..offset+128].try_into().ok()?;
            
            l_terms.push([lx, ly]);
            r_terms.push([rx, ry]);
            offset += 128;
        }

        // a_scalar
        if offset + 32 > bytes.len() { return None; }
        let a_scalar: FieldElement = bytes[offset..offset+32].try_into().ok()?;
        offset += 32;

        // b_scalar (optional)
        let b_scalar = if has_b {
            if offset + 32 > bytes.len() { return None; }
            let b: FieldElement = bytes[offset..offset+32].try_into().ok()?;
            offset += 32;
            Some(b)
        } else {
            None
        };

        // new_app_state (optional)
        let new_app_state = if has_app_state {
            if offset + 32 > bytes.len() { return None; }
            let state: FieldElement = bytes[offset..offset+32].try_into().ok()?;
            offset += 32;
            Some(state)
        } else {
            None
        };

        // next_transcript_hash
        if offset + 32 > bytes.len() { return None; }
        let next_transcript_hash: FieldElement = bytes[offset..offset+32].try_into().ok()?;

        Some(IPAStepWitness {
            public_inputs,
            l_terms,
            r_terms,
            a_scalar,
            b_scalar,
            new_app_state,
            next_transcript_hash,
        })
    }
}

// ============================================================================
// ERRORS
// ============================================================================

#[derive(Debug, Clone)]
pub enum ProofError {
    LRLengthMismatch,
    InvalidProofStructure,
    TranscriptMismatch,
    SerializationError,
}

// ============================================================================
// HELPER: MOCK PROOF GENERATION (for testing)
// ============================================================================

/// Generate a mock IPA proof for testing
/// This creates valid witness data that will pass the Poseidon verification
pub fn generate_mock_proof(
    prev_transcript: &FieldElement,
    num_rounds: usize,
    public_inputs: Vec<FieldElement>,
) -> IPAStepWitness {
    let generator = ProofGenerator::new();

    // Create mock L/R terms (Affine points)
    let l_terms: Vec<[FieldElement; 2]> = (0..num_rounds)
        .map(|i| {
            let mut x = [0u8; 32];
            x[0] = (i * 2) as u8;
            x[31] = 0x01;
            let mut y = [0u8; 32];
            y[0] = (i * 2 + 100) as u8; 
            [x, y]
        })
        .collect();

    let r_terms: Vec<[FieldElement; 2]> = (0..num_rounds)
        .map(|i| {
            let mut x = [0u8; 32];
            x[0] = (i * 2 + 1) as u8;
            x[31] = 0x02;
            let mut y = [0u8; 32];
            y[0] = (i * 2 + 101) as u8;
            [x, y]
        })
        .collect();

    let a_scalar = [0x0A; 32];
    let b_scalar = Some([0x0B; 32]);

    let proof = IPAProofComponents {
        l_commitments: l_terms,
        r_commitments: r_terms,
        a: a_scalar,
        b: b_scalar,
    };

    generator
        .generate_ipa_witness(prev_transcript, public_inputs, &proof, None)
        .expect("Mock proof generation should not fail")
}

/// Generate a valid state transition for testing
pub fn generate_mock_state_transition(
    contract: &VerifierContract,
    new_app_state: FieldElement,
) -> IPAStepWitness {
    let public_inputs = vec![
        new_app_state,  // The new state is a public input
    ];

    generate_mock_proof(
        &contract.current_state.transcript_hash,
        10,  // 10 rounds typical for IPA
        public_inputs,
    )
}

// ============================================================================
// SIZE ANALYSIS
// ============================================================================

/// Analyze witness sizes for different configurations
pub fn analyze_witness_sizes() -> WitnessSizeReport {
    let generator = ProofGenerator::new();

    // Small proof (5 rounds, 1 public input)
    let small_proof = IPAProofComponents {
        l_commitments: vec![[[0u8; 32]; 2]; 5],
        r_commitments: vec![[[0u8; 32]; 2]; 5],
        a: [0u8; 32],
        b: Some([0u8; 32]),
    };
    let small_witness = generator
        .generate_ipa_witness(&[0u8; 32], vec![[0u8; 32]], &small_proof, None)
        .unwrap();

    // Medium proof (10 rounds, 2 public inputs)
    let medium_proof = IPAProofComponents {
        l_commitments: vec![[[0u8; 32]; 2]; 10],
        r_commitments: vec![[[0u8; 32]; 2]; 10],
        a: [0u8; 32],
        b: Some([0u8; 32]),
    };
    let medium_witness = generator
        .generate_ipa_witness(&[0u8; 32], vec![[0u8; 32]; 2], &medium_proof, Some([0u8; 32]))
        .unwrap();

    // Large proof (15 rounds, 4 public inputs)
    let large_proof = IPAProofComponents {
        l_commitments: vec![[[0u8; 32]; 2]; 15],
        r_commitments: vec![[[0u8; 32]; 2]; 15],
        a: [0u8; 32],
        b: Some([0u8; 32]),
    };
    let large_witness = generator
        .generate_ipa_witness(&[0u8; 32], vec![[0u8; 32]; 4], &large_proof, Some([0u8; 32]))
        .unwrap();

    WitnessSizeReport {
        small: small_witness.size(),
        medium: medium_witness.size(),
        large: large_witness.size(),
        constants_blob: generator.constants.witness_size(),
    }
}

#[derive(Debug)]
pub struct WitnessSizeReport {
    pub small: usize,   // 5 rounds, 1 PI
    pub medium: usize,  // 10 rounds, 2 PI
    pub large: usize,   // 15 rounds, 4 PI
    pub constants_blob: usize,
}
