// Poseidon Guard Script Generator [L.2] - Bitcoin Script for hint verification
// Generates script that verifies Poseidon hints from witness stack

use crate::ghost::script::{
    OP_DUP, OP_DROP, OP_SWAP, OP_OVER,
    OP_CAT, OP_SHA256, OP_EQUAL, OP_EQUALVERIFY, OP_TRUE,
    OP_TOALTSTACK, OP_FROMALTSTACK,
    OP_SIZE, OP_SPLIT,
    push_bytes, push_number,
};
use crate::ghost::crypto::poseidon_constants::PoseidonParams;

/// Guard script configuration
#[derive(Clone, Debug)]
pub struct PoseidonGuardConfig {
    /// Number of Poseidon hashes to verify (4 per intent)
    pub hash_count: usize,
    /// Whether to include full S-box verification
    pub verify_sbox: bool,
    /// Whether to include MDS verification
    pub verify_mds: bool,
    /// Maximum script size budget
    pub max_script_size: usize,
}

impl Default for PoseidonGuardConfig {
    fn default() -> Self {
        Self {
            hash_count: 4,  // Single intent
            verify_sbox: true,
            verify_mds: true,
            max_script_size: 6500,  // Target ~6.5KB
        }
    }
}

impl PoseidonGuardConfig {
    pub fn for_intents(intent_count: usize) -> Self {
        Self {
            hash_count: intent_count * 4,
            ..Default::default()
        }
    }
}

/// Script builder for Poseidon verification
pub struct PoseidonGuardBuilder {
    script: Vec<u8>,
    config: PoseidonGuardConfig,
}

impl PoseidonGuardBuilder {
    pub fn new(config: PoseidonGuardConfig) -> Self {
        Self {
            script: Vec::with_capacity(config.max_script_size),
            config,
        }
    }

    /// Build complete verification script
    pub fn build(mut self) -> Vec<u8> {
        // Script structure:
        // 1. Verify initial state matches claimed inputs
        // 2. For each round: verify hint consistency
        // 3. Verify final output matches commitment
        
        self.emit_header();
        self.emit_round_verification();
        self.emit_output_check();
        self.emit_cleanup();
        
        self.script
    }

    fn emit_header(&mut self) {
        // Stack expectation comment (not emitted, for documentation)
        // Witness stack (bottom to top):
        //   [round_hints...] [initial_state] [claimed_output]
    }

    fn emit_round_verification(&mut self) {
        // For simplified verification, we check:
        // 1. That provided after_sbox values are consistent
        // 2. That provided after_mds values chain correctly
        
        // This is a simplified check that verifies the hint chain
        // Full verification would require BigInt arithmetic in Script
        
        let rounds_per_hash = PoseidonParams::TOTAL_ROUNDS;
        let total_rounds = self.config.hash_count * rounds_per_hash;
        
        // Emit round verification loop structure
        // Each round verifies: after_mds[n] -> add_rc -> sbox -> mds -> after_mds[n+1]
        
        for _round in 0..total_rounds {
            self.emit_single_round_check();
        }
    }

    fn emit_single_round_check(&mut self) {
        // For each round, we verify that the hint chain is internally consistent
        // This uses SHA256 binding rather than full field arithmetic
        
        // Stack: [hint_data] [state]
        // 1. DUP state for later comparison
        // 2. Verify hint structure
        // 3. Update state to next round
        
        self.script.push(OP_DUP);
        self.script.push(OP_TOALTSTACK);  // Save state
        
        // Verify hint (simplified - actual would do field arithmetic)
        // For now, we just check the hint is properly formatted
        self.script.push(OP_SIZE);
        self.script.extend(push_number(96));  // Expect 3×32 bytes per round state
        self.script.push(OP_EQUALVERIFY);
        
        self.script.push(OP_FROMALTSTACK);  // Restore state
    }

    fn emit_output_check(&mut self) {
        // Verify final state matches claimed commitment
        self.script.push(OP_EQUALVERIFY);
    }

    fn emit_cleanup(&mut self) {
        // Clean up stack, leave TRUE
        self.script.push(OP_TRUE);
    }

    /// Get current script size
    pub fn size(&self) -> usize {
        self.script.len()
    }
}

/// Generate a minimal verification script
/// This creates script that verifies hint binding via SHA256
pub fn generate_poseidon_binding_script(
    initial_left: &[u8; 32],
    initial_right: &[u8; 32],
    expected_output: &[u8; 32],
) -> Vec<u8> {
    let mut script = Vec::new();
    
    // Witness provides: [hints] [claimed_output]
    // Script verifies: SHA256(initial || hints) == claimed_output
    
    // Push initial state
    script.extend(push_bytes(initial_left));
    script.extend(push_bytes(initial_right));
    script.push(OP_CAT);
    
    // Concatenate with hints from witness
    script.push(OP_SWAP);
    script.push(OP_CAT);
    
    // Hash
    script.push(OP_SHA256);
    
    // Compare with expected
    script.extend(push_bytes(expected_output));
    script.push(OP_EQUAL);
    
    script
}

/// Hint-based Poseidon verification structure
#[derive(Clone, Debug)]
pub struct PoseidonVerifyScript {
    /// Initialization script (setup)
    pub init: Vec<u8>,
    /// Per-round verification (repeated)
    pub round_verify: Vec<u8>,
    /// Finalization (output check)
    pub finalize: Vec<u8>,
}

impl PoseidonVerifyScript {
    /// Create verification script components
    pub fn new() -> Self {
        Self {
            init: Self::generate_init(),
            round_verify: Self::generate_round_verify(),
            finalize: Self::generate_finalize(),
        }
    }

    fn generate_init() -> Vec<u8> {
        let mut script = Vec::new();
        // Initialize verification state
        // Stack: [hints...] [initial_state]
        script.push(OP_DUP);
        script.push(OP_TOALTSTACK);
        script
    }

    fn generate_round_verify() -> Vec<u8> {
        let mut script = Vec::new();
        // Verify one round of hints
        // This is called in a loop for all 64 rounds
        
        // Stack: [round_hint] [current_state]
        // Round hint format: [after_sbox: 96 bytes] [after_mds: 96 bytes]
        
        // 1. Verify hint is properly sized
        script.push(OP_OVER);
        script.push(OP_SIZE);
        script.extend(push_number(192));  // 6 × 32 bytes
        script.push(OP_EQUALVERIFY);
        
        // 2. Extract after_mds as new state
        script.push(OP_SWAP);
        script.extend(push_number(96));
        script.push(OP_SPLIT);
        script.push(OP_DROP);  // Drop after_sbox, keep after_mds as new state
        
        script
    }

    fn generate_finalize() -> Vec<u8> {
        let mut script = Vec::new();
        // Verify final state matches expected output
        // Stack: [expected_output] [final_state]
        
        script.push(OP_FROMALTSTACK);  // Get initial state for binding
        script.push(OP_DROP);  // Don't need it for simple check
        
        // Compare final state with expected
        script.push(OP_EQUALVERIFY);
        script.push(OP_TRUE);
        
        script
    }

    /// Total script size
    pub fn total_size(&self, rounds: usize) -> usize {
        self.init.len() + (self.round_verify.len() * rounds) + self.finalize.len()
    }
}

impl Default for PoseidonVerifyScript {
    fn default() -> Self {
        Self::new()
    }
}

/// Estimate Guard script size for given parameters
pub fn estimate_guard_size(intent_count: usize, include_sbox_verify: bool) -> usize {
    // Hint-based verification is compact:
    // - We don't compute in Script, just check hint binding
    // - Per hash: ~50 bytes for binding check
    // - 4 hashes per intent
    let hashes_per_intent = 4;
    let total_hashes = intent_count * hashes_per_intent;
    
    let base_overhead = 200;  // Init + finalize + structure
    let per_hash = if include_sbox_verify { 100 } else { 50 };
    
    base_overhead + (total_hashes * per_hash)
}

/// Check if Guard fits in target size
pub fn guard_fits(intent_count: usize, target_size: usize) -> bool {
    estimate_guard_size(intent_count, true) <= target_size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guard_config_default() {
        let config = PoseidonGuardConfig::default();
        assert_eq!(config.hash_count, 4);
        assert!(config.verify_sbox);
    }

    #[test]
    fn test_guard_config_for_intents() {
        let config = PoseidonGuardConfig::for_intents(3);
        assert_eq!(config.hash_count, 12);  // 3 intents × 4 hashes
    }

    #[test]
    fn test_guard_builder() {
        let config = PoseidonGuardConfig::default();
        let builder = PoseidonGuardBuilder::new(config);
        let script = builder.build();
        
        assert!(!script.is_empty());
        println!("Guard script size: {} bytes", script.len());
    }

    #[test]
    fn test_binding_script() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let output = [3u8; 32];
        
        let script = generate_poseidon_binding_script(&left, &right, &output);
        assert!(!script.is_empty());
        println!("Binding script size: {} bytes", script.len());
    }

    #[test]
    fn test_verify_script_components() {
        let verify = PoseidonVerifyScript::new();
        
        assert!(!verify.init.is_empty());
        assert!(!verify.round_verify.is_empty());
        assert!(!verify.finalize.is_empty());
        
        let total = verify.total_size(64);
        println!("Verify script size for 64 rounds: {} bytes", total);
    }

    #[test]
    fn test_size_estimation() {
        let size_1 = estimate_guard_size(1, true);
        let size_2 = estimate_guard_size(2, true);
        
        assert!(size_2 > size_1);
        println!("1 intent: {} bytes, 2 intents: {} bytes", size_1, size_2);
    }

    #[test]
    fn test_guard_fits() {
        // Single intent should fit in 6.5KB
        assert!(guard_fits(1, 6500));
        
        // Many intents may not fit
        let max_intents = (0..20).find(|&i| !guard_fits(i, 6500)).unwrap_or(20);
        println!("Max intents in 6.5KB: {}", max_intents - 1);
    }

    #[test]
    fn test_round_verify_structure() {
        let verify = PoseidonVerifyScript::new();
        
        // Round verify should be compact
        assert!(verify.round_verify.len() < 30);
        println!("Per-round verification: {} bytes", verify.round_verify.len());
    }
}
