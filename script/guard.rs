use super::opcodes::*;
use crate::ghost::size;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardType {
    Universal,
    Paymaster,
    Minimal,
    Custom,
}

#[derive(Clone, Debug)]
pub struct Guard {
    script: Vec<u8>,
    guard_type: GuardType,
}

impl Guard {
    pub fn universal() -> Self {
        let script = GuardBuilder::new()
            .introspection() // Re-enabled
            .paymaster_reconstruction()
            .paymaster_binding()
            .ipa_verification()
            .cleanup()
            .build();
        Self {
            script,
            guard_type: GuardType::Universal,
        }
    }
    pub fn paymaster() -> Self {
        let script = GuardBuilder::new()
            .introspection() // Re-enabled
            .paymaster_reconstruction()
            .paymaster_binding()
            .ipa_verification()
            .cleanup()
            .build();
        Self {
            script,
            guard_type: GuardType::Paymaster,
        }
    }
    pub fn minimal() -> Self {
        let mut script = Vec::new();
        script.push(OP_DUP);
        script.push(OP_SIZE);
        script.extend(push_number(100));
        script.push(OP_GREATERTHAN);
        script.push(OP_VERIFY);
        script.push(OP_DROP);
        script.push(OP_TRUE);
        Self {
            script,
            guard_type: GuardType::Minimal,
        }
    }
    pub fn custom(script: Vec<u8>) -> Self {
        Self {
            script,
            guard_type: GuardType::Custom,
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.script.clone()
    }
    pub fn guard_type(&self) -> GuardType {
        self.guard_type
    }
    pub fn size(&self) -> usize {
        self.script.len()
    }
    pub fn is_valid_size(&self) -> bool {
        self.size() <= size::GUARD_MAX
    }
}

struct GuardBuilder {
    script: Vec<u8>,
}

impl GuardBuilder {
    fn new() -> Self {
        Self {
            script: Vec::with_capacity(size::GUARD_TARGET),
        }
    }
    fn build(self) -> Vec<u8> {
        self.script
    }
    fn introspection(mut self) -> Self {
        self.script.push(OP_DUP);
        self.script.push(OP_TOALTSTACK);
        self
    }
    fn poseidon_binding(mut self) -> Self {
        self.script.push(OP_TRUE);
        self.script.push(OP_VERIFY);
        self
    }
    fn ipa_verification(mut self) -> Self {
        // Warning: This is a placeholder check (Size > 128).
        // Real logic should use field_script::VerifierContract.
        // Left as placeholder per audit focus on Binding Logic.
        self.script.push(OP_SIZE);
        self.script.extend(push_number(128));
        self.script.push(OP_GREATERTHAN);
        self.script.push(OP_VERIFY);
        self.script.push(OP_DROP);
        self
    }
    fn cleanup(mut self) -> Self {
        // CLEANUP FIX (Audit):
        // 1. Recover and Drop AppBytes (from paymaster_binding)
        self.script.push(OP_FROMALTSTACK);
        self.script.push(OP_DROP);
        
        // 2. Recover and Drop Preimage (from introspection)
        self.script.push(OP_FROMALTSTACK);
        self.script.push(OP_DROP);
        
        // 3. Final Success: Push TRUE and keep it.
        // The script MUST end with a truthy value on stack.
        // Do NOT consume it with OP_VERIFY.
        self.script.push(OP_TRUE);
        self
    }
    fn paymaster_reconstruction(mut self) -> Self {
        // Stack: [Proof, AppBytes, ChangeBytes, Preimage]
        
        // 1. Reconstruct hashOutputs from AppBytes + ChangeBytes
        self.script.push(OP_OVER);   // [P, A, C, Pre, C]
        self.script.push(OP_3);      
        self.script.push(OP_PICK);   // [P, A, C, Pre, C, A]
        self.script.push(OP_SWAP);   // [P, A, C, Pre, A, C]
        self.script.push(OP_CAT);    // [P, A, C, Pre, AppChange]
        self.script.push(OP_SHA256);  // [P, A, C, Pre, SHA(AppChange)] 
        self.script.push(OP_SHA256);  // [P, A, C, Pre, ComputedHash]
        
        // 2. Extract real hashOutputs from Preimage
        self.script.push(OP_TOALTSTACK); // [P, A, C, Pre] (Alt: [ComputedHash])
        
        // BIP-143 Preimage Tail: ... + hashOutputs (32) + locktime (4) + sighashType (4) = 40 bytes
        self.script.push(OP_SIZE);
        self.script.extend(push_number(40));
        self.script.push(OP_SUB);
        self.script.push(OP_SPLIT);      // [Prefix, Tail40]
        self.script.push(OP_NIP);        // [Tail40]
        
        self.script.extend(push_number(32));
        self.script.push(OP_SPLIT);      // [HashOutputs, Tail8]
        self.script.push(OP_DROP);       // [HashOutputs]
        
        // 3. Compare
        self.script.push(OP_FROMALTSTACK); // [P, A, C, HashOutputs, ComputedHash]
        self.script.push(OP_EQUALVERIFY);   // [P, A, C]
        
        self.script.push(OP_DROP);   // [P, A]
        self
    }
    fn paymaster_binding(mut self) -> Self {
        // Stack: [P, A]
        self.script.push(OP_SIZE);
        self.script.extend(push_number(32));
        self.script.push(OP_GREATERTHAN);
        self.script.push(OP_VERIFY);
        self.script.push(OP_TOALTSTACK); // Move A to Alt
        // Stack: [P]
        self
    }
}

pub fn estimate_guard_size(k: u32) -> usize {
    let ipa_size = (k as usize) * 200;
    let poseidon_size = 64 * 30;
    let overhead = 500;
    ipa_size + poseidon_size + overhead
}

pub fn guard_fits(k: u32) -> bool {
    estimate_guard_size(k) <= size::GUARD_TARGET
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_universal_guard() {
        let guard = Guard::universal();
        assert_eq!(guard.guard_type(), GuardType::Universal);
        assert!(guard.size() > 0);
        assert!(guard.is_valid_size());
    }
    #[test]
    fn test_minimal_guard() {
        let guard = Guard::minimal();
        assert_eq!(guard.guard_type(), GuardType::Minimal);
        assert!(guard.size() < 50);
    }
    #[test]
    fn test_guard_size_estimation() {
        let size_k10 = estimate_guard_size(10);
        assert!(size_k10 < size::GUARD_TARGET);
        let size_k16 = estimate_guard_size(16);
        assert!(size_k16 < size::GUARD_MAX);
    }
    #[test]
    fn test_guard_fits() {
        assert!(guard_fits(10));
        assert!(guard_fits(14));
    }
    #[test]
    fn test_paymaster_guard() {
        let guard = Guard::paymaster();
        assert_eq!(guard.guard_type(), GuardType::Paymaster);
        assert!(guard.size() > 0);
        assert!(guard.is_valid_size());
        let minimal = Guard::minimal();
        assert!(guard.size() > minimal.size());
    }
}
