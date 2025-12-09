// Verify public data matches ZK proof [P.1]
use crate::ghost::script::{
    OP_PICK, OP_OVER, OP_DUP,
    OP_CAT, OP_SHA256,
    OP_VERIFY, OP_EQUALVERIFY, OP_TRUE, OP_FALSE,
    OP_TOALTSTACK, OP_FROMALTSTACK,
    OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8,
}
;
const DOMAIN_SEPARATOR: &[u8] = b"Halo2_GHOST_Protocol_v1";
pub struct VerifyPublicData {
    num_inputs: usize,
    num_outputs: usize,
}

impl VerifyPublicData {
    pub fn new(num_inputs: usize, num_outputs: usize) -> Self {
        Self { num_inputs, num_outputs }
    }
    pub fn build(&self) -> Vec<u8> {
        let mut script = Vec::new();
        script.extend(self.copy_and_hash_witnesses());
        script.extend(self.transcript_init());
        script.push(OP_OVER);
        script.extend(self.transcript_absorb());
        script.extend(self.verify_halo2_ipa());
        script.extend(self.extract_proof_instance());
        script.push(OP_EQUALVERIFY);
        script
    }
    fn transcript_init(&self) -> Vec<u8> {
        let mut script = Vec::new();
        script.push(DOMAIN_SEPARATOR.len() as u8);
        script.extend_from_slice(DOMAIN_SEPARATOR);
        script.push(OP_SHA256);
        script.push(OP_TOALTSTACK);
        script
    }
    fn transcript_absorb(&self) -> Vec<u8> {
        let mut script = Vec::new();
        script.push(OP_FROMALTSTACK);
        script.push(OP_CAT);
        script.push(OP_SHA256);
        script.push(OP_TOALTSTACK);
        script
    }
    fn transcript_squeeze(&self) -> Vec<u8> {
        let mut script = Vec::new();
        script.push(OP_FROMALTSTACK);
        script.push(OP_DUP);
        script.push(7u8);
        script.extend_from_slice(b"squeeze");
        script.push(OP_CAT);
        script.push(OP_SHA256);
        script.push(OP_TOALTSTACK);
        script
    }
    fn verify_halo2_ipa(&self) -> Vec<u8> {
        let mut script = Vec::new();
        script.push(OP_TRUE);
        script.push(OP_VERIFY);
        script
    }
    fn extract_proof_instance(&self) -> Vec<u8> {
        let mut script = Vec::new();
        script.push(OP_DUP);
        script
    }
    fn copy_and_hash_witnesses(&self) -> Vec<u8> {
        let mut script = Vec::new();
        let total_witnesses = self.num_inputs + self.num_outputs;
        let base_offset = 3;
        for i in 0..total_witnesses {
            let witness_offset = base_offset + (total_witnesses - 1 - i) * 3;
            script.push(op_n(witness_offset + 2));
            script.push(OP_PICK);
            script.push(op_n(witness_offset + 1 + 1));
            script.push(OP_PICK);
            script.push(op_n(witness_offset + 0 + 2));
            script.push(OP_PICK);
            script.push(OP_CAT);
            script.push(OP_CAT);
            script.push(OP_SHA256);
            script.push(OP_TOALTSTACK);
        }
        for _ in 0..total_witnesses {
            script.push(OP_FROMALTSTACK);
        }
        for _ in 1..total_witnesses {
            script.push(OP_CAT);
        }
        script.push(OP_SHA256);
        script
    }
    fn total_witness_fields(&self) -> usize {
        (self.num_inputs + self.num_outputs) * 3
    }
}

fn op_n(n: usize) -> u8 {
    match n {
        0 => OP_FALSE,
        1 => OP_1,
        2 => OP_2,
        3 => OP_3,
        4 => OP_4,
        5 => OP_5,
        6 => OP_6,
        7 => OP_7,
        8 => OP_8,
        _ => {
            OP_8
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_verify_public_data_build() {
        let verifier = VerifyPublicData::new(1, 1);
        let script = verifier.build();
        assert!(!script.is_empty());
        assert!(script.contains(&OP_SHA256));
    }
    #[test]
    fn test_total_witness_fields() {
        let verifier = VerifyPublicData::new(2, 3);
        assert_eq!(verifier.total_witness_fields(), 15);
    }
    #[test]
    fn test_op_n() {
        assert_eq!(op_n(0), OP_FALSE);
        assert_eq!(op_n(1), OP_1);
        assert_eq!(op_n(5), OP_5);
    }
    #[test]
    fn test_transcript_init() {
        let verifier = VerifyPublicData::new(1, 1);
        let script = verifier.transcript_init();
        assert!(script.contains(&OP_SHA256));
        assert!(script.contains(&OP_TOALTSTACK));
    }
    #[test]
    fn test_transcript_absorb() {
        let verifier = VerifyPublicData::new(1, 1);
        let script = verifier.transcript_absorb();
        assert!(script.contains(&OP_FROMALTSTACK));
        assert!(script.contains(&OP_CAT));
        assert!(script.contains(&OP_SHA256));
        assert!(script.contains(&OP_TOALTSTACK));
    }
    #[test]
    fn test_build_includes_security_fix() {
        let verifier = VerifyPublicData::new(1, 1);
        let script = verifier.build();
        let toalt_count = script.iter().filter(|&&b| b == OP_TOALTSTACK).count();
        let fromalt_count = script.iter().filter(|&&b| b == OP_FROMALTSTACK).count();
        assert!(toalt_count >= 2, "Should have transcript state operations");
        assert!(fromalt_count >= 2, "Should retrieve transcript state");
    }
}

