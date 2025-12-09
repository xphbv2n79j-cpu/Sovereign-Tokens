use crate::ghost::binding::BindingMode;
use crate::ghost::script::{
    OP_DUP, OP_PICK, OP_DROP, OP_SWAP,
    OP_CAT, OP_SHA256, OP_EQUALVERIFY, OP_FALSE,
    OP_SPLIT, OP_SIZE,
    OP_1, OP_2, OP_3, OP_4,
}
;
const OUTPUT_SERIALIZED_SIZE: usize = 41;
pub struct VerifyBinding {
    num_app_outputs: usize,
    binding_mode: BindingMode,
}

impl VerifyBinding {
    pub fn new(num_app_outputs: usize, binding_mode: BindingMode) -> Self {
        Self { num_app_outputs, binding_mode }
    }
    pub fn build(&self) -> Vec<u8> {
        match self.binding_mode {
            BindingMode::Strict => self.build_strict(),
            BindingMode::Partial => self.build_paymaster(),
        }
    }
    fn build_strict(&self) -> Vec<u8> {
        let mut script = Vec::new();
        script.extend(self.serialize_outputs());
        script.push(OP_SHA256);
        script.push(OP_SHA256);
        script.extend(self.extract_hash_outputs());
        script.push(OP_EQUALVERIFY);
        script
    }
    fn build_paymaster(&self) -> Vec<u8> {
        let mut script = Vec::new();
        script.extend(self.serialize_outputs());
        let expected_app_length = self.num_app_outputs * 41;
        script.push(OP_DUP);
        script.push(OP_SIZE);
        script.extend(push_number(expected_app_length));
        script.push(OP_EQUALVERIFY);
        script.push(OP_2);
        script.push(OP_PICK);
        script.push(OP_DUP);
        script.push(OP_SIZE);
        script.push(OP_SWAP);
        script.push(OP_CAT);
        script.push(OP_SHA256);
        script.push(OP_SHA256);
        script.extend(self.extract_hash_outputs());
        script.push(OP_EQUALVERIFY);
        script
    }
    fn serialize_outputs(&self) -> Vec<u8> {
        let mut script = Vec::new();
        script.push(OP_FALSE);
        for i in 0..self.num_app_outputs {
            let output_base = 3 + (self.num_app_outputs - 1 - i) * 3;
            script.push(op_n(output_base + 1 + 1));
            script.push(OP_PICK);
            script.push(op_n(output_base + 0 + 2));
            script.push(OP_PICK);
            script.push(OP_SWAP);
            script.push(0x01);
            script.push(0x20);
            script.push(OP_CAT);
            script.push(OP_CAT);
            script.push(OP_CAT);
        }
        script
    }
    fn extract_hash_outputs(&self) -> Vec<u8> {
        let mut script = Vec::new();
        script.push(OP_1);
        script.push(OP_PICK);
        script.push(OP_SIZE);
        script.push(0x01);
        script.push(40);
        script.push(0x94);
        script.push(OP_SPLIT);
        script.push(0x01);
        script.push(32);
        script.push(OP_SPLIT);
        script.push(OP_DROP);
        script.push(OP_SWAP);
        script.push(OP_DROP);
        script
    }
}

fn op_n(n: usize) -> u8 {
    match n {
        0 => OP_FALSE,
        1 => OP_1,
        2 => OP_2,
        3 => OP_3,
        4 => OP_4,
        _ => {
            OP_4
        }
    }
}

fn push_number(n: usize) -> Vec<u8> {
    let mut script = Vec::new();
    if n == 0 {
        script.push(OP_FALSE);
    } else if n <= 16 {
        script.push(0x50 + n as u8);
    } else if n <= 0x7F {
        script.push(0x01);
        script.push(n as u8);
    } else if n <= 0x7FFF {
        script.push(0x02);
        script.extend(&(n as u16).to_le_bytes());
    } else if n <= 0x7FFFFF {
        script.push(0x03);
        let bytes = (n as u32).to_le_bytes();
        script.extend(&bytes[..3]);
    } else {
        script.push(0x04);
        script.extend(&(n as u32).to_le_bytes());
    }
    script
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_verify_binding_strict() {
        let verifier = VerifyBinding::new(1, BindingMode::Strict);
        let script = verifier.build();
        assert!(!script.is_empty());
        assert!(script.contains(&OP_SHA256));
        assert!(script.contains(&OP_EQUALVERIFY));
    }
    #[test]
    fn test_verify_binding_paymaster() {
        let verifier = VerifyBinding::new(1, BindingMode::Partial);
        let script = verifier.build();
        assert!(!script.is_empty());
        assert!(script.contains(&OP_CAT));
    }
    #[test]
    fn test_serialize_outputs() {
        let verifier = VerifyBinding::new(2, BindingMode::Strict);
        let script = verifier.serialize_outputs();
        assert!(!script.is_empty());
    }
}

