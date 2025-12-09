use crate::ghost::crypto::{Fp, double_sha256};
use crate::ghost::circuit::{StandardIntent, Proof};
use crate::ghost::script::{IpaHints, PoseidonHints};
use crate::ghost::binding::reconstruction::ReconstructionWitness;
use crate::ghost::{Error, Result};
#[derive(Clone, Debug)]
pub struct EcdsaSignature {
    pub der_bytes: Vec<u8>,
    pub sighash_flag: u8,
}

impl EcdsaSignature {
    pub fn new(der_bytes: Vec<u8>) -> Self {
        Self {
            der_bytes,
            sighash_flag: 0x41,
        }
    }
    pub fn with_sighash(der_bytes: Vec<u8>, flag: u8) -> Self {
        Self {
            der_bytes,
            sighash_flag: flag,
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.der_bytes.clone();
        bytes.push(self.sighash_flag);
        bytes
    }
    pub fn size(&self) -> usize {
        self.der_bytes.len() + 1
    }
}

impl Default for EcdsaSignature {
    fn default() -> Self {
        Self {
            der_bytes: vec![0x30; 70],
            sighash_flag: 0x41,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PaymasterWitness {
    pub proof: Proof,
    pub ipa_hints: IpaHints,
    pub poseidon_hints: PoseidonHints,
    pub app_outputs_bytes: Vec<u8>,
    pub change_outputs_bytes: Vec<u8>,
    pub app_fields: Vec<Fp>,
    pub preimage: Vec<u8>,
    pub user_signature: EcdsaSignature,
    pub sponsor_signature: Option<EcdsaSignature>,
}

impl PaymasterWitness {
    pub fn new(
        proof: Proof,
        ipa_hints: IpaHints,
        poseidon_hints: PoseidonHints,
        app_outputs: &[StandardIntent],
        change_outputs: &[StandardIntent],
        preimage: Vec<u8>,
    ) -> Self {
        let reconstruction = ReconstructionWitness::new(app_outputs, change_outputs);
        Self {
            proof,
            ipa_hints,
            poseidon_hints,
            app_outputs_bytes: reconstruction.app_outputs_bytes,
            change_outputs_bytes: reconstruction.change_outputs_bytes,
            app_fields: reconstruction.app_fields,
            preimage,
            user_signature: EcdsaSignature::default(),
            sponsor_signature: None,
        }
    }
    pub fn with_user_signature(mut self, sig: EcdsaSignature) -> Self {
        self.user_signature = sig;
        self
    }
    pub fn with_sponsor_signature(mut self, sig: EcdsaSignature) -> Self {
        self.sponsor_signature = Some(sig);
        self
    }
    pub fn compute_hash_outputs(&self) -> [u8; 32] {
        let mut full_bytes = Vec::new();
        full_bytes.extend(&self.app_outputs_bytes);
        full_bytes.extend(&self.change_outputs_bytes);
        double_sha256(&full_bytes)
    }
    pub fn verify_reconstruction(&self) -> Result<()> {
        if self.preimage.len() < 132 {
            return Err(Error::InvalidInput("Preimage too short".to_string()));
        }
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&self.preimage[100..132]);
        let computed = self.compute_hash_outputs();
        if expected != computed {
            return Err(Error::BindingMismatch);
        }
        Ok(())
    }
    pub fn to_script_sig(&self) -> Vec<u8> {
        let mut script = Vec::new();
        if let Some(ref sig) = self.sponsor_signature {
            let sig_bytes = sig.to_bytes();
            script.extend(push_data(&sig_bytes));
        }
        let user_sig_bytes = self.user_signature.to_bytes();
        script.extend(push_data(&user_sig_bytes));
        script.extend(push_data(&self.preimage));
        script.extend(push_data(&self.change_outputs_bytes));
        script.extend(push_data(&self.app_outputs_bytes));
        let poseidon_bytes = self.poseidon_hints.to_bytes();
        script.extend(push_data(&poseidon_bytes));
        let ipa_bytes = self.ipa_hints.to_bytes();
        script.extend(push_data(&ipa_bytes));
        let proof_bytes = self.proof.to_bytes();
        script.extend(push_data(&proof_bytes));
        script
    }
    pub fn estimate_size(&self) -> usize {
        let mut size = 0;
        size += self.proof.to_bytes().len() + 3;
        size += self.ipa_hints.to_bytes().len() + 3;
        size += self.poseidon_hints.to_bytes().len() + 3;
        size += self.app_outputs_bytes.len() + 3;
        size += self.change_outputs_bytes.len() + 3;
        size += self.preimage.len() + 3;
        size += self.user_signature.size() + 1;
        if let Some(ref sig) = self.sponsor_signature {
            size += sig.size() + 1;
        }
        size
    }
}

fn push_data(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let len = data.len();
    if len == 0 {
        result.push(0x00);
    } else if len == 1 && data[0] >= 1 && data[0] <= 16 {
        result.push(0x50 + data[0]);
    } else if len <= 75 {
        result.push(len as u8);
        result.extend(data);
    } else if len <= 255 {
        result.push(0x4c);
        result.push(len as u8);
        result.extend(data);
    } else if len <= 65535 {
        result.push(0x4d);
        result.extend(&(len as u16).to_le_bytes());
        result.extend(data);
    } else {
        result.push(0x4e);
        result.extend(&(len as u32).to_le_bytes());
        result.extend(data);
    }
    result
}

#[derive(Clone, Debug)]
pub struct StrictWitness {
    pub proof: Proof,
    pub ipa_hints: IpaHints,
    pub poseidon_hints: PoseidonHints,
    pub preimage: Vec<u8>,
    pub signature: EcdsaSignature,
}

impl StrictWitness {
    pub fn new(
        proof: Proof,
        ipa_hints: IpaHints,
        poseidon_hints: PoseidonHints,
        preimage: Vec<u8>,
    ) -> Self {
        Self {
            proof,
            ipa_hints,
            poseidon_hints,
            preimage,
            signature: EcdsaSignature::default(),
        }
    }
    pub fn with_signature(mut self, sig: EcdsaSignature) -> Self {
        self.signature = sig;
        self
    }
    pub fn to_script_sig(&self) -> Vec<u8> {
        let mut script = Vec::new();
        let sig_bytes = self.signature.to_bytes();
        script.extend(push_data(&sig_bytes));
        script.extend(push_data(&self.preimage));
        let poseidon_bytes = self.poseidon_hints.to_bytes();
        script.extend(push_data(&poseidon_bytes));
        let ipa_bytes = self.ipa_hints.to_bytes();
        script.extend(push_data(&ipa_bytes));
        let proof_bytes = self.proof.to_bytes();
        script.extend(push_data(&proof_bytes));
        script
    }
    pub fn estimate_size(&self) -> usize {
        let mut size = 0;
        size += self.proof.to_bytes().len() + 3;
        size += self.ipa_hints.to_bytes().len() + 3;
        size += self.poseidon_hints.to_bytes().len() + 3;
        size += self.preimage.len() + 3;
        size += self.signature.size() + 1;
        size
    }
}

#[derive(Default)]
pub struct PaymasterWitnessBuilder {
    proof: Option<Proof>,
    ipa_hints: Option<IpaHints>,
    poseidon_hints: Option<PoseidonHints>,
    app_outputs: Vec<StandardIntent>,
    change_outputs: Vec<StandardIntent>,
    preimage: Option<Vec<u8>>,
    user_signature: Option<EcdsaSignature>,
    sponsor_signature: Option<EcdsaSignature>,
}

impl PaymasterWitnessBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn proof(mut self, proof: Proof) -> Self {
        self.proof = Some(proof);
        self
    }
    pub fn ipa_hints(mut self, hints: IpaHints) -> Self {
        self.ipa_hints = Some(hints);
        self
    }
    pub fn poseidon_hints(mut self, hints: PoseidonHints) -> Self {
        self.poseidon_hints = Some(hints);
        self
    }
    pub fn app_output(mut self, output: StandardIntent) -> Self {
        self.app_outputs.push(output);
        self
    }
    pub fn app_outputs(mut self, outputs: Vec<StandardIntent>) -> Self {
        self.app_outputs = outputs;
        self
    }
    pub fn change_output(mut self, output: StandardIntent) -> Self {
        self.change_outputs.push(output);
        self
    }
    pub fn change_outputs(mut self, outputs: Vec<StandardIntent>) -> Self {
        self.change_outputs = outputs;
        self
    }
    pub fn preimage(mut self, preimage: Vec<u8>) -> Self {
        self.preimage = Some(preimage);
        self
    }
    pub fn user_signature(mut self, sig: EcdsaSignature) -> Self {
        self.user_signature = Some(sig);
        self
    }
    pub fn sponsor_signature(mut self, sig: EcdsaSignature) -> Self {
        self.sponsor_signature = Some(sig);
        self
    }
    pub fn build(self) -> Result<PaymasterWitness> {
        let proof = self.proof.ok_or_else(|| 
            Error::InvalidInput("Missing proof".to_string()))?;
        let ipa_hints = self.ipa_hints.ok_or_else(|| 
            Error::InvalidInput("Missing IPA hints".to_string()))?;
        let poseidon_hints = self.poseidon_hints.ok_or_else(|| 
            Error::InvalidInput("Missing Poseidon hints".to_string()))?;
        let preimage = self.preimage.ok_or_else(|| 
            Error::InvalidInput("Missing preimage".to_string()))?;
        let mut witness = PaymasterWitness::new(
            proof,
            ipa_hints,
            poseidon_hints,
            &self.app_outputs,
            &self.change_outputs,
            preimage,
        );
        if let Some(sig) = self.user_signature {
            witness = witness.with_user_signature(sig);
        }
        if let Some(sig) = self.sponsor_signature {
            witness = witness.with_sponsor_signature(sig);
        }
        Ok(witness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghost::crypto::FieldExt;
    fn make_intent(asset: u64, amount: u64, nonce: u64, recipient: u64) -> StandardIntent {
        StandardIntent::with_nonce(asset, amount, nonce, Fp::from_u64(recipient))
    }
    fn make_test_proof() -> Proof {
        Proof {
            bytes: vec![0xAB; 100],
            public_inputs: vec![Fp::from_u64(12345)],
        }
    }
    #[test]
    fn test_ecdsa_signature() {
        let sig = EcdsaSignature::new(vec![0x30, 0x45, 0x02, 0x20]);
        assert_eq!(sig.sighash_flag, 0x41);
        let bytes = sig.to_bytes();
        assert_eq!(bytes.last(), Some(&0x41));
    }
    #[test]
    fn test_push_data_small() {
        let data = vec![0x01, 0x02, 0x03];
        let pushed = push_data(&data);
        assert_eq!(pushed[0], 3);
        assert_eq!(&pushed[1..], &data);
    }
    #[test]
    fn test_push_data_medium() {
        let data = vec![0x42; 100];
        let pushed = push_data(&data);
        assert_eq!(pushed[0], 0x4c);
        assert_eq!(pushed[1], 100);
        assert_eq!(&pushed[2..], &data);
    }
    #[test]
    fn test_paymaster_witness_creation() {
        let app_outputs = vec![
            make_intent(1, 90, 1, 0xAAAA),
        ];
        let change_outputs = vec![
            make_intent(1, 10, 2, 0xBBBB),
        ];
        let witness = PaymasterWitness::new(
            make_test_proof(),
            IpaHints::placeholder(10),
            PoseidonHints::placeholder(4),
            &app_outputs,
            &change_outputs,
            vec![0x00; 180],
        );
        assert!(!witness.app_outputs_bytes.is_empty());
        assert!(!witness.change_outputs_bytes.is_empty());
        assert_eq!(witness.app_fields.len(), 1);
    }
    #[test]
    fn test_paymaster_witness_to_script_sig() {
        let witness = PaymasterWitness::new(
            make_test_proof(),
            IpaHints::placeholder(10),
            PoseidonHints::placeholder(4),
            &[make_intent(1, 90, 1, 0xAAAA)],
            &[make_intent(1, 10, 2, 0xBBBB)],
            vec![0x00; 180],
        );
        let script_sig = witness.to_script_sig();
        assert!(!script_sig.is_empty());
    }
    #[test]
    fn test_paymaster_witness_builder() {
        let witness = PaymasterWitnessBuilder::new()
            .proof(make_test_proof())
            .ipa_hints(IpaHints::placeholder(10))
            .poseidon_hints(PoseidonHints::placeholder(4))
            .app_output(make_intent(1, 90, 1, 0xAAAA))
            .change_output(make_intent(1, 10, 2, 0xBBBB))
            .preimage(vec![0x00; 180])
            .user_signature(EcdsaSignature::default())
            .build()
            .unwrap();
        assert!(witness.sponsor_signature.is_none());
        assert!(!witness.app_outputs_bytes.is_empty());
    }
    #[test]
    fn test_witness_size_estimation() {
        let witness = PaymasterWitness::new(
            make_test_proof(),
            IpaHints::placeholder(10),
            PoseidonHints::placeholder(4),
            &[make_intent(1, 90, 1, 0xAAAA)],
            &[make_intent(1, 10, 2, 0xBBBB)],
            vec![0x00; 180],
        );
        let estimated = witness.estimate_size();
        let actual = witness.to_script_sig().len();
        assert!(estimated > actual / 2);
        assert!(estimated < actual * 2);
    }
}

