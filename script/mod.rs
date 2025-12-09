mod opcodes;
mod hints;
mod guard;
mod tail;
mod witness;
mod guard_engine;
pub mod poseidon_guard;
pub mod field_script;
pub mod verifier_contract;
pub mod proof_generator;
pub use opcodes::*;
pub use hints::{IpaHints, PoseidonHints, PoseidonRoundHint, FoldingRound};
pub use guard::{Guard, GuardType};
pub use tail::{Tail, TailType, EcdsaTail, MultisigTail, LamportTail, SponsorTail, DualAuthTail, AnyoneCanSpendTail, CustomTail};
pub use witness::{PaymasterWitness, EcdsaSignature};
pub use guard_engine::{UniversalGuard, GuardConfig, VerifyPublicData, VerifyBinding, StackCleanup};
pub use verifier_contract::{
    VerifierContract, IPAAccumulator, IPAStepWitness, 
    ContractOutput, ContractTransactionBuilder, FieldElement,
    analyze_contract_sizes, ContractSizeReport,
};
pub use proof_generator::{
    ProofGenerator, TranscriptBuilder, IPAProofComponents,
    WitnessSerializer, generate_mock_proof, generate_mock_state_transition,
    analyze_witness_sizes,
};
use crate::ghost::crypto::{sha256};
#[derive(Clone, Debug)]
pub struct MulletScript {
    pub guard: Guard,
    pub tail: Box<dyn Tail>,
}

impl MulletScript {
    pub fn new(guard: Guard, tail: impl Tail + 'static) -> Self {
        Self {
            guard,
            tail: Box::new(tail),
        }
    }
    pub fn universal(tail: impl Tail + 'static) -> Self {
        Self::new(Guard::universal(), tail)
    }
    pub fn minimal(tail: impl Tail + 'static) -> Self {
        Self::new(Guard::minimal(), tail)
    }
    pub fn locking_script(&self) -> Vec<u8> {
        let mut script = self.guard.to_bytes();
        script.extend(self.tail.locking_script());
        script
    }
    pub fn script_hash(&self) -> [u8; 32] {
        sha256(&self.locking_script())
    }
    pub fn size(&self) -> usize {
        self.guard.size() + self.tail.script_size()
    }
}

#[derive(Clone, Debug)]
pub struct MulletWitness {
    pub proof: Vec<u8>,
    pub ipa_hints: IpaHints,
    pub poseidon_hints: PoseidonHints,
    pub tail_witness: TailWitness,
    pub preimage: SighashPreimage,
    // Galaxy Mode Optional Overrides (Isomorphic Binding)
    pub app_bytes: Option<Vec<u8>>,
    pub change_bytes: Option<Vec<u8>>,
}

impl MulletWitness {
    pub fn size(&self) -> usize {
        self.proof.len() 
            + self.ipa_hints.size()
            + self.poseidon_hints.size()
            + self.tail_witness.size()
            + self.preimage.size()
    }
    pub fn to_script_sig(&self) -> Vec<u8> {
        let mut sig = Vec::new();
        sig.extend(push_bytes(&self.proof)); // [Proof]
        
        // App Bytes (Output 0 for Binding)
        if let Some(app) = &self.app_bytes {
            sig.extend(push_bytes(app));
        } else {
            // Fallback for non-binding scripts
            sig.extend(self.ipa_hints.to_script_pushes());
            sig.extend(self.poseidon_hints.to_script_pushes()); 
            // Warning: If script expects coalesced AppBytes, this fallback fails.
        }

        // Change Bytes (Output 1 for Binding)
        if let Some(change) = &self.change_bytes {
            sig.extend(push_bytes(change));
        } else {
            sig.extend(self.tail_witness.to_script_pushes());
        }

        sig.extend(push_bytes(&self.preimage.to_bytes())); // [Preimage]
        sig
    }
}

#[derive(Clone, Debug)]
pub enum TailWitness {
    Ecdsa {
        signature: Vec<u8>,
        pubkey: Vec<u8>,
    },
    Multisig {
        signatures: Vec<Vec<u8>>,
    },
    Lamport {
        preimages: Vec<[u8; 32]>,
    },
    Custom(Vec<u8>),
}

impl TailWitness {
    pub fn size(&self) -> usize {
        match self {
            TailWitness::Ecdsa { signature, pubkey } => signature.len() + pubkey.len(),
            TailWitness::Multisig { signatures } => signatures.iter().map(|s| s.len()).sum(),
            TailWitness::Lamport { preimages } => preimages.len() * 32,
            TailWitness::Custom(data) => data.len(),
        }
    }
    pub fn to_script_pushes(&self) -> Vec<u8> {
        match self {
            TailWitness::Ecdsa { signature, pubkey } => {
                let mut pushes = push_bytes(signature);
                pushes.extend(push_bytes(pubkey));
                pushes
            }
            TailWitness::Multisig { signatures } => {
                let mut pushes = vec![OP_0];
                for sig in signatures {
                    pushes.extend(push_bytes(sig));
                }
                pushes
            }
            TailWitness::Lamport { preimages } => {
                let mut pushes = Vec::new();
                for preimage in preimages {
                    pushes.extend(push_bytes(preimage));
                }
                pushes
            }
            TailWitness::Custom(data) => push_bytes(data),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SighashPreimage {
    pub version: [u8; 4],
    pub hash_prevouts: [u8; 32],
    pub hash_sequence: [u8; 32],
    pub outpoint: [u8; 36],
    pub script_code: Vec<u8>,
    pub value: [u8; 8],
    pub sequence: [u8; 4],
    pub hash_outputs: [u8; 32],
    pub locktime: [u8; 4],
    pub sighash_type: [u8; 4],
}

impl SighashPreimage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(&self.version);
        bytes.extend(&self.hash_prevouts);
        bytes.extend(&self.hash_sequence);
        bytes.extend(&self.outpoint);
        bytes.extend(varint(self.script_code.len()));
        bytes.extend(&self.script_code);
        bytes.extend(&self.value);
        bytes.extend(&self.sequence);
        bytes.extend(&self.hash_outputs);
        bytes.extend(&self.locktime);
        bytes.extend(&self.sighash_type);
        bytes
    }
    pub fn size(&self) -> usize {
        4 + 32 + 32 + 36 + self.script_code.len() + 8 + 4 + 32 + 4 + 4 + 3
    }
}

pub fn push_bytes(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    if data.is_empty() {
        result.push(OP_0);
    } else if data.len() <= 75 {
        result.push(data.len() as u8);
        result.extend(data);
    } else if data.len() <= 255 {
        result.push(OP_PUSHDATA1);
        result.push(data.len() as u8);
        result.extend(data);
    } else if data.len() <= 65535 {
        result.push(OP_PUSHDATA2);
        result.extend(&(data.len() as u16).to_le_bytes());
        result.extend(data);
    } else {
        result.push(OP_PUSHDATA4);
        result.extend(&(data.len() as u32).to_le_bytes());
        result.extend(data);
    }
    result
}

pub fn varint(n: usize) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffffffff {
        let mut v = vec![0xfe];
        v.extend(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend(&(n as u64).to_le_bytes());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_push_bytes_small() {
        let data = vec![0x01, 0x02, 0x03];
        let pushed = push_bytes(&data);
        assert_eq!(pushed[0], 3);
        assert_eq!(&pushed[1..], &data);
    }
    #[test]
    fn test_push_bytes_empty() {
        let pushed = push_bytes(&[]);
        assert_eq!(pushed, vec![OP_0]);
    }
    #[test]
    fn test_varint() {
        assert_eq!(varint(0), vec![0]);
        assert_eq!(varint(252), vec![252]);
        assert_eq!(varint(253), vec![0xfd, 253, 0]);
    }
    #[test]
    fn test_mullet_script() {
        let guard = Guard::minimal();
        let tail = EcdsaTail::from_pubkey_hash(&[0u8; 20]);
        let mullet = MulletScript::new(guard, tail);
        assert!(mullet.size() > 0);
        assert_eq!(mullet.script_hash().len(), 32);
    }
}
