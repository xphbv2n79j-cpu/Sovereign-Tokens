use crate::ghost::crypto::{Fp, FieldExt};
use super::{push_bytes};
#[derive(Clone, Debug)]
pub struct IpaHints {
    pub rounds: Vec<FoldingRound>,
    pub final_scalar: Fp,
    pub final_commitment: [u8; 33],
}

impl IpaHints {
    pub fn new(rounds: Vec<FoldingRound>, final_scalar: Fp, final_commitment: [u8; 33]) -> Self {
        Self {
            rounds,
            final_scalar,
            final_commitment,
        }
    }
    pub fn num_rounds(&self) -> usize {
        self.rounds.len()
    }
    pub fn size(&self) -> usize {
        self.rounds.len() * 131 + 65
    }
    pub fn to_script_pushes(&self) -> Vec<u8> {
        let mut pushes = Vec::new();
        for round in self.rounds.iter().rev() {
            pushes.extend(round.to_script_pushes());
        }
        pushes.extend(push_bytes(&self.final_scalar.to_bytes()));
        pushes.extend(push_bytes(&self.final_commitment));
        pushes
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size());
        for round in &self.rounds {
            bytes.extend(&round.l_u);
            bytes.extend(&round.r_u_inv);
            bytes.extend(&round.c_next);
            bytes.extend(&round.challenge.to_bytes());
        }
        bytes.extend(&self.final_scalar.to_bytes());
        bytes.extend(&self.final_commitment);
        bytes
    }
    pub fn placeholder(k: u32) -> Self {
        let rounds = (0..k).map(|_| FoldingRound::placeholder()).collect();
        Self {
            rounds,
            final_scalar: Fp::from_u64(1),
            final_commitment: [0u8; 33],
        }
    }
}

#[derive(Clone, Debug)]
pub struct FoldingRound {
    pub l_u: [u8; 33],
    pub r_u_inv: [u8; 33],
    pub c_next: [u8; 33],
    pub challenge: Fp,
}

impl FoldingRound {
    pub fn new(l_u: [u8; 33], r_u_inv: [u8; 33], c_next: [u8; 33], challenge: Fp) -> Self {
        Self { l_u, r_u_inv, c_next, challenge }
    }
    pub fn size(&self) -> usize {
        33 + 33 + 33 + 32
    }
    pub fn to_script_pushes(&self) -> Vec<u8> {
        let mut pushes = Vec::new();
        pushes.extend(push_bytes(&self.l_u));
        pushes.extend(push_bytes(&self.r_u_inv));
        pushes.extend(push_bytes(&self.c_next));
        pushes.extend(push_bytes(&self.challenge.to_bytes()));
        pushes
    }
    pub fn placeholder() -> Self {
        Self {
            l_u: [0u8; 33],
            r_u_inv: [0u8; 33],
            c_next: [0u8; 33],
            challenge: Fp::from_u64(1),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PoseidonHints {
    pub round_states: Vec<PoseidonRoundHint>,
    pub output: Fp,
}

impl PoseidonHints {
    pub fn new(round_states: Vec<PoseidonRoundHint>, output: Fp) -> Self {
        Self { round_states, output }
    }
    pub fn size(&self) -> usize {
        self.round_states.len() * 192 + 32
    }
    pub fn to_script_pushes(&self) -> Vec<u8> {
        let mut pushes = Vec::new();
        for round in &self.round_states {
            pushes.extend(round.to_script_pushes());
        }
        pushes.extend(push_bytes(&self.output.to_bytes()));
        pushes
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size());
        for round in &self.round_states {
            for elem in &round.after_sbox {
                bytes.extend(&elem.to_bytes());
            }
            for elem in &round.after_mds {
                bytes.extend(&elem.to_bytes());
            }
        }
        bytes.extend(&self.output.to_bytes());
        bytes
    }
    pub fn placeholder(num_rounds: usize) -> Self {
        let round_states = (0..num_rounds)
            .map(|_| PoseidonRoundHint::placeholder())
            .collect();
        Self {
            round_states,
            output: Fp::zero(),
        }
    }
    pub fn with_output(mut self, output: Fp) -> Self {
        self.output = output;
        self
    }
}

#[derive(Clone, Debug)]
pub struct PoseidonRoundHint {
    pub after_sbox: [Fp; 3],
    pub after_mds: [Fp; 3],
}

impl PoseidonRoundHint {
    pub fn new(after_sbox: [Fp; 3], after_mds: [Fp; 3]) -> Self {
        Self { after_sbox, after_mds }
    }
    pub fn size(&self) -> usize {
        6 * 32
    }
    pub fn to_script_pushes(&self) -> Vec<u8> {
        let mut pushes = Vec::new();
        for elem in &self.after_sbox {
            pushes.extend(push_bytes(&elem.to_bytes()));
        }
        for elem in &self.after_mds {
            pushes.extend(push_bytes(&elem.to_bytes()));
        }
        pushes
    }
    pub fn placeholder() -> Self {
        Self {
            after_sbox: [Fp::zero(); 3],
            after_mds: [Fp::zero(); 3],
        }
    }
}

pub fn generate_ipa_hints(
    _proof_bytes: &[u8],
    _public_inputs: &[Fp],
    k: u32,
) -> IpaHints {
    IpaHints::placeholder(k)
}

pub fn generate_poseidon_hints(
    _asset_id: u64,
    _amount: u64,
    _nonce: u64,
    _recipient: Fp,
    _payload: Fp,
) -> PoseidonHints {
    PoseidonHints::placeholder(64)
}

pub fn ipa_verify_script(_num_rounds: usize) -> Vec<u8> {
    let mut script = Vec::new();
    script.push(super::OP_TRUE);
    script
}

pub fn poseidon_verify_script() -> Vec<u8> {
    let mut script = Vec::new();
    script.push(super::OP_TRUE);
    script
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ipa_hints_size() {
        let hints = IpaHints::placeholder(10);
        assert_eq!(hints.size(), 1375);
        assert_eq!(hints.num_rounds(), 10);
    }
    #[test]
    fn test_folding_round_size() {
        let round = FoldingRound::placeholder();
        assert_eq!(round.size(), 131);
    }
    #[test]
    fn test_poseidon_hints_size() {
        let hints = PoseidonHints::placeholder(64);
        assert_eq!(hints.size(), 64 * 192 + 32);
    }
    #[test]
    fn test_ipa_hints_serialization() {
        let hints = IpaHints::placeholder(10);
        let pushes = hints.to_script_pushes();
        assert!(!pushes.is_empty());
    }
}

