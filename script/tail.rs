use super::opcodes::*;
use crate::ghost::crypto::hash160;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TailType {
    Ecdsa,
    Multisig,
    Lamport,
    Custom,
}

pub trait Tail: Send + Sync + std::fmt::Debug + TailClone {
    fn locking_script(&self) -> Vec<u8>;
    fn tail_type(&self) -> TailType;
    fn script_size(&self) -> usize {
        self.locking_script().len()
    }
}

pub trait TailClone {
    fn clone_box(&self) -> Box<dyn Tail>;
}

impl<T: Tail + Clone + 'static> TailClone for T {
    fn clone_box(&self) -> Box<dyn Tail> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn Tail> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[derive(Clone, Debug)]
pub struct EcdsaTail {
    pub pubkey_hash: [u8; 20],
}

impl EcdsaTail {
    pub fn from_pubkey_hash(hash: &[u8; 20]) -> Self {
        Self { pubkey_hash: *hash }
    }
    pub fn from_pubkey(pubkey: &[u8; 33]) -> Self {
        Self {
            pubkey_hash: hash160(pubkey),
        }
    }
}

impl Tail for EcdsaTail {
    fn locking_script(&self) -> Vec<u8> {
        let mut script = Vec::with_capacity(25);
        script.push(OP_DUP);
        script.push(OP_HASH160);
        script.push(20);
        script.extend(&self.pubkey_hash);
        script.push(OP_EQUALVERIFY);
        script.push(OP_CHECKSIG);
        script
    }
    fn tail_type(&self) -> TailType {
        TailType::Ecdsa
    }
}

#[derive(Clone, Debug)]
pub struct MultisigTail {
    pub threshold: u8,
    pub pubkeys: Vec<[u8; 33]>,
}

impl MultisigTail {
    pub fn new(threshold: u8, pubkeys: Vec<[u8; 33]>) -> Self {
        // SECURITY FIX (Audit): Enforce bounds for opcode arithmetic
        assert!(threshold >= 1 && threshold <= 16, "Multisig Threshold must be 1-16");
        assert!(pubkeys.len() >= 1 && pubkeys.len() <= 16, "Multisig Keys must be 1-16");
        assert!(threshold <= pubkeys.len() as u8, "Threshold cannot exceed key count");
        
        Self { threshold, pubkeys }
    }
    pub fn two_of_three(pk1: [u8; 33], pk2: [u8; 33], pk3: [u8; 33]) -> Self {
        Self::new(2, vec![pk1, pk2, pk3])
    }
}

impl Tail for MultisigTail {
    fn locking_script(&self) -> Vec<u8> {
        let mut script = Vec::new();
        // Safe op arithmetic due to assertions in new()
        script.push(OP_1 + self.threshold - 1); 
        for pk in &self.pubkeys {
            script.push(33);
            script.extend(pk);
        }
        script.push(OP_1 + (self.pubkeys.len() as u8) - 1);
        script.push(OP_CHECKMULTISIG);
        script
    }
    fn tail_type(&self) -> TailType {
        TailType::Multisig
    }
}

#[derive(Clone, Debug)]
pub struct LamportTail {
    pub pubkey_hashes: Vec<([u8; 32], [u8; 32])>,
}

impl LamportTail {
    pub fn from_public_key(pubkey: &crate::ghost::crypto::LamportPublicKey) -> Self {
        Self {
            pubkey_hashes: pubkey.hashes.clone(),
        }
    }
    pub fn new(pubkey_hashes: Vec<([u8; 32], [u8; 32])>) -> Self {
        Self { pubkey_hashes }
    }
    pub fn placeholder() -> Self {
        Self {
            pubkey_hashes: vec![([0u8; 32], [0u8; 32]); 256],
        }
    }
    pub fn pubkey_hash(&self) -> [u8; 32] {
        use crate::ghost::crypto::sha256;
        let mut data = Vec::with_capacity(256 * 64);
        for (h0, h1) in &self.pubkey_hashes {
            data.extend(h0);
            data.extend(h1);
        }
        sha256(&data)
    }
}

impl Tail for LamportTail {
    fn locking_script(&self) -> Vec<u8> {
        // SECURITY CRITICAL (Audit):
        // The previous implementation was vulnerable to Signature Replay because it checked
        // Preimage == H0 OR Preimage == H1 without binding the choice to the message bits.
        // True Lamport requires inspecting the Sighash bits (Introspection) which is
        // complex/unavailable in this context. Use OP_RETURN to prevent usage.
        
        let mut script = Vec::new();
        script.push(0x6a); // OP_RETURN
        let msg = b"LAMPORT DISABLED: UNSAFE";
        script.push(msg.len() as u8);
        script.extend(msg);
        script
    }
    fn tail_type(&self) -> TailType {
        TailType::Lamport
    }
    fn script_size(&self) -> usize {
        26 // size of disabled script
    }
}

#[derive(Clone, Debug)]
pub struct CustomTail {
    script: Vec<u8>,
}

impl CustomTail {
    pub fn new(script: Vec<u8>) -> Self {
        Self { script }
    }
}

impl Tail for CustomTail {
    fn locking_script(&self) -> Vec<u8> {
        self.script.clone()
    }
    fn tail_type(&self) -> TailType {
        TailType::Custom
    }
}

#[derive(Clone, Debug)]
pub struct SponsorTail {
    pub sponsor_pubkey_hash: [u8; 20],
}

impl SponsorTail {
    pub fn from_pubkey_hash(hash: &[u8; 20]) -> Self {
        Self { sponsor_pubkey_hash: *hash }
    }
    pub fn from_pubkey(pubkey: &[u8]) -> Self {
        let hash = hash160(pubkey);
        Self { sponsor_pubkey_hash: hash }
    }
}

impl Tail for SponsorTail {
    fn locking_script(&self) -> Vec<u8> {
        let mut script = Vec::new();
        script.push(OP_DUP);
        script.push(OP_HASH160);
        script.push(20);
        script.extend(&self.sponsor_pubkey_hash);
        script.push(OP_EQUALVERIFY);
        script.push(OP_CHECKSIG);
        script
    }
    fn tail_type(&self) -> TailType {
        TailType::Custom
    }
}

#[derive(Clone, Debug)]
pub struct DualAuthTail {
    pub user_pubkey_hash: [u8; 20],
    pub sponsor_pubkey_hash: [u8; 20],
}

impl DualAuthTail {
    pub fn new(user_hash: [u8; 20], sponsor_hash: [u8; 20]) -> Self {
        Self {
            user_pubkey_hash: user_hash,
            sponsor_pubkey_hash: sponsor_hash,
        }
    }
    pub fn from_pubkeys(user_pubkey: &[u8], sponsor_pubkey: &[u8]) -> Self {
        Self {
            user_pubkey_hash: hash160(user_pubkey),
            sponsor_pubkey_hash: hash160(sponsor_pubkey),
        }
    }
}

impl Tail for DualAuthTail {
    fn locking_script(&self) -> Vec<u8> {
        let mut script = Vec::new();
        script.push(OP_DUP);
        script.push(OP_HASH160);
        script.push(20);
        script.extend(&self.sponsor_pubkey_hash);
        script.push(OP_EQUALVERIFY);
        script.push(OP_CHECKSIGVERIFY);
        script.push(OP_DUP);
        script.push(OP_HASH160);
        script.push(20);
        script.extend(&self.user_pubkey_hash);
        script.push(OP_EQUALVERIFY);
        script.push(OP_CHECKSIG);
        script
    }
    fn tail_type(&self) -> TailType {
        TailType::Custom
    }
}

#[derive(Clone, Debug)]
pub struct AnyoneCanSpendTail;
impl Tail for AnyoneCanSpendTail {
    fn locking_script(&self) -> Vec<u8> {
        vec![OP_TRUE]
    }
    fn tail_type(&self) -> TailType {
        TailType::Custom
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ecdsa_tail() {
        let tail = EcdsaTail::from_pubkey_hash(&[0u8; 20]);
        let script = tail.locking_script();
        assert_eq!(script.len(), 25);
        assert_eq!(script[0], OP_DUP);
        assert_eq!(script[1], OP_HASH160);
        assert_eq!(script[2], 20);
        assert_eq!(script[23], OP_EQUALVERIFY);
        assert_eq!(script[24], OP_CHECKSIG);
    }
    #[test]
    fn test_multisig_tail() {
        // Test Valid
        let pk1 = [0x02u8; 33];
        let pk2 = [0x03u8; 33];
        let pk3 = [0x04u8; 33];
        let tail = MultisigTail::two_of_three(pk1, pk2, pk3);
        let script = tail.locking_script();
        assert!(script.len() > 100);
        assert_eq!(script[0], OP_2);
    }
    #[test]
    #[should_panic(expected = "Multisig Threshold must be 1-16")]
    fn test_multisig_bounds_invalid_threshold() {
        MultisigTail::new(17, vec![[0u8; 33]; 17]);
    }
     #[test]
    fn test_lamport_tail_disabled() {
        let tail = LamportTail::placeholder();
        let script = tail.locking_script();
        assert_eq!(script[0], 0x6a); // OP_RETURN
    }
    #[test]
    fn test_custom_tail() {
        let custom_script = vec![OP_TRUE];
        let tail = CustomTail::new(custom_script.clone());
        assert_eq!(tail.locking_script(), custom_script);
        assert_eq!(tail.tail_type(), TailType::Custom);
    }
}
