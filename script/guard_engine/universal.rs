use super::verify_public::VerifyPublicData;
use super::verify_binding::VerifyBinding;
use super::cleanup::StackCleanup;
use crate::ghost::binding::BindingMode;
use crate::ghost::script::{IpaHints, PoseidonHints};
use crate::ghost::{Error, Result};
#[derive(Clone, Debug)]
pub struct GuardConfig {
    pub num_inputs: usize,
    pub num_app_outputs: usize,
    pub binding_mode: BindingMode,
    pub preserve_message_hash: bool,
    pub ipa_hints: Option<IpaHints>,
    pub poseidon_hints: Option<PoseidonHints>,
}

impl GuardConfig {
    pub fn new(num_inputs: usize, num_app_outputs: usize) -> Self {
        Self {
            num_inputs,
            num_app_outputs,
            binding_mode: BindingMode::Strict,
            preserve_message_hash: true,
            ipa_hints: None,
            poseidon_hints: None,
        }
    }
    pub fn strict(mut self) -> Self {
        self.binding_mode = BindingMode::Strict;
        self
    }
    pub fn paymaster(mut self, _max_sponsor_fee: u64) -> Self {
        self.binding_mode = BindingMode::Partial;
        self
    }
    pub fn preserve_message(mut self, preserve: bool) -> Self {
        self.preserve_message_hash = preserve;
        self
    }
    pub fn with_ipa_hints(mut self, hints: IpaHints) -> Self {
        self.ipa_hints = Some(hints);
        self
    }
    pub fn with_poseidon_hints(mut self, hints: PoseidonHints) -> Self {
        self.poseidon_hints = Some(hints);
        self
    }
    pub fn expected_stack_size(&self) -> usize {
        1 + (self.num_inputs * 3) + (self.num_app_outputs * 3) + 3
    }
    pub fn items_to_drop(&self) -> usize {
        self.expected_stack_size() - 1 - if self.preserve_message_hash { 1 } else { 0 }
    }
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self::new(1, 1)
    }
}

pub struct UniversalGuard {
    config: GuardConfig,
}

impl UniversalGuard {
    pub fn new(config: GuardConfig) -> Self {
        Self { config }
    }
    pub fn default_config(num_inputs: usize, num_app_outputs: usize) -> Self {
        Self::new(GuardConfig::new(num_inputs, num_app_outputs))
    }
    pub fn strict(num_inputs: usize, num_app_outputs: usize) -> Self {
        Self::new(GuardConfig::new(num_inputs, num_app_outputs).strict())
    }
    pub fn paymaster(num_inputs: usize, num_app_outputs: usize, max_fee: u64) -> Self {
        Self::new(GuardConfig::new(num_inputs, num_app_outputs).paymaster(max_fee))
    }
    pub fn build(&self) -> Vec<u8> {
        let mut script = Vec::new();
        let verify_public = VerifyPublicData::new(
            self.config.num_inputs,
            self.config.num_app_outputs,
        );
        script.extend(verify_public.build());
        let verify_binding = VerifyBinding::new(
            self.config.num_app_outputs,
            self.config.binding_mode,
        );
        script.extend(verify_binding.build());
        let cleanup = StackCleanup::new(self.config.items_to_drop())
            .preserve_tail(true)
            .preserve_message(self.config.preserve_message_hash);
        script.extend(cleanup.build());
        script
    }
    pub fn build_verification(&self) -> Vec<u8> {
        let mut script = Vec::new();
        let verify_public = VerifyPublicData::new(
            self.config.num_inputs,
            self.config.num_app_outputs,
        );
        script.extend(verify_public.build());
        let verify_binding = VerifyBinding::new(
            self.config.num_app_outputs,
            self.config.binding_mode,
        );
        script.extend(verify_binding.build());
        script
    }
    pub fn config(&self) -> &GuardConfig {
        &self.config
    }
    pub fn size_estimate(&self) -> usize {
        let verify_public_size = 500 + (self.config.num_inputs + self.config.num_app_outputs) * 50;
        let verify_binding_size = 200;
        let cleanup_size = 50;
        let ipa_hints_size = self.config.ipa_hints
            .as_ref()
            .map(|h| h.size())
            .unwrap_or(2000);
        verify_public_size + verify_binding_size + cleanup_size + ipa_hints_size
    }
    pub fn validate(&self) -> Result<()> {
        if self.config.num_inputs == 0 {
            return Err(Error::InvalidInput("At least one input required".to_string()));
        }
        if self.config.num_inputs > 16 {
            return Err(Error::InvalidInput("Too many inputs (max 16)".to_string()));
        }
        if self.config.num_app_outputs > 16 {
            return Err(Error::InvalidInput("Too many outputs (max 16)".to_string()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_guard_config_default() {
        let config = GuardConfig::default();
        assert_eq!(config.num_inputs, 1);
        assert_eq!(config.num_app_outputs, 1);
    }
    #[test]
    fn test_guard_config_paymaster() {
        let config = GuardConfig::new(2, 3).paymaster(1000);
        assert!(matches!(config.binding_mode, BindingMode::Partial));
    }
    #[test]
    fn test_guard_expected_stack_size() {
        let config = GuardConfig::new(1, 1);
        assert_eq!(config.expected_stack_size(), 10);
    }
    #[test]
    fn test_universal_guard_build() {
        let guard = UniversalGuard::strict(1, 1);
        let script = guard.build();
        assert!(!script.is_empty());
    }
    #[test]
    fn test_universal_guard_validate() {
        let guard = UniversalGuard::strict(1, 1);
        assert!(guard.validate().is_ok());
        let guard = UniversalGuard::strict(0, 1);
        assert!(guard.validate().is_err());
    }
    #[test]
    fn test_guard_size_estimate() {
        let guard = UniversalGuard::strict(1, 1);
        let size = guard.size_estimate();
        assert!(size > 0);
        assert!(size < 10000);
    }
}

