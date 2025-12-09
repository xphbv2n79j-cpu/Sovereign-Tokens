// Stack: [Proof...TailSig] → [TailSig] [P.1-3]
mod universal;
mod verify_public;
mod verify_binding;
mod cleanup;
pub use universal::{UniversalGuard, GuardConfig};
pub use verify_public::VerifyPublicData;
pub use verify_binding::VerifyBinding;
pub use cleanup::StackCleanup;
