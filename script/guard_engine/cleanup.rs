// Stack cleanup after verification [P.3]
use crate::ghost::script::{
    OP_DROP, OP_2DROP,
    OP_TOALTSTACK, OP_FROMALTSTACK,
    OP_SHA256,
}
;
pub struct StackCleanup {
    drop_count: usize,
    preserve_tail: bool,
    preserve_message: bool,
}

impl StackCleanup {
    pub fn new(drop_count: usize) -> Self {
        Self {
            drop_count,
            preserve_tail: true,
            preserve_message: false,
        }
    }
    pub fn preserve_tail(mut self, preserve: bool) -> Self {
        self.preserve_tail = preserve;
        self
    }
    pub fn preserve_message(mut self, preserve: bool) -> Self {
        self.preserve_message = preserve;
        self
    }
    pub fn build(&self) -> Vec<u8> {
        let mut script = Vec::new();
        if self.preserve_tail {
            script.push(OP_TOALTSTACK);
        }
        if self.preserve_message {
            script.push(OP_SHA256);
            script.push(OP_TOALTSTACK);
        }
        let items_to_drop = if self.preserve_tail { self.drop_count } else { self.drop_count + 1 };
        let items_to_drop = if self.preserve_message { items_to_drop - 1 } else { items_to_drop };
        let two_drops = items_to_drop / 2;
        let single_drops = items_to_drop % 2;
        for _ in 0..two_drops {
            script.push(OP_2DROP);
        }
        for _ in 0..single_drops {
            script.push(OP_DROP);
        }
        if self.preserve_message {
            script.push(OP_FROMALTSTACK);
        }
        if self.preserve_tail {
            script.push(OP_FROMALTSTACK);
        }
        script
    }
    pub fn remaining_count(&self) -> usize {
        let mut count = 0;
        if self.preserve_tail { count += 1; }
        if self.preserve_message { count += 1; }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_cleanup_basic() {
        let cleanup = StackCleanup::new(5)
            .preserve_tail(true)
            .preserve_message(false);
        let script = cleanup.build();
        assert!(script.contains(&OP_TOALTSTACK));
        assert!(script.contains(&OP_FROMALTSTACK));
    }
    #[test]
    fn test_cleanup_with_message() {
        let cleanup = StackCleanup::new(5)
            .preserve_tail(true)
            .preserve_message(true);
        let script = cleanup.build();
        assert!(script.contains(&OP_SHA256));
    }
    #[test]
    fn test_remaining_count() {
        let cleanup1 = StackCleanup::new(5)
            .preserve_tail(true)
            .preserve_message(false);
        assert_eq!(cleanup1.remaining_count(), 1);
        let cleanup2 = StackCleanup::new(5)
            .preserve_tail(true)
            .preserve_message(true);
        assert_eq!(cleanup2.remaining_count(), 2);
    }
    #[test]
    fn test_uses_2drop() {
        let cleanup = StackCleanup::new(6)
            .preserve_tail(true)
            .preserve_message(false);
        let script = cleanup.build();
        assert!(script.contains(&OP_2DROP));
    }
}

