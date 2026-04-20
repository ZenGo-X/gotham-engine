// src/
// ├── router/
// │     ├── mod.rs                      // Re-export endpoints (e.g., pub use self::recovery::*;)
// │     └── routes_recovery.rs   // Contains wrap_recovery_eddsa
// ├── recovery/
// │     ├── mod.rs                      // Contains the main module for recovery, re-exports router
// │     └── recovery.rs
// │     └── tests/
// │         └── recovery_tests.rs       // Contains tests for recovery functionality
// ├── mod.rs                          // Contains the main module for the crate, re-exports other modules
// ├── lib.rs or main.rs

pub mod routes_recovery;
pub use routes_recovery::*;