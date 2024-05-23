pub mod server;

use std::string::ToString;
use strum_macros::Display;

#[derive(Display, Debug)]
pub enum MuSig2Struct {
    #[strum(serialize = "redred")]
    Red,
}