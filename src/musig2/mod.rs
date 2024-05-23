pub mod server;

use std::string::ToString;
use strum_macros::Display;

use crate::common::MPCStruct;


#[derive(Display)]
pub enum MuSig2Struct {
    KeyPair,
}


impl MPCStruct for MuSig2Struct {
    fn get_name(&self) -> String {
        self.to_string()
    }

    fn get_table_name(&self, env: &str) -> String {
        return format!("{}-gotham-musig2-{}", env, self.get_name())
    }

    fn get_struct_name(&self) -> String {
        let res = match self {
            MuSig2Struct::KeyPair => "KeyPair",
        };

        res.to_string()
    }
}