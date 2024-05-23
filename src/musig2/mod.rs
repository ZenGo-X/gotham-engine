pub mod server;

use std::string::ToString;
use strum_macros::Display;

use crate::common::MPCStruct;


#[derive(Display)]
pub enum MuSig2Struct {
    Red,
}


impl MPCStruct for MuSig2Struct {
    fn get_name(&self) -> String {
        self.to_string()
    }

    fn to_table_name(&self, env: &str) -> String {
        return format!("{}-gotham-{}", env, self.get_name())
    }

    fn to_struct_name(&self) -> String {
        let res = match self {
            MuSig2Struct::Red => "Red",
        };

        res.to_string()
    }
}