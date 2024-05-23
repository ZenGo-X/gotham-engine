use rocket::serde::{Deserialize, Serialize};
use two_party_ecdsa::{BigInt, typetag_value, typetags::Value};
use crate::common::MPCStruct;

pub mod routes;

pub mod keygen;
pub mod sign;
pub mod rotate;
pub mod derive;


/// An enumeration which keeps track of the different table names used to store information during KeyGen and Sign
#[derive(Debug)]
pub enum EcdsaStruct {
    KeyGenFirstMsg,
    CommWitness,
    EcKeyPair,
    PaillierKeyPair,
    Party1Private,
    Party2Public,

    PDLProver,
    PDLDecommit,
    Alpha,
    Party2PDLFirstMsg,

    CCKeyGenFirstMsg,
    CCCommWitness,
    CCEcKeyPair,
    CC,

    Party1MasterKey,

    EphEcKeyPair,
    EphKeyGenFirstMsg,

    RotateCommitMessage1,
    RotateRandom1,
    RotateFirstMsg,
    RotatePrivateNew,
    RotatePdlDecom,
    RotateParty2First,
    RotateParty1Second,
    RotateAlpha,

    POS,
    Abort,
}

/// Wrapper struct for alpha values. They implement the Value trait in order to serialize/deserialize trait objects. Generics was not an option
/// since they are used inside KeyGen and Sign traits which are treated as trait objects
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Alpha {
    pub value: BigInt,
}

typetag_value!(Alpha);

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Abort {
    pub(crate) blocked: bool,
}

typetag_value!(Abort);

///common functions for the members of EcdsaStruct struct to strigify and format
impl MPCStruct for EcdsaStruct {
    fn to_string(&self) -> String {
        format!("{:?}", self)
    }

    // backward compatibility
    fn to_table_name(&self, env: &str) -> String {
        if self.to_string() == "Party1MasterKey" {
            format!("{}_{}", env, self.to_string())
        } else {
            format!("{}-gotham-{}", env, self.to_string())
        }
    }

    fn to_struct_name(&self) -> String {
        let res = match self {
            EcdsaStruct::KeyGenFirstMsg => "Party1KeyGenFirstMessage",
            EcdsaStruct::CommWitness => "Party1CommWitness",
            EcdsaStruct::EcKeyPair => "Party1EcKeyPair",
            EcdsaStruct::PaillierKeyPair => "Party1PaillierKeyPair",
            EcdsaStruct::Party1Private => "Party1Private",
            EcdsaStruct::Party2Public => "Secp256k1Point",
            EcdsaStruct::PDLProver => "PDLProver",
            EcdsaStruct::PDLDecommit => "Party1PDLDecommit",
            EcdsaStruct::Alpha => "Alpha",
            EcdsaStruct::Party2PDLFirstMsg => "Party2PDLFirstMessage",
            EcdsaStruct::CCKeyGenFirstMsg => "DHPoKParty1FirstMessage",
            EcdsaStruct::CCCommWitness => "DHPoKCommWitness",
            EcdsaStruct::CCEcKeyPair => "DHPoKEcKeyPair",
            EcdsaStruct::CC => "ChainCode1",
            EcdsaStruct::Party1MasterKey => "MasterKey1",
            EcdsaStruct::EphEcKeyPair => "Party1EphEcKeyPair",
            EcdsaStruct::EphKeyGenFirstMsg => "Party2EphKeyGenFirstMessage",
            EcdsaStruct::POS => "Party1HDPos",
            EcdsaStruct::Abort => "Abort",

            EcdsaStruct::RotateCommitMessage1 => "RotateCommitMessage1",
            EcdsaStruct::RotateRandom1 => "Rotation",
            EcdsaStruct::RotateFirstMsg => "RotationParty1Message1",
            EcdsaStruct::RotatePrivateNew => "Party1Private",
            EcdsaStruct::RotatePdlDecom => "Party1PDLDecommit",
            EcdsaStruct::RotateParty2First => "Party2PDLFirstMessage",
            EcdsaStruct::RotateParty1Second => "Party1PDLFirstMessage",
            EcdsaStruct::RotateAlpha => "RotateAlpha",
        };

        res.to_string()
    }
}

#[inline(always)]
pub fn idify(user_id: &String, id: &String, name: &dyn MPCStruct) -> String {
    format!("{}_{}_{}", user_id, id, name.to_string())
}