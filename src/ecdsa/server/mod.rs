use rocket::serde::{Deserialize, Serialize};
use strum_macros::Display;
use two_party_ecdsa::{BigInt, Secp256k1Point};
use two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::{DHPoKCommWitness, DHPoKEcKeyPair, DHPoKParty1FirstMessage};
use two_party_ecdsa::kms::chain_code::two_party::party1::ChainCode1;
use two_party_ecdsa::kms::ecdsa::two_party::MasterKey1;
use two_party_ecdsa::kms::rotation::two_party::party1::{RotateCommitMessage1, RotationParty1Message1};
use two_party_ecdsa::kms::rotation::two_party::Rotation;
use two_party_ecdsa::party_one::{Party1CommWitness, Party1EcKeyPair, Party1EphEcKeyPair, Party1HDPos, Party1KeyGenFirstMessage, Party1PaillierKeyPair, Party1PDLDecommit, Party1PDLFirstMessage, Party1Private};
use two_party_ecdsa::party_two::{Party2EphKeyGenFirstMessage, Party2PDLFirstMessage};
use crate::common::MPCStruct;
use crate::typetag_value;

pub mod routes;

pub mod keygen;
pub mod sign;
pub mod rotate;
pub mod derive;


/// An enumeration which keeps track of the different table names used to store information during KeyGen and Sign
#[derive(Display)]
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


#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Abort {
    pub(crate) blocked: bool,
}


///common functions for the members of EcdsaStruct struct to strigify and format
impl MPCStruct for EcdsaStruct {
    fn get_name(&self) -> String {
        self.to_string()
    }

    // backward compatibility
    fn get_table_name(&self, env: &str) -> String {
        if self.get_name() == EcdsaStruct::Party1MasterKey.get_name() {
            format!("{}_{}", env, self.get_name())
        } else {
            format!("{}-gotham-{}", env, self.get_name())
        }
    }

    fn get_struct_name(&self) -> String {
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
    format!("{}_{}_{}", user_id, id, name.get_name())
}

typetag_value!(Abort);
typetag_value!(Party1HDPos);
typetag_value!(Party1KeyGenFirstMessage);
typetag_value!(Party1CommWitness);
typetag_value!(Party1EcKeyPair);
typetag_value!(Secp256k1Point);
typetag_value!(Party1PaillierKeyPair);
typetag_value!(Party1Private);
typetag_value!(Party1PDLDecommit);
typetag_value!(Alpha);
typetag_value!(Party2PDLFirstMessage);
typetag_value!(DHPoKParty1FirstMessage);
typetag_value!(DHPoKCommWitness);
typetag_value!(DHPoKEcKeyPair);
typetag_value!(ChainCode1);
typetag_value!(MasterKey1);
typetag_value!(Party2EphKeyGenFirstMessage);
typetag_value!(Party1EphEcKeyPair);
typetag_value!(RotateCommitMessage1);
typetag_value!(Rotation);
typetag_value!(RotationParty1Message1);
typetag_value!(Party1PDLFirstMessage);











