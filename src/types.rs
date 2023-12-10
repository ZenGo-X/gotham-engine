//! Common types for traits the implementations thereofs at [private_gotham] and [public_gotham]
use crate::traits::MPCStruct;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fmt::{Display, Formatter};
use thiserror::Error;
use two_party_ecdsa::kms::ecdsa::two_party::party2;
use two_party_ecdsa::party_one::Value;
use two_party_ecdsa::BigInt;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
/// The DatabaseError defines different types of database errors for better error handling
pub enum DatabaseError {
    /// Failed to open database.
    #[error("Failed to open database: {0:?}")]
    ConnectionError(i32),
    /// Failed to create a table in database.
    #[error("Table Creating error code: {0:?}")]
    TableCreationError(i32),
    /// Failed to insert a value into a table.
    #[error("Database write error code: {0:?}")]
    InsertError(i32),
    /// Failed to get a value into a table.
    #[error("Database read error code: {0:?}")]
    ReadError(i32),
    /// Failed to delete a `(key, value)` pair into a table.
    #[error("Database delete error code: {0:?}")]
    DeleteError(i32),
    /// Failed to delete a `(key, value)` pair into a table.
    #[error("Database delete error code: {0:?}")]
    ConfigError(i32),
}

/// The DbConnector indicates what type of DB will be used for storing the state during the Keyge, and sign interactive protocols
pub enum DbConnector {
    RocksDB,
    DynamoDB,
    Redis,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
/// It is used as an index for the underlying Db table
pub struct DbIndex {
    ///The customerId as assigned from cognito and passed through JWT
    pub customerId: String,
    ///The is as assigned from gotham server during the first round of keygen to identify users
    pub id: String,
}

/// The Authenticator indicates how the input requests to gotham server will be authorized. Currently there is the JWT option
/// but in the future it will be discarded. Private gotham is using a jwt auth while public one does not use it
pub enum Authenticator {
    /// passthrough mode to authentication at http level
    None,
    /// verification with a valid JWT
    Jwt,
}

pub const CUSTOMER_ID_IDENTIFIER: &str = "customerId";
pub const ID_IDENTIFIER: &str = "id";

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

    POS,
    Abort,
}

impl EcdsaStruct {
    fn to_struct_name(&self) -> String {
        let res = match self {
            EcdsaStruct::KeyGenFirstMsg => "KeyGenFirstMsg",
            EcdsaStruct::CommWitness => "CommWitness",
            EcdsaStruct::EcKeyPair => "EcKeyPair",
            EcdsaStruct::PaillierKeyPair => "PaillierKeyPair",
            EcdsaStruct::Party1Private => "Party1Private",
            EcdsaStruct::Party2Public => "Secp256k1Point",
            EcdsaStruct::PDLProver => "PDLProver",
            EcdsaStruct::PDLDecommit => "PDLdecommit",
            EcdsaStruct::Alpha => "Alpha",
            EcdsaStruct::Party2PDLFirstMsg => "PDLFirstMessage",
            EcdsaStruct::CCKeyGenFirstMsg => "Party1FirstMessage",
            EcdsaStruct::CCCommWitness => "CommWitnessDHPoK",
            EcdsaStruct::CCEcKeyPair => "EcKeyPairDHPoK",
            EcdsaStruct::CC => "ChainCode1",
            EcdsaStruct::Party1MasterKey => "MasterKey1",
            EcdsaStruct::EphEcKeyPair => "EphEcKeyPair",
            EcdsaStruct::EphKeyGenFirstMsg => "EphKeyGenFirstMsg",
            EcdsaStruct::POS => "POS",
            EcdsaStruct::Abort => "Abort"
        };

        res.to_string()
    }
}


/// Wrapper struct for alpha values. They implement the Value trait in order to serialize/deserialize trait objects. Generics was not an option
/// since they are used inside KeyGen and Sign traits which are treated as trait objects
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Alpha {
    pub value: BigInt,
}

impl Display for Alpha {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[typetag::serde]
impl Value for Alpha {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &str {
        "Alpha"
    }
}

#[derive(Serialize, Deserialize,Debug)]
pub(crate) struct Aborted {
    pub(crate) isAborted: String,
}

impl Display for Aborted {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[typetag::serde]
impl Value for Aborted {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &str {
        "Aborted"
    }
}
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

    fn require_customer_id(&self) -> bool {
        self.to_string() == "Party1MasterKey" || self.to_string() == "Abort"
    }

    fn to_struct_name(&self) -> String {
        self.to_struct_name()
    }
}

//TODO move to two-party-ecdsa/kms
#[derive(Serialize, Deserialize)]
pub struct SignSecondMsgRequest {
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
    pub x_pos_child_key: BigInt,
    pub y_pos_child_key: BigInt,
}
#[inline(always)]
pub fn idify(user_id: &String, id: &String, name: &dyn MPCStruct) -> String {
    format!("{}_{}_{}", user_id, id, name.to_string())
}