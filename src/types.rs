//! Common types for traits the implementations thereofs at [private_gotham] and [public_gotham]
use erased_serde::serialize_trait_object;
use rocket::post;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

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
pub struct Db_index {
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

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
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
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HDPos {
    pub pos: u32,
}
