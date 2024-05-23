//! Common types for traits the implementations thereofs at [private_gotham] and [public_gotham]
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use thiserror::Error;
use two_party_ecdsa::typetag_value;
use two_party_ecdsa::typetags::Value;
use two_party_ecdsa::BigInt;
use two_party_ecdsa::kms::ecdsa::two_party::party2::Party2SignMessage;
use crate::common::traits::MPCStruct;


// TODO: use 'thiserror' and this enum in code
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
    pub customerId: Option<String>,
    ///The is as assigned from gotham server during the first round of keygen to identify users
    pub id: Option<String>,
}

/*      JWT is no longer used!

/// The Authenticator indicates how the input requests to gotham server will be authorized. Currently there is the JWT option
/// but in the future it will be discarded. Private gotham is using a jwt auth while public one does not use it
pub enum Authenticator {
    /// passthrough mode to authentication at http level
    None,
    /// verification with a valid JWT
    Jwt,
}

 */

pub const CUSTOMER_ID_IDENTIFIER: &str = "customerId";
pub const ID_IDENTIFIER: &str = "id";


