pub mod guarder;
pub mod macros;
pub mod client_shim;

use std::env;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use async_trait::async_trait;
use log::info;
use redis::{Commands, Connection};
use thiserror::Error;


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


/// The Db trait allows different DB's to implement a common API for insert and get
#[async_trait]
pub trait Db: Send + Sync {
    ///insert a value in the DB
    /// # Arguments
    /// * `key` - A [DbIndex] struct which acts as a key index in the DB.
    /// * `table_name` - The table name which is derived from [MPCStruct]
    /// * `value` - The value to be inserted in the db which is a trait object of the trait  [DbValue]
    /// # Examples:
    ///
    ///
    /// db.insert(
    ///             &DbIndex {
    ///                customer_id: claim.sub.to_string(),
    ///                 id: id.clone(),
    ///             },
    ///             &EcdsaStruct::PDLDecommit,
    ///             &party_one_pdl_decommit,
    ///         )
    ///             .await
    ///             .or(Err(format!(
    ///                 "Failed to insert into DB PDLDecommit, id: {}",
    ///                id
    ///            )))?;
    ///
    async fn insert(
        &self,
        key: &DbIndex,
        table_name: &dyn MPCStruct,
        value: &dyn DbValue,
    ) -> Result<(), String>;
    ///get a value from the DB
    /// # Arguments
    /// * `key` - A [DbIndex] struct which acts as a key index in the DB.
    /// * `table_name` - The table name which is derived from [MPCStruct]
    /// * `value` - The value to be inserted in the db which is a trait object of the trait  [DbValue]
    /// # Examples
    ///
    /// let party_one_pdl_decommit =
    ///             db.get(&DbIndex {
    ///                 customer_id: claim.sub.to_string(),
    ///                 id: id.clone(),
    ///             }, &EcdsaStruct::PDLDecommit)
    ///                 .await
    ///                 .or(Err(format!(
    ///                     "Failed to get party one pdl decommit, id: {}",
    ///                     id
    ///                 )))?
    ///                 .ok_or(format!("No data for such identifier {}", id))?;
    /// //downcasting the result:
    /// party_one_pdl_decommit.as_any().downcast_ref::<party_one::PDLdecommit>().unwrap()
    ///
    async fn get(
        &self,
        key: &DbIndex,
        table_name: &dyn MPCStruct,
    ) -> Result<Option<Box<dyn DbValue>>, String>;
    async fn has_active_share(&self, customerId: &str) -> Result<bool, String>;

    /// the granted function implements the logic of tx authorization. If no tx authorization is needed the function returns always true
    fn granted(&self, message: &str, customer_id: &str) -> Result<bool, String>;
}

/// Common trait both for private and public for redis api
pub trait RedisMod {
    fn get(connection: &mut Connection, key: &String) -> Result<String, String> {
        info!("Getting from Redis key [{:?}]", key);
        connection.get(key).map_err(|err| {
            format!("Failed getting from Redis at key [{}] with error: {}", key, err)
        })
    }

    fn del(connection: &mut Connection, key: &String) -> Result<(), String> {
        info!("Deleting from Redis key [{}]", key);
        connection.del(key).map_err(|err| {
            format!("Failed deleting from Redis at key [{}] with error: {}", key, err)
        })
    }

    fn set(connection: &mut Connection, key: &String, value: &String) ->  Result<(), String> {
        info!("Setting to Redis at key [{}]", key);
        connection.set(key, value).map_err(|err| {
            format!("Failed setting to Redis at key [{}] with error: {}", key, err)
        })
    }

    fn get_connection() -> Result<Connection, String> {
        let elasticache_url = env::var("ELASTICACHE_URL").map_err(|err| {
            format!("Invalid 'ELASTICACHE_URL' environment variable {}", err)
        })?;

        let redis_location = format!("redis://{}", elasticache_url);

        info!("Connecting to Redis at [{:?}]", redis_location);

        let client = redis::Client::open(redis_location.clone()).map_err(|err| {
            format!("Creating connection to {} failed with error: {}", redis_location, err)
        })?;

        client.get_connection().map_err(|err| {
            format!("Getting connection to {} failed with error: {}", redis_location, err)
        })
    }
}

///Trait for table names management for the different type of tables to be inserted in the DB
pub trait MPCStruct: Sync {
    fn get_name(&self) -> String;

    fn get_table_name(&self, env: &str) -> String {
        format!("{}_{}", env, self.get_name())
    }

    fn get_struct_name(&self) -> String;
}

use std::any::Any;

#[typetag::serde]
pub trait DbValue: Sync + Send + Any {
    fn as_any(&self) -> &dyn Any;
    fn type_name(&self) -> &str;
}

#[macro_export]
macro_rules! typetag_value {
    ($struct_name:ty) => {
        #[typetag::serde]
        impl crate::common::DbValue for $struct_name {
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }

            fn type_name(&self) -> &str {
                stringify!($struct_name)
            }
        }
    };
}
