//! The traits that define the common logic  with default implementation for keygen and sign
//! while it differentiates implementation of keygen and sign with trait objects for DB management,user authorization and tx authorization
use std::env;
use std::env::VarError;
use log::info;

use crate::types::{DbIndex};

use redis::{Commands, Connection, RedisError, RedisResult};
use rocket::{async_trait, error};
use two_party_ecdsa::typetags::Value;

/// The Db trait allows different DB's to implement a common API for insert and get
#[async_trait]
pub trait Db: Send + Sync {
    ///insert a value in the DB
    /// # Arguments
    /// * `key` - A [DbIndex] struct which acts as a key index in the DB.
    /// * `table_name` - The table name which is derived from [MPCStruct]
    /// * `value` - The value to be inserted in the db which is a trait object of the trait  [Value]
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
        value: &dyn Value,
    ) -> Result<(), String>;
    ///get a value from the DB
    /// # Arguments
    /// * `key` - A [DbIndex] struct which acts as a key index in the DB.
    /// * `table_name` - The table name which is derived from [MPCStruct]
    /// * `value` - The value to be inserted in the db which is a trait object of the trait  [Value]
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
    ) -> Result<Option<Box<dyn Value>>, String>;
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
    fn to_string(&self) -> String;

    fn to_table_name(&self, env: &str) -> String {
        format!("{}_{}", env, self.to_string())
    }

    fn require_customer_id(&self) -> bool {
        true
    }
    fn to_struct_name(&self) -> String;
}
