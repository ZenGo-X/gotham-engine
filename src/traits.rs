//! The traits that define the common logic  with default implementation for keygen and sign
//! while it differentiates implementation of keygen and sign with trait objects for DB management,user authorization and tx authorization
use std::env;

use crate::types::{DatabaseError, DbIndex};

use two_party_ecdsa::party_one::Value;

use redis::{Commands, Connection, RedisResult};
use rocket::async_trait;


/// The Db trait allows different DB's to implement a common API for insert and get
#[async_trait]
pub trait Db: Send + Sync {
    ///insert a value in the DB
    /// # Arguments
    /// * `key` - A [DbIndex] struct which acts as a key index in the DB.
    /// * `table_name` - The table name which is derived from [MPCStruct]
    /// * `value` - The value to be inserted in the db which is a trait object of the trait  [Value]
    /// # Examples:
    /// ```
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
    /// ```
    async fn insert(
        &self,
        key: &DbIndex,
        table_name: &dyn MPCStruct,
        value: &dyn Value,
    ) -> Result<(), DatabaseError>;
    ///get a value from the DB
    /// # Arguments
    /// * `key` - A [DbIndex] struct which acts as a key index in the DB.
    /// * `table_name` - The table name which is derived from [MPCStruct]
    /// * `value` - The value to be inserted in the db which is a trait object of the trait  [Value]
    /// # Examples
    /// ```
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
    /// ```
    async fn get(
        &self,
        key: &DbIndex,
        table_name: &dyn MPCStruct,
    ) -> Result<Option<Box<dyn Value>>, DatabaseError>;
    async fn has_active_share(&self, customerId: &str) -> Result<bool, String>;

    /// the granted function implements the logic of tx authorization. If no tx authorization is needed the function returns always true
    fn granted(&self, message: &str, customer_id: &str) -> Result<bool, DatabaseError>;
}

/// Common trait both for private and public for redis api
pub trait RedisMod {
    fn redis_get(key: String) -> RedisResult<String> {
        let mut con = Self::redis_get_connection()?;
        println!("[redis getting  key] {:?}", key);
        let res = con.get(key)?;
        Ok(res)
    }

    fn redis_del(key: String) -> RedisResult<String> {
        let mut con = Self::redis_get_connection()?;
        println!("[redis deleting  key] {:?}", key);
        let res: String = con.del(key)?;
        Ok(res)
    }

    fn redis_set(key: String, value: String) -> RedisResult<String> {
        let mut con = Self::redis_get_connection()?;
        println!(
            "[redis will write key - value ] = {:?}-{:?}",
            key.clone(),
            value.clone()
        );
        let res: String = con.set(key.clone(), value.clone())?;
        println!(
            "[redis wrote key - value ] = {:?}-{:?}",
            key.clone(),
            value.clone()
        );
        Ok(res)
    }

    fn redis_get_connection() -> RedisResult<Connection> {
        let redis_ip = env::var("ELASTICACHE_URL");
        let redis = String::from("redis://");
        let redis_url_var = String::from(redis + redis_ip.clone().unwrap().as_str());
        println!("[redis connecting to] {:?}", redis_url_var);
        let client = redis::Client::open(redis_url_var)?;
        let info = client.get_connection_info();
        println!("{:?}", info);
        client.get_connection()
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
