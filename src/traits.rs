//! The traits that define the common logic  with default implementation for keygen and sign
//! while it differentiates implementation of keygen and sign with trait objects for DB management,user authorization and tx authorization
use std::env;

use crate::types::{DatabaseError, DbIndex, EcdsaStruct};

use two_party_ecdsa::party_one::{Value};

use redis::{Commands, Connection, RedisResult};
use rocket::async_trait;


/// The Txauthorization trait allows for extra tx authorization during the sign protocol. Private Gotham implements the logic of authorization tx while public one lets it empty
pub trait Txauthorization {
    /// the granted function implements the logic of tx authorization. If no tx authorization is needed the function returns always true
    fn granted<T: Clone + std::fmt::Display>(&self, key: T) -> Result<bool, DatabaseError>;
}

pub trait Authentication {}

/// The Db trait allows different DB's to implement a common API for insert,delete,get
#[async_trait]
pub trait Db: Send + Sync {
    ///insert a value in the DB
    async fn insert(
        &self,
        key: &DbIndex,
        table_name: &dyn MPCStruct,
        value: &dyn Value,
    ) -> Result<(), DatabaseError>;
    ///get a value from the DB
    async fn get(
        &self,
        key: &DbIndex,
        table_name: &dyn MPCStruct,
    ) -> Result<Option<Box<dyn Value>>, DatabaseError>;
    async fn has_active_share(&self, user_id: &str) -> Result<bool, String>;
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

pub trait MPCStruct: Sync {
    fn to_string(&self) -> String;

    fn to_table_name(&self, env: &str) -> String {
        format!("{}_{}", env, self.to_string())
    }

    fn require_customer_id(&self) -> bool {
        true
    }
}



