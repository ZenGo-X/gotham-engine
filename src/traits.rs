//! The traits that define the common logic  with default implementation for keygen and sign
//! while it differentiates implementation of keygen and sign with trait objects for DB management,user authorization and tx authorization

use crate::types::{DatabaseError, Db_index, EcdsaStruct, HDPos};
use kms::ecdsa::two_party::MasterKey1;
use log::{error, warn};
use redis::{Commands, Connection, RedisResult};
use rocket::serde::json::Json;
use rocket::{async_trait, get, post, State};
use std::env;
use std::fmt::{Debug, Display, Formatter};
use tokio::sync::Mutex;
use two_party_ecdsa::party_one;
use two_party_ecdsa::party_one::KeyGenFirstMsg;
use uuid::Uuid;
use crate::guarder::Claims;

/// The Txauthorization trait allows for extra tx authorization during the sign protocol. Private Gotham implements the logic of authorization tx while public one lets it empty
pub trait Txauthorization {
    /// the granted function implements the logic of tx authorization. If no tx authorization is needed the function returns always true
    fn granted<T: Clone + std::fmt::Display>(&self, key: T) -> Result<bool, DatabaseError>;
}

pub trait Authentication {}

pub trait Value: Sync + Send + std::fmt::Display {
    // fn to_string(&self) -> String;
}

impl Display for HDPos {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.pos)
    }
}



impl Value for HDPos {}

/// The Db trait allows different DB's to implement a common API for insert,delete,get
#[async_trait]
pub trait Db: Send + Sync {
    ///insert a value in the DB
    async fn insert(
        &self,
        key: &Db_index,
        table_name: &dyn MPCStruct,
        value: &dyn Value,
    ) -> Result<(), DatabaseError>;
    ///get a value from the DB
    async fn get<'a, T: serde::de::Deserialize<'a>>(
        &self,
        key: &Db_index,
        table_name: &dyn MPCStruct,
    ) -> Result<Option<T>, DatabaseError>
    where
        Self: Sized;
    async fn has_active_share(&self, user_id: &str) -> Result<bool, String>;
}

/// Common trait both for private and public for redis api
pub trait Redis_mod {
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
        self.to_string() == "Party1MasterKey"
    }
}

#[post("/engine/traits/wrap_keygen_first", format = "json")]
pub async fn wrap_keygen_first(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
) -> Result<Json<(String, KeyGenFirstMsg)>, String> {
    // let mut gotham = state.lock().unwrap();
    // gotham.first(state,claim).await
    struct gotham {};
    impl KeyGen for gotham {};
    gotham::first(state, claim).await
}

#[async_trait]
pub trait KeyGen {
    async fn first(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
    ) -> Result<Json<(String, party_one::KeyGenFirstMsg)>, String> {
        let mut db = state.lock().await;
        match db.has_active_share(&claim.sub).await {
            Err(e) => {
                let msg = format!(
                    "Error when searching for active shares of customerId {}",
                    &claim.sub
                );
                error!("{}: {:?}", msg, e);
                return Err(format!("{}", msg));
            }
            Ok(result) => {
                if result {
                    let msg = format!("User {} already has an active share", &claim.sub);
                    warn!("{}", msg);
                    let should_fail_keygen = std::env::var("FAIL_KEYGEN_IF_ACTIVE_SHARE_EXISTS");
                    if should_fail_keygen.is_ok() && should_fail_keygen.unwrap() == "true" {
                        warn!("Abort KeyGen");
                        return Err(format!("{}", msg));
                    }
                }
            }
        }

        let (key_gen_first_msg, comm_witness, ec_key_pair) = MasterKey1::key_gen_first_message();

        let id = Uuid::new_v4().to_string();
        //save pos 0
        db.insert(
            &Db_index {
                customerId: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::POS,
            &HDPos { pos: 0u32 },
        )
        .await
        .or(Err("Failed to insert into db"))?;
        // db.insert(
        //     &Db_index {
        //         customerId: claim.sub.to_string(),
        //         id: id.clone(),
        //     },
        //     &EcdsaStruct::KeyGenFirstMsg,
        //     &key_gen_first_msg,
        // )
        //     .await
        //     .or(Err("Failed to insert into db"))?;

        // db.insert(
        //     &Db_index {
        //         customerId: claim.sub.to_string(),
        //         id: id.clone(),
        //     },
        //     &EcdsaStruct::CommWitness,
        //     &comm_witness,
        // )
        //     .await
        //     .or(Err("Failed to insert into db"))?;
        //
        // db.insert(
        //     &Db_index {
        //         customerId: claim.sub.to_string(),
        //         id: id.clone(),
        //     },
        //     &EcdsaStruct::EcKeyPair,
        //     &ec_key_pair,
        // )
        //     .await
        //     .or(Err("Failed to insert into db"))?;
        //
        // db.insert(&Db_index {
        //     customerId: claim.sub.to_string(),
        //     id: id.clone(),
        // }, &EcdsaStruct::Abort, "false")
        //     .await
        //     .or(Err("Failed to insert into db"))?;

        Ok(Json((id.clone(), key_gen_first_msg)))
    }
    // async fn second(&self, dbConn: S) {
    //     //TODO
    // }
    // async fn third(&self, dbConn: S) {
    //     //TODO
    // }
    // async fn fourth(&self, dbConn: S) {
    //     //TODO
    // }
    // async fn chaincode1(&self, dbConn: S) {
    //     //TODO
    // }
    // async fn chaincode2(&self, dbConn: S) {
    //     //TODO
    // }
}

pub trait Sign<S: Db> {
    // async fn sign_first(&self, dbConn: S) {
    //     //TODO
    // }
    // async fn sign_second(&self, dbConn: S) {
    //     //TODO
    // }
}
