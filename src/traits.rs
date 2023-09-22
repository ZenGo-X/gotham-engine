//! The traits that define the common logic  with default implementation for keygen and sign
//! while it differentiates implementation of keygen and sign with trait objects for DB management,user authorization and tx authorization


use std::env;

use crate::types::{DatabaseError, DbIndex, EcdsaStruct};
use crate::guarder::Claims;
use crate::keygen::KeyGen;

use two_party_ecdsa::{party_one, party_two};
use two_party_ecdsa::party_one::{KeyGenFirstMsg, DLogProof, Value};
use two_party_ecdsa::kms::ecdsa::two_party::{party1};
use two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::{Party1FirstMessage, Party1SecondMessage};

use redis::{Commands, Connection, RedisResult};
use rocket::serde::json::Json;
use rocket::{async_trait, post, State};
use tokio::sync::Mutex;


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
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::first(state, claim).await
}

#[post("/engine/traits/<id>/wrap_keygen_second", format = "json", data = "<dlog_proof>")]
pub async fn wrap_keygen_second(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: String,
    dlog_proof: Json<DLogProof>,
) -> Result<Json<party1::KeyGenParty1Message2>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::second(state, claim, id, dlog_proof).await
}

#[post("/engine/traits/<id>/wrap_keygen_third", format = "json", data = "<party_2_pdl_first_message>")]
pub async fn wrap_keygen_third(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: String,
    party_2_pdl_first_message: Json<party_two::PDLFirstMessage>)
    -> Result<Json<party_one::PDLFirstMessage>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::third(state, claim, id, party_2_pdl_first_message).await
}

#[post("/engine/traits/<id>/wrap_keygen_fourth", format = "json", data = "<party_two_pdl_second_message>")]
pub async fn wrap_keygen_fourth(state: &State<Mutex<Box<dyn Db>>>,
                                claim: Claims,
                                id: String,
                                party_two_pdl_second_message: Json<party_two::PDLSecondMessage>,
) -> Result<Json<party_one::PDLSecondMessage>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::fourth(state, claim, id, party_two_pdl_second_message).await
}

#[post("/engine/traits/<id>/chaincode/first", format = "json")]
pub async fn wrap_chain_code_first_message(state: &State<Mutex<Box<dyn Db>>>,
                                           claim: Claims,
                                           id: String,
) -> Result<Json<Party1FirstMessage>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::chain_code_first_message(state, claim, id).await
}

#[post(
"/engine/traits/<id>/chaincode/second",
format = "json",
data = "<cc_party_two_first_message_d_log_proof>"
)]
pub async fn wrap_chain_code_second_message(state: &State<Mutex<Box<dyn Db>>>,
                                            claim: Claims,
                                            id: String,
                                            cc_party_two_first_message_d_log_proof: Json<DLogProof>,
) -> Result<Json<Party1SecondMessage>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::chain_code_second_message(state, claim, id, cc_party_two_first_message_d_log_proof).await
}


#[async_trait]
pub trait Sign {
    // async fn sign_first(&self, dbConn: S) {
    //     //TODO
    // }
    // async fn sign_second(&self, dbConn: S) {
    //     //TODO
    // }
}
