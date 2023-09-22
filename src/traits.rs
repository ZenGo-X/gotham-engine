//! The traits that define the common logic  with default implementation for keygen and sign
//! while it differentiates implementation of keygen and sign with trait objects for DB management,user authorization and tx authorization

use std::any::{Any, TypeId};
use crate::types::{DatabaseError, DbIndex, EcdsaStruct};

use two_party_ecdsa::{GE, party_one, party_two};
use two_party_ecdsa::party_one::{KeyGenFirstMsg, DLogProof, HDPos, v, Value, CommWitness, EcKeyPair, Party1Private, PDLdecommit};
use two_party_ecdsa::party_two::{
    PDLFirstMessage as Party2PDLFirstMsg
};
use two_party_ecdsa::kms::ecdsa::two_party::{MasterKey1, party1};
use crate::types::Alpha;

use std::env;
use log::{error, warn};
use redis::{Commands, Connection, RedisResult};
use rocket::serde::json::Json;
use rocket::{async_trait, post, State};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::guarder::Claims;

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

#[async_trait]
pub trait KeyGen {
    //first round of Keygen
    async fn first(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
    ) -> Result<Json<(String, KeyGenFirstMsg)>, String> {
        let db = state.lock().await;
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
                    let should_fail_keygen = env::var("FAIL_KEYGEN_IF_ACTIVE_SHARE_EXISTS");
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
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::POS,
            &HDPos { pos: 0u32 },
        )
            .await
            .or(Err("Failed to insert into db"))?;
        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::KeyGenFirstMsg,
            &key_gen_first_msg,
        )
            .await
            .or(Err("Failed to insert into db"))?;

        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::CommWitness,
            &comm_witness,
        )
            .await
            .or(Err("Failed to insert into db"))?;

        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::EcKeyPair,
            &ec_key_pair,
        )
            .await
            .or(Err("Failed to insert into db"))?;


        let value = v { value: "false".parse().unwrap() };

        db.insert(&DbIndex {
            customer_id: claim.sub.to_string(),
            id: id.clone(),
        }, &EcdsaStruct::Abort, &value)
            .await
            .or(Err("Failed to insert into db"))?;

        Ok(Json((id.clone(), key_gen_first_msg)))
    }

    //second round of Keygen
    async fn second(state: &State<Mutex<Box<dyn Db>>>,
                    claim: Claims,
                    id: String,
                    dlog_proof: Json<DLogProof>) -> Result<Json<party1::KeyGenParty1Message2>, String> {
        let db = state.lock().await;
        let party2_public: GE = dlog_proof.0.pk;
        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::Party2Public,
            &party2_public,
        )
            .await
            .or(Err("Failed to insert into db"))?;

        let comm_witness =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::CommWitness)
                .await
                .or(Err("Failed to get from db"))?
                .ok_or(format!("No data for such identifier {}", id))?;
        let ec_key_pair =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::EcKeyPair)
                .await
                .or(Err("Failed to get from db"))?
                .ok_or(format!("No data for such identifier {}", id))?;

        let (kg_party_one_second_message, paillier_key_pair, party_one_private) =
            MasterKey1::key_gen_second_message(comm_witness.as_any().downcast_ref::<CommWitness>().unwrap(), ec_key_pair.as_any().downcast_ref::<EcKeyPair>().unwrap(), &dlog_proof.0);

        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::PaillierKeyPair,
            &paillier_key_pair,
        )
            .await
            .or(Err("Failed to insert into db"))?;
        println!("To insert typeID of party_one_private{:?}",(&party_one_private).type_id());

        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::Party1Private,
            &party_one_private,
        )
            .await
            .or(Err("Failed to insert into db"))?;

        // println!("Insert typeID of party_one_private{:?}",(&*party_one_private).type_id());

        Ok(Json(kg_party_one_second_message))
    }


    async fn third(state: &State<Mutex<Box<dyn Db>>>,
                   claim: Claims,
                   id: String,
                   party_2_pdl_first_message: Json<party_two::PDLFirstMessage>)
                   -> Result<Json<party_one::PDLFirstMessage>, String> {
        let db = state.lock().await;

        let party_one_private =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::Party1Private)
                .await
                .or(Err(format!("Failed to get from DB, id: {}", id)))?
                .ok_or(format!("No data for such identifier {}", id))?;


        let (party_one_third_message, party_one_pdl_decommit, alpha) =
            MasterKey1::key_gen_third_message(&party_2_pdl_first_message.0, &party_one_private.as_any().downcast_ref::<Party1Private>().unwrap());

        println!("To insert typeID of party_one_private{:?}",(&party_one_pdl_decommit).type_id());
        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::PDLDecommit,
            &party_one_pdl_decommit,
        )
            .await
            .or(Err(format!(
                "Failed to insert into DB PDLDecommit, id: {}",
                id
            )))?;


        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::Alpha,
            &Alpha { value: alpha },
        )
            .await
            .or(Err(format!("Failed to insert into DB Alpha, id: {}", id)))?;

        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::Party2PDLFirstMsg,
            &party_2_pdl_first_message.0,
        )
            .await
            .or(Err(format!(
                "Failed to insert into DB Party2PDLFirstMsg, id: {}",
                id
            )))?;

        Ok(Json(party_one_third_message))
    }
    async fn fourth(state: &State<Mutex<Box<dyn Db>>>,
                    claim: Claims,
                    id: String, party_two_pdl_second_message: Json<party_two::PDLSecondMessage>,
    ) -> Result<Json<party_one::PDLSecondMessage>, String> {
        let db = state.lock().await;

        let party_one_private =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::Party1Private)
                .await
                .or(Err(format!("Failed to get from DB, id:{}", id)))?
                .ok_or(format!("No data for such identifier {}", id))?;
        println!("Get typeID of party_one_private{:?}",(party_one_private).type_id());
        let party_2_pdl_first_message =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::Party2PDLFirstMsg)
                .await
                .or(Err(format!(
                    "Failed to get party 2 pdl first message from DB, id: {}",
                    id
                )))?
                .ok_or(format!("No data for such identifier {}", id))?;
        let party_one_pdl_decommit =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::PDLDecommit)
                .await
                .or(Err(format!(
                    "Failed to get party one pdl decommit, id: {}",
                    id
                )))?
                .ok_or(format!("No data for such identifier {}", id))?;



        let alpha = db.get(&DbIndex {
            customer_id: claim.sub.to_string(),
            id: id.clone(),
        }, &EcdsaStruct::Alpha)
            .await
            .or(Err(format!("Failed to get alpha from DB, id: {}", id)))?
            .ok_or(format!("No data for such identifier {}", id))?;
        // let dl: &mut dyn Value = party_one_pdl_decommit.borrow_mut();


        let res = MasterKey1::key_gen_fourth_message(
            party_2_pdl_first_message.as_any().downcast_ref::<Party2PDLFirstMsg>().unwrap().clone(),
            &party_two_pdl_second_message.0,
            party_one_private.as_any().downcast_ref::<Party1Private>().unwrap().clone(),
            party_one_pdl_decommit.as_any().downcast_ref::<PDLdecommit>().unwrap().clone(),
            alpha.as_any().downcast_ref::<Alpha>().unwrap().value.clone(),
        );
        assert!(res.is_ok());
        Ok(Json(res.unwrap()))
    }
}


// async fn chaincode1(&self, dbConn: S) {
//     //TODO
// }
// async fn chaincode2(&self, dbConn: S) {
//     //TODO
// }


pub trait Sign<S: Db> {
    // async fn sign_first(&self, dbConn: S) {
    //     //TODO
    // }
    // async fn sign_second(&self, dbConn: S) {
    //     //TODO
    // }
}
