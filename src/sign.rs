use crate::guarder::Claims;
use crate::traits::{Db, RedisMod};
use crate::types::{idify, Aborted, DbIndex, EcdsaStruct, SignSecondMsgRequest};
use config::Value;
use std::env;

use two_party_ecdsa::kms::ecdsa::two_party::MasterKey1;
use two_party_ecdsa::party_one::{v, Converter};
use two_party_ecdsa::{party_one, party_two, BigInt};

use rocket::serde::json::Json;
use rocket::{async_trait, State};
use tokio::sync::Mutex;
use uuid::Uuid;

#[async_trait]
pub trait Sign {
    async fn sign_first(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        eph_key_gen_first_message_party_two: Json<party_two::EphKeyGenFirstMsg>,
    ) -> Result<Json<party_one::EphKeyGenFirstMsg>, String> {
        let db = state.lock().await;

        let abort = db
            .get(
                &DbIndex {
                    customerId: claim.sub.to_string(),
                    id: id.clone(),
                },
                &EcdsaStruct::Abort,
            )
            .await
            .unwrap_or_else(|err| panic!("DatabaseError: {}", err))
            .unwrap_or(Box::new(v {
                value: "false".to_string(),
            }));

        let abort_res = abort.as_any().downcast_ref::<v>().unwrap();

        if abort_res.value == "true" {
            panic!("Tainted user");
        }

        let (sign_party_one_first_message, eph_ec_key_pair_party1) =
            MasterKey1::sign_first_message();

        db.insert(
            &DbIndex {
                customerId: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::EphKeyGenFirstMsg,
            &eph_key_gen_first_message_party_two.0,
        )
        .await
        .or(Err("Failed to insert into db"))?;

        db.insert(
            &DbIndex {
                customerId: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::EphEcKeyPair,
            &eph_ec_key_pair_party1,
        )
        .await
        .or(Err("Failed to insert into db"))?;

        Ok(Json(sign_party_one_first_message))
    }
    async fn sign_second(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        request: Json<SignSecondMsgRequest>,
    ) -> Result<Json<party_one::SignatureRecid>, String> {
        let db = state.lock().await;
        if env::var("REDIS_ENV").is_ok() {
            if db.granted(&*request.message.to_hex().to_string(), claim.sub.as_str()) == Ok(false) {
                panic!(
                    "Unauthorized transaction from redis-pps: {:?}",
                    id.clone().to_string()
                );
            }
        }

        //: MasterKey1
        let master_key = db
            .get(
                &DbIndex {
                    customerId: claim.sub.to_string(),
                    id: id.clone(),
                },
                &EcdsaStruct::Party1MasterKey,
            )
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;

        let x: BigInt = request.x_pos_child_key.clone();
        let y: BigInt = request.y_pos_child_key.clone();

        let child_master_key = master_key
            .as_any()
            .downcast_ref::<MasterKey1>()
            .unwrap()
            .get_child(vec![x, y]);

        //: party_one::EphEcKeyPair
        let eph_ec_key_pair_party1 = db
            .get(
                &DbIndex {
                    customerId: claim.sub.to_string(),
                    id: id.clone(),
                },
                &EcdsaStruct::EphEcKeyPair,
            )
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;

        //: party_two::EphKeyGenFirstMsg
        let eph_key_gen_first_message_party_two = db
            .get(
                &DbIndex {
                    customerId: claim.sub.to_string(),
                    id: id.clone(),
                },
                &EcdsaStruct::EphKeyGenFirstMsg,
            )
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;

        let signature_with_recid = child_master_key.sign_second_message(
            &request.party_two_sign_message,
            &eph_key_gen_first_message_party_two
                .as_any()
                .downcast_ref::<party_two::EphKeyGenFirstMsg>()
                .unwrap(),
            &eph_ec_key_pair_party1
                .as_any()
                .downcast_ref::<party_one::EphEcKeyPair>()
                .unwrap(),
            &request.message,
        );

        if signature_with_recid.is_err() {
            let value = v {
                value: "true".parse().unwrap(),
            };
            println!("signature failed, user tainted[{:?}]", id);
            db.insert(
                &DbIndex {
                    customerId: claim.sub.to_string(),
                    id: id.clone(),
                },
                &EcdsaStruct::Abort,
                &value,
            )
            .await
            .or(Err("Failed to insert into db"))?;
            panic!("Server sign_second: validation of signature failed. Potential adversary")
        };

        Ok(Json(signature_with_recid.unwrap()))
    }
    async fn sign_first_v2(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        eph_key_gen_first_message_party_two: Json<party_two::EphKeyGenFirstMsg>,
    ) -> Result<Json<(String, party_one::EphKeyGenFirstMsg)>, String> {
        let db = state.lock().await;
        println!(
            "[cross-session] Sign first round - id = {:?} - customerID = {:?}",
            id, &claim.sub
        );

        let abort = db
            .get(
                &DbIndex {
                    customerId: claim.sub.to_string(),
                    id: id.clone(),
                },
                &EcdsaStruct::Abort,
            )
            .await
            .unwrap_or_else(|err| panic!("DatabaseError: {}", err))
            .unwrap_or(Box::new(v {
                value: "false".to_string(),
            }));

        let abort_res = abort.as_any().downcast_ref::<v>().unwrap();

        if abort_res.value == "true" {
            panic!("Tainted user");
        }

        struct RedisCon {}
        impl RedisMod for RedisCon {}

        let (sign_party_one_first_message, eph_ec_key_pair_party1) =
            MasterKey1::sign_first_message();
        let sid = Uuid::new_v4().to_string();
        let ssid = String::from(id + "," + &*sid);
        println!("Server side - sign first ssid={:?}", ssid);

        //write to redis db table as customerid_ssid_EphKeyGenFirstMsg:value
        let mut key: String = idify(&claim.sub, &ssid, &EcdsaStruct::EphKeyGenFirstMsg);
        let mut res = RedisCon::redis_set(
            key.clone(),
            serde_json::to_string(&eph_key_gen_first_message_party_two.0).unwrap(),
        )
        .is_ok();
        let mut err_msg: String = format!(
            "redis error during set key-value = {:?} - {:?}",
            key.clone().to_string(),
            serde_json::to_string(&eph_key_gen_first_message_party_two.0).unwrap(),
        );

        if !res {
            println!("{:?}", err_msg);
            return Err(format!("{}", err_msg));
        }

        //write to redis db table as customerid_ssid_EphEcKeyPair:value
        key = idify(&claim.sub, &ssid, &EcdsaStruct::EphEcKeyPair);
        res = RedisCon::redis_set(
            key.clone(),
            serde_json::to_string(&eph_ec_key_pair_party1).unwrap(),
        )
        .is_ok();
        err_msg = format!(
            "redis error during set key-value = {:?} - {:?}",
            key.clone().to_string(),
            serde_json::to_string(&eph_ec_key_pair_party1).unwrap()
        );
        if !res {
            println!("{:?}", err_msg);
            return Err(format!("{}", err_msg));
        }

        Ok(Json((ssid.clone(), sign_party_one_first_message)))
    }
    async fn sign_second_v2(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        ssid: String,
        request: Json<SignSecondMsgRequest>,
    ) -> Result<Json<party_one::SignatureRecid>, String> {
        let db = state.lock().await;
        if env::var("REDIS_ENV").is_ok() {
            if db.granted(&*request.message.to_hex().to_string(), claim.sub.as_str()) == Ok(false) {
                panic!(
                    "Unauthorized transaction from redis-pps: {:?}",
                    ssid.clone().to_string()
                );
            }
        }

        println!(
            "[cross-session] Sign second round - id = {:?} - customerID = {:?} - msg = {:?}",
            ssid,
            &claim.sub,
            request.message.to_string()
        );

        struct RedisCon {}
        impl RedisMod for RedisCon {}

        let id: &str = ssid.split(",").collect::<Vec<_>>()[0];
        println!("ssid = {:?}", ssid);
        println!("id = {:?}", id);
        println!("sid = {:?}", ssid.split(",").collect::<Vec<_>>()[1]);

        //get the master key for that userid
        let master_key = db
            .get(
                &DbIndex {
                    customerId: claim.sub.to_string(),
                    id: id.clone().to_string(),
                },
                &EcdsaStruct::Party1MasterKey,
            )
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;

        let x: BigInt = request.x_pos_child_key.clone();
        let y: BigInt = request.y_pos_child_key.clone();

        let child_master_key = master_key
            .as_any()
            .downcast_ref::<MasterKey1>()
            .unwrap()
            .get_child(vec![x, y]);
        let key1 = idify(&claim.sub, &ssid, &EcdsaStruct::EphEcKeyPair);
        let eph_ec_key_pair_party1: party_one::EphEcKeyPair =
            serde_json::from_slice(&RedisCon::redis_get(key1.clone()).unwrap().as_bytes()).unwrap();

        let key2 = idify(&claim.sub, &ssid, &EcdsaStruct::EphKeyGenFirstMsg);
        let eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg =
            serde_json::from_slice(&RedisCon::redis_get(key2.clone()).unwrap().as_bytes()).unwrap();

        let _ = RedisCon::redis_del(key1);
        let _ = RedisCon::redis_del(key2);

        let signature_with_recid = child_master_key.sign_second_message(
            &request.party_two_sign_message,
            &eph_key_gen_first_message_party_two,
            &eph_ec_key_pair_party1,
            &request.message,
        );

        if signature_with_recid.is_err() {
            println!("signature failed, user tainted[{:?}]", id);

            let message: BigInt = request.message.clone();
            println!("date: {}", chrono::offset::Utc::now().to_string());
            println!("ssid: {}", ssid.to_string());
            println!("msg: {}", message.to_string());
            println!(
                "party_two_sign_message: {:?}",
                request.party_two_sign_message.second_message
            );
            println!(
                "partial_sig: {:?}",
                request.party_two_sign_message.partial_sig
            );
            println!("eph_ec_key_pair_party1: {:?}", eph_ec_key_pair_party1);
            println!(
                "eph_key_gen_first_message_party_two: {:?}",
                eph_key_gen_first_message_party_two
            );
            println!(
                "x_pos_child_key: {}",
                request.x_pos_child_key.clone().to_string()
            );
            println!(
                "y_pos_child_key: {}",
                request.y_pos_child_key.clone().to_string()
            );
            println!(
                "public: {:?}",
                master_key
                    .as_any()
                    .downcast_ref::<MasterKey1>()
                    .unwrap()
                    .public
            );
            println!(
                "private {:?}",
                master_key
                    .as_any()
                    .downcast_ref::<MasterKey1>()
                    .unwrap()
                    .private
            );

            let item = Aborted {
                isAborted: "true".to_string(),
            };

            db.insert(
                &DbIndex {
                    customerId: claim.sub.to_string(),
                    id: id.clone().to_string(),
                },
                &EcdsaStruct::Abort,
                &item,
            )
            .await
            .or(Err("Failed to insert into db"))?;
            panic!("Server sign_second: verification of signature failed. Potential adversary")
        };

        Ok(Json(signature_with_recid.unwrap()))
    }
}
