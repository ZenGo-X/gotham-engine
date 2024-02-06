use crate::guarder::Claims;
use crate::traits::{Db, RedisMod};
use crate::types::{idify, Abort, DbIndex, EcdsaStruct};
use config::Value;
use std::env;

use rocket::serde::json::Json;
use rocket::{async_trait, State};
use tokio::sync::Mutex;
use two_party_ecdsa::kms::ecdsa::two_party::party2::Party2SignSecondMessage;
use two_party_ecdsa::kms::ecdsa::two_party::MasterKey1;
use two_party_ecdsa::party_one::{Converter, Party1EphEcKeyPair, Party1EphKeyGenFirstMessage, SignatureRecid};
use two_party_ecdsa::party_two::Party2EphKeyGenFirstMessage;
use two_party_ecdsa::BigInt;
use uuid::Uuid;
use crate::{db_cast, db_get, db_get_required, db_insert};

#[async_trait]
pub trait Sign {
    async fn sign_first(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        eph_key_gen_first_message_party_two: Json<Party2EphKeyGenFirstMessage>,
    ) -> Result<Json<Party1EphKeyGenFirstMessage>, String> {
        let db = state.lock().await;

        let tmp = db_get!(db, claim.sub, id, Abort)
            .unwrap_or(Box::new(Abort { blocked: false }));
        let to_abort = db_cast!(tmp, Abort);

        if to_abort.blocked == true {
            panic!("customer_id {} exists in Abort table and thus is blocked", claim.sub.to_string());
        }

        let (sign_party_one_first_message, eph_ec_key_pair_party1) =
            MasterKey1::sign_first_message();

        db_insert!(db, claim.sub, id, EphKeyGenFirstMsg, &eph_key_gen_first_message_party_two.0);

        db_insert!(db, claim.sub, id, EphEcKeyPair, &eph_ec_key_pair_party1);

        Ok(Json(sign_party_one_first_message))
    }
    async fn sign_second(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        request: Json<Party2SignSecondMessage>,
    ) -> Result<Json<SignatureRecid>, String> {
        let db = state.lock().await;
        if env::var("REDIS_ENV").is_ok() {
            if db.granted(&*request.message.to_hex().to_string(), claim.sub.as_str()) == Ok(false) {
                panic!(
                    "Unauthorized transaction from redis-pps for customer_id {}, id {}:",
                    claim.sub.as_str(), id.as_str()
                );
            }
        }

        //: MasterKey1

        let tmp = db_get_required!(db, claim.sub, id, Party1MasterKey);
        let master_key = db_cast!(tmp, MasterKey1);

        let x: BigInt = request.x_pos_child_key.clone();
        let y: BigInt = request.y_pos_child_key.clone();

        let child_master_key = master_key.get_child(vec![x, y]);

        //: party_one::EphEcKeyPair

        let tmp = db_get_required!(db, claim.sub, id, EphEcKeyPair);
        let eph_ec_key_pair_party1 = db_cast!(tmp, Party1EphEcKeyPair);


        let tmp = db_get_required!(db, claim.sub, id, EphKeyGenFirstMsg);
        let eph_key_gen_first_message_party_two = db_cast!(tmp, Party2EphKeyGenFirstMessage);

        let signature_with_recid = child_master_key.sign_second_message(
            &request.party_two_sign_message,
            &eph_key_gen_first_message_party_two,
            &eph_ec_key_pair_party1,
            &request.message,
        );

        if signature_with_recid.is_err() {
            db_insert!(db, claim.sub, id, Abort, &Abort { blocked: true });
            panic!("sign_second failed for customer_id {}, id {}. Inserted into Abort table",  claim.sub, id);
        };

        Ok(Json(signature_with_recid.unwrap()))
    }
    async fn sign_first_v2(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        eph_key_gen_first_message_party_two: Json<Party2EphKeyGenFirstMessage>,
    ) -> Result<Json<(String, Party1EphKeyGenFirstMessage)>, String> {
        let db = state.lock().await;
        println!(
            "[cross-session] Sign first round - id = {:?} - customerID = {:?}",
            id, &claim.sub
        );

        let tmp = db_get!(db, claim.sub, id, Abort)
            .unwrap_or(Box::new(Abort { blocked: false }));
        let to_abort = db_cast!(tmp, Abort);

        if to_abort.blocked == true {
            panic!("customer_id {} exists in Abort table and thus is blocked", claim.sub.to_string());
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
        request: Json<Party2SignSecondMessage>,
    ) -> Result<Json<SignatureRecid>, String> {
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
        let tmp = db_get_required!(db, claim.sub, id, Party1MasterKey);
        let master_key = db_cast!(tmp, MasterKey1);

        let x: BigInt = request.x_pos_child_key.clone();
        let y: BigInt = request.y_pos_child_key.clone();

        let child_master_key = master_key.get_child(vec![x, y]);

        let key1 = idify(&claim.sub, &ssid, &EcdsaStruct::EphEcKeyPair);
        let eph_ec_key_pair_party1: Party1EphEcKeyPair =
            serde_json::from_slice(&RedisCon::redis_get(key1.clone()).unwrap().as_bytes()).unwrap();

        let key2 = idify(&claim.sub, &ssid, &EcdsaStruct::EphKeyGenFirstMsg);
        let eph_key_gen_first_message_party_two: Party2EphKeyGenFirstMessage =
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
                master_key.public
            );
            println!(
                "private {:?}",
                master_key.private
            );

            db_insert!(db, claim.sub, id, Abort, &Abort { blocked: true });
            panic!("sign_second failed for customer_id {}, id {}. Inserted into Abort table",  claim.sub, id);
        };

        Ok(Json(signature_with_recid.unwrap()))
    }
}
