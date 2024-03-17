use crate::guarder::Claims;
use crate::traits::{Db, RedisMod};
use crate::types::{idify, Abort, DbIndex, EcdsaStruct};
use config::Value;
use std::env;

use rocket::serde::json::Json;
use rocket::{async_trait, error, info, State};
use tokio::sync::Mutex;
use two_party_ecdsa::kms::ecdsa::two_party::MasterKey1;
use two_party_ecdsa::party_one::{Converter, Party1EphEcKeyPair, Party1EphKeyGenFirstMessage, Party1SignatureRecid};
use two_party_ecdsa::party_two::Party2EphKeyGenFirstMessage;
use two_party_ecdsa::BigInt;
use two_party_ecdsa::kms::ecdsa::two_party::party2::{Party2SignSecondMessage, Party2SignSecondMessageVector};
use two_party_ecdsa::kms::Errors;
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
            return Err(format!("customer_id {} exists in Abort table and thus is blocked",
                               claim.sub.to_string()));
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
    ) -> Result<Json<Party1SignatureRecid>, String> {
        let db = state.lock().await;
        if env::var("REDIS_ENV").is_ok() {
            if db.granted(&*request.message.to_hex().to_string(), claim.sub.as_str()) == Ok(false) {
                return Err(format!("Unauthorized transaction from redis-pps for customer_id {}, id {}:",
                    claim.sub.as_str(), id.as_str())
                );
            }
        }

        //: MasterKey1

        let master_key = db_get_required!(db, claim.sub, id, Party1MasterKey, MasterKey1);
        // let master_key = db_cast!(tmp, MasterKey1);

        let x: BigInt = request.x_pos_child_key.clone();
        let y: BigInt = request.y_pos_child_key.clone();

        let child_master_key = master_key.get_child(vec![x, y]);

        //: party_one::EphEcKeyPair

        let eph_ec_key_pair_party1 = db_get_required!(db, claim.sub, id, EphEcKeyPair, Party1EphEcKeyPair);
        // let eph_ec_key_pair_party1 = db_cast!(tmp, Party1EphEcKeyPair);


        let eph_key_gen_first_message_party_two = db_get_required!(db, claim.sub, id, EphKeyGenFirstMsg, Party2EphKeyGenFirstMessage);
        // let eph_key_gen_first_message_party_two = db_cast!(tmp, Party2EphKeyGenFirstMessage);

        let signature_with_recid = child_master_key.sign_second_message(
            &request.party_two_sign_message,
            &eph_key_gen_first_message_party_two,
            &eph_ec_key_pair_party1,
            &request.message,
        );

        match signature_with_recid {
            Ok(sig) => Ok(Json(sig)),
            Err(_) => {
                db_insert!(db, claim.sub, id, Abort, &Abort { blocked: true });
                Err(format!("sign_second failed for customer_id {}, id {}. Inserted into Abort table",  claim.sub, id))
            }
        }
    }

    async fn sign_first_v2(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        eph_key_gen_first_message_party_two: Json<Party2EphKeyGenFirstMessage>,
    ) -> Result<Json<(String, Party1EphKeyGenFirstMessage)>, String> {
        sign_first_helper(state, claim, id, eph_key_gen_first_message_party_two).await
    }

    async fn sign_second_v2(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        ssid: String,
        request: Json<Party2SignSecondMessage>,
    ) -> Result<Json<Party1SignatureRecid>, String> {
        let vector_request =  Party2SignSecondMessageVector {
            message: request.message.clone(),
            party_two_sign_message: request.party_two_sign_message.clone(),
            pos_child_key: vec![request.x_pos_child_key.clone(), request.y_pos_child_key.clone()],
        };

        sign_second_helper(state, claim, ssid, Json(vector_request)).await
    }

    async fn sign_first_v3(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        eph_key_gen_first_message_party_two: Json<Party2EphKeyGenFirstMessage>,
    ) -> Result<Json<(String, Party1EphKeyGenFirstMessage)>, String> {
        sign_first_helper(state, claim, id, eph_key_gen_first_message_party_two).await
    }

    async fn sign_second_v3(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        ssid: String,
        request: Json<Party2SignSecondMessageVector>,
    ) -> Result<Json<Party1SignatureRecid>, String> {
        sign_second_helper(state, claim, ssid, request).await
    }
}


async fn sign_first_helper(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: String,
    eph_key_gen_first_message_party_two: Json<Party2EphKeyGenFirstMessage>,
) -> Result<Json<(String, Party1EphKeyGenFirstMessage)>, String> {
    let db = state.lock().await;

    let tmp = db_get!(db, claim.sub, id, Abort)
        .unwrap_or(Box::new(Abort { blocked: false }));
    let to_abort = db_cast!(tmp, Abort);

    if to_abort.blocked == true {
        return Err(format!("customer_id {} exists in Abort table and thus is blocked", claim.sub.to_string()));
    }

    struct RedisCon {}
    impl RedisMod for RedisCon {}

    let mut connection = RedisCon::get_connection()?;

    let (sign_party_one_first_message, eph_ec_key_pair_party1) =
        MasterKey1::sign_first_message();

    let sid = Uuid::new_v4().to_string();
    let ssid = String::from(id + "," + &*sid);

    //write to redis db table as customerid_ssid_EphKeyGenFirstMsg:value
    let mut key: String = idify(&claim.sub, &ssid, &EcdsaStruct::EphKeyGenFirstMsg);
    if let Err(err) = RedisCon::set(&mut connection,
        &key.clone(),
        &serde_json::to_string(&eph_key_gen_first_message_party_two.0).unwrap(),
    ) {
        return Err(err);
    }

    //write to redis db table as customerid_ssid_EphEcKeyPair:value
    key = idify(&claim.sub, &ssid, &EcdsaStruct::EphEcKeyPair);
    if let Err(err) = RedisCon::set(&mut connection,
        &key.clone(),
        &serde_json::to_string(&eph_ec_key_pair_party1).unwrap(),
    ) {
        return Err(err);
    }

    Ok(Json((ssid.clone(), sign_party_one_first_message)))
}
async fn sign_second_helper(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    ssid: String,
    request: Json<Party2SignSecondMessageVector>,
) -> Result<Json<Party1SignatureRecid>, String> {
    let db = state.lock().await;
    if env::var("REDIS_ENV").is_ok() {
        if db.granted(request.message.to_hex().to_string().as_str(), claim.sub.as_str()) == Ok(false) {
            return Err(format!("Unauthorized transaction from redis-pps: {}", ssid));
        }
    }

    struct RedisCon {}
    impl RedisMod for RedisCon {}

    let mut connection = RedisCon::get_connection()?;

    let ssid_vec = ssid.split(",").collect::<Vec<_>>();
    if ssid_vec.len() != 2 {
        return Err("ssid must include only two values: id,sid".to_string());
    }

    let id: &str = ssid_vec[0];
    let sid: &str = ssid_vec[1];

    //get the master key for that userid
    let master_key = db_get_required!(db, claim.sub, id, Party1MasterKey, MasterKey1);
    // let master_key = db_cast!(tmp, MasterKey1);

    let child_master_key = master_key.get_child(request.pos_child_key.clone());

    let key1 = idify(&claim.sub, &ssid, &EcdsaStruct::EphEcKeyPair);
    let eph_ec_key_pair_party1 =
        serde_json::from_slice(
            &RedisCon::get(&mut connection, &key1)?.as_bytes()
        ).unwrap();

    let key2 = idify(&claim.sub, &ssid, &EcdsaStruct::EphKeyGenFirstMsg);
    let eph_key_gen_first_message_party2 =
        serde_json::from_slice(
            &RedisCon::get(&mut connection, &key2)?.as_bytes()
        ).unwrap();

    let _ = RedisCon::del(&mut connection, &key1);
    let _ = RedisCon::del(&mut connection, &key2);

    let signature_with_recid = child_master_key.sign_second_message(
        &request.party_two_sign_message,
        &eph_key_gen_first_message_party2,
        &eph_ec_key_pair_party1,
        &request.message,
    );

    match signature_with_recid {
        Ok(sig) => Ok(Json(sig)),
        Err(err) => {
            db_insert!(db, claim.sub, id, Abort, &Abort { blocked: true });
            Err(format!("sign_second failed for customer_id {}, ssid {}, id: {}, sid: {}. \
            Inserted into Abort table",  claim.sub, ssid, id, sid))
        }
    }
}