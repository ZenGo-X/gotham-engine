use crate::guarder::Claims;
use crate::traits::Db;
use crate::types::{DbIndex, EcdsaStruct};

use two_party_ecdsa::{BigInt, party_one, party_two};
use two_party_ecdsa::kms::ecdsa::two_party::{MasterKey1, party2};
use two_party_ecdsa::party_one::{CommWitness, v};

use rocket::serde::json::Json;
use rocket::{async_trait, State};
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize)]
pub struct SignSecondMsgRequest {
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
    pub x_pos_child_key: BigInt,
    pub y_pos_child_key: BigInt,
}
#[async_trait]
pub trait Sign {
    async fn sign_first(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        eph_key_gen_first_message_party_two: Json<party_two::EphKeyGenFirstMsg>,
    ) -> Result<Json<party_one::EphKeyGenFirstMsg>, String> {
        let db = state.lock().await;


        let abort = db.get(&DbIndex {
            customer_id: claim.sub.to_string(),
            id: id.clone(),
        }, &EcdsaStruct::Abort)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;
        let abort_res = abort.as_any().downcast_ref::<v>().unwrap();

        if abort_res.value == "true" {
            panic!("Tainted user");
        }

        let (sign_party_one_first_message, eph_ec_key_pair_party1) = MasterKey1::sign_first_message();

        db.insert(&DbIndex {
            customer_id: claim.sub.to_string(),
            id: id.clone(),
        },
                  &EcdsaStruct::EphKeyGenFirstMsg,
                  &eph_key_gen_first_message_party_two.0,
        )
            .await
            .or(Err("Failed to insert into db"))?;

        db.insert(&DbIndex {
            customer_id: claim.sub.to_string(),
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

        //: MasterKey1
        let master_key = db.get(&DbIndex {
            customer_id: claim.sub.to_string(),
            id: id.clone(),
        }, &EcdsaStruct::Party1MasterKey)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;

        let x: BigInt = request.x_pos_child_key.clone();
        let y: BigInt = request.y_pos_child_key.clone();

        let child_master_key = master_key.as_any().downcast_ref::<MasterKey1>().unwrap().get_child(vec![x, y]);

        //: party_one::EphEcKeyPair
        let eph_ec_key_pair_party1 =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::EphEcKeyPair)
                .await
                .or(Err("Failed to get from db"))?
                .ok_or(format!("No data for such identifier {}", id))?;

        //: party_two::EphKeyGenFirstMsg
        let eph_key_gen_first_message_party_two =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::EphKeyGenFirstMsg)
                .await
                .or(Err("Failed to get from db"))?
                .ok_or(format!("No data for such identifier {}", id))?;

        let signature_with_recid = child_master_key.sign_second_message(
            &request.party_two_sign_message,
            &eph_key_gen_first_message_party_two.as_any().downcast_ref::<party_two::EphKeyGenFirstMsg>().unwrap(),
            &eph_ec_key_pair_party1.as_any().downcast_ref::<party_one::EphEcKeyPair>().unwrap(),
            &request.message,
        );

        if signature_with_recid.is_err() {
            let value = v { value: "true".parse().unwrap() };
            println!("signature failed, user tainted[{:?}]", id);
            db.insert(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::Abort, &value)
                .await
                .or(Err("Failed to insert into db"))?;
            panic!("Server sign_second: validation of signature failed. Potential adversary")
        };

        Ok(Json(signature_with_recid.unwrap()))
    }
}
