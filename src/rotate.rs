use async_trait::async_trait;
use rocket::serde::json::Json;
use rocket::State;
use tokio::sync::Mutex;
use two_party_ecdsa::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds::{CoinFlipParty1FirstMessage, CoinFlipParty1SecondMessage, CoinFlipParty2FirstMessage};
use two_party_ecdsa::curv::elliptic::curves::traits::ECScalar;
use two_party_ecdsa::kms::ecdsa::two_party::MasterKey1;
use two_party_ecdsa::kms::ecdsa::two_party::party1::RotationParty1Message1;
use crate::guarder::Claims;
use crate::traits::Db;
use two_party_ecdsa::kms::rotation::two_party::party1::Rotation1;
use two_party_ecdsa::party_one::Party1Private;
use two_party_ecdsa::Secp256k1Scalar;
use crate::db_get;
use crate::types::{DbIndex, EcdsaStruct};



#[async_trait]
pub trait Rotate {
    async fn rotate_first(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
    ) -> Result<Json<CoinFlipParty1FirstMessage>, String>{
        let db = state.lock().await;

        let (party1_first_message, m1, r1) = Rotation1::key_rotate_first_message();

        db.insert(
            &DbIndex {
                customerId: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::RotateFirstMsg,
            &party1_first_message,
        )
            .await
            .or(Err("Failed to insert into db"))?;

        db.insert(
            &DbIndex {
                customerId: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::RotateCommitMessage1M,
            &m1,
        )
            .await
            .or(Err("Failed to insert into db"))?;

        db.insert(
            &DbIndex {
                customerId: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::RotateCommitMessage1R,
            &r1,
        )
            .await
            .or(Err("Failed to insert into db"))?;

        Ok(Json(party1_first_message))
    }




    async fn rotate_second(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        coin_flip_party2_first_message: Json<CoinFlipParty2FirstMessage>,
    ) -> Result<Json<(CoinFlipParty1SecondMessage, RotationParty1Message1)>, String>{
        let db = state.lock().await;



        // let m1 = db
        //     .get(
        //         &DbIndex {
        //             customerId: claim.sub.to_string(),
        //             id: id.clone(),
        //         },
        //         &EcdsaStruct::RotateCommitMessage1M
        //     )
        //     .await
        //     .or(Err("Failed to get from db"))?
        //     .ok_or(format!("No data for such identifier {}", id))?;

        let m1 = db_get!(db, claim.sub.to_string(), id.clone(), RotateCommitMessage1M);
        let m1 = m1.as_any().downcast_ref::<Secp256k1Scalar>().unwrap();

        // let r1 = db
        //     .get(
        //         &DbIndex {
        //             customerId: claim.sub.to_string(),
        //             id: id.clone(),
        //         },
        //         &EcdsaStruct::RotateCommitMessage1R
        //     )
        //     .await
        //     .or(Err("Failed to get from db"))?
        //     .ok_or(format!("No data for such identifier {}", id))?;

        let r1 = db_get!(db, claim.sub.to_string(), id.clone(), RotateCommitMessage1R);
        let r1 = r1.as_any().downcast_ref::<Secp256k1Scalar>().unwrap();


        let (coin_flip_party1_second_message, mut random) =
            Rotation1::key_rotate_second_message(&coin_flip_party2_first_message, &m1, &r1);

        let party_one_master_key = db
            .get(
                &DbIndex {
                    customerId: claim.sub.to_string(),
                    id: id.clone(),
                },
                &EcdsaStruct::Party1MasterKey
            )
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;

        let party_one_master_key: MasterKey1 = party_one_master_key
            .as_any().downcast_ref::<MasterKey1>().unwrap().clone();

        if !Party1Private::check_rotated_key_bounds(&party_one_master_key.private, &random.rotation.to_big_int()) {
            return Err("".to_string());
        }

        db.insert(
            &DbIndex {
                customerId: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::RotateRandom1,
            &random,
        )
            .await
            .or(Err("Failed to insert into db"))?;


        let (rotation_party_one_first_message, party_one_master_key_rotated) =
            party_one_master_key.rotation_first_message(&random);


        Ok(Json((coin_flip_party1_second_message, rotation_party_one_first_message)))
    }
}