use async_trait::async_trait;
use rocket::serde::json::Json;

use crate::{db_cast, db_get, db_get_required, db_insert};
use rocket::State;
use tokio::sync::Mutex;
use two_party_ecdsa::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use two_party_ecdsa::curv::elliptic::curves::traits::ECScalar;
use two_party_ecdsa::kms::ecdsa::two_party::MasterKey1;
use two_party_ecdsa::kms::rotation::two_party::party1::{RotateCommitMessage1 as RotateCommitMessage1Struct, Rotation1, RotationParty1Message1, RotationParty1ValidMessage1};
use two_party_ecdsa::kms::rotation::two_party::Rotation;
use two_party_ecdsa::{party_one, party_two};
use two_party_ecdsa::party_one::{Party1PDLDecommit, Party1Private};
use two_party_ecdsa::party_two::Party2PDLFirstMessage;
use crate::common::guarder::Claims;
use crate::common::Db;
use crate::ecdsa::server::Alpha;
use crate::ecdsa::server::EcdsaStruct::{Party1MasterKey, RotateAlpha, RotateCommitMessage1, RotateFirstMsg, RotateParty1Second, RotateParty2First, RotatePdlDecom, RotatePrivateNew, RotateRandom1};


#[async_trait]
pub trait Rotate {
    async fn rotate_first(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
    ) -> Result<Json<coin_flip_optimal_rounds::Party1FirstMessage>, String> {
        let db = state.lock().await;

        let (coin_flip_party1_first_message, rotate_commit_message) = Rotation1::key_rotate_first_message();

        db_insert!(
            db,
            None::<String>,
            Some(id.clone()),
            RotateCommitMessage1,
            &rotate_commit_message
        );

        Ok(Json(coin_flip_party1_first_message))
    }

    async fn rotate_second(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        coin_flip_party2_first: Json<coin_flip_optimal_rounds::Party2FirstMessage>,
    ) -> Result<Json<RotationParty1ValidMessage1>, String> {
        let db = state.lock().await;

        let rotate_commit_message = db_get_required!(db, None::<String>, Some(id.clone()), RotateCommitMessage1, RotateCommitMessage1Struct);

        let (coin_flip_party1_second, random1) =
            Rotation1::key_rotate_second_message(&coin_flip_party2_first.0, &rotate_commit_message);

        let party_one_master_key = db_get_required!(db, Some(claim.sub.clone()), Some(id.clone()), Party1MasterKey, MasterKey1);

        if !Party1Private::check_rotated_key_bounds(
            &party_one_master_key.private,
            &random1.rotation.to_big_int(),
        ) {
            return Ok(Json(
                RotationParty1ValidMessage1 {
                    coin_flip_party1_second_message: None,
                    rotation_party1_first_message: None,
                    is_valid: false,
                }
            ));
        }

        db_insert!(db, None::<String>, Some(id.clone()), RotateRandom1, &random1);

        let (rotation_party1_first, party_one_private_new) =
            party_one_master_key.rotation_first_message(&random1);

        db_insert!(db, None::<String>, Some(id.clone()), RotateFirstMsg, &rotation_party1_first);

        db_insert!(db, None::<String>, Some(id.clone()), RotatePrivateNew, &party_one_private_new);

        Ok(Json(
            RotationParty1ValidMessage1 {
                coin_flip_party1_second_message: Some(coin_flip_party1_second),
                rotation_party1_first_message: Some(rotation_party1_first),
                is_valid: true,
            }
        ))
    }

    async fn rotate_third(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        rotation_party_two_first: Json<Party2PDLFirstMessage>,
    ) -> Result<Json<party_one::Party1PDLFirstMessage>, String> {
        let db = state.lock().await;

        let rotate_party_one_private = db_get_required!(db, None::<String>, Some(id.clone()), RotatePrivateNew, Party1Private);

        let (rotation_party_one_second, party_one_pdl_decommit, party_one_alpha) =
            MasterKey1::rotation_second_message(
                &rotation_party_two_first,
                &rotate_party_one_private,
            );

        let party_one_alpha = Alpha {
            value: party_one_alpha,
        };

        db_insert!(db, None::<String>, Some(id.clone()), RotateAlpha, &party_one_alpha);

        db_insert!(db, None::<String>, Some(id.clone()), RotatePdlDecom, &party_one_pdl_decommit);

        db_insert!(
            db,
            None::<String>,
            Some(id.clone()),
            RotateParty2First,
            &rotation_party_two_first.0
        );

        db_insert!(
            db,
            None::<String>,
            Some(id.clone()),
            RotateParty1Second,
            &rotation_party_one_second
        );

        Ok(Json(rotation_party_one_second))
    }

    async fn rotate_forth(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        rotation_party_two_second: Json<party_two::Party2PDLSecondMessage>,
    ) -> Result<Json<party_one::Party1PDLSecondMessage>, String> {
        let db = state.lock().await;

        let rotation_party_one_first = db_get_required!(db, None::<String>, Some(id.clone()), RotateFirstMsg, RotationParty1Message1);

        let rotate_party_one_private = db_get_required!(db, None::<String>, Some(id.clone()), RotatePrivateNew, Party1Private);

        let random = db_get_required!(db, None::<String>, Some(id.clone()), RotateRandom1, Rotation);

        // let tmp = db_get_required!(db, None::<String>, Some(id.clone()), RotateParty1Second);
        // let rotation_party_one_second = db_cast!(tmp, party_one::PDLSecondMessage);

        let rotation_party_two_first = db_get_required!(db, None::<String>, Some(id.clone()), RotateParty2First, Party2PDLFirstMessage);

        let party_one_alpha = db_get_required!(db, None::<String>, Some(id.clone()), RotateAlpha, Alpha);

        let party_one_pdl_decommit = db_get_required!(db, None::<String>, Some(id.clone()), RotatePdlDecom, Party1PDLDecommit);

        let party_one_master_key_temp = db_get_required!(db, Some(claim.sub.clone()), Some(id.clone()), Party1MasterKey, MasterKey1);

        let party_one_master_key = party_one_master_key_temp.clone();

        let rotate_party_two_second = party_one_master_key.rotation_third_message(
            &rotation_party_one_first,
            rotate_party_one_private.clone(),
            &random,
            &rotation_party_two_first,
            &rotation_party_two_second.0,
            party_one_pdl_decommit.clone(),
            party_one_alpha.clone().value,
        );

        if rotate_party_two_second.is_err() {
            return Err(format!("rotation failed for customerId: {:?}, id: {:?}", Some(claim.sub.clone()), Some(id.clone())));
        }

        let (rotation_party_one_third, party_one_master_key_rotated) =
            rotate_party_two_second.unwrap();

        db_insert!(
            db,
            None::<String>,
            Some(id.clone()),
            Party1MasterKey,
            &party_one_master_key_rotated
        );

        Ok(Json(rotation_party_one_third))
    }
}
