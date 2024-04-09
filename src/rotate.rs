use async_trait::async_trait;
use rocket::serde::json::Json;

use crate::guarder::Claims;
use crate::traits::Db;
use crate::types::{Alpha, EcdsaStruct};
use crate::{db_cast, db_get, db_get_required, db_insert};
use rocket::State;
use tokio::sync::Mutex;
use two_party_ecdsa::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use two_party_ecdsa::curv::elliptic::curves::traits::ECScalar;
use two_party_ecdsa::kms::ecdsa::two_party::MasterKey1;
use two_party_ecdsa::kms::rotation::two_party::party1::{
    RotateCommitMessage1, Rotation1, RotationParty1Message1,
};
use two_party_ecdsa::kms::rotation::two_party::Rotation;
use two_party_ecdsa::{party_one, party_two};
use two_party_ecdsa::party_one::{Party1PDLDecommit, Party1Private};
use two_party_ecdsa::party_two::Party2PDLFirstMessage;

#[async_trait]
pub trait Rotate {
    async fn rotate_first(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
    ) -> Result<Json<coin_flip_optimal_rounds::Party1FirstMessage>, String> {
        let db = state.lock().await;

        let (party1_first, rotate_commit_message) = Rotation1::key_rotate_first_message();

        db_insert!(
            db,
            claim.sub,
            id,
            RotateCommitMessage1,
            &rotate_commit_message
        );

        Ok(Json(party1_first))
    }

    async fn rotate_second(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        coin_flip_party2_first: Json<coin_flip_optimal_rounds::Party2FirstMessage>,
    ) -> Result<
        Json<
            Option<(
                coin_flip_optimal_rounds::Party1SecondMessage,
                RotationParty1Message1,
            )>,
        >,
        String,
    > {
        let db = state.lock().await;

        let rotate_commit_message = db_get_required!(db, claim.sub, id, RotateCommitMessage1, RotateCommitMessage1);

        let (coin_flip_party1_second, random1) =
            Rotation1::key_rotate_second_message(&coin_flip_party2_first.0, &rotate_commit_message);

        let party_one_master_key = db_get_required!(db, claim.sub, id, Party1MasterKey, MasterKey1);

        if Party1Private::check_rotated_key_bounds(
            &party_one_master_key.private,
            &random1.rotation.to_big_int(),
        ) {
            // TODO: check if RotateCommitMessage1M and RotateCommitMessage1R need to be deleted
            return Ok(Json(None));
        }

        db_insert!(db, claim.sub, id, RotateRandom1, &random1);

        let (rotation_party_one_first, party_one_private_new) =
            party_one_master_key.rotation_first_message(&random1);

        db_insert!(db, claim.sub, id, RotateFirstMsg, &rotation_party_one_first);

        db_insert!(db, claim.sub, id, RotatePrivateNew, &party_one_private_new);

        Ok(Json(Some((
            coin_flip_party1_second,
            rotation_party_one_first,
        ))))
    }

    async fn rotate_third(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        rotation_party_two_first: Json<party_two::Party2PDLFirstMessage>,
    ) -> Result<Json<party_one::Party1PDLFirstMessage>, String> {
        let db = state.lock().await;

        let rotate_party_one_private = db_get_required!(db, claim.sub, id, RotatePrivateNew, Party1Private);

        let (rotation_party_one_second, party_one_pdl_decommit, party_one_alpha) =
            MasterKey1::rotation_second_message(
                &rotation_party_two_first,
                &rotate_party_one_private,
            );

        let party_one_alpha = Alpha {
            value: party_one_alpha,
        };

        db_insert!(db, claim.sub, id, RotateAlpha, &party_one_alpha);

        db_insert!(db, claim.sub, id, RotatePdlDecom, &party_one_pdl_decommit);

        db_insert!(
            db,
            claim.sub,
            id,
            RotateParty2First,
            &rotation_party_two_first.0
        );

        db_insert!(
            db,
            claim.sub,
            id,
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

        let rotation_party_one_first = db_get_required!(db, claim.sub, id, RotateFirstMsg, RotationParty1Message1);

        let rotate_party_one_private = db_get_required!(db, claim.sub, id, RotatePrivateNew, Party1Private);

        let random = db_get_required!(db, claim.sub, id, RotateRandom1, Rotation);

        // let tmp = db_get_required!(db, claim.sub, id, RotateParty1Second);
        // let rotation_party_one_second = db_cast!(tmp, party_one::PDLSecondMessage);

        let rotation_party_two_first = db_get_required!(db, claim.sub, id, RotateParty2First, Party2PDLFirstMessage);

        let party_one_alpha = db_get_required!(db, claim.sub, id, RotateAlpha, Alpha);

        let party_one_pdl_decommit = db_get_required!(db, claim.sub, id, RotatePdlDecom, Party1PDLDecommit);

        let party_one_master_key_temp = db_get_required!(db, claim.sub, id, Party1MasterKey, MasterKey1);

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
            return Err(format!("rotation failed for customerId: {}, id: {}", claim.sub, id));
        }

        let (rotation_party_one_third, party_one_master_key_rotated) =
            rotate_party_two_second.unwrap();

        db_insert!(
            db,
            claim.sub,
            id,
            Party1MasterKey,
            &party_one_master_key_rotated
        );

        Ok(Json(rotation_party_one_third))
    }
}
