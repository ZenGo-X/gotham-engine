use async_trait::async_trait;
use rocket::serde::json::Json;

use crate::guarder::Claims;
use crate::traits::Db;
use crate::types::EcdsaStruct;
use crate::{db_cast, db_get, db_insert};
use rocket::State;
use tokio::sync::Mutex;
use two_party_ecdsa::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use two_party_ecdsa::curv::elliptic::curves::traits::ECScalar;
use two_party_ecdsa::kms::ecdsa::two_party::party1::RotationParty1Message1;
use two_party_ecdsa::kms::ecdsa::two_party::MasterKey1;
use two_party_ecdsa::kms::rotation::two_party::party1::Rotation1;
use two_party_ecdsa::{party_one, party_two, Secp256k1Scalar};

// https://github.com/ZenGo-X/gotham-city/blob/a762b3c13a2aa64f09c25e20e9b5a72d09078f01/gotham-server/src/routes/ecdsa.rs#L353
// https://github.com/ZenGo-X/gotham-city/blob/a762b3c13a2aa64f09c25e20e9b5a72d09078f01/gotham-client/src/ecdsa/rotate.rs
#[async_trait]
pub trait Rotate {
    async fn rotate_first(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
    ) -> Result<Json<coin_flip_optimal_rounds::Party1FirstMessage>, String> {
        let db = state.lock().await;

        let (party1_first_message, m1, r1) = Rotation1::key_rotate_first_message();

        db_insert!(db, claim.sub, id, RotateCommitMessage1R, m1);

        db_insert!(db, claim.sub, id, RotateCommitMessage1R, r1);

        Ok(Json(party1_first_message))
    }

    async fn rotate_second(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        coin_flip_party2_first_message: Json<coin_flip_optimal_rounds::Party2FirstMessage>,
    ) -> Result<Json<Option<(coin_flip_optimal_rounds::Party1SecondMessage, RotationParty1Message1)>>, String> {
        let db = state.lock().await;

        let m1 = db_get!(db, claim.sub, id, RotateCommitMessage1M);
        let m1 = db_cast!(m1, Secp256k1Scalar);

        let r1 = db_get!(db, claim.sub, id, RotateCommitMessage1R);
        let r1 = db_cast!(r1, Secp256k1Scalar);

        let (coin_flip_party1_second_message, random) =
            Rotation1::key_rotate_second_message(&coin_flip_party2_first_message.0, &m1, &r1);

        let party_one_master_key = db_get!(db, claim.sub, id, Party1MasterKey);
        let party_one_master_key_temp = db_cast!(party_one_master_key, MasterKey1);
        let party_one_master_key = party_one_master_key_temp.clone();

        if !party_one::Party1Private::check_rotated_key_bounds(
            &party_one_master_key_temp.private,
            &random.rotation.to_big_int(),
        ) {
            // TODO: check if RotateCommitMessage1M and RotateCommitMessage1R need to be deleted
            return Ok(Json(None));
        }

        db_insert!(db, claim.sub, id, RotateRandom1, random);

        let (rotation_party_one_first_message, party_one_private_new) =
            party_one_master_key.rotation_first_message(&random);

        db_insert!(
            db,
            claim.sub,
            id,
            RotateFirstMsg,
            rotation_party_one_first_message
        );

        db_insert!(db, claim.sub, id, RotatePrivateNew, party_one_private_new);

        Ok(Json(Some((
            coin_flip_party1_second_message,
            rotation_party_one_first_message,
        ))))
    }

    async fn rotate_third(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        rotation_party_two_first_message: Json<party_two::PDLFirstMessage>,
    ) -> Result<Json<party_one::PDLFirstMessage>, String> {
        let db = state.lock().await;

        let party_one_private_new = db_get!(db, claim.sub, id, RotatePrivateNew);
        let party_one_private_new = db_cast!(party_one_private_new, party_one::Party1Private);

        let (rotation_party_one_second_message, party_one_pdl_decommit, alpha) =
            MasterKey1::rotation_second_message(
                &rotation_party_two_first_message,
                &party_one_private_new,
            );

        db_insert!(db, claim.sub, id, RotatePdlDecom, party_one_pdl_decommit);

        db_insert!(db, claim.sub, id, RotateParty2First, rotation_party_two_first_message.0);

        db_insert!(db, claim.sub, id, RotateParty1Second, rotation_party_one_second_message);

        Ok(Json(rotation_party_one_second_message))
    }
}
