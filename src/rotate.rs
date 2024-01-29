use async_trait::async_trait;
use rocket::serde::json::Json;

use crate::guarder::Claims;
use crate::traits::Db;
use crate::types::{Alpha, EcdsaStruct};
use crate::{db_cast, db_get, db_insert};
use rocket::State;
use tokio::sync::Mutex;
use two_party_ecdsa::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use two_party_ecdsa::curv::elliptic::curves::traits::ECScalar;
use two_party_ecdsa::kms::ecdsa::two_party::party1::RotationParty1Message1;
use two_party_ecdsa::kms::ecdsa::two_party::MasterKey1;
use two_party_ecdsa::kms::rotation::two_party::party1::Rotation1;
use two_party_ecdsa::{BigInt, party_one, party_two, Secp256k1Scalar};
use two_party_ecdsa::kms::rotation::two_party::Rotation;

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

        let (party1_first, m1, r1) = Rotation1::key_rotate_first_message();

        db_insert!(db, claim.sub, id, RotateCommitMessage1R, m1);

        db_insert!(db, claim.sub, id, RotateCommitMessage1R, r1);

        Ok(Json(party1_first))
    }

    async fn rotate_second(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        coin_flip_party2_first: Json<coin_flip_optimal_rounds::Party2FirstMessage>,
    ) -> Result<Json<Option<(coin_flip_optimal_rounds::Party1SecondMessage, RotationParty1Message1)>>, String> {
        let db = state.lock().await;

        let tmp = db_get!(db, claim.sub, id, RotateCommitMessage1M);
        let m1 = db_cast!(tmp, Secp256k1Scalar);

        let tmp = db_get!(db, claim.sub, id, RotateCommitMessage1R);
        let r1 = db_cast!(tmp, Secp256k1Scalar);

        let (coin_flip_party1_second, random) =
            Rotation1::key_rotate_second_message(&coin_flip_party2_first.0, &m1, &r1);

        let mk_tmp = db_get!(db, claim.sub, id, Party1MasterKey);
        let party_one_master_key_temp = db_cast!(mk_tmp, MasterKey1);
        let party_one_master_key = party_one_master_key_temp.clone();

        if !party_one::Party1Private::check_rotated_key_bounds(
            &party_one_master_key_temp.private,
            &random.rotation.to_big_int(),
        ) {
            // TODO: check if RotateCommitMessage1M and RotateCommitMessage1R need to be deleted
            return Ok(Json(None));
        }

        db_insert!(db, claim.sub, id, RotateRandom1, random);

        let (rotation_party_one_first, party_one_private_new) =
            party_one_master_key.rotation_first_message(&random);

        db_insert!(db, claim.sub, id, RotateFirstMsg, rotation_party_one_first);

        db_insert!(db, claim.sub, id, RotatePrivateNew, party_one_private_new);

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

        let tmp = db_get!(db, claim.sub, id, RotatePrivateNew);
        let rotate_party_one_private = db_cast!(tmp, party_one::Party1Private);

        let (rotation_party_one_second, party_one_pdl_decommit, party_one_alpha) =
            MasterKey1::rotation_second_message(
                &rotation_party_two_first,
                &rotate_party_one_private,
            );

        let party_one_alpha = Alpha { value: party_one_alpha,  };

        db_insert!(db, claim.sub, id, RotateAlpha, party_one_alpha);

        db_insert!(db, claim.sub, id, RotatePdlDecom, party_one_pdl_decommit);

        db_insert!(db, claim.sub, id, RotateParty2First, rotation_party_two_first.0);

        db_insert!(db, claim.sub, id, RotateParty1Second, rotation_party_one_second);

        Ok(Json(rotation_party_one_second))
    }

    async fn rotate_forth(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        rotation_party_two_second: Json<party_two::Party2PDLSecondMessage>,
    ) -> Result<Json<(party_one::Party1PDLSecondMessage)>, String> {
        let db = state.lock().await;

        let tmp = db_get!(db, claim.sub, id, RotateFirstMsg);
        let rotation_party_one_first =
            db_cast!(tmp, RotationParty1Message1);

        let tmp = db_get!(db, claim.sub, id, RotatePrivateNew);
        let rotate_party_one_private = db_cast!(tmp, party_one::Party1Private);

        let tmp = db_get!(db, claim.sub, id, RotateRandom1);
        let random = db_cast!(tmp, Rotation);

        // let tmp = db_get!(db, claim.sub, id, RotateParty1Second);
        // let rotation_party_one_second = db_cast!(tmp, party_one::PDLSecondMessage);

        let tmp = db_get!(db, claim.sub, id, RotateParty2First);
        let rotation_party_two_first = db_cast!(tmp, party_two::Party2PDLFirstMessage);

        let tmp = db_get!(db, claim.sub, id, RotateAlpha);
        let party_one_alpha = db_cast!(tmp, Alpha);

        let tmp = db_get!(db, claim.sub, id, RotatePdlDecom);
        let party_one_pdl_decommit = db_cast!(tmp, party_one::Party1PDLDecommit);

        let mk_tmp = db_get!(db, claim.sub, id, Party1MasterKey);
        let party_one_master_key_temp = db_cast!(mk_tmp, MasterKey1);
        let party_one_master_key = party_one_master_key_temp.clone();

        let rotate_party_two_second = party_one_master_key.rotation_third_message(
            rotation_party_one_first,
            rotate_party_one_private.clone(),
            random,
            rotation_party_two_first,
            &rotation_party_two_second.0,
            party_one_pdl_decommit.clone(),
            party_one_alpha.clone().value
        );

        if rotate_party_two_second.is_err() {
            panic!("rotation failed for customerId: {}, id: {}", claim.sub, id);
        }

        let (rotation_party_one_third, party_one_master_key_rotated) =
            rotate_party_two_second.unwrap();

        db_insert!(db, claim.sub, id, Party1MasterKey, party_one_master_key_rotated);

        Ok(Json(rotation_party_one_third))
    }
}
