use async_trait::async_trait;
use rocket::serde::json::Json;
use tokio::sync::Mutex;
use rocket::State;
use two_party_musig2_eddsa::aggregate::AggPublicKeyAndMusigCoeff as AggPublicKeyAndMusigCoeffStruct;

use two_party_musig2_eddsa::keypair::{KeyPair as MuSig2KeyPair, KeyPair};
use two_party_musig2_eddsa::public_partial_nonces::PublicPartialNonces;

use uuid::Uuid;
use crate::common::guarder::Claims;
use crate::common::Db;
use crate::common::DbIndex;
use crate::{db_get_required, db_insert};
use crate::musig2::MuSig2Struct::{AggPublicKeyAndMusigCoeff, Party1KeyPair, Party1PrivatePartialNonces, Party1PublicPartialNonces, Party2PublicPartialNonces};

pub type PubkeyCompressedEdwardsY = [u8; 32];
pub type MessageSlice = [u8];


#[async_trait]
pub trait Commands {
    async fn keygen(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        client_pubkey: PubkeyCompressedEdwardsY,
    ) -> Result<Json<(String, PubkeyCompressedEdwardsY)>, String> {
        let db = state.lock().await;
        let (keypair, restore_secret) = MuSig2KeyPair::create();

        let id = Uuid::new_v4().to_string();
        db_insert!(db, Some(claim.sub.clone()), Some(id.clone()), Party1KeyPair, &keypair);

        let agg_pubkey =
            AggPublicKeyAndMusigCoeffStruct::aggregate_public_keys(keypair.pubkey(), client_pubkey)
                .map_err(|_| "Received an invalid public key")?;

        db_insert!(db, Some(claim.sub.clone()), Some(id.clone()), AggPublicKeyAndMusigCoeff, &agg_pubkey);

        Ok(Json((id, keypair.pubkey())))
    }

    async fn sign_first(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        client_public_nonces: PublicPartialNonces,
    ) -> Result<Json<(PublicPartialNonces)>, String> {
        let db = state.lock().await;

        let keypair = db_get_required!(db, Some(claim.sub.clone()), Some(id.clone()), Party1KeyPair, KeyPair);

        let (private_nonces, public_nonces) = keypair.generate_partial_nonces(None);

        db_insert!(db, Some(claim.sub.clone()), Some(id.clone()), Party1PrivatePartialNonces, &private_nonces);
        db_insert!(db, Some(claim.sub.clone()), Some(id.clone()), Party1PublicPartialNonces, &public_nonces);
        db_insert!(db, Some(claim.sub.clone()), Some(id.clone()), Party2PublicPartialNonces, &client_public_nonces);

        Ok(Json(public_nonces))
    }

    async fn sign_second(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        message: &MessageSlice,
    // ) -> Result<Json<(PartialSignature)>, String> {
    ) -> Result<Json<()>, String> {

        let db = state.lock().await;

        let keypair = db_get_required!(db, Some(claim.sub.clone()), Some(id.clone()), Party1KeyPair, KeyPair);
        let agg_pubkey = db_get_required!(db, Some(claim.sub.clone()), Some(id.clone()), AggPublicKeyAndMusigCoeff, AggPublicKeyAndMusigCoeffStruct);


        Ok(Json(()))

    }
}