use async_trait::async_trait;
use hex::FromHexError;
use rocket::serde::json::Json;
use tokio::sync::Mutex;
use rocket::State;
use two_party_musig2_eddsa::aggregate::AggPublicKeyAndMusigCoeff as AggPublicKeyAndMusigCoeffStruct;

use two_party_musig2_eddsa::keypair::{KeyPair as MuSig2KeyPair, KeyPair};
use two_party_musig2_eddsa::partial_sig::PartialSignature;
use two_party_musig2_eddsa::private_partial_nonces::PrivatePartialNonces;
use two_party_musig2_eddsa::public_partial_nonces::PublicPartialNonces;

use uuid::Uuid;
use crate::common::guarder::Claims;
use crate::common::Db;
use crate::common::DbIndex;
use crate::{db_get_required, db_insert};
use crate::musig2::MuSig2Struct::{AggPublicKeyAndMusigCoeff, AggregatedNonce, Party1KeyPair, Party1PrivatePartialNonces, Party1PublicPartialNonces, Party2PublicPartialNonces};

pub type PublicKeyCompressedEdwardsY = [u8; 32];
pub type MessageSlice = [u8];
pub type CompressedPublicPartialNonces = [u8; 64];
#[async_trait]
pub trait Commands {
    async fn keygen(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        client_pubkey: PublicKeyCompressedEdwardsY,
    ) -> Result<(String, PublicKeyCompressedEdwardsY), String> {
        let db = state.lock().await;
        let (keypair, restore_secret) = MuSig2KeyPair::create();

        let id = Uuid::new_v4().to_string();
        db_insert!(db, Some(claim.sub.clone()), Some(id.clone()), Party1KeyPair, &keypair);

        let agg_pubkey =
            AggPublicKeyAndMusigCoeffStruct::aggregate_public_keys(keypair.pubkey(), client_pubkey)
                .map_err(|_| "Received an invalid public key")?;

        db_insert!(db, Some(claim.sub.clone()), Some(id.clone()), AggPublicKeyAndMusigCoeff, &agg_pubkey);

        Ok((id, keypair.pubkey()))
    }

    async fn sign_first(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        compressed_client_public_nonces: CompressedPublicPartialNonces,
     ) -> Result<CompressedPublicPartialNonces, String> {
        let db = state.lock().await;

        let keypair = db_get_required!(db, Some(claim.sub.clone()), Some(id.clone()), Party1KeyPair, KeyPair);

        let (private_nonces, public_nonces) = keypair.generate_partial_nonces(None);

        let client_public_nonces = PublicPartialNonces::deserialize(compressed_client_public_nonces).unwrap();

        db_insert!(db, Some(claim.sub.clone()), Some(id.clone()), Party1PrivatePartialNonces, &private_nonces);
        db_insert!(db, Some(claim.sub.clone()), Some(id.clone()), Party1PublicPartialNonces, &public_nonces);
        db_insert!(db, Some(claim.sub.clone()), Some(id.clone()), Party2PublicPartialNonces, &client_public_nonces);

        let compressed_public_nonces = PublicPartialNonces::serialize(&public_nonces);

        Ok(compressed_public_nonces)
    }

    async fn sign_second(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        message: &MessageSlice,
    ) -> Result<PartialSignature, String> {
        let db = state.lock().await;

        let keypair = db_get_required!(db, Some(claim.sub.clone()), Some(id.clone()), Party1KeyPair, KeyPair);
        let agg_pubkey = db_get_required!(db, Some(claim.sub.clone()), Some(id.clone()), AggPublicKeyAndMusigCoeff, AggPublicKeyAndMusigCoeffStruct);

        let private_nonces = db_get_required!(db, Some(claim.sub.clone()), Some(id.clone()), Party1PrivatePartialNonces, PrivatePartialNonces);
        let public_nonces = db_get_required!(db, Some(claim.sub.clone()), Some(id.clone()), Party1PublicPartialNonces, PublicPartialNonces);
        let client_public_nonces = db_get_required!(db, Some(claim.sub.clone()), Some(id.clone()), Party2PublicPartialNonces, PublicPartialNonces);

        let (partial_sig, agg_nonce) = keypair.partial_sign(
            private_nonces,
            [public_nonces, client_public_nonces],
            &agg_pubkey,
            message,
        );

        db_insert!(db, Some(claim.sub.clone()), Some(id.clone()), AggregatedNonce, &agg_nonce);

        Ok(partial_sig)

    }
}