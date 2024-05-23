use async_trait::async_trait;
use rocket::serde::json::Json;
use tokio::sync::Mutex;
use rocket::State;

use two_party_musig2_eddsa::keypair::KeyPair as MuSig2KeyPair;
use uuid::Uuid;
use crate::common::guarder::Claims;
use crate::common::Db;
use crate::common::DbIndex;
use crate::db_insert;
use crate::musig2::MuSig2Struct::KeyPair;


#[async_trait]
pub trait Commands {
    async fn keygen(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
    ) -> Result<Json<()>, String> {
    // ) -> Result<Json<(String, [u8; 32])>, String> {
        // let db = state.lock().await;
        // let (keypair, restore_secret) = MuSig2KeyPair::create();
        //
        // let id = Uuid::new_v4().to_string();
        // db_insert!(db, Some(claim.sub.clone()), Some(id.clone()), KeyPair, &keypair);
        // Ok(Json((id, keypair.pubkey())))
        Ok(Json(()))
    }
}