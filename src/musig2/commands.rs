use async_trait::async_trait;
use rocket::serde::json::Json;
use tokio::sync::Mutex;
use rocket::State;

use two_party_musig2_eddsa::keypair::KeyPair;
use crate::common::guarder::Claims;
use crate::common::traits::Db;


#[async_trait]
pub trait Commands {
    async fn keygen(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
    ) -> Result<Json<[u8; 32]>, String> {
        let db = state.lock().await;
        let (keypair, restore_secret) = KeyPair::create();

        Ok(Json(keypair.pubkey()))
    }
}