use async_trait::async_trait;
use rocket::serde::json::Json;
use rocket::State;
use tokio::sync::Mutex;
use two_party_ecdsa::BigInt;
use two_party_ecdsa::kms::ecdsa::two_party::MasterKey1;
use crate::types::EcdsaStruct;
use crate::db_get_required;
use crate::guarder::Claims;
use crate::traits::Db;

#[async_trait]
pub trait Derive {
    async fn first(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        request: Json<Vec<BigInt>>) ->  Result<Json<MasterKey1>, String> {
        let db = state.lock().await;

        //get the master key for that userid
        let master_key = db_get_required!(db, claim.sub, id, Party1MasterKey, MasterKey1);
        // let master_key = db_cast!(tmp, MasterKey1);

        let child_master_key = master_key.get_child(request.0);

        Ok(Json(child_master_key))
    }
}