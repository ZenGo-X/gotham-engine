use async_trait::async_trait;
use rocket::serde::json::Json;
use rocket::State;
use tokio::sync::Mutex;
use two_party_ecdsa::BigInt;
use two_party_ecdsa::kms::ecdsa::two_party::MasterKey1;
use crate::common::Db;
use crate::db_get_required;
use crate::server::EcdsaStruct::Party1MasterKey;


#[async_trait]
pub trait Derive {
    async fn first(
        state: &State<Mutex<Box<dyn Db>>>,
        // claims: Claims,
        id: String,
        request: Json<Vec<i64>>) ->  Result<Json<MasterKey1>, String> {
        let db = state.lock().await;

        // get the master key for that id
        // customerId is not required as Claims are not passed to this endpoint)
        let master_key = db_get_required!(db, None::<String>, Some(id.clone()), Party1MasterKey, MasterKey1);

        let derivation_vector = request.0.iter().map(|&x| BigInt::from(x)).collect();

        let child_master_key = master_key.get_child(derivation_vector);

        Ok(Json(child_master_key))
    }
}