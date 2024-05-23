use async_trait::async_trait;
use rocket::serde::json::Json;
use tokio::sync::Mutex;
use rocket::State;

use two_party_musig2_eddsa::keypair::KeyPair;
use uuid::Uuid;
use crate::common::guarder::Claims;
use crate::common::Db;
use crate::common::DbIndex;


#[async_trait]
pub trait Commands {
    async fn keygen(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
    ) -> Result<Json<[u8; 32]>, String> {
        let db = state.lock().await;
        let (keypair, restore_secret) = KeyPair::create();

        let id = Uuid::new_v4().to_string();
        let index = DbIndex { customerId : Some(claim.sub), id: Some(id)} ;
        // db.insert(&index);
        /*
        match $db.insert(
            &$crate::ecdsa::server::types::DbIndex {
                customerId: $customer_id,
                id: $id,
            },
            &$crate::ecdsa::server::types::EcdsaStruct::$enum_ident,
            $new_value,
        )
            .await {
            Ok(_) => { },
            Err(err) => {
                let txt = format!("Failed to insert into {} with customerId: {:?}, id: {:?} with error:\n{}",
                    stringify!($enum_ident),
                    $customer_id,
                    $id,
                    err);
                println!("{}", txt);
                return Err(txt)
            }
        }
    };
        */
        Ok(Json(keypair.pubkey()))
    }
}