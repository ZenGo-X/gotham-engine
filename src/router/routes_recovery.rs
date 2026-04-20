use rocket::{get, post, http::Status, State};
use rocket::serde::{json::Json};

use rocket::response::status;
use rocket::response::status::Custom;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;
use log::error;
use log::info;
use std::time::Instant;

use two_party_ecdsa::curv::arithmetic::traits::Converter;
use two_party_ecdsa::curv::elliptic::curves::traits::ECPoint;
use two_party_ecdsa::curv::BigInt;
use two_party_ecdsa::curv::GE;
use two_party_ecdsa::{Helgamal, Helgamalsegmented, Witness};
use two_party_ecdsa::party_one::{Party1Private};
use two_party_ecdsa::kms::ecdsa::two_party::MasterKey1;

use crate::db_get_required;

#[derive(Deserialize)]
pub struct EncryptRequest {
    pub customer_id: String,
    pub master_key_id: String,
    pub rsa_pubkey_asn: String,
}

#[derive(Serialize)]
pub struct EncryptResponse {
    pub witness: Witness,
    pub helgamalsegmented: Helgamalsegmented,
}

use crate::traits::Db;
use crate::guarder::Claims;

#[post("/recovery/encrypt", format = "json", data = "<req>")]
pub async fn wrap_ecdsa_encrypt_route(
    state: &State<Mutex<Box<dyn Db>>>,
    req: Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>, String> {
    info!(
        "[recovery/encrypt] Incoming request: customer_id={}, master_key_id={}",
        req.customer_id, req.master_key_id
    );

    let db = state.lock().await;

    info!(
        "[recovery/encrypt] Attempting to fetch Party1Private from DB with master_key_id={}",
        req.master_key_id
    );
    let party_one_private: Party1Private = db_get_required!(
        db,
        None::<String>,
        Some(req.master_key_id.clone()),
        Party1Private,
        Party1Private
    );

    info!(
        "[recovery/encrypt] Retrieved master key share (x1 prefix)"
    );

    info!(
        "[recovery/encrypt] Parsed RSA ASN hex ({} chars): {}",
        req.rsa_pubkey_asn.len(),
        &req.rsa_pubkey_asn
    );

    let segment_size = 8;
    let num_segments = 32;
    let g = GE::generator();

    let y_bn = BigInt::from_str_radix(&req.rsa_pubkey_asn, 16).map_err(|e| {
        let msg = format!("[recovery/encrypt] Invalid public key hex (ASN): {}", e);
        error!("{}", msg);
        msg
    })?;

    let y_vec = BigInt::to_vec(&y_bn);

    info!("[recovery/encrypt] BigInt Y bytes: {:?}", &y_vec);

    let y = GE::from_bytes(&y_vec).map_err(|e| {
        let msg = format!("[recovery/encrypt] Failed to construct GE point from bytes: {:?}", e);
        error!("{}", msg);
        msg
    })?;

    let (witness, encrypted) = party_one_private.to_encrypted_segment(
        &segment_size,
        num_segments,
        &y,
        &g,
    );

    // Log the structure of the encrypted payload
    info!(
        "[recovery/encrypt] Encryption complete.\nWitness.x_vec.len = {}\nWitness.r_vec.len = {}\nEncrypted segments (DE.len) = {}",
        witness.x_vec.len(),
        witness.r_vec.len(),
        encrypted.DE.len()
    );
    if let Some(first) = encrypted.DE.first() {
        let d_x_preview = first.D.x_coor()
            .map(|x| x.to_hex().chars().take(12).collect::<String>())
            .unwrap_or_else(|| "<none>".to_string());

        let e_x_preview = first.E.x_coor()
            .map(|x| x.to_hex().chars().take(12).collect::<String>())
            .unwrap_or_else(|| "<none>".to_string());

        info!(
            "[recovery/encrypt] First encrypted segment: D.x={}..., E.x={}...",
            d_x_preview,
            e_x_preview
        );
    }

    Ok(Json(EncryptResponse {
        witness,
        helgamalsegmented: encrypted,
    }))
}


// needs to add getter to Party1Private in two_party_ecdsa proj 
// two_party_ecdsa/src/party_one/mod.rs
// Log extracted secret share
// let x1_preview = party_one_private
//     .x1
//     .to_hex()
//     .chars()
//     .take(12)
//     .collect::<String>();