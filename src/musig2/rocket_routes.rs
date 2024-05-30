use hex::FromHexError;
use rocket::{post, State};
use rocket::serde::json::Json;
use tokio::sync::Mutex;
use two_party_musig2_eddsa::partial_sig::PartialSignature;
use crate::common::Db;
use crate::common::guarder::Claims;
use crate::musig2::server::Commands;

#[post("/musig2/keygen", format = "json", data = "<client_pubkey>")]
pub async fn wrap_musig2_keygen(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    client_pubkey: Json<[u8; 32]>
) -> Result<Json<(String, [u8; 32])>, String> {
    println!("/musig2/keygen | {:?}", claim);
    struct Gotham {}
    impl Commands for Gotham {}
    let result = Gotham::keygen(state, claim, client_pubkey.0).await;
    match result {
        Ok(res) => Ok(Json(res)),
        Err(err) => Err(err)
    }
}


#[post("/musig2/sign/<id>/first", format = "json", data = "<client_public_nonces_hex>")]
pub async fn wrap_musig2_sign_first(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: String,
    client_public_nonces_hex: Json<String>,
) -> Result<Json<String>, String> {
    println!("/musig2/sign/{}/first | {:?}", id, claim);

    let mut client_public_nonces_slice = [0u8; 64];
    match hex::decode_to_slice(client_public_nonces_hex.0,
                         &mut client_public_nonces_slice as &mut [u8]) {
        Ok(_) => {}
        Err(err) =>  { return Err(err.to_string()) }
    }

    struct Gotham {}
    impl Commands for Gotham {}
    let result = Gotham::sign_first(state, claim, id, client_public_nonces_slice).await;
    match result {
        Ok(slice) => {
            Ok(Json(hex::encode(slice)))
        },
        Err(err) => Err(err)
    }
}


#[post("/musig2/sign/<id>/second", format = "json", data = "<message_hex>")]
pub async fn wrap_musig2_sign_second(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: String,
    message_hex: Json<String>,
) -> Result<Json<String>, String> {
    println!("/musig2/sign/{}/second | {:?}", id, claim);
    struct Gotham {}
    impl Commands for Gotham {}

    let decoded_message = hex::decode(message_hex.0).map_err(|err| err.to_string())?;
    let message = decoded_message.as_slice();

    match Gotham::sign_second(state, claim, id, message).await {
        Ok(partial_sig) =>  Ok(Json(hex::encode(partial_sig.serialize()))),
        Err(err) => Err(err)
    }
}
