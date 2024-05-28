use rocket::{post, State};
use rocket::serde::json::Json;
use tokio::sync::Mutex;
use two_party_musig2_eddsa::partial_sig::PartialSignature;
use crate::common::Db;
use crate::common::guarder::Claims;
use crate::musig2::server::{Commands, CompressedPublicPartialNonces, MessageSlice, PublicKeyCompressedEdwardsY};

#[post("/musig2/keygen", format = "json", data = "<client_pubkey>")]
pub async fn wrap_musig2_keygen(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    client_pubkey: Json<PublicKeyCompressedEdwardsY>
) -> Result<Json<(String, PublicKeyCompressedEdwardsY)>, String> {
    println!("/musig2/keygen | {:?}", claim);
    struct Gotham {}
    impl Commands for Gotham {}
    Gotham::keygen(state, claim, client_pubkey).await
}

#[post("/musig2/sign/<id>/first", format = "json", data = "<compressed_client_public_nonces>")]
pub async fn wrap_musig2_sign_first(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: String,
    compressed_client_public_nonces: Json<CompressedPublicPartialNonces>,
) -> Result<Json<CompressedPublicPartialNonces>, String> {
    println!("/musig2/sign/{}/first | {:?}", id, claim);
    struct Gotham {}
    impl Commands for Gotham {}
    Gotham::sign_first(state, claim, id, compressed_client_public_nonces).await
}

#[post("/musig2/sign/<id>/second", format = "json", data = "<message>")]
pub async fn wrap_musig2_sign_second(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: String,
    message: Json<&MessageSlice>,
) -> Result<Json<PartialSignature>, String> {
    println!("/musig2/sign/{}/second | {:?}", id, claim);
    struct Gotham {}
    impl Commands for Gotham {}
    Gotham::sign_second(state, claim, id, message).await
}