//! The routes that gotham-engine exposes. Notice that these are actually wrappers on the underlying implementations due
//! to the fact that rockets http server does not allow to mount directly routes as trait functions.

use crate::guarder::Claims;
use crate::keygen::KeyGen;
use crate::sign::Sign;
use crate::traits::Db;

use two_party_ecdsa::party_one::{Party1KeyGenFirstMessage, Party1KeyGenSecondMessage, DLogProof, Party1EphKeyGenFirstMessage, SignatureRecid, Party1PDLFirstMessage, Party1PDLSecondMessage};
use two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::{DHPoKParty1FirstMessage, DHPoKParty1SecondMessage};

use crate::rotate::Rotate;
use rocket::serde::json::Json;
use rocket::{get, http::Status, post, State};
use tokio::sync::Mutex;
use two_party_ecdsa::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use two_party_ecdsa::kms::ecdsa::two_party::party2::Party2SignSecondMessage;
use two_party_ecdsa::kms::rotation::two_party::party1::RotationParty1Message1;
use two_party_ecdsa::party_two::{
    Party2EphKeyGenFirstMessage, Party2PDLFirstMessage, Party2PDLSecondMessage,
};

#[post("/ecdsa/keygen_v2/first", format = "json")]
pub async fn wrap_keygen_first(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
) -> Result<Json<(String, Party1KeyGenFirstMessage)>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::first(state, claim).await
}

#[post("/ecdsa/keygen_v2/<id>/second", format = "json", data = "<dlog_proof>")]
pub async fn wrap_keygen_second(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: &str,
    dlog_proof: Json<DLogProof>,
) -> Result<Json<Party1KeyGenSecondMessage>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::second(state, claim, id.to_string(), dlog_proof).await
}

#[post(
    "/ecdsa/keygen_v2/<id>/third",
    format = "json",
    data = "<party_2_pdl_first_message>"
)]
pub async fn wrap_keygen_third(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: &str,
    party_2_pdl_first_message: Json<Party2PDLFirstMessage>,
) -> Result<Json<Party1PDLFirstMessage>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::third(state, claim, id.to_string(), party_2_pdl_first_message).await
}

#[post(
    "/ecdsa/keygen_v2/<id>/fourth",
    format = "json",
    data = "<party_two_pdl_second_message>"
)]
pub async fn wrap_keygen_fourth(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: &str,
    party_two_pdl_second_message: Json<Party2PDLSecondMessage>,
) -> Result<Json<Party1PDLSecondMessage>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::fourth(state, claim, id.to_string(), party_two_pdl_second_message).await
}

#[post("/ecdsa/keygen_v2/<id>/chaincode/first", format = "json")]
pub async fn wrap_chain_code_first_message(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: &str,
) -> Result<Json<DHPoKParty1FirstMessage>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::chain_code_first_message(state, claim, id.to_string()).await
}

#[post(
    "/ecdsa/keygen_v2/<id>/chaincode/second",
    format = "json",
    data = "<cc_party_two_first_message_d_log_proof>"
)]
pub async fn wrap_chain_code_second_message(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: &str,
    cc_party_two_first_message_d_log_proof: Json<DLogProof>,
) -> Result<Json<DHPoKParty1SecondMessage>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::chain_code_second_message(
        state,
        claim,
        id.to_string(),
        cc_party_two_first_message_d_log_proof,
    )
    .await
}

#[post(
    "/ecdsa/sign/<id>/first",
    format = "json",
    data = "<eph_key_gen_first_message_party_two>"
)]
pub async fn wrap_sign_first(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: &str,
    eph_key_gen_first_message_party_two: Json<Party2EphKeyGenFirstMessage>,
) -> Result<Json<Party1EphKeyGenFirstMessage>, String> {
    struct Gotham {}
    impl Sign for Gotham {}
    Gotham::sign_first(
        state,
        claim,
        id.to_string(),
        eph_key_gen_first_message_party_two,
    )
    .await
}

#[post("/ecdsa/sign/<id>/second", format = "json", data = "<request>")]
pub async fn wrap_sign_second(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: &str,
    request: Json<Party2SignSecondMessage>,
) -> Result<Json<SignatureRecid>, String> {
    struct Gotham {}
    impl Sign for Gotham {}
    Gotham::sign_second(state, claim, id.to_string(), request).await
}

#[post(
    "/ecdsa/sign/<id>/first_v2",
    format = "json",
    data = "<eph_key_gen_first_message_party_two>"
)]
pub async fn wrap_sign_first_v2(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: &str,
    eph_key_gen_first_message_party_two: Json<Party2EphKeyGenFirstMessage>,
) -> Result<Json<(String, Party1EphKeyGenFirstMessage)>, String> {
    struct Gotham {}
    impl Sign for Gotham {}
    Gotham::sign_first_v2(
        state,
        claim,
        id.to_string(),
        eph_key_gen_first_message_party_two,
    )
    .await
}

#[post("/ecdsa/sign/<ssid>/second_v2", format = "json", data = "<request>")]
pub async fn wrap_sign_second_v2(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    ssid: &str,
    request: Json<Party2SignSecondMessage>,
) -> Result<Json<SignatureRecid>, String> {
    struct Gotham {}
    impl Sign for Gotham {}
    Gotham::sign_second_v2(state, claim, ssid.to_string(), request).await
}

#[post("/ecdsa/rotate/<id>/first", format = "json")]
pub async fn wrap_rotate_first(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: &str,
) -> Result<Json<coin_flip_optimal_rounds::Party1FirstMessage>, String> {
    struct Gotham {}
    impl Rotate for Gotham {}
    Gotham::rotate_first(state, claim, id.to_string()).await
}

#[post("/ecdsa/rotate/<id>/second", format = "json", data = "<request>")]
pub async fn wrap_rotate_second(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: &str,
    request: Json<coin_flip_optimal_rounds::Party2FirstMessage>,
) -> Result<
    Json<
        Option<(
            coin_flip_optimal_rounds::Party1SecondMessage,
            RotationParty1Message1,
        )>,
    >,
    String,
> {
    struct Gotham {}
    impl Rotate for Gotham {}
    Gotham::rotate_second(state, claim, id.to_string(), request).await
}

#[post("/ecdsa/rotate/<id>/third", format = "json", data = "<request>")]
pub async fn wrap_rotate_third(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: &str,
    request: Json<Party2PDLFirstMessage>,
) -> Result<Json<Party1PDLFirstMessage>, String> {
    struct Gotham {}
    impl Rotate for Gotham {}
    Gotham::rotate_third(state, claim, id.to_string(), request).await
}

#[post("/ecdsa/rotate/<id>/forth", format = "json", data = "<request>")]
pub async fn wrap_rotate_forth(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: &str,
    request: Json<Party2PDLSecondMessage>,
) -> Result<Json<Party1PDLSecondMessage>, String> {
    struct Gotham {}
    impl Rotate for Gotham {}
    Gotham::rotate_forth(state, claim, id.to_string(), request).await
}

#[get("/health")]
pub fn ping() -> Status {
    // TODO: Add logic for health check
    Status::Ok
}
