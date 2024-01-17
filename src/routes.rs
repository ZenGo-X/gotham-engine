//! The routes that gotham-engine exposes. Notice that these are actually wrappers on the underlying implementations due
//! to the fact that rockets http server does not allow to mount directly routes as trait functions.

use crate::guarder::Claims;
use crate::keygen::KeyGen;
use crate::sign::Sign;
use crate::traits::{Db};
use crate::types::SignSecondMsgRequest;

use two_party_ecdsa::{party_one, party_two};
use two_party_ecdsa::party_one::{KeyGenFirstMsg, DLogProof};
use two_party_ecdsa::kms::ecdsa::two_party::{party1};
use two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::{Party1FirstMessage, Party1SecondMessage};

use rocket::serde::json::Json;
use rocket::{post, get, http::Status, State};
use tokio::sync::Mutex;


#[post("/ecdsa/keygen_v2/first", format = "json")]
pub async fn wrap_keygen_first(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
) -> Result<Json<(String, KeyGenFirstMsg)>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::first(state, claim).await
}

#[post("/ecdsa/keygen_v2/<id>/second", format = "json", data = "<dlog_proof>")]
pub async fn wrap_keygen_second(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: String,
    dlog_proof: Json<DLogProof>,
) -> Result<Json<party1::KeyGenParty1Message2>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::second(state, claim, id, dlog_proof).await
}

#[post(
"/ecdsa/keygen_v2/<id>/third",
format = "json",
data = "<party_2_pdl_first_message>"
)]
pub async fn wrap_keygen_third(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: String,
    party_2_pdl_first_message: Json<party_two::PDLFirstMessage>,
) -> Result<Json<party_one::PDLFirstMessage>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::third(state, claim, id, party_2_pdl_first_message).await
}

#[post(
"/ecdsa/keygen_v2/<id>/fourth",
format = "json",
data = "<party_two_pdl_second_message>"
)]
pub async fn wrap_keygen_fourth(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: String,
    party_two_pdl_second_message: Json<party_two::PDLSecondMessage>,
) -> Result<Json<party_one::PDLSecondMessage>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::fourth(state, claim, id, party_two_pdl_second_message).await
}

#[post("/ecdsa/keygen_v2/<id>/chaincode/first", format = "json")]
pub async fn wrap_chain_code_first_message(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: String,
) -> Result<Json<Party1FirstMessage>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::chain_code_first_message(state, claim, id).await
}

#[post(
"/ecdsa/keygen_v2/<id>/chaincode/second",
format = "json",
data = "<cc_party_two_first_message_d_log_proof>"
)]
pub async fn wrap_chain_code_second_message(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: String,
    cc_party_two_first_message_d_log_proof: Json<DLogProof>,
) -> Result<Json<Party1SecondMessage>, String> {
    struct Gotham {}
    impl KeyGen for Gotham {}
    Gotham::chain_code_second_message(state, claim, id, cc_party_two_first_message_d_log_proof)
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
    id: String,
    eph_key_gen_first_message_party_two: Json<party_two::EphKeyGenFirstMsg>,
) -> Result<Json<party_one::EphKeyGenFirstMsg>, String> {
    struct Gotham {}
    impl Sign for Gotham {}
    Gotham::sign_first(state, claim, id, eph_key_gen_first_message_party_two).await
}

#[post("/ecdsa/sign/<id>/second", format = "json", data = "<request>")]
pub async fn wrap_sign_second(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: String,
    request: Json<SignSecondMsgRequest>,
) -> Result<Json<party_one::SignatureRecid>, String> {
    struct Gotham {}
    impl Sign for Gotham {}
    Gotham::sign_second(state, claim, id, request).await
}

#[post(
"/ecdsa/sign/<id>/first_v2",
format = "json",
data = "<eph_key_gen_first_message_party_two>"
)]
pub async fn wrap_sign_first_v2(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    id: String,
    eph_key_gen_first_message_party_two: Json<party_two::EphKeyGenFirstMsg>,
) -> Result<Json<(String, party_one::EphKeyGenFirstMsg)>, String> {
    struct Gotham {}
    impl Sign for Gotham {}
    Gotham::sign_first_v2(state, claim, id, eph_key_gen_first_message_party_two).await
}

#[post("/ecdsa/sign/<ssid>/second_v2", format = "json", data = "<request>")]
pub async fn wrap_sign_second_v2(
    state: &State<Mutex<Box<dyn Db>>>,
    claim: Claims,
    ssid: String,
    request: Json<SignSecondMsgRequest>,
) -> Result<Json<party_one::SignatureRecid>, String> {
    struct Gotham {}
    impl Sign for Gotham {}
    Gotham::sign_second_v2(state, claim, ssid, request).await
}


#[get("/health")]
pub fn ping() -> Status {
    // TODO: Add logic for health check
    Status::Ok
}
