use std::collections::HashMap;
use std::env;
use std::time::Instant;
use crate::public::server;
use rocket::{http::ContentType, http::{Header, Status}, local::blocking::Client};
use two_party_ecdsa::curv::arithmetic::traits::Converter;
use two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::*;
use two_party_ecdsa::{party_one, party_two, curv::BigInt};
use kms::chain_code::two_party as chain_code;
use kms::ecdsa::two_party::{MasterKey2, party1};
use crate::routes::sign::SignSecondMsgRequest;

fn key_gen(client: &Client) -> String {
    let response = client
        .post("/engine/traits/wrap_keygen_first")
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let res_body = response.into_string().unwrap();

    let (id, kg_party_one_first_message): (String, party_one::KeyGenFirstMsg) =
        serde_json::from_str(&res_body).unwrap();

    let start = Instant::now();

    let (kg_party_two_first_message, kg_ec_key_pair_party2) = MasterKey2::key_gen_first_message();

    /*************** END: FIRST MESSAGE ***************/

    /*************** START: SECOND MESSAGE ***************/
    let body = serde_json::to_string(&kg_party_two_first_message.d_log_proof).unwrap();

    id
}

#[test]
fn key_gen_and_sign() {
    // Passthrough mode
    env::set_var("region", "");
    env::set_var("pool_id", "");
    env::set_var("issuer", "");
    env::set_var("audience", "");
    // env::set_var("ELASTICACHE_URL", "127.0.0.1");

    let settings = HashMap::<String, String>::from([
        ("db".to_string(), "local".to_string()),
        ("db_name".to_string(), "KeyGenAndSign".to_string()),
    ]);
    let server = server::get_server(settings);
    let client = Client::tracked(server).expect("valid rocket instance");
    let id = key_gen(&client);

    // let message = BigInt::from(1234u32);
    //
    // let signature: party_one::SignatureRecid =
    //     sign(&client, id.clone(), master_key_2, message.clone());
    //
    // println!(
    //     "s = (r: {}, s: {}, recid: {})",
    //     signature.r.to_hex(),
    //     signature.s.to_hex(),
    //     signature.recid
    // );
    // //test v2 sign interface with session id enabled
}
