use crate::guarder::Claims;
use crate::traits::Db;
use crate::types::{Alpha, DbIndex, EcdsaStruct};

use two_party_ecdsa::GE;
use two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::{DHPoKCommWitness, DHPoKEcKeyPair, DHPoKParty1FirstMessage, DHPoKParty1SecondMessage};
use two_party_ecdsa::kms::chain_code::two_party::party1::ChainCode1;
use two_party_ecdsa::kms::ecdsa::two_party::{MasterKey1};

use crate::{db_cast, db_get, db_get_required, db_insert};
use log::{error, warn};
use rocket::serde::json::Json;
use rocket::{async_trait, State};
use std::env;
use rocket::futures::TryFutureExt;
use tokio::sync::Mutex;
use two_party_ecdsa::party_one::{
    DLogProof, Party1CommWitness, Party1EcKeyPair, Party1HDPos, Party1KeyGenFirstMessage,
    Party1KeyGenSecondMessage, Party1PDLDecommit, Party1PDLFirstMessage, Party1PDLSecondMessage,
    Party1PaillierKeyPair, Party1Private,
};
use two_party_ecdsa::party_two::{Party2PDLFirstMessage, Party2PDLSecondMessage};
use uuid::Uuid;


#[async_trait]
pub trait KeyGen {
    ///first round of Keygen
    async fn first(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
    ) -> Result<Json<(String, Party1KeyGenFirstMessage)>, String> {
        let db = state.lock().await;
        //do not run in a local env
        if env::var("REDIS_ENV").is_ok() {
            match db.has_active_share(&claim.sub).await {
                Ok(true) => {
                    let should_fail_keygen = env::var("FAIL_KEYGEN_IF_ACTIVE_SHARE_EXISTS");
                    if should_fail_keygen.is_ok() && should_fail_keygen.unwrap() == "true" {
                        return Err(format!("customerId {} already has an active share, abort KeyGen",
                                           &claim.sub));
                    }
                },
                Err(err) => { return Err(format!("Error when searching for active shares of customerId {}: {}", &claim.sub, err)); },
                Ok(false) => {}
            };
        }

        let (key_gen_first_msg, comm_witness, ec_key_pair) =
            MasterKey1::key_gen_first_message();

        let id = Uuid::new_v4().to_string();

        //save pos 0
        let hd_pos = Party1HDPos { pos: 0u32 };
        db_insert!(db, claim.sub, id, POS, &hd_pos);

        db_insert!(db, claim.sub, id, KeyGenFirstMsg, &key_gen_first_msg);

        db_insert!(db, claim.sub, id, CommWitness, &comm_witness);

        db_insert!(db, claim.sub, id, EcKeyPair, &ec_key_pair);

        Ok(Json((id.clone(), key_gen_first_msg)))
    }

    //second round of Keygen
    async fn second(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        dlog_proof: Json<DLogProof>,
    ) -> Result<Json<Party1KeyGenSecondMessage>, String> {
        let db = state.lock().await;
        let party2_public: GE = dlog_proof.0.pk;


        db_insert!(db, claim.sub, id, Party2Public, &party2_public);

        let comm_witness = db_get_required!(db, claim.sub, id, CommWitness, Party1CommWitness);

        let ec_key_pair = db_get_required!(db, claim.sub, id, EcKeyPair, Party1EcKeyPair);

        let (kg_party_one_second_message, paillier_key_pair, party_one_private) =
            MasterKey1::key_gen_second_message(&comm_witness, &ec_key_pair, &dlog_proof.0);

        db_insert!(db, claim.sub, id, PaillierKeyPair, &paillier_key_pair);

        db_insert!(db, claim.sub, id, Party1Private, &party_one_private);

        Ok(Json(kg_party_one_second_message))
    }

    async fn third(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        party_2_pdl_first_message: Json<Party2PDLFirstMessage>,
    ) -> Result<Json<Party1PDLFirstMessage>, String> {
        let db = state.lock().await;

        let party_one_private = db_get_required!(db, claim.sub, id, Party1Private, Party1Private);

        let (party_one_third_message, party_one_pdl_decommit, alpha) =
            MasterKey1::key_gen_third_message(
                &party_2_pdl_first_message.0,
                &party_one_private,
            );

        db_insert!(db, claim.sub, id, PDLDecommit, &party_one_pdl_decommit);

        let alpha = Alpha { value: alpha };
        db_insert!(db, claim.sub, id, Alpha, &alpha);

        db_insert!(db, claim.sub, id, Party2PDLFirstMsg, &party_2_pdl_first_message.0);

        Ok(Json(party_one_third_message))
    }
    async fn fourth(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        party_two_pdl_second_message: Json<Party2PDLSecondMessage>,
    ) -> Result<Json<Party1PDLSecondMessage>, String> {
        let db = state.lock().await;

        let party_one_private = db_get_required!(db, claim.sub, id, Party1Private, Party1Private);

        let party_2_pdl_first_message = db_get_required!(db, claim.sub, id, Party2PDLFirstMsg, Party2PDLFirstMessage);

        let party_one_pdl_decommit = db_get_required!(db, claim.sub, id, PDLDecommit, Party1PDLDecommit);

        let alpha = db_get_required!(db, claim.sub, id, Alpha, Alpha);

        // let dl: &mut dyn Value = party_one_pdl_decommit.borrow_mut();

        let res = MasterKey1::key_gen_fourth_message(
            &party_2_pdl_first_message,
            &party_two_pdl_second_message.0,
            party_one_private.clone(),
            party_one_pdl_decommit.clone(),
            alpha.value.clone(),
        );

        assert!(res.is_ok());
        Ok(Json(res.unwrap()))
    }

    async fn chain_code_first_message(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
    ) -> Result<Json<DHPoKParty1FirstMessage>, String> {
        let db = state.lock().await;

        let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
            ChainCode1::chain_code_first_message();

        db_insert!(db, claim.sub, id, CCKeyGenFirstMsg, &cc_party_one_first_message);

        db_insert!(db, claim.sub, id, CCCommWitness, &cc_comm_witness);

        db_insert!(db, claim.sub, id, CCEcKeyPair, &cc_ec_key_pair1);

        Ok(Json(cc_party_one_first_message))
    }
    async fn chain_code_second_message(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
        id: String,
        cc_party_two_first_message_d_log_proof: Json<DLogProof>,
    ) -> Result<Json<DHPoKParty1SecondMessage>, String> {
        let db = state.lock().await;

        let cc_comm_witness = db_get_required!(db, claim.sub, id, CCCommWitness, DHPoKCommWitness);

        let party1_cc_res = ChainCode1::chain_code_second_message(
            cc_comm_witness.clone(),
            &cc_party_two_first_message_d_log_proof.0,
        );

        let party2_pub = &cc_party_two_first_message_d_log_proof.pk;

        let cc_ec_key_pair_party1 = db_get_required!(db, claim.sub, id, CCEcKeyPair, DHPoKEcKeyPair);

        let party1_cc = ChainCode1::compute_chain_code(
            &cc_ec_key_pair_party1.clone(),
            party2_pub,
        );

        db_insert!(db, claim.sub, id, CC, &party1_cc);

        let party2_public = db_get_required!(db, claim.sub, id, Party2Public, GE);

        let paillier_key_pair = db_get_required!(db, claim.sub, id, PaillierKeyPair, Party1PaillierKeyPair);

        let party1_cc = db_get_required!(db, claim.sub, id, CC, ChainCode1);

        let party_one_private = db_get_required!(db, claim.sub, id, Party1Private, Party1Private);

        let comm_witness = db_get_required!(db, claim.sub, id, CommWitness, Party1CommWitness);

        let master_key = MasterKey1::set_master_key(
            &party1_cc.chain_code,
            party_one_private.clone(),
            &comm_witness.public_share,
            &party2_public,
            paillier_key_pair.clone(),
        );


        db_insert!(db, claim.sub, id, Party1MasterKey, &master_key);

        Ok(Json(party1_cc_res))
    }
}
