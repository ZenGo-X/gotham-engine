use std::any::{Any};
use crate::types::{ DbIndex, EcdsaStruct};

use two_party_ecdsa::{GE, party_one, party_two};
use two_party_ecdsa::party_one::{KeyGenFirstMsg, DLogProof, HDPos, v, CommWitness, EcKeyPair, Party1Private, PaillierKeyPair};
use two_party_ecdsa::party_two::{
    PDLFirstMessage as Party2PDLFirstMsg
};
use two_party_ecdsa::kms::ecdsa::two_party::{MasterKey1, party1};
use crate::types::Alpha;

use std::env;
use log::{error, warn};
use rocket::serde::json::Json;
use rocket::{async_trait, State};
use tokio::sync::Mutex;
use two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::{Party1FirstMessage, Party1SecondMessage};
use two_party_ecdsa::kms::chain_code::two_party::party1::ChainCode1;
use uuid::Uuid;
use crate::guarder::Claims;
use crate::traits::Db;

#[async_trait]
pub trait KeyGen {
    //first round of Keygen
    async fn first(
        state: &State<Mutex<Box<dyn Db>>>,
        claim: Claims,
    ) -> Result<Json<(String, KeyGenFirstMsg)>, String> {
        let db = state.lock().await;
        match db.has_active_share(&claim.sub).await {
            Err(e) => {
                let msg = format!(
                    "Error when searching for active shares of customerId {}",
                    &claim.sub
                );
                error!("{}: {:?}", msg, e);
                return Err(format!("{}", msg));
            }
            Ok(result) => {
                if result {
                    let msg = format!("User {} already has an active share", &claim.sub);
                    warn!("{}", msg);
                    let should_fail_keygen = env::var("FAIL_KEYGEN_IF_ACTIVE_SHARE_EXISTS");
                    if should_fail_keygen.is_ok() && should_fail_keygen.unwrap() == "true" {
                        warn!("Abort KeyGen");
                        return Err(format!("{}", msg));
                    }
                }
            }
        }

        let (key_gen_first_msg, comm_witness, ec_key_pair) = MasterKey1::key_gen_first_message();

        let id = Uuid::new_v4().to_string();
        //save pos 0
        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::POS,
            &HDPos { pos: 0u32 },
        )
            .await
            .or(Err("Failed to insert into db"))?;
        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::KeyGenFirstMsg,
            &key_gen_first_msg,
        )
            .await
            .or(Err("Failed to insert into db"))?;

        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::CommWitness,
            &comm_witness,
        )
            .await
            .or(Err("Failed to insert into db"))?;

        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::EcKeyPair,
            &ec_key_pair,
        )
            .await
            .or(Err("Failed to insert into db"))?;


        let value = v { value: "false".parse().unwrap() };

        db.insert(&DbIndex {
            customer_id: claim.sub.to_string(),
            id: id.clone(),
        }, &EcdsaStruct::Abort, &value)
            .await
            .or(Err("Failed to insert into db"))?;

        Ok(Json((id.clone(), key_gen_first_msg)))
    }

    //second round of Keygen
    async fn second(state: &State<Mutex<Box<dyn Db>>>,
                    claim: Claims,
                    id: String,
                    dlog_proof: Json<DLogProof>) -> Result<Json<party1::KeyGenParty1Message2>, String> {
        let db = state.lock().await;
        let party2_public: GE = dlog_proof.0.pk;
        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::Party2Public,
            &party2_public,
        )
            .await
            .or(Err("Failed to insert into db"))?;

        let comm_witness =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::CommWitness)
                .await
                .or(Err("Failed to get from db"))?
                .ok_or(format!("No data for such identifier {}", id))?;
        let ec_key_pair =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::EcKeyPair)
                .await
                .or(Err("Failed to get from db"))?
                .ok_or(format!("No data for such identifier {}", id))?;

        let (kg_party_one_second_message, paillier_key_pair, party_one_private) =
            MasterKey1::key_gen_second_message(comm_witness.as_any().downcast_ref::<CommWitness>().unwrap(), ec_key_pair.as_any().downcast_ref::<EcKeyPair>().unwrap(), &dlog_proof.0);

        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::PaillierKeyPair,
            &paillier_key_pair,
        )
            .await
            .or(Err("Failed to insert into db"))?;

        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::Party1Private,
            &party_one_private,
        )
            .await
            .or(Err("Failed to insert into db"))?;

        // println!("Insert typeID of party_one_private{:?}",(&*party_one_private).type_id());

        Ok(Json(kg_party_one_second_message))
    }


    async fn third(state: &State<Mutex<Box<dyn Db>>>,
                   claim: Claims,
                   id: String,
                   party_2_pdl_first_message: Json<party_two::PDLFirstMessage>)
                   -> Result<Json<party_one::PDLFirstMessage>, String> {
        let db = state.lock().await;

        let party_one_private =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::Party1Private)
                .await
                .or(Err(format!("Failed to get from DB, id: {}", id)))?
                .ok_or(format!("No data for such identifier {}", id))?;


        let (party_one_third_message, party_one_pdl_decommit, alpha) =
            MasterKey1::key_gen_third_message(&party_2_pdl_first_message.0, &party_one_private.as_any().downcast_ref::<Party1Private>().unwrap());

        println!("To insert typeID of party_one_private{:?}", (&party_one_pdl_decommit).type_id());
        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::PDLDecommit,
            &party_one_pdl_decommit,
        )
            .await
            .or(Err(format!(
                "Failed to insert into DB PDLDecommit, id: {}",
                id
            )))?;


        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::Alpha,
            &Alpha { value: alpha },
        )
            .await
            .or(Err(format!("Failed to insert into DB Alpha, id: {}", id)))?;

        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::Party2PDLFirstMsg,
            &party_2_pdl_first_message.0,
        )
            .await
            .or(Err(format!(
                "Failed to insert into DB Party2PDLFirstMsg, id: {}",
                id
            )))?;

        Ok(Json(party_one_third_message))
    }
    async fn fourth(state: &State<Mutex<Box<dyn Db>>>,
                    claim: Claims,
                    id: String, party_two_pdl_second_message: Json<party_two::PDLSecondMessage>,
    ) -> Result<Json<party_one::PDLSecondMessage>, String> {
        let db = state.lock().await;

        let party_one_private =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::Party1Private)
                .await
                .or(Err(format!("Failed to get from DB, id:{}", id)))?
                .ok_or(format!("No data for such identifier {}", id))?;

        println!("Get typeID of party_one_private{:?}", (party_one_private).type_id());

        let party_2_pdl_first_message =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::Party2PDLFirstMsg)
                .await
                .or(Err(format!(
                    "Failed to get party 2 pdl first message from DB, id: {}",
                    id
                )))?
                .ok_or(format!("No data for such identifier {}", id))?;
        let party_one_pdl_decommit =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::PDLDecommit)
                .await
                .or(Err(format!(
                    "Failed to get party one pdl decommit, id: {}",
                    id
                )))?
                .ok_or(format!("No data for such identifier {}", id))?;


        let alpha = db.get(&DbIndex {
            customer_id: claim.sub.to_string(),
            id: id.clone(),
        }, &EcdsaStruct::Alpha)
            .await
            .or(Err(format!("Failed to get alpha from DB, id: {}", id)))?
            .ok_or(format!("No data for such identifier {}", id))?;
        // let dl: &mut dyn Value = party_one_pdl_decommit.borrow_mut();


        let res = MasterKey1::key_gen_fourth_message(
            party_2_pdl_first_message.as_any().downcast_ref::<Party2PDLFirstMsg>().unwrap().clone(),
            &party_two_pdl_second_message.0,
            party_one_private.as_any().downcast_ref::<Party1Private>().unwrap().clone(),
            party_one_pdl_decommit.as_any().downcast_ref::<party_one::PDLdecommit>().unwrap().clone(),
            alpha.as_any().downcast_ref::<Alpha>().unwrap().value.clone(),
        );
        assert!(res.is_ok());
        Ok(Json(res.unwrap()))
    }
    async fn chain_code_first_message(state: &State<Mutex<Box<dyn Db>>>,
                                      claim: Claims,
                                      id: String,
    ) -> Result<Json<Party1FirstMessage>, String> {
        let db = state.lock().await;

        let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
            ChainCode1::chain_code_first_message();

        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::CCKeyGenFirstMsg,
            &cc_party_one_first_message,
        )
            .await
            .or(Err("Failed to insert into db"))?;

        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::CCCommWitness,
            &cc_comm_witness,
        )
            .await
            .or(Err("Failed to insert into db"))?;

        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::CCEcKeyPair,
            &cc_ec_key_pair1,
        )
            .await
            .or(Err("Failed to insert into db"))?;

        Ok(Json(cc_party_one_first_message))
    }
    async fn chain_code_second_message(state: &State<Mutex<Box<dyn Db>>>,
                                       claim: Claims,
                                       id: String,
                                       cc_party_two_first_message_d_log_proof: Json<DLogProof>,
    ) -> Result<Json<Party1SecondMessage>, String> {

        let db = state.lock().await;
        let cc_comm_witness =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::CCCommWitness)
                .await
                .or(Err("Failed to get from db"))?
                .ok_or(format!("No data for such identifier {}", id))?;

        let party1_cc_res = ChainCode1::chain_code_second_message(
            cc_comm_witness.as_any().downcast_ref::<two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::CommWitnessDHPoK>().unwrap().clone(),
            &cc_party_two_first_message_d_log_proof.0,
        );

        let party2_pub = &cc_party_two_first_message_d_log_proof.pk;
        // chain_code_compute_message(state, claim, id, party2_pub).await?;

        //compute_chain_code_message
        let cc_ec_key_pair_party1 =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::CCEcKeyPair)
                .await
                .or(Err("Failed to get from db"))?
                .ok_or(format!("No data for such identifier {}", id))?;
        let party1_cc = ChainCode1::compute_chain_code(
            &cc_ec_key_pair_party1.as_any().downcast_ref::<two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::EcKeyPairDHPoK>().unwrap().clone(),
            party2_pub,
        );

        db.insert(&DbIndex {
            customer_id: claim.sub.to_string(),
            id: id.clone(),
        }, &EcdsaStruct::CC, &party1_cc)
            .await
            .or(Err("Failed to insert into db"))?;

        //set master key
        let party2_public = db.get(&DbIndex {
            customer_id: claim.sub.to_string(),
            id: id.clone(),
        }, &EcdsaStruct::Party2Public)
            .await
            .or(Err(format!("Failed to get alpha from DB, id: {}", id)))?
            .ok_or(format!("No data for such identifier {}", id))?;

        let paillier_key_pair =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::PaillierKeyPair)
                .await
                .or(Err(format!("Failed to get alpha from DB, id: {}", id)))?
                .ok_or(format!("No data for such identifier {}", id))?;

        let party1_cc =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::CC)
                .await
                .or(Err(format!("Failed to get alpha from DB, id: {}", id)))?
                .ok_or(format!("No data for such identifier {}", id))?;

        let party_one_private =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::Party1Private)
                .await
                .or(Err(format!("Failed to get alpha from DB, id: {}", id)))?
                .ok_or(format!("No data for such identifier {}", id))?;

        let comm_witness =
            db.get(&DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            }, &EcdsaStruct::CommWitness)
                .await
                .or(Err(format!("Failed to get alpha from DB, id: {}", id)))?
                .ok_or(format!("No data for such identifier {}", id))?;

        let master_key = MasterKey1::set_master_key(
            &party1_cc.as_any().downcast_ref::<ChainCode1>().unwrap().chain_code,
            party_one_private.as_any().downcast_ref::<Party1Private>().unwrap().clone(),
            &comm_witness.as_any().downcast_ref::<CommWitness>().unwrap().public_share,
            party2_public.as_any().downcast_ref::<GE>().unwrap(),
            paillier_key_pair.as_any().downcast_ref::<PaillierKeyPair>().unwrap().clone(),
        );

        db.insert(
            &DbIndex {
                customer_id: claim.sub.to_string(),
                id: id.clone(),
            },
            &EcdsaStruct::Party1MasterKey,
            &master_key,
        )
            .await
            .or(Err("Failed to insert into db"))?;


        Ok(Json(party1_cc_res))
    }
}