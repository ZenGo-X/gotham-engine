pub mod server;
mod rocket_routes;
mod client;

use std::string::ToString;
use strum_macros::Display;
use two_party_musig2_eddsa::aggregate::{AggPublicKeyAndMusigCoeff, AggregatedNonce};
use two_party_musig2_eddsa::keypair::KeyPair;
use two_party_musig2_eddsa::public_partial_nonces::{PublicPartialNonces};
use two_party_musig2_eddsa::private_partial_nonces::{PrivatePartialNonces};

use crate::common::MPCStruct;
use crate::typetag_value;


#[derive(Display)]
pub enum MuSig2Struct {
    Party1KeyPair,
    AggPublicKeyAndMusigCoeff,
    Party1PrivatePartialNonces,
    Party1PublicPartialNonces,
    Party2PublicPartialNonces,
    AggregatedNonce,
}


impl MPCStruct for MuSig2Struct {
    fn get_name(&self) -> String {
        self.to_string()
    }

    fn get_table_name(&self, env: &str) -> String {
        return format!("{}-gotham-musig2-{}", env, self.get_name())
    }

    fn get_struct_name(&self) -> String {
        let res = match self {
            MuSig2Struct::Party1KeyPair => "KeyPair",
            MuSig2Struct::AggPublicKeyAndMusigCoeff => "AggPublicKeyAndMusigCoeff",
            MuSig2Struct::Party1PrivatePartialNonces => "PrivatePartialNonces",
            MuSig2Struct::Party1PublicPartialNonces => "PublicPartial",
            MuSig2Struct::Party2PublicPartialNonces => "PublicPartialNonces",
            MuSig2Struct::AggregatedNonce => "AggregatedNonce"
        };

        res.to_string()
    }
}


typetag_value!(KeyPair);
typetag_value!(AggPublicKeyAndMusigCoeff);
typetag_value!(PublicPartialNonces);
typetag_value!(PrivatePartialNonces);
typetag_value!(AggregatedNonce);



