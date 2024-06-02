use failure::format_err;
use rocket::http::hyper::body::HttpBody;
use two_party_ecdsa::party_two::Party2EphKeyGenFirstMessage;
use two_party_musig2_eddsa::keypair::KeyPair;
use crate::common::client_shim::{Client, ClientShim};
use two_party_musig2_eddsa::aggregate::{AggPublicKeyAndMusigCoeff as AggPublicKeyAndMusigCoeffStruct, AggPublicKeyAndMusigCoeff};
use two_party_musig2_eddsa::partial_sig::PartialSignature;
use two_party_musig2_eddsa::public_partial_nonces::PublicPartialNonces;
use two_party_musig2_eddsa::signature::Signature;


pub fn keygen<C: Client>(
    client_shim: &ClientShim<C>,
) -> Result<(String, KeyPair, AggPublicKeyAndMusigCoeff), failure::Error> {
    let (keypair, _secret) = KeyPair::create();

    let request: [u8; 32] = keypair.pubkey();

    let (id, server_pubkey): (String, [u8; 32]) =
        client_shim.postb("/musig2/keygen", &request).ok_or(format_err!("musig2/keygen failed"))?;

    let agg_pubkey =
        AggPublicKeyAndMusigCoeffStruct::aggregate_public_keys(keypair.pubkey(), server_pubkey)?;

    Ok((id, keypair, agg_pubkey))
}


pub fn sign<C: Client>(
    client_shim: &ClientShim<C>,
    id: String,
    keypair: KeyPair,
    agg_pubkey: AggPublicKeyAndMusigCoeffStruct,
    message: &[u8]
)-> Result<Signature, failure::Error> {
    let message_hex = hex::encode(message);

    let (private_nonces, public_nonces) = keypair.generate_partial_nonces(Some(message));

    let public_nonces_ser = public_nonces.serialize();

    let request = (hex::encode(public_nonces_ser), message_hex.clone());

    let server_public_nonces_hex: String =
        client_shim.postb(&format!("/musig2/sign/{}/first", id), &request)
            .ok_or(format_err!("musig2/sign/first failed"))?;

    let mut server_public_nonces_slice = [0u8; 64];
    hex::decode_to_slice(server_public_nonces_hex,
                         &mut server_public_nonces_slice as &mut [u8]).map_err(|err| format_err!("{}", err.to_string()))?;


    let server_public_nonces = PublicPartialNonces::deserialize(server_public_nonces_slice)
        .ok_or(format_err!("deserialization failed"))?;

    let (partial_sig, agg_nonce) = keypair.partial_sign(
        private_nonces,
        [public_nonces, server_public_nonces],
        &agg_pubkey,
        message,
    );

    let request = message_hex;

    let server_partial_sig_hex: String =
        client_shim.postb(&format!("/musig2/sign/{}/second", id), &request)
            .ok_or(format_err!("musig2/second failed"))?;

    let mut server_partial_sig_slice = [0u8; 32];
    hex::decode_to_slice(server_partial_sig_hex,
                         &mut server_partial_sig_slice as &mut [u8]).map_err(|err| format_err!("{}", err.to_string()))?;

    let server_partial_sig =
        PartialSignature::deserialize(server_partial_sig_slice).ok_or(format_err!("Received invalid partial signature"))?;

    let sig = Signature::aggregate_partial_signatures(agg_nonce, [partial_sig, server_partial_sig]);

    sig.verify(message, agg_pubkey.aggregated_pubkey()).map_err(|err| format_err!("{}", err.to_string()))?;

    Ok(sig)
}