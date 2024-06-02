use two_party_ecdsa::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use two_party_ecdsa::kms::ecdsa::two_party::MasterKey2;
use two_party_ecdsa::kms::rotation::two_party::party1::{RotationParty1Message1, RotationParty1ValidMessage1};
use two_party_ecdsa::kms::rotation::two_party::party2::Rotation2;
use two_party_ecdsa::party_one::{Party1PDLFirstMessage, Party1PDLSecondMessage};
use crate::common::client_shim::{Client, ClientShim};
use crate::client::PrivateShare;

const ROT_PATH_PRE: &str = "ecdsa/rotate";

pub fn rotate_master_key<C: Client>(client_shim: &ClientShim<C>,
                                    master_key_2: &MasterKey2,
                                    id: &str) -> PrivateShare {

    let mut coin_flip_party1_first_message: coin_flip_optimal_rounds::Party1FirstMessage;
    let mut coin_flip_party2_first_message: coin_flip_optimal_rounds::Party2FirstMessage;
    let mut rotation_party1_valid_first_message: RotationParty1ValidMessage1;

    loop {
        coin_flip_party1_first_message =
            client_shim.post(&format!("{}/{}/first", ROT_PATH_PRE, id)).unwrap();

        coin_flip_party2_first_message  =
            Rotation2::key_rotate_first_message(&coin_flip_party1_first_message);

        let body = &coin_flip_party2_first_message;

        rotation_party1_valid_first_message = client_shim.postb(
            &format!("{}/{}/second", ROT_PATH_PRE, id),
            body,
        ).unwrap();

        if rotation_party1_valid_first_message.is_valid {
            break;
        }
    }

    let rotation2 = Rotation2::key_rotate_second_message(
        &rotation_party1_valid_first_message.coin_flip_party1_second_message.unwrap(),
        &coin_flip_party2_first_message,
        &coin_flip_party1_first_message
    );

    let result_rotate_party_one_first_message =
        master_key_2.rotate_first_message(
            &rotation2, &rotation_party1_valid_first_message.rotation_party1_first_message.unwrap());

    if result_rotate_party_one_first_message.is_err() {
        panic!("rotation failed");
    }

    let (rotation_party_two_first_message, party_two_pdl_chal, party_two_paillier) =
        result_rotate_party_one_first_message.unwrap();

    let body = &rotation_party_two_first_message;

    let rotation_party1_second_message: Party1PDLFirstMessage = client_shim.postb(
        &format!("{}/{}/third", ROT_PATH_PRE, id),
        body,
    ).unwrap();

    let rotation_party_two_second_message = MasterKey2::rotate_second_message(&party_two_pdl_chal);

    let body = &rotation_party_two_second_message;

    let rotation_party1_third_message: Party1PDLSecondMessage = client_shim.postb(
        &format!("{}/{}/forth", ROT_PATH_PRE, id),
        body,
    )
        .unwrap();

    let result_rotate_party_one_third_message = master_key_2.rotate_third_message(
        &rotation2,
        &party_two_paillier,
        &party_two_pdl_chal,
        &rotation_party1_second_message,
        &rotation_party1_third_message,
    );

    if result_rotate_party_one_third_message.is_err() {
        panic!("rotation failed");
    }

    let rotated_mk = result_rotate_party_one_third_message.unwrap();

    PrivateShare { id : id.to_string(), master_key: rotated_mk }
}