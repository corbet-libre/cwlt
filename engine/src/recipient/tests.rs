//! Real maintained HPKE/Merkle/signature framing; no admitted-account authority.
use super::*;
use czkp::{ProofScope, record::Purpose};
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
enum Damage {
    None,
    Certificate,
    Path,
    Root,
    Index,
}

fn publication(same_recipient: bool, damage: Damage) -> (Epoch, Vec<u8>) {
    let issuer = SigningKey::from_bytes(&[19; 32]);
    let leaves = [
        Leaf {
            owner: [3; 32],
            version: 4,
            state: [1; 32],
            required_inbox: [5; 32],
            blinding: [9; 32],
        },
        Leaf {
            owner: if same_recipient { [3; 32] } else { [4; 32] },
            version: 5,
            state: [2; 32],
            required_inbox: [6; 32],
            blinding: [10; 32],
        },
    ];
    let hashes = leaves
        .iter()
        .map(|leaf| leaf.commitment(&[1; 32], 2).unwrap())
        .collect::<Vec<_>>();
    let tree = rs_merkle::MerkleTree::<EpochTree>::from_leaves(&hashes);
    let packet_size = ENCAP + TAG + LEAF + 32 + CERTIFICATE;
    let mut epoch = Epoch {
        purpose: Purpose::RecordEpochV3,
        community: [1; 32],
        policy_epoch: 1,
        epoch: 2,
        starts_at: 200,
        expires_at: 300,
        root: tree.root().unwrap(),
        issuer_key: issuer.verifying_key().to_bytes(),
        proof_scope: ProofScope {
            circuit_digest: [7; 32],
            verifying_key_digest: [8; 32],
        },
        leaf_count: 2,
        download_digest: [1; 32],
        download_bytes: (PREFIX.len() + 8 + 2 * packet_size) as u64,
    };
    if matches!(damage, Damage::Root) {
        epoch.root[0] ^= 1;
    }
    let aad = packet_aad(&epoch).unwrap();
    let mut packets = Vec::new();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([21; 32]);
    for (index, leaf) in leaves.iter().enumerate() {
        let mut plaintext = Zeroizing::new(Vec::new());
        plaintext.extend_from_slice(&leaf.owner);
        plaintext.extend_from_slice(&leaf.version.to_be_bytes());
        plaintext.extend_from_slice(&leaf.state);
        plaintext.extend_from_slice(&leaf.required_inbox);
        plaintext.extend_from_slice(&leaf.blinding);
        plaintext.extend_from_slice(&(index as u32).to_be_bytes());
        for hash in tree.proof(&[index]).proof_hashes() {
            plaintext.extend_from_slice(hash);
        }
        let certificate = issuer
            .sign(
                &czkp::record::certificate_bytes(&epoch.community, epoch.epoch, &hashes[index])
                    .unwrap(),
            )
            .to_bytes();
        plaintext.extend_from_slice(&certificate);
        if index == 0 {
            match damage {
                Damage::Certificate => *plaintext.last_mut().unwrap() ^= 1,
                Damage::Path => plaintext[LEAF] ^= 1,
                Damage::Index => plaintext[136..140].copy_from_slice(&2u32.to_be_bytes()),
                _ => (),
            }
        }
        let seed = if index == 0 || same_recipient {
            [11; 32]
        } else {
            [12; 32]
        };
        let public = Kem::derive_keypair(&seed).1;
        let (enc, encrypted) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
            &hpke::OpModeS::Base,
            &public,
            INFO,
            &plaintext,
            &aad,
            &mut rng,
        )
        .unwrap();
        packets.push([enc.to_bytes().as_slice(), encrypted.as_slice()].concat());
    }
    // The original common object is shuffled and has no recipient label.
    packets.reverse();
    let mut object = PREFIX.to_vec();
    object.extend_from_slice(&epoch.leaf_count.to_be_bytes());
    object.extend_from_slice(&(packet_size as u32).to_be_bytes());
    for packet in packets {
        object.extend_from_slice(&packet);
    }
    epoch.download_digest = Sha256::digest(&object).into();
    (epoch, object)
}

fn receive(
    epoch: &Epoch,
    period: u64,
    owner: [u8; 32],
    object: &[u8],
    now: u64,
) -> Result<ReceivedRecord, Error> {
    let mut seed = [11; 32];
    RecordRecipient::from_seed(&mut seed, [1; 32], 200)
        .unwrap()
        .receive(epoch, period, owner, object, now)
}

#[test]
fn original_packet_opens_once_and_input_is_wiped_without_account_initialization() {
    let (epoch, object) = publication(false, Damage::None);
    let mut seed = [11; 32];
    {
        let recipient = RecordRecipient::from_seed(&mut seed, [1; 32], 200).unwrap();
        let expected: [u8; 32] = Kem::derive_keypair(&[11; 32])
            .1
            .to_bytes()
            .as_slice()
            .try_into()
            .unwrap();
        assert_eq!(recipient.public_key(), expected);
        // Expected owner is fixture input; no genuine accepted account is claimed.
        let received = recipient
            .receive(&epoch, 100, [3; 32], &object, 210)
            .unwrap();
        assert_eq!(received.epoch(), &epoch);
        assert!(received.check(&epoch, [4; 32], 210).is_err());
        let mut changed = epoch.clone();
        changed.policy_epoch += 1;
        assert!(received.check(&changed, [3; 32], 210).is_err());
        received.check(&epoch, [3; 32], 299).unwrap();
    }
    assert_eq!(seed, [0; 32]);
    let mut refused = [11; 32];
    assert!(RecordRecipient::from_seed(&mut refused, [0; 32], 200).is_err());
    assert_eq!(refused, [0; 32]);
}

#[test]
fn decoded_packet_retains_highest_ram_clock_and_terminal_rollback_or_expiry() {
    let (epoch, object) = publication(false, Damage::None);
    let received = receive(&epoch, 100, [3; 32], &object, 210).unwrap();
    received.check(&epoch, [3; 32], 220).unwrap();
    assert!(received.check(&epoch, [3; 32], 219).is_err());
    assert!(received.check(&epoch, [3; 32], 220).is_err());
    let received = receive(&epoch, 100, [3; 32], &object, 210).unwrap();
    assert!(received.check(&epoch, [3; 32], 300).is_err());
    assert!(received.check(&epoch, [3; 32], 299).is_err());
}

#[test]
fn foreign_community_owner_and_recipient_or_expiry_refuse() {
    let (epoch, object) = publication(false, Damage::None);
    for (period, owner, now) in [
        (99, [3; 32], 210),
        (100, [4; 32], 210),
        (100, [3; 32], 199),
        (100, [3; 32], 300),
    ] {
        assert!(receive(&epoch, period, owner, &object, now).is_err());
    }
    let mut seed = [11; 32];
    let foreign = RecordRecipient::from_seed(&mut seed, [2; 32], 200).unwrap();
    assert!(foreign.receive(&epoch, 100, [3; 32], &object, 210).is_err());
    let mut seed = [13; 32];
    let wrong_key = RecordRecipient::from_seed(&mut seed, [1; 32], 200).unwrap();
    assert!(
        wrong_key
            .receive(&epoch, 100, [3; 32], &object, 210)
            .is_err()
    );
    let mut seed = [11; 32];
    let newer_floor = RecordRecipient::from_seed(&mut seed, [1; 32], 211).unwrap();
    assert!(
        newer_floor
            .receive(&epoch, 100, [3; 32], &object, 210)
            .is_err()
    );
}

#[test]
fn actual_encrypted_bad_certificate_path_root_and_index_refuse() {
    for damage in [
        Damage::Certificate,
        Damage::Path,
        Damage::Root,
        Damage::Index,
    ] {
        let (epoch, object) = publication(false, damage);
        assert!(receive(&epoch, 100, [3; 32], &object, 210).is_err());
    }
}

#[test]
fn whole_object_digest_and_exact_bounded_framing_precede_opening() {
    let (epoch, object) = publication(false, Damage::None);
    let mut changed = object.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(receive(&epoch, 100, [3; 32], &changed, 210).is_err());
    for offset in [0, PREFIX.len(), PREFIX.len() + 4] {
        let mut changed = object.clone();
        changed[offset] ^= 1;
        let mut descriptor = epoch.clone();
        descriptor.download_digest = Sha256::digest(&changed).into();
        assert!(receive(&descriptor, 100, [3; 32], &changed, 210).is_err());
    }
    for changed in [
        object[..object.len() - 1].to_vec(),
        [object.as_slice(), &[0]].concat(),
    ] {
        let mut descriptor = epoch.clone();
        descriptor.download_bytes = changed.len() as u64;
        descriptor.download_digest = Sha256::digest(&changed).into();
        assert!(receive(&descriptor, 100, [3; 32], &changed, 210).is_err());
    }
    let mut excessive = epoch.clone();
    excessive.download_bytes = czkp::record::MAX_DOWNLOAD_BYTES + 1;
    assert!(receive(&excessive, 100, [3; 32], &object, 210).is_err());
    excessive = epoch.clone();
    excessive.leaf_count = czkp::record::MAX_LEAVES + 1;
    assert!(receive(&excessive, 100, [3; 32], &object, 210).is_err());
}

#[test]
fn two_successfully_decryptable_original_packets_are_ambiguous() {
    let (epoch, object) = publication(true, Damage::None);
    let mut seed = [11; 32];
    let recipient = RecordRecipient::from_seed(&mut seed, [1; 32], 200).unwrap();
    assert!(
        recipient
            .receive(&epoch, 100, [3; 32], &object, 210)
            .is_err()
    );
}
