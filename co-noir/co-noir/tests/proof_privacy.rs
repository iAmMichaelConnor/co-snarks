use ark_bn254::G1Projective;
use co_noir_common::{
    keys::{
        proof_privacy::ProofPrivacy,
        proving_key::{Rep3ProvingKey, ShamirProvingKey},
    },
    polynomials::entities::Polynomials,
    types::ZeroKnowledge,
};
use mpc_core::protocols::rep3::id::PartyID;

#[test]
fn translating_serialized_private_key_retains_proof_requirement() {
    for id in [PartyID::ID0, PartyID::ID1, PartyID::ID2] {
        let key = Rep3ProvingKey::<G1Projective> {
            proof_privacy: ProofPrivacy::PrivateRecursion,
            circuit_size: 2,
            polynomials: Polynomials::new(2),
            ..Default::default()
        };
        let bytes = bincode::serialize(&key).unwrap();
        let key: Rep3ProvingKey<G1Projective> = bincode::deserialize(&bytes).unwrap();
        let translated = co_noir::translate_proving_key(key, id).unwrap();
        let bytes = bincode::serialize(&translated).unwrap();
        let loaded: ShamirProvingKey<G1Projective> = bincode::deserialize(&bytes).unwrap();
        assert_eq!(loaded.proof_privacy, ProofPrivacy::PrivateRecursion);
        assert!(
            loaded
                .proof_privacy
                .validate_proving_mode(ZeroKnowledge::No, false)
                .is_err()
        );
        assert!(
            loaded
                .proof_privacy
                .validate_proving_mode(ZeroKnowledge::Yes, true)
                .is_err()
        );
        assert!(
            loaded
                .proof_privacy
                .validate_proving_mode(ZeroKnowledge::Yes, false)
                .is_ok()
        );
    }
}

#[test]
fn split_key_apis_preserve_both_privacy_profiles() {
    use co_noir_common::keys::plain_proving_key::PlainProvingKey;
    for privacy in [ProofPrivacy::Standard, ProofPrivacy::PrivateRecursion] {
        let plain = || PlainProvingKey::<G1Projective> {
            proof_privacy: privacy,
            circuit_size: 2,
            polynomials: co_noir_common::polynomials::polynomial::Polynomials::new(2),
            ..Default::default()
        };
        for key in co_noir::split_proving_key_rep3(plain()).unwrap() {
            let loaded: Rep3ProvingKey<G1Projective> =
                bincode::deserialize(&bincode::serialize(&key).unwrap()).unwrap();
            assert_eq!(loaded.proof_privacy, privacy);
        }
        for key in co_noir::split_proving_key_shamir(plain(), 1, 3).unwrap() {
            let loaded: ShamirProvingKey<G1Projective> =
                bincode::deserialize(&bincode::serialize(&key).unwrap()).unwrap();
            assert_eq!(loaded.proof_privacy, privacy);
        }
    }
}
