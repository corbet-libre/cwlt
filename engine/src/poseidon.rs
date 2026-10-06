//! Maintained Rust implementation of the original Noir/BB Poseidon2 framing.
//! No local permutation, sponge, constants, or caller-selected backend.
use super::hash::Hash;
use super::{Error, Field};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

pub(super) struct Poseidon(pso_poseidon::Poseidon2<Fr>);

impl Poseidon {
    pub(super) fn new() -> Self {
        Self(pso_poseidon::Poseidon2::new())
    }
}

impl Hash for Poseidon {
    async fn poseidon2(&mut self, fields: &[Field]) -> Result<Field, Error> {
        // Validate BEFORE the maintained modular conversion so a noncanonical
        // encoding can never alias a different original transcript field.
        let mut input = Vec::with_capacity(fields.len());
        for field in fields {
            czkp::field(field, false).map_err(|_| Error::Crypto)?;
            input.push(Fr::from_be_bytes_mod_order(field));
        }
        // hash_noir is deliberate. The dependency's PoseidonHasher::hash uses
        // different framing for lengths divisible by three (including map leaves).
        let bytes = self.0.hash_noir(&input).into_bigint().to_bytes_be();
        bytes.try_into().map_err(|_| Error::Crypto)
    }
}
