//! Exact original account transcript framing around maintained CZKP Poseidon2.
use super::Field;
use crate::Error;
use czkp::poseidon::{integer, limbs};
use zeroize::Zeroize;

fn domain(text: &[u8]) -> Field {
    let mut field = [0; 32];
    field[32 - text.len()..].copy_from_slice(text);
    field
}

pub(super) fn hash(tag: u64, fields: &[Field]) -> Result<Field, Error> {
    let mut input = vec![domain(b"cfrm.account-state.v2"), integer(tag)];
    input.extend_from_slice(fields);
    let result = czkp::poseidon::hash(&input).map_err(|_| Error::Crypto);
    input.zeroize();
    result
}

fn legacy(tag: u64, fields: &[Field]) -> Result<Field, Error> {
    let mut input = vec![domain(b"cfrm.accounting.poseidon2.v1"), integer(tag)];
    input.extend_from_slice(fields);
    let result = czkp::poseidon::hash(&input).map_err(|_| Error::Crypto);
    input.zeroize();
    result
}

pub(super) fn secret(community: &Field, seed: &Field) -> Result<Field, Error> {
    let mut fields = [limbs(community), limbs(seed)].concat();
    let result = legacy(2, &fields);
    fields.zeroize();
    result
}

pub(super) fn enrollment_node(left: Field, right: Field) -> Result<Field, Error> {
    legacy(6, &[left, right])
}

pub(super) fn digest(bytes: &[u8]) -> Result<Field, Error> {
    czkp::decode(&czkp::digest(bytes)).map_err(|_| Error::Crypto)
}

pub(super) fn integer128(value: u128) -> Field {
    let mut result = [0; 32];
    result[16..].copy_from_slice(&value.to_be_bytes());
    result
}
