//! Exact original update/genesis ABI; no additional public output can be admitted.
use crate::Error;
use acvm::AcirField;
use noirc_abi::{
    Abi, AbiType, AbiVisibility, Sign,
    input_parser::{Format, InputValue},
};

fn uint(width: u32) -> AbiType {
    AbiType::Integer {
        sign: Sign::Unsigned,
        width,
    }
}
fn array(typ: AbiType, length: u32) -> AbiType {
    AbiType::Array {
        length,
        typ: Box::new(typ),
    }
}
fn bytes(n: u32) -> AbiType {
    array(uint(8), n)
}
fn fields(names: &[(&str, AbiType)]) -> Vec<(String, AbiType)> {
    names
        .iter()
        .map(|(n, t)| ((*n).into(), t.clone()))
        .collect()
}
fn structure(names: &[(&str, AbiType)]) -> AbiType {
    AbiType::Struct {
        path: String::new(),
        fields: fields(names),
    }
}

pub(super) fn expected() -> Vec<(&'static str, AbiType, AbiVisibility)> {
    let extension = structure(&[
        ("revision", uint(64)),
        ("quorum", uint(32)),
        ("change_cost", uint(32)),
        ("delay", uint(64)),
        ("batch", uint(8)),
    ]);
    let enrollment = structure(&[
        ("key", bytes(64)),
        ("secret_hash", bytes(32)),
        ("start", uint(64)),
        ("end", uint(64)),
        ("delegation_digest", bytes(32)),
        ("path", array(AbiType::Field, 32)),
        ("index", uint(32)),
    ]);
    let opening = structure(&[
        ("available", uint(32)),
        ("reserved", uint(128)),
        ("debt", uint(64)),
        ("accepted", uint(64)),
        ("declined", uint(64)),
        ("punished", uint(64)),
        ("inbox", bytes(32)),
        ("authorization", AbiType::Field),
        ("outgoing_root", AbiType::Field),
        ("outgoing_count", uint(64)),
        ("incoming_root", AbiType::Field),
        ("incoming_count", uint(64)),
        ("pair_root", AbiType::Field),
        ("pair_count", uint(64)),
        ("frontier", uint(64)),
        ("created_at", uint(64)),
        ("admission_epoch", uint(64)),
        ("admissions", uint(32)),
        ("blind", bytes(32)),
    ]);
    let slot = structure(&[
        ("role", uint(8)),
        ("peer", bytes(32)),
        ("nonce", bytes(32)),
        ("group", bytes(32)),
        ("contact_policy", bytes(32)),
        ("amount", uint(32)),
        ("phase", uint(8)),
        ("outcome", uint(8)),
        ("answered", AbiType::Boolean),
        ("self_punished", AbiType::Boolean),
        ("admitted_at", uint(64)),
        ("expires_at", uint(64)),
        ("peer_authority", AbiType::Field),
        ("owner_authority", AbiType::Field),
    ]);
    let map = structure(&[
        ("leaf", array(AbiType::Field, 4)),
        ("index", uint(32)),
        ("path", array(AbiType::Field, 32)),
        ("append_path", array(AbiType::Field, 32)),
    ]);
    let resolution = structure(&[
        ("kind", uint(8)),
        ("issued_at", uint(64)),
        ("history_digest", bytes(32)),
        ("ed25519_receipt_digest", bytes(32)),
        ("signature", bytes(64)),
    ]);
    let ack = structure(&[("issued_at", uint(64)), ("signature", bytes(64))]);
    let public = [
        ("extension", extension),
        ("previous_inbox", bytes(32)),
        ("inbox", bytes(32)),
        ("consume_only", AbiType::Boolean),
        ("change_binding", bytes(32)),
        ("community", bytes(32)),
        ("owner", bytes(32)),
        ("policy_digest", bytes(32)),
        ("enrollment_root", bytes(32)),
        ("now", uint(64)),
        ("valid_until", uint(64)),
        ("genesis", AbiType::Boolean),
        ("previous_version", uint(64)),
        ("next_version", uint(64)),
        ("previous_state", bytes(32)),
        ("next_state", bytes(32)),
        ("settlement_marker", bytes(32)),
        ("initial_credit", uint(32)),
        ("maximum_available", uint(32)),
        ("outgoing_reservation", uint(32)),
        ("incoming_reservation", uint(32)),
        ("policy_revision", uint(64)),
        ("policy_valid_from", uint(64)),
        ("policy_valid_until", uint(64)),
        ("newcomer_period", uint(64)),
        ("rate_window", uint(64)),
        ("newcomer_admissions", uint(32)),
        ("maximum_admissions", uint(32)),
        ("refill_period", uint(64)),
        ("refill_units", uint(32)),
        ("abandon_after", uint(64)),
    ];
    let private = [
        ("owner_secret", bytes(32)),
        ("owner_enrollment", enrollment.clone()),
        ("peer_enrollment", enrollment.clone()),
        ("receipt_owner_enrollment", enrollment),
        ("delivery_kind", uint(8)),
        ("contact_signature", bytes(64)),
        ("old", opening),
        ("new_blind", bytes(32)),
        ("action", uint(8)),
        ("slot", slot),
        ("own_map", map.clone()),
        ("opposite_map", map.clone()),
        ("pair_map", map),
        ("pair_exists", AbiType::Boolean),
        ("resolution", resolution),
        ("acknowledgment", ack),
    ];
    public
        .into_iter()
        .map(|(n, t)| (n, t, AbiVisibility::Public))
        .chain(
            private
                .into_iter()
                .map(|(n, t)| (n, t, AbiVisibility::Private)),
        )
        .collect()
}

fn same(actual: &AbiType, expected: &AbiType) -> bool {
    match (actual, expected) {
        (AbiType::Struct { fields: a, .. }, AbiType::Struct { fields: b, .. }) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b)
                    .all(|((an, at), (bn, bt))| an == bn && same(at, bt))
        }
        (AbiType::Array { length: a, typ: at }, AbiType::Array { length: b, typ: bt }) => {
            a == b && same(at, bt)
        }
        _ => actual == expected,
    }
}
pub(super) fn check(abi: &Abi) -> Result<(), Error> {
    let expected = expected();
    if abi.return_type.is_some()
        || abi.parameters.len() != expected.len()
        || !abi
            .parameters
            .iter()
            .zip(expected)
            .all(|(a, (n, t, v))| a.name == n && a.visibility == v && same(&a.typ, &t))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn flatten(value: &InputValue, typ: &AbiType, result: &mut Vec<[u8; 32]>) -> Result<(), Error> {
    match (value, typ) {
        (InputValue::Field(field), _) => result.push(
            field
                .to_be_bytes()
                .as_slice()
                .try_into()
                .map_err(|_| Error::Invalid)?,
        ),
        (InputValue::Vec(values), AbiType::Array { typ, .. }) => {
            for v in values {
                flatten(v, typ, result)?;
            }
        }
        (InputValue::Struct(values), AbiType::Struct { fields, .. }) => {
            for (name, typ) in fields {
                flatten(values.get(name).ok_or(Error::Invalid)?, typ, result)?;
            }
        }
        _ => return Err(Error::Invalid),
    }
    Ok(())
}
pub(super) fn public_inputs(abi: &Abi, json: &str) -> Result<Vec<[u8; 32]>, Error> {
    check(abi)?;
    let inputs = Format::Json.parse(json, abi).map_err(|_| Error::Invalid)?;
    abi.encode(&inputs, None).map_err(|_| Error::Invalid)?;
    let mut public = Vec::new();
    for p in &abi.parameters {
        if p.visibility == AbiVisibility::Public {
            flatten(
                inputs.get(&p.name).ok_or(Error::Invalid)?,
                &p.typ,
                &mut public,
            )?;
        }
    }
    if public.len() != 345 {
        return Err(Error::Invalid);
    }
    for field in &public {
        czkp::field(field, false).map_err(|_| Error::Invalid)?;
    }
    Ok(public)
}

pub(super) fn public_only(abi: &Abi, json: &str) -> Result<Vec<[u8; 32]>, Error> {
    check(abi)?;
    let public = Abi {
        parameters: abi
            .parameters
            .iter()
            .filter(|p| p.visibility == AbiVisibility::Public)
            .cloned()
            .collect(),
        return_type: None,
        error_types: Default::default(),
    };
    let inputs = Format::Json
        .parse(json, &public)
        .map_err(|_| Error::Invalid)?;
    public.encode(&inputs, None).map_err(|_| Error::Invalid)?;
    let mut result = Vec::new();
    for p in &public.parameters {
        flatten(
            inputs.get(&p.name).ok_or(Error::Invalid)?,
            &p.typ,
            &mut result,
        )?;
    }
    if result.len() != 345 {
        return Err(Error::Invalid);
    }
    Ok(result)
}
