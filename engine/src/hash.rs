//! Original account hash transcript; maintained BB owns Poseidon2.
use super::{Error, Field};

pub(super) fn integer(value: u64) -> Field {
    let mut field = [0; 32];
    field[24..].copy_from_slice(&value.to_be_bytes());
    field
}

// Private adapter boundary; consumers cannot supply a hash/proof callback.
// ACCOUNT_DOMAIN and tag construction stay here, never caller-selected.
pub(super) trait Hash {
    async fn poseidon2(&mut self, fields: &[Field]) -> Result<Field, Error>;

    async fn tagged(&mut self, tag: u64, values: &[Field]) -> Result<Field, Error> {
        let mut domain = [0; 32];
        let text = b"cfrm.account-state.v2";
        domain[32 - text.len()..].copy_from_slice(text);
        let mut fields = Vec::with_capacity(values.len() + 2);
        fields.extend([domain, integer(tag)]);
        fields.extend_from_slice(values);
        let output = self.poseidon2(&fields).await?;
        czkp::field(&output, false).map_err(|_| Error::Crypto)?;
        Ok(output)
    }
}
