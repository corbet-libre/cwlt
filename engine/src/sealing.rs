//! Owner-specific sealing of private engine state; never a generic byte oracle.
use super::{Engine, Error};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use std::sync::Arc;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"cwlt.extension-holder.v1\0";
const RECORD_MAGIC: &[u8] = b"cwlt.extension-holder.v2\0";
const NONCE: usize = 24;
// Current uninitialized state: state tag, original purpose seed. Accepted-state
// encoding is intentionally not inferred from caller bytes or another proof.
const PLAIN: usize = 1 + 32;
const SIZE: usize = MAGIC.len() + NONCE + PLAIN + 16;
const MAX_SIZE: usize = SIZE + 8 * 1024 * 1024 + 16 * 1024;

pub(super) struct Binding {
    cipher: XChaCha20Poly1305,
    context: Vec<u8>,
}
impl Binding {
    pub(super) fn matches_context(&self, context: &[u8]) -> bool {
        self.context[MAGIC.len()..] == *context
    }
    pub(super) fn new(key: &[u8; 32], context: &[u8]) -> Result<Self, Error> {
        if context.is_empty() || context.len() > 4096 {
            return Err(Error::Invalid);
        }
        let mut aad = Vec::with_capacity(MAGIC.len() + context.len());
        aad.extend_from_slice(MAGIC);
        aad.extend_from_slice(context);
        Ok(Self {
            cipher: XChaCha20Poly1305::new(key.into()),
            context: aad,
        })
    }
}

/// Bounded authenticated ciphertext. It never contains an externally readable
/// opening, and cannot be used to replace the engine's immutable key binding.
pub struct Sealed(Vec<u8>);
impl Sealed {
    /// Validate the outer format before authenticated restore by the same engine.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if !((bytes.len() == SIZE && bytes.starts_with(MAGIC))
            || (bytes.len() > SIZE && bytes.len() <= MAX_SIZE && bytes.starts_with(RECORD_MAGIC)))
        {
            return Err(Error::Invalid);
        }
        Ok(Self(bytes.to_vec()))
    }
    /// Bytes safe to persist through the original encrypted Store.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl Engine {
    /// Seal only this engine's private state using its original immutable key.
    /// There is no caller-selected key, context, plaintext or rekey argument.
    pub fn seal(&self) -> Result<Sealed, Error> {
        let mut nonce = [0; NONCE];
        getrandom::fill(&mut nonce).map_err(|_| Error::Crypto)?;
        let mut plaintext = Zeroizing::new(vec![0; PLAIN]);
        plaintext[1..].copy_from_slice(self.seed.as_ref());
        if let Some(record) = &self.record {
            record.validate()?;
            plaintext[0] = 1;
            // Only this concrete private owner state is serializable here.
            serde_json::to_writer(&mut *plaintext, record).map_err(|_| Error::Invalid)?;
        }
        if plaintext.len() + MAGIC.len() + NONCE + 16 > MAX_SIZE {
            return Err(Error::Invalid);
        }
        let ciphertext = self
            .sealing
            .cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &self.sealing.context,
                },
            )
            .map_err(|_| Error::Crypto)?;
        let mut bytes = Vec::with_capacity(SIZE);
        bytes.extend_from_slice(if self.record.is_some() {
            RECORD_MAGIC
        } else {
            MAGIC
        });
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);
        Ok(Sealed(bytes))
    }

    /// Authenticate a separate candidate while leaving the live engine intact.
    /// Same-key but wrong-root state is refused; no silent genesis reset or merge.
    pub fn restored(&self, sealed: &Sealed) -> Result<Self, Error> {
        let offset = MAGIC.len();
        let nonce: [u8; NONCE] = sealed.0[offset..offset + NONCE]
            .try_into()
            .map_err(|_| Error::Crypto)?;
        let plaintext = Zeroizing::new(
            self.sealing
                .cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &sealed.0[offset + NONCE..],
                        aad: &self.sealing.context,
                    },
                )
                .map_err(|_| Error::Crypto)?,
        );
        if plaintext.len() < PLAIN || plaintext[1..PLAIN] != self.seed[..] {
            return Err(Error::Crypto);
        }
        let record = match plaintext[0] {
            0 if plaintext.len() == PLAIN && sealed.0.starts_with(MAGIC) => None,
            1 if sealed.0.starts_with(RECORD_MAGIC) => {
                let record: super::record::State =
                    serde_json::from_slice(&plaintext[PLAIN..]).map_err(|_| Error::Crypto)?;
                record.validate()?;
                Some(record)
            }
            _ => return Err(Error::Crypto),
        };
        Ok(Self {
            seed: self.seed.clone(),
            sealing: Arc::clone(&self.sealing),
            record,
        })
    }
}
