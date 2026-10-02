//! Owner-specific sealing of private engine state; never a generic byte oracle.
use super::{Engine, Error};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use std::sync::Arc;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"cwlt.extension-holder.v1\0";
const NONCE: usize = 24;
// Current uninitialized state: state tag, original purpose seed. Accepted-state
// encoding is intentionally not inferred from caller bytes or another proof.
const PLAIN: usize = 1 + 32;
const SIZE: usize = MAGIC.len() + NONCE + PLAIN + 16;

pub(super) struct Binding {
    cipher: XChaCha20Poly1305,
    context: Vec<u8>,
}
impl Binding {
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
        if bytes.len() != SIZE || !bytes.starts_with(MAGIC) {
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
        let mut plaintext = Zeroizing::new([0; PLAIN]);
        plaintext[1..].copy_from_slice(self.seed.as_ref());
        let ciphertext = self
            .sealing
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &self.sealing.context,
                },
            )
            .map_err(|_| Error::Crypto)?;
        let mut bytes = Vec::with_capacity(SIZE);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);
        Ok(Sealed(bytes))
    }

    /// Authenticate a separate candidate while leaving the live engine intact.
    /// Same-key but wrong-root state is refused; no silent genesis reset or merge.
    pub fn restored(&self, sealed: &Sealed) -> Result<Self, Error> {
        let offset = MAGIC.len();
        let plaintext = Zeroizing::new(
            self.sealing
                .cipher
                .decrypt(
                    XNonce::from_slice(&sealed.0[offset..offset + NONCE]),
                    Payload {
                        msg: &sealed.0[offset + NONCE..],
                        aad: &self.sealing.context,
                    },
                )
                .map_err(|_| Error::Crypto)?,
        );
        if plaintext.len() != PLAIN || plaintext[0] != 0 || plaintext[1..] != self.seed[..] {
            return Err(Error::Crypto);
        }
        Ok(Self {
            seed: self.seed.clone(),
            sealing: Arc::clone(&self.sealing),
        })
    }
}
