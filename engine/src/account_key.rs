//! Fixed account-key custody, separate from unchanged legacy Engine formats.
//! This internal crypto primitive never verifies Store, admission or a proof.
use crate::{Engine, Error, account, sealing};
use chacha20poly1305::{
    XNonce,
    aead::{Aead, Payload},
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner},
    elliptic_curve::Generate,
};
use std::sync::Arc;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"cwlt.account-owner.v1\0";
const PLAIN: usize = 1 + 32 + 32 + 32;
const SIZE: usize = MAGIC.len() + 24 + PLAIN + 16;

/// Fixed public cryptographic data, not an accepted enrollment or a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Projection {
    /// Original uncompressed P-256 x/y coordinates, without the SEC1 prefix.
    pub public_key: [u8; 64],
    /// Original maintained commitment to the balance-purpose private secret.
    pub registered_secret: [u8; 32],
}

/// One private random P-256 owner; no raw key, signing oracle or Clone exists.
/// The upper wallet releases its public data only after a genuine Store receipt.
pub struct AccountKey {
    key: SigningKey,
    seed: Zeroizing<[u8; 32]>,
    binding: Arc<sealing::Binding>,
    scope: String,
    operation: [u8; 32],
}

/// Bounded ciphertext for this concrete private owner only.
pub struct SealedAccountKey(Vec<u8>);

/// One account-key signature over exactly one digest. No Clone, Debug or serde.
///
/// Only the raw balance seed and balance sealing key can mint it, and those bytes
/// exist only inside Keys custody (ckmg's private identity roots); no [`Engine`],
/// [`AccountKey`] or other lent value produces one. Keys mints it after the ledger,
/// the exact (action, digest) admission and the final current recheck, for the one
/// digest it admitted. [`Self::sign`] consumes it: it restores the key, signs that
/// digest and drops the key.
///
/// ```compile_fail
/// # fn escape(engine: &cwlt_engine::Engine, sealed: &cwlt_engine::account_key::SealedAccountKey) {
/// let key = engine.restore_account_key(sealed, "scope").unwrap();
/// let _ = key.sign_prehash(engine, &[0; 32]);
/// # }
/// ```
/// ```compile_fail
/// # fn copy(signing: cwlt_engine::account_key::AccountSigning) {
/// let again = signing.clone();
/// # }
/// ```
pub struct AccountSigning {
    engine: Engine,
    digest: [u8; 32],
}

impl AccountSigning {
    /// Bind the raw balance seed and sealing key to one digest. Both caller buffers
    /// are wiped on every return. Keys calls this only for a digest it admitted.
    pub fn mint(
        seed: &mut [u8; 32],
        sealing_key: &mut [u8; 32],
        wallet_context: &[u8],
        digest: [u8; 32],
    ) -> Result<Self, Error> {
        Ok(Self {
            engine: Engine::from_seed_and_sealing_key(seed, sealing_key, wallet_context)?,
            digest,
        })
    }

    /// Restore the account key from `sealed` under `scope`, sign exactly the minted
    /// digest and drop the key.
    pub fn sign(self, sealed: &SealedAccountKey, scope: &str) -> Result<[u8; 64], Error> {
        let key = self.engine.restore_account_key(sealed, scope)?;
        key.sign_prehash(&self.engine, &self.digest)
    }
}
impl SealedAccountKey {
    /// Check the exact envelope before original immutable-binding authentication.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SIZE || !bytes.starts_with(MAGIC) {
            return Err(Error::Invalid);
        }
        Ok(Self(bytes.to_vec()))
    }
    /// Encrypted bytes safe to retain inside the original atomic Store.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Engine {
    /// Generate one random owner for an explicit operation under this binding.
    /// This internal construction grants no enrollment, Store or signing right.
    pub fn prepare_account_key(
        &self,
        scope: &str,
        operation: [u8; 32],
    ) -> Result<AccountKey, Error> {
        if operation == [0; 32] || !self.sealing.matches_context(scope.as_bytes()) {
            return Err(Error::Invalid);
        }
        Ok(AccountKey {
            key: SigningKey::try_generate().map_err(|_| Error::Crypto)?,
            seed: self.seed.clone(),
            binding: Arc::clone(&self.sealing),
            scope: scope.into(),
            operation,
        })
    }

    /// Restore only this fixed owner codec; never generate on absence or refusal.
    pub fn restore_account_key(
        &self,
        sealed: &SealedAccountKey,
        scope: &str,
    ) -> Result<AccountKey, Error> {
        if !self.sealing.matches_context(scope.as_bytes()) {
            return Err(Error::Crypto);
        }
        let offset = MAGIC.len();
        let nonce: [u8; 24] = sealed.0[offset..offset + 24]
            .try_into()
            .map_err(|_| Error::Crypto)?;
        let aad = [MAGIC, self.sealing.context.as_slice()].concat();
        let plaintext = Zeroizing::new(
            self.sealing
                .cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &sealed.0[offset + 24..],
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::Crypto)?,
        );
        if plaintext.len() != PLAIN || plaintext[0] != 0 || plaintext[1..33] != self.seed[..] {
            return Err(Error::Crypto);
        }
        let operation: [u8; 32] = plaintext[33..65].try_into().map_err(|_| Error::Crypto)?;
        if operation == [0; 32] {
            return Err(Error::Crypto);
        }
        Ok(AccountKey {
            key: SigningKey::from_slice(&plaintext[65..97]).map_err(|_| Error::Crypto)?,
            seed: self.seed.clone(),
            binding: Arc::clone(&self.sealing),
            scope: scope.into(),
            operation,
        })
    }
}

impl AccountKey {
    /// Authenticated creation-operation metadata, not a receipt or a permission.
    pub fn operation(&self) -> [u8; 32] {
        self.operation
    }

    /// Pure public data for internal composition; production release is owned by
    /// DurableAccountOwner, after actual receipt and freshly authorized Keys Use.
    pub fn projection(&self, engine: &Engine) -> Result<Projection, Error> {
        if self.seed[..] != engine.seed[..]
            || !engine.sealing.matches_context(self.scope.as_bytes())
        {
            return Err(Error::Crypto);
        }
        let point = self.key.verifying_key().to_sec1_point(false);
        let public_key = point.as_bytes()[1..]
            .try_into()
            .map_err(|_| Error::Crypto)?;
        Ok(Projection {
            public_key,
            registered_secret: account::registered_secret(&self.scope, &self.seed)?,
        })
    }

    /// Sign one 32-byte digest with the account key: P-256, deterministic (RFC 6979), low-S,
    /// the exact form the update circuit and `verify_prehash` accept. Crate-private: the
    /// only caller is [`AccountSigning::sign`], which Keys mints for one admitted digest.
    /// The engine must be the one that restored this key.
    pub(crate) fn sign_prehash(
        &self,
        engine: &Engine,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], Error> {
        if self.seed[..] != engine.seed[..]
            || !engine.sealing.matches_context(self.scope.as_bytes())
        {
            return Err(Error::Crypto);
        }
        let signature: Signature = self.key.sign_prehash(digest).map_err(|_| Error::Crypto)?;
        let signature = signature.normalize_s();
        signature
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| Error::Crypto)
    }

    /// Encrypt only the fixed private state under the original root/context.
    /// No caller-selected plaintext, key, nonce or context is accepted.
    pub fn seal(&self) -> Result<SealedAccountKey, Error> {
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| Error::Crypto)?;
        let mut plaintext = Zeroizing::new(vec![0; PLAIN]);
        plaintext[1..33].copy_from_slice(self.seed.as_ref());
        plaintext[33..65].copy_from_slice(&self.operation);
        let private = Zeroizing::new(self.key.to_bytes());
        plaintext[65..97].copy_from_slice(private.as_ref());
        let aad = [MAGIC, self.binding.context.as_slice()].concat();
        let encrypted = self
            .binding
            .cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?;
        Ok(SealedAccountKey([MAGIC, &nonce, &encrypted].concat()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn engine(seed: u8, key: u8, scope: &[u8]) -> Engine {
        Engine::from_seed_and_sealing_key(&mut [seed; 32], &mut [key; 32], scope).unwrap()
    }
    #[test]
    fn separate_owner_wire_restores_same_random_key_and_refuses_foreign_roots_and_legacy_wire() {
        let original = engine(7, 8, b"community");
        let key = original.prepare_account_key("community", [1; 32]).unwrap();
        let public = key.projection(&original).unwrap();
        let sealed = key.seal().unwrap();
        assert!(crate::Sealed::from_bytes(sealed.as_bytes()).is_err());
        assert!(SealedAccountKey::from_bytes(original.seal().unwrap().as_bytes()).is_err());
        let equal = engine(7, 8, b"community");
        let reopened = equal.restore_account_key(&sealed, "community").unwrap();
        assert_eq!(reopened.operation(), [1; 32]);
        assert_eq!(reopened.projection(&equal).unwrap(), public);
        assert_ne!(
            equal
                .prepare_account_key("community", [2; 32])
                .unwrap()
                .projection(&equal)
                .unwrap(),
            public
        );
        assert!(
            engine(6, 8, b"community")
                .restore_account_key(&sealed, "community")
                .is_err()
        );
        assert!(
            engine(7, 6, b"community")
                .restore_account_key(&sealed, "community")
                .is_err()
        );
        assert!(
            engine(7, 8, b"other")
                .restore_account_key(&sealed, "other")
                .is_err()
        );
        assert!(original.restore_account_key(&sealed, "other").is_err());
        assert!(original.prepare_account_key("community", [0; 32]).is_err());
        assert!(original.prepare_account_key("other", [1; 32]).is_err());
    }
    #[test]
    fn a_signature_verifies_for_its_projection_only_and_a_foreign_engine_cannot_sign() {
        let engine = engine(7, 8, b"community");
        let key = engine.prepare_account_key("community", [1; 32]).unwrap();
        let public = key.projection(&engine).unwrap().public_key;
        let digest = [9u8; 32];
        let signature = key.sign_prehash(&engine, &digest).unwrap();
        assert_eq!(signature, key.sign_prehash(&engine, &digest).unwrap());
        crate::account::verify_prehash(&public, &digest, &signature).unwrap();
        assert!(crate::account::verify_prehash(&public, &[8; 32], &signature).is_err());
        let other = self::engine(6, 8, b"community");
        assert!(key.sign_prehash(&other, &digest).is_err());
    }
    #[test]
    fn a_minted_signing_signs_exactly_its_digest_and_needs_the_same_roots() {
        let engine = engine(7, 8, b"community");
        let key = engine.prepare_account_key("community", [1; 32]).unwrap();
        let public = key.projection(&engine).unwrap().public_key;
        let sealed = key.seal().unwrap();
        let mint = |seed, sealing, digest| {
            AccountSigning::mint(&mut [seed; 32], &mut [sealing; 32], b"community", digest).unwrap()
        };
        let signature = mint(7, 8, [9; 32]).sign(&sealed, "community").unwrap();
        crate::account::verify_prehash(&public, &[9; 32], &signature).unwrap();
        // Deterministic: a retry recomputes identical bytes.
        assert_eq!(
            mint(7, 8, [9; 32]).sign(&sealed, "community").unwrap(),
            signature
        );
        assert!(mint(6, 8, [9; 32]).sign(&sealed, "community").is_err());
        assert!(mint(7, 6, [9; 32]).sign(&sealed, "community").is_err());
        assert!(mint(7, 8, [9; 32]).sign(&sealed, "other").is_err());
    }

    #[test]
    fn authentic_nonpending_tag_and_zero_operation_never_restore() {
        let engine = engine(7, 8, b"community");
        let key = engine.prepare_account_key("community", [1; 32]).unwrap();
        let sealed = key.seal().unwrap();
        let offset = MAGIC.len();
        let nonce: [u8; 24] = sealed.0[offset..offset + 24].try_into().unwrap();
        let aad = [MAGIC, engine.sealing.context.as_slice()].concat();
        let plaintext = Zeroizing::new(
            engine
                .sealing
                .cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &sealed.0[offset + 24..],
                        aad: &aad,
                    },
                )
                .unwrap(),
        );
        for tag in [true, false] {
            let mut malformed = plaintext.clone();
            if tag {
                malformed[0] = 1;
            } else {
                malformed[33..65].fill(0);
            }
            let encrypted = engine
                .sealing
                .cipher
                .encrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: malformed.as_ref(),
                        aad: &aad,
                    },
                )
                .unwrap();
            let wire = SealedAccountKey::from_bytes(&[MAGIC, &nonce, &encrypted].concat()).unwrap();
            assert!(engine.restore_account_key(&wire, "community").is_err());
        }
    }
}
