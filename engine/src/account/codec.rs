//! Tiny length-checked binary codec shared by every sealed account record.
use crate::Error;
use zeroize::Zeroizing;

/// Growing plaintext buffer, wiped on drop.
pub(crate) struct Writer(pub(crate) Zeroizing<Vec<u8>>);
impl Writer {
    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }
    pub(crate) fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }
    pub(crate) fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    pub(crate) fn var(&mut self, value: &[u8]) -> Result<(), Error> {
        self.u32(u32::try_from(value.len()).map_err(|_| Error::Invalid)?);
        self.bytes(value);
        Ok(())
    }
}

/// Bounds-checked reader over a plaintext.
pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);
impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::Crypto);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Crypto)
    }
    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    pub(crate) fn var(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let n = usize::try_from(self.u32()?).map_err(|_| Error::Crypto)?;
        if n > max {
            return Err(Error::Crypto);
        }
        self.take(n)
    }
}
