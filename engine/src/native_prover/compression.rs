//! Bounded original gzip transport decoding; no circuit or witness reencoding.
use super::Error;
use flate2::read::MultiGzDecoder;
use std::io::Read;
use zeroize::Zeroizing;

pub(super) fn decode(compressed: &[u8], maximum: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    if compressed.is_empty() || compressed.len() > maximum {
        return Err(Error::Invalid);
    }
    let limit = maximum.checked_add(1).ok_or(Error::Invalid)?;
    let mut decoded = Zeroizing::new(Vec::new());
    // Concatenated members have one cumulative bound. Unlike the wrapper's
    // permissive padding case, no trailing non-member bytes are accepted.
    MultiGzDecoder::new(compressed)
        .take(limit as u64)
        .read_to_end(&mut decoded)
        .map_err(|_| Error::Invalid)?;
    if decoded.len() > maximum || !matches!(decoded.first(), Some(2 | 3)) {
        return Err(Error::Invalid);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn actual_gzip_transport_preserves_both_original_messagepack_markers() {
        for marker in [2, 3] {
            let original = [marker, 0x91, 0x90];
            assert_eq!(&**decode(&gzip(&original), 128).unwrap(), &original);
            let mut members = gzip(&original[..1]);
            members.extend(gzip(&original[1..]));
            assert_eq!(&**decode(&members, 128).unwrap(), &original);
        }
    }

    #[test]
    fn inflation_and_concatenated_members_share_the_exact_cumulative_bound() {
        let mut original = vec![3; 4096];
        original[1] = 0x90;
        let compressed = gzip(&original);
        assert!(compressed.len() < 128);
        assert!(decode(&compressed, 128).is_err());
        assert_eq!(decode(&compressed, original.len()).unwrap().len(), 4096);
        let mut members = gzip(&original[..64]);
        members.extend(gzip(&original[64..]));
        assert!(decode(&members, 128).is_err());
    }

    #[test]
    fn malformed_checksum_truncation_padding_and_foreign_format_refuse() {
        let original = gzip(&[3, 0x91, 0x90]);
        assert!(decode(&[], 128).is_err());
        assert!(decode(&original, 0).is_err());
        assert!(decode(&original[..original.len() - 1], 128).is_err());
        let mut corrupt = original.clone();
        let crc = corrupt.len() - 8;
        corrupt[crc] ^= 1;
        assert!(decode(&corrupt, 128).is_err());
        for trailing in [vec![0], vec![1, 2], gzip(&[3])[..8].to_vec()] {
            let mut bytes = original.clone();
            bytes.extend(trailing);
            assert!(decode(&bytes, 128).is_err());
        }
        assert!(decode(&gzip(&[1, 0x90]), 128).is_err());
        assert!(decode(&gzip(&[]), 128).is_err());
    }
}
