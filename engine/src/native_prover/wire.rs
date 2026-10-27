//! Compact frame encoding of the public byte blobs (circuit group, key group, setup) that
//! the parent hands the disposable worker. A byte slice serialized the serde default way is a
//! JSON array of decimal numbers (about 3.7 text bytes per setup byte, 300 MB for the 80 MiB
//! setup, seconds of encoding and parsing on both sides); one Base64 string is a third larger
//! than the bytes and parses in milliseconds. Only the private frame between the parent and its
//! own worker changes: the bytes, their digests and every proof are exactly the same.
use data_encoding::BASE64;
use serde::{Deserializer, Serializer, de};

pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&BASE64.encode(bytes))
}

pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct Text;
    impl de::Visitor<'_> for Text {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a Base64 string")
        }
        fn visit_str<E: de::Error>(self, text: &str) -> Result<Vec<u8>, E> {
            BASE64
                .decode(text.as_bytes())
                .map_err(|_| E::custom("invalid Base64"))
        }
    }
    deserializer.deserialize_str(Text)
}
