use core::borrow::Borrow;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

pub fn vec_from_hex<'de, D, B>(deserializer: D) -> Result<B, D::Error>
where
    D: Deserializer<'de>,
    B: From<Vec<u8>>,
{
    if deserializer.is_human_readable() {
        let s: &str = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(Error::custom)?;
        Ok(B::from(bytes))
    } else {
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
        Ok(B::from(bytes.to_owned()))
    }
}
pub fn hex_from_bytes<'de, S, B>(bytes: &B, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    B: Borrow<[u8]>,
{
    if serializer.is_human_readable() {
        let bytes = hex::encode(bytes.borrow());
        serializer.serialize_str(&bytes)
    } else {
        serializer.serialize_bytes(bytes.borrow())
    }
}
