use core::borrow::Borrow;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};
use ed25519_dalek::PublicKey as DalekPublicKey;

#[cfg(feature = "std")]
pub fn serialize_pub_key<S>(public_key: &DalekPublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        let bytes = hex::encode(public_key.as_bytes());
        serializer.serialize_str(&bytes)
    } else {
        serializer.serialize_bytes(public_key.as_bytes())
    }
}

#[cfg(feature = "std")]
pub fn deserialize_pub_key<'de, D>(deserializer: D) -> Result<DalekPublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let s: &str = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(Error::custom)?;
        let pub_key = DalekPublicKey::from_bytes(bytes.as_slice()).map_err(Error::custom)?;
        Ok(pub_key)
    } else {
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
        let pub_key = DalekPublicKey::from_bytes(bytes).map_err(Error::custom)?;
        Ok(pub_key)
    }
}


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
