use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};
use std::borrow::Cow;
use core::borrow::Borrow;

pub fn cow_from_hex<'de, D>(deserializer: D) -> Result<Cow<'static, [u8]>, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let s: &str = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(Error::custom)?;
        Ok(Cow::Owned(bytes.to_owned()))
    } else {
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
        Ok(Cow::Owned(bytes.to_owned()))
    }
}

pub fn hex_from_cow<'de, S>(cow: &Cow<'de, [u8]>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        let bytes = hex::encode(cow.as_ref());
        serializer.serialize_str(&bytes)
    } else {
        serializer.serialize_bytes(cow.as_ref())
    }
}

//pub fn vec_from_hex<'de, D, B>(deserializer: D) -> Result<B, D::Error>
//where
//    D: Deserializer<'de>,
//    B: Borrow<[u8]> + PartialEq + Eq
//{
//    if deserializer.is_human_readable() {
//        let s: &str = Deserialize::deserialize(deserializer)?;
//        let bytes = hex::decode(s).map_err(Error::custom)?;
//        Ok(Box::new(bytes.as_slice()))
//    } else {
//        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
//        Ok(Box::new(bytes.to_owned()))
//    }
//}
pub fn hex_from_bytes<'de, S, B>(bytes: &B, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    B: Borrow<[u8]>{
    if serializer.is_human_readable() {
        let bytes = hex::encode(bytes.borrow());
        serializer.serialize_str(&bytes)
    } else {
        serializer.serialize_bytes(bytes.borrow())
    }
}
