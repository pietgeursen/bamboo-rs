use std::borrow::Cow;
use serde::{Deserialize, Deserializer, Serializer};

pub fn cow_from_hex<'de, D>(deserializer: D) -> Result<Cow<'static, [u8]>, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable(){
        let s: &str = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(s).unwrap();
        Ok(Cow::Owned(bytes.to_owned()))
    }else{
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
        Ok(Cow::Owned(bytes.to_owned()))
    }
}

pub fn hex_from_cow<'de, S>(cow: &Cow<'de, [u8]>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable(){
        let bytes = hex::encode(cow.as_ref());
        serializer.serialize_str(&bytes)
    }else{
        serializer.serialize_bytes(cow.as_ref())
    }
}
