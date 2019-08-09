use arrayvec::ArrayVec;
use core::borrow::Borrow;
use core::convert::TryFrom;
#[cfg(feature = "std")]
use std::io::Write;
use varu64::{
    decode as varu64_decode, encode as varu64_encode, encoding_length as varu64_encoding_length,
};

#[cfg(feature = "std")]
use varu64::encode_write as varu64_encode_write;

use ed25519_dalek::{PublicKey as DalekPublicKey, Signature as DalekSignature};

use super::signature::{Signature, MAX_SIGNATURE_SIZE};
use super::yamf_hash::{YamfHash, MAX_YAMF_HASH_SIZE};
use super::yamf_signatory::{YamfSignatory, MAX_YAMF_SIGNATORY_SIZE};
use crate::yamf_hash::new_blake2b;
use ed25519_dalek::{Keypair, PublicKey};

pub use crate::error::*;

const TAG_BYTE_LENGTH: usize = 1;
const MAX_VARU64_SIZE: usize = 9;
pub const MAX_ENTRY_SIZE_: usize = TAG_BYTE_LENGTH
    + MAX_SIGNATURE_SIZE
    + MAX_YAMF_SIGNATORY_SIZE
    + (MAX_YAMF_HASH_SIZE * 3)
    + (MAX_VARU64_SIZE * 2);

/// This is useful if you need to know at compile time how big an entry can get.
pub const MAX_ENTRY_SIZE: usize = 316;

// Yes, this is hacky. It's because cbindgen can't understand how to add consts together. This is a
// way to hard code a value for MAX_ENTRY_SIZE that cbindgen can use, but make sure at compile time
// that the value is actually correct.
const_assert_eq!(max_entry_size; MAX_ENTRY_SIZE_ as isize, MAX_ENTRY_SIZE as isize);

#[cfg_attr(feature = "std", derive(Deserialize))]
#[derive(Serialize, Debug, Eq, PartialEq)]
pub struct Entry<'a, H, A, S>
where
    H: Borrow<[u8]>,
    A: Borrow<[u8]>,
    S: Borrow<[u8]>,
{
    #[serde(rename = "isEndOfFeed")]
    pub is_end_of_feed: bool,
    #[cfg_attr(feature = "std", serde(bound(deserialize = "H: From<Vec<u8>>")))]
    #[serde(rename = "payloadHash")]
    pub payload_hash: YamfHash<H>,
    #[serde(rename = "payloadSize")]
    pub payload_size: u64,
    #[cfg_attr(feature = "std", serde(bound(deserialize = "A: From<Vec<u8>>")))]
    pub author: YamfSignatory<'a, A>,
    #[serde(rename = "sequenceNumber")]
    pub seq_num: u64,
    #[serde(rename = "backLink")]
    pub backlink: Option<YamfHash<H>>,
    #[serde(rename = "lipmaaLink")]
    pub lipmaa_link: Option<YamfHash<H>>,
    #[serde(rename = "signature")]
    #[cfg_attr(feature = "std", serde(bound(deserialize = "S: From<Vec<u8>>")))]
    pub sig: Option<Signature<S>>,
}

impl<'a> TryFrom<&'a [u8]> for Entry<'a, &'a [u8], &'a [u8], &'a [u8]> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Entry<'a, &'a [u8], &'a [u8], &'a [u8]>, Self::Error> {
        decode(bytes)
    }
}

impl<'a, H, A, S> TryFrom<Entry<'a, H, A, S>> for ArrayVec<[u8; 512]>
where
    H: Borrow<[u8]>,
    A: Borrow<[u8]>,
    S: Borrow<[u8]>,
{
    type Error = Error;

    fn try_from(entry: Entry<'a, H, A, S>) -> Result<ArrayVec<[u8; 512]>, Self::Error> {
        let mut buff = [0u8; 512];
        let len = entry.encode(&mut buff)?;
        let mut vec = ArrayVec::<[u8; 512]>::from(buff);
        unsafe {
            vec.set_len(len);
        }
        Ok(vec)
    }
}

impl<'a, H, A, S> Entry<'a, H, A, S>
where
    H: Borrow<[u8]>,
    A: Borrow<[u8]>,
    S: Borrow<[u8]>,
{
    pub fn publish(
        out: &mut [u8],
        key_pair: Option<&Keypair>,
        payload: &[u8],
        is_end_of_feed: bool,
        last_seq_num: u64,
        lipmaa_entry_bytes: Option<&[u8]>,
        backlink_bytes: Option<&[u8]>,
    ) -> Result<usize, Error> {
        let public_key = key_pair
            .as_ref()
            .map(|keys| keys.public.clone())
            .ok_or(Error::PublishWithoutKeypair)?;

        let author = YamfSignatory::<&[u8]>::Ed25519(&public_key.as_bytes()[..], None);

        // calc the payload hash
        let payload_hash = new_blake2b(payload);
        let payload_size = payload.len() as u64;

        let seq_num = last_seq_num + 1;

        let mut entry: Entry<_, _, &[u8]> = Entry {
            is_end_of_feed,
            payload_hash,
            payload_size,
            author,
            seq_num,
            backlink: None,
            lipmaa_link: None,
            sig: None,
        };

        // if the seq is larger than 1, we need to append the lipmaa and backlink hashes.
        if seq_num > 1 {
            let lipmaa_link =
                new_blake2b(lipmaa_entry_bytes.ok_or(Error::PublishWithoutLipmaaEntry)?);

            //Make sure we're not trying to publish after the end of a feed.
            let backlink_entry =
                decode(&backlink_bytes.ok_or(Error::PublishWithoutBacklinkEntry)?[..])?;
            if backlink_entry.is_end_of_feed {
                return Err(Error::PublishAfterEndOfFeed);
            }

            let backlink = new_blake2b(backlink_bytes.ok_or(Error::PublishWithoutBacklinkEntry)?);

            entry.backlink = Some(backlink);
            entry.lipmaa_link = Some(lipmaa_link);
        }

        let mut buff = [0u8; 512];
        let buff_size = entry.encode(&mut buff)?;

        let signature = key_pair
            .as_ref()
            .ok_or(Error::PublishWithoutSecretKey)?
            .sign(&buff[..buff_size]);
        let sig_bytes = &signature.to_bytes()[..];
        let signature = Signature(sig_bytes.into());

        entry.sig = Some(signature);

        entry.encode(out)
    }
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < self.encoding_length() {
            return Err(Error::EncodeBufferLength);
        }

        let mut next_byte_num = 0;

        // Encode the end of feed.
        if self.is_end_of_feed {
            out[0] = 1;
        } else {
            out[0] = 0;
        }
        next_byte_num += 1;

        next_byte_num += self
            .payload_hash
            .encode(&mut out[next_byte_num..])
            .map_err(|_| Error::EncodePayloadHashError)?;
        next_byte_num += varu64_encode(self.payload_size, &mut out[next_byte_num..]);
        next_byte_num += self
            .author
            .encode(&mut out[next_byte_num..])
            .map_err(|_| Error::EncodeAuthorError)?;
        next_byte_num += varu64_encode(self.seq_num, &mut out[next_byte_num..]);

        // Encode the backlink and lipmaa links if its not the first sequence
        next_byte_num = match (self.seq_num, &self.backlink, &self.lipmaa_link) {
            (n, Some(ref backlink), Some(ref lipmaa_link)) if n > 1 => {
                next_byte_num += backlink
                    .encode(&mut out[next_byte_num..])
                    .map_err(|_| Error::EncodeBacklinkError)?;
                next_byte_num += lipmaa_link
                    .encode(&mut out[next_byte_num..])
                    .map_err(|_| Error::EncodeLipmaaError)?;
                Ok(next_byte_num)
            }
            (n, Some(_), Some(_)) if n <= 1 => Err(Error::EncodeEntryHasBacklinksWhenSeqZero),
            _ => Ok(next_byte_num),
        }?;

        // Encode the signature
        if let Some(ref sig) = self.sig {
            next_byte_num += sig
                .encode(&mut out[next_byte_num..])
                .map_err(|_| Error::EncodeSigError)?;
        }

        Ok(next_byte_num as usize)
    }

    #[cfg(feature = "std")]
    pub fn encode_write<W: Write>(&self, mut w: W) -> Result<()> {
        // Encode the "is end of feed" tag.
        let mut is_end_of_feed_byte = [0];
        if self.is_end_of_feed {
            is_end_of_feed_byte[0] = 1;
        }
        w.write_all(&is_end_of_feed_byte[..])
            .map_err(|_| Error::EncodeIsEndOfFeedError)?;

        // Encode the payload hash
        self.payload_hash
            .encode_write(&mut w)
            .map_err(|_| Error::EncodePayloadHashError)?;

        // Encode the payload size
        varu64_encode_write(self.payload_size, &mut w)
            .map_err(|_| Error::EncodePayloadSizeError)?;
        self.author
            .encode_write(&mut w)
            .map_err(|_| Error::EncodeAuthorError)?;

        // Encode the sequence number
        varu64_encode_write(self.seq_num, &mut w).map_err(|_| Error::EncodeSeqError)?;

        // Encode the backlink and lipmaa links if its not the first sequence
        match (self.seq_num, &self.backlink, &self.lipmaa_link) {
            (n, Some(ref backlink), Some(ref lipmaa_link)) if n > 1 => {
                backlink
                    .encode_write(&mut w)
                    .map_err(|_| Error::EncodeBacklinkError)?;
                lipmaa_link
                    .encode_write(&mut w)
                    .map_err(|_| Error::EncodeLipmaaError)
            }
            (n, Some(_), Some(_)) if n <= 1 => Err(Error::EncodeEntryHasBacklinksWhenSeqZero),
            _ => Ok(()),
        }?;

        // Encode the signature
        if let Some(ref sig) = self.sig {
            sig.encode_write(&mut w)
                .map_err(|_| Error::EncodeSigError)?;
        }

        Ok(())
    }

    pub fn encoding_length(&self) -> usize {
        TAG_BYTE_LENGTH
            + self.payload_hash.encoding_length()
            + varu64_encoding_length(self.payload_size)
            + self.author.encoding_length()
            + varu64_encoding_length(self.seq_num)
            + self
                .backlink
                .as_ref()
                .map(|backlink| backlink.encoding_length())
                .unwrap_or(0)
            + self
                .lipmaa_link
                .as_ref()
                .map(|lipmaa_link| lipmaa_link.encoding_length())
                .unwrap_or(0)
            + self
                .sig
                .as_ref()
                .map(|sig| sig.encoding_length())
                .unwrap_or(0)
    }
    pub fn verify_signature(&mut self) -> Result<bool> {
        //Pluck off the signature before we encode it
        let sig = self.sig.take();

        let ssb_sig = DalekSignature::from_bytes(sig.as_ref().unwrap().0.borrow())
            .map_err(|_| Error::DecodeSsbSigError)?;

        let mut buff = [0u8; 512];

        let encoded_size = self.encode(&mut buff).unwrap();

        let result = match self.author {
            YamfSignatory::Ed25519(ref author, _) => {
                let pub_key = DalekPublicKey::from_bytes(author.borrow())
                    .map_err(|_| Error::DecodeSsbPubKeyError)?;
                pub_key
                    .verify(&buff[..encoded_size], &ssb_sig)
                    .map(|_| true)
                    .unwrap_or(false)
            }
        };

        // Put the signature back on
        self.sig = sig;

        Ok(result)
    }
}

pub fn decode<'a>(bytes: &'a [u8]) -> Result<Entry<'a, &'a [u8], &'a [u8], &'a [u8]>, Error> {
    // Decode is end of feed
    if bytes.len() == 0 {
        return Err(Error::DecodeInputIsLengthZero);
    }
    let is_end_of_feed = bytes[0] == 1;

    // Decode the payload hash
    let (payload_hash, remaining_bytes) =
        YamfHash::<&[u8]>::decode(&bytes[1..]).map_err(|_| Error::DecodePayloadHashError)?;

    // Decode the payload size
    let (payload_size, remaining_bytes) = varu64_decode(remaining_bytes)
        .map_err(|(err, _)| err)
        .map_err(|_| Error::DecodePayloadSizeError)?;

    // Decode the author
    let (author, remaining_bytes) =
        YamfSignatory::<&[u8]>::decode(remaining_bytes).map_err(|_| Error::DecodeAuthorError)?;

    // Decode the sequence number
    let (seq_num, remaining_bytes) = varu64_decode(remaining_bytes)
        .map_err(|(err, _)| err)
        .map_err(|_| Error::DecodeSeqError)?;

    if seq_num == 0 {
        return Err(Error::DecodeSeqIsZero);
    }

    // Decode the backlink and lipmaa links if its not the first sequence
    let (backlink, lipmaa_link, remaining_bytes) = match seq_num {
        1 => (None, None, remaining_bytes),
        _ => {
            let (backlink, remaining_bytes) = YamfHash::<&[u8]>::decode(remaining_bytes)
                .map_err(|_| Error::DecodeBacklinkError)?;
            let (lipmaa_link, remaining_bytes) =
                YamfHash::<&[u8]>::decode(remaining_bytes).map_err(|_| Error::DecodeLipmaaError)?;
            (Some(backlink), Some(lipmaa_link), remaining_bytes)
        }
    };

    // Decode the signature
    let (sig, _) =
        Signature::<&[u8]>::decode(remaining_bytes).map_err(|_| Error::DecodeSigError)?;

    Ok(Entry {
        is_end_of_feed,
        payload_hash,
        payload_size,
        author,
        seq_num,
        backlink,
        lipmaa_link,
        sig: Some(sig),
    })
}
