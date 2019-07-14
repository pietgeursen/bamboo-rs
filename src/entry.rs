use snafu::{ResultExt, Snafu};
use std::io::{Error as IoError, Write};
use varu64::{
    decode as varu64_decode, encode_write as varu64_encode_write, DecodeError as varu64DecodeError,
};

use ssb_crypto::{verify_detached, PublicKey, Signature as SsbSignature};

use super::signature::{Signature, Error as SigError};
use super::yamf_hash::YamfHash;
use super::yamf_signatory::YamfSignatory;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Error when decoding entry. {}", source))]
    DecodeError { source: varu64DecodeError },
    #[snafu(display("Error when encoding field: {} of entry. {}", field, source))]
    EncodeFieldError { source: IoError, field: String },
    #[snafu(display("Error when encoding signature of entry. {}", source))]
    EncodeSigError { source: SigError },
    #[snafu(display("Error when decoding signature of entry. {}", source))]
    DecodeSigError { source: SigError },
    #[snafu(display("Error when decoding, input had length 0"))]
    DecodeInputIsLengthZero,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub struct Entry<'a> {
    pub is_end_of_feed: bool,
    pub payload_hash: YamfHash<'a>,
    pub payload_size: u64,
    pub author: YamfSignatory<'a>,
    pub seq_num: u64,
    pub backlink: Option<YamfHash<'a>>,
    pub lipmaa_link: Option<YamfHash<'a>>,
    pub sig: Option<Signature<'a>>,
}

impl<'a> Entry<'a> {
    pub fn encode_write<W: Write>(&self, mut w: W) -> Result<(), Error> {
        let mut is_end_of_feed_byte = [0];
        if self.is_end_of_feed {
            is_end_of_feed_byte[0] = 1;
        }
        w.write_all(&is_end_of_feed_byte[..])
            .context(EncodeFieldError{field: "is_end_of_feed"})?;

        self.payload_hash
            .encode_write(&mut w)
            .context(EncodeFieldError{field: "payload_hash"})?;

        varu64_encode_write(self.payload_size, &mut w)
            .context(EncodeFieldError{field: "payload_size"})?;
        self.author.encode_write(&mut w)
            .context(EncodeFieldError{field: "author"})?;
        varu64_encode_write(self.seq_num, &mut w)
            .context(EncodeFieldError{field: "seq_num"})?;

        match (self.seq_num, &self.backlink, &self.lipmaa_link) {
            (n, Some(ref backlink), Some(ref lipmaa_link)) if n > 1 => {
                backlink.encode_write(&mut w)
                    .context(EncodeFieldError{field: "backlink"})?;
                lipmaa_link.encode_write(&mut w)
                    .context(EncodeFieldError{field: "lipmaa_link"})?;
            }
            _ => (), //TODO: error
        }

        if let Some(ref sig) = self.sig {
            sig.encode_write(&mut w)
                    .context(EncodeSigError)?;
        }

        Ok(())
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Entry<'a>, Error> {
        if bytes.len() == 0 {
            return Err(Error::DecodeInputIsLengthZero)
        }
        let is_end_of_feed = bytes[0] == 1;

        let (payload_hash, remaining_bytes) = YamfHash::decode(&bytes[1..]).context(DecodeError)?;

        let (payload_size, remaining_bytes) = varu64_decode(remaining_bytes)
            .map_err(|(err, _)| err)
            .context(DecodeError)?;

        let (author, remaining_bytes) =
            YamfSignatory::decode(remaining_bytes).context(DecodeError)?;
        let (seq_num, remaining_bytes) = varu64_decode(remaining_bytes)
            .map_err(|(err, _)| err)
            .context(DecodeError)?;

        let (backlink, lipmaa_link, remaining_bytes) = match seq_num {
            1 => (None, None, remaining_bytes),
            _ => {
                let (backlink, remaining_bytes) =
                    YamfHash::decode(remaining_bytes).context(DecodeError)?;
                let (lipmaa_link, remaining_bytes) =
                    YamfHash::decode(remaining_bytes).context(DecodeError)?;
                (Some(backlink), Some(lipmaa_link), remaining_bytes)
            }
        };

        let (sig, _) = Signature::decode(remaining_bytes).context(DecodeSigError)?;

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

    pub fn verify_signature(&mut self) -> bool {
        //Pluck off the signature before we encode it
        let sig = self.sig.take();

        let ssb_sig = SsbSignature::from_slice(sig.as_ref().unwrap().0).unwrap();

        let mut buff = Vec::new();
        self.encode_write(&mut buff).unwrap();

        let result = match self.author {
            YamfSignatory::Ed25519(author, _) => {
                let pub_key = PublicKey::from_slice(author).unwrap();
                verify_detached(&ssb_sig, &buff, &pub_key)
            }
        };

        // Put the signature back on
        self.sig = sig;

        result
    }
}

#[cfg(test)]
mod tests {
    use super::{Entry, Signature, YamfHash, YamfSignatory};
    use varu64::encode_write as varu64_encode_write;

    #[test]
    fn encode_decode_entry() {
        let backlink_bytes = [0xAA; 64];
        let backlink = YamfHash::Blake2b(backlink_bytes[..].into());
        let payload_hash_bytes = [0xAB; 64];
        let payload_hash = YamfHash::Blake2b(payload_hash_bytes[..].into());
        let lipmaa_link_bytes = [0xAC; 64];
        let lipmaa_link = YamfHash::Blake2b(lipmaa_link_bytes[..].into());
        let payload_size = 512;
        let seq_num = 2;
        let sig_bytes = [0xDD; 128];
        let sig = Signature(&sig_bytes);
        let author_bytes = [0xEE; 32];
        let author = YamfSignatory::Ed25519(&author_bytes, None);

        let mut entry_vec = Vec::new();

        entry_vec.push(1u8); // end of feed is true

        payload_hash.encode_write(&mut entry_vec).unwrap();
        varu64_encode_write(payload_size, &mut entry_vec).unwrap();
        author.encode_write(&mut entry_vec).unwrap();
        varu64_encode_write(seq_num, &mut entry_vec).unwrap();
        backlink.encode_write(&mut entry_vec).unwrap();
        lipmaa_link.encode_write(&mut entry_vec).unwrap();
        sig.encode_write(&mut entry_vec).unwrap();

        let entry = Entry::decode(&entry_vec).unwrap();

        assert_eq!(entry.is_end_of_feed, true);
        assert_eq!(entry.payload_size, payload_size);

        match entry.payload_hash {
            YamfHash::Blake2b(ref hash) => {
                assert_eq!(hash.as_ref(), &payload_hash_bytes[..]);
            }
        }

        match entry.backlink {
            Some(YamfHash::Blake2b(ref hash)) => {
                assert_eq!(hash.as_ref(), &backlink_bytes[..]);
            }
            _ => panic!(),
        }
        match entry.lipmaa_link {
            Some(YamfHash::Blake2b(ref hash)) => {
                assert_eq!(hash.as_ref(), &lipmaa_link_bytes[..]);
            }
            _ => panic!(),
        }

        match entry.sig {
            Some(Signature(ref sig)) => {
                assert_eq!(sig.as_ref(), &sig_bytes[..]);
            }
            _ => panic!(),
        }

        match entry.author {
            YamfSignatory::Ed25519(auth, None) => {
                assert_eq!(auth, &author_bytes[..]);
            }
            _ => panic!(),
        }

        let mut encoded = Vec::new();

        entry.encode_write(&mut encoded).unwrap();

        assert_eq!(encoded, entry_vec);
    }
}
