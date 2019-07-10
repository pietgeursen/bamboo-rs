use std::io::{Error, Write};
use varu64::{
    decode as varu64_decode, encode as varu64_encode, encode_write as varu64_encode_write,
    DecodeError,
};

use super::signature::Signature;
use super::yamf_hash::YamfHash;
use super::yamf_signatory::YamfSignatory;

pub struct Entry<'a> {
    pub is_end_of_feed: bool,
    pub payload_hash: YamfHash<'a>,
    pub payload_size: u64,
    pub author: YamfSignatory<'a>,
    pub seq_num: u64,
    pub backlink: Option<YamfHash<'a>>,
    pub lipmaa_link: Option<YamfHash<'a>>,
    pub sig: Signature<'a>,
}

impl<'a> Entry<'a> {
    pub fn encode(self, out: &mut [u8]) {
        unimplemented!();
    }

    pub fn encode_write<W: Write>(&self, mut w: W) -> Result<(), Error> {
        let mut is_end_of_feed_byte = [0];
        if self.is_end_of_feed {
            is_end_of_feed_byte[0] = 1;
        }
        w.write_all(&is_end_of_feed_byte[..])?;
        self.payload_hash.encode_write(&mut w)?;
        varu64_encode_write(self.payload_size, &mut w)?;
        self.author.encode_write(&mut w)?;
        varu64_encode_write(self.seq_num, &mut w)?;

        match (self.seq_num, &self.backlink, &self.lipmaa_link) {
            (n, Some(ref backlink), Some(ref lipmaa_link)) if n > 1 => {
                backlink.encode_write(&mut w)?;
                lipmaa_link.encode_write(&mut w)?;
            }
            _ => (), //TODO: error
        }

        self.sig.encode_write(&mut w)?;

        Ok(())
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Entry<'a>, DecodeError> {
        let is_end_of_feed = bytes[0] == 1;

        let (payload_hash, remaining_bytes) = YamfHash::decode(&bytes[1..])?;
        let (payload_size, remaining_bytes) =
            varu64_decode(remaining_bytes).map_err(|(err, _)| err)?;
        let (author, remaining_bytes) = YamfSignatory::decode(remaining_bytes)?;
        let (seq_num, remaining_bytes) = varu64_decode(remaining_bytes).map_err(|(err, _)| err)?;

        let (backlink, lipmaa_link, remaining_bytes) = match seq_num {
            1 => (None, None, remaining_bytes),
            _ => {
                let (backlink, remaining_bytes) = YamfHash::decode(remaining_bytes)?;
                let (lipmaa_link, remaining_bytes) = YamfHash::decode(remaining_bytes)?;
                (Some(backlink), Some(lipmaa_link), remaining_bytes)
            }
        };

        let (sig, _) = Signature::decode(remaining_bytes)?;

        Ok(Entry {
            is_end_of_feed,
            payload_hash,
            payload_size,
            author,
            seq_num,
            backlink,
            lipmaa_link,
            sig,
        })
    }

    pub fn verify_signature() {
        //how would be verify this type ergonimcally tho?
        //verifying means we have to get the contents of the buffer up to but not including the
        //sig.
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::{Entry, Signature, YamfHash, YamfSignatory};
    use varu64::{
        decode as varu64_decode, encode as varu64_encode, encode_write as varu64_encode_write,
    };

    #[test]
    fn encode_decode_entry() {
        let backlink_bytes = [0xAA; 64];
        let backlink = YamfHash::Blake2b(&backlink_bytes);
        let payload_hash_bytes = [0xAB; 64];
        let payload_hash = YamfHash::Blake2b(&payload_hash_bytes);
        let lipmaa_link_bytes = [0xAC; 64];
        let lipmaa_link = YamfHash::Blake2b(&lipmaa_link_bytes);
        let payload_size = 512;
        let seq_num = 2;
        let sig_bytes = [0xDD; 128];
        let sig = Signature(&sig_bytes);
        let author_bytes = [0xEE; 32];
        let author = YamfSignatory::Ed25519(&author_bytes);

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
            YamfHash::Blake2b(hash) => {
                assert_eq!(hash, &payload_hash_bytes[..]);
            }
            _ => panic!(),
        }

        match entry.backlink {
            Some(YamfHash::Blake2b(hash)) => {
                assert_eq!(hash, &backlink_bytes[..]);
            }
            _ => panic!(),
        }
        match entry.lipmaa_link {
            Some(YamfHash::Blake2b(hash)) => {
                assert_eq!(hash, &lipmaa_link_bytes[..]);
            }
            _ => panic!(),
        }

        match entry.sig {
            Signature(sig) => {
                assert_eq!(sig, &sig_bytes[..]);
            }
            _ => panic!(),
        }

        match entry.author {
            YamfSignatory::Ed25519(auth) => {
                assert_eq!(auth, &author_bytes[..]);
            }
            _ => panic!(),
        }

        let mut encoded = Vec::new();

        entry.encode_write(&mut encoded).unwrap();

        assert_eq!(encoded, entry_vec);
    }
}
