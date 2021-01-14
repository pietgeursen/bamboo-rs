use core::borrow::Borrow;
use snafu::{ensure, ResultExt};

#[cfg(feature = "std")]
use std::io::Write;
use varu64::{encode as varu64_encode, encoding_length as varu64_encoding_length};

#[cfg(feature = "std")]
use varu64::encode_write as varu64_encode_write;

use super::{Entry, TAG_BYTE_LENGTH};
pub mod error;
pub use error::*;

impl<'a, H, S> Entry<H, S>
where
    H: Borrow<[u8]>,
    S: Borrow<[u8]>,
{
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut next_byte_num = self.encode_for_signing(out)?;
        // Encode the signature
        if let Some(ref sig) = self.sig {
            next_byte_num += sig
                .encode(&mut out[next_byte_num..])
                .context(EncodeSigError)?;
        }

        Ok(next_byte_num as usize)
    }

    pub fn encode_for_signing(&self, out: &mut [u8]) -> Result<usize, Error> {
        ensure!(out.len() >= self.encoding_length(), EncodeBufferLength);
        ensure!(self.seq_num > 0, EncodeSeqIsZero);

        let mut next_byte_num = 0;

        // Encode the end of feed.
        if self.is_end_of_feed {
            out[0] = 1;
        } else {
            out[0] = 0;
        }
        next_byte_num += 1;

        // Encode the author
        let author_bytes = self.author.as_bytes();
        out[next_byte_num..author_bytes.len() + next_byte_num].copy_from_slice(&author_bytes[..]);
        next_byte_num += author_bytes.len();

        // Encode the log_id
        next_byte_num += varu64_encode(self.log_id, &mut out[next_byte_num..]);

        // Encode the sequence number
        next_byte_num += varu64_encode(self.seq_num, &mut out[next_byte_num..]);

        // Encode the backlink and lipmaa links if its not the first sequence
        next_byte_num = match (self.seq_num, &self.backlink, &self.lipmaa_link) {
            (n, Some(ref backlink), Some(ref lipmaa_link)) if n > 1 => {
                next_byte_num += lipmaa_link
                    .encode(&mut out[next_byte_num..])
                    .context(EncodeLipmaaError)?;
                next_byte_num += backlink
                    .encode(&mut out[next_byte_num..])
                    .context(EncodeBacklinkError)?;
                Ok(next_byte_num)
            }
            (n, Some(ref backlink), None) if n > 1 => {
                next_byte_num += backlink
                    .encode(&mut out[next_byte_num..])
                    .context(EncodeBacklinkError)?;
                Ok(next_byte_num)
            }
            (n, Some(_), Some(_)) if n <= 1 => Err(Error::EncodeEntryHasBacklinksWhenSeqZero),
            _ => Ok(next_byte_num),
        }?;

        // Encode the payload size
        next_byte_num += varu64_encode(self.payload_size, &mut out[next_byte_num..]);

        // Encode the payload hash
        next_byte_num += self
            .payload_hash
            .encode(&mut out[next_byte_num..])
            .context(EncodePayloadHashError)?;

        Ok(next_byte_num as usize)
    }

    /// Encode the entry ready for signing.
    #[cfg(feature = "std")]
    pub fn encode_for_signing_write<W: Write>(&self, mut w: W) -> Result<()> {
        ensure!(self.seq_num > 0, EncodeSeqIsZero);
        // Encode the "is end of feed" tag.
        let mut is_end_of_feed_byte = [0];
        if self.is_end_of_feed {
            is_end_of_feed_byte[0] = 1;
        }
        w.write_all(&is_end_of_feed_byte[..])
            .map_err(|_| Error::EncodeIsEndOfFeedError)?;

        // Encode the author
        let author_bytes = self.author.as_bytes();

        w.write_all(author_bytes)
            .map_err(|_| Error::EncodeAuthorError)?;

        // Encode the log_id
        varu64_encode_write(self.log_id, &mut w).map_err(|_| Error::EncodeLogIdError)?;

        // Encode the sequence number
        varu64_encode_write(self.seq_num, &mut w).map_err(|_| Error::EncodeSeqError)?;

        // Encode the backlink and lipmaa links if its not the first sequence
        match (self.seq_num, &self.backlink, &self.lipmaa_link) {
            (n, Some(ref backlink), Some(ref lipmaa_link)) if n > 1 => {
                lipmaa_link
                    .encode_write(&mut w)
                    .context(EncodeLipmaaError)?;

                backlink.encode_write(&mut w).context(EncodeBacklinkError)
            }
            (n, Some(ref backlink), None) if n > 1 => {
                backlink.encode_write(&mut w).context(EncodeBacklinkError)
            }
            (n, Some(_), Some(_)) if n <= 1 => Err(Error::EncodeEntryHasBacklinksWhenSeqZero),
            (n, None, Some(_)) if n <= 1 => Err(Error::EncodeEntryHasBacklinksWhenSeqZero),
            (n, Some(_), None) if n <= 1 => Err(Error::EncodeEntryHasBacklinksWhenSeqZero),
            _ => Ok(()),
        }?;

        // Encode the payload size
        varu64_encode_write(self.payload_size, &mut w)
            .map_err(|_| Error::EncodePayloadSizeError)?;

        // Encode the payload hash
        self.payload_hash
            .encode_write(&mut w)
            .context(EncodePayloadHashError)?;

        Ok(())
    }

    #[cfg(feature = "std")]
    pub fn encode_write<W: Write>(&self, mut w: W) -> Result<()> {
        self.encode_for_signing_write(&mut w)?;

        // Encode the signature
        if let Some(ref sig) = self.sig {
            sig.encode_write(&mut w).context(EncodeSigError)?;
        }

        Ok(())
    }

    pub fn encoding_length(&self) -> usize {
        TAG_BYTE_LENGTH
            + self.payload_hash.encoding_length()
            + varu64_encoding_length(self.payload_size)
            + varu64_encoding_length(self.log_id)
            + self.author.as_bytes().len()
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
}
