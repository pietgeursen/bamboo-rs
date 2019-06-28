use super::Entry;

/// Serialize a `Message` into an owned byte vector, using the
/// [legacy encoding](https://spec.scuttlebutt.nz/messages.html#legacy-json-encoding).
///
/// If `compact`, this omits all whitespace. Else, this produces the signing encoding.
pub fn to_vec(entry: &Entry) -> Result<Vec<u8>, ()> {
    let mut out = Vec::with_capacity(256);
    Ok(out)
}
