#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define BLAKE2B_HASH_SIZE 64

#define BLAKE2B_NUMERIC_ID 0

#define ED25519_NUMERIC_ID 0

#define ED25519_SIGNATURE_SIZE 64

#define ED25519_SIZE 32

/**
 * This is useful if you need to know at compile time how big an entry can get.
 */
#define MAX_ENTRY_SIZE 325

#define MAX_ENTRY_SIZE_ ((((TAG_BYTE_LENGTH + MAX_SIGNATURE_SIZE) + MAX_YAMF_SIGNATORY_SIZE) + (MAX_YAMF_HASH_SIZE * 3)) + (MAX_VARU64_SIZE * 3))

/**
 * The maximum number of bytes this will use.
 *
 * This is a bit yuck because it knows the number of bytes varu64 uses to encode the
 * signature.
 */
#define MAX_SIGNATURE_SIZE (ED25519_SIGNATURE_SIZE + 1)

/**
 * The maximum number of bytes this will use for any variant.
 *
 * This is a bit yuck because it knows the number of bytes varu64 uses to encode the
 * BLAKE2B_HASH_SIZE and the BLAKE2B_NUMERIC_ID (2).
 * This is unlikely to cause a problem until there are hundreds of variants.
 */
#define MAX_YAMF_HASH_SIZE (BLAKE2B_HASH_SIZE + 2)

/**
 * The maximum number of bytes this will use for any variant.
 *
 * This is a bit yuck because it knows the number of bytes varu64 uses to encode the
 * ED25519_NUMERIC_ID and the ED25519_SIZE (2).
 * This is unlikely to cause a problem until there are hundreds of variants.
 */
#define MAX_YAMF_SIGNATORY_SIZE (ED25519_SIZE + 2)

typedef enum {
  NoError = 0,
  EncodeIsEndOfFeedError = 1,
  EncodePayloadHashError,
  EncodePayloadSizeError,
  EncodeAuthorError,
  EncodeSeqError,
  EncodeLogIdError,
  EncodeBacklinkError,
  EncodeLipmaaError,
  EncodeSigError,
  EncodeEntryHasBacklinksWhenSeqZero,
  EncodeBufferLength,
  PublishAfterEndOfFeed,
  PublishWithIncorrectLogId,
  PublishWithoutSecretKey,
  PublishWithoutKeypair,
  PublishWithoutLipmaaEntry,
  PublishWithoutBacklinkEntry,
  DecodeIsEndOfFeedError,
  DecodePayloadHashError,
  DecodePayloadSizeError,
  DecodeLogIdError,
  DecodeAuthorError,
  DecodeSeqError,
  DecodeSeqIsZero,
  DecodeBacklinkError,
  DecodeLipmaaError,
  DecodeSigError,
  DecodeSsbSigError,
  DecodeSsbPubKeyError,
  VerifySsbSigError,
  DecodeInputIsLengthZero,
  GetEntrySequenceInvalid,
  GetEntryFailed,
  EntryNotFound,
  EncodingForSigningFailed,
  EncodingForStoringFailed,
  AppendFailed,
  PreviousDecodeFailed,
  PublishNewEntryFailed,
  AddEntryDecodeFailed,
  AddEntryPayloadLengthDidNotMatch,
  AddEntryLipmaaHashDidNotMatch,
  AddEntryPayloadHashDidNotMatch,
  AddEntryBacklinkHashDidNotMatch,
  AddEntryGetBacklinkError,
  AddEntryGetLipmaalinkError,
  AddEntryNoLipmaalinkInStore,
  AddEntryDecodeLipmaalinkFromStore,
  AddEntryAuthorDidNotMatchLipmaaEntry,
  AddEntryLogIdDidNotMatchLipmaaEntry,
  AddEntryAuthorDidNotMatchPreviousEntry,
  AddEntryLogIdDidNotMatchPreviousEntry,
  AddEntryGetLastEntryError,
  AddEntryGetLastEntryNotFound,
  AddEntryDecodeLastEntry,
  AddEntryToFeedThatHasEnded,
  AddEntryWithInvalidSignature,
  AddEntryDecodeEntryBytesForSigning,
  AddEntrySigNotValidError,
  DecodeVaru64Error,
  DecodeError,
  EncodeWriteError,
  EncodeError,
  SignatureInvalid,
} Error;

typedef struct {
  uint64_t log_id;
  bool is_end_of_feed;
  uint8_t payload_hash_bytes[BLAKE2B_HASH_SIZE];
  uint64_t payload_length;
  uint8_t author[ED25519_SIZE];
  uint64_t seq_num;
  uint8_t backlink[BLAKE2B_HASH_SIZE];
  bool has_backlink;
  uint8_t lipmaa_link[BLAKE2B_HASH_SIZE];
  bool has_lipmaa_link;
  uint8_t sig[ED25519_SIGNATURE_SIZE];
} CEntry;

typedef struct {
  CEntry out_decoded_entry;
  const uint8_t *entry_bytes;
  uintptr_t entry_length;
} DecodeEd25519Blade2bEntryArgs;

typedef struct {
  uint8_t *out;
  uintptr_t out_length;
  const uint8_t *payload_bytes;
  uintptr_t payload_length;
  const uint8_t *public_key_bytes;
  uintptr_t public_key_length;
  const uint8_t *secret_key_bytes;
  uintptr_t secret_key_length;
  const uint8_t *backlink_bytes;
  uintptr_t backlink_length;
  const uint8_t *lipmaalink_bytes;
  uintptr_t lipmaalink_length;
  bool is_end_of_feed;
  uint64_t last_seq_num;
  uint64_t log_id;
} PublishEd25519Blake2bEntryArgs;

typedef struct {
  const uint8_t *entry_bytes;
  uintptr_t entry_length;
  const uint8_t *payload_bytes;
  uintptr_t payload_length;
  const uint8_t *backlink_bytes;
  uintptr_t backlink_length;
  const uint8_t *lipmaalink_bytes;
  uintptr_t lipmaalink_length;
} VerifyEd25519Blake2bEntryArgs;

/**
 * Attempts to decode bytes as an entry.
 *
 * Returns `Error` which will have a value of `0` if decoding was
 * successful.
 */
Error decode_ed25519_blake2b_entry(DecodeEd25519Blade2bEntryArgs *args);

Error publish_ed25519_blake2b_entry(PublishEd25519Blake2bEntryArgs *args);

Error verify_ed25519_blake2b_entry(VerifyEd25519Blake2bEntryArgs *args);
