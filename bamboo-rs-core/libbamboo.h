#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_ENTRY_SIZE_ ((((TAG_BYTE_LENGTH + MAX_SIGNATURE_SIZE) + PUBLIC_KEY_LENGTH) + (MAX_YAMF_HASH_SIZE * 3)) + (MAX_VARU64_SIZE * 3))

/**
 * This is useful if you need to know at compile time how big an entry can get.
 */
#define MAX_ENTRY_SIZE 322

#define ED25519_SIGNATURE_SIZE 64

/**
 * The maximum number of bytes this will use.
 */
#define MAX_SIGNATURE_SIZE ED25519_SIGNATURE_SIZE

typedef enum Error_Tag {
  NoError,
  EncodeIsEndOfFeedError,
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
  DecodePayloadHashError,
  DecodePayloadSizeError,
  DecodeLogIdError,
  DecodeAuthorError,
  DecodeSeqError,
  DecodeSeqIsZero,
  DecodeBacklinkError,
  DecodeLipmaaError,
  DecodeSsbSigError,
  DecodeInputIsLengthZero,
  GetEntryFailed,
  EntryNotFound,
  AppendFailed,
  PublishNewEntryFailed,
  AddEntryDecodeFailed,
  AddEntryPayloadLengthDidNotMatch,
  AddEntryLipmaaHashDidNotMatch,
  AddEntryPayloadHashDidNotMatch,
  AddEntryBacklinkHashDidNotMatch,
  AddEntryNoLipmaalinkInStore,
  AddEntryDecodeLipmaalinkFromStore,
  AddEntryAuthorDidNotMatchLipmaaEntry,
  AddEntryLogIdDidNotMatchLipmaaEntry,
  AddEntryAuthorDidNotMatchPreviousEntry,
  AddEntryLogIdDidNotMatchPreviousEntry,
  AddEntryDecodeLastEntry,
  AddEntryToFeedThatHasEnded,
  AddEntryWithInvalidSignature,
  AddEntrySigNotValidError,
  DecodeError,
  EncodeWriteError,
  EncodeError,
  SignatureInvalid,
} Error_Tag;

typedef struct EncodePayloadHashError_Body {
  YamfHashError source;
} EncodePayloadHashError_Body;

typedef struct EncodeBacklinkError_Body {
  YamfHashError source;
} EncodeBacklinkError_Body;

typedef struct EncodeLipmaaError_Body {
  YamfHashError source;
} EncodeLipmaaError_Body;

typedef struct DecodePayloadHashError_Body {
  YamfHashError source;
} DecodePayloadHashError_Body;

typedef struct DecodeBacklinkError_Body {
  YamfHashError source;
} DecodeBacklinkError_Body;

typedef struct DecodeLipmaaError_Body {
  YamfHashError source;
} DecodeLipmaaError_Body;

typedef struct Error {
  Error_Tag tag;
  union {
    EncodePayloadHashError_Body encode_payload_hash_error;
    EncodeBacklinkError_Body encode_backlink_error;
    EncodeLipmaaError_Body encode_lipmaa_error;
    DecodePayloadHashError_Body decode_payload_hash_error;
    DecodeBacklinkError_Body decode_backlink_error;
    DecodeLipmaaError_Body decode_lipmaa_error;
  };
} Error;

typedef struct CEntry {
  uint64_t log_id;
  bool is_end_of_feed;
  uint8_t payload_hash_bytes[BLAKE2B_HASH_SIZE];
  uint64_t payload_length;
  uint8_t author[PUBLIC_KEY_LENGTH];
  uint64_t seq_num;
  uint8_t backlink[BLAKE2B_HASH_SIZE];
  bool has_backlink;
  uint8_t lipmaa_link[BLAKE2B_HASH_SIZE];
  bool has_lipmaa_link;
  uint8_t sig[ED25519_SIGNATURE_SIZE];
} CEntry;

typedef struct DecodeEd25519Blade2bEntryArgs {
  struct CEntry out_decoded_entry;
  const uint8_t *entry_bytes;
  uintptr_t entry_length;
} DecodeEd25519Blade2bEntryArgs;

typedef struct VerifyEd25519Blake2bEntryArgs {
  const uint8_t *entry_bytes;
  uintptr_t entry_length;
  const uint8_t *payload_bytes;
  uintptr_t payload_length;
  const uint8_t *backlink_bytes;
  uintptr_t backlink_length;
  const uint8_t *lipmaalink_bytes;
  uintptr_t lipmaalink_length;
} VerifyEd25519Blake2bEntryArgs;

typedef struct PublishEd25519Blake2bEntryArgs {
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

void panic(const PanicInfo *panic_info);

/**
 * Attempts to decode bytes as an entry.
 *
 * Returns `Error` which will have a value of `0` if decoding was
 * successful.
 */
struct Error decode_ed25519_blake2b_entry(struct DecodeEd25519Blade2bEntryArgs *args);

struct Error verify_ed25519_blake2b_entry(struct VerifyEd25519Blake2bEntryArgs *args);

struct Error publish_ed25519_blake2b_entry(struct PublishEd25519Blake2bEntryArgs *args);
