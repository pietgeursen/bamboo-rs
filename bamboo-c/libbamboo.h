#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define TAG_BYTE_LENGTH 1

#define MAX_VARU64_SIZE 9

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

/**
 * The length of a ed25519 `Signature`, in bytes.
 */
#define SIGNATURE_LENGTH 64

/**
 * The length of a ed25519 `SecretKey`, in bytes.
 */
#define SECRET_KEY_LENGTH 32

/**
 * The length of an ed25519 `PublicKey`, in bytes.
 */
#define PUBLIC_KEY_LENGTH 32

/**
 * The length of an ed25519 `Keypair`, in bytes.
 */
#define KEYPAIR_LENGTH (SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH)

/**
 * The length of an "expanded" ed25519 key, `ExpandedSecretKey`, in bytes.
 */
#define EXPANDED_SECRET_KEY_LENGTH (EXPANDED_SECRET_KEY_KEY_LENGTH + EXPANDED_SECRET_KEY_NONCE_LENGTH)

#define BLAKE2B_HASH_SIZE 64

#define BLAKE2B_NUMERIC_ID 0

/**
 * The maximum number of bytes this will use for any variant.
 *
 * This is a bit yuck because it knows the number of bytes varu64 uses to encode the
 * BLAKE2B_HASH_SIZE and the BLAKE2B_NUMERIC_ID (2).
 * This is unlikely to cause a problem until there are hundreds of variants.
 */
#define MAX_YAMF_HASH_SIZE (BLAKE2B_HASH_SIZE + 2)

typedef enum DecodeError {
  DecodeError_NoError,
  DecodeError_PayloadHashError,
  DecodeError_PayloadSizeError,
  DecodeError_LogIdError,
  DecodeError_AuthorError,
  DecodeError_SeqError,
  DecodeError_SeqIsZero,
  DecodeError_BacklinkError,
  DecodeError_LipmaaError,
  DecodeError_SigError,
  DecodeError_InputIsLengthZero,
} DecodeError;

typedef enum PublishError {
  PublishError_NoError,
  PublishError_PublishWithoutKeypair,
  PublishError_PublishAfterEndOfFeed,
  PublishError_PublishWithIncorrectLogId,
  PublishError_PublishWithoutSecretKey,
  PublishError_PublishWithoutLipmaaEntry,
  PublishError_PublishWithoutBacklinkEntry,
  PublishError_DecodeBacklinkEntry,
  PublishError_EncodeEntryToOutBuffer,
} PublishError;

typedef enum VerifyError {
  VerifyError_NoError,
  VerifyError_DecodeSigError,
  VerifyError_InvalidSignature,
  VerifyError_PayloadHashDidNotMatch,
  VerifyError_PayloadLengthDidNotMatch,
  VerifyError_LipmaaHashDoesNotMatch,
  VerifyError_DecodeLipmaaEntry,
  VerifyError_LipmaaLogIdDoesNotMatch,
  VerifyError_LipmaaAuthorDoesNotMatch,
  VerifyError_LipmaaLinkRequired,
  VerifyError_DecodeBacklinkEntry,
  VerifyError_BacklinkLogIdDoesNotMatch,
  VerifyError_BacklinkAuthorDoesNotMatch,
  VerifyError_PublishedAfterEndOfFeed,
  VerifyError_BacklinkHashDoesNotMatch,
  VerifyError_BackLinkRequired,
  VerifyError_DecodeEntry,
  VerifyError_EncodeEntryForSigning,
} VerifyError;

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

/**
 * Attempts to decode bytes as an entry.
 *
 * Returns `Error` which will have a value of `0` if decoding was
 * successful.
 */
enum DecodeError decode_ed25519_blake2b_entry(struct DecodeEd25519Blade2bEntryArgs *args);

enum PublishError publish_ed25519_blake2b_entry(struct PublishEd25519Blake2bEntryArgs *args);

enum VerifyError verify_ed25519_blake2b_entry(struct VerifyEd25519Blake2bEntryArgs *args);
