#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define BLAKE2B_NUMERIC_ID 0

#define ED25519_NUMERIC_ID 0

#define MAX_ENTRY_SIZE 325

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
} Error;

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
  bool is_valid;
  const uint8_t *entry_bytes;
  uintptr_t entry_length;
  const uint8_t *payload_bytes;
  uintptr_t payload_length;
  const uint8_t *backlink_bytes;
  uintptr_t backlink_length;
  const uint8_t *lipmaalink_bytes;
  uintptr_t lipmaalink_length;
} VerifyEd25519Blake2bEntryArgs;

Error publish_ed25519_blake2b_entry(PublishEd25519Blake2bEntryArgs *args);

Error verify_ed25519_blake2b_entry(VerifyEd25519Blake2bEntryArgs *args);
