#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define BLAKE2B_NUMERIC_ID 0

#define ED25519_NUMERIC_ID 0

#define MAX_ENTRY_SIZE 316

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

intptr_t publish_ed25519_blake2b_entry(PublishEd25519Blake2bEntryArgs *args);

intptr_t verify_ed25519_blake2b_entry(VerifyEd25519Blake2bEntryArgs *args);
