#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ssl_ticket.h"
#include "mbedtls_api.h"


static int aes_init(void **context);
static void aes_deinit(void **context);
static int aes_set_key(
  void *context,
  const unsigned char *key,
  u32 keybits,
  u32 bits_per_word);

static int aes_encrypt_ecb(
  void *context,
  const unsigned char input[16],
  unsigned char output[16]);

static int aes_decrypt_ecb(
  void *context,
  const unsigned char input[16],
  unsigned char output[16]);

static int aes_encrypt_cbc(
  void *context,
  u32 length,
  unsigned char iv[16],
  const unsigned char *input,
  unsigned char *output);

static int aes_decrypt_cbc(
  void *context,
  u32 length,
  unsigned char iv[16],
  const unsigned char *input,
  unsigned char *output);

static int aes_encrypt_ctr(
  void *context,
  u32 length,
  u32 *nc_off,
  unsigned char nonce_counter[16],
  unsigned char stream_block[16],
  const unsigned char *input,
  unsigned char *output);

static int aes_decrypt_ctr(
  void *context,
  u32 length,
  u32 *nc_off,
  unsigned char nonce_counter[16],
  unsigned char stream_block[16],
  const unsigned char *input,
  unsigned char *output);

const crypt_aes_api_t mbedtls_crypt_aes_api = {
  .sos_api
  = {.name = "mbedtls_crypt_aes", .version = 0x0001, .git_hash = CMSDK_GIT_HASH},
  .init = aes_init,
  .deinit = aes_deinit,
  .set_key = aes_set_key,
  .encrypt_ecb = aes_encrypt_ecb,
  .decrypt_ecb = aes_decrypt_ecb,
  .encrypt_cbc = aes_encrypt_cbc,
  .decrypt_cbc = aes_decrypt_cbc,
  .encrypt_ctr = aes_encrypt_ctr,
  .decrypt_ctr = aes_decrypt_ctr};

typedef struct {
  mbedtls_aes_context aes;
  unsigned char key[32];
  u32 key_bits;
} mbedtls_crypt_aes_context_t;

int aes_init(void **context) {
  mbedtls_crypt_aes_context_t *c = malloc(sizeof(mbedtls_crypt_aes_context_t));
  if (c == 0) {
    return -1;
  }
  mbedtls_aes_init(&c->aes);
  *context = c;
  return 0;
}

void aes_deinit(void **context) {
  mbedtls_crypt_aes_context_t *c = *context;
  if (c) {
    mbedtls_aes_free(&c->aes);
    mbedtls_platform_zeroize(c, sizeof(mbedtls_crypt_aes_context_t));
    free(c);
    *context = 0;
  }
}

int aes_set_key(
  void *context,
  const unsigned char *key,
  u32 keybits,
  u32 bits_per_word) {
  MCU_UNUSED_ARGUMENT(bits_per_word);
  mbedtls_crypt_aes_context_t *c = context;
  memcpy(c->key, key, keybits / 8);
  c->key_bits = keybits;
  return 0;
}

int aes_encrypt_ecb(
  void *context,
  const unsigned char input[16],
  unsigned char output[16]) {
  mbedtls_crypt_aes_context_t *c = context;

  if (mbedtls_aes_setkey_enc(&c->aes, c->key, c->key_bits) < 0) {
    return -1 * __LINE__;
  }

  return mbedtls_aes_crypt_ecb(&c->aes, MBEDTLS_AES_ENCRYPT, input, output);
}

int aes_decrypt_ecb(
  void *context,
  const unsigned char input[16],
  unsigned char output[16]) {
  mbedtls_crypt_aes_context_t *c = context;

  if (mbedtls_aes_setkey_dec(&c->aes, c->key, c->key_bits) < 0) {
    return -1 * __LINE__;
  }

  return mbedtls_aes_crypt_ecb(&c->aes, MBEDTLS_AES_DECRYPT, input, output);
}

int aes_encrypt_cbc(
  void *context,
  u32 length,
  unsigned char iv[16],
  const unsigned char *input,
  unsigned char *output) {
  mbedtls_crypt_aes_context_t *c = context;

  if (mbedtls_aes_setkey_enc(&c->aes, c->key, c->key_bits) < 0) {
    return -1 * __LINE__;
  }

  return mbedtls_aes_crypt_cbc(
    &c->aes,
    MBEDTLS_AES_ENCRYPT,
    length,
    iv,
    input,
    output);
}

int aes_decrypt_cbc(
  void *context,
  u32 length,
  unsigned char iv[16],
  const unsigned char *input,
  unsigned char *output) {
  mbedtls_crypt_aes_context_t *c = context;

  if (mbedtls_aes_setkey_dec(&c->aes, c->key, c->key_bits) < 0) {
    return -1 * __LINE__;
  }

  return mbedtls_aes_crypt_cbc(
    &c->aes,
    MBEDTLS_AES_DECRYPT,
    length,
    iv,
    input,
    output);
}

int aes_encrypt_ctr(
  void *context,
  u32 length,
  u32 *nc_off,
  unsigned char nonce_counter[16],
  unsigned char stream_block[16],
  const unsigned char *input,
  unsigned char *output) {
  mbedtls_crypt_aes_context_t *c = context;

  if (mbedtls_aes_setkey_enc(&c->aes, c->key, c->key_bits) < 0) {
    return -1 * __LINE__;
  }

  return -1;
}

int aes_decrypt_ctr(
  void *context,
  u32 length,
  u32 *nc_off,
  unsigned char nonce_counter[16],
  unsigned char stream_block[16],
  const unsigned char *input,
  unsigned char *output) {
  mbedtls_crypt_aes_context_t *c = context;

  if (mbedtls_aes_setkey_dec(&c->aes, c->key, c->key_bits) < 0) {
    return -1 * __LINE__;
  }

  return -1;
}



