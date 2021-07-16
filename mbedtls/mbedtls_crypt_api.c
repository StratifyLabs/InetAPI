#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "mbedtls/aes.h"
#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ssl_ticket.h"
#include "mbedtls_api.h"

static int sha256_init(void **context);
static void sha256_deinit(void **context);
static int sha256_start(void *context);
static int sha256_update(void *context, const unsigned char *input, u32 size);
static int sha256_finish(void *context, unsigned char *output, u32 size);

const crypt_hash_api_t mbedtls_crypt_sha256_api = {
  .sos_api
  = {.name = "mbedtls_crypt_sha256", .version = 0x0001, .git_hash = SOS_GIT_HASH},
  .init = sha256_init,
  .deinit = sha256_deinit,
  .start = sha256_start,
  .update = sha256_update,
  .finish = sha256_finish};

typedef struct {
  mbedtls_sha256_context sha256;
} mbedtls_crypt_sha256_context_t;

static int sha512_init(void **context);
static void sha512_deinit(void **context);
static int sha512_start(void *context);
static int sha512_update(void *context, const unsigned char *input, u32 size);
static int sha512_finish(void *context, unsigned char *output, u32 size);

const crypt_hash_api_t mbedtls_crypt_sha512_api = {
  .sos_api
  = {.name = "mbedtls_crypt_sha512", .version = 0x0001, .git_hash = SOS_GIT_HASH},
  .init = sha512_init,
  .deinit = sha512_deinit,
  .start = sha512_start,
  .update = sha512_update,
  .finish = sha512_finish};

typedef struct {
  mbedtls_sha512_context sha512;
} mbedtls_crypt_sha512_context_t;

int sha256_init(void **context) {
  mbedtls_crypt_sha256_context_t *c
    = malloc(sizeof(mbedtls_crypt_sha256_context_t));
  if (c == 0) {
    return -1;
  }
  mbedtls_sha256_init(&c->sha256);
  *context = c;
  return 0;
}

void sha256_deinit(void **context) {
  mbedtls_crypt_sha256_context_t *c = *context;
  if (c) {
    mbedtls_sha256_free(&c->sha256);
    free(c);
    *context = 0;
  }
}

int sha256_start(void *context) {
  mbedtls_crypt_sha256_context_t *c = context;
  if (c == 0) {
    errno = EINVAL;
    return -1;
  }
  return mbedtls_sha256_starts_ret(&c->sha256, 0);
}

int sha256_update(void *context, const unsigned char *input, u32 size) {
  mbedtls_crypt_sha256_context_t *c = context;
  if (c == 0) {
    errno = EINVAL;
    return -1;
  }
  return mbedtls_sha256_update_ret(&c->sha256, input, size);
}

int sha256_finish(void *context, unsigned char *output, u32 size) {
  if (size != 32) { // sha256 output is always 32 bytes (256 bits)
    errno = EINVAL;
    return -1;
  }

  mbedtls_crypt_sha256_context_t *c = context;
  if (c == 0) {
    errno = EINVAL;
    return -1;
  }
  return mbedtls_sha256_finish_ret(&c->sha256, output);
}

int sha512_init(void **context) {
  mbedtls_crypt_sha512_context_t *c
    = malloc(sizeof(mbedtls_crypt_sha512_context_t));
  if (c == 0) {
    return -1;
  }
  mbedtls_sha512_init(&c->sha512);
  *context = c;
  return 0;
}

void sha512_deinit(void **context) {
  mbedtls_crypt_sha512_context_t *c = *context;
  if (c) {
    mbedtls_sha512_free(&c->sha512);
    free(c);
    *context = 0;
  }
}

int sha512_start(void *context) {
  mbedtls_crypt_sha512_context_t *c = context;
  if (c == 0) {
    errno = EINVAL;
    return -1;
  }
  return mbedtls_sha512_starts_ret(&c->sha512, 0);
}

int sha512_update(void *context, const unsigned char *input, u32 size) {
  mbedtls_crypt_sha512_context_t *c = context;
  if (c == 0) {
    errno = EINVAL;
    return -1;
  }
  return mbedtls_sha512_update_ret(&c->sha512, input, size);
}

int sha512_finish(void *context, unsigned char *output, u32 size) {
  if (size != 64) { // sha512 output is always 64 bytes (512 bits)
    errno = EINVAL;
    return -1;
  }

  mbedtls_crypt_sha512_context_t *c = context;
  if (c == 0) {
    errno = EINVAL;
    return -1;
  }
  return mbedtls_sha512_finish_ret(&c->sha512, output);
}

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
  = {.name = "mbedtls_crypt_aes", .version = 0x0001, .git_hash = SOS_GIT_HASH},
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

static int mbedtls_random_init(void **context);
static void mbedtls_random_deinit(void **context);
static int
mbedtls_random_seed(void *context, const unsigned char *data, u32 data_len);
static int
mbedtls_random_random(void *context, unsigned char *output, u32 output_length);

const crypt_random_api_t mbedtls_crypt_random_api = {
  .init = mbedtls_random_init,
  .deinit = mbedtls_random_deinit,
  .seed = mbedtls_random_seed,
  .random = mbedtls_random_random};

typedef struct {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
} mbedtls_crypt_random_context_t;

int mbedtls_random_init(void **context) {
  mbedtls_crypt_random_context_t *c
    = malloc(sizeof(mbedtls_crypt_random_context_t));
  if (c == 0) {
    return -1;
  }
  mbedtls_entropy_init(&c->entropy);
  mbedtls_ctr_drbg_init(&c->ctr_drbg);
  *context = c;
  return 0;
}

void mbedtls_random_deinit(void **context) {
  mbedtls_crypt_random_context_t *c = *context;
  if (c) {
    mbedtls_entropy_free(&c->entropy);
    mbedtls_ctr_drbg_free(&c->ctr_drbg);
    mbedtls_platform_zeroize(c, sizeof(mbedtls_crypt_random_context_t));
    free(c);
    *context = 0;
  }
}

int mbedtls_random_seed(
  void *context,
  const unsigned char *data,
  u32 data_len) {
  mbedtls_crypt_random_context_t *c = context;

  int result = mbedtls_ctr_drbg_seed(
    &c->ctr_drbg,
    mbedtls_entropy_func,
    &c->entropy,
    data,
    data_len);

  return result;
}

int mbedtls_random_random(
  void *context,
  unsigned char *output,
  u32 output_length) {
  mbedtls_crypt_random_context_t *c = context;
  int result = mbedtls_ctr_drbg_random(&c->ctr_drbg, output, output_length);

  if (result == 0) {
    return output_length;
  }

  return -1;
}


