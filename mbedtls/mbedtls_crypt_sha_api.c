#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"
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


