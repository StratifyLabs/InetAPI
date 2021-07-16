#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "mbedtls/aes.h"
#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ssl_ticket.h"
#include "mbedtls_api.h"


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


