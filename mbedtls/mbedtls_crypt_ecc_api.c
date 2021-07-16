#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls_api.h"

static int ecc_init(void **context);
static void ecc_deinit(void **context);

static int ecc_dh_create_key_pair(
  void *context,
  crypt_ecc_key_pair_t type,
  u8 *public_key,
  u32 *public_key_capacity);

static int ecc_dh_calculate_shared_secret(
  void *context,
  const u8 *public_key,
  u32 public_key_length,
  u8 *secret,
  u32 secret_length);

static int ecc_dsa_create_key_pair(
  void *context,
  crypt_ecc_key_pair_t type,
  u8 *public_key,
  u32 *public_key_capacity,
  u8 *private_key,
  u32 *private_key_capacity);

static int ecc_dsa_set_key_pair(void *context,
  const u8 *public_key,
  u32 public_key_capacity,
  const u8 *private_key,
  u32 private_key_capacity);

static int ecc_dsa_sign(
  void *context,
  const u8 *message_hash,
  u32 hash_size,
  u8 * signature, u32 * signature_length);

static int ecc_dsa_verify(
  void *context,
  const u8 *message_hash,
  u32 hash_size,
  const u8 *signature, u32 signature_length);

const crypt_ecc_api_t mbedtls_crypt_ecc_api = {
  .sos_api
  = {.name = "mbedtls_crypt_ecc", .version = 0x0001, .git_hash = SOS_GIT_HASH},
  .init = ecc_init,
  .deinit = ecc_deinit,
  .dh_create_key_pair = ecc_dh_create_key_pair,
  .dh_calculate_shared_secret = ecc_dh_calculate_shared_secret,
  .dsa_create_key_pair = ecc_dsa_create_key_pair,
  .dsa_set_key_pair = ecc_dsa_set_key_pair,
  .dsa_sign = ecc_dsa_sign,
  .dsa_verify = ecc_dsa_verify};

typedef struct {
  mbedtls_ecdh_context ecdh;
  mbedtls_pk_context pk;

  // random context
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

} mbedtls_crypt_ecc_context_t;

int ecc_init(void **context) {
  mbedtls_crypt_ecc_context_t *c = malloc(sizeof(mbedtls_crypt_ecc_context_t));
  if (c == NULL) {
    return -1;
  }

  mbedtls_entropy_init(&c->entropy);
  mbedtls_ctr_drbg_init(&c->ctr_drbg);
  mbedtls_ctr_drbg_seed(&c->ctr_drbg, mbedtls_entropy_func, &c->entropy, NULL, 0);

  mbedtls_ecdh_init(&(c->ecdh));
  mbedtls_pk_init(&c->pk);


  *context = c;
  return 0;
}

void ecc_deinit(void **context) {
  mbedtls_crypt_ecc_context_t *c = *context;

  if (c) {
    mbedtls_ecdh_free(&(c->ecdh));
    mbedtls_pk_free(&c->pk);
    mbedtls_entropy_free(&c->entropy);
    mbedtls_ctr_drbg_free(&c->ctr_drbg);
    mbedtls_platform_zeroize(c, sizeof(mbedtls_crypt_ecc_context_t));

    free(c);
    *context = 0;
  }
}

int ecc_dh_create_key_pair(
  void *context,
  crypt_ecc_key_pair_t type,
  u8 *public_key,
  u32 *public_key_capacity) {
  mbedtls_crypt_ecc_context_t *c = context;

  mbedtls_ecdh_setup(&(c->ecdh), MBEDTLS_ECP_DP_SECP256R1);

  size_t olen = 0;
  int result = mbedtls_ecdh_make_public(
    &c->ecdh,
    &olen,
    public_key,
    *public_key_capacity,
    c->ctr_drbg.f_entropy,
    c->ctr_drbg.p_entropy);

  if (result < 0) {
    errno = EINVAL;
    return -1;
  }

  *public_key_capacity = olen;

  return 0;
}

int ecc_dh_calculate_shared_secret(
  void *context,
  const u8 *public_key,
  u32 public_key_length,
  u8 *secret,
  u32 secret_length) {
  mbedtls_crypt_ecc_context_t *c = context;

  mbedtls_ecdh_read_public(&c->ecdh, public_key, public_key_length);

  size_t olen = 0;
  int result = mbedtls_ecdh_calc_secret(
    &c->ecdh,
    &olen,
    secret,
    secret_length,
    c->ctr_drbg.f_entropy,
    c->ctr_drbg.p_entropy);

  if (result < 0) {
    errno = EINVAL;
    return -1;
  }

  return 0;
}

static int ecc_dsa_create_key_pair(
  void *context,
  crypt_ecc_key_pair_t type,
  u8 *public_key,
  u32 *public_key_capacity,
  u8 *private_key,
  u32 *private_key_capacity) {
  mbedtls_crypt_ecc_context_t *c = context;

  mbedtls_pk_setup(&c->pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

  int key_result = mbedtls_ecdsa_genkey(
    c->pk.pk_ctx,
    MBEDTLS_ECP_DP_SECP256R1,
    c->ctr_drbg.f_entropy,
    c->ctr_drbg.p_entropy);
  if (key_result < 0) {
    errno = EINVAL;
    return -1;
  }

  int private_key_result
    = mbedtls_pk_write_key_der(&c->pk, private_key, *private_key_capacity);

  if (private_key_result > 0) {
    memcpy(
      private_key,
      private_key + *private_key_capacity - private_key_result,
      private_key_result);
    *private_key_capacity = private_key_result;
  } else {
    *private_key_capacity = 0;
    *public_key_capacity = 0;
    errno = EINVAL;
    return -2;
  }

  int public_key_result
    = mbedtls_pk_write_pubkey_der(&c->pk, public_key, *public_key_capacity);

  if (public_key_result > 0) {
    memcpy(
      public_key,
      public_key + *public_key_capacity - public_key_result,
      public_key_result);
    *public_key_capacity = public_key_result;
  } else {
    errno = EINVAL;
    *public_key_capacity = 0;
    return -3;
  }

  // keys are written to the end, move them to the beginning

  return 0;
}

static int ecc_dsa_set_key_pair(
  void *context,
  const u8 *public_key,
  u32 public_key_size,
  const u8 *private_key,
  u32 private_key_size) {
  mbedtls_crypt_ecc_context_t *c = context;

  {
    int result
      = mbedtls_pk_parse_public_key(&c->pk, public_key, public_key_size);
    if (result < 0) {
      errno = EINVAL;
      return -1;
    }
  }

  if (private_key && private_key_size) {
    int result
      = mbedtls_pk_parse_key(&c->pk, private_key, private_key_size, 0, 0);
    if (result < 0) {
      errno = EINVAL;
      return -2;
    }
  }



  return 0;
}

int ecc_dsa_sign(
  void *context,
  const u8 *message_hash,
  u32 hash_size,
  u8 *signature, u32 * signature_length) {
  mbedtls_crypt_ecc_context_t *c = context;

  size_t length = 0;
  int result = mbedtls_pk_sign(
    &c->pk,
    MBEDTLS_MD_SHA256,
    message_hash,
    hash_size,
    signature,
    &length,
    c->ctr_drbg.f_entropy,
    c->ctr_drbg.p_entropy);
  if( result < 0 ){
    errno = EINVAL;
    return -1;
  }

  *signature_length = length;
  return 0;
}

int ecc_dsa_verify(
  void *context,
  const u8 *message_hash,
  u32 hash_size,
  const u8 *signature, u32 signature_length) {
  mbedtls_crypt_ecc_context_t *c = context;

  const int result = mbedtls_pk_verify(
    &c->pk,
    MBEDTLS_MD_SHA256,
    message_hash,
    hash_size,
    signature,
    signature_length);

  if( result == 0 ){
    return 1;
  }

  return 0;
}
