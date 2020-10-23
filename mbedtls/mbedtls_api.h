#ifndef MBEDTLS_API_H
#define MBEDTLS_API_H

#include <sos/api/crypt_api.h>

#if defined __win32
#define _BSD_SOURCE
#include <winsock2.h>
#include <ws2tcpip.h>
typedef u32 in_addr_t;
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#define MBEDTLS_API_T 1 // increment when adding functions

typedef struct {
  sos_api_t sos_api;
  // enough for a client
  int (*socket)(void **context, int domain, int type, int protocol);
  int (*connect)(void *context, const struct sockaddr *address,
                 socklen_t address_len, const char *server_name);
  int (*close)(void **context);
  int (*write)(void *context, const void *buf, int nbyte);
  int (*read)(void *context, void *buf, int nbyte);
  int (*fileno)(void *context);
  int (*write_ticket)(void *context, void *buf, int nbyte, u32 lifetime);
  int (*parse_ticket)(void *context, void *buf, int nbyte);

  // server
  // bind_and_listen()
  // accept()

} mbedtls_api_t;

//#if defined __cplusplus
// extern "C" {
//#endif

extern const mbedtls_api_t mbedtls_api;
extern const crypt_hash_api_t mbedtls_crypt_sha256_api;
extern const crypt_hash_api_t mbedtls_crypt_sha512_api;
extern const crypt_aes_api_t mbedtls_crypt_aes_api;
extern const crypt_random_api_t mbedtls_crypt_random_api;

#if defined __link
#define MBEDTLS_API_REQUEST &mbedtls_api
#else
#define MBEDTLS_API_REQUEST MCU_API_REQUEST_CODE('m', 't', 'l', 's')
#endif

//#if defined __cplusplus
//}
//#endif

#endif /* MBEDTLS_API_H */
