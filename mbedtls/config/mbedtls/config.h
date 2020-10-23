#ifndef CONFIG_MBEDTLS_CONFIG_H
#define CONFIG_MBEDTLS_CONFIG_H


#if defined IS_LOCAL_BUILD

#if defined __link
#include "mbedtls_link_config.h"
#else
#include "mbedtls_sos_config.h"
#endif

#else

#if defined __link
#include "../mbedtls_link_config.h"
#else
#include "../mbedtls_sos_config.h"
#endif

#endif

#endif // CONFIG_MBEDTLS_CONFIG_H
