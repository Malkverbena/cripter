/* mbedtls_cripter_config.h */


#ifndef MBEDTLS_CRIPTER_CONFIG_H
#define MBEDTLS_CRIPTER_CONFIG_H

#include <limits.h>

#include "platform_config.h"


// Enable mbedtls_strerror()
#define MBEDTLS_ERROR_C


// For AES
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CFB
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_CIPHER_MODE_OFB
#define MBEDTLS_CIPHER_MODE_XTS


#define MBEDTLS_AES_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_MD5_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_PLATFORM_ZEROIZE_ALT
#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES


// Disable deprecated
#define MBEDTLS_DEPRECATED_REMOVED


// Disable weak cryptography.
#undef MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
#undef MBEDTLS_DES_C
#undef MBEDTLS_DHM_C


#if !(defined(__linux__) && defined(__aarch64__))
#undef MBEDTLS_AESCE_C
#endif


#if defined(__MINGW32__)
#define MBEDTLS_PLATFORM_C
#endif



#endif // MBEDTLS_CRIPTER_CONFIG_H