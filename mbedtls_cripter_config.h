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


// GENERAL
#define MBEDTLS_AES_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_MD5_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_PLATFORM_ZEROIZE_ALT
#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES


// RSA
#define MBEDTLS_OID_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PK_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED   // Habilitar as curvas que você deseja usar
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PEM_WRITE_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_MD_C


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