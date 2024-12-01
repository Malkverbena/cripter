

#ifndef CONFIG_2_H
#define CONFIG_2_H


#include "platform_config.h"

#include <mbedtls/mbedtls_config.h>

#include "mbedtls/build_info.h"

#include <stddef.h>


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


#endif // CONFIG_2_H
