/* mbedtls_config.h */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H



#include "platform_config.h"

#ifdef GODOT_MBEDTLS_INCLUDE_H

// Allow platforms to customize the mbedTLS configuration.
#include GODOT_MBEDTLS_INCLUDE_H

#else

// Include default mbedTLS config.
#include <mbedtls/mbedtls_config.h>

// Disable weak cryptography.
#undef MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
#undef MBEDTLS_DES_C
#undef MBEDTLS_DHM_C

#if !(defined(__linux__) && defined(__aarch64__))
// ARMv8 hardware AES operations. Detection only possible on linux.
// May technically be supported on some ARM32 arches but doesn't seem
// to be in our current Linux SDK's neon-fp-armv8.
#undef MBEDTLS_AESCE_C
#endif

// Disable deprecated
#define MBEDTLS_DEPRECATED_REMOVED

#endif // GODOT_MBEDTLS_INCLUDE_H




#endif // MBEDTLS_CONFIG_H


/*mbedtls_config.h*/