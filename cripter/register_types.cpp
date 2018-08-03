/* register_types.cpp */

#include "register_types.h"

//#include <stddef.h>

#include "cripter.h"
#include "variant.h"
#include "thirdparty/mbedtls/include/mbedtls/gcm.h"
#include "thirdparty/mbedtls/include/mbedtls/aes.h"


void register_cripter_types() {

        ClassDB::register_class<cripter>();
}

void unregister_cripter_types() {
   //nothing to do here
}

