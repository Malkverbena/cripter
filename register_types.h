/* register_types.h */


#ifndef CRIPTER_REGISTER_TYPES_H
#define CRIPTER_REGISTER_TYPES_H

#define MBEDTLS_ERROR_C

#include "modules/register_module_types.h"

void initialize_cripter_module(ModuleInitializationLevel p_level);
void uninitialize_cripter_module(ModuleInitializationLevel p_level);


#endif // CRIPTER_REGISTER_TYPES_H