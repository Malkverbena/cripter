/* register_types.h */


#ifndef CRIPTER_REGISTER_TYPES_H
#define CRIPTER_REGISTER_TYPES_H

#include "modules/register_module_types.h"

#ifndef GD4

void initialize_cripter_module(ModuleInitializationLevel p_level);
void uninitialize_cripter_module(ModuleInitializationLevel p_level);

#else

void register_cripter_types();
void unregister_cripter_types();

#endif



#endif // CRIPTER_REGISTER_TYPES_H






