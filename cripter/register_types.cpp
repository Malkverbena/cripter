/* register_types.cpp */

#include "register_types.h"
#include "cripter.h"
	 

#ifdef GD4

void initialize_cripter_module(ModuleInitializationLevel p_level) {
	if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE) {
		return;
	}
	GDREGISTER_CLASS(Cripter);
}

void uninitialize_cripter_module(ModuleInitializationLevel p_level) {
	if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE) {
		return;
	}
}

#else

void register_cripter_types() {
	ClassDB::register_class<Cripter>();
}

void unregister_cripter_types() {
}

#endif


