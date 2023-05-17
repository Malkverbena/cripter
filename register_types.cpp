/* register_types.cpp */

#include "register_types.h"

#include "core/object/class_db.h"
#include "cripter.h"

void initialize_cripter_module(ModuleInitializationLevel p_level) {
    if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE) {
            return;
    }
    ClassDB::register_class<Cripter>();
}

void uninitialize_cripter_module(ModuleInitializationLevel p_level) {
    if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE) {
            return;
    }

}
