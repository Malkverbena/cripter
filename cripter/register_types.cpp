/* register_types.cpp */

#include "register_types.h"

#include "cripter.h"
#include "core/variant.h"


void register_cripter_types() { ClassDB::register_class<cripter>(); }

void unregister_cripter_types() { }

