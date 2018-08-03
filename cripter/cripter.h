/*cripter.h*/

#ifndef CRIPTER_H
#define CRIPTER_H



#include "core/ustring.h"
#include "reference.h"
#include "core/variant.h"

//#include "thirdparty/mbedtls/include/mbedtls/gcm.h"
//#include "thirdparty/mbedtls/include/mbedtls/aes.h"


class cripter : public Reference {
	GDCLASS(cripter,Reference);
	

protected:
	static void _bind_methods();

		
public:

	PoolByteArray encrypt_byte_aes_cbc(PoolByteArray p_pool, String p_key);
	PoolByteArray decrypt_byte_aes_cbc(PoolByteArray p_mati, String p_key);
	
	//PoolByteArray encrypt_var_aes_cbc(Variant p_data, String p_key);
	//Variant decrypt_var_aes_cbc(PoolByteArray p_data, String p_key);

	cripter();
};


#endif

