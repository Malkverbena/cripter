/*cripter.h*/

#ifndef CRIPTER_H
#define CRIPTER_H



#include "core/ustring.h"
#include "reference.h"
#include "core/variant.h"
#include "core/io/marshalls.h"


#include "thirdparty/mbedtls/include/mbedtls/gcm.h"
#include "thirdparty/mbedtls/include/mbedtls/aes.h"


class cripter : public Reference {
	GDCLASS(cripter,Reference);
	

//private:


protected:

	//struct crip_err {	}

	static void _bind_methods();
	
	//PoolByteArray encode_var(const Variant p_data) const;
	//Variant decode_var(const PoolByteArray p_data) const;

		
public:
	//CBC
	PoolByteArray encrypt_byte_aes_cbc(const PoolByteArray p_input,const String p_key)const;
	PoolByteArray decrypt_byte_aes_cbc(const PoolByteArray p_input,const String p_key)const;
	
	//GCM
	Array encrypt_byte_aes_gcm(const PoolByteArray p_input,const String p_key, const String p_add = "")const;
	//PoolByteArray decrypt_byte_aes_gcm(const PoolByteArray p_input, const String p_key, const PoolByteArray p_tag)const;
	

	cripter();
	~cripter();
};


#endif

