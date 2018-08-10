/*cripter.h*/

#ifndef CRIPTER_H
#define CRIPTER_H

/*
	To Do:
		CBC - GCM
		Encode/Decote Variant to encrypt var function
		Add Entropy
		Streaming 
		RSA
		Check the right way to access to vetors 
		Function to Errors
		Keep c++98
		rewrite the bad code(awake and with coffee this time...)
		
*/


#include "core/ustring.h"
#include "reference.h"
//#include "core/variant.h"
#include "core/io/marshalls.h"


#include "thirdparty/mbedtls/include/mbedtls/gcm.h"
#include "thirdparty/mbedtls/include/mbedtls/aes.h"


class cripter : public Reference {
	GDCLASS(cripter,Reference);
	
private:

	//struct cripter_err {	}
	

	PoolByteArray encode_var(const Variant p_data) const;
	Variant decode_var(const PoolByteArray p_data) const;
	
	PoolByteArray char2pool(const uint8_t *p_in, size_t p_size) const;
	//void pool2char() const;


protected:

	static void _bind_methods();
	

			
public:

	//CBC
	PoolByteArray encrypt_byte_aes_CBC(const PoolByteArray p_input, const String p_key) const;
	PoolByteArray decrypt_byte_aes_CBC(const PoolByteArray p_input, const String p_key) const;
	
	PoolByteArray encrypt_var_aes_CBC(const Variant p_input, const String p_key) const;
	Variant decrypt_var_aes_CBC(const PoolByteArray p_input, const String p_key) const;
	
	
	//GCM
	Array encrypt_byte_aes_GCM(const PoolByteArray p_input, const String p_key, const String p_add = "") const;
	PoolByteArray decrypt_byte_aes_GCM(const PoolByteArray p_input, const String p_key, const PoolByteArray p_tag, const String p_add = "") const;
	
	Array encrypt_var_aes_GCM(const Variant p_input, const String p_key, const String p_add = "") const;
	Variant decrypt_var_aes_GCM(const PoolByteArray p_input, const String p_key, const PoolByteArray p_tag, const String p_add = "") const;

	cripter();

	
};


#endif

