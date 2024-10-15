/*cripter.h*/
#ifndef CRIPTER_H
#define CRIPTER_H


#include <core/config/project_settings.h>
#include "core/object/ref_counted.h"
#include "core/core_bind.h"


#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/gcm.h>
#include <mbedtls/pk.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/md.h> 
#include <mbedtls/error.h>




class Cripter : public RefCounted{
	GDCLASS(Cripter, RefCounted);



private:

	static String mbed_error_msn(int mbedtls_erro, const char* p_function);



protected:

	static void _bind_methods();




public:


	enum KeySize { // - Standard sizes for keys.
		BITS_128 = 128,
		BITS_192 = 192,
		BITS_256 = 256,
		BITS_512 = 512,
		BITS_1024 = 1024,
		BITS_2048 = 2048,
		BITS_3072 = 3072,
		BITS_4096 = 4096,
		BITS_7680 = 7680,
		BITS_8192 = 8192,
	};










	static PackedByteArray generate_iv(
		const int iv_length, 
		const String p_personalization
	);

	static String derive_key_pbkdf2(
		const String p_password, const String p_salt, 
		int iterations = 500, 
		int key_length = 16
	);


	static Dictionary gcm_encrypt(
		const PackedByteArray &plaintext, 
		const String &p_password, 
		const PackedByteArray &iv, 
		const String &p_aad = String(), 
		Cripter::KeySize p_keybits = BITS_256
	);

	static Dictionary gcm_decrypt(
		const PackedByteArray &ciphertext,
		const String &p_password,
		const PackedByteArray &iv,
		const String &p_aad,
		const PackedByteArray &p_tag,
		Cripter::KeySize p_keybits = BITS_256
	);


	Cripter();
	~Cripter();

};



#endif 
/*cripter.h*/
