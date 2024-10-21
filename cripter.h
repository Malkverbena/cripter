/*cripter.h*/
#ifndef CRIPTER_H
#define CRIPTER_H


#define MBEDTLS_ERROR_C


#include "core/config/project_settings.h"
#include "core/object/ref_counted.h"
#include "core/core_bind.h"


#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/gcm.h>
#include <mbedtls/pk.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/md.h>


#include <vector>
#include <iostream>



class Cripter : public RefCounted{
	GDCLASS(Cripter, RefCounted);


public:


	static const int GCM_TAG_SIZE = 16;
	static const int AES_BLOCK_SIZE = 16;


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


	enum Algorithm {
		EBC,
		CBC,
		XTS,
		CFB128,
		CFB8,
		OFB,
		CTR
	};

//CTR

private:

	static const int MBEDTLS_ERROR_BUFFER_LENGTH = 255;


	static std::vector<unsigned char> GDstring_to_STDvector(const String p_string);

	static std::vector<unsigned char> byteArray_to_vector(const PackedByteArray &p_packed_array);

	static String mbed_error_msn(int mbedtls_erro, const char* p_function);

	static Error add_pkcs7_padding(const std::vector<unsigned char>& data, std::vector<unsigned char>& padded_data, size_t block_size);
	
	static Error remove_pkcs7_padding(const std::vector<unsigned char>& padded_data, std::vector<unsigned char>& data, size_t block_size);

	static Variant _gcm_crypt(std::vector<unsigned char> input, std::vector<unsigned char> password, std::vector<unsigned char> iv, std::vector<unsigned char> aad, std::vector<unsigned char> tag,		Cripter::KeySize keybits, int mode);


	static std::vector<unsigned char> _aes_crypt(
		std::vector<unsigned char> input,
		std::vector<unsigned char> password,
		std::vector<unsigned char> iv,
		Algorithm algorith,
		Cripter::KeySize keybits,
		int mode
	);


protected:

	static void _bind_methods();




public:

	// Utilities

	static PackedByteArray generate_iv(
		const int iv_length,
		const String p_personalization
	);

	static String derive_key_pbkdf2(
		const String p_password, const String p_salt,
		int iterations = 500,
		int key_length = 16
	);



	// AES


	static PackedByteArray aes_encrypt(
		const PackedByteArray plaintext,
		const String p_password,		// A chave precisa ter um tamanho especifico. Use "derive_key_pbkdf2" para derivar a chave para 32 bytes / 256 bits.
		PackedByteArray p_iv,			// CBC=128 bits (16 bytes)
		Algorithm algorith = CBC,
		KeySize keybits = BITS_256
	);

	static PackedByteArray aes_decrypt(
		const PackedByteArray p_input,
		const String p_password,		
		PackedByteArray p_iv,			
		Algorithm algorith = CBC,
		KeySize keybits = BITS_256
	);



	// GCM



	static Dictionary gcm_encrypt(
		const PackedByteArray plaintext,
		const String p_password,
		const PackedByteArray p_iv,
		String p_aad = "",
		Cripter::KeySize keybits = BITS_256
	);

	static PackedByteArray gcm_decrypt(
		const PackedByteArray ciphertext,
		const String p_password,
		const PackedByteArray p_iv,
		const PackedByteArray p_tag,
		const String p_aad,
		Cripter::KeySize keybits = BITS_256
	);



	Cripter();
	~Cripter();

};

VARIANT_ENUM_CAST(Cripter::KeySize);
VARIANT_ENUM_CAST(Cripter::Algorithm);



#endif


/*cripter.h*/
