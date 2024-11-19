/*cripter.h*/



// DEPENDENCIES
/*  // RSA
#if !defined(MBEDTLS_PK_WRITE_C) || !defined(MBEDTLS_PEM_WRITE_C) ||	\
	!defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_ENTROPY_C) ||			\
	!defined(MBEDTLS_CTR_DRBG_C) || !defined(MBEDTLS_BIGNUM_C)

#endif		// RSA

*/





#ifndef CRIPTER_H
#define CRIPTER_H


#define MBEDTLS_ERROR_C
#define MBEDTLS_ERROR_BUFFER_LENGTH 255

#define GCM_TAG_SIZE 16
#define AES_BLOCK_SIZE 16
#define HASH_SIZE_SHA_256 32
#define EXPONENT 65537



#include "core/config/project_settings.h"
#include "core/object/ref_counted.h"
#include "core/core_bind.h"


#include "mbedtls/error.h"
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/gcm.h>
#include <mbedtls/pk.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/md.h>
#include "mbedtls/rsa.h"
#include <mbedtls/ecp.h>


#include <iostream>
#include <stdio.h>
#include <fstream>
#include <vector>
#include <string>
#include <map>




class Cripter : public RefCounted{
	GDCLASS(Cripter, RefCounted);


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

	enum Algorithm {
		EBC,
		CBC,
		XTS,
		CFB128,
		CFB8,
		OFB,
		CTR
	};

	enum FileFormat {
		PEM,
		DER
	};

	using PK_TYPE = mbedtls_pk_type_t;
	using CURVE_TYPE = mbedtls_ecp_curve_type;
	using ECP_GROUP_ID = mbedtls_ecp_group_id;



private:

	static constexpr u_int8_t TYPE_RSA = 0;
	static constexpr u_int8_t TYPE_ECC = 1;

	static size_t get_max_rsa_input_size(const mbedtls_pk_context *pk);

	static String ensure_global_path(String p_path);

	static std::vector<unsigned char> GDstring_to_STDvector(const String p_string);

	static std::vector<unsigned char> byteArray_to_vector(const PackedByteArray &p_packed_array);

	static String mbed_error_msn(int mbedtls_erro, const char* p_function);

	static Error add_pkcs7_padding(const std::vector<unsigned char>& data, std::vector<unsigned char>& padded_data, const size_t block_size);
	static PackedByteArray add_pkcs7_padding(const PackedByteArray data, const size_t block_size);

	static Error remove_pkcs7_padding(const std::vector<unsigned char>& padded_data, std::vector<unsigned char>& data, const size_t block_size);
	static PackedByteArray remove_pkcs7_padding(PackedByteArray padded_data, const size_t block_size);


	static Variant _gcm_crypt(
		std::vector<unsigned char> input,
		std::vector<unsigned char> password,
		std::vector<unsigned char> iv,
		std::vector<unsigned char> aad,
		std::vector<unsigned char> tag,
		Cripter::KeySize keybits, 
		int mode
	);

/*
	static std::vector<unsigned char> _aes_crypt(
		std::vector<unsigned char> input,
		std::vector<unsigned char> password,
		std::vector<unsigned char> iv,
		Algorithm algorith,
		Cripter::KeySize keybits,
		int mode
	);
*/

	static PackedByteArray _aes_crypt(
		PackedByteArray input,
		String password,
		PackedByteArray iv,
		Algorithm algorith,
		Cripter::KeySize keybits,
		int mode
	);


protected:

	static void _bind_methods();



public:

	// Utilities ========================

	static PackedByteArray generate_iv(const int iv_length, const String p_personalization);

	static String derive_key_pbkdf2(const String p_password, const String p_salt, int iterations = 500, int key_length = 16);

	static PackedStringArray get_available_curves();



	//AES ========================
	//TODO Finish XTS
	static PackedByteArray aes_encrypt(
		const PackedByteArray plaintext,
		const String p_password,		// A chave precisa ter um tamanho especifico. Use "derive_key_pbkdf2" para derivar a chave para 32 bytes / 256 bits.
		PackedByteArray p_iv,			// CBC=128 bits (16 bytes)
		Algorithm algorith = CBC,
		KeySize keybits = BITS_256
	);

	static PackedByteArray aes_decrypt(
		const PackedByteArray ciphertext,
		const String p_password,
		PackedByteArray p_iv,
		Algorithm algorith = CBC,
		KeySize keybits = BITS_256
	);



	// GCM ========================

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

	// TODO ===============
	// Stream Start-Update-Stop


	// PK ========================

	static Dictionary pk_analyze_key(const String p_key_path);

	static Error pk_generate_keys(
		PK_TYPE algorithm_type,							// RSA or ECC
		KeySize key_size,								// Key size in bits (for RSA)
		const ECP_GROUP_ID curve,						// Curve (for ECC)
		FileFormat storage_format,						// PEM or DER
		const String password,							// Password for encryption (optional)
		const String p_private_key_filename,			// Output private key filename
		const String p_public_key_filename,				// Output public key filename
		const String personalization = "key_generation"	// Personalization
	);


	static Variant pk_match_keys(const String p_private_key_path, const String p_public_key_path, const String password);


	static PackedByteArray pk_encrypt(
		const PackedByteArray plaintext,	// The data to beencrypted.
		const String p_public_key_path		// The path to the key.
	);


	// Decrypt using RSA or EC.
	static PackedByteArray pk_decrypt(
		const PackedByteArray ciphertext,	// Buffer to decrypt.
		const String p_private_key_path,		// The path to the key.
		const String password = ""			// The data to beencrypted.
	);




	static PackedByteArray pk_sign(const String private_key_path, const PackedByteArray data, const String password = "");

	static Variant pk_verify_signature(const String public_key_path, const PackedByteArray data, const String password = "");



	// TODO ===============
	// Create certificate?







	Cripter();
	~Cripter();

};




 // ENUMS CASTS ========================

VARIANT_ENUM_CAST(Cripter::FileFormat);
VARIANT_ENUM_CAST(Cripter::Algorithm);
VARIANT_ENUM_CAST(Cripter::KeySize);
VARIANT_ENUM_CAST(Cripter::PK_TYPE);
VARIANT_ENUM_CAST(Cripter::CURVE_TYPE);
VARIANT_ENUM_CAST(Cripter::ECP_GROUP_ID);






#endif	// CRIPTER_H


/*cripter.h*/
