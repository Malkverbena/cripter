/*cripter.h*/
#ifndef CRIPTER_H
#define CRIPTER_H

#ifdef GD4
	#include "core/object/ref_counted.h"
	#include "core/io/resource_saver.h"
	#include "core/io/resource_loader.h"
	#include <core/config/project_settings.h>
#else
	#include "core/reference.h"
#endif


//TODO: Support to big-endian on RSA

#include <mbedtls/error.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "mbedtls/platform.h"
#include "mbedtls/bignum.h"

#include "mbedtls/rsa.h"
#include <mbedtls/gcm.h>
#include <mbedtls/pk.h>


#ifdef GD4
class RsaKey : public RefCounted{
	GDCLASS(RsaKey, RefCounted);
#else
class RsaKey : public Reference {
	GDCLASS(RsaKey,Reference);
#endif

friend class Cripter;

private:
	int key_type;
	int key_format;
	Vector<uint8_t> N, P, Q, D, E, DP, DQ, QP;


protected:
	static void _bind_methods();


public:
	RsaKey();
	~RsaKey();

};






#ifdef GD4
class Cripter : public RefCounted{
	GDCLASS(Cripter, RefCounted);
	
#else
class Cripter : public Reference {
	GDCLASS(Cripter,Reference);

#endif


private:

	static String mbed_error_msn(int mbedtls_erro, const char* p_function);
	static Dictionary _analize_pk_key(String p_key_path, bool is_private);


protected:

	static void _bind_methods();


public:
	enum KEY_FORMAT{
		DER	= 0,
		PEM	= 1,
	};

	enum EC_CURVE{};


	enum KEY_TYPE {
		PRIVATE	= 0,
		PUBLIC	= 1,
	};

	enum PK_TYPE{
//		PK_NONE			= MBEDTLS_PK_NONE,
		PK_RSA			= MBEDTLS_PK_RSA,
		PK_ECKEY		= MBEDTLS_PK_ECKEY,
//		PK_ECKEY_DH		= MBEDTLS_PK_ECKEY_DH,
//		PK_ECDSA		= MBEDTLS_PK_ECDSA,
//		PK_RSA_ALT		= MBEDTLS_PK_RSA_ALT,
//		PK_RSASSA_PSS	= MBEDTLS_PK_RSASSA_PSS,
//		PK_OPAQUE		= MBEDTLS_PK_OPAQUE,
	};


	enum KeySize { // - 
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
	//	CTR >> CTR is straming orientated. We don't need it now.
	};


/* GCM */
	// This function performs an encryption using CGM algorithm.
	// INPUT: is the content to be encrypted.
	// PASSWORD: Is the password used to encrypt the data.
	// ADDITIONAL DATA: An additional and optional data that can be used to encryptation. If te optional data be used to encryptation, the same data must be used to decrypt the content.
	static Vector<uint8_t> gcm_encrypt(Vector<uint8_t> p_input, String p_password, String p_add = String(), KeySize p_keybits = BITS_256);

	// This function performs a decryption using CGM algorithm.
	// INPUT: is the content to be dencrypted.
	// PASSWORD: Is the password used to decrypt the data.
	// ADDITIONAL DATA: An additional AND optional data used on encryptation data. If the additional data was used to encrypt, the same data must be used to decrypt the content.
	static Vector<uint8_t> gcm_decrypt(Vector<uint8_t> p_input, String p_password, String p_add = String(), KeySize p_keybits = BITS_256);


/* AES */
	// This function performs an AES encryption operation.
	// INPUT: is the content to be encrypted.
	// PASSWORD: Is the password used to encrypt the data.
	// ALGORITH: The Algorithm used to perform the encryptation
	static Vector<uint8_t> aes_encrypt(Vector<uint8_t> p_input, String p_password, Algorithm p_algorith = CBC, KeySize p_keybits = BITS_256);

	// This function performs an AES decryption operation.
	// INPUT: is the content to be dencrypted.
	// PASSWORD: Is the password used to decrypt the data.
	// KYBITS: The size of password in bits. Common AES accepts the sizes 128, 192 and 256. XTS is an exception and only accepts the sizes 256 and 512. 
	// ALGORITH: The Algorithm used to perform the dencryptation
	static Vector<uint8_t> aes_decrypt(Vector<uint8_t> p_input, String p_password, Algorithm p_algorith = CBC, KeySize p_keybits = BITS_256);


/* PK */
	// Generates an RSA PK keypair.  NOTE: The maximum size of the input to be encrypted is limited by the key size in bits.
	// PATH: path to file to private key.
	// KEY_NAME: The name of keys pair file.
	// TYPE: Type of key (RSA or EC).
	// FORMAT: Format of key (DER or PEM).
	// SIZE: Bits of the key. Acceptable sizes: 1024 till 8196.
	// EC_CURVE: Curve used on EC keys only.
	static int gen_pk_keys(String p_path, String key_name, PK_TYPE p_type = PK_RSA, KeySize p_keybits = BITS_2048, String ec_curve = "secp521r1");

	// Check if a public-private pair of keys matches. 
	// NOTE: mbedtls_erro returns a negatine int. Godot error returns a positive int. Valid result returns True or False.
	// PRIVATE_PATH: Pathto the private key.
	// PUBLIC_PATH: Pathto the public key.
	// PASSWORD: The private key's password.
	static Variant compare_pk_keys(String p_private_key_path, String p_public_key_path, String p_password = String());

	// Return info about the PK keys
	// KEY_PATH: The path to the key. 
	static Dictionary analize_pk_key(String p_key_path);

	// Return the ec curves available in your system.  
	static PackedStringArray get_available_ec_curves();

	// Encrypt using PK_RSA OR PK_ECP. NOTE: The maximum size of data you can encrypt if equal the size of the key in Bytes.
	// INPUT: The data to beencrypted.
	// KEY_PATH: The path to the key. 
	static Vector<uint8_t> pk_encrypt(Vector<uint8_t> p_input, String p_key_path);

	// Decrypt using PK_RSA OR PK_ECP.
	// INPUT: The data to beencrypted.
	// KEY_PATH: The path to the key. 
	static Vector<uint8_t> pk_decrypt(Vector<uint8_t> p_input, String p_key_path, String p_password = String());


	static Array gen_rsa_keys(KEY_FORMAT p_format = PEM, KeySize p_keybits = BITS_1024);



	Cripter();
	~Cripter();

};

VARIANT_ENUM_CAST(Cripter::KEY_TYPE);

VARIANT_ENUM_CAST(Cripter::PK_TYPE);
VARIANT_ENUM_CAST(Cripter::KeySize);
VARIANT_ENUM_CAST(Cripter::Algorithm);
VARIANT_ENUM_CAST(Cripter::KEY_FORMAT);




#endif 
/*cripter.h*/
