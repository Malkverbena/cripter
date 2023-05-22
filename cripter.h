/*cripter.h*/
#ifndef CRIPTER_H
#define CRIPTER_H

#ifdef GD4
	#include "core/object/ref_counted.h"
	#include "core/io/resource_saver.h"
#else
	#include "core/reference.h"
#endif


#include <mbedtls/error.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ecdsa.h>


#pragma once


#ifdef GD4
class Cripter : public RefCounted{
	GDCLASS(Cripter, RefCounted);
	
#else
class Cripter : public Reference {
	GDCLASS(Cripter,Reference);

#endif

	
private:

	enum GCMMode {
		GCM_ENCRYPT = MBEDTLS_GCM_ENCRYPT,
		GCM_DECRYPT = MBEDTLS_GCM_DECRYPT,
	};

	Vector<uint8_t> _gcm_crypt(Vector<uint8_t> p_input, String p_password, String p_additional_data, GCMMode mode, int p_rounds);



protected:
	static void _bind_methods();


public:




	// Encrypt using CBC algorithm.
	// INPUT: is the content to be encrypted.
	// KEY: is the key in String format.
	Vector<uint8_t> aes_encrypt(Vector<uint8_t> p_input, String p_password, Algorithm p_algorith = CBC);

	// Decrypt using CBC algorithm.
	// INPUT: is the content to be encrypted.
	// KEY: is the key in String format.
	Vector<uint8_t> aes_decrypt(Vector<uint8_t> p_input, String p_password, Algorithm p_algorith = CBC);


	// Encrypt using CGM algorithm.
	// INPUT: is the content to be encrypted.
	// KEY: is the key in String format.
	// TAG: An additional TAG can be used to encrypt data. If a tag is used to encrypt, the same tag must be used to decrypty the content.
	// RAOUND: The number of key derivation. Higher numbers result in slower passphrase but increased resistance to brute-force password cracking. Must be between 4 and 128.
	Vector<uint8_t> gcm_encrypt(Vector<uint8_t> p_input, String p_password, String p_additional_data = String(), int p_rounds = 32);

	// Decrypt using CGM algorithm.
	// INPUT: is the content to be encrypted.
	// KEY: is the key in String format.
	// ADDITIONAL DATA: An optional ADDITIONAL DATA used to encrypt data. If the tag was used to encrypt, the same tag must be used to decrypty the content.
	Vector<uint8_t> gcm_decrypt(Vector<uint8_t> p_input, String p_password, String p_additional_data = String());


	// Generates an RSA PK keypair.  NOTE: The maximum size of the input to be encrypted is limited by the key size in bits.
	// PATH: path to file to private key.
	// TYPE: Type of key (RSA or EC).
	// FORMAT: Format of key (DER or PEM).
	// SIZE: Bits of the key.
	//int gen_pk_key(String p_path, RSAType type = PK_RSA, KeyFormat format = PEM, KeySize p_size = BITS_4096);



	// Encrypt and decrypt using RSA algorithm.
	//Vector<uint8_t> rsa_encrypt(Vector<uint8_t> p_input, String p_key_path);
	//Vector<uint8_t> rsa_decrypt(Vector<uint8_t> p_input, String p_key_path, String p_password = String());

	// Encrypt and decrypt using PK algorithm.
	//Vector<uint8_t> pk_encrypt(Vector<uint8_t> p_input, String p_key_path, String p_password = String());
	//Vector<uint8_t> pk_decrypt(Vector<uint8_t> p_input, String p_key_path);

	//Checks if the private and public keys match.
	//int check_keys (String p_private_key_path, String p_public_key_pathm, String p_password = String());
	
	// Create RSA key pair
	// Create_keys();
	
	// Get all available information about the last error.
	// get_last_error();

	Cripter();
	~Cripter();
};




VARIANT_ENUM_CAST(Cripter::Algorithm);


#endif 
/*cripter.h*/
