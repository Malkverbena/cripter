/*cripter.h*/
#ifndef CRIPTER_H
#define CRIPTER_H

#ifdef GD4
	#include "core/object/ref_counted.h"
#else
	#include "core/reference.h"
#endif


#include <mbedtls/error.h>
#include <mbedtls/gcm.h>

/*
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/aes.h>
*/


#pragma once

#ifdef GD4
class Cripter : public RefCounted{
	GDCLASS(Cripter, RefCounted);
	
#else
class Cripter : public Reference {
	GDCLASS(Cripter,Reference);

#endif
	
private:
	Dictionary last_error;
	void _error_process(int mbedtls_erro, const char* p_function);


protected:
	static void _bind_methods();


public:
	// Encrypt and decrypt using CBC algorithm.
	//Vector<uint8_t> cbc_encrypt(Vector<uint8_t> p_input, String p_key);
	//Vector<uint8_t> cbc_decrypt(Vector<uint8_t> p_input, String p_key);



	// Encrypt using CGM algorithm.
	// INPUT: is the content to be encrypted.
	// KEY: is the key in String format.
	// TAG: An additional TAG can be used to encrypt data. If a tag is used to encrypt, the same tag must be used to decrypty the content.
	Vector<uint8_t> gcm_encrypt(Vector<uint8_t> input, String key, String p_tag = String());


	// Decrypt using CGM algorithm.
	// INPUT: is the content to be encrypted.
	// KEY: is the key in String format.
	// TAG: An optional TAG used to encrypt data. If the tag was used to encrypt, the same tag must be used to decrypty the content.
	Vector<uint8_t> gcm_decrypt(Vector<uint8_t> input, String key, String p_tag = String());


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


#endif 
/*cripter.h*/
