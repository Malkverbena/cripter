/*cripter.h*/
#ifndef CRIPTER_H
#define CRIPTER_H

#ifdef GD4
	#include "core/object/ref_counted.h"
#else
	#include "core/reference.h"
#endif

#include "core/io/marshalls.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/error.h>

#pragma once

#ifdef GD4
class Cripter : public RefCounted{
	GDCLASS(Cripter, RefCounted);
	
#else
class Cripter : public Reference {
	GDCLASS(Cripter,Reference);

#endif
	
private:
	mbedtls_aes_context aes_ctx;
	mbedtls_gcm_context gcm_ctx;
	mbedtls_entropy_context entropy;
	mbedtls_pk_context key_ctx;
	mbedtls_ctr_drbg_context ctr_drbg;

	String show_error(int p_error, const char* p_function);


protected:
	static void _bind_methods();


public:
	Vector<uint8_t> cbc_encrypt(Vector<uint8_t> p_input, String p_key);
	Vector<uint8_t> cbc_decrypt(Vector<uint8_t> p_input, String p_key);
	Vector<uint8_t> gcm_encrypt(Vector<uint8_t> p_input, String p_key, String p_add = String());
	Vector<uint8_t> gcm_decrypt(Vector<uint8_t> p_input, String p_key, String p_add = String());
	Vector<uint8_t> rsa_encrypt(Vector<uint8_t> p_input, String p_key_path);
	Vector<uint8_t> rsa_decrypt(Vector<uint8_t> p_input, String p_key_path, String p_password = String());
	int keys_match_check(String p_private_key_path, String p_public_key_pathm, String p_password = String());

	Cripter();
	~Cripter();
};


#endif 
/*cripter.h*/
