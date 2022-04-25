/*cripter.h*/
#ifndef CRIPTER_H
#define CRIPTER_H



#include "core/version_generated.gen.h"

#if VERSION_MAJOR == 4
	#include "core/object/ref_counted.h"
#else
	#include "core/reference.h"
	#include "core/pool_vector.h"
#endif


#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/error.h>

#pragma once


#if VERSION_MAJOR == 4
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
	Vector<uint8_t> gcm_encrypt(Vector<uint8_t> p_input, String p_key, String p_add = String());
	Vector<uint8_t> gcm_decrypt(Vector<uint8_t> p_input, String p_key, String p_add = String());
	Vector<uint8_t> cbc_encrypt(Vector<uint8_t> p_input, String p_key);
	Vector<uint8_t> cbc_decrypt(Vector<uint8_t> p_input, String p_key);
	Vector<uint8_t> rsa_encrypt(Vector<uint8_t> p_input, String p_key_path);
	Vector<uint8_t> rsa_decrypt(Vector<uint8_t> p_input, String p_key_path, String p_password = String());

	int check_keys_pair(String p_private_key_path, String p_public_key_path);
	
	Cripter();
	~Cripter();
};



//check_key_type

#endif /*cripter.h*/




/*
#ifdef GODOT4
	core_bind::Marshalls *_marshalls = memnew(core_bind::Marshalls);
#else

	_Marshalls *_marshalls = memnew(_Marshalls);

#endif
*/


/*
#ifdef GODOT4

#else	

#endif
*/

