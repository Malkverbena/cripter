/*cripter.h*/
#ifndef CRIPTER_H
#define CRIPTER_H

#ifdef GODOT4
	#include "core/object/ref_counted.h"  

#else
	#include "core/reference.h"
	//#include "core/bind/core_bind.h" 
	#include "core/io/marshalls.h"


#endif
//#include "core/io/marshalls.h"



#include "thirdparty/mbedtls/include/mbedtls/pk.h"
#include "thirdparty/mbedtls/include/mbedtls/ctr_drbg.h"
#include "thirdparty/mbedtls/include/mbedtls/entropy.h"

#include "thirdparty/mbedtls/include/mbedtls/gcm.h"
#include "thirdparty/mbedtls/include/mbedtls/aes.h"
#include "thirdparty/mbedtls/include/mbedtls/rsa.h"


#include "thirdparty/mbedtls/include/mbedtls/error.h"  //  ---  Desenvolver   ---


//#include "thirdparty/mbedtls/include/mbedtls/config.h"
//#include "thirdparty/mbedtls/include/mbedtls/platform.h"
//#include "thirdparty/mbedtls/include/mbedtls/bignum.h"


#pragma once

/*
#ifdef GODOT4
class cripter : public RefCounted{
	GDCLASS(cripter,RefCounted);
	typedef PackedByteArray PoolByteArray;
#else	
*/
class cripter : public Reference {
	GDCLASS(cripter,Reference);
//#endif



private:
	mbedtls_pk_context ctx_pkey;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	/*
#ifdef GODOT4
	core_bind::Marshalls *_marshalls = memnew(core_bind::Marshalls);
#else

	_Marshalls *_marshalls = memnew(_Marshalls);

#endif
*/

protected:
	static void _bind_methods();


public:
/*
#ifdef GODOT4
	typedef PackedByteArray PoolByteArray;
#endif
*/
	//CBC
	Vector<uint8_t> encrypt_byte_CBC(Vector<uint8_t> p_input, String p_key);
	Vector<uint8_t> decrypt_byte_CBC(Vector<uint8_t> p_input, String p_key);

	//GCM
	Vector<uint8_t> encrypt_byte_GCM(Vector<uint8_t> p_input, String p_key, String p_add = "");
	Vector<uint8_t> decrypt_byte_GCM(Vector<uint8_t> p_input, String p_key, String p_add = "");

	//RSA
//	Vector<uint8_t> encrypt_byte_RSA(Vector<uint8_t> p_input, String p_key_path);
//	Vector<uint8_t> decrypt_byte_RSA(Vector<uint8_t> p_input, String p_key_path, String p_password);


	cripter();
	~cripter();
};


#endif /*cripter.h*/



/*
#ifdef GODOT4

#else	

#endif
*/

