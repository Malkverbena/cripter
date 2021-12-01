/*cripter.h*/
#ifndef CRIPTER_H
#define CRIPTER_H

#include "core/reference.h"
#include "core/io/marshalls.h"

#include "thirdparty/mbedtls/include/mbedtls/gcm.h"
#include "thirdparty/mbedtls/include/mbedtls/aes.h"
#include "thirdparty/mbedtls/include/mbedtls/pk.h"
#include "thirdparty/mbedtls/include/mbedtls/ctr_drbg.h"
#include "thirdparty/mbedtls/include/mbedtls/rsa.h"
#include "thirdparty/mbedtls/include/mbedtls/entropy.h"

#include "thirdparty/mbedtls/include/mbedtls/error.h"  //  ---  Desenvolver   ---

/*
#include "thirdparty/mbedtls/include/mbedtls/config.h"
#include "thirdparty/mbedtls/include/mbedtls/platform.h"
#include "thirdparty/mbedtls/include/mbedtls/bignum.h"
*/

#pragma once


class cripter : public Reference {
	GDCLASS(cripter,Reference);


private:
	PoolByteArray encode_var(const Variant p_data) const;
	Variant decode_var(const PoolByteArray p_data) const;
	PoolByteArray char2pool(const uint8_t *p_in, const size_t p_size) const;


protected:
	static void _bind_methods();


public:
	//CBC
	PoolByteArray encrypt_byte_CBC(const PoolByteArray p_input, const String p_key) const;
	PoolByteArray decrypt_byte_CBC(const PoolByteArray p_input, const String p_key) const;
	PoolByteArray encrypt_var_CBC(const Variant p_input, const String p_key) const;
	Variant decrypt_var_CBC(const PoolByteArray p_input, const String p_key) const;
	//GCM
	PoolByteArray encrypt_byte_GCM(const PoolByteArray p_input, const String p_key, const String p_add = "") const;
	PoolByteArray decrypt_byte_GCM(const PoolByteArray p_input, const String p_key, const String p_add = "") const;
	PoolByteArray encrypt_var_GCM(const Variant p_input, const String p_key, const String p_add = "") const;
	Variant decrypt_var_GCM(const PoolByteArray p_input, const String p_key, const String p_add = "") const;
	//RSA
	PoolByteArray encrypt_byte_RSA(const PoolByteArray p_input,  String p_key_path) const;
	PoolByteArray decrypt_byte_RSA(const PoolByteArray p_input, const String p_key_path, const String p_password) const;
	PoolByteArray encrypt_var_RSA(const Variant p_input, const String p_key_path) const;
	Variant decrypt_var_RSA(const PoolByteArray p_input, const String p_key_path, const String p_password) const;

	cripter();
};


#endif /*cripter.h*/

