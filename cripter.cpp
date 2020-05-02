/*cripter.cpp*/

#include "cripter.h"

//include <stdio.h>		//---Testar aquivo
//#include <stdlib.h>
//#include <string.h>     //---???

//---Do:
	//RSA  ---> Check if key file is valid / Maximun input size / Erros

#define KEY_SIZE   32
#define EXT_SIZE   16
#define TAG_SIZE   4


//-------------- Encrypt Vars
PoolByteArray cripter::encrypt_var_CBC(const Variant p_input, const String p_key) const { return encrypt_byte_CBC((encode_var(p_input)), p_key); }

PoolByteArray cripter::encrypt_var_GCM(const Variant p_input, const String p_key, const String p_add) const { return encrypt_byte_GCM((encode_var(p_input)), p_key, p_add); }

PoolByteArray cripter::encrypt_var_RSA(const Variant p_input, const String p_key_path) const{ return encrypt_byte_RSA((encode_var(p_input)), p_key_path); }


//-------------- Decrypt Vars
Variant cripter::decrypt_var_CBC(const PoolByteArray p_input, const String p_key) const{ return decode_var((decrypt_byte_CBC(p_input, p_key))); }

Variant cripter::decrypt_var_GCM(const PoolByteArray p_input, const String p_key, const String p_add) const { return decode_var(decrypt_byte_GCM(p_input, p_key, p_add)); }

Variant cripter::decrypt_var_RSA(const PoolByteArray p_input, const String p_key_path, const String p_password) const{ return decode_var((decrypt_byte_RSA(p_input, p_key_path, p_password))); }



//-------------- Simetric - GCM
PoolByteArray cripter::encrypt_byte_GCM(const PoolByteArray p_input, const String p_key, const String p_add) const {
	uint8_t _err = 0;

	//Prepare key & iv **
	String h_key = p_key.md5_text();
	uint8_t key[KEY_SIZE];
	uint8_t iv[EXT_SIZE];
	for (uint8_t i = 0; i < KEY_SIZE; i++) {
		key[i] = h_key[i];
	}
	for (uint8_t i = 0; i < EXT_SIZE; i++){
		iv[i] = key[i*2];
	}

	//Preparing Buffer
	char erro[150];
	//Array ret;
	uint8_t input[p_input.size()];
	uint8_t output[sizeof(input)];

	PoolVector<uint8_t>::Read r = p_input.read();   //PoolByteArray to CharArray
	for (uint8_t i = 0; i < p_input.size(); i++) {
		input[i] = (uint8_t)p_input[i];
	}

	//Prepare Tag
	uint8_t tag[TAG_SIZE];

	//Prepare Addicional Data
	uint8_t add_len = p_add.length();
	uint8_t add[add_len];
	for (uint8_t i = 0; i < add_len; i++) {
		add[i] = p_add[i];
	}

	//Encryptation
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);

	if (add_len == 0){
		_err = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, sizeof(input), iv, EXT_SIZE, NULL, 0, input, output, TAG_SIZE, tag);
		if( _err != 0)
	{
		mbedtls_strerror( _err, erro, sizeof(erro) );
		print_error( erro );
	}

	}else
	{
		_err = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, sizeof(input), iv, EXT_SIZE, add, add_len, input, output, TAG_SIZE, tag);
		if( _err != 0)
		{
			mbedtls_strerror( _err, erro, sizeof(erro) );
			print_error( erro );
		}
	}

	mbedtls_gcm_free( &ctx );

	PoolByteArray ret_output = char2pool(output, sizeof(output));
	PoolByteArray ret_tag = char2pool(tag, sizeof(tag));
	ret_output.append_array(ret_tag);

	return ret_output;
}


PoolByteArray cripter::decrypt_byte_GCM(const PoolByteArray p_input, const String p_key, const String p_add) const{
	uint8_t _err;

	//Prepare key & iv **
	String h_key = p_key.md5_text();
	uint8_t key[KEY_SIZE];
	uint8_t iv[EXT_SIZE];
	for (uint8_t i = 0; i < KEY_SIZE; i++)
	{
		key[i] = h_key[i];
	}
	for (uint8_t i = 0; i < EXT_SIZE; i++)
	{
		iv[i] = key[i*2];
	}

	//Preparing Buffer
	char erro[150];
	PoolByteArray ret_output;
	uint8_t data_len = p_input.size();
	uint8_t input[(data_len - TAG_SIZE)];
	uint8_t output[sizeof(input)];

	PoolVector<uint8_t>::Read r = p_input.read();
	for (uint8_t i = 0; i < (data_len - TAG_SIZE); i++)
	{
		input[i] = (uint8_t)p_input[i];
	}

	//Extract Tag
	uint8_t tag[TAG_SIZE];
	PoolVector<uint8_t>::Read R = p_input.read();
	for (uint8_t i = 0; i < TAG_SIZE; i++)
		{
			tag[i] = (uint8_t)p_input[ (data_len - TAG_SIZE) + i];
		}

	//Prepare Addicional Data
	uint8_t add_len = p_add.length();
	uint8_t add[add_len];
	for (uint8_t i = 0; i < add_len; i++)
	{
		add[i] = p_add[i];
	}

	//Decryptation
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);

	if (add_len == 0)
	{
		_err = mbedtls_gcm_auth_decrypt(&ctx, sizeof(input), iv, EXT_SIZE, NULL, 0, tag, TAG_SIZE, input, output);
		if( _err != 0)
		{
			mbedtls_strerror( _err, erro, sizeof(erro) );
			print_error( erro );
		}

	}else
	{
		_err = mbedtls_gcm_auth_decrypt(&ctx, sizeof(input), iv, EXT_SIZE, add, add_len, tag, TAG_SIZE, input, output);
		if( _err != 0)
	{
		mbedtls_strerror( _err, erro, sizeof(erro) );
		print_error( erro );
	}
	}

	//Ending
	mbedtls_gcm_free( &ctx );
	return char2pool(output, sizeof(output));
}


//-------------- Simetric - CBC
PoolByteArray cripter::encrypt_byte_CBC(const PoolByteArray p_input, const String p_key) const{
	uint8_t _err;

	//Prepare key & iv **
	String h_key = p_key.md5_text();
	uint8_t key[KEY_SIZE];
	uint8_t iv[EXT_SIZE];
	for (uint8_t i = 0; i < KEY_SIZE; i++)
	{
		key[i] = h_key[i];
	}
	for (uint8_t i = 0; i < EXT_SIZE; i++)
	{
		iv[i] = key[i*2];
	}

	//Preparing buffer **
	uint8_t data_len = p_input.size();
	uint8_t extra_len;
	uint8_t total_len;
	char erro[150];

	if (data_len % 16) {
		extra_len = (16 - (data_len % 16));
		total_len = data_len + extra_len ;
	} else 
	{
		total_len = data_len;
		extra_len = 0;
	}

	uint8_t input[total_len];
	uint8_t output[sizeof(input)];
	for (uint8_t g = 0; g < data_len; g++)
	{
		input[g] = (uint8_t)p_input[g];
	}
	for (uint8_t l = data_len; l < total_len; l++)  //fill with zeros couse the input must be multiple of 16
	{
		input[l] = 0;
	}

	//Encryptation **
	mbedtls_aes_context ctx;
	mbedtls_aes_init( &ctx );

	_err = mbedtls_aes_setkey_enc( &ctx, key, 256 );
	if( _err != 0)
	{
		mbedtls_strerror( _err, erro, sizeof(erro) );
		print_error( erro );
	}
	_err = mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_ENCRYPT, total_len, iv, input, output );
	if( _err != 0)
	{
		mbedtls_strerror( _err, erro, sizeof(erro) );
		print_error( erro );
	}

	mbedtls_aes_free( &ctx );


	//--- Fit data *
	PoolByteArray ret = char2pool(output, (sizeof(output)));
	ret.push_back(extra_len);
	return ret;
}


PoolByteArray cripter::decrypt_byte_CBC(const PoolByteArray p_input, const String p_key) const {
	uint8_t _err;

	//Prepare key & iv **
	String h_key = p_key.md5_text();
	uint8_t key[KEY_SIZE];
	uint8_t iv[EXT_SIZE];
	for (uint8_t i = 0; i < KEY_SIZE; i++)
	{
		key[i] = h_key[i];
	}
	for (uint8_t i = 0; i < EXT_SIZE; i++)
	{
		iv[i] = key[i*2];
	}

	//Preparing buffer **
	uint8_t data_len = p_input.size() - 1;
	uint8_t zeros = p_input[data_len];
	uint8_t input[data_len];
	uint8_t output[data_len];
	char erro[150];

	for (uint8_t g = 0; g < data_len; g++)
	{
		input[g] = (uint8_t)p_input[g];
	}

	//Decryptation **
	mbedtls_aes_context ctx;
	mbedtls_aes_init( &ctx );

	_err = mbedtls_aes_setkey_dec(&ctx, key, 256);
	if(_err != 0)
	{
		mbedtls_strerror( _err, erro, sizeof(erro) );
		print_error( erro );
	}

	_err = mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_DECRYPT, data_len, iv, input, output);
	if( _err != 0)
	{
		mbedtls_strerror( _err, erro, sizeof(erro) );
		print_error( erro );
	}

	mbedtls_aes_free( &ctx );

	//Fit data **
	return char2pool(output, (sizeof(output) - zeros)); //No more extra zeros here
}


//-------------- Asymmetric - RSA
PoolByteArray cripter::encrypt_byte_RSA(const PoolByteArray p_input, String p_key_path) const {
	uint8_t _err;

	//--- Load key
	char key[p_key_path.length()+1];
	for (uint8_t i = 0; i < p_key_path.length(); i++)
	{
		key[i] = p_key_path[i];
	}
	key[p_key_path.length()] = 0;

	//---Buffer
	size_t olen = 0;
	const char *pers = "rsa_encrypt";
	char erro[150];

	uint8_t input[p_input.size()];
	uint8_t output[512];

	PoolVector<uint8_t>::Read r = p_input.read();
	for (uint8_t i = 0; i < sizeof(input); i++)
	{
		input[i] = (uint8_t)p_input[i];
	}

	//---Init
	mbedtls_pk_context pk;
	mbedtls_pk_init( &pk );

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init( &entropy );

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init( &ctr_drbg );


	_err = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
									&entropy, (const unsigned char *) pers,
									strlen( pers )) ;

	if( _err != 0)
	{
		mbedtls_strerror( _err, erro, sizeof(erro) );
		print_error( erro );
	}

	//---Encryptation
	_err = mbedtls_pk_parse_public_keyfile( &pk,  key);
	if( _err != 0 )
	{
		mbedtls_strerror( _err, erro, sizeof(erro) );
		print_error( erro );
	//	printf( "%c", erro );
	}

	fflush( stdout );

	_err = mbedtls_pk_encrypt( &pk, input, sizeof(input),
									output, &olen, sizeof(output),
									mbedtls_ctr_drbg_random, &ctr_drbg );
									
	if( _err != 0 )
	{
		mbedtls_strerror( _err, erro, sizeof(erro) );
		print_error( erro );
	}

	//--- Fit data
	mbedtls_pk_free( &pk);
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );

	return char2pool(output, olen);
}



PoolByteArray cripter::decrypt_byte_RSA(const PoolByteArray p_input, const String p_key_path, const String p_password) const {
	uint8_t _err;

	//--- Load key
	char key[p_key_path.length()+1];
	for (uint8_t i = 0; i < p_key_path.length(); i++) 
	{
		key[i] = p_key_path[i];
	}
	key[p_key_path.length()] = 0;

	//--- Load Password
	char password[p_password.length()+1];
	for (uint8_t i = 0; i < p_password.length(); i++)
	{
		password[i] = p_password[i];
	}
	password[p_password.length()] = 0;

	//---Buffer
	uint8_t input[512];
	uint8_t output[512];

	size_t olen = 0;
	const char *pers = "rsa_decrypt";
	char erro[150];	

	PoolVector<uint8_t>::Read r = p_input.read();
	for (uint8_t i = 0; i < 512; i++) {
		input[i] = (uint8_t)p_input[i];
	}

	//---Init
	mbedtls_pk_context ctx_pk;
	mbedtls_pk_init( &ctx_pk );

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init( &entropy );

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init( &ctr_drbg );

	_err = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
							&entropy, (const unsigned char *) pers,
							strlen( pers ));

	if(_err != 0)
	{
		mbedtls_strerror( _err, erro, sizeof(erro) );
		print_error( erro );
	}

	//---Decryptation **
	_err = mbedtls_pk_parse_keyfile( &ctx_pk, key, password );
	if( _err != 0 )
	{
		mbedtls_strerror( _err, erro, sizeof(erro) );
		print_error( erro );
	}

	fflush( stdout );


	_err = mbedtls_pk_decrypt( &ctx_pk, input, sizeof(input),
									output, &olen, sizeof(output),
									mbedtls_ctr_drbg_random, &ctr_drbg );

	if(_err != 0 )
	{
		mbedtls_strerror( _err, erro, sizeof(erro) );
		print_error( erro );
	}

	//---Turn off the lights **
	mbedtls_pk_free( &ctx_pk);
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );

	return char2pool(output, olen); 
}


//-------------- Support
PoolByteArray cripter::char2pool(const uint8_t *p_in, const size_t p_size)const{
	PoolByteArray data;
	data.resize(p_size);
	PoolVector<uint8_t>::Write w = data.write();
	for (uint8_t i = 0; i < p_size; i++)
	{
		w[i] = (uint8_t)p_in[i];
	}
	w = PoolVector<uint8_t>::Write();
	return data;
}


PoolByteArray cripter::encode_var(const Variant data) const{
	//Encoder
	PoolByteArray ret;
	int len;
	Error err = encode_variant(data, NULL, len);
	if (err != OK)
	{
		print_line("Unexpected error encoding variable to bytes");
		return ret;
	}
	ret.resize(len);
	{
		PoolByteArray::Write w = ret.write();
		encode_variant(data, w.ptr(), len);
	}
	return ret;
}


Variant cripter::decode_var(const PoolByteArray p_data) const{
	//Decoder
	Variant ret;
	PoolByteArray data = p_data;
	PoolByteArray::Read r = data.read();
	Error err = decode_variant(ret, r.ptr(), data.size(), NULL);

	if (err != OK)
	{
		print_line("Unexpected error decoding bytes to variable");
		Variant f;
		return f;
	}
	return ret;
}


void cripter::_bind_methods(){
	//CBC
	ClassDB::bind_method(D_METHOD("encrypt_byte_CBC", "Encrypt data", "key"),&cripter::encrypt_byte_CBC);
	ClassDB::bind_method(D_METHOD("decrypt_byte_CBC", "Decrypt data", "key"),&cripter::decrypt_byte_CBC);
	ClassDB::bind_method(D_METHOD("encrypt_var_CBC", "Encrypt data", "key"),&cripter::encrypt_var_CBC);
	ClassDB::bind_method(D_METHOD("decrypt_var_CBC", "Decrypt data", "key"),&cripter::decrypt_var_CBC);
	//GCM
	ClassDB::bind_method(D_METHOD("encrypt_byte_GCM", "Encrypt data", "key", "Additional Data"),&cripter::encrypt_byte_GCM);
	ClassDB::bind_method(D_METHOD("decrypt_byte_GCM", "Decrypt data", "key", "Additional Data"),&cripter::decrypt_byte_GCM);
	ClassDB::bind_method(D_METHOD("encrypt_var_GCM", "Encrypt data", "key", "Additional Data"),&cripter::encrypt_var_GCM);
	ClassDB::bind_method(D_METHOD("decrypt_var_GCM", "Decrypt data", "key", "Additional Data"),&cripter::decrypt_var_GCM);
	//RSA
	ClassDB::bind_method(D_METHOD("encrypt_byte_RSA", "Encrypt data", "key path"),&cripter::encrypt_byte_RSA);
	ClassDB::bind_method(D_METHOD("decrypt_byte_RSA", "Decrypt data", "key path", "Password"),&cripter::decrypt_byte_RSA);
	ClassDB::bind_method(D_METHOD("encrypt_var_RSA", "Encrypt data", "key path"),&cripter::encrypt_var_RSA);
	ClassDB::bind_method(D_METHOD("decrypt_var_RSA", "Decrypt data", "key path", "Password"),&cripter::decrypt_var_RSA);
}

cripter::cripter(){
} /*cripter.cpp*/
