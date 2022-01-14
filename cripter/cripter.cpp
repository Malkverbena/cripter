/*cripter.cpp*/

#include "cripter.h"

#define KEY_SIZE 32
#define IV_SIZE  16
#define TAG_SIZE  4

//---Do:
	//RSA  ---> Check if key file is valid / Maximun input size / Erros


//-------------- Simetric - GCM
Vector<uint8_t> cripter::encrypt_byte_GCM(Vector<uint8_t> p_input, String p_key, String p_add){
	int _err = OK;
	int size = p_input.size();
	int add_len = p_add.length();
	uint8_t p_tag[TAG_SIZE];
	uint8_t buffer[size];

	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, (unsigned char *)p_key.md5_text().utf8().get_data(), 256);

	if (add_len > 0) {
		_err = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, size, p_key.md5_buffer().ptr(), IV_SIZE, (unsigned char *)p_add.utf8().get_data(), add_len, p_input.ptr(), buffer, TAG_SIZE, p_tag);
	}else{
		_err = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, size, p_key.md5_buffer().ptr(), IV_SIZE, NULL, 0, p_input.ptr(), buffer, TAG_SIZE, p_tag);
	}

	mbedtls_gcm_free( &ctx );

	Vector<uint8_t> ret;
	char erro[150];
	mbedtls_strerror( _err, erro, sizeof(erro) );
	ERR_FAIL_COND_V_MSG(_err, ret, String::utf8(erro) + itos(_err));

	ret.resize(size);
	memcpy(ret.ptrw(), buffer, size);
	
	Vector<uint8_t> tag; 
	tag.resize(TAG_SIZE);
	memcpy(tag.ptrw(), p_tag, TAG_SIZE);
	
	ret.append_array(tag);
	return ret;
}


Vector<uint8_t> cripter::decrypt_byte_GCM(Vector<uint8_t> p_input, String p_key, String p_add){
	int _err = OK;
	int size = p_input.size();
	int add_len = p_add.length();
	uint8_t buffer[size];
	uint8_t input[size-TAG_SIZE];
	uint8_t tag[TAG_SIZE];

	for (int i = 0; i < size; i++) {
		if( i <  size-TAG_SIZE ){
			input[i] = p_input[i];
		}else{
			tag[i] = p_input[i];
		}
	}

	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, (unsigned char *)p_key.md5_text().utf8().get_data(), 256);

	if (add_len > 0) {
		_err = mbedtls_gcm_auth_decrypt(&ctx, size, p_key.md5_buffer().ptr(), IV_SIZE, (unsigned char *)p_add.utf8().get_data(), add_len, tag, TAG_SIZE, input, buffer);
	}else{
		_err = mbedtls_gcm_auth_decrypt(&ctx, size, p_key.md5_buffer().ptr(), IV_SIZE, NULL, 0, tag, TAG_SIZE, input, buffer);
	}

	mbedtls_gcm_free( &ctx );

	Vector<uint8_t> ret;
	char erro[150];
	mbedtls_strerror( _err, erro, sizeof(erro) );
	ERR_FAIL_COND_V_MSG(_err, ret, String::utf8(erro) + itos(_err));

	ret.resize(size);
	memcpy(ret.ptrw(), buffer, size-TAG_SIZE);
	return ret;
}


//-------------- Simetric - CBC
Vector<uint8_t> cripter::encrypt_byte_CBC(Vector<uint8_t> p_input, String p_key){
	
	int _err = OK;
	int input_len = p_input.size();
	int total_len = input_len;
	int extra_len = 0;

	if (input_len % 16) {
		extra_len = (16 - (input_len % 16));
		total_len = input_len + extra_len ;
	}

	uint8_t buffer[total_len];
	uint8_t input[total_len];

	for (int i = 0; i < total_len; i++) {   
		if (i < input_len){
			input[i] = (uint8_t)p_input[i];
		}else{
			//fill with zeros couse the input must be multiple of 16
			input[i] = 0;
		}
	}

	Vector<uint8_t> ret;
	char erro[150];

	mbedtls_aes_context ctx;
	mbedtls_aes_init( &ctx );

	_err = mbedtls_aes_setkey_enc( &ctx, (unsigned char *)p_key.md5_text().utf8().get_data(), 256 );
	mbedtls_strerror( _err, erro, sizeof(erro) );
	ERR_FAIL_COND_V_MSG(_err, ret, String::utf8(erro) + itos(_err));

	_err = mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_ENCRYPT, total_len, p_key.md5_buffer().ptr(), input, buffer );
	mbedtls_strerror( _err, erro, sizeof(erro) );
	ERR_FAIL_COND_V_MSG(_err, ret, String::utf8(erro) + itos(_err));

	mbedtls_aes_free( &ctx );
	
	ret.resize(total_len);
	memcpy(ret.ptrw(), buffer, total_len);
	return ret;
}


Vector<uint8_t> cripter::decrypt_byte_CBC(Vector<uint8_t> p_input, String p_key){
	Vector<uint8_t> ret;
	return ret;	
}

/*
//-------------- Asymmetric - RSA
Vector<uint8_t> cripter::encrypt_byte_RSA(Vector<uint8_t> p_input, String p_key_path){
	Vector<uint8_t> ret;
	return ret;
}


Vector<uint8_t> cripter::decrypt_byte_RSA(Vector<uint8_t> p_input, String p_key_path, String p_password){

	Vector<uint8_t> ret;
	return ret;
}

*/

void cripter::_bind_methods(){
	//CBC
	ClassDB::bind_method(D_METHOD("encrypt_byte_CBC", "Encrypt data", "key"),&cripter::encrypt_byte_CBC);
	ClassDB::bind_method(D_METHOD("decrypt_byte_CBC", "Decrypt data", "key"),&cripter::decrypt_byte_CBC);
//	ClassDB::bind_method(D_METHOD("encrypt_var_CBC", "Encrypt data", "key"),&cripter::encrypt_var_CBC);
//	ClassDB::bind_method(D_METHOD("decrypt_var_CBC", "Decrypt data", "key"),&cripter::decrypt_var_CBC);
	//GCM
	ClassDB::bind_method(D_METHOD("encrypt_byte_GCM", "Encrypt data", "key", "Additional Data"),&cripter::encrypt_byte_GCM);
	ClassDB::bind_method(D_METHOD("decrypt_byte_GCM", "Decrypt data", "key", "Additional Data"),&cripter::decrypt_byte_GCM);
//	ClassDB::bind_method(D_METHOD("encrypt_var_GCM", "Encrypt data", "key", "Additional Data"),&cripter::encrypt_var_GCM);
//	ClassDB::bind_method(D_METHOD("decrypt_var_GCM", "Decrypt data", "key", "Additional Data"),&cripter::decrypt_var_GCM);
	//RSA
//	ClassDB::bind_method(D_METHOD("encrypt_byte_RSA", "Encrypt data", "key path"),&cripter::encrypt_byte_RSA);
//	ClassDB::bind_method(D_METHOD("decrypt_byte_RSA", "Decrypt data", "key path", "Password"),&cripter::decrypt_byte_RSA);
//	ClassDB::bind_method(D_METHOD("encrypt_var_RSA", "Encrypt data", "key path"),&cripter::encrypt_var_RSA);
//	ClassDB::bind_method(D_METHOD("decrypt_var_RSA", "Decrypt data", "key path", "Password"),&cripter::decrypt_var_RSA);
}


cripter::cripter(){
}


cripter::~cripter(){
}


 /*cripter.cpp*/
