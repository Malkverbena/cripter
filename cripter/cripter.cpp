/*cripter.cpp*/

#include "cripter.h"

#define KEY_SIZE 32
#define IV_SIZE  16
#define TAG_SIZE  4

//---Do:
	//RSA  ---> Check if key file is valid 
	//RSA  ---> mbedtls_pk_check_pair

//-------------- Simetric - GCM
Vector<uint8_t> Cripter::gcm_encrypt(Vector<uint8_t> p_input, String p_key, String p_add ){
	String error_text;
	int size = p_input.size();
	int add_len = p_add.length();
	uint8_t p_tag[TAG_SIZE];
	uint8_t buffer[size];
	Vector<uint8_t> ret;

	mbedtls_gcm_init(&gcm_ctx);

	int mbedtls_erro = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, (unsigned char *)p_key.md5_text().utf8().get_data(), 256);
	if( mbedtls_erro != OK) {
		error_text = show_error(mbedtls_erro, "mbedtls_gcm_setkey" );  
	}

	if( mbedtls_erro == OK) { 
		if (add_len > 0) {
			mbedtls_erro = mbedtls_gcm_crypt_and_tag(&gcm_ctx, MBEDTLS_GCM_ENCRYPT, size, p_key.md5_buffer().ptr(), IV_SIZE, (unsigned char *)p_add.utf8().get_data(), add_len, p_input.ptr(), buffer, TAG_SIZE, p_tag);
		}else{
			mbedtls_erro = mbedtls_gcm_crypt_and_tag(&gcm_ctx, MBEDTLS_GCM_ENCRYPT, size, p_key.md5_buffer().ptr(), IV_SIZE, NULL, 0, p_input.ptr(), buffer, TAG_SIZE, p_tag);
		}
	}else{ 
		error_text = show_error(mbedtls_erro, "mbedtls_gcm_crypt_and_tag"); 
	}

	mbedtls_gcm_free( &gcm_ctx );

	ERR_FAIL_COND_V_MSG(mbedtls_erro, ret, error_text + itos(mbedtls_erro));

	ret.resize(size);
	memcpy(ret.ptrw(), buffer, size);
	Vector<uint8_t> tag; 
	tag.resize(TAG_SIZE);
	memcpy(tag.ptrw(), p_tag, TAG_SIZE);
	ret.append_array(tag);
	return ret;
}


Vector<uint8_t> Cripter::gcm_decrypt(Vector<uint8_t> p_input, String p_key, String p_add ){
	String error_text;
	Vector<uint8_t> ret;
	int size = p_input.size();
	int add_size = p_add.length();
	uint8_t output[ size - TAG_SIZE ];

#ifdef GD4
	Vector<uint8_t> data = (p_input.slice(0, size - TAG_SIZE));
	Vector<uint8_t> tag = (p_input.slice(size - TAG_SIZE, size));
#else
	uint8_t p_tag[TAG_SIZE];
	for (int i = 0; i < TAG_SIZE; i++) {
		p_tag[i] = (uint8_t)p_input[ (size - TAG_SIZE) + i];
	}
	Vector<uint8_t> tag;
	memcpy(tag.ptrw(), p_tag, TAG_SIZE);

	uint8_t input[ size - TAG_SIZE ];
	for (int i = 0; i < (size - TAG_SIZE); i++) {
		input[i] = (uint8_t)p_input[i];
	}
	Vector<uint8_t> data;
	memcpy(data.ptrw(), input, size - TAG_SIZE);
#endif

	mbedtls_gcm_init(&gcm_ctx);

	int mbedtls_erro = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, (unsigned char *)p_key.md5_text().utf8().get_data(), 256);
	if( mbedtls_erro != OK) {
		error_text = show_error(mbedtls_erro, "mbedtls_gcm_setkey" );  
	}

	if( mbedtls_erro == OK) { 
		if (add_size > 0) {
			mbedtls_erro = mbedtls_gcm_auth_decrypt(&gcm_ctx, data.size(), p_key.md5_buffer().ptr(), IV_SIZE, (unsigned char *)p_add.utf8().get_data(), add_size, tag.ptr(), TAG_SIZE, data.ptr(), output);
		}else{
			mbedtls_erro = mbedtls_gcm_auth_decrypt(&gcm_ctx, data.size(), p_key.md5_buffer().ptr(), IV_SIZE, NULL, add_size, tag.ptr(), TAG_SIZE, data.ptr(), output);
		}
	}else{ 
		error_text = show_error(mbedtls_erro, "mbedtls_gcm_auth_decrypt" ); 
	}

	mbedtls_gcm_free( &gcm_ctx );

	ERR_FAIL_COND_V_MSG(mbedtls_erro, ret, error_text + itos(mbedtls_erro));

	ret.resize(size - TAG_SIZE);
	memcpy(ret.ptrw(), output, size);
	return ret;
}


//-------------- Simetric - CBC
Vector<uint8_t> Cripter::cbc_encrypt(Vector<uint8_t> p_input, String p_key){
	String error_text;
	int extra_len = 0;
	Vector<uint8_t> ret;
	int input_size = p_input.size();

	mbedtls_aes_context aes_ctx;
	mbedtls_aes_init( &aes_ctx );

	if (input_size % 16) {
		extra_len = (16 - (input_size % 16));
		input_size = input_size + extra_len;
		p_input.resize(input_size);
	}
	uint8_t output[input_size];

	mbedtls_aes_init( &aes_ctx );

	int mbedtls_erro = mbedtls_aes_setkey_enc( &aes_ctx, (unsigned char *)p_key.md5_text().utf8().get_data(), 256 );
	if( mbedtls_erro != OK) {
		error_text = show_error(mbedtls_erro, "mbedtls_aes_setkey_enc");  
	}

	if( mbedtls_erro == OK) { 
		mbedtls_erro = mbedtls_aes_crypt_cbc( &aes_ctx, MBEDTLS_AES_ENCRYPT, input_size,  (unsigned char *)p_key.md5_buffer().ptr(), p_input.ptr(), output );
	}else{ 
		error_text = show_error(mbedtls_erro, "mbedtls_aes_crypt_cbc"); 
	}

	mbedtls_aes_free( &aes_ctx );

	ERR_FAIL_COND_V_MSG(mbedtls_erro, ret, error_text + itos(mbedtls_erro));

	ret.resize(input_size);
	memcpy(ret.ptrw(), output, input_size);
	ret.push_back((uint8_t)extra_len);
	return ret;
}


Vector<uint8_t> Cripter::cbc_decrypt(Vector<uint8_t> p_input, String p_key){
	String error_text;
	Vector<uint8_t> ret;
	
	int input_size = p_input.size();
	int extra_len = (int)p_input[input_size-1];
	p_input.resize(input_size-1);
	
	input_size = p_input.size();
	uint8_t output[input_size];

	mbedtls_aes_init( &aes_ctx );

	int mbedtls_erro = mbedtls_aes_setkey_dec(&aes_ctx, (unsigned char *)p_key.md5_text().utf8().get_data(), 256);
	if( mbedtls_erro != OK) {
		error_text = show_error(mbedtls_erro, "mbedtls_aes_setkey_dec");  
	}

	if( mbedtls_erro == OK) { 
		mbedtls_erro = mbedtls_aes_crypt_cbc( &aes_ctx, MBEDTLS_AES_DECRYPT, input_size,  (unsigned char *)p_key.md5_buffer().ptr(), p_input.ptr(), output);
	}else{ 
		error_text = show_error(mbedtls_erro, "mbedtls_aes_crypt_cbc"); 
	}

	mbedtls_aes_free( &aes_ctx );

	ERR_FAIL_COND_V_MSG(mbedtls_erro, ret, error_text + itos(mbedtls_erro));

	ret.resize(input_size - extra_len);
	memcpy(ret.ptrw(), output, input_size - extra_len);
	return ret;
}


//-------------- Asymmetric - RSA 188 - 239
Vector<uint8_t> Cripter::rsa_encrypt(Vector<uint8_t> p_input, String p_key_path){
	size_t olen = 0;
	String error_text;
	uint8_t output[512];
	Vector<uint8_t> ret;
	const char *pers = "rsa_encrypt";
	const char *key_path = p_key_path.utf8().get_data();

	mbedtls_pk_init( &key_ctx );
	mbedtls_entropy_init( &entropy );
	mbedtls_ctr_drbg_init( &ctr_drbg );
	
	int mbedtls_erro = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers )) ;
	if( mbedtls_erro != OK) {
		error_text = show_error(mbedtls_erro, "mbedtls_ctr_drbg_seed");  
	}
	
	if( mbedtls_erro == OK) { 
		mbedtls_erro = mbedtls_pk_parse_public_keyfile( &key_ctx,  key_path);
	}else{ 
		error_text = show_error(mbedtls_erro, "mbedtls_pk_parse_public_keyfile");  
	}

	if( mbedtls_erro == OK) { 
		mbedtls_erro = mbedtls_pk_encrypt( &key_ctx, p_input.ptr(), p_input.size(), output, &olen, sizeof(output), mbedtls_ctr_drbg_random, &ctr_drbg );
	}else{ 
		error_text = show_error(mbedtls_erro, "mbedtls_pk_encrypt");  
	}

	mbedtls_pk_free( &key_ctx);
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );

	ERR_FAIL_COND_V_MSG(mbedtls_erro, ret, error_text + itos(mbedtls_erro));

	ret.resize(olen);
	memcpy(ret.ptrw(), output, olen);
	return ret;
}


Vector<uint8_t> Cripter::rsa_decrypt(Vector<uint8_t> p_input, String p_key_path, String p_password){

	const char *key_path = p_key_path.utf8().get_data();
	const char *password = p_password.utf8().get_data();

	String error_text;
	uint8_t output[512];
	size_t olen = 0;
	const char *pers = "rsa_decrypt";
	Vector<uint8_t> ret;

	mbedtls_pk_init( &key_ctx );
	mbedtls_entropy_init( &entropy );
	mbedtls_ctr_drbg_init( &ctr_drbg );
	
	int mbedtls_erro = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ));
	if( mbedtls_erro != OK) {
		error_text = show_error(mbedtls_erro, "mbedtls_ctr_drbg_seed" );  
	}
	
	if( mbedtls_erro == OK) { 
		mbedtls_erro = mbedtls_pk_parse_keyfile( &key_ctx, key_path, password );
	}else{ 
		error_text = show_error(mbedtls_erro, "mbedtls_pk_parse_keyfile" );  
	}

	if( mbedtls_erro == OK) { 
		mbedtls_erro = mbedtls_pk_decrypt( &key_ctx, p_input.ptr(), p_input.size(), output, &olen, sizeof(output), mbedtls_ctr_drbg_random, &ctr_drbg );
	}else{ 
		error_text = show_error(mbedtls_erro, "mbedtls_pk_decrypt" );  
	}

	mbedtls_pk_free( &key_ctx);
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
	
	ERR_FAIL_COND_V_MSG(mbedtls_erro, ret, error_text + itos(mbedtls_erro));

//---------------------------------------------------
	ret.resize(olen);
	memcpy(ret.ptrw(), output, olen);
	return ret;
}


int Cripter::check_keys_pair(String p_private_key_path, String p_public_key_path){

	String error_text;
	const char *private_key_path = p_private_key_path.utf8().get_data();
	const char *public_key_path = p_public_key_path.utf8().get_data();

	mbedtls_pk_context private_ctx;
	mbedtls_pk_context public_ctx;
	mbedtls_pk_init( &private_ctx );
	mbedtls_pk_init( &public_ctx );

	int mbedtls_erro = mbedtls_pk_parse_keyfile( &private_ctx, private_key_path, "" );
	if( mbedtls_erro != OK) {
		error_text = show_error(mbedtls_erro, "mbedtls_pk_parse_keyfile" );  
	}
	
	if( mbedtls_erro == OK) { 
		mbedtls_erro = mbedtls_pk_parse_public_keyfile( &public_ctx, public_key_path );
	}else{ 
		error_text = show_error(mbedtls_erro, "mbedtls_pk_parse_public_keyfile" );  
	}

	int ret = mbedtls_pk_check_pair(&public_ctx, &private_ctx);

	mbedtls_pk_free( &private_ctx);
	mbedtls_pk_free( &public_ctx);

	ERR_FAIL_COND_V_MSG(mbedtls_erro, ret, error_text + itos(mbedtls_erro));	

	return ret;
}


String Cripter::show_error(int mbedtls_erro, const char* p_function){
	char mbedtls_erro_text[256];
	mbedtls_strerror( mbedtls_erro, mbedtls_erro_text, sizeof(mbedtls_erro_text) );
	String ret = String::utf8(mbedtls_erro_text) + String::utf8("\n At function: ") + String::utf8(p_function) ;
	print_error(ret);
	return ret;
}


void Cripter::_bind_methods(){
	ClassDB::bind_method(D_METHOD("gcm_encrypt", "Encrypt data", "Password", "Additional Data"),&Cripter::gcm_encrypt);
	ClassDB::bind_method(D_METHOD("gcm_decrypt", "Decrypt data", "Password", "Additional Data"),&Cripter::gcm_decrypt);
	ClassDB::bind_method(D_METHOD("cbc_encrypt", "Encrypt data", "Password"),&Cripter::cbc_encrypt);
	ClassDB::bind_method(D_METHOD("cbc_decrypt", "Decrypt data", "Password"),&Cripter::cbc_decrypt);
	ClassDB::bind_method(D_METHOD("rsa_encrypt", "Encrypt data", "Private key path"),&Cripter::rsa_encrypt);
	ClassDB::bind_method(D_METHOD("rsa_decrypt", "Decrypt data", "Public key path", "Password"),&Cripter::rsa_decrypt, DEFVAL(String()));
	
	ClassDB::bind_method(D_METHOD("check_keys_pair", "Private key path", "Public key path"),&Cripter::check_keys_pair);
}

Cripter::Cripter(){
}
Cripter::~Cripter(){
}

/*cripter.cpp*/
