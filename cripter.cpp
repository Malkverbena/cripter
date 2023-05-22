/*cripter.cpp*/

#include "cripter.h"



#define IV_SIZE  16
#define TAG_SIZE  8

#define ROUND_SIZE  4



using namespace std;




Vector<uint8_t> Cripter::aes_encrypt(Vector<uint8_t> input, String p_password){

	int extra_len = 0;
	Vector<uint8_t> ret;
	int input_size = input.size();

	if (input_size % 16) {
		extra_len = (16 - (input_size % 16));
		input_size = input_size + extra_len;
		input.resize(input_size);
	}
	uint8_t output[input_size];

	mbedtls_aes_context aes_ctx;
	mbedtls_aes_init( &aes_ctx );
	int mbedtls_erro;

	mbedtls_erro = mbedtls_aes_setkey_enc( &aes_ctx, (unsigned char *)p_password.md5_text().utf8().get_data(), 256 );
	ERR_FAIL_COND_V_EDMSG(mbedtls_erro != OK, ret, " failed\n  ! mbedtls_aes_setkey_enc returned the error: " + itos(mbedtls_erro) + String::utf8((const char*)&mbedtls_erro) );

	mbedtls_erro = mbedtls_aes_crypt_cbc( &aes_ctx, MBEDTLS_AES_ENCRYPT, input_size,  (unsigned char *)p_password.md5_buffer().ptr(), input.ptr(), output );
	ERR_FAIL_COND_V_EDMSG(mbedtls_erro != OK, ret, " failed\n  ! mbedtls_aes_crypt_cbc returned the error: " + itos(mbedtls_erro) + String::utf8((const char*)&mbedtls_erro) );

	mbedtls_aes_free( &aes_ctx );

	ret.resize(input_size);
	memcpy(ret.ptrw(), output, input_size);
	ret.push_back((uint8_t)extra_len);

	return ret;

}

Vector<uint8_t> Cripter::aes_decrypt(Vector<uint8_t> input, String p_password){

	Vector<uint8_t> ret;
	int input_size = input.size();
	int extra_len = (int)input[input_size-1];
	input.resize(input_size-1);
	input_size = input.size();
	uint8_t output[input_size];

	mbedtls_aes_context aes_ctx;
	mbedtls_aes_init( &aes_ctx );

	int mbedtls_erro;
	
	mbedtls_erro = mbedtls_aes_setkey_dec(&aes_ctx, (unsigned char *)p_password.md5_text().utf8().get_data(), 256);
	ERR_FAIL_COND_V_EDMSG(mbedtls_erro != OK, ret, " failed\n  ! mbedtls_aes_setkey_dec returned the error: " + itos(mbedtls_erro) + String::utf8((const char*)&mbedtls_erro) );






	mbedtls_erro = mbedtls_aes_crypt_cbc( &aes_ctx, MBEDTLS_AES_DECRYPT, input_size,  (unsigned char *)p_password.md5_buffer().ptr(), input.ptr(), output);
	ERR_FAIL_COND_V_EDMSG(mbedtls_erro != OK, ret, " failed\n  ! mbedtls_aes_crypt_cbc returned the error: " + itos(mbedtls_erro) + String::utf8((const char*)&mbedtls_erro) );






	mbedtls_aes_free( &aes_ctx );

	ret.resize(input_size - extra_len);
	memcpy(ret.ptrw(), output, input_size - extra_len);

	return ret;

}




Vector<uint8_t> Cripter::gcm_encrypt(Vector<uint8_t> p_input, String p_password, String p_additional_data, int p_rounds){
	/*
	if (p_rounds < 4){
		p_rounds = 4;
	}
	if (p_rounds > 128){
		p_rounds = 128;
	}
	*/
	return _gcm_crypt(p_input, p_password, p_additional_data, GCM_ENCRYPT, p_rounds);
}

Vector<uint8_t> Cripter::gcm_decrypt(Vector<uint8_t> p_input, String p_password, String p_additional_data){
	return _gcm_crypt(p_input, p_password, p_additional_data, GCM_DECRYPT, 0);
}


Vector<uint8_t> Cripter::_gcm_crypt(Vector<uint8_t> p_input, String p_password, String p_additional_data, GCMMode mode, int p_rounds){

	// Input
	int input_size = p_input.size();
	const unsigned char *input = p_input.ptr();
	
	// Output
	unsigned char  output_buf;
	Vector<uint8_t> output;

	// IV
	const unsigned char * iv = p_password.md5_buffer().ptr();

	// Tag
	uint8_t tag[TAG_SIZE];

	uint8_t rounds = p_rounds * 4;

	// IF MBEDTLS_GCM_DECRYPT
	if (mode == MBEDTLS_GCM_DECRYPT){
		rounds = (uint8_t)p_input[0] * 4;
		input = (p_input.slice(1, -TAG_SIZE)).ptr();
		for (int i = 0; i < TAG_SIZE; i++) {
			tag[i] = (uint8_t)p_input[ (input_size - TAG_SIZE) + i];
		}
	}
	
	// Password
	String random_pass = p_password; 
	for (int i = 0; i < rounds; i++) {
		random_pass = random_pass.md5_text();
	}
	unsigned char * password = (unsigned char *)random_pass.utf8().get_data();

	// Additional data
	unsigned char * add = NULL;
	size_t add_length = p_additional_data.length();
	if (add_length > 0) {
		add = (unsigned char *)p_additional_data.utf8().get_data();
	}

	int mbedtls_erro;
	mbedtls_gcm_context gcm_ctx;
	mbedtls_gcm_init(&gcm_ctx);

	mbedtls_erro = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, password, 256);
	ERR_FAIL_COND_V_EDMSG(mbedtls_erro != OK, output, " failed\n  ! mbedtls_gcm_setkey returned the error: " + itos(mbedtls_erro) + String::utf8((const char*)&mbedtls_erro) );

	mbedtls_erro = mbedtls_gcm_crypt_and_tag(&gcm_ctx, mode, input_size, iv, IV_SIZE, add, add_length, input, &output_buf, TAG_SIZE, tag);
	ERR_FAIL_COND_V_EDMSG(mbedtls_erro != OK, output, " failed\n  ! mbedtls_gcm_crypt_and_tag returned the error: " + itos(mbedtls_erro) + String::utf8((const char*)&mbedtls_erro) );

	mbedtls_gcm_free(&gcm_ctx);


	// Output
	output.resize(input_size);
	memcpy(output.ptrw(), &output_buf, input_size);

	if (mode == MBEDTLS_GCM_ENCRYPT){
		// Tag
		Vector<uint8_t> tag_output; 
		tag_output.resize(TAG_SIZE);
		memcpy(tag_output.ptrw(), tag, TAG_SIZE);

		// Contruct
		Vector<uint8_t> ret;
		ret.push_back((uint8_t)rounds);
		ret.append_array(output);
		ret.append_array(tag_output);
		return ret;
	}

	return output;

}






void Cripter::_bind_methods() {

	ClassDB::bind_method(D_METHOD("gcm_encrypt", "Encrypt data", "Password", "Additional Data"),&Cripter::gcm_encrypt, DEFVAL(String()), DEFVAL(32) );
	ClassDB::bind_method(D_METHOD("gcm_decrypt", "Decrypt data", "Password", "Additional Data"),&Cripter::gcm_decrypt, DEFVAL(String()) );

	ClassDB::bind_method(D_METHOD("aes_encrypt", "Encrypt data", "Password", "Algorithm"),&Cripter::aes_encrypt);
	ClassDB::bind_method(D_METHOD("aes_decrypt", "Decrypt data", "Password", "Algorithm"),&Cripter::aes_decrypt);


	





}



Cripter::Cripter(){
}
Cripter::~Cripter(){
}

/*cripter.cpp*/
