/*cripter.cpp*/

#include "cripter.h"


#define KEY_SIZE 32
#define IV_SIZE  16
#define TAG_SIZE  4

using namespace std;




//-------------- Simetric - GCM
Vector<uint8_t> Cripter::gcm_encrypt(Vector<uint8_t> input, String key, String p_tag ){

	Vector<uint8_t> ret;
	int input_size = input.size();
	int tag_length = p_tag.length();
	uint8_t buffer[input_size];
	int mbedtls_erro;
	uint8_t ret_tag[TAG_SIZE];
	
	mbedtls_gcm_context gcm_ctx;
	mbedtls_gcm_init(&gcm_ctx);	
	mbedtls_erro = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, (unsigned char *)key.md5_text().utf8().get_data(), 256);

	if( mbedtls_erro != OK) {
		_error_process(mbedtls_erro, "mbedtls_gcm_setkey");
		return ret;
	}

	if (tag_length > 0) {
		mbedtls_erro = mbedtls_gcm_crypt_and_tag(
				&gcm_ctx, MBEDTLS_GCM_ENCRYPT, input_size, 
				key.md5_buffer().ptr(), IV_SIZE, (unsigned char *)p_tag.utf8().get_data(), 
				tag_length, input.ptr(), buffer, TAG_SIZE, ret_tag
			);
				
	}else{
		mbedtls_erro = mbedtls_gcm_crypt_and_tag(
			&gcm_ctx, MBEDTLS_GCM_ENCRYPT, input_size, key.md5_buffer().ptr(), 
			IV_SIZE, NULL, 0, input.ptr(), buffer, TAG_SIZE, ret_tag
		);
	}

	mbedtls_gcm_free( &gcm_ctx );

	if( mbedtls_erro != OK) {
		_error_process(mbedtls_erro, "mbedtls_gcm_crypt_and_tag");
	}

	else{
		ret.resize(input_size);
		memcpy(ret.ptrw(), buffer, input_size);
		Vector<uint8_t> tag; 
		tag.resize(TAG_SIZE);
		memcpy(tag.ptrw(), ret_tag, TAG_SIZE);
		ret.append_array(tag);
	}


	return ret;

}



Vector<uint8_t> Cripter::gcm_decrypt(Vector<uint8_t> p_input, String p_key, String p_add ){






}




void Cripter::_error_process(int mbedtls_erro, const char* p_function){
	char mbedtls_erro_text;
	mbedtls_strerror(mbedtls_erro, &mbedtls_erro_text, sizeof(&mbedtls_erro_text));
	last_error.clear();
	last_error["DESCRIPTION"] = String::utf8((const char*)&mbedtls_erro_text);
	last_error["FUNCTION"] = String::utf8(p_function);
	last_error["ERROR"] = mbedtls_erro;	

#ifdef DEBUG
	print_error(last_error);
	ERR_PRINT(last_error);
#endif

}


void Cripter::_bind_methods(){
	ClassDB::bind_method(D_METHOD("gcm_encrypt", "Encrypt data", "Password", "Optional Tag"),&Cripter::gcm_encrypt, DEFVAL(String()));
	ClassDB::bind_method(D_METHOD("gcm_decrypt", "Decrypt data", "Password", "Optional Tag"),&Cripter::gcm_decrypt, DEFVAL(String()));



}



Cripter::Cripter(){
}
Cripter::~Cripter(){
}

/*cripter.cpp*/
