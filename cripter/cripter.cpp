/*cripter.cpp*/

#include "cripter.h"

#include "core/variant.h"
#include "reference.h"
#include "core/print_string.h"

#include "thirdparty/mbedtls/include/mbedtls/gcm.h"
#include "thirdparty/mbedtls/include/mbedtls/aes.h"

#include "thirdparty/mbedtls/include/mbedtls/cipher.h"
#include <stdint.h>



Array cripter::encrypt_byte_aes_gcm(const PoolByteArray p_input, const String p_key, const String p_add) const {

	//Prepare key & iv **
	String h_key = p_key.md5_text();
	uint8_t key[32];
	uint8_t iv[16];
	for (int i = 0; i < 32; i++) {
		key[i] = h_key[i];
		if (i % 2 == 0){
			iv[i] = key[i];	
		}
	}
	
	//Preparing buffer ** Input
	int data_len = p_input.size();
	int extra_len;
	int total_len;

	if (data_len % 16 != 0) { 
		extra_len = (16 - (data_len % 16));    
		total_len = data_len + extra_len ;   
	} else { 
		total_len = data_len;
		extra_len = 0; 
	}
	uint8_t input[total_len];
	uint8_t output[total_len];	
		
	for (int g = 0; g < data_len; g++){   
		input[g] = p_input[g];
	}
	for (int l = data_len; l < total_len; l++){  //fill with zeros   
		input[l] = 0;
	}

	// Additional data
	int add_len = p_add.size();
	uint8_t add[add_len];
		
	for (int g = 0; g < add_len; g++){   
		add[g] = p_add[g];
	}

	// Tag
	uint8_t tag[16];
	
	
	
	
	//Encryptation **
	//mbedtls_gcm_self_test << Add to error verifications
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init( &ctx );
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES , key, 256);
	mbedtls_gcm_crypt_and_tag( &ctx, MBEDTLS_GCM_ENCRYPT, data_len, iv, 16, add, add_len, input,  output, 16, tag);
	mbedtls_gcm_free( &ctx );
	
	//Fit data ** 
		
	//Output
	PoolByteArray out_ret;
	for (int i = 0; i < sizeof(output); i++){
		out_ret.push_back(output[i]);
	}
	out_ret.push_back(extra_len);
	
	//Tag
	PoolByteArray out_tag;
	for (int i = 0; i < sizeof(tag); i++){
		out_tag.push_back(tag[i]);
	}
	out_tag.push_back( (int)sizeof(tag) );
	
	//Array with Output and Tag
	Array ret;
	ret.push_back(out_ret);
	ret.push_back(out_tag);
	return ret;
	


}


PoolByteArray cripter::decrypt_byte_aes_cbc(const PoolByteArray p_input, const String p_key) const {

	//Prepare key & iv **
	String h_key = p_key.md5_text();
	uint8_t key[32];
	uint8_t iv[16];
	for (int i = 0; i < 32; i++) {
		key[i] = h_key[i];
		if (i % 2 == 0){
			iv[i] = key[i];	
		}
	}

	//Preparing buffer **
	int data_len = p_input.size() - 1;
	int zeros = p_input[data_len];
	uint8_t input[data_len];	
	uint8_t output[data_len];
			
	for (int g = 0; g < data_len; g++){   
		input[g] = p_input[g];
	}
	
	//Decryptation **
	mbedtls_aes_context ctx;
	mbedtls_aes_init( &ctx );
	mbedtls_aes_setkey_dec(&ctx, key, 256);
	mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_DECRYPT, data_len, iv, input, output);
	mbedtls_aes_free( &ctx );

	//Fit data **
	PoolByteArray retu;
	for (int i = 0; i < (sizeof(output) - zeros); i++){    //No more extra zeros here
		retu.push_back(output[i]);
	}

	return retu;
}	


PoolByteArray cripter::encrypt_byte_aes_cbc(const PoolByteArray p_input, const String p_key) const {

	//Prepare key & iv **
	String h_key = p_key.md5_text();
	uint8_t key[32];
	uint8_t iv[16];
	for (int i = 0; i < 32; i++) {
		key[i] = h_key[i];
		if (i % 2 == 0){
			iv[i] = key[i];	
		}
	}

	//Preparing buffer **
	//About sizes
	int data_len = p_input.size();
	int extra_len;
	int total_len;

	if (data_len % 16 != 0) { 
		extra_len = (16 - (data_len % 16));    
		total_len = data_len + extra_len ;   
	} else { 
		total_len = data_len;
		extra_len = 0; 
	}
	

	uint8_t input[total_len];
	uint8_t output[sizeof(input)];
	for (int g = 0; g < data_len; g++){   
		input[g] = p_input[g];
	}
	for (int l = data_len; l < total_len; l++){  //fill with zeros   
		input[l] = 0;
	}

	
	//Encryptation **
	mbedtls_aes_context ctx;
	mbedtls_aes_init( &ctx );
	mbedtls_aes_setkey_enc( &ctx, key, 256 );
	mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_ENCRYPT, total_len, iv, input, output );
	mbedtls_aes_free( &ctx );


	//Fit data **
	PoolByteArray ret;
	for (int i = 0; i < sizeof(output); i++){
		ret.push_back(output[i]);
	}
	ret.push_back(extra_len);
	return ret;
	
}


void cripter::_bind_methods(){

	//CBC
	ClassDB::bind_method(D_METHOD("encrypt_byte_aes_cbc", "ByteArray", "key"),&cripter::encrypt_byte_aes_cbc);
	ClassDB::bind_method(D_METHOD("decrypt_byte_aes_cbc", "ByteArray", "key"),&cripter::decrypt_byte_aes_cbc);
	
	//GCM
	ClassDB::bind_method(D_METHOD("encrypt_byte_aes_gcm", "ByteArray", "key", "Additional Data"),&cripter::encrypt_byte_aes_gcm);
	//ClassDB::bind_method(D_METHOD("decrypt_byte_aes_gcm", "ByteArray", "key"),&cripter::decrypt_byte_aes_gcm);
	
}


cripter::cripter(){
	
}

