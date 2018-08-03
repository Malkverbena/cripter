/*cripter.cpp*/

#include "cripter.h"

#include "core/variant.h"
#include "reference.h"

#include "thirdparty/mbedtls/include/mbedtls/gcm.h"
#include "thirdparty/mbedtls/include/mbedtls/aes.h"


void cripter::_bind_methods()
{
	ClassDB::bind_method(D_METHOD("encrypt_byte_aes_cbc", "PoolByteArray", "key"),&cripter::encrypt_byte_aes_cbc);
	ClassDB::bind_method(D_METHOD("decrypt_byte_aes_cbc", "PoolByteArray", "key"),&cripter::decrypt_byte_aes_cbc);

	//ClassDB::bind_method(D_METHOD("encrypt_var_aes_cbc", "Var", "key"),&cripter::encrypt_var_aes_cbc);
	//ClassDB::bind_method(D_METHOD("decrypt_var_aes_cbc", "PoolByteArray", "key"),&cripter::decrypt_var_aes_cbc);
}

cripter::cripter() {
}


PoolByteArray cripter::decrypt_byte_aes_cbc(PoolByteArray p_mati, String p_key)
{
	//Prepare key & iv
	String h_key = p_key.md5_text();
	uint8_t input_key[32];
	uint8_t iv[16];
	for (int i = 0; i < 32; i++) {
		input_key[i] = h_key[i];
		if (i % 2 == 0){
			iv[i] = input_key[i];	
		}
	}

	//Preparing buffer 
	int data_size = p_mati.size() - 1;
	int zero_size = p_mati[data_size];
	uint8_t arr_buf[data_size];	
		
	for (int g = 0; g < data_size; g++){   
		arr_buf[g] = p_mati[g];
	}
	
	//Decryptation
	uint8_t output_buff[data_size];
	
	mbedtls_aes_context ctx;
	mbedtls_aes_init( &ctx );
	mbedtls_aes_setkey_dec(&ctx, input_key, 256);
	mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_DECRYPT, data_size, iv, arr_buf, output_buff);
	mbedtls_aes_free( &ctx );

	//Fit data	
	PoolByteArray retu;
	for (int i = 0; i < (sizeof(output_buff) - zero_size); i++){    //No more extra zeros here
		retu.push_back(output_buff[i]);
	}

	return retu;
}	



PoolByteArray cripter::encrypt_byte_aes_cbc( PoolByteArray p_pool,  String p_key) {

	//Prepare key & iv
	String h_key = p_key.md5_text();
	uint8_t input_key[32];
	uint8_t iv[16];
	for (int i = 0; i < 32; i++) {
		input_key[i] = h_key[i];
		if (i % 2 == 0){
			iv[i] = input_key[i];	
		}
	}

	//About sizes
	int data_size = p_pool.size();
	int extra_size;
	int total_size;

	if (data_size % 16 != 0) { 
		extra_size = (16 - (data_size % 16));    
		total_size = data_size + extra_size ;   
	} else { 
		total_size = data_size;
		extra_size = 0; 
	}
	
	//Preparing buffer 
	uint8_t in_buffer[total_size];

	for (int g = 0; g < data_size; g++){   
		in_buffer[g] = p_pool[g];
	}

	for (int l = data_size; l < total_size; l++){  //fill with zeros   
		in_buffer[l] = 0;
	}
		
	//Encryptation
	uint8_t OutputMessage[sizeof(in_buffer)];
		
	mbedtls_aes_context ctx;
	mbedtls_aes_init( &ctx );
	mbedtls_aes_setkey_enc( &ctx, input_key, 256 );
	mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_ENCRYPT, total_size, iv, in_buffer, OutputMessage );
	mbedtls_aes_free( &ctx );

	//Fit data	
	PoolByteArray back_out;
	for (int i = 0; i < sizeof(OutputMessage); i++){
		back_out.push_back(OutputMessage[i]);
	}
	
	back_out.push_back(extra_size);
	return back_out;
	
}



