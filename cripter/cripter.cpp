/*cripter.cpp*/

#include "cripter.h"

//#include "core/variant.h"
//#include "reference.h"

//#include "thirdparty/mbedtls/include/mbedtls/gcm.h"
//#include "thirdparty/mbedtls/include/mbedtls/aes.h"

//#include <cstdio>
//#include <iostream>

#define KEY_SIZE   32
#define EXT_SIZE   16

//Testar os dados do add_data e Tag

PoolByteArray cripter::encrypt_var_aes_CBC(const Variant p_input, const String p_key) const {

	return encrypt_byte_aes_CBC((encode_var(p_input)), p_key);	
}

Array cripter::encrypt_var_aes_GCM(const Variant p_input, const String p_key, const String p_add) const {

	return encrypt_byte_aes_GCM((encode_var(p_input)), p_key, p_add);
}

Variant cripter::decrypt_var_aes_CBC(const PoolByteArray p_input, const String p_key) const{

	return decode_var((decrypt_byte_aes_CBC(p_input, p_key)));
}

Variant cripter::decrypt_var_aes_GCM(const PoolByteArray p_input, const String p_key, const PoolByteArray p_tag, const String p_add) const {

	return decode_var(decrypt_byte_aes_GCM(p_input, p_key, p_tag, p_add));
}

//-------

Array cripter::encrypt_byte_aes_GCM(const PoolByteArray p_input, const String p_key, const String p_add) const {

    //Prepare key & iv **
	String h_key = p_key.md5_text();
	uint8_t key[KEY_SIZE];
	uint8_t iv[EXT_SIZE];
	for (int i = 0; i < KEY_SIZE; i++) {
		key[i] = h_key[i];
	}
	for (int i = 0; i < EXT_SIZE; i++){
		iv[i] = key[i*2];	
	}

	//Preparing Buffer
	Array ret;
	uint8_t input[int (p_input.size())];
	uint8_t output[ sizeof(input)];

	PoolVector<uint8_t>::Read r = p_input.read();   //PoolByteArray to CharArray
	for (int i = 0; i < p_input.size(); i++) {
		input[i] = p_input[i];
	}

	//Prepare Tag
    uint8_t tag[EXT_SIZE];
    
    
	//Prepare Addicional Data
	int add_len = p_add.length();
	uint8_t add[add_len];
	for (int i = 0; i < add_len; i++) {
		add[i] = p_add[i];
	}
	
	//Encryptation
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);

	if (add_len == 0){
		int err = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, sizeof(input), iv, EXT_SIZE, NULL, 0, input, output, EXT_SIZE, tag);
		if (err != 0){
			//printf("Erro: %i", err);
			//Do something about errors
			return ret;
		}

	}else{
		int err = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, sizeof(input), iv, EXT_SIZE, add, add_len, input, output, EXT_SIZE, tag);
		if (err != 0){
			//printf(" Erro: %i", err);
			//Do something about errors
			return ret;
		}
	}
		
    mbedtls_gcm_free( &ctx );
       
    PoolByteArray ret_output = char2pool(output, sizeof(output));
   	PoolByteArray ret_tag = char2pool(tag, sizeof(tag));
   	
   	ret.push_back(ret_output);
   	ret.push_back(ret_tag);
   	
   	return ret;

}


PoolByteArray cripter::decrypt_byte_aes_GCM(const PoolByteArray p_input, const String p_key, const PoolByteArray p_tag, const String p_add) const{
	
	//Prepare key & iv **
	String h_key = p_key.md5_text();
	uint8_t key[KEY_SIZE];
	uint8_t iv[EXT_SIZE];
	for (int i = 0; i < KEY_SIZE; i++) {
		key[i] = h_key[i];
	}
	for (int i = 0; i < EXT_SIZE; i++){
		iv[i] = key[i*2];	
	}
	
	//Preparing Buffer
	PoolByteArray ret_output;
	uint8_t input[int (p_input.size())];
	uint8_t output[int (sizeof(input))];
	PoolVector<uint8_t>::Read r = p_input.read();   
	for (int i = 0; i < p_input.size(); i++) {
		input[i] = p_input[i];
	}
				
	//Preparing Tag
	uint8_t tag[EXT_SIZE];
	PoolVector<uint8_t>::Read R = p_tag.read();   
	for (int i = 0; i < p_tag.size(); i++) {
		tag[i] = (uint8_t)p_tag[i];
	}
		
	//Prepare Addicional Data
	int add_len = p_add.length();
	uint8_t add[add_len];
	for (int i = 0; i < add_len; i++) {
		add[i] = p_add[i];
	}
			
	//Decryptation
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
     	
	if (add_len == 0){
		int err =  mbedtls_gcm_auth_decrypt(&ctx, sizeof(input), iv, EXT_SIZE, NULL, 0, tag, EXT_SIZE, input, output);
		if (err != 0){
			//printf("Erro: %i", err);
			//Do something about errors
			return ret_output;
		}

	}else{
		int err = mbedtls_gcm_auth_decrypt(&ctx, sizeof(input), iv, EXT_SIZE, add, add_len, tag, EXT_SIZE, input, output);
		if (err != 0){
			//Do something about errors
			//printf("Erro: %i", err);
			return ret_output;	
		}
	}
	    						
	mbedtls_gcm_free( &ctx );
	return char2pool(output, sizeof(output));
	
}
    
PoolByteArray cripter::encrypt_byte_aes_CBC(const PoolByteArray p_input, const String p_key) const{
	
	//Prepare key & iv **
	String h_key = p_key.md5_text();
	uint8_t key[KEY_SIZE];
	uint8_t iv[EXT_SIZE];
	for (int i = 0; i < KEY_SIZE; i++) {
		key[i] = h_key[i];
	}
	for (int i = 0; i < EXT_SIZE; i++){
		iv[i] = key[i*2];	
	}
	
	//Preparing buffer **
	int data_len = p_input.size();
	int extra_len;
	int total_len;

	if (data_len % 16) { 
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
	for (int l = data_len; l < total_len; l++){  //fill with zeros couse the input must be multiple of 16
		input[l] = 0;
	}

	//Encryptation **
	mbedtls_aes_context ctx;
	mbedtls_aes_init( &ctx );
	mbedtls_aes_setkey_enc( &ctx, key, 256 );
	mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_ENCRYPT, total_len, iv, input, output );
	mbedtls_aes_free( &ctx );


	//Fit data **
	PoolByteArray ret = char2pool(output, (sizeof(output)));
	ret.push_back(extra_len);
	return ret;

} 
    
PoolByteArray cripter::decrypt_byte_aes_CBC(const PoolByteArray p_input, const String p_key) const {

	//Prepare key & iv **
	String h_key = p_key.md5_text();
	uint8_t key[KEY_SIZE];
	uint8_t iv[EXT_SIZE];
	for (int i = 0; i < KEY_SIZE; i++) {
		key[i] = h_key[i];
	}
	for (int i = 0; i < EXT_SIZE; i++){
		iv[i] = key[i*2];	
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
	return char2pool(output, (sizeof(output) - zeros)); //No more extra zeros here
}


PoolByteArray cripter::char2pool(const uint8_t *p_in, size_t p_size)const {

    PoolByteArray data;
	data.resize(p_size);
	PoolVector<uint8_t>::Write w = data.write();
	for (int i = 0; i < p_size; i++) {
		w[i] = p_in[i];
	}
	w = PoolVector<uint8_t>::Write();
	return data;
}


PoolByteArray cripter::encode_var(const Variant data) const {
	//Encoder	
	PoolByteArray ret;
	int len;
	Error err = encode_variant(data, NULL, len);
	if (err != OK) {
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


Variant cripter::decode_var(const PoolByteArray p_data) const {
	//Decoder
	Variant ret;
	PoolByteArray data = p_data;
	PoolByteArray::Read r = data.read();	
	Error err = decode_variant(ret, r.ptr(), data.size(), NULL);	
	
	if (err != OK) {
		print_line("Unexpected error decoding bytes to variable");
		Variant f;
		return f;	
	}
	return ret;
}

void cripter::_bind_methods(){

	//CBC
	ClassDB::bind_method(D_METHOD("encrypt_byte_aes_CBC", "Data to encrypt", "key"),&cripter::encrypt_byte_aes_CBC);
	ClassDB::bind_method(D_METHOD("decrypt_byte_aes_CBC", "Data to decrypt", "key"),&cripter::decrypt_byte_aes_CBC);
	
	ClassDB::bind_method(D_METHOD("encrypt_var_aes_CBC", "Data to encrypt", "key"),&cripter::encrypt_var_aes_CBC);
	ClassDB::bind_method(D_METHOD("decrypt_var_aes_CBC", "Data to decrypt", "key"),&cripter::decrypt_var_aes_CBC);
	
	
	//GCM
	ClassDB::bind_method(D_METHOD("encrypt_byte_aes_GCM", "Data to encrypt", "key", "Additional Data"),&cripter::encrypt_byte_aes_GCM);
	ClassDB::bind_method(D_METHOD("decrypt_byte_aes_GCM", "Data to decrypt", "key", "Tag", "Additional Data"),&cripter::decrypt_byte_aes_GCM);
	
	ClassDB::bind_method(D_METHOD("encrypt_var_aes_GCM", "Data to encrypt", "key"),&cripter::encrypt_var_aes_GCM);
	ClassDB::bind_method(D_METHOD("decrypt_var_aes_GCM", "Data to decrypt", "key", "Tag", "Additional Data"),&cripter::decrypt_var_aes_GCM);
	
}

cripter::cripter(){
	
}

