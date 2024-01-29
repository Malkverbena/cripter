/*cripter.cpp*/

#include "cripter.h"


#define IV_SIZE  16
#define TAG_SIZE  8
#define EXPONENT 65537


// -------------GCM

Vector<uint8_t> Cripter::gcm_encrypt(Vector<uint8_t> p_input, String p_password, String p_add, KeySize p_keybits){

	if (p_keybits < BITS_128){
		WARN_PRINT("GCM Algorithm only accepts key with 128, 192, or 256 bits");
		p_keybits = BITS_128;
	}
	if (p_keybits > BITS_256){
		WARN_PRINT("GCM Algorithm only accepts key with 128, 192, or 256 bits");
		p_keybits = BITS_256;
	}

	// Input
	int input_size = p_input.size();

	// Output
	uint8_t p_tag[TAG_SIZE];
	uint8_t output_buf[input_size];
	Vector<uint8_t> output;

	// Init Context
	int mbedtls_erro;
	mbedtls_gcm_context gcm_ctx;
	mbedtls_gcm_init(&gcm_ctx);

	// Additional data
	int add_len = 0;
	unsigned char * add_data = NULL;
	if (p_add.is_empty()) {
		add_data = (unsigned char *)p_add.utf8().get_data();
		add_len = p_add.length();
	}

	// Password
	String random_pass = p_password;
	for (int i = 0; i < 256; i++) {
		random_pass = random_pass.md5_text();
	}
	unsigned char * password = (unsigned char *)random_pass.utf8().get_data();

	// Gears running
	mbedtls_erro = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, password, p_keybits);
	if (mbedtls_erro != OK){
		mbedtls_gcm_free(&gcm_ctx);
		ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_gcm_setkey"));
	}

	mbedtls_erro = mbedtls_gcm_crypt_and_tag(&gcm_ctx, MBEDTLS_GCM_ENCRYPT, input_size, p_password.md5_buffer().ptr(), IV_SIZE, add_data, add_len, p_input.ptr(), output_buf, TAG_SIZE, p_tag);
	if (mbedtls_erro != OK){
		mbedtls_gcm_free(&gcm_ctx);
		ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_gcm_crypt_and_tag"));
	}

	mbedtls_gcm_free(&gcm_ctx);

	// Building output
	output.resize(input_size);
	memcpy(output.ptrw(), output_buf, input_size);
	Vector<uint8_t> tag;
	tag.resize(TAG_SIZE);
	memcpy(tag.ptrw(), p_tag, TAG_SIZE);
	output.append_array(tag);

	return output;

}


Vector<uint8_t> Cripter::gcm_decrypt(Vector<uint8_t> p_input, String p_password, String p_add, KeySize p_keybits){

	if (p_keybits < BITS_128){
		WARN_PRINT("GCM Algorithm only accepts key with 128, 192, or 256 bits");
		p_keybits = BITS_128;
	}
	if (p_keybits > BITS_256){
		WARN_PRINT("GCM Algorithm only accepts key with 128, 192, or 256 bits");
		p_keybits = BITS_256;
	}

	// Output
	int input_size = p_input.size();
	Vector<uint8_t> output;
	uint8_t output_buf[ input_size - TAG_SIZE ];

	// Input
#ifdef GD4
	Vector<uint8_t> data = (p_input.slice(0, -TAG_SIZE ));
	Vector<uint8_t> tag = (p_input.slice( (input_size - TAG_SIZE), p_input.size() ));
#else
	uint8_t p_tag[TAG_SIZE];
	Vector<uint8_t> R = p_input;
	for (int i = 0; i < TAG_SIZE; i++) {
		p_tag[i] = (uint8_t)p_input[ (input_size - TAG_SIZE) + i];
	}
	Vector<uint8_t> tag;
	tag.resize(TAG_SIZE);
	memcpy(tag.ptrw(), _tag, TAG_SIZE);

	uint8_t input[(input_size - TAG_SIZE)];
	Vector<uint8_t> r = p_input;
	for (int i = 0; i < (input_size - TAG_SIZE); i++) {
		input[i] = (uint8_t)p_input[i];
	}
	Vector<uint8_t> data;
	data.resize(input_size - TAG_SIZE);
	memcpy(data.ptrw(), input, input_size - TAG_SIZE);
#endif

	// Init Context
	int mbedtls_erro;
	mbedtls_gcm_context gcm_ctx;
	mbedtls_gcm_init(&gcm_ctx);

	// Additional data
	int add_len = 0;
	unsigned char * add_data = NULL;
	if (p_add.is_empty()) {
		add_data = (unsigned char *)p_add.utf8().get_data();
		add_len = p_add.length();
	}

	// Password
	String random_pass = p_password;
	for (int i = 0; i < 256; i++) {
		random_pass = random_pass.md5_text();
	};
	unsigned char * password = (unsigned char *)random_pass.utf8().get_data();

	// Gears running
	mbedtls_erro = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, password, p_keybits);
	if (mbedtls_erro != OK){
		mbedtls_gcm_free(&gcm_ctx);
		ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_gcm_setkey"));
	};

	mbedtls_erro = mbedtls_gcm_auth_decrypt(&gcm_ctx, data.size(), p_password.md5_buffer().ptr(), IV_SIZE, add_data, add_len, tag.ptr(), TAG_SIZE, data.ptr(), output_buf);
	if (mbedtls_erro != OK){
		mbedtls_gcm_free(&gcm_ctx);
		ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_gcm_auth_decrypt"));
	};

	mbedtls_gcm_free(&gcm_ctx);

	// Building output
	output.resize(input_size - TAG_SIZE);
	memcpy(output.ptrw(), output_buf, input_size);
	return output;

}



// -------------AES

Vector<uint8_t> Cripter::aes_encrypt(Vector<uint8_t> p_input, String p_password, Algorithm p_algorith, KeySize p_keybits){

	if ((p_algorith != XTS) and (p_keybits < BITS_128)){
		WARN_PRINT("Most AES algorithms support 128,192 and 256 bits keys, with the exception of XTS, which only supports 256 and 512 bits keys. - Using 128 Bits key size");
		p_keybits = BITS_128;
	}
	else if (p_algorith != XTS and p_keybits > BITS_256){
		WARN_PRINT("Most AES algorithms support 128,192 and 256 bits keys, with the exception of XTS, which only supports 256 and 512 bits keys. - Using 256 Bits key size");
		p_keybits = BITS_256;
	}
	else if (p_algorith == XTS and p_keybits < BITS_256){
		WARN_PRINT("XTS algorithm support only supports 256 and 512 bits keys. - Using 256 Bits key size");
		p_keybits = BITS_256;
	}
	else if (p_algorith == XTS and p_keybits > BITS_512){
		WARN_PRINT("XTS algorithm support only supports 256 and 512 bits keys. - Using 512 Bits key size");
		p_keybits = BITS_512;
	}

	// Input
	int input_size = p_input.size();

	// Output
	unsigned char output_buf[input_size];
	Vector<uint8_t> output;

	// IV
	size_t iv_offset = 1;
	unsigned char *iv = (unsigned char *)p_password.md5_buffer().ptr();

	// Password
	String random_pass = p_password;
	for (int i = 0; i < 256; i++) {
		random_pass = random_pass.md5_text();
	};
	const unsigned char * password = (unsigned char *)random_pass.utf8().get_data();

	// Init Context
	int mbedtls_erro;
	mbedtls_aes_context aes_ctx;
	mbedtls_aes_init(&aes_ctx);

	mbedtls_erro = mbedtls_aes_setkey_enc( &aes_ctx, password, (unsigned int)p_keybits );
	if (mbedtls_erro != OK){
		mbedtls_aes_free(&aes_ctx);
		ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_setkey_enc"));
	};

	switch (p_algorith) {

		case EBC: {
			mbedtls_erro = mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, p_input.ptr(), (unsigned char * )&output_buf);
			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_ecb"));
			}
		}
		break;

		case CBC: {
			// Extra len >> CBC operates on full blocks. The input size must be a multiple of 16 Bytes. It feels the input and with zeros untill the input size be a multiple of 16.
			int extra_len = 0;
			if (input_size % 16) {
				extra_len = (16 - (input_size % 16));
				input_size = input_size + extra_len;
				p_input.resize(input_size);
			}
			mbedtls_erro = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, input_size, iv, p_input.ptr(), (unsigned char * )&output_buf);
			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_cbc"));
			}
			output.resize(input_size);
			memcpy(output.ptrw(), &output_buf, input_size);
			output.append((uint8_t)extra_len);
			return output;
		}
		break;

		case OFB: {
			// For the OFB mode, the initialisation vector must be unique every encryption operation. Reuse of an initialisation vector will compromise security.
			// The password shold not be the same in each encryption operation coz the vector is made using with the password.
			unsigned char iv2[16] = { 0 };
			mbedtls_erro = mbedtls_aes_crypt_ofb(&aes_ctx, input_size, &iv_offset, iv2, (unsigned char *)p_input.ptr(), (unsigned char *)&output_buf);
			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_ofb"));
			}
		}
		break;

		case CFB128: {
			mbedtls_erro = mbedtls_aes_crypt_cfb128(&aes_ctx, MBEDTLS_AES_ENCRYPT, input_size, &iv_offset, iv, p_input.ptr(), (unsigned char * )&output_buf);
			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_cfb128"));
			}
		}
		break;

		case CFB8: {
			mbedtls_erro = mbedtls_aes_crypt_cfb8(&aes_ctx, MBEDTLS_AES_ENCRYPT, input_size, iv, p_input.ptr(), (unsigned char * )&output_buf);
			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_cfb8"));
			}
		}
		break;

		case XTS: {
			mbedtls_aes_xts_context xts_ctx;
			mbedtls_aes_xts_init(&xts_ctx);
			mbedtls_erro = mbedtls_aes_xts_setkey_enc( &xts_ctx, password, p_keybits );
			if (mbedtls_erro != OK){
				mbedtls_aes_xts_free(&xts_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_xts_setkey_enc"));
			}
			const unsigned char data_unit[16] = {0};
			mbedtls_erro = mbedtls_aes_crypt_xts(&xts_ctx, MBEDTLS_AES_ENCRYPT, input_size, data_unit ,p_input.ptr(), (unsigned char * )&output_buf);
			if (mbedtls_erro != OK){
				mbedtls_aes_xts_free(&xts_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_xts"));
			}
			mbedtls_aes_xts_free(&xts_ctx);
		}
		break;
	}; // switch case


	// Constructing
	mbedtls_aes_free( &aes_ctx );
	output.resize(input_size);
	memcpy(output.ptrw(), &output, input_size);

	return output;
}


Vector<uint8_t> Cripter::aes_decrypt(Vector<uint8_t> p_input, String p_password, Algorithm p_algorith, KeySize p_keybits){

	if (p_algorith != XTS and p_keybits < BITS_128){
		WARN_PRINT("Most AES algorithms support 128,192 and 256 bits keys, with the exception of XTS, which only supports 256 and 512 bits keys. - Using 128 Bits key size");
		p_keybits = BITS_128;
	}
	else if (p_algorith != XTS and p_keybits > BITS_256){
		WARN_PRINT("Most AES algorithms support 128,192 and 256 bits keys, with the exception of XTS, which only supports 256 and 512 bits keys. - Using 256 Bits key size");
		p_keybits = BITS_256;
	}
	else if (p_algorith == XTS and p_keybits < BITS_256){
		WARN_PRINT("XTS algorithm support only supports 256 and 512 bits keys. - Using 256 Bits key size");
		p_keybits = BITS_256;
	}
	else if (p_algorith == XTS and p_keybits > BITS_512){
		WARN_PRINT("XTS algorithm support only supports 256 and 512 bits keys. - Using 512 Bits key size");
		p_keybits = BITS_512;
	};

	// Input
	int input_size = p_input.size();

	// Output
	uint8_t output_buf[input_size];
	Vector<uint8_t> output;
	output.resize(input_size);

	//	IV
	size_t iv_offset = 1;
	unsigned char *iv = (unsigned char *)p_password.md5_buffer().ptr();

	// Password
	String random_pass = p_password;
	for (int i = 0; i < 256; i++) {
		random_pass = random_pass.md5_text();
	};
	const unsigned char * password = (unsigned char *)random_pass.utf8().get_data();

	// Init Context
	int mbedtls_erro;
	mbedtls_aes_context aes_ctx;
	mbedtls_aes_init(&aes_ctx);

	switch (p_algorith) {
		case EBC: {
			mbedtls_erro = mbedtls_aes_setkey_dec( &aes_ctx, password, p_keybits);
			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_setkey_dec"));
			}

			mbedtls_erro = mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_DECRYPT, p_input.ptr(), (unsigned char * )&output_buf);
			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_ecb"));
			}

			mbedtls_aes_free(&aes_ctx);
		}
		break;

		case CBC: {
			uint8_t extra_len = p_input[input_size-1];
			p_input.resize(input_size-1);

			mbedtls_erro = mbedtls_aes_setkey_dec( &aes_ctx, password, p_keybits);
			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_setkey_dec"));
			}

			mbedtls_erro = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, input_size-1, iv, p_input.ptr(), (unsigned char * )&output_buf);
			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_cbc"));
			}

			mbedtls_aes_free(&aes_ctx);

			output.resize(input_size - extra_len - 1);
			memcpy(output.ptrw(), &output_buf, input_size - extra_len);
			return output;

		}
		break;

		case OFB: {
			mbedtls_erro = mbedtls_aes_setkey_dec( &aes_ctx, password, (unsigned int)p_keybits);
			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_setkey_dec"));
			}

			unsigned char iv2[16] = { 0 };
			mbedtls_erro = mbedtls_aes_crypt_ofb(&aes_ctx, input_size, &iv_offset, iv2, p_input.ptr(), (unsigned char * )&output_buf);
			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_ofb"));
			}

			mbedtls_aes_free(&aes_ctx);
		}
		break;

		case CFB128: {
			mbedtls_erro = mbedtls_aes_setkey_enc( &aes_ctx, password, p_keybits );
			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_setkey_enc"));
			}

			mbedtls_erro = mbedtls_aes_crypt_cfb128(&aes_ctx, MBEDTLS_AES_DECRYPT, input_size, &iv_offset, iv, p_input.ptr(), (unsigned char * )&output_buf);
			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_cfb128"));
			}

			mbedtls_aes_free(&aes_ctx);
		}
		break;

		case CFB8: {
			mbedtls_erro = mbedtls_aes_setkey_enc( &aes_ctx, password, p_keybits );
			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_setkey_enc"));
			}

			mbedtls_erro = mbedtls_aes_crypt_cfb8(&aes_ctx, MBEDTLS_AES_DECRYPT, input_size, iv, p_input.ptr(), (unsigned char * )&output_buf);
			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_cfb8"));
			}

			mbedtls_aes_free(&aes_ctx);
		}
		break;

		case XTS: {
			unsigned char data_unit[16] = {0};
			mbedtls_aes_xts_context xts_ctx;
			mbedtls_aes_xts_init(&xts_ctx);

			mbedtls_erro = mbedtls_aes_xts_setkey_dec( &xts_ctx, password, (unsigned int)p_keybits );
			if (mbedtls_erro != OK){
				mbedtls_aes_xts_free(&xts_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_xts_setkey_dec"));
			}

			mbedtls_erro = mbedtls_aes_crypt_xts(&xts_ctx, MBEDTLS_AES_DECRYPT, input_size, data_unit, p_input.ptr(), (unsigned char * )&output_buf);
			if (mbedtls_erro != OK){
				mbedtls_aes_xts_free(&xts_ctx);
				ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_xts"));
			}

			mbedtls_aes_xts_free(&xts_ctx);
			output.resize(sizeof(output_buf));
			memcpy(output.ptrw(), &output_buf, input_size);
			return output;
		}
		break;

	} // switch case

	// Constructing
	memcpy(output.ptrw(), &output_buf, input_size);
	return output;

}


// -------------ASSIMETRIC

int Cripter::gen_pk_key(String p_path, String key_name, PK_TYPE p_type, KeySize p_keybits, String ec_curve){

	const char *pers = "gen_key";
	int mbedtls_erro;

	// Init Context
	mbedtls_pk_context pk_key;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_pk_init(&pk_key);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	//Init entropy
	/*
	mbedtls_erro = mbedtls_entropy_add_source(&entropy, dev_random_entropy_poll, nullptr, DEV_RANDOM_THRESHOLD, MBEDTLS_ENTROPY_SOURCE_STRONG);
		if (mbedtls_erro != OK){
		mbedtls_pk_free(&pk_key);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		ERR_FAIL_V_MSG(mbedtls_erro, mbed_error_msn(mbedtls_erro, "mbedtls_entropy_add_source"));
	}
	*/
	
	mbedtls_erro = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));
	if (mbedtls_erro != OK){
		mbedtls_pk_free(&pk_key);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		ERR_FAIL_V_MSG(mbedtls_erro, mbed_error_msn(mbedtls_erro, "mbedtls_ctr_drbg_seed"));
	}

	// Insert info context
	mbedtls_erro = mbedtls_pk_setup(&pk_key, mbedtls_pk_info_from_type((mbedtls_pk_type_t)p_type));
	if (mbedtls_erro != OK){
		mbedtls_pk_free(&pk_key);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		ERR_FAIL_V_MSG(mbedtls_erro, mbed_error_msn(mbedtls_erro, "mbedtls_pk_setup"));
	}

	// Generate key RSA
	if (p_type == PK_RSA) {
		mbedtls_erro = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk_key), mbedtls_ctr_drbg_random, &ctr_drbg, (unsigned int)p_keybits, EXPONENT);
		if (mbedtls_erro != OK){
			mbedtls_pk_free(&pk_key);
			mbedtls_ctr_drbg_free(&ctr_drbg);
			mbedtls_entropy_free(&entropy);
			ERR_FAIL_V_MSG(mbedtls_erro, mbed_error_msn(mbedtls_erro, "mbedtls_rsa_gen_key"));
		}
	}

	// Generate key EC
	else if (p_type == PK_ECKEY) {
		const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_info_from_name(ec_curve.utf8().get_data());    
		mbedtls_erro = mbedtls_ecp_gen_key((mbedtls_ecp_group_id)curve_info->grp_id, mbedtls_pk_ec(pk_key), mbedtls_ctr_drbg_random, &ctr_drbg);
		if (mbedtls_erro != OK){
			mbedtls_pk_free(&pk_key);
			mbedtls_ctr_drbg_free(&ctr_drbg);
			mbedtls_entropy_free(&entropy);
			ERR_FAIL_V_MSG(mbedtls_erro, mbed_error_msn(mbedtls_erro, "mbedtls_ecp_gen_key"));
		}
	}

	// Output Buffer
	unsigned char pri_output_buf[16000];
	unsigned char pub_output_buf[16000];

	memset(pri_output_buf, 0, sizeof(pri_output_buf));
	memset(pub_output_buf, 0, sizeof(pub_output_buf));

	// Write keys
	mbedtls_erro = mbedtls_pk_write_key_pem(&pk_key, pri_output_buf, sizeof(pri_output_buf));
	if (mbedtls_erro != OK){
		mbedtls_pk_free(&pk_key);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		ERR_FAIL_V_MSG(mbedtls_erro, mbed_error_msn(mbedtls_erro, "mbedtls_pk_write_key_pem"));
	}

	mbedtls_erro = mbedtls_pk_write_pubkey_pem(&pk_key, pub_output_buf, sizeof(pub_output_buf));
	if (mbedtls_erro != OK){
		mbedtls_pk_free(&pk_key);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		ERR_FAIL_V_MSG(mbedtls_erro, mbed_error_msn(mbedtls_erro, "mbedtls_pk_write_pubkey_pem"));
	}

	// Clean up
	mbedtls_pk_free(&pk_key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	// Save Private
	String private_path = p_path + "/" + key_name + ".key";
	Ref<FileAccess> f_private = FileAccess::open(private_path, FileAccess::WRITE);
	ERR_FAIL_COND_V_MSG(f_private.is_null(), ERR_INVALID_PARAMETER, "Cannot save private RSA key to file: '" + private_path + "'.");

	size_t pri_len = strlen((char *)pri_output_buf);
	f_private->store_buffer(pri_output_buf, pri_len);
	mbedtls_platform_zeroize(pri_output_buf, sizeof(pri_output_buf));

	// Save Public
	String public_path = p_path + "/" + key_name + ".pub";
	Ref<FileAccess> f_public = FileAccess::open(public_path, FileAccess::WRITE);
	ERR_FAIL_COND_V_MSG(f_public.is_null(), ERR_INVALID_PARAMETER, "Cannot save public RSA key to file: '" + public_path + "'.");

	size_t pub_len = strlen((char *)pub_output_buf);
	f_public->store_buffer(pub_output_buf, pub_len);
	mbedtls_platform_zeroize(pub_output_buf, sizeof(pub_output_buf));

	return mbedtls_erro;

}



Variant Cripter::compare_keys(String p_private_key_path, String p_public_key_path){

	// Open private key
	Ref<FileAccess> f_priv = FileAccess::open(p_private_key_path, FileAccess::READ);
	ERR_FAIL_COND_V_MSG(f_priv.is_null(), ERR_INVALID_PARAMETER, "Cannot open private key file '" + p_private_key_path + "'.");

	PackedByteArray private_key;
	uint64_t f_priv_len = f_priv->get_length();
	private_key.resize(f_priv_len + 1);
	f_priv->get_buffer(private_key.ptrw(), f_priv_len);
	private_key.write[f_priv_len] = 0; // string terminator

	// Open public key
	Ref<FileAccess> f_pub = FileAccess::open(p_public_key_path, FileAccess::READ);
	ERR_FAIL_COND_V_MSG(f_pub.is_null(), ERR_INVALID_PARAMETER, "Cannot open private key file '" + p_private_key_path + "'.");

	PackedByteArray public_key;
	uint64_t f_pub_len = f_pub->get_length();
	public_key.resize(f_pub_len + 1);
	f_pub->get_buffer(public_key.ptrw(), f_pub_len);
	public_key.write[f_pub_len] = 0; // string terminator

	// Init Context
	int mbedtls_erro;
	mbedtls_pk_context private_ctx, public_ctx;
	mbedtls_pk_init(&private_ctx);
	mbedtls_pk_init(&public_ctx);

	// Parse private key
	mbedtls_erro = mbedtls_pk_parse_key(&private_ctx, private_key.ptr(), private_key.size(), nullptr, 0);
	mbedtls_platform_zeroize(private_key.ptrw(), private_key.size());
	if (mbedtls_erro != OK){
		mbedtls_pk_free(&private_ctx);
		mbedtls_pk_free(&public_ctx);
		ERR_FAIL_V_MSG(mbedtls_erro,  "Error parsing private key '" + itos(mbedtls_erro) + "'.");
	}

	// Parse public key
	mbedtls_erro = mbedtls_pk_parse_public_key(&public_ctx, public_key.ptr(), public_key.size());
	mbedtls_platform_zeroize(public_key.ptrw(), public_key.size());
	if (mbedtls_erro != OK){
		mbedtls_pk_free(&private_ctx);
		mbedtls_pk_free(&public_ctx);
		ERR_FAIL_V_MSG(mbedtls_erro,  "Error parsing public key '" + itos(mbedtls_erro) + "'.");
	}

	// Check
	mbedtls_erro = mbedtls_pk_check_pair(&public_ctx, &private_ctx);
	if (mbedtls_erro != OK){
		mbedtls_pk_free(&private_ctx);
		mbedtls_pk_free(&public_ctx);
		ERR_FAIL_V_MSG(mbedtls_erro, mbed_error_msn(mbedtls_erro, "mbedtls_pk_check_pair"));
	}

	// Clean up
	mbedtls_pk_free( &private_ctx);
	mbedtls_pk_free( &public_ctx);
	
	if (mbedtls_erro == OK){
		return true;
	}
	
	return mbedtls_erro;

}


Vector<uint8_t> Cripter::pk_encrypt(Vector<uint8_t> p_input, String p_key_path){

	// Start
	int mbedtls_erro;
	const char *pers = "pk_encrypt";
	Vector<uint8_t> output;

	ProjectSettings &ps = *ProjectSettings::get_singleton();
	const char *key_path = ps.globalize_path(p_key_path).utf8().get_data();

	// Init Context
	mbedtls_pk_context pk_key;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_pk_init(&pk_key);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	// Gears
	mbedtls_erro = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers )) ;
	if (mbedtls_erro != OK){
		mbedtls_pk_free( &pk_key);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_ctr_drbg_seed"));
	}

	mbedtls_erro = mbedtls_pk_parse_public_keyfile(&pk_key, key_path);
	if (mbedtls_erro != OK){
		mbedtls_pk_free( &pk_key);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_pk_parse_public_keyfile"));
	}

	// Output
	size_t olen = mbedtls_rsa_get_len(mbedtls_pk_rsa(pk_key));
	unsigned char output_buf[olen];
	if (olen < (size_t)p_input.size()){
		mbedtls_pk_free( &pk_key);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);	
		ERR_FAIL_V_MSG(output, "Plaintext length bigger then the key size in Bytes. ");
	}


	mbedtls_erro = mbedtls_pk_encrypt( &pk_key, p_input.ptr(), p_input.size(), output_buf, &olen, sizeof(output_buf), mbedtls_ctr_drbg_random, &ctr_drbg );
	if (mbedtls_erro != OK){
		mbedtls_pk_free( &pk_key);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_pk_encrypt"));
	}

	// Clean up
	mbedtls_pk_free( &pk_key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);


	// Constructing
	output.resize(olen);
	memcpy(output.ptrw(), &output_buf, olen);
	return output;

}


Vector<uint8_t> Cripter::pk_decrypt(Vector<uint8_t> p_input, String p_key_path){

	int mbedtls_erro;
	const char *pers = "pk_decrypt";
	Vector<uint8_t> output;

	ProjectSettings &ps = *ProjectSettings::get_singleton();
	const char *key_path = ps.globalize_path(p_key_path).utf8().get_data();

	// TODO: RSA encrypt and decrypty with password.

	// Init Context
	mbedtls_pk_context pk_key;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_pk_init( &pk_key );
	mbedtls_entropy_init( &entropy );
	mbedtls_ctr_drbg_init( &ctr_drbg );

	// Gears
	mbedtls_erro = mbedtls_pk_parse_keyfile( &pk_key, key_path, nullptr);
	if (mbedtls_erro != OK){
		mbedtls_pk_free(&pk_key);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_pk_parse_keyfile"));
	}

	// Output
	size_t olen = mbedtls_rsa_get_len(mbedtls_pk_rsa(pk_key));
	unsigned char output_buf[olen];
	ERR_FAIL_COND_V_MSG(olen < (size_t)p_input.size(), output, " failed! ciphertext length bigger than the Bytes of the key.");

	mbedtls_erro = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ));
	if (mbedtls_erro != OK){
		mbedtls_pk_free(&pk_key);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_ctr_drbg_seed"));
	}

	mbedtls_erro = mbedtls_pk_decrypt( &pk_key, p_input.ptr(), p_input.size(), output_buf, &olen, sizeof(output_buf), mbedtls_ctr_drbg_random, &ctr_drbg );
	if (mbedtls_erro != OK){
		mbedtls_pk_free(&pk_key);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		ERR_FAIL_V_MSG(output, mbed_error_msn(mbedtls_erro, "mbedtls_pk_decrypt"));
	}

	// Clean up
	mbedtls_pk_free(&pk_key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	// Constructing
	output.resize(olen);
	memcpy(output.ptrw(), &output_buf, olen);
	return output;

}


Dictionary Cripter::analize_pk_key(String p_key_path){

	Ref<FileAccess> f = FileAccess::open(p_key_path, FileAccess::READ);
	if(f.is_null()){
		Dictionary ret;
		ret["FileAccess ERROR"] = ERR_INVALID_PARAMETER;
		ERR_FAIL_V_MSG(ret, "Cannot open private key file '" + p_key_path + "'.");
	}

	String s = f->get_line();
	bool type = s.contains("PRIVATE");
	return _analize_pk_key(p_key_path, type);
}



Dictionary Cripter::_analize_pk_key(String p_key_path, bool is_private){

	int mbedtls_erro;
	Dictionary ret;

	ProjectSettings &ps = *ProjectSettings::get_singleton();
	const char *key_path = ps.globalize_path(p_key_path).utf8().get_data();
	
	mbedtls_pk_context pk_key;
	mbedtls_pk_init(&pk_key);

	if (is_private){
		ret["bits"] = String("PRIVATE");
		mbedtls_erro = mbedtls_pk_parse_keyfile( &pk_key, key_path, nullptr);   
		if (mbedtls_erro != OK){
			mbedtls_pk_free(&pk_key);
			ERR_FAIL_V_MSG(ret, mbed_error_msn(mbedtls_erro, "mbedtls_pk_parse_keyfile"));
		}
	}

	else{
		ret["bits"] = String("PUBLIC");
		mbedtls_erro = mbedtls_pk_parse_public_keyfile(&pk_key, key_path);
		if (mbedtls_erro != OK){
			mbedtls_pk_free( &pk_key);
			ERR_FAIL_V_MSG(ret, mbed_error_msn(mbedtls_erro, "mbedtls_pk_parse_public_keyfile"));
		}
	}

	// Name
	String name = String(mbedtls_pk_get_name(&pk_key));
	ERR_FAIL_COND_V_EDMSG(name == "invalid PK", ret, "Invalid key!");

	ret["name"] = String(name);						// RSA or EC.  
	ret["bits"] = mbedtls_pk_get_len((&pk_key));	// Length in Bytes. 

	// ECP Curve
	if( mbedtls_pk_get_type(&pk_key) == MBEDTLS_PK_ECKEY){
		mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(pk_key);
		mbedtls_ecp_group_id grp_id = ecp->grp.id;
		const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_info_from_grp_id(grp_id);
		ret["ec_curve"]	= curve_info->name;	
	}

	mbedtls_pk_free(&pk_key);
	return ret;

}


PackedStringArray Cripter::get_available_ec_curves(){
	PackedStringArray ret;
	const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_list();
	while ((++curve_info)->name != NULL) {
		ret.append(curve_info->name);
	}
	return ret;
}


String Cripter::mbed_error_msn(int mbedtls_erro, const char* p_function){
	char mbedtls_erro_text[256];
	mbedtls_strerror( mbedtls_erro, mbedtls_erro_text, sizeof(mbedtls_erro_text) );
	std::string s = std::to_string(mbedtls_erro);
	String ret = String::utf8("failed! mbedtls returned the error: ") + String::utf8(s.c_str()) + \
	String::utf8(" - Function: ") + String::utf8(p_function) + String::utf8(" - Description: ") + String::utf8(mbedtls_erro_text);
	return ret;
}


void Cripter::_bind_methods(){

	ClassDB::bind_static_method("Cripter", D_METHOD("gcm_encrypt", "plaintext", "password", "additional data", "key bits"),&Cripter::gcm_encrypt, DEFVAL(String()), DEFVAL(BITS_256));
	ClassDB::bind_static_method("Cripter", D_METHOD("gcm_decrypt", "ciphertext", "password", "additional data", "key bits"),&Cripter::gcm_decrypt, DEFVAL(String()), DEFVAL(BITS_256));

	ClassDB::bind_static_method("Cripter", D_METHOD("aes_encrypt", "plaintext", "password", "algorithm", "key bits"),&Cripter::aes_encrypt, DEFVAL(CBC), DEFVAL(BITS_256));
	ClassDB::bind_static_method("Cripter", D_METHOD("aes_decrypt", "ciphertext", "password", "algorithm", "key bits"),&Cripter::aes_decrypt, DEFVAL(CBC), DEFVAL(BITS_256));

	ClassDB::bind_static_method("Cripter", D_METHOD("pk_encrypt", "plaintext", "public key path"), &Cripter::pk_encrypt);
	ClassDB::bind_static_method("Cripter", D_METHOD("pk_decrypt", "ciphertext", "private key path"), &Cripter::pk_decrypt);

	ClassDB::bind_static_method("Cripter", D_METHOD("gen_pk_key", "path", "key name", "type", "bits", "ec_curve"), &Cripter::gen_pk_key, DEFVAL(PK_RSA), DEFVAL(BITS_2048), DEFVAL(String("secp521r1")));
	ClassDB::bind_static_method("Cripter", D_METHOD("compare_keys", "private key path", "public key path"), &Cripter::compare_keys);
	ClassDB::bind_static_method("Cripter", D_METHOD("analize_pk_key", "key path"), &Cripter::analize_pk_key);
	ClassDB::bind_static_method("Cripter", D_METHOD("get_available_ec_curves"), &Cripter::get_available_ec_curves);


	BIND_ENUM_CONSTANT(PK_RSA);
	BIND_ENUM_CONSTANT(PK_ECKEY);

	BIND_ENUM_CONSTANT(BITS_128);
	BIND_ENUM_CONSTANT(BITS_192);
	BIND_ENUM_CONSTANT(BITS_256);
	BIND_ENUM_CONSTANT(BITS_512);
	BIND_ENUM_CONSTANT(BITS_1024);
	BIND_ENUM_CONSTANT(BITS_2048);
	BIND_ENUM_CONSTANT(BITS_3072);
	BIND_ENUM_CONSTANT(BITS_4096);
	BIND_ENUM_CONSTANT(BITS_7680);
	BIND_ENUM_CONSTANT(BITS_8192);

	BIND_ENUM_CONSTANT(EBC);
	BIND_ENUM_CONSTANT(CBC);
	BIND_ENUM_CONSTANT(XTS);
	BIND_ENUM_CONSTANT(CFB128);
	BIND_ENUM_CONSTANT(CFB8);
	BIND_ENUM_CONSTANT(OFB);
//	BIND_ENUM_CONSTANT(CTR);

}



Cripter::Cripter(){
}

Cripter::~Cripter(){
}

/*cripter.cpp*/
