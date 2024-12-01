/*cripter.cpp*/

#include "cripter.h"




// =============== AES FUNCTION ===============


PackedByteArray Cripter::aes_encrypt(const PackedByteArray plaintext, const String p_password, PackedByteArray p_iv, Algorithm algorith, KeySize keybits){


	PackedByteArray result = _aes_crypt(plaintext, p_password, p_iv, algorith, keybits, MBEDTLS_AES_ENCRYPT);
	return result;

/*
	std::vector<unsigned char> password = GDstring_to_STDvector(p_password);
	std::vector<unsigned char> input = byteArray_to_vector(plaintext);
	std::vector<unsigned char> iv = byteArray_to_vector(p_iv);

	std::vector<unsigned char> result = _aes_crypt(input, password, iv, algorith, keybits, MBEDTLS_AES_ENCRYPT);

	PackedByteArray ret;
	ret.resize(result.size());
	memcpy(ret.ptrw(), result.data(), result.size());

	return ret;
*/
}


PackedByteArray Cripter::aes_decrypt(const PackedByteArray ciphertext, const String p_password, PackedByteArray p_iv, Algorithm algorith, KeySize keybits){
	PackedByteArray result = _aes_crypt(ciphertext, p_password, p_iv, algorith, keybits, MBEDTLS_AES_DECRYPT);
	return result;
/*
	std::vector<unsigned char> password = GDstring_to_STDvector(p_password);
	std::vector<unsigned char> input = byteArray_to_vector(ciphertext);
	std::vector<unsigned char> iv = byteArray_to_vector(p_iv);

	std::vector<unsigned char> result = _aes_crypt(input, password, iv, algorith, keybits, MBEDTLS_AES_DECRYPT);

	PackedByteArray ret;
	ret.resize(result.size());
	memcpy(ret.ptrw(), result.data(), result.size());

	return ret;
*/
}



PackedByteArray Cripter::_aes_crypt(PackedByteArray input, String password, PackedByteArray iv, Algorithm algorith, Cripter::KeySize keybits, int mode){
//std::vector<unsigned char> Cripter::_aes_crypt(std::vector<unsigned char> input, std::vector<unsigned char> password, std::vector<unsigned char> iv, Algorithm algorith, Cripter::KeySize keybits, int mode){


	if ((keybits < BITS_128)){
		WARN_PRINT("Most AES algorithms support 128,192 and 256 bits keys, with the exception of XTS, which only supports 256 and 512 bits keys. - Using 128 Bits key size");
		keybits = BITS_128;
	}
	else if (keybits > BITS_256){
		WARN_PRINT("Most AES algorithms support 128,192 and 256 bits keys, with the exception of XTS, which only supports 256 and 512 bits keys. - Using 256 Bits key size");
		keybits = BITS_256;
	}

/*
	if ((algorith != XTS) and (keybits < BITS_128)){
		WARN_PRINT("Most AES algorithms support 128,192 and 256 bits keys, with the exception of XTS, which only supports 256 and 512 bits keys. - Using 128 Bits key size");
		keybits = BITS_128;
	}
	else if (algorith != XTS and keybits > BITS_256){
		WARN_PRINT("Most AES algorithms support 128,192 and 256 bits keys, with the exception of XTS, which only supports 256 and 512 bits keys. - Using 256 Bits key size");
		keybits = BITS_256;
	}

	else if (algorith == XTS and keybits < BITS_256){
		WARN_PRINT("XTS algorithm support only supports 256 and 512 bits keys. - Using 256 Bits key size");
		keybits = BITS_256;
	}
	else if (algorith == XTS and keybits > BITS_512){
		WARN_PRINT("XTS algorithm support only supports 256 and 512 bits keys. - Using 512 Bits key size");
		keybits = BITS_512;
	}
*/

	// std::vector<unsigned char> output;
	PackedByteArray output;

	if (iv.size() != AES_GCM_BLOCK_SIZE){
		WARN_PRINT("The IV size must be AES_BLOCK_SIZE for AES encryption.");
		return output;
	}

	int mbedtls_erro;
	mbedtls_aes_context aes_ctx;
	mbedtls_aes_init(&aes_ctx);
	output.resize(input.size());

//	mbedtls_erro = mbedtls_aes_setkey_enc(&aes_ctx, password.data(), keybits);
	mbedtls_erro = mbedtls_aes_setkey_enc(&aes_ctx, reinterpret_cast<const unsigned char*>(password.utf8().get_data()), keybits);
	if (mbedtls_erro != OK){
		mbedtls_aes_free(&aes_ctx);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_aes_setkey_enc");
		WARN_PRINT(String("Failed to configure AES key.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
		return output;
	};


	switch (algorith) {

		case EBC: {
			//mbedtls_erro = mbedtls_aes_crypt_ecb(&aes_ctx, mode, input.data(), output.data());
			mbedtls_erro = mbedtls_aes_crypt_ecb(&aes_ctx, mode, input.ptr(), output.ptrw());
			mbedtls_aes_free(&aes_ctx);
			if (mbedtls_erro != OK){
				String _err = mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_ecb");
				WARN_PRINT(String("EBC Encryption error: -0x%04x\n") + String::num_int64(-mbedtls_erro, 16) + _err);
			}
			return output;
		}
		break;


		case CBC: {
			if (mode == MBEDTLS_AES_ENCRYPT){
/*
				if (add_pkcs7_padding(input, input, AES_GCM_BLOCK_SIZE) != OK){
					WARN_PRINT(String("Invalid parameter. AES block must be 16 Bytes."));
					mbedtls_aes_free(&aes_ctx);
					return output;
				}
*/
				input = add_pkcs7_padding(input, AES_GCM_BLOCK_SIZE);
			}

		//	unsigned char iv_copy[16];
		//	memcpy(iv_copy, iv.data(), 16);

			PackedByteArray iv_copy = iv.duplicate();

			//mbedtls_erro = mbedtls_aes_crypt_cbc(&aes_ctx, mode, input.size(), iv_copy, input.data(), output.data());
			mbedtls_erro = mbedtls_aes_crypt_cbc(&aes_ctx, mode, input.size(), iv_copy.ptrw(), input.ptr(), output.ptrw());
			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				String _err = mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_cbc");
				WARN_PRINT(String("CBC Encryption error: -0x%04x\n") + String::num_int64(-mbedtls_erro, 16) + _err);
				return output;
			}

			if (mode == MBEDTLS_AES_DECRYPT){
/*
				Error _err = remove_pkcs7_padding(output, output, AES_GCM_BLOCK_SIZE);
				if ( _err == ERR_INVALID_PARAMETER){
					WARN_PRINT("Block size out of parameter.");
				}
				else if(_err == ERR_INVALID_DATA){
					WARN_PRINT(String("Input buffer contains invalid Padding."));
				}
*/
				output = remove_pkcs7_padding(output, AES_GCM_BLOCK_SIZE);
			}
			return output;
		}
		break;


		case CFB128:{
	//		unsigned char iv_copy[16];
	//		memcpy(iv_copy, iv.data(), 16);
			size_t iv_off = 0;

			PackedByteArray iv_copy = iv.duplicate();

	//		mbedtls_erro = mbedtls_aes_crypt_cfb128(&aes_ctx, mode, input.size(), &iv_off, iv_copy, input.data(), output.data());
			mbedtls_erro = mbedtls_aes_crypt_cfb128(&aes_ctx, mode, input.size(), &iv_off, iv_copy.ptrw(), input.ptr(), output.ptrw());
			mbedtls_aes_free(&aes_ctx);
			if (mbedtls_erro != OK){
				String _err = mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_cfb128");
				WARN_PRINT(String("CFB128 Encryption error: -0x%04x\n") + String::num_int64(-mbedtls_erro, 16) + _err);
			}
			return output;
		}
		break;


		case CFB8:{
	//		unsigned char iv_copy[16];
	//		memcpy(iv_copy, iv.data(), 16);
			PackedByteArray iv_copy = iv.duplicate();

			mbedtls_erro = mbedtls_aes_crypt_cfb8(&aes_ctx, mode, input.size(), iv_copy.ptrw(), input.ptr(), output.ptrw());
			mbedtls_aes_free(&aes_ctx);
			if (mbedtls_erro != OK){
				String _err = mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_cfb8");
				WARN_PRINT(String("CFB8 Encryption error: -0x%04x\n") + String::num_int64(-mbedtls_erro, 16) + _err);
			}
			return output;
		}
		break;


		case OFB:{
		//	unsigned char iv_copy[16];
		//	memcpy(iv_copy, iv.data(), 16);

			PackedByteArray iv_copy = iv.duplicate();
			size_t iv_off = 0;

			mbedtls_erro = mbedtls_aes_crypt_ofb(&aes_ctx, input.size(), &iv_off, iv_copy.ptrw(), input.ptr(), output.ptrw());
			mbedtls_aes_free(&aes_ctx);
			if (mbedtls_erro != OK){
				String _err = mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_ofb");
				WARN_PRINT(String("OFB Encryption error: -0x%04x\n") + String::num_int64(-mbedtls_erro, 16) + _err);
			}
			return output;

		}
		break;

		case CTR: {
			size_t nc_off = 0;
			PackedByteArray nonce_counter = iv.duplicate();
			PackedByteArray stream_block;
			stream_block.resize(AES_GCM_BLOCK_SIZE);
			stream_block.fill(0);

			mbedtls_erro = mbedtls_aes_crypt_ctr(&aes_ctx, input.size(), &nc_off, nonce_counter.ptrw(), stream_block.ptrw(), input.ptr(), output.ptrw());
			mbedtls_aes_free(&aes_ctx);
			if (mbedtls_erro != OK){
				String _err = mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_ctr");
				WARN_PRINT(String("CTR Encryption error: -0x%04x\n") + String::num_int64(-mbedtls_erro, 16) + _err);
			}
			return output;
		}
		break;

/*
		case CTR: {
		//	unsigned char nonce_counter[16];
		//	memcpy(nonce_counter, iv.data(), 16);
		//	unsigned char stream_block[16];
		//	memset(stream_block, 0, 16);
			size_t nc_off = 0;

			PackedByteArray nonce_counter = iv.duplicate();
			PackedByteArray stream_block;
			stream_block.resize(AES_GCM_BLOCK_SIZE);
			stream_block.fill(0);

			mbedtls_erro = mbedtls_aes_crypt_ctr(&aes_ctx, input.size(), &nc_off, nonce_counter.ptrw(), stream_block.ptrw(), input.ptr(), output.ptrw());
			mbedtls_aes_free(&aes_ctx);
			if (mbedtls_erro != OK){
				String _err = mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_ctr");
				WARN_PRINT(String("CTR Encryption error: -0x%04x\n") + String::num_int64(-mbedtls_erro, 16) + _err);
			}
			return output;
		}
		break;
*/




	}; // switch case

	return output;

}


// Error Cripter::aes_start_stream(const String password){}
// Error Cripter::aes_update_stream(const PackedByteArray data){}
// Error Cripter::aes_stop_stream(){}



// =============== GCM FUNCTION ===============


Dictionary Cripter::gcm_encrypt(const PackedByteArray plaintext, const String p_password, const PackedByteArray p_iv, String p_aad, Cripter::KeySize keybits){
	std::vector<unsigned char> password = GDstring_to_STDvector(p_password);
	std::vector<unsigned char> input = byteArray_to_vector(plaintext);
	std::vector<unsigned char> aad = GDstring_to_STDvector(p_aad);
	std::vector<unsigned char> iv = byteArray_to_vector(p_iv);
	std::vector<unsigned char> tag(GCM_TAG_SIZE);
	Dictionary ret = _gcm_crypt(input, password, iv, aad, tag, keybits, MBEDTLS_GCM_ENCRYPT);
	return ret;
}



PackedByteArray Cripter::gcm_decrypt(const PackedByteArray ciphertext, const String p_password, const PackedByteArray p_iv, const PackedByteArray p_tag, String p_aad,	Cripter::KeySize keybits){
	ERR_FAIL_COND_V_MSG(p_tag.size() != 16, PackedByteArray(), "Tags for GCM encryption must have the default value of 16.");
	std::vector<unsigned char> password = GDstring_to_STDvector(p_password);
	std::vector<unsigned char> input = byteArray_to_vector(ciphertext);
	std::vector<unsigned char> aad = GDstring_to_STDvector(p_aad);
	std::vector<unsigned char> tag = byteArray_to_vector(p_tag);
	std::vector<unsigned char> iv = byteArray_to_vector(p_iv);
	PackedByteArray ret = _gcm_crypt(input, password, iv, aad, tag, keybits, MBEDTLS_GCM_DECRYPT);
	return ret;
}

Variant Cripter::_gcm_crypt(
	std::vector<unsigned char> input,
	std::vector<unsigned char> password,
	std::vector<unsigned char> iv,
	std::vector<unsigned char> aad,
	std::vector<unsigned char> tag,
	Cripter::KeySize keybits,
	int mode
	){

	if (keybits < BITS_128){
		WARN_PRINT("GCM Algorithm only accepts key with 128, 192, or 256 bits");
		keybits = BITS_128;
	}
	if (keybits > BITS_256){
		WARN_PRINT("GCM Algorithm only accepts key with 128, 192, or 256 bits");
		keybits = BITS_256;
	}

	mbedtls_gcm_context gcm_ctx;
	mbedtls_gcm_init(&gcm_ctx);

	PackedByteArray output;
	output.resize(input.size());

	int mbedtls_erro = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, password.data(), keybits);
	if (mbedtls_erro != OK) {
		mbedtls_gcm_free(&gcm_ctx);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_gcm_setkey");
		ERR_FAIL_V_EDMSG(Dictionary(), String("Failed to configure GCM key.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_erro = mbedtls_gcm_crypt_and_tag(
		&gcm_ctx, mode, input.size(),
		iv.data(), iv.size(),
		aad.data(), aad.size(),
		input.data(), output.ptrw(),
		GCM_TAG_SIZE, tag.data()
	);

	mbedtls_gcm_free(&gcm_ctx);

	if (mbedtls_erro != OK) {
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_gcm_crypt_and_tag");
		ERR_FAIL_V_EDMSG(Dictionary(), String("Encryption error. : -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	PackedByteArray tag_array;
	tag_array.resize(GCM_TAG_SIZE);
	memcpy(tag_array.ptrw(), tag.data(), GCM_TAG_SIZE);

	Dictionary ret;
	ret["Tag"] = tag_array;
	ret["Ciphertext"] = output;
	return ret;

}


// Stream


Error Cripter::gcm_start_stream(const String password, const PackedByteArray iv, const CryptMode mode, Cripter::KeySize keybits){

	if (gcm_stream != nullptr){
		mbedtls_gcm_free(&gcm_stream->gcm_ctx);
		delete gcm_stream;
		gcm_stream = nullptr;
	}

	gcm_stream = new gcm_streamer();
	mbedtls_gcm_init(&gcm_stream->gcm_ctx);
	int mbedtls_erro;
	const unsigned char *key = reinterpret_cast<const unsigned char*>(password.utf8().get_data());

	if (keybits < BITS_128){
		WARN_PRINT("GCM Algorithm only accepts key with 128, 192, or 256 bits");
		keybits = BITS_128;
	}
	if (keybits > BITS_256){
		WARN_PRINT("GCM Algorithm only accepts key with 128, 192, or 256 bits");
		keybits = BITS_256;
	}

	mbedtls_erro = mbedtls_gcm_setkey(&gcm_stream->gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, keybits);
	if (mbedtls_erro != OK) {
		mbedtls_gcm_free(&gcm_stream->gcm_ctx);
		delete gcm_stream;
		gcm_stream = nullptr;
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_gcm_setkey");
		ERR_FAIL_V_EDMSG(FAILED, String("Failed to configure GCM key.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_erro = mbedtls_gcm_starts(&gcm_stream->gcm_ctx, (int)mode, iv.ptr(), iv.size());
	if (mbedtls_erro != OK) {
		mbedtls_gcm_free(&gcm_stream->gcm_ctx);
		delete gcm_stream;
		gcm_stream = nullptr;
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_gcm_starts");
		ERR_FAIL_V_EDMSG(FAILED, String("Failed to set the streamer.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	return OK;
}


PackedByteArray Cripter::gcm_update_stream(const PackedByteArray data, const bool in_chunk){

	PackedByteArray output;
	int mbedtls_erro;
	size_t plaintext_len = data.size();
	output.resize(plaintext_len + AES_GCM_BLOCK_SIZE);
	size_t output_len = 0;

	if (in_chunk){


		size_t chunk_size = AES_GCM_BLOCK_SIZE;
		size_t offset = 0;

		while (offset < plaintext_len) {
			size_t len = (plaintext_len - offset > chunk_size) ? chunk_size : (plaintext_len - offset);

			mbedtls_erro = mbedtls_gcm_update(
				&gcm_stream->gcm_ctx,
				data.ptr() + offset, len,
				output.ptrw() + offset,
				offset,
				&output_len
			);

			if (mbedtls_erro != OK) {
				String _err = mbed_error_msn(mbedtls_erro, "mbedtls_gcm_update");
				ERR_FAIL_V_EDMSG(PackedByteArray(), String("Failed to perform GCM stream operation.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
			}
			offset += len;
	}

	}else{

		mbedtls_erro = mbedtls_gcm_update(&gcm_stream->gcm_ctx, data.ptr(), plaintext_len, output.ptrw(), plaintext_len, &plaintext_len);
		if (mbedtls_erro != OK) {
			String _err = mbed_error_msn(mbedtls_erro, "mbedtls_gcm_update");
			ERR_FAIL_V_EDMSG(PackedByteArray(), String("Failed to perform GCM stream operation.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
		}
	}

	return output;
}


PackedByteArray Cripter::gcm_stop_stream(PackedByteArray data){

	PackedByteArray tag;
	tag.resize(GCM_TAG_SIZE);
	size_t tag_size = GCM_TAG_SIZE;

	int mbedtls_erro = mbedtls_gcm_finish(&gcm_stream->gcm_ctx, data.ptrw(), (size_t)data.size(), &tag_size, tag.ptrw(), tag.size());
	if(mbedtls_erro != OK){
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_gcm_update");
		String err_msn = String("Failed to perform GCM stream operation.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err;
		WARN_PRINT(err_msn);
	}

	mbedtls_gcm_free(&gcm_stream->gcm_ctx);
	delete gcm_stream;
	gcm_stream = nullptr;
	return tag;
}










// =============== ASYMMETRIC ===============
//TODO criptografar a chave
PackedStringArray Cripter::get_available_curves() {
	PackedStringArray curve_names;
	const mbedtls_ecp_curve_info* curve_info = mbedtls_ecp_curve_list();
	while (curve_info != NULL && curve_info->name != NULL) {
		curve_names.append(String(curve_info->name));
		curve_info++;
	}
	return curve_names;
}

Error Cripter::pk_generate_keys(
	PK_TYPE algorithm_type,
	Cripter::KeySize key_size,
	const ECP_GROUP_ID curve,
	FileFormat storage_format,
	const String password,
	const String p_private_key_filename,
	const String p_public_key_filename,
	const String personalization
	) {


	// Create Variables
	//unsigned char pri_output_buf[16000];
	//unsigned char pub_output_buf[16000];

	//std::vector<unsigned char> pri_output_buf(16000, 0);
	//std::vector<unsigned char> pub_output_buf(16000, 0);

	PackedByteArray pri_output_buf;
	PackedByteArray pub_output_buf;
	pri_output_buf.resize(16000);
	pub_output_buf.resize(16000);

	int pk_key_type;
	int mbedtls_erro = 0;
	const char* pers = personalization.utf8().get_data();

	mbedtls_pk_type_t algorithm = static_cast<mbedtls_pk_type_t>(algorithm_type);
	mbedtls_pk_context pk_key;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;


	// Init Variables
	//memset(pri_output_buf, 0, sizeof(pri_output_buf));
	//memset(pub_output_buf, 0, sizeof(pub_output_buf));
	mbedtls_pk_init(&pk_key);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	String private_key_filename = ensure_global_path(p_private_key_filename);
	String public_key_filename = ensure_global_path(p_public_key_filename);

	if (algorithm == MBEDTLS_PK_ECKEY || algorithm == MBEDTLS_PK_ECKEY_DH || algorithm == MBEDTLS_PK_ECDSA) {
		pk_key_type = TYPE_ECC;
	}
	else if (algorithm == MBEDTLS_PK_RSA || algorithm == MBEDTLS_PK_RSA_ALT || algorithm == MBEDTLS_PK_RSASSA_PSS){
		pk_key_type = TYPE_RSA;
	}

	if (key_size <  BITS_1024){
		WARN_PRINT("RSA keys support sizes from 1024 to 8192 bits. - Using 1024 Bits key size");
		key_size = BITS_1024;
	}
	else if (key_size > BITS_8192){
		WARN_PRINT("RSA keys support sizes from 1024 to 8192 bits. - Using 8192 Bits key size");
		key_size = BITS_8192;
	}

	// ENTROPY SEED
	mbedtls_erro = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, reinterpret_cast<const unsigned char*>(pers), strlen(pers));
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_ctr_drbg_seed");
		ERR_FAIL_V_EDMSG(FAILED, String("Failed to seed the random generator: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	const mbedtls_pk_info_t *pk_type = mbedtls_pk_info_from_type((mbedtls_pk_type_t) algorithm);
	if (pk_type == NULL) {
		mbedtls_pk_free(&pk_key);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		ERR_FAIL_V_EDMSG(FAILED, "Invalid PK type info.");
	}


	mbedtls_erro = mbedtls_pk_setup(&pk_key, pk_type);
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_pk_setup");
		ERR_FAIL_V_EDMSG(FAILED, String("Failed to Initialize a PK context: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	// ===================================== RSA =====================================
	if (pk_key_type == TYPE_RSA){
		mbedtls_erro = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk_key), mbedtls_ctr_drbg_random, &ctr_drbg, (unsigned int)key_size, EXPONENT);
		if (mbedtls_erro != OK) {
			mbedtls_pk_free(&pk_key);
			mbedtls_entropy_free(&entropy);
			mbedtls_ctr_drbg_free(&ctr_drbg);
			String _err = mbed_error_msn(mbedtls_erro, "mbedtls_rsa_gen_key");
			ERR_FAIL_V_EDMSG(FAILED, String("Failed to create RSA key pair.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
		}
	}
	// ===================================== ECC =====================================
	else if (pk_key_type == TYPE_ECC){
		mbedtls_erro = mbedtls_ecp_gen_key((mbedtls_ecp_group_id)algorithm, mbedtls_pk_ec(pk_key), mbedtls_ctr_drbg_random, &ctr_drbg);
		if (mbedtls_erro != OK) {
			mbedtls_pk_free(&pk_key);
			mbedtls_entropy_free(&entropy);
			mbedtls_ctr_drbg_free(&ctr_drbg);
			String _err = mbed_error_msn(mbedtls_erro, "mbedtls_ecp_gen_key");
			ERR_FAIL_V_EDMSG(FAILED, String("Failed to create ECP key pair.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
		}
	}
	// =================================== INVALID ====================================
	else {
		WARN_PRINT("Unsupported key type");
		return ERR_INVALID_PARAMETER;
	}

	// Export keys ====

	// PEM
	if (storage_format == PEM){
		mbedtls_erro = mbedtls_pk_write_key_pem(&pk_key, pri_output_buf.ptrw(), pri_output_buf.size());
		if (mbedtls_erro != OK){
			mbedtls_pk_free(&pk_key);
			mbedtls_ctr_drbg_free(&ctr_drbg);
			mbedtls_entropy_free(&entropy);
			ERR_FAIL_V_MSG(FAILED, mbed_error_msn(mbedtls_erro, "mbedtls_pk_write_key_pem"));
		}

		mbedtls_erro = mbedtls_pk_write_pubkey_pem(&pk_key, pub_output_buf.ptrw(), pub_output_buf.size());
		if (mbedtls_erro != OK){
			mbedtls_pk_free(&pk_key);
			mbedtls_ctr_drbg_free(&ctr_drbg);
			mbedtls_entropy_free(&entropy);
			ERR_FAIL_V_MSG(FAILED, mbed_error_msn(mbedtls_erro, "mbedtls_pk_write_pubkey_pem"));
		}
	}

	// DER
	else if (storage_format == DER){
		mbedtls_erro = mbedtls_pk_write_key_der(&pk_key, pri_output_buf.ptrw(), pri_output_buf.size());
		if (mbedtls_erro != OK){
			mbedtls_pk_free(&pk_key);
			mbedtls_ctr_drbg_free(&ctr_drbg);
			mbedtls_entropy_free(&entropy);
			ERR_FAIL_V_MSG(FAILED, mbed_error_msn(mbedtls_erro, "mbedtls_pk_write_key_pem"));
		}

		mbedtls_erro = mbedtls_pk_write_pubkey_der(&pk_key, pub_output_buf.ptrw(), pub_output_buf.size());
		if (mbedtls_erro != OK){
			mbedtls_pk_free(&pk_key);
			mbedtls_ctr_drbg_free(&ctr_drbg);
			mbedtls_entropy_free(&entropy);
			ERR_FAIL_V_MSG(FAILED, mbed_error_msn(mbedtls_erro, "mbedtls_pk_write_pubkey_pem"));
		}
	}


	// Encrypt key
	if (not password.is_empty()){
		PackedByteArray iv = generate_iv(AES_GCM_BLOCK_SIZE, String("Encrypt PKey"));
		pri_output_buf = _aes_crypt(pri_output_buf, password, iv, CBC, BITS_256, MBEDTLS_AES_ENCRYPT);
	}


	// WRITE FILES

	// Private
	Ref<FileAccess> f_private = FileAccess::open(private_key_filename, FileAccess::WRITE);
	ERR_FAIL_COND_V_MSG(f_private.is_null(), ERR_INVALID_PARAMETER, "Cannot save private RSA key to file: '" + private_key_filename + "'.");
//	size_t pri_len = strlen((char *)pri_output_buf);
//	f_private->store_buffer(pri_output_buf, pri_len);
//	mbedtls_platform_zeroize(pri_output_buf, sizeof(pri_output_buf));
	f_private->store_buffer(pri_output_buf);
	pri_output_buf.fill(0); //zeroize


	// Public
	Ref<FileAccess> f_public = FileAccess::open(public_key_filename, FileAccess::WRITE);
	ERR_FAIL_COND_V_MSG(f_public.is_null(), ERR_INVALID_PARAMETER, "Cannot save public RSA key to file: '" + public_key_filename + "'.");
//	size_t pub_len = strlen((char *)pub_output_buf);
//	f_public->store_buffer(pub_output_buf, pub_len);
//	mbedtls_platform_zeroize(pub_output_buf, sizeof(pub_output_buf));
	f_private->store_buffer(pub_output_buf);
	pub_output_buf.fill(0); //zeroize


	// Clean up
	mbedtls_pk_free(&pk_key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return OK;

}



Variant Cripter::pk_match_keys(const String p_private_key_path, const String p_public_key_path, const String password){

	const String private_key_path = ensure_global_path(p_private_key_path);
	const String public_key_path = ensure_global_path(p_public_key_path);
	int mbedtls_erro;
	const char *pers = "pk_match_keys";

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_pk_context private_ctx, public_ctx;

	mbedtls_pk_init(&private_ctx);
	mbedtls_pk_init(&public_ctx);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);


	mbedtls_erro = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, reinterpret_cast<const unsigned char*>(pers), strlen(pers));
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&private_ctx);
		mbedtls_pk_free(&public_ctx);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_ctr_drbg_seed");
		ERR_FAIL_V_EDMSG(mbedtls_erro, String("Failed to seed random number generator: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}


	if (password.is_empty()){
		mbedtls_erro = mbedtls_pk_parse_keyfile(&private_ctx, private_key_path.utf8().get_data(), nullptr, mbedtls_ctr_drbg_random, &ctr_drbg);
	}else{
		mbedtls_erro = mbedtls_pk_parse_keyfile(&private_ctx, private_key_path.utf8().get_data(), password.utf8().get_data(), mbedtls_ctr_drbg_random, &ctr_drbg);
	}
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&private_ctx);
		mbedtls_pk_free(&public_ctx);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_pk_parse_keyfile");
		ERR_FAIL_V_EDMSG(mbedtls_erro, String("Error parsing private key.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}


	mbedtls_erro = mbedtls_pk_parse_public_keyfile(&public_ctx, public_key_path.utf8().get_data());
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&private_ctx);
		mbedtls_pk_free(&public_ctx);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_pk_parse_public_keyfile");
		ERR_FAIL_V_EDMSG(mbedtls_erro, String("Error parsing public key.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}


	mbedtls_erro = mbedtls_pk_check_pair(&public_ctx, &private_ctx, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_pk_free(&private_ctx);
	mbedtls_pk_free(&public_ctx);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	if (mbedtls_erro != OK) {
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_pk_parse_public_keyfile");
		ERR_FAIL_V_EDMSG(mbedtls_erro, String("Error parsing public key.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}


	if (mbedtls_erro == OK){
		return true;
	}

	return mbedtls_erro;

}






Dictionary Cripter::pk_analyze_key(const String p_key_path) {

	Dictionary ret;
	int mbedtls_error = 0;
	const char *pers = "pk_parse_key";
	String key_path = ensure_global_path(p_key_path);


	mbedtls_pk_context pk;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_pk_init(&pk);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);


	mbedtls_error = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, reinterpret_cast<const unsigned char*>(pers), strlen(pers));
	if (mbedtls_error != OK) {
		mbedtls_pk_free(&pk);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_error, "mbedtls_ctr_drbg_seed");
		ERR_FAIL_V_EDMSG(ret, String("Failed to seed random number generator: -0x") + String::num_int64(-mbedtls_error, 16) + _err);
	}

	// Try to load as private key
	//const char *key_path = p_key_path.utf8().get_data();
	mbedtls_error = mbedtls_pk_parse_keyfile(&pk, key_path.utf8().get_data(), nullptr, mbedtls_ctr_drbg_random, &ctr_drbg);
	bool is_private = false;

	// Determines whether it is a public or private key.
	if (mbedtls_error != OK) {
		// Try to load as public key
		mbedtls_error = mbedtls_pk_parse_public_keyfile(&pk, key_path.utf8().get_data());
		if (mbedtls_error != OK) {
			mbedtls_pk_free(&pk);
			mbedtls_entropy_free(&entropy);
			mbedtls_ctr_drbg_free(&ctr_drbg);
			String _err = mbed_error_msn(mbedtls_error, "mbedtls_pk_parse_public_keyfile");
			ERR_FAIL_V_EDMSG(ret, String("Failed to parse public keyfile.: -0x") + String::num_int64(-mbedtls_error, 16) + _err);
		}
		ret["CATEGORY"] = "PUBLIC";
	} else {
		ret["CATEGORY"] = "PRIVATE";
		is_private = true;
	}

	// Get the key type and name
	mbedtls_pk_type_t pk_type = mbedtls_pk_get_type(&pk);
	const char *pk_name = mbedtls_pk_get_name(&pk);
	ret["NAME"] = String(pk_name);

	// Get the key size in bytes and bits
	ret["LENGTH"] = (int)mbedtls_pk_get_len(&pk);
	ret["BITS_LENGTH"] = (int)mbedtls_pk_get_bitlen(&pk);

	// Key Type
	mbedtls_pk_type_t key_type = mbedtls_pk_get_type(&pk);
	ret["TYPE"] = static_cast<PK_TYPE>(key_type);


	//====================================== ECP ====================================================
	if (
		static_cast<mbedtls_pk_type_t>(pk_type) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY ||
		static_cast<mbedtls_pk_type_t>(pk_type) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY_DH ||
		static_cast<mbedtls_pk_type_t>(pk_type) == mbedtls_pk_type_t::MBEDTLS_PK_ECDSA
	){

		// Get EC Context
		mbedtls_ecp_keypair *ec_key = mbedtls_pk_ec(pk);
		if (ec_key == NULL) {
			mbedtls_pk_free(&pk);
			mbedtls_entropy_free(&entropy);
			mbedtls_ctr_drbg_free(&ctr_drbg);
			mbedtls_ecp_keypair_free(ec_key);
			String _err = mbed_error_msn(mbedtls_error, "mbedtls_pk_ec");
			ERR_FAIL_V_EDMSG(ret, String("Invalid ECP Context: -0x") + String::num_int64(-mbedtls_error, 16) + _err);
		}

		// Get courve Info
		mbedtls_ecp_group *ecp_group = &ec_key->private_grp;
		mbedtls_ecp_curve_type curve_type = mbedtls_ecp_get_type(ecp_group);
		ret["CURVE_TYPE"] = curve_type;

		mbedtls_ecp_group_id grp_id = mbedtls_ecp_keypair_get_group_id(ec_key);
		const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_info_from_grp_id(grp_id);
		if (curve_info != NULL) {
			ret["CURVE"] = String(curve_info->name);
		} else {
			ret["CURVE"] = "Unknown";
		}

		if (is_private){
			mbedtls_error = mbedtls_ecp_check_privkey(&ec_key->private_grp, &ec_key->private_d);
			if (mbedtls_error != OK) {
				mbedtls_pk_free(&pk);
				mbedtls_entropy_free(&entropy);
				mbedtls_ctr_drbg_free(&ctr_drbg);
				mbedtls_ecp_keypair_free(ec_key);
				String _err = mbed_error_msn(mbedtls_error, "mbedtls_ecp_check_pubkey");
				ERR_FAIL_V_EDMSG(ret, String("Invalid EC private point: -0x") + String::num_int64(-mbedtls_error, 16) + _err);
			}
		}
		else{
			mbedtls_error = mbedtls_ecp_check_pubkey(&ec_key->private_grp, &ec_key->private_Q);
			if (mbedtls_error != OK) {
				mbedtls_pk_free(&pk);
				mbedtls_entropy_free(&entropy);
				mbedtls_ctr_drbg_free(&ctr_drbg);
				mbedtls_ecp_keypair_free(ec_key);
				String _err = mbed_error_msn(mbedtls_error, "mbedtls_ecp_check_pubkey");
				ERR_FAIL_V_EDMSG(ret, String("Invalid EC public point: -0x") + String::num_int64(-mbedtls_error, 16) + _err);
			}
		}

		// Get the X and Y coordinates
		mbedtls_mpi X, Y;
		mbedtls_mpi_init(&X);
		mbedtls_mpi_init(&Y);
		mbedtls_mpi_copy(&X, &ec_key->private_Q.private_X);
		mbedtls_mpi_copy(&Y, &ec_key->private_Q.private_Y);

		// Convert X and Y to hexadecimal strings
		char buffer[8192];
		size_t n;

		mbedtls_mpi_write_string(&X, 16, buffer, sizeof(buffer), &n);
		ret["X"] = String(buffer);

		mbedtls_mpi_write_string(&Y, 16, buffer, sizeof(buffer), &n);
		ret["Y"] = String(buffer);

		if (is_private) {
			// Get the private key 'd'
			mbedtls_mpi_write_string(&ec_key->private_d, 16, buffer, sizeof(buffer), &n);
			ret["d"] = String(buffer);
		}

		// Cleaning
		mbedtls_mpi_free(&X);
		mbedtls_mpi_free(&Y);
		mbedtls_ecp_keypair_free(ec_key);


	//====================================== RSA ====================================================
	} else if (
		static_cast<mbedtls_pk_type_t>(pk_type) == mbedtls_pk_type_t::MBEDTLS_PK_RSA ||
		static_cast<mbedtls_pk_type_t>(pk_type) == mbedtls_pk_type_t::MBEDTLS_PK_RSA_ALT ||
		static_cast<mbedtls_pk_type_t>(pk_type) == mbedtls_pk_type_t::MBEDTLS_PK_RSASSA_PSS
	) {

		// Get RSA Context
		mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
		if (rsa == NULL) {
			mbedtls_pk_free(&pk);
			mbedtls_entropy_free(&entropy);
			mbedtls_ctr_drbg_free(&ctr_drbg);
			mbedtls_rsa_free(rsa);
			String _err = mbed_error_msn(mbedtls_error, "mbedtls_pk_rsa");
			ERR_FAIL_V_EDMSG(ret, String("Invalid RSA Context: -0x") + String::num_int64(-mbedtls_error, 16) + _err);
		}


		mbedtls_rsa_free(rsa);

	//==========================================================================================


	} else {
		WARN_PRINT("Unsupported key type");
	}

	// Frees up resources.
	mbedtls_pk_free(&pk);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	return ret;
}







PackedByteArray Cripter::pk_sign(const String private_key_path, const PackedByteArray data, const String password){

	int mbedtls_erro;
	const char *pers = "pk_sign";
	PackedByteArray hash;
	PackedByteArray signature;
	const String key_path = ensure_global_path(private_key_path);

	hash.resize(HASH_SIZE_SHA_256);
	signature.resize(MBEDTLS_PK_SIGNATURE_MAX_SIZE);

	mbedtls_pk_context pk_key;
	mbedtls_md_context_t md_ctx;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_pk_init(&pk_key);
	mbedtls_md_init(&md_ctx);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);


	mbedtls_erro = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)) ;
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_md_free(&md_ctx);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_ctr_drbg_seed");
		ERR_FAIL_V_EDMSG(signature, String("Failed to seed the random generator: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}


	if (password.is_empty()){
		mbedtls_erro = mbedtls_pk_parse_keyfile( &pk_key, key_path.utf8().get_data(), nullptr, mbedtls_ctr_drbg_random, &ctr_drbg);
	}else{
		mbedtls_erro = mbedtls_pk_parse_keyfile(&pk_key, key_path.utf8().get_data(), password.utf8().get_data(), mbedtls_ctr_drbg_random, &ctr_drbg);
	}
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_md_free(&md_ctx);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_pk_parse_keyfile");
		ERR_FAIL_V_EDMSG(signature, String("Failed to parse key file.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}


	mbedtls_erro = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_md_free(&md_ctx);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_md_setup");
		ERR_FAIL_V_EDMSG(signature, String("Failed to selects the message digest algorithm.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_erro = mbedtls_md_starts(&md_ctx);
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_md_free(&md_ctx);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_md_starts");
		ERR_FAIL_V_EDMSG(signature, String("Failed to starts a message-digest computation..: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_erro =  mbedtls_md_update(&md_ctx, data.ptr(), data.size());
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_md_free(&md_ctx);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_md_update");
		ERR_FAIL_V_EDMSG(signature, String("Failed to feeds an input buffer.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_erro = mbedtls_md_finish(&md_ctx, hash.ptrw());
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_md_free(&md_ctx);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_md_finish");
		ERR_FAIL_V_EDMSG(signature, String("Failed to finishes the digest operation.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	size_t sig_len = signature.size();
	mbedtls_erro = mbedtls_pk_sign(&pk_key, MBEDTLS_MD_SHA256, hash.ptrw(), hash.size(),  signature.ptrw(), signature.size(), &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_md_free(&md_ctx);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_pk_sign");
		ERR_FAIL_V_EDMSG(signature, String("Failed to make signature.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_pk_free(&pk_key);
	mbedtls_md_free(&md_ctx);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);

	return signature;

}



Variant Cripter::pk_verify_signature(const String public_key_path, const PackedByteArray data, const String password){

	int mbedtls_erro;
	PackedByteArray signature;
	PackedByteArray hash;
	hash.resize(HASH_SIZE_SHA_256);

	mbedtls_pk_context pk_key;
	mbedtls_md_context_t md_ctx;

	mbedtls_md_init(&md_ctx);
	mbedtls_pk_init(&pk_key);

	const String key_path = ensure_global_path(public_key_path);

	mbedtls_erro = mbedtls_pk_parse_public_keyfile(&pk_key, key_path.utf8().get_data());
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_md_free(&md_ctx);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_pk_parse_public_keyfile");
		ERR_FAIL_V_EDMSG(signature, String("Failed to parse public keyfile.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_erro = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_md_free(&md_ctx);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_md_setup");
		ERR_FAIL_V_EDMSG(signature, String("Failed to selects the message digest algorithm.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_erro = mbedtls_md_starts(&md_ctx);
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_md_free(&md_ctx);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_md_starts");
		ERR_FAIL_V_EDMSG(signature, String("Failed to starts a message-digest computation..: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_erro =  mbedtls_md_update(&md_ctx, data.ptr(), data.size());
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_md_free(&md_ctx);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_md_update");
		ERR_FAIL_V_EDMSG(signature, String("Failed to feeds an input buffer.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_erro = mbedtls_md_finish(&md_ctx, hash.ptrw());
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_md_free(&md_ctx);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_md_finish");
		ERR_FAIL_V_EDMSG(signature, String("Failed to finishes the digest operation.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_erro = mbedtls_pk_verify(&pk_key, MBEDTLS_MD_SHA256, hash.ptr(), hash.size(), signature.ptr(), signature.size());
	mbedtls_pk_free(&pk_key);
	mbedtls_md_free(&md_ctx);

	if (mbedtls_erro == OK){
		return true;
	}

	return mbedtls_erro;

}



PackedByteArray Cripter::pk_encrypt(const PackedByteArray plaintext, const String p_public_key_path){

	size_t olen = plaintext.size();
	PackedByteArray output;
	output.resize(olen);
	int mbedtls_erro;
	const char *pers = "pk_encrypt";
	const String key_path = ensure_global_path(p_public_key_path);

	// Init Context
	mbedtls_pk_context pk_key;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_pk_init(&pk_key);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_erro = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)) ;
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_ctr_drbg_seed");
		ERR_FAIL_V_EDMSG(output, String("Failed to seed the random generator: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_erro = mbedtls_pk_parse_public_keyfile(&pk_key, key_path.utf8().get_data());
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_pk_parse_public_keyfile");
		ERR_FAIL_V_EDMSG(output, String("Failed to parse public keyfile.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	const size_t max_rsa_input_size = get_max_rsa_input_size(&pk_key);
	if (olen >= max_rsa_input_size){
		mbedtls_pk_free(&pk_key);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		ERR_FAIL_V_EDMSG(output, "The input data compliance exceeds the key capacity.");
	}

	mbedtls_erro = mbedtls_pk_encrypt(&pk_key, plaintext.ptr(), plaintext.size(), output.ptrw(), &olen, olen, mbedtls_ctr_drbg_random, &ctr_drbg);
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_pk_encrypt");
		ERR_FAIL_V_EDMSG(output, String("Failed to encrypt data.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_pk_free( &pk_key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return output;
}


PackedByteArray Cripter::pk_decrypt(const PackedByteArray ciphertext, const String p_private_key_path, const String password){

	const String key_path = ensure_global_path(p_private_key_path);
	int mbedtls_erro;

	size_t olen = ciphertext.size();
	PackedByteArray output;
	output.resize(olen);
	const char *pers = "pk_decrypt";


	// Init Context
	mbedtls_pk_context pk_key;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_pk_init(&pk_key);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);


	if (password.is_empty()){
		mbedtls_erro = mbedtls_pk_parse_keyfile(&pk_key, key_path.utf8().get_data(), nullptr, mbedtls_ctr_drbg_random, &ctr_drbg);
	}else{
		mbedtls_erro = mbedtls_pk_parse_keyfile(&pk_key, key_path.utf8().get_data(), password.utf8().get_data(), mbedtls_ctr_drbg_random, &ctr_drbg);
	}
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_pk_parse_keyfile");
		ERR_FAIL_V_EDMSG(output, String("Failed to parse key file.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}


	mbedtls_erro = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)) ;
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_ctr_drbg_seed");
		ERR_FAIL_V_EDMSG(output, String("Failed to seed the random generator: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_erro = mbedtls_pk_decrypt(&pk_key, ciphertext.ptr(), ciphertext.size(), output.ptrw(), &olen, olen, mbedtls_ctr_drbg_random, &ctr_drbg);
	if (mbedtls_erro != OK) {
		mbedtls_pk_free(&pk_key);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_pk_decrypt");
		ERR_FAIL_V_EDMSG(output, String("Failed to decrypt data.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_pk_free(&pk_key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return output;
}









// =============== UTILITIES ===============


PackedByteArray Cripter::generate_iv(const int iv_length, const String p_personalization) {

	ERR_FAIL_COND_V_MSG(iv_length <= 0, PackedByteArray(), "Invalid IV length.");
	//ERR_FAIL_COND_V_MSG(p_personalization.is_empty(), PackedByteArray(), "The IV personalization string cannot be empty.");

	PackedByteArray iv;
	iv.resize(iv_length);
	const char *personalization = p_personalization.utf8().get_data();

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	int mbedtls_erro = mbedtls_ctr_drbg_seed(&ctr_drbg,mbedtls_entropy_func, &entropy,(const unsigned char *)personalization, strlen(personalization));
	if (mbedtls_erro != OK) {
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_ctr_drbg_seed");
		ERR_FAIL_V_EDMSG(PackedByteArray(), String("Failed to seed the random generator: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_erro = mbedtls_ctr_drbg_random(&ctr_drbg, iv.ptrw(), iv.size());

	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);

	if (mbedtls_erro != OK) {
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_ctr_drbg_random");
		ERR_FAIL_V_EDMSG(PackedByteArray(),  String("Failed to generate IV: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	return iv;
}


// =============== HELPERS ===============

String Cripter::ensure_global_path(String  p_path){
	if (p_path.is_absolute_path()){
		return p_path;
	}
	else if (p_path.is_relative_path()){
		ProjectSettings &ps = *ProjectSettings::get_singleton();
		return ps.globalize_path(p_path);
	}
	else {
		return String();
	}
}


String Cripter::mbed_error_msn(int mbedtls_erro, const char* p_function){
	char mbedtls_erro_text[MBEDTLS_ERROR_BUFFER_LENGTH];
	mbedtls_strerror(mbedtls_erro, mbedtls_erro_text, MBEDTLS_ERROR_BUFFER_LENGTH);
	std::string s = std::to_string(mbedtls_erro);
	String ret = String::utf8("failed! mbedtls returned the error: ") + String::utf8(s.c_str()) + \
	String::utf8("\n - Function: ") + String::utf8(p_function) + String::utf8(" - Description: ") + String::utf8(mbedtls_erro_text);
	return ret;
}


std::vector<unsigned char> Cripter::byteArray_to_vector(const PackedByteArray &p_packed_array) {
	if (p_packed_array.is_empty()) {
		return std::vector<unsigned char>();
	}
	const unsigned char* data_ptr = p_packed_array.ptr();
	size_t data_size = p_packed_array.size();
	std::vector<unsigned char> byte_vector(data_ptr, data_ptr + data_size);
	return byte_vector;
}


std::vector<unsigned char> Cripter::GDstring_to_STDvector(const String p_string) {
	if (p_string.is_empty()) {
		return std::vector<unsigned char>();
	}
	const char* data = p_string.utf8().get_data();
	size_t size = p_string.size();
	const unsigned char* unsigned_data = reinterpret_cast<const unsigned char*>(data);
	std::vector<unsigned char> byte_vector(unsigned_data, unsigned_data + size);

	return byte_vector;
}


Error Cripter::add_pkcs7_padding(const std::vector<unsigned char>& data, std::vector<unsigned char>& padded_data, const size_t block_size) {
	if (block_size == 4 || block_size > 255) {
		return ERR_INVALID_PARAMETER;
	}

	size_t data_length = data.size();
	size_t padding_length = block_size - (data_length % block_size);
	if (padding_length == 0) {
		padding_length = block_size;
	}

	padded_data = data;
	padded_data.resize(data_length + padding_length, static_cast<unsigned char>(padding_length));

	return OK;
}


PackedByteArray Cripter::add_pkcs7_padding(PackedByteArray data, const size_t block_size) {
	PackedByteArray padded_data;

	if (block_size == 4 || block_size > 255) {
		WARN_PRINT("Invalid Padding");
		return padded_data;
	}

	size_t data_length = data.size();
	size_t padding_length = block_size - (data_length % block_size);
	if (padding_length == 0) {
		padding_length = block_size;
	}

	padded_data = data.duplicate();
	PackedByteArray padd;
	padd.resize(padding_length);
	padd.fill(padding_length);
	padded_data.append_array(padd);
	return padded_data;
}


Error Cripter::remove_pkcs7_padding(const std::vector<unsigned char>& padded_data, std::vector<unsigned char>& data, const size_t block_size) {
	if (padded_data.empty() || padded_data.size() % block_size != 0) {
		return ERR_INVALID_PARAMETER;
	}

	unsigned char padding_length = padded_data.back();

	if (padding_length == 0 || padding_length > block_size || padding_length > padded_data.size()) {
		return ERR_INVALID_DATA;
	}
	for (size_t i = padded_data.size() - padding_length; i < padded_data.size(); ++i) {
		if (padded_data[i] != padding_length) {
			return ERR_INVALID_DATA;
		}
	}

	data.assign(padded_data.begin(), padded_data.end() - padding_length);

	return OK;
}



PackedByteArray Cripter::remove_pkcs7_padding(PackedByteArray padded_data, const size_t block_size) {
	PackedByteArray data;

	if (padded_data.is_empty() || padded_data.size() % block_size != 0) {
		WARN_PRINT("Invalid Padding");
		return data;
	}

	const size_t padding_length = padded_data[padded_data.size() - 1];

	if (padding_length == 0 || padding_length > block_size || padding_length > (const size_t)padded_data.size()) {
		WARN_PRINT("Invalid Padding");
		return data;
	}

	data = padded_data.duplicate();
	data.resize(data.size() - padding_length);
	return data;
}


size_t Cripter::get_max_rsa_input_size(const mbedtls_pk_context *pk) {

	const mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*pk);
	size_t key_size_bytes = mbedtls_rsa_get_len(rsa);
	const int *padding = &rsa->MBEDTLS_PRIVATE(padding);
	const int *hash_id = &rsa->MBEDTLS_PRIVATE(hash_id);

	size_t hash_len = 0;
	switch (*hash_id) {
		case MBEDTLS_MD_NONE:       hash_len = 0; break;
		case MBEDTLS_MD_MD5:        hash_len = 16; break;
		case MBEDTLS_MD_SHA1:       hash_len = 20; break;
		case MBEDTLS_MD_SHA224:     hash_len = 28; break;
		case MBEDTLS_MD_SHA256:     hash_len = 32; break;
		case MBEDTLS_MD_SHA384:     hash_len = 48; break;
		case MBEDTLS_MD_SHA512:     hash_len = 64; break;
		case MBEDTLS_MD_RIPEMD160:  hash_len = 20; break;
		default:
			hash_len = (size_t)-1; break;
	}

	size_t max_data_size = 0;
	if (*padding == MBEDTLS_RSA_PKCS_V15) {
		max_data_size = key_size_bytes - 11; // PKCS#1 v1.5
	} else if (*padding == MBEDTLS_RSA_PKCS_V21) {
		max_data_size = key_size_bytes - 2 * hash_len - 2; // OAEP
	} else {
		return 0;
	}
	return max_data_size;
}



// =============== GODOT CLASS ===============

void Cripter::_bind_methods(){

	// Utilities
	ClassDB::bind_static_method("Cripter", D_METHOD("generate_iv", "iv length", "personalization"), &Cripter::generate_iv);
	ClassDB::bind_static_method("Cripter", D_METHOD("get_available_curves"), &Cripter::get_available_curves);


	// GCM
	ClassDB::bind_static_method("Cripter", D_METHOD("gcm_encrypt", "plaintext", "password", "iv", "aad", "key_length"), &Cripter::gcm_encrypt, DEFVAL(String()), DEFVAL(BITS_256));
	ClassDB::bind_static_method("Cripter", D_METHOD("gcm_decrypt", "ciphertext", "password", "iv", "tag", "aad", "key_length"), &Cripter::gcm_decrypt, DEFVAL(BITS_256));

	ClassDB::bind_method(D_METHOD("gcm_start_stream", "password", "iv", "mode", "keybits"), &Cripter::gcm_start_stream, DEFVAL(BITS_256));
	ClassDB::bind_method(D_METHOD("gcm_update_stream", "data", "in_chunk"), &Cripter::gcm_update_stream);
	ClassDB::bind_method(D_METHOD("gcm_stop_stream", "final_data"), &Cripter::gcm_stop_stream);


	// AES
	ClassDB::bind_static_method("Cripter", D_METHOD("aes_encrypt", "plaintext", "password", "iv_nonce", "algorith", "key_length"), &Cripter::aes_encrypt, DEFVAL(PackedByteArray()), DEFVAL(CBC), DEFVAL(BITS_256));
	ClassDB::bind_static_method("Cripter", D_METHOD("aes_decrypt", "ciphertext", "password", "iv_nonce", "algorith", "key_length"), &Cripter::aes_decrypt, DEFVAL(PackedByteArray()), DEFVAL(CBC), DEFVAL(BITS_256));

//	ClassDB::bind_method(D_METHOD("aes_start_stream"), &Cripter::aes_start_stream);
//	ClassDB::bind_method(D_METHOD("aes_update_stream"), &Cripter::aes_update_stream);
//	ClassDB::bind_method(D_METHOD("aes_stop_stream"), &Cripter::aes_stop_stream);

	// PK
	ClassDB::bind_static_method("Cripter",D_METHOD("pk_generate_keys", "algorithm_type", "key_size", "curve_name", "storage_format", "password", "private_key_filename", "public_key_filename", "personalization"), &Cripter::pk_generate_keys, DEFVAL("key_generation"));
	ClassDB::bind_static_method("Cripter", D_METHOD("pk_analyze_key", "key_path"), &Cripter::pk_analyze_key);
	ClassDB::bind_static_method("Cripter", D_METHOD("pk_match_keys", "private_key_path", "public_key_path", "password"), &Cripter::pk_match_keys, DEFVAL(""));

	ClassDB::bind_static_method("Cripter", D_METHOD("pk_encrypt", "plaintext", "key_path"), &Cripter::pk_encrypt);
	ClassDB::bind_static_method("Cripter", D_METHOD("pk_decrypt", "ciphertext", "key_path", "password"), &Cripter::pk_decrypt, DEFVAL(""));

	ClassDB::bind_static_method("Cripter", D_METHOD("pk_verify_signature", "private_key_path","data", "password"), &Cripter::pk_verify_signature, DEFVAL(""));
	ClassDB::bind_static_method("Cripter", D_METHOD("pk_sign", "public_key_path","data", "password"), &Cripter::pk_sign, DEFVAL(""));


	// Constants
	BIND_CONSTANT(GCM_TAG_SIZE);
	BIND_CONSTANT(AES_GCM_BLOCK_SIZE);

	// CryptMode
	BIND_ENUM_CONSTANT(DECRYPT);
	BIND_ENUM_CONSTANT(ENCRYPT);

	// FileFormat
	BIND_ENUM_CONSTANT(PEM);
	BIND_ENUM_CONSTANT(DER);

	// PK_TYPE
	BIND_ENUM_CONSTANT(MBEDTLS_PK_NONE);
	BIND_ENUM_CONSTANT(MBEDTLS_PK_RSA);
	BIND_ENUM_CONSTANT(MBEDTLS_PK_ECKEY);
	BIND_ENUM_CONSTANT(MBEDTLS_PK_ECKEY_DH);
	BIND_ENUM_CONSTANT(MBEDTLS_PK_ECDSA);
	BIND_ENUM_CONSTANT(MBEDTLS_PK_RSA_ALT);
	BIND_ENUM_CONSTANT(MBEDTLS_PK_RSASSA_PSS);

	// CURVE_TYPE
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_TYPE_NONE);
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS);
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_TYPE_MONTGOMERY);

	// ECP_GROUP_ID
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_DP_NONE);
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_DP_SECP192R1);
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_DP_SECP224R1);
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_DP_SECP256R1);
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_DP_SECP384R1);
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_DP_SECP521R1);
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_DP_BP256R1);
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_DP_BP384R1);
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_DP_BP512R1);
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_DP_CURVE25519);
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_DP_SECP192K1);
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_DP_SECP224K1);
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_DP_SECP256K1);
	BIND_ENUM_CONSTANT(MBEDTLS_ECP_DP_CURVE448);

	// Algorithm
	BIND_ENUM_CONSTANT(EBC);
	BIND_ENUM_CONSTANT(CBC);
	BIND_ENUM_CONSTANT(CFB128);
	BIND_ENUM_CONSTANT(CFB8);
	BIND_ENUM_CONSTANT(OFB);
	BIND_ENUM_CONSTANT(CTR);

	// KeySize
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


}



Cripter::Cripter(){
}

Cripter::~Cripter(){
}

/*cripter.cpp*/
