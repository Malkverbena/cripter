/*cripter.cpp*/

#include "cripter.h"




// =============== AES FUNCTION ===============


PackedByteArray Cripter::aes_encrypt(const PackedByteArray plaintext, const String p_password, PackedByteArray p_iv, Algorithm algorith,	KeySize keybits){

	std::vector<unsigned char> password = GDstring_to_STDvector(p_password);
	std::vector<unsigned char> input = byteArray_to_vector(plaintext);
	std::vector<unsigned char> iv = byteArray_to_vector(p_iv);

	std::vector<unsigned char> result = _aes_crypt(input, password, iv, algorith, keybits, MBEDTLS_AES_ENCRYPT);

	PackedByteArray ret;
	ret.resize(result.size());
	memcpy(ret.ptrw(), result.data(), result.size());

	return ret;
}


PackedByteArray Cripter::aes_decrypt(const PackedByteArray ciphertext, const String p_password, PackedByteArray p_iv, Algorithm algorith, KeySize keybits){

	std::vector<unsigned char> password = GDstring_to_STDvector(p_password);
	std::vector<unsigned char> input = byteArray_to_vector(ciphertext);
	std::vector<unsigned char> iv = byteArray_to_vector(p_iv);

	std::vector<unsigned char> result = _aes_crypt(input, password, iv, algorith, keybits, MBEDTLS_AES_DECRYPT);

	PackedByteArray ret;
	ret.resize(result.size());
	memcpy(ret.ptrw(), result.data(), result.size());

	return ret;
}


std::vector<unsigned char> Cripter::_aes_crypt(std::vector<unsigned char> input, std::vector<unsigned char> password, std::vector<unsigned char> iv, Algorithm algorith, Cripter::KeySize keybits, int mode){

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

	std::vector<unsigned char> output;

	if (iv.size() != AES_BLOCK_SIZE){
		WARN_PRINT("The IV size must be AES_BLOCK_SIZE for AES encryption.");
		return output;
	}

	int mbedtls_erro;
	mbedtls_aes_context aes_ctx;
	mbedtls_aes_init(&aes_ctx);
	output.resize(input.size());

	mbedtls_erro = mbedtls_aes_setkey_enc(&aes_ctx, password.data(), keybits);
	if (mbedtls_erro != OK){
		mbedtls_aes_free(&aes_ctx);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_aes_setkey_enc");
		WARN_PRINT(String("Failed to configure AES key.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
		return output;
	};

	switch (algorith) {

		case EBC: {
			mbedtls_erro = mbedtls_aes_crypt_ecb(&aes_ctx, mode, input.data(), output.data());
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
				if (add_pkcs7_padding(input, input, AES_BLOCK_SIZE) != OK){
					WARN_PRINT(String("Invalid parameter. AES block must be 16 Bytes."));
					mbedtls_aes_free(&aes_ctx);
					return output;
				}
			}

			unsigned char iv_copy[16];
			memcpy(iv_copy, iv.data(), 16);

			mbedtls_erro = mbedtls_aes_crypt_cbc(&aes_ctx, mode, input.size(), iv_copy, input.data(), output.data());
			mbedtls_aes_free(&aes_ctx);

			if (mbedtls_erro != OK){
				mbedtls_aes_free(&aes_ctx);
				String _err = mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_cbc");
				WARN_PRINT(String("CBC Encryption error: -0x%04x\n") + String::num_int64(-mbedtls_erro, 16) + _err);
				return output;
			}

			if (mode == MBEDTLS_AES_DECRYPT){
				Error _err = remove_pkcs7_padding(output, output, AES_BLOCK_SIZE);
				if ( _err == ERR_INVALID_PARAMETER){
					WARN_PRINT("Block size out of parameter.");
				}
				else if(_err == ERR_INVALID_DATA){
					WARN_PRINT(String("Input buffer contains invalid Padding."));
				}
			}
			return output;
		}
		break;


		case CFB128:{
			unsigned char iv_copy[16];
			memcpy(iv_copy, iv.data(), 16);
			size_t iv_off = 0;

			mbedtls_erro = mbedtls_aes_crypt_cfb128(&aes_ctx, mode, input.size(), &iv_off, iv_copy, input.data(), output.data());
			mbedtls_aes_free(&aes_ctx);

			if (mbedtls_erro != OK){
				String _err = mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_cfb128");
				WARN_PRINT(String("CFB128 Encryption error: -0x%04x\n") + String::num_int64(-mbedtls_erro, 16) + _err);
			}
			return output;
		}
		break;


		case CFB8:{
			unsigned char iv_copy[16];
			memcpy(iv_copy, iv.data(), 16);

			mbedtls_erro = mbedtls_aes_crypt_cfb8(&aes_ctx, mode, input.size(), iv_copy, input.data(), output.data());
			mbedtls_aes_free(&aes_ctx);
			if (mbedtls_erro != OK){
				String _err = mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_cfb8");
				WARN_PRINT(String("CFB8 Encryption error: -0x%04x\n") + String::num_int64(-mbedtls_erro, 16) + _err);
			}
			return output;
		}
		break;


		case OFB:{
			unsigned char iv_copy[16];
			memcpy(iv_copy, iv.data(), 16);
			size_t iv_off = 0;

			mbedtls_erro = mbedtls_aes_crypt_ofb(&aes_ctx, input.size(), &iv_off, iv_copy, input.data(), output.data());
			mbedtls_aes_free(&aes_ctx);
			if (mbedtls_erro != OK){
				String _err = mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_ofb");
				WARN_PRINT(String("OFB Encryption error: -0x%04x\n") + String::num_int64(-mbedtls_erro, 16) + _err);
			}
			return output;

		}
		break;

		case CTR: {
			unsigned char nonce_counter[16];
			memcpy(nonce_counter, iv.data(), 16);
			unsigned char stream_block[16];
			memset(stream_block, 0, 16);
			size_t nc_off = 0;

			mbedtls_erro = mbedtls_aes_crypt_ctr(&aes_ctx, input.size(), &nc_off, nonce_counter, stream_block, input.data(), output.data());
			mbedtls_aes_free(&aes_ctx);
			if (mbedtls_erro != OK){
				String _err = mbed_error_msn(mbedtls_erro, "mbedtls_aes_crypt_ctr");
				WARN_PRINT(String("CTR Encryption error: -0x%04x\n") + String::num_int64(-mbedtls_erro, 16) + _err);
			}
			return output;
		}
		break;



	}; // switch case

}






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


// =============== ASYMMETRIC ===============

PackedStringArray Cripter::get_available_curves() {
	PackedStringArray curve_names;
	const mbedtls_ecp_curve_info* curve_info = mbedtls_ecp_curve_list();
	while (curve_info != NULL && curve_info->name != NULL) {
		curve_names.append(String(curve_info->name));
		curve_info++;
	}
	return curve_names;
}

Error Cripter::generate_pk_keys(
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
	unsigned char pri_output_buf[16000];
	unsigned char pub_output_buf[16000];
	int pk_key_type;
	int mbedtls_erro = 0;
	const char* pers = personalization.utf8().get_data();

	mbedtls_pk_type_t algorithm = static_cast<mbedtls_pk_type_t>(algorithm_type);
	mbedtls_pk_context pk_key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;


	// Init Variables
	memset(pri_output_buf, 0, sizeof(pri_output_buf));
	memset(pub_output_buf, 0, sizeof(pub_output_buf));
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
		mbedtls_erro = mbedtls_pk_write_key_pem(&pk_key, pri_output_buf, sizeof(pri_output_buf));
		if (mbedtls_erro != OK){
			mbedtls_pk_free(&pk_key);
			mbedtls_ctr_drbg_free(&ctr_drbg);
			mbedtls_entropy_free(&entropy);
			ERR_FAIL_V_MSG(FAILED, mbed_error_msn(mbedtls_erro, "mbedtls_pk_write_key_pem"));
		}

		mbedtls_erro = mbedtls_pk_write_pubkey_pem(&pk_key, pub_output_buf, sizeof(pub_output_buf));
		if (mbedtls_erro != OK){
			mbedtls_pk_free(&pk_key);
			mbedtls_ctr_drbg_free(&ctr_drbg);
			mbedtls_entropy_free(&entropy);
			ERR_FAIL_V_MSG(FAILED, mbed_error_msn(mbedtls_erro, "mbedtls_pk_write_pubkey_pem"));
		}
	} 

	// DER 
	else if (storage_format == DER){
		mbedtls_erro = mbedtls_pk_write_key_der(&pk_key, pri_output_buf, sizeof(pri_output_buf));
		if (mbedtls_erro != OK){
			mbedtls_pk_free(&pk_key);
			mbedtls_ctr_drbg_free(&ctr_drbg);
			mbedtls_entropy_free(&entropy);
			ERR_FAIL_V_MSG(FAILED, mbed_error_msn(mbedtls_erro, "mbedtls_pk_write_key_pem"));
		}

		mbedtls_erro = mbedtls_pk_write_pubkey_der(&pk_key, pub_output_buf, sizeof(pub_output_buf));
		if (mbedtls_erro != OK){
			mbedtls_pk_free(&pk_key);
			mbedtls_ctr_drbg_free(&ctr_drbg);
			mbedtls_entropy_free(&entropy);
			ERR_FAIL_V_MSG(FAILED, mbed_error_msn(mbedtls_erro, "mbedtls_pk_write_pubkey_pem"));
		}
	}

	// Write files ====

	// Private
	Ref<FileAccess> f_private = FileAccess::open(private_key_filename, FileAccess::WRITE);
	ERR_FAIL_COND_V_MSG(f_private.is_null(), ERR_INVALID_PARAMETER, "Cannot save private RSA key to file: '" + private_key_filename + "'.");
	size_t pri_len = strlen((char *)pri_output_buf);
	f_private->store_buffer(pri_output_buf, pri_len);
	mbedtls_platform_zeroize(pri_output_buf, sizeof(pri_output_buf));

	// Public
	Ref<FileAccess> f_public = FileAccess::open(public_key_filename, FileAccess::WRITE);
	ERR_FAIL_COND_V_MSG(f_public.is_null(), ERR_INVALID_PARAMETER, "Cannot save public RSA key to file: '" + public_key_filename + "'.");
	size_t pub_len = strlen((char *)pub_output_buf);
	f_public->store_buffer(pub_output_buf, pub_len);
	mbedtls_platform_zeroize(pub_output_buf, sizeof(pub_output_buf));

	// Clean up
    mbedtls_pk_free(&pk_key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

	return OK;

}




Dictionary Cripter::analyze_pk_key(String p_key_path) {

	Dictionary ret;
	int mbedtls_error = 0;
	const char *pers = "pk_parse_key";

	mbedtls_pk_context pk;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_pk_init(&pk);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);


	mbedtls_error = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, reinterpret_cast<const unsigned char*>(pers), strlen(pers));
	if (mbedtls_error != 0) {
		mbedtls_pk_free(&pk);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		String _err = mbed_error_msn(mbedtls_error, "mbedtls_ctr_drbg_seed");
		ERR_FAIL_V_EDMSG(ret, String("Failed to seed random number generator: -0x") + String::num_int64(-mbedtls_error, 16) + _err);
	}

	// Try to load as private key
	const char *key_path = p_key_path.utf8().get_data();
	mbedtls_error = mbedtls_pk_parse_keyfile(&pk, key_path, nullptr, mbedtls_ctr_drbg_random, &ctr_drbg);
	bool is_private = false;

	// Determines whether it is a public or private key.
	if (mbedtls_error != 0) {
		// Try to load as public key
		mbedtls_error = mbedtls_pk_parse_public_keyfile(&pk, key_path);
		if (mbedtls_error != 0) {
			mbedtls_pk_free(&pk);
			mbedtls_entropy_free(&entropy);
			mbedtls_ctr_drbg_free(&ctr_drbg);
			String _err = mbed_error_msn(mbedtls_error, "mbedtls_pk_parse_public_keyfile");
			ERR_FAIL_V_EDMSG(ret, String("Failed to load key.: -0x") + String::num_int64(-mbedtls_error, 16) + _err);
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


	// Processes EC keys.
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
			if (mbedtls_error != 0) {
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
			if (mbedtls_error != 0) {
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


//==========================================================================================


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



// =============== UTILITIES ===============


PackedByteArray Cripter::generate_iv(const int iv_length, const String p_personalization) {

	ERR_FAIL_COND_V_MSG(iv_length <= 0, PackedByteArray(), "Invalid IV length.");
	ERR_FAIL_COND_V_MSG(p_personalization.is_empty(), PackedByteArray(), "The IV personalization string cannot be empty.");

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


String Cripter::derive_key_pbkdf2(const String p_password, const String p_salt, int iterations, int key_length) {
	ERR_FAIL_COND_V_MSG(iterations <= 0, String(""), "Number of iterations must be positive.");
	ERR_FAIL_COND_V_MSG(key_length <= 0, String(""), "Key size must be positive.");

	const unsigned char *password = (const unsigned char *)(p_password.utf8().get_data());
	const unsigned char *salt = (const unsigned char *)(p_salt.utf8().get_data());
	unsigned char derived_key[key_length];
	size_t password_len = p_password.utf8().size();
	size_t salt_len = p_salt.utf8().size();

	int mbedtls_erro = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, password, password_len, salt, salt_len, iterations, key_length, derived_key);
	if (mbedtls_erro != OK) {
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_ctr_drbg_random");
		ERR_FAIL_V_EDMSG(String(""),  String("Failed to generate IV: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	String ret_derived_key = String((const char *)derived_key);
	return ret_derived_key;
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


Error Cripter::add_pkcs7_padding(const std::vector<unsigned char>& data, std::vector<unsigned char>& padded_data, size_t block_size) {
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


Error Cripter::remove_pkcs7_padding(const std::vector<unsigned char>& padded_data, std::vector<unsigned char>& data, size_t block_size) {
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



// =============== GODOT CLASS ===============

void Cripter::_bind_methods(){

	// Utilities
	ClassDB::bind_static_method("Cripter", D_METHOD("generate_iv", "iv length", "personalization"), &Cripter::generate_iv);
	ClassDB::bind_static_method("Cripter", D_METHOD("derive_key_pbkdf2", "password", "salt", "iterations", "key_length"), &Cripter::derive_key_pbkdf2, DEFVAL(500), DEFVAL(16));
	ClassDB::bind_static_method("Cripter", D_METHOD("get_available_curves"), &Cripter::get_available_curves);


	// GCM
	ClassDB::bind_static_method("Cripter", D_METHOD("gcm_encrypt", "plaintext", "password", "iv", "aad", "key_length"), &Cripter::gcm_encrypt, DEFVAL(String()), DEFVAL(BITS_256));
	ClassDB::bind_static_method("Cripter", D_METHOD("gcm_decrypt", "ciphertext", "password", "iv", "tag", "aad", "key_length"), &Cripter::gcm_decrypt, DEFVAL(BITS_256));
	// Streaming IN
	// Streaming OUT


	// AES
	ClassDB::bind_static_method("Cripter", D_METHOD("aes_encrypt", "plaintext", "password", "iv_nonce", "algorith", "key_length"), &Cripter::aes_encrypt, DEFVAL(PackedByteArray()), DEFVAL(CBC), DEFVAL(BITS_256));
	ClassDB::bind_static_method("Cripter", D_METHOD("aes_decrypt", "ciphertext", "password", "iv_nonce", "algorith", "key_length"), &Cripter::aes_encrypt, DEFVAL(PackedByteArray()), DEFVAL(CBC), DEFVAL(BITS_256));
	// Streaming IN
	// Streaming OUT


	// PK
	ClassDB::bind_static_method("Cripter",D_METHOD("generate_pk_keys", "algorithm_type", "key_size", "curve_name", "storage_format", "password", "private_key_filename", "public_key_filename", "personalization"), &Cripter::generate_pk_keys, DEFVAL("key_generation"));
	ClassDB::bind_static_method("Cripter", D_METHOD("analyze_pk_key", "key_path"), &Cripter::analyze_pk_key);
	// Compare keys
	// Encrypt
	// Decript



	BIND_CONSTANT(GCM_TAG_SIZE);
	BIND_CONSTANT(AES_BLOCK_SIZE);


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
	BIND_ENUM_CONSTANT(XTS);
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
