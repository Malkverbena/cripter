/*cripter.cpp*/

#include "cripter.h"



// =============== GCM FUNCTION =============== 



Dictionary Cripter::gcm_encrypt(
	const PackedByteArray &plaintext,
	const String &p_password,
	const PackedByteArray &iv,
	const String &p_aad,
	Cripter::KeySize p_keybits
	){

	if (p_keybits < BITS_128){
		WARN_PRINT("GCM Algorithm only accepts key with 128, 192, or 256 bits");
		p_keybits = Cripter::BITS_128;
	}
	if (p_keybits > BITS_256){
		WARN_PRINT("GCM Algorithm only accepts key with 128, 192, or 256 bits");
		p_keybits = Cripter::BITS_256;
	}

	mbedtls_gcm_context gcm_ctx;
	mbedtls_gcm_init(&gcm_ctx);
	unsigned char tag[16];
	unsigned char * password = (unsigned char *)(p_password.utf8().get_data());
	unsigned char * aad = (unsigned char *)(p_aad.utf8().get_data());
	size_t aad_len = p_aad.size();
	size_t plaintext_len = plaintext.size();
	PackedByteArray output;
	output.resize(plaintext_len);

	int mbedtls_erro = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, password, p_keybits);
	if (mbedtls_erro != OK) {
		mbedtls_gcm_free(&gcm_ctx);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_gcm_setkey");
		ERR_FAIL_V_EDMSG(Dictionary(), String("Failed to configure GCM key.: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_erro = mbedtls_gcm_crypt_and_tag(
		&gcm_ctx, MBEDTLS_GCM_ENCRYPT, plaintext_len,
		iv.ptr(), iv.size(),
		aad, aad_len,
		plaintext.ptr(), output.ptrw(),
		sizeof(tag), tag
	);

	mbedtls_gcm_free(&gcm_ctx);

	if (mbedtls_erro != OK) {
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_gcm_crypt_and_tag");
		ERR_FAIL_V_EDMSG(Dictionary(), String("Encryption error. : -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	String str_tag = String((const char *)tag);
	Dictionary ret;
	ret["Tag"] = str_tag;
	ret["Ciphertext"] = output;
	return ret;
}


Dictionary Cripter::gcm_decrypt(
	const PackedByteArray &ciphertext,
	const String &p_password,
	const PackedByteArray &iv,
	const String &p_aad,
	const PackedByteArray &p_tag,
	Cripter::KeySize p_keybits
	) {

	if (p_keybits < BITS_128) {
		WARN_PRINT("GCM Algorithm only accepts key with 128, 192, or 256 bits");
		p_keybits = Cripter::BITS_128;
	}
	if (p_keybits > BITS_256) {
		WARN_PRINT("GCM Algorithm only accepts key with 128, 192, or 256 bits");
		p_keybits = Cripter::BITS_256;
	}

	mbedtls_gcm_context gcm_ctx;
	mbedtls_gcm_init(&gcm_ctx);

	unsigned char *password = (unsigned char *)(p_password.utf8().get_data());
	unsigned char *aad = (unsigned char *)(p_aad.utf8().get_data());
	size_t aad_len = p_aad.size();
	size_t ciphertext_len = ciphertext.size();
	size_t tag_len = p_tag.size();
	PackedByteArray output;
	output.resize(ciphertext_len);

	// Configuração da chave GCM
	int mbedtls_erro = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, password, p_keybits);
	if (mbedtls_erro != 0) {
		mbedtls_gcm_free(&gcm_ctx);
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_gcm_setkey");
		ERR_FAIL_V_EDMSG(Dictionary(), String("Failed to configure GCM key: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	mbedtls_erro = mbedtls_gcm_auth_decrypt(&gcm_ctx, ciphertext_len, iv.ptr(), iv.size(), aad, aad_len, p_tag.ptr(), tag_len, ciphertext.ptr(), output.ptrw());

	mbedtls_gcm_free(&gcm_ctx);

	if (mbedtls_erro != 0) {
		String _err = mbed_error_msn(mbedtls_erro, "mbedtls_gcm_auth_decrypt");
		ERR_FAIL_V_EDMSG(Dictionary(), String("Decryption error: -0x") + String::num_int64(-mbedtls_erro, 16) + _err);
	}

	Dictionary ret;
	ret["Plaintext"] = output;
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

	int mbedtls_erro = mbedtls_ctr_drbg_seed(
				&ctr_drbg,
				mbedtls_entropy_func,
				&entropy,
				(const unsigned char *)personalization,
				strlen(personalization)
	);

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


String Cripter::mbed_error_msn(int mbedtls_erro, const char* p_function){
	char mbedtls_erro_text[256];
	mbedtls_strerror( mbedtls_erro, mbedtls_erro_text, sizeof(mbedtls_erro_text) );
	std::string s = std::to_string(mbedtls_erro);
	String ret = String::utf8("failed! mbedtls returned the error: ") + String::utf8(s.c_str()) + \
	String::utf8("\n - Function: ") + String::utf8(p_function) + String::utf8(" - Description: ") + String::utf8(mbedtls_erro_text);
	return ret;
}




// =============== GODOT CLASS =============== 

void Cripter::_bind_methods(){

	ClassDB::bind_static_method("Cripter", D_METHOD("generate_iv", "iv length", "personalization"), &Cripter::generate_iv);
	ClassDB::bind_static_method("Cripter", D_METHOD("derive_key_pbkdf2", "password", "salt", "iterations", "key_length"), &Cripter::derive_key_pbkdf2, DEFVAL(500), DEFVAL(16));

	ClassDB::bind_static_method("Cripter", D_METHOD("gcm_encrypt", "plaintext", "password", "IV", "AAD", "keybits"), &Cripter::gcm_encrypt, DEFVAL(String()), DEFVAL(BITS_256));
	ClassDB::bind_static_method("Cripter", D_METHOD("gcm_decrypt", "ciphertext", "password", "IV", "AAD", "tag", "keybits"), &Cripter::gcm_decrypt, DEFVAL(BITS_256));



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
