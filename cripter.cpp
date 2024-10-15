/*cripter.cpp*/

#include "cripter.h"






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
}



Cripter::Cripter(){
}

Cripter::~Cripter(){
}

/*cripter.cpp*/
