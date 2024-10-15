/*cripter.cpp*/

#include "cripter.h"




String Cripter::mbed_error_msn(int mbedtls_erro, const char* p_function){
	char mbedtls_erro_text[256];
	mbedtls_strerror( mbedtls_erro, mbedtls_erro_text, sizeof(mbedtls_erro_text) );
	std::string s = std::to_string(mbedtls_erro);
	String ret = String::utf8("failed! mbedtls returned the error: ") + String::utf8(s.c_str()) + \
	String::utf8("\n - Function: ") + String::utf8(p_function) + String::utf8(" - Description: ") + String::utf8(mbedtls_erro_text);
	return ret;
}



void Cripter::_bind_methods(){
}



Cripter::Cripter(){
}

Cripter::~Cripter(){
}

/*cripter.cpp*/
