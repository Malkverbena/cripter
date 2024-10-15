/*cripter.h*/
#ifndef CRIPTER_H
#define CRIPTER_H


#include <core/config/project_settings.h>
#include "core/object/ref_counted.h"
#include "core/core_bind.h"


#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/gcm.h>
#include <mbedtls/pk.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/md.h> 
#include <mbedtls/error.h>




class Cripter : public RefCounted{
	GDCLASS(Cripter, RefCounted);



private:

	static String mbed_error_msn(int mbedtls_erro, const char* p_function);



protected:

	static void _bind_methods();


public:


	Cripter();
	~Cripter();

};



#endif 
/*cripter.h*/
