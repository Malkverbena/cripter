##	Small class to extend Crypter functions. 
##	With this class you can encrypt any data type without first having to encode it.
extends Cripter
class_name CripterVar


## Decrypt data using CBC algorithm.
func cbc_decrypt_var(cipher, password: String): 
	return bytes2var( cbc_decrypt(cipher, password) )


##	Encrypt data using CBC algorithm.
func cbc_encrypt_var(data, password: String) -> PackedByteArray: 
	return cbc_encrypt( var2bytes(data), password )


##	Decrypt data using GCM algorithm.
func gcm_decrypt_var(cipher: PackedByteArray, password: String, add: String = ""): 
	return bytes2var( gcm_decrypt(cipher, password, add) )


##	Decrypt data using GCM algorithm.
func gcm_encrypt_var(data, password: String, add: String = "") -> PackedByteArray: 
	return gcm_encrypt( var2bytes(data), password, add )


##	Decrypt data using RSA algorithm.  The path to keysmust be global. You can get it using  ProjectSettings.globalize_path()
func rsa_decrypt_var(cipher: PackedByteArray, public_key: String, Password: String = ""): 
	return bytes2var( rsa_decrypt(cipher, public_key, Password) )


##	Decrypt data using RSA algorithm. The path to keysmust be global. You can get it using  ProjectSettings.globalize_path()
func rsa_encrypt_var(data, private_key) -> PackedByteArray: 
	return rsa_encrypt(var2bytes(data), private_key) 
