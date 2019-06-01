extends Node


#----Cripter usage:

func _ready():

	var Cripte = cripter.new()
	
	var key = "My not secret key"

	#---Must be an absolut path 
	var rsa_public_key_path = "/home/cleber/certs/id_rsa.pem"
	var rsa_private_key_path = "/home/cleber/certs/id_rsa"
	var rsa_password = "mypass"

	var gcm_add = "adicional data is: port: 316"
	
	var gcm_input = var2bytes("The cow goes muuuu")
	var cbc_input = var2bytes("The cat goes mewwwww")
	var rsa_input = var2bytes("The pig goes oink oink")
	
	var gcm_var = [234, "ub", {"k":34, "revt":"3e4r", "kjh":Vector3(70,3,5), [5,"ert", Vector2(0,9)]:Basis() }, true, Color(1.4,2.3,3.2,4.1)]
	var cbc_var = {"cxv":[345,"vgdf", Vector2(7,0)], "xcv":"6546", "123dfg":5.96}
	var rsa_var = {"ff":[4,"sdfsdf","sdfsdf",{"cd":456, "hh":Vector3(45,2,84.1)}, 0.14, ["fgf",456,14.02]], 78:4234, "8ug":Vector2(3.8,8.4)}
	
	print("\n \n \n#---Encrypt/Decrypt bytes GCM")
#-------------------------------------------------------------------
	var encrypted_array_gcm = Cripte.encrypt_byte_GCM(gcm_input, key, gcm_add)
	var decrypted_array_gcm = Cripte.decrypt_byte_GCM(encrypted_array_gcm, key, gcm_add) 
	print("\n", bytes2var(decrypted_array_gcm))


	print("\n \n \n#---Encrypt/Decrypt bytes CBC")
#-------------------------------------------------------------------
	var encrypted_array_cbc = Cripte.encrypt_byte_CBC(cbc_input, key)
	var decrypted_array_cbc = Cripte.decrypt_byte_CBC(encrypted_array_cbc, key)
	print("\n", bytes2var(decrypted_array_cbc))
	
	
	print("\n \n \n#---Encrypt/Decrypt bytes RSA")
#-------------------------------------------------------------------
	var encrypted_array_rsa = Cripte.encrypt_byte_RSA(rsa_input, rsa_public_key_path) #---Using public key
	var decrypted_array_rsa = Cripte.decrypt_byte_RSA(encrypted_array_rsa, rsa_private_key_path, rsa_password) #---Using private key
#	print("\n", bytes2var(decrypted_array_rsa)) 
	
	
	print("\n \n \n#---Encrypt/Decrypt Var CBC")
#-------------------------------------------------------------------
	var encrypted_var_cbc = Cripte.encrypt_var_CBC(cbc_var, key)
	var decrypted_var_cbc = Cripte.decrypt_var_CBC(encrypted_var_cbc, key)
	print("\n", decrypted_var_cbc)
	
	
	
	print("\n \n \n#---Encrypt/Decrypt Var GCM")
#-------------------------------------------------------------------
	var encrypted_var_gcm = Cripte.encrypt_var_GCM(gcm_var, key, gcm_add)
	var decrypted_var_gcm = Cripte.decrypt_var_GCM(encrypted_var_gcm, key, gcm_add) 
	print("\n", decrypted_var_gcm)


	print("\n \n \n#---Encrypt/Decrypt Var RSA")
#-------------------------------------------------------------------
	var encrypted_var_rsa = Cripte.encrypt_var_RSA(rsa_var, rsa_public_key_path) #---Using public key
	var decrypted_var_rsa = Cripte.decrypt_var_RSA(encrypted_var_rsa, rsa_private_key_path, rsa_password) #---Using private key
#	print("\n", decrypted_var_rsa) 


	print("\n")
#	get_tree().quit()
