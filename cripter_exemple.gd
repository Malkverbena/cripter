extends Node

#----Cripter usage:

func _ready():

	var Cripte = cripter.new()
	
	var key = "My not secret key"
	var gcm_add = "abc"
	
	var gcm_input = var2bytes("the cow goes muuuu")
	var cbc_input = var2bytes("The cat goes mewwwww")
	
	var gcm_var = [234, "ub", {"k":34, "revt":"3e4r", "kjh":Vector2(3,5) }, true, Color(1.4,2.3,3.2,4.1)]
	var cbc_var = {"cxv":[345,"vgdf", Vector2(7,0)], "xcv":"6546", "123dfg":5.96}
	
	
	
	#---Encrypt/Decrypt bytes GCM
#-------------------------------------------------------------------
	var encrypted_array_gcm = Cripte.encrypt_byte_aes_GCM(gcm_input, key, gcm_add)
	var gcm_tag = encrypted_array_gcm[1]
	var decrypted_array_gcm = Cripte.decrypt_byte_aes_GCM(encrypted_array_gcm[0], key, gcm_tag, gcm_add) 
	print("\n", bytes2var(decrypted_array_gcm))


	#---Encrypt/Decrypt bytes CBC
#-------------------------------------------------------------------
	var encrypted_array_cbc = Cripte.encrypt_byte_aes_CBC(cbc_input, key)
	var decrypted_array_cbc = Cripte.decrypt_byte_aes_CBC(encrypted_array_cbc, key)
	print("\n", bytes2var(decrypted_array_cbc))
	
	
		
	#---Encrypt/Decrypt Var CBC
#-------------------------------------------------------------------
	var encrypted_var_cbc = Cripte.encrypt_var_aes_CBC(cbc_var, key)
	var decrypted_var_cbc = Cripte.decrypt_var_aes_CBC(encrypted_var_cbc, key)
	print("\n", decrypted_var_cbc)
	
	
	
	#---Encrypt/Decrypt Var GCM
#-------------------------------------------------------------------
	var encrypted_var_gcm = Cripte.encrypt_var_aes_GCM(gcm_var, key, gcm_add)
	var gcm_var_tag = encrypted_var_gcm[1]
	var decrypted_var_gcm = Cripte.decrypt_var_aes_GCM(encrypted_var_gcm[0], key, gcm_var_tag, gcm_add) 
	print("\n", decrypted_var_gcm)



	print("\n")
	get_tree().quit()
