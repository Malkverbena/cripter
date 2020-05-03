tool
extends Panel

"""
This module allows you to encrypt and decrypt both variants and binaries for convenience and performance.

THE KEY PAIRS FOR THIS DEMO WERE CREATED USING THE FOLLOWING COMMANDS:
ssh-keygen -t rsa -b 4096 -C "cripter_exemple"
ssh-keygen -f id_rsa.pub -m 'PEM' -e > id_rsa.pem
"""

var encripter = cripter.new()

#########  RSA CREDENTIALS  #########
#---You must use an absolute path here, otherwise the module will not find the keys folder.
#---Set the path here or on editor.
""" IT WON'T WORK IF YOU DO NOT SET THE PATH CORRECTLY!!!!!! """
export(String, DIR, GLOBAL) var path_keys := "/home/myself/godot_project/cripter/certs"  

var rsa_password := "cripter_exemple"
var rsa_public_key_path := path_keys + "/id_rsa.pem"
var rsa_private_key_path := path_keys + "/id_rsa"


#########  OTHER CREDENTIALS  #########
var key = "My not secret key"
var gcm_add = "adicional data is port 316 or maybe not"


func _ready():

	#########  DATA TO ENCRYPT
	var gcm_input = var2bytes("The cow goes muuuu")
	var cbc_input = var2bytes("The cat goes mewwwww")
	var rsa_input = var2bytes("The pig goes oink oink")

	var gcm_var = [234, "ub", {"k":34, "revt":"3e4r", "kjh":Vector3(70,3,5), [5,"ert", Vector2(0,9)]:Basis() }, true, Color(1.4,2.3,3.2,4.1)]
	var cbc_var = {"cxv":[345,"vgdf", Vector2(7,0)], "xcv":"6546", "123dfg":5.96}
	var rsa_var = {"ff":[4,"sdfsdf","sdfsdf",{"cd":456, "hh":Vector3(45,2,84.1)}, 0.14, ["fgf",456,14.02]], 78:4234, "8ug":Vector2(3.8,8.4)}


	######### LET'S WORK!!!
	$Label.text = "Encrypt/Decrypt bytes: \n"
	print("#---Encrypt/Decrypt bytes GCM")
	var encrypted_array_gcm = encripter.encrypt_byte_GCM(gcm_input, key, gcm_add)
	var decrypted_array_gcm = encripter.decrypt_byte_GCM(encrypted_array_gcm, key, gcm_add) 
	print("\n", bytes2var(decrypted_array_gcm))
	$Label.text = $Label.text + "\n GCM:  " + str(bytes2var(decrypted_array_gcm))


	print("#---Encrypt/Decrypt bytes CBC")
	var encrypted_array_cbc = encripter.encrypt_byte_CBC(cbc_input, key)
	var decrypted_array_cbc = encripter.decrypt_byte_CBC(encrypted_array_cbc, key)
	print("\n", bytes2var(decrypted_array_cbc))
	$Label.text = $Label.text + "\n CBC:  " + str(bytes2var(decrypted_array_cbc))


	print("#---Encrypt/Decrypt bytes RSA")
	var encrypted_array_rsa = encripter.encrypt_byte_RSA(rsa_input, rsa_public_key_path) #---Using public key
	var decrypted_array_rsa = encripter.decrypt_byte_RSA(encrypted_array_rsa, rsa_private_key_path, rsa_password) #---Using private key
	print("\n", bytes2var(decrypted_array_rsa)) 
	$Label.text = $Label.text + "\n RSA:  " + str(bytes2var(decrypted_array_rsa))


	$Label.text = $Label.text + "\n\n\nEncrypt/Decrypt Variants \n"
	print("#---Encrypt/Decrypt Var CBC")
	var encrypted_var_cbc = encripter.encrypt_var_CBC(cbc_var, key)
	var decrypted_var_cbc = encripter.decrypt_var_CBC(encrypted_var_cbc, key)
	print("\n", decrypted_var_cbc)
	$Label.text = $Label.text + "\n CBC:  " + str(decrypted_var_cbc)


	print("#---Encrypt/Decrypt Var GCM")
	var encrypted_var_gcm = encripter.encrypt_var_GCM(gcm_var, key, gcm_add)
	var decrypted_var_gcm = encripter.decrypt_var_GCM(encrypted_var_gcm, key, gcm_add) 
	print("\n", decrypted_var_gcm)
	$Label.text = $Label.text + "\n GCM:  " + str(decrypted_var_gcm)


	print("#---Encrypt/Decrypt Var RSA")
	var encrypted_var_rsa = encripter.encrypt_var_RSA(rsa_var, rsa_public_key_path) #---Using public key
	var decrypted_var_rsa = encripter.decrypt_var_RSA(encrypted_var_rsa, rsa_private_key_path, rsa_password) #---Using private key
	print("\n", decrypted_var_rsa) 
	$Label.text = $Label.text + "\n RSA:  " + str(decrypted_var_rsa)



func _on_Button_pressed():
	get_tree().quit()
