extends Node

var encripter = Cripter.new()

var key = "My not secret key"
var gcm_add = "adicional data is port 316 or maybe not"
var to_encr = [234, "ub", {"k":34, "revt":"3e4r", "kjh":Vector3(70,3,5), [5,"ert", Vector2(0,9)]:Basis() }, true, Color(1.4,2.3,3.2,4.1)]
var gcm_input = var_to_bytes(to_encr)

func _ready():
	print("Not Encripted Data: ", to_encr)
	print("\nNOT ENCRPTY: ", gcm_input.size(), "\n",gcm_input)
	var encrypted_array_gcm = encripter.gcm_encrypt(gcm_input, key, gcm_add)
	print("\nENCRPTY: ",encrypted_array_gcm.size(), "\n",encrypted_array_gcm)
	var decrypted_array_gcm = encripter.gcm_decrypt(encrypted_array_gcm, key, gcm_add)
	print("\nDENCRPTY: ",decrypted_array_gcm.size(), "\n",decrypted_array_gcm)
	print("\nData: ", bytes_to_var(decrypted_array_gcm))

	get_tree().quit()