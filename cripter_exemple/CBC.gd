extends Node

var encripter = Cripter.new()

var key = "My not secret key"

var to_encr = [234, "ub", {"k":34, "revt":"3e4r", "kjh":Vector3(70,3,5), [5,"ert", Vector2(0,9)]:Basis() }, true, Color(1.4,2.3,3.2,4.1)]
var cbc_input = var_to_bytes(to_encr)

func _ready():
	print("Not Encripted Data: ", to_encr)
	print("\nBinary Array: ", cbc_input)
	print("\nNOT ENCRPTY:\n",cbc_input)
	var encrypted_array_cbc = encripter.cbc_encrypt(cbc_input, key)
	print("\nENCRPTY: ",encrypted_array_cbc.size(), "\n",encrypted_array_cbc)
	var decrypted_array_cbc = encripter.cbc_decrypt(encrypted_array_cbc, key)
	print("\nDDDDENCRPTY: ",decrypted_array_cbc.size(), "\n",decrypted_array_cbc)
	print("\nData:\n", bytes_to_var(decrypted_array_cbc))
	
	
	
	get_tree().quit()
