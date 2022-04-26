extends Node

var encripter = Cripter.new()

var key = "My not secret key"
var cbc_input = var2bytes([234, "ub", {"k":34, "revt":"3e4r", "kjh":Vector3(70,3,5), [5,"ert", Vector2(0,9)]:Basis() }, true, Color(1.4,2.3,3.2,4.1)])

func _ready():
	print(bytes2var(cbc_input))
	print("\nNOT ENCRPTY:\n",cbc_input)
	var encrypted_array_cbc = encripter.cbc_encrypt(cbc_input, key)
	print("\nENCRPTY: ",encrypted_array_cbc.size(), "\n",encrypted_array_cbc)
	var decrypted_array_cbc = encripter.cbc_decrypt(encrypted_array_cbc, key)
	print("\nDDDDENCRPTY: ",decrypted_array_cbc.size(), "\n",decrypted_array_cbc)
	print("\nData:\n", bytes2var(decrypted_array_cbc))

	get_tree().quit()
