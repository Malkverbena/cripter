extends Node

var data = """
THE KEY PAIRS FOR THIS DEMO WERE CREATED USING THE FOLLOWING COMMANDS:
openssl genrsa -out rsa_private_key.pem -aes256 4096
openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
"""

var cripter = Cripter.new()

var rsa_password := "cripter_exemple"
var key = "My not secret key"
var cbc_input = var2bytes("aaaaa")

@export_global_file var private_key
@export_global_file var public_key 

func _ready():
	var private_key_path = ProjectSettings.globalize_path(String(private_key))
	var public_key_path = ProjectSettings.globalize_path(String(public_key))
	print("private_key_path: ", private_key_path)
	print("public_key_path: ", public_key_path)

#	print(cripter.check_keys_pair(private_key_path, public_key_path))

	var not_encrypted = var2bytes(data)
	print("not_encrypted size: ", not_encrypted.size(), " \n=> ",not_encrypted)
	
	print("=========================\n")
	var encrypted = cripter.rsa_encrypt(not_encrypted, public_key_path)
	print("encrypted: ", encrypted.size(), " \n-> ", encrypted)

	print("=========================\n")
	var dencrypted = cripter.rsa_decrypt(encrypted, private_key_path, "cripter_exemple")
	print("decrypted size: ", dencrypted.size(), " \n-> ", dencrypted)

	print( bytes2var(dencrypted))
	get_tree().quit()
