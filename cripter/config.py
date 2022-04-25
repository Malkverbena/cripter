def can_build(env, platform):
	return True


def configure(env):
	pass


def get_doc_classes():
	return [
        "Cripter",
	]


def get_doc_path():
	import version
	return "doc_classes" + str(version.major)
