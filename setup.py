import os
from sys import exit, argv

DEFAULT_J3M_SERVER = "https://camera-v.org"
DEFAULT_GNUPG_PATH = os.path.expanduser("~/.gnupg")
DEFAULT_NOTARY_DOC_DIR = os.path.expanduser("~/CameraVNotary")

def __setup(with_config):
	global DEFAULT_J3M_SERVER, DEFAULT_GNUPG_PATH, DEFAULT_NOTARY_DOC_DIR
	from c_utils.cutils import DUtilsKey, build_config, save_config

	conf_keys = [
		DutilsKey("USER_NAME", "Your name", "No one", "No one", None),
		DUtilsKey("NOTARY_DOC_DIR", "Directory where notary proofs are stored",
			DEFAULT_NOTARY_DOC_DIR, DEFAULT_NOTARY_DOC_DIR, None),
		DUtilsKey("DEFAULT_OUTPUT_DIR", "Default output directory (where all exported data should be saved)",
			None, "parent directory of media", None),
		DUtilsKey("POE_SERVER", "Host IP of your Proof of Existence server (like, http://localhost:8080)", \
			None, "None", None),
		DUtilsKey("POE_SERVER_ALIAS", "Alias of your Proof of Existence server", None, "None", None),
		DUtilsKey("J3M_SERVER", "URL of your J3M Media Server",
			DEFAULT_J3M_SERVER, DEFAULT_J3M_SERVER, None),
		DUtilsKey("GNUPG_PATH", "Path to your GPG Keyring", DEFAULT_GNUPG_PATH, DEFAULT_GNUPG_PATH, None),
		DUtilsKey("GPG_KEY_ID", "Your key ID", None, "none", None),
		DUtilsKey("KEYBASE_ID", "Your Keybase.io ID", None, "none", None)
	]

	res, config = save_config(build_config(conf_keys, with_config), return_config=True)
	
	if res:
		from fabric.api import settings, local

		for p in ['DEFAULT_OUTPUT_DIR', 'NOTARY_DOC_DIR']:
			if config[p] is not None and os.path.exists(p):
				with settings(warn_only=True):
					local("mkdir -p %s" % config[p])

	return res

if __name__ == "__main__":
	with_config = None
	if len(argv) >= 2:
		with_config = argv[1]

	exit(0 if __setup(with_config) else -1)