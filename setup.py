import os
from sys import exit, argv

DEFAULT_J3M_SERVER = "https://camera-v.org"
DEFAULT_GNUPG_PATH = os.path.expanduser("~/.gnupg")

def __setup(with_config):
	global DEFAULT_J3M_SERVER, DEFAULT_GNUPG_PATH
	from c_utils.cutils import DUtilsKey, build_config, save_config

	conf_keys = [
		DUtilsKey("DEFAULT_OUTPUT_DIR", "Default output directory (where all exported data should be saved)",
			None, "parent directory of media", None),
		DUtilsKey("POE_URL", "URL of your Proof of Existence server", None, "None", None),
		DUtilsKey("J3M_SERVER", "URL of your J3M Media Server",
			DEFAULT_J3M_SERVER, DEFAULT_J3M_SERVER, None),
		DUtilsKey("GNUPG_PATH", "Path to your GPG Keyring",
			DEFAULT_GNUPG_PATH, DEFAULT_GNUPG_PATH, None)
	]

	res, config = save_config(build_config(conf_keys, with_config), return_config=True)
	
	if res and config['DEFAULT_OUTPUT_DIR'] is not None:
		if not os.path.exists(config['DEFAULT_OUTPUT_DIR']):
			from fabric.api import settings, local
			
			with settings(warn_only=True):
				local("mkdir -p %(DEFAULT_OUTPUT_DIR)s" % config)

	return res

if __name__ == "__main__":
	with_config = None
	if len(argv) >= 2:
		with_config = argv[1]

	exit(0 if __setup(with_config) else -1)