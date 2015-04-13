import os

BASH_CMD = {
	'GET_MIME_TYPE' : "file %(file_path)s",
	'KEYBASE_VERIFY' : "keybase verify %(sig_file_path)s %(verify_path)s",
	'GET_MEDIA_HASH' : "",
	'GPG_ADD_TO_KEYRING' : "gpg --homedir=%(GNUPG_PATH)s add",
	'GPG_SIGN_KEY' : "gpg --homedir=%(GNUPG_PATH)s sign",
	'KEYBASE_SIGN_MESSAGE' : "keybase sign %(message_path)s --detatch-sign"
}


KEYBASE_DEFAULT_MESSAGE = {
	'remote_hostname' : "%(J3M_SERVER)s",
	'type' : "web_service_binding.generic"	
}

KB_URL = "https://keybase.io/_/api/1.0"
KEYBASE_IO = {
	'SIG_POST' : "%s/sig/post.json" % KB_URL,
	'SALT' : "%s/getsalt.json" % KB_URL,
	'LOGIN' : "%s/login.json" % KB_URL
}

PROOF_OF_EXISTENCE_IO = {
	'STATUS' : "%(POE_URL)s/status",
	'REQUEST' : "%(POE_URL)s/request"
}