import os, requests, json, re, gnupg

from time import time
from copy import deepcopy
from sys import argv, exit

from fabric.api import settings, local
from fabric.operations import prompt

from vars import BASH_CMD, KEYBASE_IO, KEYBASE_DEFAULT_MESSAGE
from c_utils.cutils import DUtilsKey, DUtilsTransforms, load_config, parse_config_keys
from lib.camerav.camerav_express import camerav_parser

class CameraVNotaryInstance():
	def __init__(self, notarize_media=None):
		self.obj = {'date_admitted' : time() * 1000}
		self.prop = load_config()

		if self.prop is None:
			self.prop = {}

		self.gpg = gnupg.GPG(homedir=self.prop['GNUPG_PATH'])

		secrets = [DUtilsKey(s, s, None, "none", DUtilsTransforms['NONE_IF_EMPTY']) \
			for s in ['KEYBASE_PWD', 'GPG_PWD']]

		self.prop.update(parse_config_keys(secrets))

		if notarize_media is not None:
			self.notarize_media(notarize_media)

	def notarize_media(self, file_path):
		self.prop['file_path'] = file_path
		self.notarized = False

		out_dir = None if 'DEFAULT_OUTPUT_DIR' not in self.prop.keys() \
			else self.prop['DEFAULT_OUTPUT_DIR']

		with settings(warn_only=True):
			res, output = camerav_parser(
				local(BASH_CMD['GET_MIME_TYPE'] % self.prop, capture=True),
				self.prop['file_path'],
				out_dir=out_dir
			)

		try:
			self.prop.update(output)
			self.obj['mime_type'] = self.prop['mime_type']
			print self.prop
		except Exception as e:
			print e, type(e)
			return

		if self.obj['mime_type'] == "source":
			p = self.parse_source()
		elif self.obj['mime_type'] in ["image", "video"]:
			p = self.parse_submission()

		if p and self.generate_message():
			self.notarized = self.publish_message()

	def __do_bash(self, cmd):
		with settings(warn_only=True):
			b = local(cmd, capture=True)

		content = None
		res = False if b.return_code != 0 else True
		
		try:
			content = b.stdout
		except Exception as e:
			print e, type(e)

		return res, content

	def __do_keybase_request(self, url, data):
		if 'keybase_session' not in self.prop.keys() and not self.__do_keybase_login():
			return False, None

		try:
			r = requests.post(url, data=data, cookies=self.prop['keybase_session'])
			res = False if r.status_code != 200 else True
			content = json.loads(r.content)

			print content

			if 'csrf_token' in content.keys():
				self.prop['keybase_session']['csrf_token'] = content['csrf_token']

			return res, content
		except Exception as e:
			print "could not do keybase api call to %s" % url
			print e, type(e)

		return False, None

	def __do_keybase_login(self):
		import binascii, hmac, scrypt, hashlib
		from base64 import b64decode

		kb_data = {'email_or_username' : self.prop['KEYBASE_ID']}

		# XXX: get salt and csrf_token (get to /salt)
		try:
			r = requests.get(KEYBASE_IO['SALT'], data=kb_data)

			if r.status_code != 200:
				print "ERROR: status code : %d" % r.status_code
				return False

			res = json.loads(r.content)
			kb_data.update({
				'login_session' : res['login_session'],
				'csrf_token' : res['csrf_token']
			})

		except Exception as e:
			print "could not get salt:"
			print e, type(e)
			return False

		# XXX: calculate pwd hash
		try:
			pwh = scrypt.hash(self.prop['KEYBASE_PWD'], binascii.unhexlify(res['salt']), \
				N=2**15, r=8, p=1, buflen=224)[192:224]
		except Exception as e:
			print "could not generate pwd hash"
			print e, type(e)
			return False

		# XXX: calculate hmac of pwd hash
		try:
			hmac_pwh = hmac.new(pwh, b64decode(res['login_session']), hashlib.sha512)
			kb_data['hmac_pwh'] = binascii.hexlify(hmac_pwh.digest())
		except Exception as e:
			print "could not generate hmac of pwh"
			print e, type(e)
			return False

		# XXX: post to /login and set session cookie
		try:
			r = requests.post(KEYBASE_IO['LOGIN'], data=kb_data)

			if r.status_code != 200:
				print "ERROR: status code : %d" % r.status_code
				return False

			res = json.loads(r.content)
			if res['status']['code'] != 0:
				print "ERROR: KEYBASE status code : %d" % res['status']['code'], res['status']['desc']
				return False

			self.prop.update({
				'csrf_token' : res['csrf_token'],
				'session' : res['session']
			})

			del self.prop['KEYBASE_PWD']
			return True

		except Exception as e:
			print "could not post to login:"
			print e, type(e)
			return False

		return False

	def parse_submission(self):
		print "PARSING SUBMISSION"

		try:
			# XXX: verify signature in j3m
			res, gpg_result = self.__do_bash(BASH_CMD['GPG_VERIFY'] % self.prop)
			if not res:
				return False

			self.obj['gpg_verified'] = gpg_result

			# XXX: media hasher applied
			res, media_hash_result = self.__do_bash(BASH_CMD['GET_MEDIA_HASH'] % self.prop)
			if not res:
				return False

			self.obj['media_hash_verified'] = media_hash_result

			return True

		except Exception as e:
			print e, type(e)

		return False

	def parse_source(self):
		for _, _, files in os.walk(self.prop['data']):

			for f in [os.path.join(self.prop['data'], f) for f in files]:
				r, d = self.__do_bash(BASH_CMD['GET_MIME_TYPE'] % {'file_path' : f })
				if not r:
					continue

				if re.match(r'.*\:\sPGP public key block$', d):
					self.prop['pgp_key_path'] = f
					break

		if 'pgp_key_path' not in self.prop.keys():
			print "No PGP key detected"
			return False
		
		try:
			
			with open(self.prop['pgp_key_path'], 'rb') as K:
				pgp_key = self.gpg.import_keys(K.read())

			self.obj['fingerprint'] = pgp_key.results[0]['fingerprint']
			return True
		except Exception as e:
			print e, type(e)

		return False

	def generate_message(self):
		if self.obj['mime_type'] == "source":
			message = self.generate_source_message()
		elif self.obj['mime_type'] in ["image", "video"]:
			message = self.generate_submission_message()

		if message is not None:
			print message
			return self.sign_message(message)

		return False

	def generate_source_message(self):
		try:
			return "Camera-V user %s has been introduced.\n\n%s" % (self.obj['fingerprint'], json.dumps(self.obj))
		except Exception as e:
			print e, type(e)

		return None

	def generate_submission_message(self):
		try:
			return "A new submission has been processed.\n\n%s" % json.dumps(self.obj)
		except Exception as e:
			print e, type(e)

		return None

	def sign_message(self, message):
		signed_message = self.gpg.sign(message, default_key=self.prop['GPG_KEY_ID'],
			passphrase=prompt("GPG PWD: "), clearsign=True)
		
		try:
			if len(signed_message.data) > 0:
				self.prop['signed_message'] = signed_message.data
				return True
		except Exception as e:
			print e, type(e)

		return False
		
	def publish_message(self):
		# XXX: post signature document to keybase server
		try:
			kb_receipt = deepcopy(KEYBASE_DEFAULT_MESSAGE)
			kb_receipt['sig'] = self.prop['signed_message']

			res, content = self.__do_keybase_request(KEYBASE_IO['SIG_POST'], data=kb_receipt)
			return res
		except Exception as e:
			print e, type(e)

		return False

if __name__ == "__main__":
	res = False

	try:
		cni = CameraVNotaryInstance(notarize_media=argv[1])
		res = cni.notarized
	except Exception as e:
		print e, type(e)

	exit(0 if res else -1)

