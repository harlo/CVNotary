import os, requests, json
from time import time
from copy import deepcopy
from sys import argv, exit
from fabric.api import settings, local

from vars import BASH_CMD, KEYBASE_IO, KEYBASE_DEFAULT_MESSAGE
from lib.camera-v.camerav_express import camerav_parser

from c_utils.cutils import __load_config

class CameraVNotaryInstance():
	def __init__(self, file_path):
		self.obj = {'date_admitted' : time() * 1000}

		self.prop = __load_config
		if self.prop is None:
			self.prop = {}

		self.prop['file_path'] = file_path
		self.notarized = False

		with settings(warn_only=True):
			res, output = camerav_parser(
				local(BASH_CMD['GET_MIME_TYPE'] % self.prop, capture=True),
				self.prop['file_path']
			)

		try:
			self.prop.update(output)
			self.obj['mime_type'] = self.prop['mime_type']
			print self.obj
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
		# XXX: if not logged in,
		# XXX: get salt and csrf_token (get to /salt)
		# XXX: calculate pwd hash
		# XXX: post to /login and set session cookie

		# XXX: set necessary headers around the data

		r = requests.post(url, data=data)

		content = None
		res = False if r.status_code != 200 else True

		return res, content

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
		try:
			# XXX: add to keyring in gpg
			res, gpg_result = self.__do_bash(BASH_CMD['GPG_ADD_TO_KEYRING'] % self.prop)
			if not res:
				return False

			self.obj['fingerprint'] = gpg_result

			return self.sign_key()
		except Exception as e:
			print e, type(e)

		return False

	def sign_key(self):
		# XXX: sign key in gpg
		res, gpg_result = self.__do_bash(BASH_CMD['GPG_SIGN_KEY'] % self.prop)
		return res

	def generate_message(self):
		if self.obj['mime_type'] == "source":
			message = self.generate_source_message()
		elif self.obj['mime_type'] in ["image", "video"]:
			message = self.generate_submission_message()

		if message is not None:
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
		# XXX: sign message via keybase
		res, keybase_result = self.__do_bash(BASH_CMD['KEYBASE_SIGN_MESSAGE'] % self.prop)
		return res

	def publish_message(self):
		# XXX: post signature document to keybase server
		try:
			message = deepcopy(KEYBASE_DEFAULT_MESSAGE)

			with open(self.prop['signed_message'], 'rb') as m:
				message['sig'] = m.read()

			res, content = self.__do_keybase_request(KEYBASE_IO['SIG_POST'], data=message)
			return res
		except Exception as e:
			print e, type(e)

		return False

if __name__ == "__main__":
	res = False

	
	print argv

	exit(0 if res else -1)