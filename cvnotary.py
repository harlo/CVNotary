import os
from time import time
from sys import argv, exit
from fabric.api import settings, local

from vars import BASH_CMD
from lib.camera-v.camerav_express import camerav_parser

class CVNotary():
	def __init__(self, file_path):
		self.obj = {
			'date_admitted' : time() * 1000
		}

		self.prop = {}
		self.notarized = False

		try:
			with open(os.path.join(BASE_DIR, ".config.json"), 'rb') as conf:
				self.prop = json.loads(conf.read())
		except Exception as e:
			print e, type(e)
			self.properties_updated = True

		self.prop['file_path'] = file_path

		with settings(warn_only=True):
			res, output = camerav_parser(
				local(BASH_CMD['GET_MIME_TYPE'] % self.prop, capture=True),
				self.prop['file_path']
			)

		try:
			self.obj.update(output)
			print self.obj
		except Exception as e:
			print e, type(e)
			return

		if self.obj['mime_type'] == "source":
			p = self.parse_source()
		elif self.obj['mime_type'] in ["image", "video"]:
			p = self.parse_submission()

		if p and self.generate_message():
			self.notarized = True

		del self.prop['file_path']

		if hasattr(self, 'properties_updated') and self.properties_updated:
			save_props = prompt('Save changes? [y|N] : ')
			if save_props == "y":
				with open(os.path.join(BASE_DIR, ".config.json"), 'wb+') as conf:
					conf.write(json.dumps(self.prop))

	def parse_submission(self):
		try:
			# XXX: verify signature in j3m
			self.obj['gpg_verified'] = gpg_result

			# XXX: media hasher applied
			self.obj['media_hash_verified'] = media_hash_result

			return True

		except Exception as e:
			print e, type(e)

		return False

	def parse_source(self):
		try:
			# XXX: add to keyring in gpg
			self.obj['fingerprint'] = gpg_result

			return self.sign_key()
		except Exception as e:
			print e, type(e)

		return False

	def sign_key(self):
		# XXX: sign keyring in gpg
		# XXX: publish keyring updates to keybase
		
		return False

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
		# XXX: sign message in gpg
		return self.publish_signing_document(message)

	def publish_signing_document(self, doc):
		# XXX: push to keybase via api
		return False

if __name__ == "__main__":
	if len(argv) == 0:
		exit(-1)

	cvn = CVNotary(argv[1])
	exit(0 if cvn.notarized else -1)