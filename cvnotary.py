import os
from time import time
from sys import argv, exit
from fabric.api import settings, local

from vars import *

class CVNotary():
	def __init__(self, file_path):
		self.obj = {
			'date_admitted' : time() * 1000
		}

		self.prop = {}

		try:
			with open(os.path.join(BASE_DIR, ".config.json"), 'rb') as conf:
				self.prop = json.loads(conf.read())
		except Exception as e:
			print e, type(e)
			self.properties_updated = True

		self.prop['file_path'] = file_path

		if self.type == "source":
			self.parse_source()
		elif self.type == "submission":
			self.parse_submission()

		del self.prop['file_path']
		
		if hasattr(self, 'properties_updated') and self.properties_updated:
			save_props = prompt('Save changes? [y|N] : ')
			if save_props == "y":
				with open(os.path.join(BASE_DIR, ".config.json"), 'wb+') as conf:
					conf.write(json.dumps(self.prop))

	def parse_submission(self):
		# XXX: unpack j3m stuff
		self.obj['verified'] = verify_metadata()

		return False

	def parse_source(self, sign_key=True):
		# XXX: unpack submission package
		
		try:
			# XXX: add to keyring in gpg
			self.obj['fingerprint'] = source_obj

			if sign_key:
				return self.sign_key()
		except Exception as e:
			print e, type(e)

		return False

	def sign_key(self, publish=True):
		# XXX: sign keyring in gpg

		if publish:
			# XXX: publish signature to keybase
			self.generate_message()
		return False

	def verify_metadata(self):
		# XXX: camerav task
		return False

	def generate_message(self):
		if self.type == "source":
			message = self.generate_source_message()
		elif media.type == "submission":
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

	def sign_message(self, message, publish=True):
		# XXX: sign message in gpg

		if publish:
			return self.publish_signing_document(message)

		return False

	def publish_signing_document(self, doc):
		# XXX: push to keybase via api
		return False

if __name__ == "__main__":
	if len(argv) == 0:
		exit(-1)