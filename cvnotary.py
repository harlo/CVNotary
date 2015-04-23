import os, requests, json, re, gnupg

from time import time
from datetime import datetime
from copy import deepcopy
from sys import argv, exit

from fabric.api import settings, local

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

		self.prop.update(parse_config_keys(secrets, self.prop))
		self.prop['date_admitted_str'] = datetime.fromtimestamp(float(self.obj['date_admitted']/1000)).strftime("%B %d, %Y (%H:%M:%S)")

		if notarize_media is not None:
			self.notarize_media(notarize_media)

	def notarize_media(self, file_path):
		self.prop.update({
			'file_path' : file_path,
			'file_name' : file_path.split("/")[-1]
		})
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
			self.obj.update({
				'mime_type' : self.prop['mime_type'],
				'date_admitted_str' : self.prop['date_admitted_str']
			})

		except Exception as e:
			print e, type(e)
			return

		if self.obj['mime_type'] == "source":
			p = self.parse_source()
		elif self.obj['mime_type'] in ["image", "video"]:
			p = self.parse_submission()

		self.__do_J3M_Lookup()

		if p and self.generate_message():
			if not self.prop['POE_SERVER']:
				self.notarized = True
			else:
				self.notarized = self.submit_to_blockchain()
				self.__do_J3M_Lookup()

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

	def __do_J3M_Lookup(self):
		if not self.prop['J3M_SERVER']:
			return False

		h = None

		if 'J3M_SERVER_ID_LEN' not in self.prop.keys() or self.prop['J3M_SERVER_ID_LEN'] == 40:
			from hashlib import sha1
			h = sha1()
		elif self.prop['J3M_SERVER_ID_LEN'] == 32:
			from hashlib import md5
			h = md5()

		if h is None:
			return False

		with open(self.prop['file_path'], 'rb') as f:
			for chunk in iter(lambda: f.read(4096), b''):
				h.update(chunk)

		self.prop['j3m_hash'] = h.hexdigest()

		url = "%s/documents/?_id=%s" % (self.prop['J3M_SERVER'], self.prop['j3m_hash'])

		try:
			r = requests.get(url, data={'_id' : self.prop['j3m_hash']})
			if r.status_code != 200:
				return False

			if "J3M_SERVER_ALIAS" not in self.prop.keys():
				self.prop['J3M_SERVER_ALIAS'] = self.prop['J3M_SERVER']

			if self.prop['mime_type'] in ["image", "video"]:
				self.prop['j3m_server_url'] = "%(J3M_SERVER_ALIAS)s/submission/%(j3m_hash)s/" % self.prop
			else:
				self.prop['j3m_server_url'] = "%(J3M_SERVER_ALIAS)s/source/%(j3m_hash)s/" % self.prop

			published_message = [
				"\nMore details about this document's metadata can be found [here](%(j3m_server_url)s)."
			]

			with open(self.prop['notarized_message_path'], 'a') as doc:
				doc.write("\n".join([l % self.prop for l in published_message]))

			return True

		except Exception as e:
			print e, type(e)

		return False

	def __do_POE_request(self, url, data):
		if not self.prop['POE_SERVER']:
			return False, None

		url = "%s/%s" % (self.prop['POE_SERVER'], url)

		try:
			r = requests.post(url, data=data)
			res = False if r.status_code != 200 else True
			content = json.loads(r.content)

			print content

			return res, content
		except Exception as e:
			print "could not do POE api call to %s" % url
			print e, type(e)

		return False, None

	def __check_POE_status(self):
		res, doc_entry = self.__do_POE_request("api/v1/status", {'d' : self.prop['signed_message_hash']})
		if not res:
			return None

		return doc_entry

	def __do_keybase_request(self, url, data):
		if 'keybase_session' not in self.prop.keys() and not self.__do_keybase_login():
			return False, None

		try:
			data.update({'csrf_token' : self.prop['keybase_session']['csrf_token']})
			r = requests.post(url, data=data, cookies=self.prop['keybase_session']['cookies'])
			
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
			pwh = scrypt.hash(str(self.prop['KEYBASE_PWD']), binascii.unhexlify(res['salt']), \
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

			self.prop['keybase_session'] = {
				'csrf_token' : res['csrf_token'],
				'cookies' : {'session' : res['session']}
			}

			del self.prop['KEYBASE_PWD']
			return True

		except Exception as e:
			print "could not post to login:"
			print e, type(e)
			return False

		return False

	def parse_submission(self):
		try:
			with open(self.prop['data'], 'rb') as j3m_metadata:
				self.obj['j3m_metadata'] = j3m_metadata.read()
		except Exception as e:
			print e, type(e)
			return False

		try:
			self.obj['j3m_metadata'] = json.loads(self.obj['j3m_metadata'])
		except Exception as e:
			print "j3m is not JSON formatted at the moment."
			print e, type(e)

		return True

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
			self.prop.update({
				'message' : message,
				'signed_message_path' : "%s.nmsg" % self.prop['data']
			})

			with open(self.prop['signed_message_path'], 'wb+') as nmsg:
				nmsg.write(message)

			return self.sign_message() and self.publish_message()

		return False

	def generate_source_message(self):
		try:
			return "Camera-V user %s has been introduced.\n\n%s" % (self.obj['fingerprint'], json.dumps(self.obj, indent=4))
		except Exception as e:
			print e, type(e)

		return None

	def generate_submission_message(self):
		try:
			return "A new submission has been processed.\n\n%s\n" % json.dumps(self.obj, indent=4)
		except Exception as e:
			print e, type(e)

		return None

	def sign_message(self):
		with open(self.prop['signed_message_path'], 'rb') as m_stream:
			signed_message = self.gpg.sign(m_stream, default_key=self.prop['GPG_KEY_ID'],
				passphrase=self.prop['GPG_PWD'], clearsign=False)
		
		try:
			if len(signed_message.data) > 0:
				from hashlib import sha256
				
				s = sha256()
				s.update(signed_message.data)

				self.prop.update({
					'signed_message' : signed_message.data,
					'signed_message_hash' : s.hexdigest()
				})

				return True
		except Exception as e:
			print e, type(e)

		return False
		
	def publish_message(self):
		from vars import MD_FORMATTING_SENTINELS

		self.prop['notarized_message_path'] = os.path.join(self.prop['NOTARY_DOC_DIR'], \
			"%s.md" % self.prop['signed_message_hash'])
		
		code_block_sentinels = MD_FORMATTING_SENTINELS['code_block'] \
			["standard" if not self.prop['MD_FORMATTING'] else self.prop['MD_FORMATTING']]
		
		json_sentinels = MD_FORMATTING_SENTINELS['json'] \
			["standard" if not self.prop['MD_FORMATTING'] else self.prop['MD_FORMATTING']]
		
		front_matter = None if not self.prop['MD_FORMATTING'] \
			else MD_FORMATTING_SENTINELS['frontmatter'][self.prop['MD_FORMATTING']]

		try:
			published_message = [
				"On %(date_admitted_str)s, I/we (%(USER_NAME)s) received document **%(file_name)s**.\n",
				json_sentinels[0],
				"\n%(message)s\n",
				json_sentinels[1],
				"The following is my/our *notarization document*.",
				code_block_sentinels[0],
				"\n%(signed_message)s\n",
				code_block_sentinels[1]
			]

			if front_matter:
				published_message = front_matter + published_message

			with open(self.prop['notarized_message_path'], 'wb+') as doc:
				doc.write("\n".join([l % self.prop for l in published_message]))

			return True
		except Exception as e:
			print e, type(e)

		return False

	def submit_to_blockchain(self):
		# XXX: check to see if document is there
		doc_entry = self.__check_POE_status()
		if doc_entry is None:
			return False

		if doc_entry['success']:
			print "ALREADY SUBMITTED"
		else:
			if doc_entry['reason'] == "nonexistent":
				res, doc_entry = self.__do_POE_request("api/v1/register", {'d' : self.prop['signed_message_hash']})

				if not res:
					print "res is false"
					return False

				if not doc_entry['success']:
					print "still could not register."
					return False

				new_status = self.__check_POE_status()
				if new_status is None:
					print "poor doc entry :("
					return False

				doc_entry['status'] = new_status['status']
			else:
				print "unknown error?"
				return False

		self.prop.update(doc_entry)

		if self.prop['status'] == "registered" and self.prop['pay_address'] and self.prop['price']:
			from fabric.operations import prompt

			print "\n** Must pay %(price)d to %(pay_address)s **\n" % self.prop
			print "Wait until payment made?"

			if prompt("y/N : ") == "y":
				print "Go ahead and make your payment of %(price)d to %(pay_address)s" % self.prop
				if prompt("[Press ENTER when done] "):
					pass

			new_status = self.__check_POE_status()
			if new_status is None:
				return False

			self.prop.update(new_status)

		if self.prop['status'] in ["pending", "confirmed", "registered"]:
			# Update notary message
			try:
				if 'POE_SERVER_ALIAS' not in self.prop.keys():
					published_message = [
						"\nThis *notarization document* has been submitted to a Proof of Existence server hosted locally."
					]

					if "transaction" in self.prop.keys() and "txstamp" in self.prop.keys():
						published_message += [
							"\nThis *notarization document* has been absorbed into the blockchain on %(txstamp)s.",
							"Transaction: [https://insight.bitpay.com/tx/%(transaction)s](https://insight.bitpay.com/tx/%(transaction)s)"
						]
				else:
					published_message = [
						"\nThis *notarization document* has been submitted to a Proof of Existence server at [%(POE_SERVER_ALIAS)s](%(POE_SERVER_ALIAS)s).",
						"\nTo view its status on the blockchain, please visit [%(POE_SERVER_ALIAS)s/detail/%(signed_message_hash)s](%(POE_SERVER_ALIAS)s/detail/%(signed_message_hash)s)."
					]

				with open(self.prop['notarized_message_path'], 'a') as doc:
					doc.write("\n".join([l % self.prop for l in published_message]))

				return True
			except Exception as e:
				print "could not update notary message"
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

