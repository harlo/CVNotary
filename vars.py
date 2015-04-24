BASH_CMD = {
	'GET_MIME_TYPE' : "file %(file_path)s",
	'GET_MEDIA_HASH' : ""
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

MD_FORMATTING_SENTINELS = {
	'code_block' : {
		'standard' : ["```", "```"],
		'jekyll' : ["{%% highlight text %%}", "{%% endhighlight %%}"]
	},
	'json' : {
		'standard' : ["```", "```"],
		'jekyll' : ["{%% highlight json %%}", "{%% endhighlight %%}"]
	},
	'frontmatter' : {
		'jekyll' : ["---", "layout: notary", \
			"title: %(signed_message_hash)s", "date: %(date_admitted_str_md)s", "---\n"]
	}
}