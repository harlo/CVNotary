1.	inputs file
1.	submit to keybase

ok, i think i know.

### with sources
1.	on init source, we add to keyring AND sign key (using standard gpg unforch)
1.	we publish the signing document to blockchain, and then keybase for notarizing

### with submissions
1.	on receive media, we verify (using standard gpg unforch)
1.	if verified OR NOT, we generate a message, and sign it (using standard gpg again)
1.	we publish the signing document to blockchain, and then keybase for notarizing

### the messages:
1.	date created
1.	date admitted
1.	fingerprint of submitter
1.	hashes

if submission:

1.	verified or not (if media)

if source:

1.	fingerprint of new source