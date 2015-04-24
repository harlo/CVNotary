### Install

Be sure to pull down submodules:

`git submodule update --init --recursive`

Then, run `./install.sh` to build the utility, with optional `/path/to/config/file.json`.  During setup, you'll be asked the following:

1.	**USER_NAME**: The name you'd like to be called, as a notary.
1.	**NOTARY_DOC_DIR**: The directory in which the app will store your *notarization anouncements*.
1.	**MD_FORMATTING**: *Notarization documents* are generated in markdown.  If you ultimately want to publish to an engine like jekyll, certain extra formatting will be required.  If you just want plain markdown, leave this as blank.
1.	**DEFAULT_OUTPUT_DIR**: You can require all output from the documents you notarize to be dropped in a folder *(recommended)*.  Leave this blank if you want the extra data left in the same folder as the document.
1.	**POE_SERVER**: The protocol and host of your associated [Proof of Existence](https://camera-v.org/about#what_is_proof) server.
1.	**POE_SERVER_ALIAS**: The protocol and host of the public address of your Proof of Existence server, *if you want the a link to the associated proof included in your notarization anouncement.*
1.	**J3M_SERVER**: The protocol and host of your associated [J3M server](https://camera-v.org/about#what_is_j3m).
1.	**J3M_SERVER_ALIAS**: The protocol and host of the public address of your J3M server, *if you want the a link to the associated J3M entry included in your notarization anouncement.*
1.	**GNUPG_PATH**: The full path to your GPG keyring.  (Defaults to `~/.gnupg` if blank.)
1.	**GPG_KEY_ID**: The key ID associated to the secret GPG key in your keyring used to sign and verify content.

### Usage

To notarize a document, run `./notarize.sh /path/to/document`.  Your *notarization annoucement* will be left in your notary directory, and associated data from the document will be found at the path specified in your config.

#### Submitting to the Blockchain

Before the *notarization announcement* can be generated, the document will be submitted to the blockchain via your associated Proof of Existence server.  You will be notified of a payment address to submit bitcoin to (and you can also query the Proof of Existence server independently, if you need to.)  This app **does not** monitor the transaction; that is for Proof of Existence to do; but if you have the POE_SERVER_ALIAS configured, the link to this transaction will be included in your notarization announcement.

#### Publishing a Notarization Announcement

Notarization announcements are in markdown.  It is recommended using git, svn, or some kind of version control to ensure that these announcements are publicly available.  A user can import the signed PGP message to verify your notarization announcement.  **For this to mean anything to end-users, be sure to publish your public key** on a keyserver, at [keybase.io](https://keybase.io), or on an SSL-protected site you have ownersip over.