certbot-dns-git
===============

Git repository-based DNS authenticator plugin for Certbot.

This plugin clones a Git repository containing BIND zone files, adds or
removes ``_acme-challenge`` TXT records for the ACME dns-01 challenge,
commits the change, and pushes it back to the remote.

Installation
------------

.. code:: bash

   pip install certbot-dns-git

Credentials file format
-----------------------

.. code:: ini

   dns_git_repo = https://github.com/example/dns-zones.git
   dns_git_token = your_git_token
   dns_git_branch = main
   dns_git_zone_path = zones/example.com
   dns_git_zone_prefix = db.
   dns_git_zone_suffix = .zone
   dns_git_git_user = certbot-bot
   dns_git_git_email = certbot@example.com

Usage
-----

.. code:: bash

   certbot certonly \\
     --authenticator dns-git \\
     --dns-git-credentials /path/to/credentials.ini \\
     -d example.com
