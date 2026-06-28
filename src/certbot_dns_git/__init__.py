"""
``certbot-dns-git`` — Git repository-based DNS authenticator plugin for Certbot.

Plugin registered as ``dns-git`` manages ``_acme-challenge`` TXT records in
BIND zone files hosted in a Git repository.  The plugin clones the repo,
modifies the zone file, commits, and pushes.

Credentials file format (``dns_git_``-prefixed INI keys):

.. code-block:: ini

   dns_git_repo = https://github.com/example/dns-zones.git
   dns_git_token = <personal-access-token>
   dns_git_branch = main
   dns_git_zone_path = zones/example.com
   dns_git_zone_prefix = db.
   dns_git_zone_suffix = .zone
   dns_git_git_user = certbot-bot
   dns_git_git_email = certbot@example.com

Only ``dns_git_repo`` is required; all other keys are optional.

Usage::

    certbot certonly \\
      --authenticator dns-git \\
      --dns-git-credentials /path/to/credentials.ini \\
      -d example.com
"""
