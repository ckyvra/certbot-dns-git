import logging
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from certbot import errors
from certbot.plugins import dns_common
from dulwich.porcelain import add, clone, commit, push

logger = logging.getLogger(__name__)

RECORD_NAME = "_acme-challenge"


def _make_record_lines(
    action: str, domain: str, value: str, lines: list[str]
) -> list[str]:
    domain_dot = f"{domain}."

    rel = re.compile(
        r"^\s*_acme-challenge\s+(?:\d+\s+)?(?:IN\s+)?TXT\s+\"(.*)\"\s*(?:;.*)?$",
        re.IGNORECASE,
    )
    abs_dot = re.compile(
        rf"^\s*_acme-challenge\.{re.escape(domain_dot)}\s+"
        rf"(?:\d+\s+)?(?:IN\s+)?TXT\s+\"(.*)\"\s*(?:;.*)?$",
        re.IGNORECASE,
    )
    abs_no_dot = re.compile(
        rf"^\s*_acme-challenge\.{re.escape(domain)}\s+"
        rf"(?:\d+\s+)?(?:IN\s+)?TXT\s+\"(.*)\"\s*(?:;.*)?$",
        re.IGNORECASE,
    )

    canonical_line = f"_acme-challenge.{domain_dot} IN TXT \"{value}\"\n"

    index = None
    for i, line in enumerate(lines):
        if rel.match(line) or abs_dot.match(line) or abs_no_dot.match(line):
            index = i
            break

    if action == "remove":
        if index is not None:
            lines.pop(index)
        return lines

    if index is not None:
        lines[index] = canonical_line
        return lines

    insert_pos = len(lines)
    for i, line in enumerate(lines):
        if re.search(r"SOA\s", line, re.IGNORECASE):
            for j in range(i, min(i + 30, len(lines))):
                if ")" in lines[j]:
                    insert_pos = j + 1
                    break
            break

    lines.insert(insert_pos, canonical_line)
    return lines


class Authenticator(dns_common.DNSAuthenticator):
    description = (
        "Obtain certificates using a DNS TXT record in a "
        "git-hosted BIND zone file"
    )
    ttl = 60

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.credentials: Optional[dns_common.CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add, default_propagation_seconds=30):
        super().add_parser_arguments(add, default_propagation_seconds)
        add("credentials", help="Git DNS credentials INI file")

    def more_info(self) -> str:
        return (
            "This plugin configures a DNS TXT record to respond to a "
            "dns-01 challenge using git-hosted BIND zone files. "
            "It clones a git repository, modifies the zone file, "
            "commits, and pushes."
        )

    def _validate_credentials(self, credentials) -> None:
        if not credentials.conf("repo"):
            raise errors.PluginError(
                "dns_git_repo is required in the credentials INI file"
            )

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            "credentials",
            "Git DNS credentials INI file",
            None,
            self._validate_credentials,
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        client = self._get_client()
        client.add_txt_record(domain, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        client = self._get_client()
        client.remove_txt_record(domain, validation)

    def _get_client(self) -> "_GitClient":
        if not self.credentials:
            raise errors.Error("Plugin has not been prepared.")
        return _GitClient(
            repo=self.credentials.conf("repo"),
            token=self._optional("token"),
            branch=self._optional("branch", "main"),
            zone_path=self._optional("zone_path", ""),
            zone_prefix=self._optional("zone_prefix", ""),
            zone_suffix=self._optional("zone_suffix", ""),
            git_user=self._optional("git_user", "certbot-dns-git"),
            git_email=self._optional("git_email", "certbot@localhost"),
        )

    def _optional(self, key: str, default: str = "") -> Optional[str]:
        val = self.credentials.conf(key) if self.credentials else None
        return val if val else default


class _GitClient:
    def __init__(
        self,
        repo: str,
        token: Optional[str] = None,
        branch: str = "main",
        zone_path: str = "",
        zone_prefix: str = "",
        zone_suffix: str = "",
        git_user: str = "certbot-dns-git",
        git_email: str = "certbot@localhost",
    ):
        self.repo = repo
        self.token = token
        self.branch = branch
        self.zone_path = zone_path
        self.zone_prefix = zone_prefix
        self.zone_suffix = zone_suffix
        self.git_user = git_user
        self.git_email = git_email
        self._tmpdir: Optional[Path] = None
        self._repo_dir: Optional[Path] = None
        self._auth: dict[str, str] = {}
        if token:
            self._auth = {"username": "x-access-token", "password": token}

    def add_txt_record(self, domain: str, value: str) -> bool:
        if not self._repo_dir:
            self._clone()
        zone_file = self._resolve_zone_file(domain)
        if not zone_file.exists():
            raise errors.PluginError(f"Zone file not found: {zone_file}")
        original = zone_file.read_text(encoding="utf-8")
        lines = original.splitlines(keepends=True)
        lines = _make_record_lines("add", domain, value, lines)
        modified = "".join(lines)
        if modified == original:
            return False
        zone_file.write_text(modified, encoding="utf-8")
        self._commit_and_push(domain, "add")
        return True

    def remove_txt_record(self, domain: str, value: str) -> bool:
        if not self._repo_dir:
            self._clone()
        zone_file = self._resolve_zone_file(domain)
        if not zone_file.exists():
            return False
        original = zone_file.read_text(encoding="utf-8")
        lines = original.splitlines(keepends=True)
        lines = _make_record_lines("remove", domain, value, lines)
        modified = "".join(lines)
        if modified == original:
            return False
        zone_file.write_text(modified, encoding="utf-8")
        self._commit_and_push(domain, "remove")
        return True

    def _clone(self) -> Path:
        if self.token and not self.repo.startswith("https://"):
            raise errors.PluginError(
                "Only HTTPS repository URLs are supported for token auth"
            )
        self._tmpdir = Path(tempfile.mkdtemp(prefix="certbot-dns-git-"))
        repo_dir = self._tmpdir / "repo"
        try:
            clone(
                source=self.repo,
                target=str(repo_dir),
                depth=1,
                branch=self.branch,
                **self._auth,
            )
        except Exception as exc:
            raise errors.PluginError(
                f"Failed to clone repository: {exc}"
            ) from exc
        self._repo_dir = repo_dir
        return repo_dir

    def _resolve_zone_file(self, domain: str) -> Path:
        zone_dir = self._repo_dir / self.zone_path if self._repo_dir else Path()
        return zone_dir / f"{self.zone_prefix}{domain}{self.zone_suffix}"

    def _commit_and_push(self, domain: str, action: str) -> None:
        if not self._repo_dir:
            return
        repo_path = str(self._repo_dir)
        identity = f"{self.git_user} <{self.git_email}>".encode()
        try:
            add(repo=repo_path, paths=None)
            commit(
                repo=repo_path,
                message=f"dns: {action} {RECORD_NAME}.{domain}",
                author=identity,
                committer=identity,
            )
            push(
                repo=repo_path,
                remote_location=self.repo,
                refspecs=f"{self.branch}:{self.branch}",
                **self._auth,
            )
        except Exception as exc:
            raise errors.PluginError(
                f"Failed to commit and push changes: {exc}"
            ) from exc

    def cleanup(self) -> None:
        if self._tmpdir and self._tmpdir.exists():
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None
            self._repo_dir = None

    def __enter__(self):
        self._clone()
        return self

    def __exit__(self, *exc_info):
        self.cleanup()
