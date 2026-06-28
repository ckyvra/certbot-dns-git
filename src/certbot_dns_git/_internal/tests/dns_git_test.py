import shutil
import textwrap
from pathlib import Path

import pytest
from dulwich.porcelain import add, clone, commit, push
from dulwich.repo import Repo

from certbot_dns_git._internal.dns_git import RECORD_NAME, _GitClient, _make_record_lines

ZONE_CONTENT = textwrap.dedent("""\
    $ORIGIN example.com.
    $TTL 3600
    @  IN  SOA  ns1.example.com. admin.example.com. (
      1  ; serial
      3600  ; refresh
      900  ; retry
      604800  ; expire
      86400  ; minimum
    )
    @  IN  NS  ns1.example.com.
""")


@pytest.fixture
def bare_repo(tmp_path: Path) -> str:
    bare_dir = tmp_path / "remote.git"
    working = tmp_path / "working"
    bare_dir.mkdir()

    working.mkdir()
    repo = Repo.init(str(working))
    repo.refs.set_symbolic_ref(b"HEAD", b"refs/heads/main")

    cfg = repo.get_config()
    section = b'remote "origin"'
    cfg.set(section, b"url", str(bare_dir))
    cfg.set(section, b"fetch", b"+refs/heads/*:refs/remotes/origin/*")
    cfg.write_to_path()
    repo.close()

    (working / "example.com.zone").write_text(ZONE_CONTENT)

    add(repo=str(working), paths=None)
    commit(
        repo=str(working),
        message="init",
        author=b"Test <test@test>",
        committer=b"Test <test@test>",
    )

    Repo.init_bare(str(bare_dir))

    push(
        repo=str(working),
        remote_location=str(bare_dir),
        refspecs="main:main",
    )

    return str(bare_dir)


@pytest.fixture
def client(bare_repo: str) -> _GitClient:
    c = _GitClient(
        repo=bare_repo,
        branch="main",
        zone_path="",
        zone_prefix="",
        zone_suffix=".zone",
        git_user="test",
        git_email="test@test",
    )
    yield c
    c.cleanup()


class TestMakeRecordLines:
    def _zone(self, *lines: str) -> list[str]:
        return [l + "\n" for l in lines]

    def test_add_to_empty_zone(self):
        zone = self._zone(
            "$ORIGIN example.com.",
            "$TTL 3600",
            "@  IN  SOA  ns1.example.com. admin.example.com. (",
            "  2024010101  ; serial",
            "  3600        ; refresh",
            "  900         ; retry",
            "  604800      ; expire",
            "  86400       ; minimum",
            ")",
            "@  IN  NS  ns1.example.com.",
        )
        result = _make_record_lines("add", "example.com", "abc123", zone)
        result_str = "".join(result)
        expected = textwrap.dedent("""\
            $ORIGIN example.com.
            $TTL 3600
            @  IN  SOA  ns1.example.com. admin.example.com. (
              2024010101  ; serial
              3600        ; refresh
              900         ; retry
              604800      ; expire
              86400       ; minimum
            )
            _acme-challenge.example.com. IN TXT "abc123"
            @  IN  NS  ns1.example.com.
            """)
        assert result_str == expected

    def test_update_existing_record(self):
        zone = self._zone(
            "$ORIGIN example.com.",
            '_acme-challenge.example.com. IN TXT "oldvalue"',
        )
        result = _make_record_lines("add", "example.com", "newvalue", zone)
        assert "newvalue" in "".join(result)
        assert "oldvalue" not in "".join(result)

    def test_remove_record(self):
        zone = self._zone(
            "$ORIGIN example.com.",
            '_acme-challenge.example.com. IN TXT "abc123"',
        )
        result = _make_record_lines("remove", "example.com", "abc123", zone)
        assert "_acme-challenge" not in "".join(result)

    def test_remove_nonexistent_record(self):
        zone = self._zone("$ORIGIN example.com.")
        result = _make_record_lines("remove", "example.com", "abc123", zone)
        assert len(result) == len(zone)

    def test_relative_format(self):
        zone = self._zone(
            "$ORIGIN example.com.",
            '_acme-challenge IN TXT "old"',
        )
        result = _make_record_lines("add", "example.com", "new", zone)
        result_str = "".join(result)
        assert '_acme-challenge.example.com. IN TXT "new"' in result_str
        assert 'IN TXT "old"' not in result_str

    def test_mixed_case_record(self):
        zone = self._zone("_acme-challenge.example.com. in txt \"val\"")
        result = _make_record_lines("add", "example.com", "new", zone)
        assert "new" in "".join(result)

    def test_with_ttl(self):
        zone = self._zone(
            "$ORIGIN example.com.",
            "_acme-challenge  300  IN  TXT  \"val\"",
        )
        result = _make_record_lines("add", "example.com", "new", zone)
        assert "new" in "".join(result)
        assert "val" not in "".join(result)


class TestGitClientE2E:
    def test_add_txt_record(self, client: _GitClient):
        assert client.add_txt_record("example.com", "abc123") is True
        content = (client._repo_dir / "example.com.zone").read_text()
        assert '_acme-challenge.example.com. IN TXT "abc123"' in content

    def test_remove_txt_record(self, client: _GitClient):
        client.add_txt_record("example.com", "abc123")
        assert client.remove_txt_record("example.com", "abc123") is True
        content = (client._repo_dir / "example.com.zone").read_text()
        assert "_acme-challenge" not in content

    def test_noop_when_record_exists(self, client: _GitClient):
        client.add_txt_record("example.com", "abc123")
        assert client.add_txt_record("example.com", "abc123") is False

    def test_push_to_remote(self, bare_repo: str, client: _GitClient):
        client.add_txt_record("example.com", "abc123")
        client.cleanup()

        verify = Path(temp := __import__("tempfile").mkdtemp())
        try:
            clone(source=bare_repo, target=str(verify))
            content = (verify / "example.com.zone").read_text()
            assert '_acme-challenge.example.com. IN TXT "abc123"' in content
        finally:
            shutil.rmtree(temp)

    def test_remove_nonexistent_record_returns_false(self, client: _GitClient):
        assert client.remove_txt_record("example.com", "doesnotexist") is False

    def test_token_auth_https_check(self):
        with pytest.raises(Exception):
            c = _GitClient(
                repo="https://github.com/user/repo.git",
                token="test",
                branch="main",
            )
            c._clone()
            c.cleanup()
