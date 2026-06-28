import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from certbot_dns_git._internal.dns_git import _make_record_lines


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
