import pytest
from app.services.defang import defang_url


def test_defang_http_and_https_schemes():
    assert defang_url("http://example.com") == "hxxp://example[.]com"
    assert defang_url("https://example.com") == "hxxps://example[.]com"
    assert defang_url("HTTP://MALICIOUS.COM/PATH") == "hxxp://MALICIOUS[.]COM/PATH"


def test_defang_subdomains_and_path():
    result = defang_url("https://login.microsoft.attacker.com/auth/login.php?user=test#top")
    assert result == "hxxps://login[.]microsoft[.]attacker[.]com/auth/login.php?user=test#top"


def test_defang_ip_literal():
    assert defang_url("http://192.168.1.1:8080/cmd") == "hxxp://192[.]168[.]1[.]1:8080/cmd"


def test_defang_userinfo_in_url():
    result = defang_url("http://admin@login.microsoft.attacker.com/")
    assert result == "hxxp://admin@login[.]microsoft[.]attacker[.]com/"


def test_defang_no_scheme_domain_or_path():
    assert defang_url("attacker.com") == "attacker[.]com"
    assert defang_url("attacker.com/malware.exe") == "attacker[.]com/malware.exe"


def test_defang_idempotence():
    already_defanged = "hxxps://attacker[.]com/login"
    assert defang_url(already_defanged) == "hxxps://attacker[.]com/login"


def test_defang_empty_or_none():
    assert defang_url("") == ""
    assert defang_url(None) == ""
