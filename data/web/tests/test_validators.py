import re

import pytest

from crassostrea import validators as v


@pytest.mark.parametrize("value,expected", [
    ("user@example.com", "user@example.com"),
    ("User@Example.COM", "user@example.com"),
    ("@example.com", "*@example.com"),
    ("example.com", "*@example.com"),
    ("*@*.example.com", "*@*.example.com"),
    ("news+promo@shop.example", "news+promo@shop.example"),
])
def test_sender_pattern_normalisation(value, expected):
    assert v.normalize_sender_pattern(value) == expected


@pytest.mark.parametrize("value", [
    "", "*", "*@*", "a@b@c", "user@exa mple.com", "user@example.com/i", "us\"er@example.com",
    "user@example.com\n/.*/", "#comment@example.com",
])
def test_sender_pattern_rejects_dangerous_values(value):
    with pytest.raises(v.ValidationError):
        v.normalize_sender_pattern(value)


def test_sender_regex_matches_expected_addresses():
    regex = v.sender_pattern_to_regex("*@example.com")
    assert regex == r"/^.*@example\.com$/i"
    compiled = re.compile(regex[1:-2], re.I)
    assert compiled.match("anyone@example.com")
    assert not compiled.match("anyone@example.com.evil.org")
    assert not compiled.match("anyone@exampleXcom")

    plus = re.compile(v.sender_pattern_to_regex("a+b@x.org")[1:-2], re.I)
    assert plus.match("a+b@x.org")
    assert not plus.match("aab@x.org")


@pytest.mark.parametrize("value,expected", [
    ("Example.COM.", "example.com"),
    ("sub.example.co.uk", "sub.example.co.uk"),
    ("xn--bcher-kva.example", "xn--bcher-kva.example"),
])
def test_domain(value, expected):
    assert v.normalize_domain(value) == expected


@pytest.mark.parametrize("value", ["localhost", "-bad.com", "exa_mple.com", "a" * 64 + ".com", "1.2.3.4"])
def test_domain_invalid(value):
    with pytest.raises(v.ValidationError):
        v.normalize_domain(value)


@pytest.mark.parametrize("value,expected", [
    ("mail.internal", "mail.internal"),
    ("[192.0.2.10]", "192.0.2.10"),
    ("2001:db8::1", "2001:db8::1"),
    ("exchange01", "exchange01"),
])
def test_host(value, expected):
    assert v.normalize_host(value) == expected


def test_network():
    assert v.normalize_network("192.0.2.7/24") == "192.0.2.0/24"
    assert v.normalize_network("2001:db8::1") == "2001:db8::1/128"
    with pytest.raises(v.ValidationError):
        v.normalize_network("not-an-ip")
