"""Password hashes imported from other mail systems (passwords.py) and the
mailbox user API that takes them."""
import base64
import hashlib

import pytest

from crassostrea import passwords
from crassostrea.extensions import db
from crassostrea.models import Domain, MailboxUser

PASSWORD = "Old-Passw0rd!"
# made with libxcrypt and argon2-cffi for PASSWORD
VECTORS = {
    "md5-crypt": "$1$fvCKcK9j$jxH3h.4WpTNyzUXMg9K5z/",
    "sha256-crypt": "$5$zg/V9I7d2tltYmXo$exOOfh5S669pY3ozp9ZqbrFy82q098O3kJajyVl8960",
    "sha512-crypt": "$6$qB48wAvyKonTFd9b$fE6WqH4N.4ZP9y8ocUYduyzmgZyLHdJlfI81aaiB24VbLBimfPCHg.iTXHqFxsCqxxdE9sQmqNBV"
                    "xRHvCCxXH.",
    "bcrypt": "$2y$05$T2jp9Pe.IxQNYDwO/lgKYuIBySVyKO.pEf647GEGsv/0UgTf/0JYC",
    "yescrypt": "$y$j9T$mQ5YA5rENWPyblJHeTf7h1$1KurikYOP6N/Tp.2UAq7aXvMTAFV23TCL2kjjrmtsCB",
    "scrypt-crypt": "$7$CU..../....lq/nBoCOZw..WBVBrwe5J/$Xof.4sy9HhMPjz8unWYs20CfNstR1RmBRAcCYYpHDv3",
    "argon2id": "$argon2id$v=19$m=1024,t=1,p=1$Jiy/7Bjqn5OxcC0/3OHIVQ$8oQEqJcIr6VK9IXAyjeyNeWxTMtegu45qjV1QlZ5WJw",
}


def _ssha(name, salt=b"saltsalt", encode=base64.b64encode):
    return encode(hashlib.new(name, PASSWORD.encode() + salt).digest() + salt).decode()


def _imports():
    """(given hash, stored scheme) of every format."""
    sha512 = VECTORS["sha512-crypt"]
    django = base64.b64encode(hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), b"djsalt", 1000)).decode()
    dovecot = hashlib.pbkdf2_hmac("sha1", PASSWORD.encode(), b"dvsalt", 1000).hex()
    return [
        (sha512, "crypt"), ("{SHA512-CRYPT}" + sha512, "crypt"), ("{CRYPT}" + sha512, "crypt"),
        ("{SHA256-CRYPT}" + VECTORS["sha256-crypt"], "crypt"), ("{MD5-CRYPT}" + VECTORS["md5-crypt"], "crypt"),
        ("{MD5}" + VECTORS["md5-crypt"], "crypt"), ("{BLF-CRYPT}" + VECTORS["bcrypt"], "crypt"),
        (VECTORS["yescrypt"], "crypt"), (VECTORS["scrypt-crypt"], "crypt"),
        (VECTORS["argon2id"], "argon2"), ("{ARGON2ID}" + VECTORS["argon2id"], "argon2"),
        ("argon2" + VECTORS["argon2id"], "argon2"),
        ("{SSHA512}" + _ssha("sha512"), "ssha512"), ("{SSHA256}" + _ssha("sha256"), "ssha256"),
        ("{SSHA}" + _ssha("sha1"), "ssha"), ("{SMD5}" + _ssha("md5"), "smd5"),
        ("{SSHA256.HEX}" + (hashlib.sha256(PASSWORD.encode() + b"xy").digest() + b"xy").hex(), "ssha256"),
        ("{SHA512}" + base64.b64encode(hashlib.sha512(PASSWORD.encode()).digest()).decode(), "sha512"),
        ("{SHA256}" + base64.b64encode(hashlib.sha256(PASSWORD.encode()).digest()).decode(), "sha256"),
        ("{SHA}" + base64.b64encode(hashlib.sha1(PASSWORD.encode()).digest()).decode(), "sha"),
        ("{SHA.HEX}" + hashlib.sha1(PASSWORD.encode()).hexdigest(), "sha"),
        ("{PLAIN-MD5}" + hashlib.md5(PASSWORD.encode()).hexdigest(), "md5"),
        ("{LDAP-MD5}" + base64.b64encode(hashlib.md5(PASSWORD.encode()).digest()).decode(), "md5"),
        (f"pbkdf2_sha256$1000$djsalt${django}", "pbkdf2-django"),
        (f"{{PBKDF2}}$1$dvsalt$1000${dovecot}", "pbkdf2-dovecot"),
        ("pbkdf2:sha256:1000$abcdefgh$" + hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), b"abcdefgh", 1000).hex(),
         "pbkdf2"),
        ("{PLAIN}" + PASSWORD, "scrypt"), ("{CLEARTEXT}" + PASSWORD, "scrypt"),
    ]


@pytest.mark.parametrize("given, kind", _imports())
def test_import_and_verify(given, kind):
    stored = passwords.normalize(given)
    assert passwords.scheme(stored) == kind
    assert passwords.verify(stored, PASSWORD)
    assert not passwords.verify(stored, PASSWORD + "x") and not passwords.verify(stored, "")
    assert passwords.needs_upgrade(stored) == (kind != "scrypt")
    assert PASSWORD not in stored


@pytest.mark.parametrize("given, message", [
    ("", "non-empty"),
    ("5f4dcc3b5aa765d61d8327deb882cf99", "Unsupported password hash format"),   # bare hex: which digest?
    ("{NTLM}abc", "Unsupported password scheme"),
    ("abJnggxhB/yWI", "Unsupported"),                                           # DES crypt
    ("$2x$05$T2jp9Pe.IxQNYDwO/lgKYuIBySVyKO.pEf647GEGsv/0UgTf/0JYC", "Not a supported crypt"),
    ("$2y$31$T2jp9Pe.IxQNYDwO/lgKYuIBySVyKO.pEf647GEGsv/0UgTf/0JYC", "cost of at most"),
    ("$6$rounds=99999999$salt$hash", "at most 1000000 rounds"),
    ("$argon2id$v=19$m=4194304,t=1,p=1$Jiy/7Bjqn5OxcC0/3OHIVQ$8oQEqJcIr6VK9IXAyjeyNeWxTMtegu45qjV1QlZ5WJw",
     "too large"),
    ("{SSHA256}" + base64.b64encode(b"short").decode(), "not a digest with a salt"),
    ("{SHA256}" + base64.b64encode(b"x" * 20).decode(), "digest of 32 bytes"),
    ("{PLAIN}", "empty"),
    ("pbkdf2_sha256$9999999$s$abc=", "iterations"),
])
def test_refused(given, message):
    with pytest.raises(passwords.HashError, match=message):
        passwords.normalize(given)


def test_garbage_never_verifies():
    for stored in ("{CRYPT}$6$x$y", "{SSHA}!!!", "{ARGON2}$argon2id$bad", "{UNKNOWN}x", "nonsense"):
        assert not passwords.verify(stored, PASSWORD)


@pytest.fixture
def domain(app):
    d = Domain(name="example.com", destination_host="mx.internal")
    db.session.add(d)
    db.session.commit()
    return d


def test_api_import_and_upgrade_at_login(api, client, domain):
    body = api("POST", "/mailbox-users", json={"email": "alice@example.com",
                                                "password_hash": "{SHA512-CRYPT}" + VECTORS["sha512-crypt"]})
    assert body.status_code == 201, body.get_json()
    assert body.get_json()["password_format"] == "crypt"
    assert MailboxUser.query.one().password_hash.startswith("{CRYPT}$6$")
    response = client.post("/login", data={"username": "alice@example.com", "password": "wrong-password"})
    assert response.status_code == 200 and MailboxUser.query.one().password_hash.startswith("{CRYPT}")
    response = client.post("/login", data={"username": "alice@example.com", "password": PASSWORD})
    assert response.status_code == 302
    user = MailboxUser.query.one()
    assert user.password_hash.startswith("scrypt:") and user.check_password(PASSWORD)
    assert api("GET", f"/mailbox-users/{user.id}").get_json()["password_format"] == "scrypt"


def test_api_password_choices(api, domain):
    both = api("POST", "/mailbox-users", json={"email": "a@example.com", "password": "a-long-password",
                                                "password_hash": VECTORS["bcrypt"]})
    assert both.status_code == 422 and "either password or password_hash" in both.get_json()["error"]
    neither = api("POST", "/mailbox-users", json={"email": "a@example.com"})
    assert neither.status_code == 422
    bad = api("POST", "/mailbox-users", json={"email": "a@example.com", "password_hash": "{NTLM}x"})
    assert bad.status_code == 422 and bad.get_json()["field"] == "password_hash"
    user = api("POST", "/mailbox-users", json={"email": "a@example.com", "password": "a-long-password"}).get_json()
    assert user["password_format"] == "scrypt"
    patched = api("PATCH", f"/mailbox-users/{user['id']}", json={"password_hash": VECTORS["argon2id"]})
    assert patched.get_json()["password_format"] == "argon2"
    assert MailboxUser.query.one().check_password(PASSWORD)
