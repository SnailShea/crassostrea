"""Client for the Rspamd controller API (stats, learning)."""
import requests
from flask import current_app


class RspamdError(Exception):
    pass


class RspamdClient:
    def __init__(self, url, password, timeout=10):
        self.url = url.rstrip("/")
        self.password = password
        self.timeout = timeout

    def _request(self, method, path, data=None, headers=None, timeout=None):
        hdrs = {"Password": self.password}
        hdrs.update(headers or {})
        try:
            response = requests.request(method, self.url + path, data=data, headers=hdrs,
                                        timeout=timeout or self.timeout)
        except requests.RequestException as exc:
            raise RspamdError(f"Rspamd is not reachable: {exc}") from exc
        if response.status_code == 403:
            raise RspamdError("Rspamd rejected the controller password (check RSPAMD_PASSWORD)")
        return response

    def _json(self, method, path, **kwargs):
        response = self._request(method, path, **kwargs)
        try:
            payload = response.json()
        except ValueError:
            raise RspamdError(f"Unexpected response from Rspamd ({response.status_code})")
        if response.status_code >= 400 or (isinstance(payload, dict) and payload.get("error")):
            message = payload.get("error") if isinstance(payload, dict) else None
            raise RspamdError(message or f"Rspamd returned HTTP {response.status_code}")
        return payload

    def ping(self):
        try:
            response = self._request("GET", "/ping", timeout=3)
        except RspamdError:
            return False
        return response.ok and response.text.strip() == "pong"

    def stat(self):
        return self._json("GET", "/stat")

    def learn(self, message, spam):
        return self._json("POST", "/learnspam" if spam else "/learnham", data=message, timeout=60)

    def fuzzy_add(self, message, flag=11, weight=10):
        """Add a message to the local fuzzy storage (flag 11 = LOCAL_FUZZY_DENIED)."""
        return self._json("POST", "/fuzzyadd", data=message,
                          headers={"Flag": str(flag), "Weight": str(weight)}, timeout=60)


def client():
    return RspamdClient(current_app.config["RSPAMD_URL"], current_app.config["RSPAMD_PASSWORD"])


def train(message, spam):
    """Learn a message as spam (incl. local fuzzy hash) or ham.

    Returns a list of human readable result strings. "Already learned" is
    not treated as an error.
    """
    rspamd = client()
    results = []
    try:
        rspamd.learn(message, spam)
        results.append("learned as spam" if spam else "learned as ham")
    except RspamdError as exc:
        if "already learned" not in str(exc).lower():
            raise
        results.append("was already learned")
    if spam:
        try:
            rspamd.fuzzy_add(message)
            results.append("fuzzy hash stored")
        except RspamdError as exc:
            current_app.logger.warning("fuzzy_add failed: %s", exc)
    return results
