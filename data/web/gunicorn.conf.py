import os
import re

from gunicorn.glogging import Logger

# Digest links carry an access token in the path (/q/<token>/...)
_TOKEN_PATH = re.compile(r"/q/[^/?\s\"]+")


class TokenRedactingLogger(Logger):
    """Access log without digest link tokens: whoever can read the logs must
    not be able to open (and release) other people's quarantine."""

    def atoms(self, resp, req, environ, request_time):
        atoms = super().atoms(resp, req, environ, request_time)
        return {key: _TOKEN_PATH.sub("/q/[token]", value) if isinstance(value, str) else value
                for key, value in atoms.items()}


workers = int(os.environ.get("WEB_WORKERS", "2"))
threads = 4
timeout = 120
accesslog = "-"
errorlog = "-"
logger_class = TokenRedactingLogger
