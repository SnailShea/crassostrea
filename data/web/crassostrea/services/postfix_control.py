"""Client for the Postfix control service (mail queue).

The service (system/libexec/postfix-control) runs as root, socket-activated
per connection on a unix socket that only the crassostrea group may open. It
accepts one JSON request per connection, only for the fixed actions below,
and validates queue IDs itself.
"""
import json
import socket

from flask import current_app

QUEUE_TASKS = ("flush", "deliver", "hold", "unhold", "delete", "super_delete")


class PostfixControlError(Exception):
    pass


def _call(action, ids=None, timeout=30):
    request = {"action": action}
    if ids is not None:
        request["ids"] = list(ids)
    path = current_app.config["POSTFIX_CONTROL_SOCKET"]
    chunks = []
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(path)
            sock.sendall(json.dumps(request).encode() + b"\n")
            sock.shutdown(socket.SHUT_WR)
            while chunk := sock.recv(65536):
                chunks.append(chunk)
    except OSError as exc:
        raise PostfixControlError(f"Postfix control service is not reachable: {exc}") from exc
    try:
        response = json.loads(b"".join(chunks))
    except ValueError:
        raise PostfixControlError("Unexpected response from the Postfix control service")
    if not isinstance(response, dict):
        raise PostfixControlError("Unexpected response from the Postfix control service")
    if not response.get("ok"):
        raise PostfixControlError(response.get("error") or "command failed")
    return response


def mail_queue():
    """Parsed ``postqueue -j`` output."""
    return _call("list").get("queue") or []


def queue_message(queue_id):
    return _call("cat", [queue_id]).get("output", "")


def queue_action(task, queue_ids=None):
    """task: flush | deliver | hold | unhold | delete | super_delete"""
    if task not in QUEUE_TASKS:
        raise PostfixControlError(f"Unknown queue action {task}")
    return _call(task, None if task in ("flush", "super_delete") else (queue_ids or []))
