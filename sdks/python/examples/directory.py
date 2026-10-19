"""An in-memory user directory and mailer: the same "memdir" conformance
plugin as plugins/external/directory_test.go. Use it as a template for a
directory backed by your own identity system.

    plugins:
      - plugin: external
        name: memdir
        config:
          command: ["python3", "sdks/python/examples/directory.py"]
    users:
      directory: memdir
      mailer: memdir
"""

import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tenarium_plugin import InvalidCredentials, NotFound, Plugin, Unsupported, serve  # noqa: E402

plugin = Plugin(id="memdir-py", name="Memory directory (Python example)", version="1.0.0")
invited = []
sent = []


class MemoryDirectory:
    name = "memdir"

    def __init__(self):
        self.users = {}
        self.lock = threading.Lock()  # requests are served on several threads

    def _lookup(self, user):
        rec = self.users.get(user.get("external_id") or "")
        if rec is None:
            raise NotFound(f"no user {user.get('external_id')}")
        return rec

    def create_user(self, user):
        email = user["email"].lower()
        ext = "ext-" + email
        with self.lock:
            self.users.setdefault(ext, {"email": email, "name": user.get("name"), "password": None})
        return ext

    def update_user(self, user):
        with self.lock:
            rec = self._lookup(user)
            rec["email"], rec["name"] = user["email"].lower(), user.get("name")

    def delete_user(self, user):
        with self.lock:
            self.users.pop(user.get("external_id") or "", None)

    def set_password(self, user, password):
        with self.lock:
            rec = self._lookup(user)
            if rec["email"].endswith("@sso.example"):
                raise Unsupported("passwords are managed by SSO")
            rec["password"] = password

    def verify_password(self, user, password):
        with self.lock:
            rec = self.users.get(user.get("external_id") or "")
            if rec is None or not rec["password"] or rec["password"] != password:
                raise InvalidCredentials()

    def send_invitation(self, user):
        with self.lock:
            invited.append(self._lookup(user)["email"])


def send(message):
    if not message.get("to"):
        raise ValueError("no recipients")
    sent.append({"to": message["to"], "subject": message.get("subject", ""), "tag": message.get("tag", "")})


@plugin.init
def init(r):
    r.user_directory(MemoryDirectory())
    r.mailer(send, name="memmail")

    @r.route("GET /outbox")
    def outbox(req):
        return {"body": {"invited": invited, "sent": sent}}


if __name__ == "__main__":
    serve(plugin)
