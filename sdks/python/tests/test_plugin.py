import json
import os
import sys
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from tenarium_plugin import (  # noqa: E402
    InvalidCredentials,
    NotFound,
    Plugin,
    Unsupported,
    make_server,
)

SECRET = "s3cret"


class Directory:
    """Implements verify_password but not send_invitation."""

    def __init__(self):
        self.passwords = {}

    def create_user(self, user):
        return "" if user["email"] == "empty@example.com" else "ext-" + user["email"]

    def update_user(self, user):
        if user.get("external_id") == "missing":
            raise NotFound()

    def delete_user(self, user):
        pass

    def set_password(self, user, password):
        if user["email"].endswith("@sso.example"):
            raise Unsupported()
        self.passwords[user["external_id"]] = password

    def verify_password(self, user, password):
        if self.passwords.get(user.get("external_id")) != password:
            raise InvalidCredentials()


outbox = []


def send(message):
    if message.get("subject") == "boom":
        raise RuntimeError("smtp down")
    outbox.append(message)


plugin = Plugin(id="dir-test", name="Directory test", version="0.0.0")


@plugin.init
def init(r):
    r.user_directory(Directory())
    r.mailer(send)


def user(**over):
    u = {"id": "u1", "email": "alice@example.com", "status": "active", "email_verified": True,
         "directory": "x", "version": 1, "external_id": "ext-alice@example.com"}
    u.update(over)
    return u


class DirectoryProtocolTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server(plugin, "127.0.0.1:0", SECRET)
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        status, body = cls.call("/init", {"protocol": 1, "instance": "dirs", "config": {}})
        assert status == 200, body
        cls.init_body = body

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    @classmethod
    def call(cls, path, body, secret=SECRET):
        req = Request(cls.base + path, data=json.dumps(body).encode(), method="POST",
                      headers={"Authorization": "Bearer " + secret, "Content-Type": "application/json"})
        try:
            with urlopen(req) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw) if raw else None
        except HTTPError as e:
            raw = e.read()
            return e.code, json.loads(raw) if raw else None

    def test_init_declares_directory_and_mailer(self):
        # verify_password is implemented, send_invitation is not; names default to the instance.
        self.assertEqual(self.init_body["user_directory"], {"verify_password": True})
        self.assertEqual(self.init_body["mailer"], {})

    def test_directory_operations(self):
        status, body = self.call("/directory/create_user", {"user": user(external_id=None)})
        self.assertEqual((status, body), (200, {"external_id": "ext-alice@example.com"}))
        for path, body in [
            ("/directory/update_user", {"user": user()}),
            ("/directory/delete_user", {"user": user()}),
            ("/directory/set_password", {"user": user(), "password": "pw"}),
            ("/directory/verify_password", {"user": user(), "password": "pw"}),
        ]:
            self.assertEqual(self.call(path, body)[0], 204, path)

    def test_errors_carry_codes(self):
        self.call("/directory/set_password", {"user": user(), "password": "pw"})
        cases = [
            ("/directory/update_user", {"user": user(external_id="missing")}, 404, "not_found"),
            ("/directory/set_password", {"user": user(email="bob@sso.example"), "password": "x"}, 501, "unsupported"),
            ("/directory/verify_password", {"user": user(), "password": "wrong"}, 403, "invalid_credentials"),
            ("/directory/send_invitation", {"user": user()}, 501, "unsupported"),
            ("/directory/create_user", {"user": user(email="empty@example.com")}, 500, None),
            ("/directory/explode", {"user": user()}, 404, None),
            ("/mailer/send", {"to": ["a@b.c"], "subject": "boom", "text": ""}, 500, None),
        ]
        for path, body, want_status, want_code in cases:
            status, resp = self.call(path, body)
            self.assertEqual(status, want_status, path)
            self.assertEqual(resp.get("code"), want_code, path)
            self.assertTrue(resp["error"], path)

    def test_mailer_sends(self):
        msg = {"to": ["a@b.c"], "subject": "Welcome", "text": "hi", "tag": "invitation"}
        self.assertEqual(self.call("/mailer/send", msg)[0], 204)
        self.assertEqual(outbox[-1], msg)

    def test_wrong_secret_is_refused(self):
        self.assertEqual(self.call("/mailer/send", {"to": ["a@b.c"]}, secret="nope")[0], 401)

    def test_registration_checks_required_methods(self):
        from tenarium_plugin import Registrar

        with self.assertRaises(TypeError):
            Registrar("x", {}).user_directory(object())
        with self.assertRaises(TypeError):
            Registrar("x", {}).mailer(object())


if __name__ == "__main__":
    unittest.main()
