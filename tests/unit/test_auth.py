"""Unit tests for dashboard/app/auth.py: password hashing, user management, roles, sessions and sign-in throttling."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import base64  # noqa: E402
import hashlib  # noqa: E402
import hmac  # noqa: E402
import stat  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import auth  # noqa: E402
import store  # noqa: E402

PW = "correct-horse-battery"      # placeholder test passwords (not real secrets)
PW2 = "another-long-passphrase"
LAN_IP = "10.0.1.10"
LAN_IP2 = "10.0.1.11"
NET_IP = "100.64.0.%d"            # shared address space: not private/loopback per ipaddress, not a real host


class _AuthBase(unittest.TestCase):
    """Common isolation: empty DB and cleared throttle state for every test."""

    @staticmethod
    def _reset_db():
        c = getattr(store._dl, "c", None)
        if c is not None:  # close store's cached connection so fresh_db does not leak it
            c.close()
        _env.fresh_db()

    def setUp(self):
        self._reset_db()
        auth._fail.clear()
        auth._ufail.clear()

    def tearDown(self):
        auth._fail.clear()
        auth._ufail.clear()
        self._reset_db()

    def _users(self, **recs):
        """Write a users document directly (no scrypt) for tests that do not sign in."""
        store.jdump(recs, auth.USERS)


class TestHashing(_AuthBase):
    """Password hashing and verification."""

    def test_hash_format_is_salted_scrypt(self):
        """A stored hash has the form scrypt$n$r$p$salt$dk with a 16-byte salt and 32-byte key.
        REQ: AUTH-01"""
        h = auth._hash(PW)
        parts = h.split("$")
        self.assertEqual(parts[0], "scrypt")
        self.assertEqual(parts[1:4], [str(2 ** 14), "8", "1"])
        self.assertEqual(len(bytes.fromhex(parts[4])), 16)
        self.assertEqual(len(bytes.fromhex(parts[5])), 32)
        self.assertNotIn(PW, h)

    def test_same_password_gets_different_salts(self):
        """Hashing the same password twice gives two different stored values (random salt).
        REQ: AUTH-01"""
        self.assertNotEqual(auth._hash(PW), auth._hash(PW))

    def test_verify_accepts_right_and_rejects_wrong_password(self):
        """The right password verifies; a wrong, empty or case-changed one does not.
        REQ: AUTH-01"""
        h = auth._hash(PW)
        self.assertTrue(auth._verify(PW, h))
        self.assertFalse(auth._verify(PW + "x", h))
        self.assertFalse(auth._verify("", h))
        self.assertFalse(auth._verify(PW.upper(), h))

    def test_verify_never_raises_on_damaged_hash(self):
        """A malformed stored hash (wrong field count, bad hex, None) simply fails verification.
        REQ: AUTH-01"""
        for bad in ("", "scrypt$1$2", "scrypt$16384$8$1$zz$00", None, "plain-text-password"):
            self.assertFalse(auth._verify(PW, bad), bad)


class TestUserManagement(_AuthBase):
    """Adding, deleting and resetting accounts."""

    def test_add_user_stores_hash_not_password(self):
        """add() creates a record with an scrypt hash, gen 1 and the requested role; the password is not stored.
        REQ: AUTH-01, AUTH-03"""
        self.assertIsNone(auth.add("alice", PW, "defender"))
        rec = auth.load()["alice"]
        self.assertTrue(rec["hash"].startswith("scrypt$"))
        self.assertEqual(rec["gen"], 1)
        self.assertEqual(rec["role"], "defender")
        self.assertNotIn(PW, repr(rec))
        self.assertTrue(auth._verify(PW, rec["hash"]))

    def test_new_account_gets_welcome_until_done(self):
        """add() flags a new account for the welcome walkthrough; welcome_done() clears it; other accounts are unaffected.
        REQ: AUTH-08"""
        self.assertIsNone(auth.add("carol", PW))
        self.assertIsNone(auth.add("dave", PW))
        self.assertTrue(auth.welcome_pending("carol"))
        auth.welcome_done("carol")
        self.assertFalse(auth.welcome_pending("carol"))
        self.assertTrue(auth.welcome_pending("dave"))
        self.assertFalse(auth.welcome_pending("nobody"))

    def test_add_rejects_short_password(self):
        """A 9-character password is rejected; exactly 10 characters is accepted.
        REQ: AUTH-02"""
        self.assertIn("at least 10", auth.add("bob", "x" * 9))
        self.assertNotIn("bob", auth.load())
        self.assertIsNone(auth.add("bob", "x" * 10))

    def test_add_rejects_missing_password(self):
        """A None password is treated as empty and rejected rather than crashing.
        REQ: AUTH-02"""
        self.assertIn("at least", auth.add("bob", None))

    def test_username_rules(self):
        """Usernames must be 2-40 chars of letters, digits and . _ @ -; anything else is rejected.
        REQ: AUTH-03"""
        for bad in ("a", "x" * 41, "has space", "semi;colon", "slash/name", "", None, "ümlaut"):
            self.assertIsNotNone(auth.add(bad, PW), repr(bad))
        self.assertEqual(auth.load(), {})
        for good in ("ab", "x" * 40, "first.last", "u_1", "me@example.org", "a-b"):
            self.assertIsNone(auth.add(good, PW), good)

    def test_duplicate_username_rejected(self):
        """Adding an existing username again fails and leaves the original record untouched.
        REQ: AUTH-03"""
        auth.add("alice", PW)
        before = auth.load()["alice"]["hash"]
        self.assertEqual(auth.add("alice", PW2), "user already exists")
        self.assertEqual(auth.load()["alice"]["hash"], before)

    def test_add_rejects_unknown_role(self):
        """Only admin, defender and user are accepted roles when adding.
        REQ: AC-02"""
        self.assertIn("role must be", auth.add("alice", PW, "root"))
        self.assertNotIn("alice", auth.load())

    def test_set_password_by_admin_bumps_generation(self):
        """An admin reset (actor != user) needs no current password, changes the hash and bumps gen.
        REQ: AUTH-02, AUTH-04, AC-08"""
        auth.add("alice", PW)
        self.assertIsNone(auth.set_password("alice", PW2, actor="admin1"))
        rec = auth.load()["alice"]
        self.assertTrue(auth._verify(PW2, rec["hash"]))
        self.assertEqual(rec["gen"], 2)

    def test_set_password_validation(self):
        """set_password rejects short passwords, unknown users, and a self-change with the wrong current password.
        REQ: AUTH-02"""
        auth.add("alice", PW)
        self.assertIn("at least", auth.set_password("alice", "short", actor="admin1"))
        self.assertEqual(auth.set_password("ghost", PW2), "no such user")
        self.assertEqual(auth.set_password("alice", PW2, actor="alice", current="wrong-one-here"), "current password is wrong")
        self.assertIsNone(auth.set_password("alice", PW2, actor="alice", current=PW))

    def test_delete_rules(self):
        """delete() refuses unknown users, self-deletion, the last user and the last admin; otherwise removes.
        REQ: AC-05, AC-08"""
        self._users(a1={"hash": "x", "role": "admin"})
        self.assertEqual(auth.delete("a1", "someone"), "can't delete the last user")
        self._users(a1={"hash": "x", "role": "admin"}, u1={"hash": "x", "role": "user"})
        self.assertEqual(auth.delete("nobody", "a1"), "no such user")
        self.assertEqual(auth.delete("a1", "a1"), "you can't delete the account you're logged in with")
        self.assertEqual(auth.delete("a1", "u1"), "can't delete the last admin")
        self.assertIsNone(auth.delete("u1", "a1"))
        self.assertEqual(set(auth.load()), {"a1"})


class TestRoles(_AuthBase):
    """Role lookup, changes and migration."""

    def test_role_of_least_privilege_default(self):
        """Unknown users, missing roles and unrecognised roles all resolve to 'user'.
        REQ: AC-02"""
        self._users(a={"role": "admin"}, d={"role": "defender"}, n={}, x={"role": "superuser"})
        self.assertEqual(auth.role_of("a"), "admin")
        self.assertEqual(auth.role_of("d"), "defender")
        self.assertEqual(auth.role_of("n"), "user")
        self.assertEqual(auth.role_of("x"), "user")
        self.assertEqual(auth.role_of("ghost"), "user")

    def test_public_list_normalises_roles_and_hides_hash(self):
        """public_list() is sorted by name, maps bad roles to 'user' and never exposes hashes.
        REQ: AC-02"""
        self._users(zed={"hash": "scrypt$secret", "role": "admin"}, amy={"hash": "scrypt$secret", "role": "bogus"})
        lst = auth.public_list()
        self.assertEqual([r["username"] for r in lst], ["amy", "zed"])
        self.assertEqual(lst[0]["role"], "user")
        self.assertNotIn("hash", repr(lst))

    def test_migrate_roles_once(self):
        """Accounts without a valid role become admin once; a second run migrates nothing.
        REQ: AUTH-07"""
        self._users(old={"hash": "x"}, bad={"hash": "x", "role": "boss"}, u={"hash": "x", "role": "user"})
        self.assertEqual(sorted(auth.migrate_roles()), ["bad", "old"])
        u = auth.load()
        self.assertEqual((u["old"]["role"], u["bad"]["role"], u["u"]["role"]), ("admin", "admin", "user"))
        self.assertEqual(auth.migrate_roles(), [])

    def test_set_role_rules(self):
        """set_role validates the role and user, protects the last admin and self-demotion, else applies at once.
        REQ: AC-05, AC-08"""
        self._users(a1={"role": "admin"}, u1={"role": "user"})
        self.assertIn("role must be", auth.set_role("u1", "god", "a1"))
        self.assertEqual(auth.set_role("ghost", "user", "a1"), "no such user")
        self.assertEqual(auth.set_role("a1", "user", "a1"), "can't remove the last admin")
        self.assertIsNone(auth.set_role("u1", "admin", "a1"))
        self.assertEqual(auth.role_of("u1"), "admin")
        self.assertEqual(auth.set_role("a1", "defender", "a1"), "you can't take admin away from yourself - ask another admin")
        self.assertIsNone(auth.set_role("a1", "defender", "u1"))
        self.assertEqual(auth.role_of("a1"), "defender")

    def test_read_upto_only_moves_forward(self):
        """The private read marker starts at 0, only increases, and ignores unknown users.
        REQ: AC-07"""
        self._users(u1={"role": "user"})
        self.assertEqual(auth.read_upto("u1"), 0)
        auth.set_read_upto("u1", 7)
        auth.set_read_upto("u1", 3)
        self.assertEqual(auth.read_upto("u1"), 7)
        auth.set_read_upto("ghost", 9)
        self.assertNotIn("ghost", auth.load())


class TestBootstrap(_AuthBase):
    """First-start seeding from DASH_USER / DASH_PASS."""

    def test_bootstrap_seeds_first_admin(self):
        """On an empty store bootstrap creates one admin whose password verifies.
        REQ: AUTH-06"""
        self.assertTrue(auth.bootstrap("owner", PW))
        u = auth.load()
        self.assertEqual(list(u), ["owner"])
        self.assertEqual(u["owner"]["role"], "admin")
        self.assertTrue(auth._verify(PW, u["owner"]["hash"]))

    def test_bootstrap_ignored_afterwards(self):
        """Once any account exists, bootstrap does nothing (env vars are ignored).
        REQ: AUTH-06"""
        self.assertTrue(auth.bootstrap("owner", PW))
        self.assertFalse(auth.bootstrap("intruder", PW2))
        self.assertEqual(list(auth.load()), ["owner"])

    def test_bootstrap_needs_both_values(self):
        """A missing user name or password seeds nothing.
        REQ: AUTH-06"""
        self.assertFalse(auth.bootstrap("", PW))
        self.assertFalse(auth.bootstrap("owner", ""))
        self.assertFalse(auth.bootstrap(None, None))
        self.assertEqual(auth.load(), {})


class TestSessions(_AuthBase):
    """Signed session cookies."""

    def setUp(self):
        super().setUp()
        self._users(alice={"hash": "x", "gen": 3, "role": "user"})

    def test_cookie_roundtrip(self):
        """A freshly made cookie maps back to its user and has four dot-separated fields.
        REQ: AUTH-04"""
        c = auth.make_cookie("alice", 3)
        self.assertEqual(len(c.split(".")), 4)
        self.assertEqual(auth.session_user(c), "alice")

    def test_tampered_cookie_rejected(self):
        """Changing the user, expiry, gen or signature of a cookie invalidates it.
        REQ: AUTH-04"""
        self._users(alice={"hash": "x", "gen": 3}, mallory={"hash": "x", "gen": 3})
        b64, exp, gen, sig = auth.make_cookie("alice", 3).split(".")
        other = base64.urlsafe_b64encode(b"mallory").decode()
        for bad in (f"{other}.{exp}.{gen}.{sig}", f"{b64}.{int(exp) + 999}.{gen}.{sig}", f"{b64}.{exp}.4.{sig}",
                    f"{b64}.{exp}.{gen}.{'0' * 64}", f"{b64}.{exp}.{gen}"):
            self.assertIsNone(auth.session_user(bad), bad)

    def test_garbage_cookie_values(self):
        """Empty, None and non-cookie strings give no user and never raise.
        REQ: AUTH-04"""
        for bad in ("", None, "a.b.c.d", "....", "x" * 500):
            self.assertIsNone(auth.session_user(bad))

    def test_expired_cookie_rejected(self):
        """A cookie whose expiry lies in the past is refused.
        REQ: AUTH-04"""
        with mock.patch.object(auth, "SESSION_TTL", -5):
            c = auth.make_cookie("alice", 3)
        self.assertIsNone(auth.session_user(c))

    def test_expiry_uses_session_ttl(self):
        """The expiry field is now + SESSION_TTL (SESSION_HOURS, default 12 h).
        REQ: AUTH-04"""
        exp = int(auth.make_cookie("alice", 3).split(".")[1])
        self.assertAlmostEqual(exp, time.time() + auth.SESSION_TTL, delta=5)

    def test_generation_bump_revokes_sessions(self):
        """After the user's gen changes (password change / reset) old cookies stop working.
        REQ: AUTH-04"""
        c = auth.make_cookie("alice", 3)
        self._users(alice={"hash": "x", "gen": 4})
        self.assertIsNone(auth.session_user(c))

    def test_deleted_user_session_rejected(self):
        """A valid signature for a user that no longer exists yields no session.
        REQ: AUTH-04"""
        c = auth.make_cookie("alice", 3)
        self._users(bob={"hash": "x", "gen": 3})
        self.assertIsNone(auth.session_user(c))

    def test_signature_is_hmac_of_body_with_secret(self):
        """The signature is HMAC-SHA256 over 'b64user.exp.gen' with the secret key, which is owner-only.
        REQ: AUTH-04, SEC-06"""
        c = auth.make_cookie("alice", 3)
        body, sig = c.rsplit(".", 1)
        self.assertEqual(sig, hmac.new(auth._secret(), body.encode(), hashlib.sha256).hexdigest())
        self.assertEqual(stat.S_IMODE(os.stat(auth.SECRET).st_mode), 0o600)
        self.assertGreaterEqual(len(auth._secret()), 32)

    def test_short_secret_file_regenerated(self):
        """A truncated secret key file is replaced, invalidating cookies signed with the old key.
        REQ: AUTH-04"""
        c = auth.make_cookie("alice", 3)
        with open(auth.SECRET, "wb") as f:
            f.write(b"short")
        self.assertIsNone(auth.session_user(c))
        with open(auth.SECRET, "rb") as f:
            self.assertEqual(len(f.read()), 32)


class TestLogin(_AuthBase):
    """Sign-in and throttling."""

    def setUp(self):
        super().setUp()
        auth.add("alice", PW, "admin")

    def test_login_success_records_last_login(self):
        """Correct credentials return a valid cookie, no error, and set last_login.
        REQ: AUTH-01, AUTH-04"""
        cookie, err = auth.login("alice", PW, LAN_IP)
        self.assertIsNone(err)
        self.assertEqual(auth.session_user(cookie), "alice")
        self.assertIsNotNone(auth.load()["alice"]["last_login"])

    def test_login_failures_same_message(self):
        """Wrong password and unknown user both fail with the same generic message.
        REQ: AUTH-01"""
        self.assertEqual(auth.login("alice", "wrong-password-x", LAN_IP), (None, "invalid username or password"))
        self.assertEqual(auth.login("nobody", PW, LAN_IP), (None, "invalid username or password"))
        self.assertEqual(auth.login("alice", None, LAN_IP), (None, "invalid username or password"))

    def test_ip_throttle_after_eight_failures(self):
        """After 8 failures from one address even the right password is refused there, but not from another address.
        REQ: AUTH-05"""
        for _ in range(auth.IP_MAX):
            auth.login("alice", "wrong-password-x", LAN_IP)
        cookie, err = auth.login("alice", PW, LAN_IP)
        self.assertIsNone(cookie)
        self.assertIn("too many failed attempts", err)
        cookie, err = auth.login("alice", PW, LAN_IP2)
        self.assertIsNotNone(cookie)

    def test_ip_throttle_window_expires(self):
        """Failures older than the 5-minute window no longer count.
        REQ: AUTH-05"""
        auth._fail[LAN_IP] = [time.time() - auth.IP_WIN - 1] * auth.IP_MAX
        self.assertFalse(auth.throttled(LAN_IP))
        auth._fail[LAN_IP] = [time.time()] * auth.IP_MAX
        self.assertTrue(auth.throttled(LAN_IP))

    def test_success_clears_ip_failures(self):
        """A successful sign-in resets that address's failure count.
        REQ: AUTH-05"""
        for _ in range(3):
            auth.login("alice", "wrong-password-x", LAN_IP)
        self.assertEqual(len(auth._fail[LAN_IP]), 3)
        auth.login("alice", PW, LAN_IP)
        self.assertNotIn(LAN_IP, auth._fail)

    def test_remote_account_lock(self):
        """20 Internet failures against one account lock remote sign-in to it, while the LAN still works.
        REQ: AUTH-05"""
        now = time.time()
        auth._ufail["alice"] = [(now, NET_IP % i) for i in range(auth.USER_MAX)]
        cookie, err = auth.login("alice", PW, NET_IP % 200)
        self.assertIsNone(cookie)
        self.assertIn("temporarily locked", err)
        cookie, err = auth.login("alice", PW, LAN_IP)
        self.assertIsNotNone(cookie)

    def test_lan_failures_do_not_lock_remote(self):
        """Failures from LAN addresses never count toward the per-account Internet lock.
        REQ: AUTH-05"""
        auth._ufail["alice"] = [(time.time(), LAN_IP)] * (auth.USER_MAX + 5)
        self.assertFalse(auth.user_throttled("alice", NET_IP % 1))

    def test_failed_login_records_user_failure(self):
        """A failed sign-in from the Internet is recorded against the username with its source address.
        REQ: AUTH-05"""
        auth.login("alice", "wrong-password-x", NET_IP % 7)
        self.assertEqual([ip for _, ip in auth._ufail["alice"]], [NET_IP % 7])

    def test_private_detection(self):
        """RFC1918, loopback and documentation ranges count as private; garbage does not.
        REQ: AUTH-05"""
        self.assertTrue(auth._private(LAN_IP))
        self.assertTrue(auth._private("127.0.0.1"))
        self.assertTrue(auth._private("192.0.2.5"))
        self.assertFalse(auth._private(NET_IP % 1))
        self.assertFalse(auth._private("not-an-ip"))


class TestChangeOwnPassword(_AuthBase):
    """Self-service password change."""

    def setUp(self):
        super().setUp()
        auth.add("alice", PW, "user")

    def test_change_success_reissues_cookie(self):
        """A valid change returns a new working cookie and revokes the old session.
        REQ: AUTH-04, DASH-03"""
        old, _ = auth.login("alice", PW, LAN_IP)
        new, err = auth.change_own_password("alice", PW, PW2, LAN_IP)
        self.assertIsNone(err)
        self.assertEqual(auth.session_user(new), "alice")
        self.assertIsNone(auth.session_user(old))
        self.assertTrue(auth._verify(PW2, auth.load()["alice"]["hash"]))

    def test_change_rejections(self):
        """Wrong current, unchanged, containing the username, or too-short new passwords are rejected.
        REQ: AUTH-02, DASH-03"""
        self.assertEqual(auth.change_own_password("alice", "wrong-password-x", PW2, LAN_IP), (None, "current password is wrong"))
        self.assertEqual(auth.change_own_password("alice", PW, PW, LAN_IP)[1], "the new password must be different from the current one")
        self.assertEqual(auth.change_own_password("alice", PW, "my-ALICE-password", LAN_IP)[1], "the password must not contain your username")
        self.assertIn("at least", auth.change_own_password("alice", PW, "short", LAN_IP)[1])
        self.assertEqual(auth.change_own_password("ghost", PW, PW2, LAN_IP), (None, "no such user"))
        self.assertTrue(auth._verify(PW, auth.load()["alice"]["hash"]))

    def test_wrong_current_counts_toward_throttle(self):
        """Wrong current passwords share the per-IP throttle with failed logins.
        REQ: AUTH-05"""
        auth._fail[LAN_IP] = [time.time()] * (auth.IP_MAX - 1)
        auth.change_own_password("alice", "wrong-password-x", PW2, LAN_IP)
        self.assertEqual(auth.change_own_password("alice", PW, PW2, LAN_IP), (None, "too many failed attempts - wait 5 minutes"))

    def test_account_info(self):
        """account_info reports role and minimum password length without the hash.
        REQ: DASH-03"""
        info = auth.account_info("alice")
        self.assertEqual((info["user"], info["role"], info["min_password"]), ("alice", "user", 10))
        self.assertNotIn("hash", info)


if __name__ == "__main__":
    unittest.main()
