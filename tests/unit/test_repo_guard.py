"""Unit tests for repo_guard.py scan(): forbidden files, MAC addresses, site IPs and sensitive terms."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E402

import shutil  # noqa: E402
import tempfile  # noqa: E402
import unittest  # noqa: E402

import repo_guard  # noqa: E402
import store  # noqa: E402
from fixtures import mac  # noqa: E402

SITE = {"internal_cidr": "10.77.0.0/16", "wan_ip": "203.0.113.200", "sensitive_terms": ["zorblaxhost", "ab", "Two Words"],
        "site_name": "Quuxfamily", "gateway_name": "gw", "own_domains": ["quux-home.test"]}


class _TmpFiles(unittest.TestCase):
    """Base: a temp directory for scanned sample files."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="guard-")

    def tearDown(self):
        shutil.rmtree(self.dir, True)

    def write(self, name, text, mode="w"):
        p = os.path.join(self.dir, name)
        with open(p, mode) as f:
            f.write(text)
        return p

    def whys(self, path):
        return [w for _, _, w in repo_guard.scan([path])]


class ForbiddenFilesTest(_TmpFiles):
    """Files that must never be committed are refused by name."""

    def test_forbidden_names(self):
        """Site/policy JSON, .env, DBs, keys, PDFs and JSONL files are refused even if they do not exist.
        REQ: SEC-04"""
        for p in ("site.json", "conf/policy.json", "host_policy.json", "known_benign.json", "sec_accepted.json", ".env",
                  "x/netmon.db", "certs/server.pem", "server.key", "report.pdf", "logs/a.jsonl"):
            self.assertEqual(repo_guard.scan([p]), [(p, 0, "file must never be committed")], p)

    def test_forbidden_directories(self):
        """Anything under data/, baseline/, dashboard/state, dashboard/certs or intel/ (except the ATT&CK catalog) is refused.
        REQ: SEC-04"""
        for p in ("data/2026-01-05T1200Z.json", "baseline/x.txt", "dashboard/state/users.json", "dashboard/certs/a.crt", "intel/feodo_ips.txt"):
            self.assertTrue(repo_guard.scan([p]), p)

    def test_allowed_names(self):
        """Ordinary source names, the ATT&CK catalog and look-alike names are not refused by name.
        REQ: SEC-04"""
        for p in ("intel/attack_enterprise.json", "mysite.json.example", "docs/SETUP.md", "store.py", "dashboard/app/static/app.js"):
            self.assertFalse(repo_guard.FORBIDDEN_FILES.search(p), p)

    def test_forbidden_absolute_path_in_temp_dir(self):
        """An absolute path to a forbidden file name outside the repo is still refused.
        REQ: SEC-04"""
        p = self.write("site.json", "{}")
        res = repo_guard.scan([p])
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0][1:], (0, "file must never be committed"))

    def test_missing_ordinary_file_is_skipped(self):
        """A non-forbidden path that does not exist (deleted file) is not reported.
        REQ: SEC-04"""
        self.assertEqual(repo_guard.scan([os.path.join(self.dir, "gone.py")]), [])


class MacDetectionTest(_TmpFiles):
    """MAC addresses in file content are reported with their line number."""

    def setUp(self):
        super().setUp()
        _env.fresh_db()  # no site config: only MACs / file names count

    def test_mac_detected_with_line_number(self):
        """A MAC address on line 3 is reported as 'MAC address' on line 3.
        REQ: SEC-04"""
        p = self.write("a.py", f"x = 1\ny = 2\nm = '{mac(10)}'\n")
        res = repo_guard.scan([p])
        self.assertEqual([(n, w) for _, n, w in res], [(3, "MAC address")])

    def test_uppercase_mac_detected(self):
        """Upper-case MAC addresses are detected too.
        REQ: SEC-04"""
        self.assertEqual(self.whys(self.write("b.txt", "dev " + mac(171).upper() + " seen")), ["MAC address"])

    def test_mac_built_at_runtime_not_flagged(self):
        """Code that builds a MAC at run time (no literal) is clean.
        REQ: SEC-04"""
        p = self.write("c.py", 'def mac(i):\n    return ":".join(["02", "00", "00", "00", "00", "%02x" % i])\n')
        self.assertEqual(repo_guard.scan([p]), [])

    def test_non_mac_patterns_clean(self):
        """Timestamps, IPv6 fragments with fewer than six groups and plain hex are not MACs.
        REQ: SEC-04"""
        p = self.write("d.txt", "time 12:30:45\nfe80::1\nhash deadbeefcafe\nratio 02:00:00:00:00\n")
        self.assertEqual(repo_guard.scan([p]), [])

    def test_skip_content_files(self):
        """Vendored chart.umd.min.js and PNGs are not content-scanned.
        REQ: SEC-04"""
        p1 = self.write("chart.umd.min.js", mac(1))
        p2 = self.write("icon.png", mac(2))
        self.assertEqual(repo_guard.scan([p1, p2]), [])

    def test_no_site_config_ignores_private_ips(self):
        """Without site settings, ordinary private and documentation IPs are not flagged.
        REQ: SEC-04"""
        p = self.write("e.md", "host 10.0.0.5 and 198.51.100.4\n")
        self.assertEqual(repo_guard.scan([p]), [])

    def test_multiple_files_and_lines(self):
        """Findings from several files are all returned, each with its own file and line.
        REQ: SEC-04"""
        p1 = self.write("f1.txt", mac(3) + "\nok\n" + mac(4) + "\n")
        p2 = self.write("f2.txt", "clean\n")
        res = repo_guard.scan([p1, p2])
        self.assertEqual([n for _, n, _ in res], [1, 3])
        self.assertTrue(all(f.endswith("f1.txt") for f, _, _ in res))


class SiteValuesTest(_TmpFiles):
    """Site IPs and sensitive terms come from the stored site settings."""

    def setUp(self):
        super().setUp()
        store.cfg_save("site", SITE)

    def tearDown(self):
        _env.fresh_db()
        super().tearDown()

    def test_site_values_from_store(self):
        """_site_values() collects every IP in the settings, terms of 4+ chars (longest first) and the internal network.
        REQ: SEC-04"""
        ips, terms, net = repo_guard._site_values()
        self.assertIn("203.0.113.200", ips)
        self.assertEqual(str(net), "10.77.0.0/16")
        self.assertIn("zorblaxhost", terms)
        self.assertIn("Quuxfamily", terms)
        self.assertIn("quux-home.test", terms)
        self.assertNotIn("ab", terms)
        self.assertNotIn("gw", terms)
        self.assertEqual(terms, sorted(terms, key=len, reverse=True))

    def test_internal_cidr_ip_flagged(self):
        """An IP inside internal_cidr is flagged as a site IP; one outside is not.
        REQ: SEC-04"""
        self.assertEqual(self.whys(self.write("a.txt", "ip 10.77.3.4\n")), ["site IP 10.77.3.4"])
        self.assertEqual(self.whys(self.write("b.txt", "ip 10.78.3.4\n")), [])

    def test_ip_listed_in_settings_flagged(self):
        """An IP that appears anywhere in the site settings (the WAN IP) is flagged.
        REQ: SEC-04"""
        self.assertEqual(self.whys(self.write("a.txt", "wan=203.0.113.200;\n")), ["site IP 203.0.113.200"])

    def test_ip_boundaries(self):
        """An IP embedded in a longer dotted number is not taken for a site IP.
        REQ: SEC-04"""
        self.assertEqual(self.whys(self.write("a.txt", "version 1.10.77.3.4\n")), [])

    def test_sensitive_term_case_insensitive(self):
        """A sensitive term is found regardless of case and reported as written.
        REQ: SEC-04"""
        self.assertEqual(self.whys(self.write("a.txt", "ssh ZorblaxHost now\n")), ["site term 'ZorblaxHost'"])

    def test_term_inside_longer_word_ignored(self):
        """A term that continues into a longer word does not match.
        REQ: SEC-04"""
        self.assertEqual(self.whys(self.write("a.txt", "zorblaxhosting and xzorblaxhost\n")), [])

    def test_two_word_term(self):
        """A two-word term matches as a phrase but not as part of a longer phrase.
        REQ: SEC-04"""
        self.assertEqual(self.whys(self.write("a.txt", "the two words here\n")), ["site term 'two words'"])
        self.assertEqual(self.whys(self.write("b.txt", "two wordsmiths\n")), [])

    def test_domain_term(self):
        """An own domain from the settings is flagged.
        REQ: SEC-04"""
        self.assertEqual(self.whys(self.write("a.txt", "url https://nas.quux-home.test/x\n")), ["site term 'quux-home.test'"])

    def test_combined_reasons_on_one_line(self):
        """Several problems on one line are reported together, comma-separated.
        REQ: SEC-04"""
        w = self.whys(self.write("a.txt", f"zorblaxhost 10.77.0.9 {mac(9)}\n"))
        self.assertEqual(w, ["site IP 10.77.0.9, MAC address, site term 'zorblaxhost'"])

    def test_short_terms_ignored(self):
        """Terms shorter than 4 characters never match.
        REQ: SEC-04"""
        self.assertEqual(self.whys(self.write("a.txt", "ab gw\n")), [])


if __name__ == "__main__":
    unittest.main()
