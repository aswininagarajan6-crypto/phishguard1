import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import phishguard as pg


class Tests(unittest.TestCase):
    def test_safe(self):
        self.assertEqual(pg.analyze_url("https://www.google.com")["verdict"], "SAFE")

    def test_ip_address(self):
        r = pg.analyze_url("http://192.168.1.5/login")
        self.assertIn("Uses an IP address instead of a domain name", r["reasons"])

    def test_at_symbol(self):
        r = pg.analyze_url("http://google.com@evil.tk/login")
        self.assertIn("Contains '@' in the address (hides real destination)", r["reasons"])

    def test_dangerous(self):
        r = pg.analyze_url("http://paypal-secure-login-verify.xyz/account/update")
        self.assertEqual(r["verdict"], "DANGEROUS")

    def test_brand_abuse(self):
        r = pg.analyze_url("https://amazon.account-check.top")
        self.assertTrue(any("Brand name" in x for x in r["reasons"]))

    def test_real_brand_ok(self):
        r = pg.analyze_url("https://www.paypal.com")
        self.assertFalse(any("Brand name" in x for x in r["reasons"]))


if __name__ == "__main__":
    unittest.main()
