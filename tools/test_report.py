#!/usr/bin/env python3
"""Tests for build_report.py and sign_report.py: python3 -m unittest discover -s tools -p 'test_*.py'

Grype's results here are small stand-ins with the fields build_report reads; the shape was taken
from a real `grype registry:... --platform linux/arm64 -o json` run (grype 0.120.1).
"""
import base64
import copy
import json
import os
import sys
import unicodedata
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_report as br

try:
    import sign_report
except ImportError:  # cryptography isn't installed; the signing tests are skipped
    sign_report = None

INDEX = "sha256:" + "a" * 64
ARM = "sha256:" + "b" * 64
OTHER = "sha256:" + "c" * 64


def match(vid, severity, name="openssl", version="3.0.1", fixed=("3.0.2",), state="fixed", related=()):
    return {
        "vulnerability": {"id": vid, "severity": severity, "fix": {"versions": list(fixed), "state": state}},
        "relatedVulnerabilities": [{"id": r} for r in related],
        "artifact": {"name": name, "version": version},
    }


def scan(reference="docker.io/library/nats:2.15.0", matches=(), index=INDEX, arm=ARM, arch="arm64"):
    return {
        "matches": list(matches),
        "source": {"type": "image", "target": {
            "userInput": reference, "manifestDigest": arm, "architecture": arch, "os": "linux",
            "repoDigests": ["index.docker.io/library/nats@" + index]}},
        "descriptor": {"name": "grype", "version": "0.120.1",
                       "db": {"status": {"built": "2026-10-18T06:27:17Z"}}},
    }


def library(*images):
    return {"schema": 1, "version": "1", "entries": [
        {"id": "x%d" % n, "kind": "container", "container": {"image": image}} for n, image in enumerate(images)]}


# The same inputs as VulnerabilityReportTests.nastyText in Flotilla; keep the two lists together.
NASTY = ["x\u001b[31mred", "a\u202eevil", "zero\u200bwidth", "tab\there", "line\nbreak", "nb\u00a0sp",
         "sep\u2028sep", "a" * 255 + "\u00e9", "\u00e9" * 200, "\u202e\n", "x" * 1000]


def consumer_accepts(text, limit=256, required=False):
    """Mirror of `VulnerabilityReport.isText`: bounded bytes, no control, format or non-space whitespace."""
    if len(text.encode("utf-8")) > limit or (required and not text):
        return False
    return not any(unicodedata.category(c) in ("Cc", "Cf") or (c.isspace() and c != " ") for c in text)


class BuildReport(unittest.TestCase):
    def build(self, scans, images=("docker.io/library/nats:2.15.0",)):
        return br.build(library(*images), scans, "2026-10-18T07:00:00Z")

    def test_shape_and_both_digests(self):
        report, problems = self.build([scan(matches=[match("CVE-2026-1", "Critical")])])
        self.assertEqual(problems, [])
        self.assertEqual(report["schema"], 1)
        self.assertEqual(report["generated"], "2026-10-18T07:00:00Z")
        self.assertEqual(report["scanner"], {"name": "grype", "version": "0.120.1", "dbBuilt": "2026-10-18T06:27:17Z"})
        image = report["images"][0]
        self.assertEqual(image["digests"], [INDEX, ARM])
        self.assertEqual(image["findings"], [{"id": "CVE-2026-1", "severity": "Critical", "package": "openssl",
                                              "installed": "3.0.1", "fixed": "3.0.2"}])

    def test_counts_cover_every_severity_but_findings_only_critical_and_high(self):
        matches = [match("CVE-1", "Critical"), match("CVE-2", "High"), match("CVE-3", "Medium"),
                   match("CVE-4", "Low"), match("CVE-5", "Low", name="zlib"), match("CVE-6", "Negligible"),
                   match("CVE-7", "Unknown")]
        image = self.build([scan(matches=matches)])[0]["images"][0]
        self.assertEqual(image["counts"], {"critical": 1, "high": 1, "medium": 1, "low": 2})
        self.assertEqual([f["id"] for f in image["findings"]], ["CVE-1", "CVE-2"])

    def test_unfixed_has_null_fixed(self):
        image = self.build([scan(matches=[match("CVE-1", "High", fixed=(), state="not-fixed"),
                                          match("CVE-2", "High", fixed=("1.2",), state="wont-fix")])])[0]["images"][0]
        self.assertEqual([f["fixed"] for f in image["findings"]], [None, None])

    def test_same_finding_at_two_paths_counts_once(self):
        image = self.build([scan(matches=[match("CVE-1", "High"), match("CVE-1", "High")])])[0]["images"][0]
        self.assertEqual(image["counts"]["high"], 1)
        self.assertEqual(len(image["findings"]), 1)

    def test_a_cve_alias_replaces_an_advisory_number(self):
        image = self.build([scan(matches=[match("GHSA-xxxx", "High", related=("CVE-2026-9", "CVE-2026-1"))])])[0]["images"][0]
        self.assertEqual(image["findings"][0]["id"], "CVE-2026-1")

    def test_findings_sort_critical_first_then_id(self):
        matches = [match("CVE-3", "High"), match("CVE-9", "Critical"), match("CVE-1", "High"), match("CVE-2", "Critical")]
        image = self.build([scan(matches=matches)])[0]["images"][0]
        self.assertEqual([f["id"] for f in image["findings"]], ["CVE-2", "CVE-9", "CVE-1", "CVE-3"])

    def test_nasty_text_is_made_plain_and_within_the_consumers_byte_limits(self):
        for text in NASTY:
            report, _ = self.build([scan(matches=[match(text, "Critical", name=text, version=text, fixed=(text,))])])
            image = report["images"][0]
            self.assertEqual(image["counts"]["critical"], 1, repr(text))
            finding = image["findings"][0]
            self.assertTrue(consumer_accepts(finding["id"], 64, True), repr(text))
            self.assertTrue(consumer_accepts(finding["package"], required=True), repr(text))
            self.assertTrue(consumer_accepts(finding["installed"]), repr(text))
            self.assertTrue(finding["fixed"] is None or consumer_accepts(finding["fixed"], required=True), repr(text))
        self.assertEqual(br.clip("a\u001b[0m\u202eb"), "a [0m b")
        self.assertEqual(br.clip("a" * 255 + "\u00e9").encode("utf-8")[-3:], "…".encode("utf-8"))

    def test_text_that_is_nothing_but_controls_is_still_a_nonempty_name(self):
        report, _ = self.build([scan(matches=[match("\u202e", "High", name="\u001b", version="")])])
        finding = report["images"][0]["findings"][0]
        self.assertEqual((finding["id"], finding["package"], finding["installed"]), ("unknown", "unknown", ""))

    def test_a_scan_with_untrustworthy_timestamps_is_not_published(self):
        for bad in ["2026-10-18T07:00:00Z\n\u202eUNTRUSTED", "2026-10-18", "2026-13-18T07:00:00Z", "2026-10-18T07:00:00+00:00"]:
            with self.assertRaises(ValueError):
                br.build(library("docker.io/library/nats:2.15.0"), [scan()], bad)
        odd = scan()
        odd["descriptor"]["db"]["status"]["built"] = "2026-10-18T06:27:17.123456789+02:00"
        report, _ = self.build([odd])
        self.assertEqual(report["scanner"]["dbBuilt"], "")

    def test_a_long_reference_is_refused_before_it_can_invalidate_the_report(self):
        with self.assertRaises(ValueError):
            br.library_images(library("docker.io/library/" + "a" * 250 + ":1"))

    def test_duplicates_keep_the_highest_severity_whatever_the_order(self):
        medium = match("CVE-2026-9", "Medium", fixed=("3.0.3",))
        critical = match("CVE-2026-9", "Critical", fixed=("3.0.2",))
        results = []
        for order in ([medium, critical], [critical, medium]):
            report, _ = self.build([scan(matches=order)])
            image = report["images"][0]
            self.assertEqual(image["counts"], {"critical": 1, "high": 0, "medium": 0, "low": 0})
            results.append(image)
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0]["findings"][0]["severity"], "Critical")
        self.assertEqual(results[0]["findings"][0]["fixed"], "3.0.2, 3.0.3")

    def test_duplicates_with_and_without_a_fix_agree_in_either_order(self):
        unfixed = match("CVE-2026-9", "High", fixed=(), state="not-fixed")
        fixed = match("CVE-2026-9", "High", fixed=("3.0.2",))
        a, _ = self.build([scan(matches=[unfixed, fixed])])
        b, _ = self.build([scan(matches=[fixed, unfixed])])
        self.assertEqual(a, b)
        self.assertEqual(a["images"][0]["findings"][0]["fixed"], "3.0.2")
        self.assertEqual(a["images"][0]["counts"]["high"], 1)

    def test_deterministic_whatever_the_input_order(self):
        a = scan("docker.io/library/a:1", [match("CVE-1", "High"), match("CVE-2", "High")], arm="sha256:" + "1" * 64)
        b = scan("docker.io/library/b:1", [match("CVE-3", "High")], arm="sha256:" + "2" * 64)
        images = ("docker.io/library/a:1", "docker.io/library/b:1")
        one, _ = self.build([a, b], images)
        two, _ = self.build([copy.deepcopy(b), copy.deepcopy(a)], images)
        self.assertEqual(br.encode(one), br.encode(two))
        self.assertEqual([i["reference"] for i in one["images"]], list(images))

    def test_a_manifest_that_is_the_index_is_listed_once(self):
        image = self.build([scan(index=ARM)])[0]["images"][0]
        self.assertEqual(image["digests"], [ARM])

    def test_an_image_that_is_not_the_librarys_is_skipped(self):
        report, problems = self.build([scan(), scan("docker.io/library/evil:1")])
        self.assertEqual(len(report["images"]), 1)
        self.assertTrue(any("evil" in p and "not an image of the library" in p for p in problems))

    def test_an_image_scanned_for_another_platform_is_skipped(self):
        with self.assertRaises(ValueError):
            self.build([scan(arch="amd64")])

    def test_a_library_image_with_no_scan_is_named_and_left_out(self):
        report, problems = self.build([scan()], images=("docker.io/library/nats:2.15.0", "docker.io/library/redis:8"))
        self.assertEqual([i["reference"] for i in report["images"]], ["docker.io/library/nats:2.15.0"])
        self.assertTrue(any("redis:8 has no scan" in p for p in problems))

    def test_nothing_usable_is_an_error_not_an_empty_report(self):
        with self.assertRaises(ValueError):
            self.build([])

    def test_a_malformed_digest_is_never_reported(self):
        bad = scan(arm="sha256:nothex")
        bad["source"]["target"]["repoDigests"] = ["x@sha256:short"]
        with self.assertRaises(ValueError):  # skipped, and then nothing is left to report
            self.build([bad])

    def test_images_listing_covers_containers_and_stacks_and_refuses_odd_references(self):
        lib = {"entries": [
            {"container": {"image": "docker.io/a/b:1"}},
            {"stack": {"services": [{"image": "ghcr.io/c/d:2"}, {"image": "docker.io/a/b:1"}]}}]}
        self.assertEqual(br.library_images(lib), ["docker.io/a/b:1", "ghcr.io/c/d:2"])
        with self.assertRaises(ValueError):
            br.library_images({"entries": [{"container": {"image": "--output=x"}}]})

    def test_over_the_cap_high_findings_go_first_and_it_says_so(self):
        many = [match("CVE-%06d" % n, "High" if n % 2 else "Critical", name="pkg%d" % n) for n in range(5000)]
        small = br.MAX_BYTES
        try:
            br.MAX_BYTES = 200 * 1024
            report, problems = self.build([scan(matches=many)])
        finally:
            br.MAX_BYTES = small
        self.assertLessEqual(len(br.encode(report)), 200 * 1024)
        image = report["images"][0]
        self.assertEqual(image["counts"]["critical"] + image["counts"]["high"], 5000)  # counts are never cut
        self.assertGreater(report["omitted"]["high"], 0)
        self.assertTrue(any("findings were dropped" in p for p in problems))
        self.assertTrue(any(f["severity"] == "Critical" for f in image["findings"]))

    def test_the_per_image_cap_keeps_critical_ones(self):
        many = [match("CVE-%06d" % n, "Critical" if n < 10 else "High", name="p%d" % n) for n in range(700)]
        report, _ = self.build([scan(matches=many)])
        image = report["images"][0]
        self.assertEqual(len(image["findings"]), br.MAX_FINDINGS_PER_IMAGE)
        self.assertEqual(sum(f["severity"] == "Critical" for f in image["findings"]), 10)
        self.assertEqual(report["omitted"], {"high": 200})

    def test_same_apart_from_generated(self):
        a, _ = self.build([scan()])
        b = copy.deepcopy(a)
        b["generated"] = "2027-01-01T00:00:00Z"
        self.assertTrue(br.same_apart_from_generated(a, b))
        b["images"][0]["counts"]["high"] = 1
        self.assertFalse(br.same_apart_from_generated(a, b))


@unittest.skipIf(sign_report is None, "cryptography isn't installed")
class SignReport(unittest.TestCase):
    SEED = base64.b64encode(bytes(range(32))).decode()

    def test_signature_verifies_for_exact_bytes_only(self):
        key = sign_report.private_key(self.SEED)
        data = b'{"schema":1}\n'
        signature = sign_report.sign(data, key)
        public = sign_report.public_text(key)
        self.assertEqual(len(base64.b64decode(signature)), 64)
        self.assertTrue(sign_report.verify(data, signature, public))
        self.assertFalse(sign_report.verify(data + b" ", signature, public))
        other = sign_report.public_text(sign_report.private_key(base64.b64encode(bytes(range(1, 33))).decode()))
        self.assertFalse(sign_report.verify(data, signature, other))

    def test_a_bad_key_is_refused_without_echoing_it(self):
        for bad in ("", "not base64!!", base64.b64encode(b"short").decode()):
            with self.assertRaises(ValueError) as caught:
                sign_report.private_key(bad)
            if bad:
                self.assertNotIn(bad, str(caught.exception))

    def test_main_writes_sig_and_never_prints_the_key(self):
        import contextlib, io, tempfile
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "report.json")
            with open(path, "wb") as handle:
                handle.write(b"{}\n")
            os.environ["REPORT_SIGNING_KEY"] = self.SEED
            out, err = io.StringIO(), io.StringIO()
            try:
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(sign_report.main([path]), 0)
            finally:
                del os.environ["REPORT_SIGNING_KEY"]
            self.assertNotIn(self.SEED, out.getvalue() + err.getvalue())
            with open(path + ".sig") as handle:
                signature = handle.read()
            self.assertTrue(sign_report.verify(b"{}\n", signature,
                                               sign_report.public_text(sign_report.private_key(self.SEED))))


if __name__ == "__main__":
    unittest.main()
