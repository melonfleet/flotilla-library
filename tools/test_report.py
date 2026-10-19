#!/usr/bin/env python3
"""Tests for build_report.py and sign_report.py: python3 -m unittest discover -s tools -p 'test_*.py'

Grype's results here are small stand-ins with the fields build_report reads; the shape was taken
from a real `grype registry:... --platform linux/arm64 -o json` run (grype 0.120.1).
"""
import base64
import copy
import json
import os
import re
import sys
import unicodedata
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_report as br
import platform_report as pr

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
         "sep\u2028sep", "a" * 255 + "\u00e9", "\u00e9" * 200, "\u202e\n", "x" * 1000,
         # U+0890 and U+0891 are format characters in Unicode 14+ and unassigned (Cn) in older Python
         # databases; U+1343 is as given in review; U+0378 is unassigned in every version.
         "pkg\u0890evil", "pkg\u1343" "9name", "pkg\u08919name", "pkg\u0378name",
         # Invisible look-alikes (default-ignorables) and U+13439 as Kyle meant it.
         "pkg\U00013439name", "open\u034fssl", "open\ufe0fssl", "open\u3164ssl", "open\u1160ssl",
         "open\u115fssl", "open\u00adssl", "open\U000e0041ssl"]


# Disallowed by the app whatever this Python's Unicode database says about them.
KNOWN_UNASSIGNED_OR_FORMAT = {0x0378, 0x0890, 0x0891}


def consumer_accepts(text, limit=256, required=False):
    """Mirror of `VulnerabilityReport.isText`: bounded bytes, no control, format, unassigned or
    non-space whitespace. Never relies on this Python's Unicode version for the known cases: they are
    listed by code point as well."""
    if len(text.encode("utf-8")) > limit or (required and not text):
        return False
    return not any(unicodedata.category(c) in ("Cc", "Cf", "Cn") or ord(c) in KNOWN_UNASSIGNED_OR_FORMAT
                   or br.default_ignorable(c) or (c.isspace() and c != " ") for c in text)


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

    def test_distinct_ids_sharing_a_clipped_prefix_stay_distinct(self):
        prefix = "GHSA-" + "x" * 80  # clips to the same 64 bytes
        unfixed = match(prefix + "-a", "Critical", fixed=(), state="not-fixed")
        fixed = match(prefix + "-b", "High", fixed=("1.1",))
        for order in ([unfixed, fixed], [fixed, unfixed]):
            image = self.build([scan(matches=order)])[0]["images"][0]
            self.assertEqual(image["counts"], {"critical": 1, "high": 1, "medium": 0, "low": 0})
            self.assertEqual([(f["severity"], f["fixed"]) for f in image["findings"]],
                             [("Critical", None), ("High", "1.1")])
        # The same goes for package names and versions that clip alike.
        a = match("CVE-1", "High", name="p" * 300 + "a")
        b = match("CVE-1", "High", name="p" * 300 + "b")
        self.assertEqual(self.build([scan(matches=[a, b])])[0]["images"][0]["counts"]["high"], 2)

    def test_the_image_cap_is_the_apps(self):
        names = ["docker.io/library/i%d:1" % n for n in range(br.MAX_IMAGES + 1)]
        scans = [scan(name, arm="sha256:%064x" % n, index="sha256:%064x" % (n + 10 ** 6)) for n, name in enumerate(names)]
        with self.assertRaises(ValueError):
            self.build(scans, names)
        report, _ = self.build(scans[:-1], names[:-1])
        self.assertEqual(len(report["images"]), br.MAX_IMAGES)

    def test_too_many_digests_or_a_huge_count_skips_that_scan(self):
        many = scan()
        many["source"]["target"]["repoDigests"] = ["x@sha256:%064x" % n for n in range(br.MAX_DIGESTS + 1)]
        with self.assertRaises(ValueError):
            self.build([many])

    def test_caps_equal_the_apps(self):
        """Reads the app's source if it is checked out beside this repo (or at $FLOTILLA_SOURCE)."""
        here = os.path.dirname(os.path.abspath(__file__))
        core = os.path.join(os.environ.get("FLOTILLA_SOURCE", os.path.join(here, "..", "..", "Flotilla")),
                            "Sources", "FlotillaCore")
        path = os.path.join(core, "VulnerabilityReport.swift")
        if not os.path.exists(path):
            self.skipTest("the app's source isn't checked out beside this repo; set FLOTILLA_SOURCE")
        source = ""
        for name in ("VulnerabilityReport.swift", "PlatformAdvisory.swift"):
            with open(os.path.join(core, name), encoding="utf-8") as handle:
                source += handle.read()
        app = {name: eval(expr.replace("_", ""), {"__builtins__": {}}) for name, expr in
               re.findall(r"static let (max\w+) = ([0-9_ *]+)\n", source)}
        pairs = {"maxBytes": br.MAX_BYTES, "maxImages": br.MAX_IMAGES,
                 "maxFindingsPerImage": br.MAX_FINDINGS_PER_IMAGE, "maxDigestsPerImage": br.MAX_DIGESTS,
                 "maxText": br.MAX_STRING, "maxID": br.MAX_ID, "maxReference": br.MAX_APP_REFERENCE,
                 "maxCount": br.MAX_COUNT, "maxOmitted": br.MAX_OMITTED,
                 # The platform section (PlatformAdvisory.swift).
                 "maxReleases": pr.MAX_RELEASES, "maxCVEsPerRelease": pr.MAX_CVES_PER_RELEASE,
                 "maxExploitedPerRelease": pr.MAX_EXPLOITED_PER_RELEASE,
                 "maxCurrentVersions": pr.MAX_CURRENT_VERSIONS, "maxKernels": pr.MAX_KERNELS,
                 "maxKernelTop": pr.MAX_KERNEL_TOP, "maxVersion": pr.MAX_VERSION}
        for name, ours in pairs.items():
            self.assertIn(name, app, "%s not found in the app's source" % name)
            self.assertEqual(app[name], ours, name)
        self.assertEqual(set(app), set(pairs), "the app has a cap the builder doesn't know")
        self.assertLessEqual(br.MAX_REFERENCE, app["maxReference"])
        # Shared with the report's own caps, not restated.
        self.assertEqual((pr.MAX_ID, pr.MAX_STRING, pr.MAX_COUNT), (br.MAX_ID, br.MAX_STRING, br.MAX_COUNT))

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


FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "platform")


def fixture(name, mode="r"):
    with open(os.path.join(FIXTURES, name), mode, **({} if "b" in mode else {"encoding": "utf-8"})) as handle:
        return handle.read()


CHECKED = "2026-10-19T10:00:00Z"
# The kernel names apple/container's releases use, and the release each is; the same table is in
# Flotilla's PlatformAdvisoryTests.
KERNEL_NAMES = [("vmlinux-6.18.35-197-debug", "6.18.35"), ("vmlinux-6.18.15-186", "6.18.15"),
                ("vmlinux-6.12.28-153", "6.12.28"), ("vmlinux-6.19-rc1-200", "6.19-rc1"),
                ("vmlinux-6.18.35", "6.18.35"), ("vmlinux-kvm", None), ("vmlinux-6.18.35-rt-1", None),
                ("bzImage-6.18.35", None), ("vmlinux-6.18.35\n", None), ("vmlinux-../6.1", None)]


def macos_from_fixtures(**change):
    notes = {n: fixture("apple-note-%s.html" % n) for n in ("149228", "125886", "148281")}
    index = fixture("apple-security-releases-100100.html")
    return pr.macos_section(change.get("index", index), change.get("notes", notes),
                            change.get("pmv", fixture("gdmf-pmv.json", "rb")), CHECKED)


def captured_index(drop=None):
    """The captured index cut to the rows whose notes are captured (and those with none), without
    the row for version `drop`."""
    index = fixture("apple-security-releases-100100.html")
    keep = {"149228", "125886", "148281", None}
    rows = re.findall(r"<tr>.*?</tr>", index, re.S)
    kept = [row for row in rows if (not re.search(r"support\.apple\.com/en-us/(\d+)", row)
                                    or re.search(r"support\.apple\.com/en-us/(\d+)", row).group(1) in keep)
            and not (drop and re.search(r"macOS [A-Za-z ]+ %s<" % re.escape(drop), row))]
    return "<table>" + "".join(kept) + "</table>"


def sources_folder(folder, tags=("1.5.0", "1.2.2"), osv=None):
    """The scan job's download folder, from the captured sources (layout in scan.yml)."""
    import shutil
    os.makedirs(os.path.join(folder, "container-config"))
    for tag in tags:
        with open(os.path.join(folder, "container-config", tag + ".swift"), "w", encoding="utf-8") as handle:
            handle.write(fixture("container-%s-ContainerSystemConfig.swift" % tag))
    with open(os.path.join(folder, "container-latest.txt"), "w") as handle:
        handle.write("https://github.com/apple/container/releases/tag/1.5.0")
    with open(os.path.join(folder, "container-tags.txt"), "w") as handle:
        handle.write("".join("0000 refs/tags/%s\n" % tag for tag in ("1.5.0", "1.2.2")))
    shutil.copy(osv or os.path.join(FIXTURES, "osv-linux-sample.zip"), os.path.join(folder, "osv-linux.zip"))


def configs():
    return {"1.5.0": fixture("container-1.5.0-ContainerSystemConfig.swift"),
            "1.2.2": fixture("container-1.2.2-ContainerSystemConfig.swift")}


def kernel_from_fixtures(**change):
    return pr.kernel_section(change.get("configs", configs()), "1.5.0", os.path.join(FIXTURES, "osv-linux-sample.zip"),
                             CHECKED, br.clip, min_records=change.get("min_records", 1))


class PlatformSources(unittest.TestCase):
    """Parsed from captured responses; see fixtures/platform/CAPTURED.md."""

    def test_current_versions_from_apples_feed(self):
        self.assertEqual(pr.current_versions(fixture("gdmf-pmv.json", "rb")), ["27.0.1", "26.7.1"])
        for bad in (b"", b"{}", u'{"PublicAssetSets":{"macOS":[{"ProductVersion":"26.1\u202e"}]}}'.encode("utf-8"), b"\xff"):
            with self.assertRaises(pr.SourceError):
                pr.current_versions(bad)

    def test_the_index_lists_macos_26_and_later_with_their_notes(self):
        rows = pr.security_releases(fixture("apple-security-releases-100100.html"))
        by_version = {r["version"]: r for r in rows}
        self.assertEqual(by_version["26.7.1"], {"name": "macOS Tahoe 26.7.1", "version": "26.7.1",
                                                "released": "2026-09-28", "note": "149228", "noCVEs": False})
        self.assertTrue(by_version["27.0.1"]["noCVEs"])
        self.assertIsNone(by_version["27.0.1"]["note"])
        self.assertIn("26", by_version)  # macOS Tahoe 26, the line's first release
        self.assertTrue(all(pr.macos_version(r["version"])[0] >= 26 for r in rows))
        self.assertNotIn("15.8.1", by_version)

    def test_a_note_counts_the_cves_that_lead_a_paragraph_and_the_exploited_ones(self):
        cves, exploited = pr.note_fixes(fixture("apple-note-149228.html"), "macOS Tahoe 26.7.1")
        self.assertEqual((cves, exploited), ({"CVE-2026-86950"}, {"CVE-2026-86950"}))
        page = fixture("apple-note-125886.html")
        cves, exploited = pr.note_fixes(page, "macOS Tahoe 26.2")
        # Independently: every paragraph that begins with an id, up to the next <h2>.
        body = page[page.index(">macOS Tahoe 26.2</h2>"):]
        body = body[:body.index("<h2", 1)] if "<h2" in body[1:] else body
        self.assertEqual(cves, set(re.findall(r'<p class="gb-paragraph">(CVE-\d{4}-\d+)[:<]', body)))
        self.assertEqual(exploited, {"CVE-2025-14174", "CVE-2025-43529"})
        cves, exploited = pr.note_fixes(fixture("apple-note-148281.html"), "macOS Tahoe 26.6.2")
        self.assertEqual((len(cves), exploited), (34, set()))

    def test_a_note_for_another_release_or_with_no_cves_is_refused(self):
        with self.assertRaises(pr.SourceError):
            pr.note_fixes(fixture("apple-note-149228.html"), "macOS Tahoe 26.7")
        with self.assertRaises(pr.SourceError):
            pr.note_fixes("<h2>macOS Tahoe 26.7.1</h2><p>Nothing here</p>", "macOS Tahoe 26.7.1")
        for junk in ("", "<h2>macOS Tahoe 26.7.1", "\x00" * 100, "<" * 10000):
            with self.assertRaises(pr.SourceError):
                pr.note_fixes(junk, "macOS Tahoe 26.7.1")
        with self.assertRaises(pr.SourceError):
            pr.note_fixes("<h2>macOS Tahoe 26.7.1</h2>" + "<p>x</p>" * 10 + "a" * pr.MAX_HTML_BYTES, "macOS Tahoe 26.7.1")

    def test_a_missing_note_fails_the_section_rather_than_counting_short(self):
        with self.assertRaises(pr.SourceError):
            macos_from_fixtures()  # only three of the Tahoe notes are captured here
        with self.assertRaises(pr.SourceError):
            macos_from_fixtures(index="<table><tr><td><p>Safari 26</p></td><td><p>x</p></td><td><p>1 Jan 2026</p></td></tr></table>")

    def test_a_section_from_the_captured_index_and_notes(self):
        index = fixture("apple-security-releases-100100.html")
        rows = pr.security_releases(index)
        # Keep the rows whose notes are captured (and those with none); the rest of the index is cut.
        keep = {"149228", "125886", "148281", None}
        index_rows = re.findall(r"<tr>.*?</tr>", index, re.S)
        kept = [row for row in index_rows if not re.search(r"support\.apple\.com/en-us/(\d+)", row)
                or re.search(r"support\.apple\.com/en-us/(\d+)", row).group(1) in keep]
        section = macos_from_fixtures(index="<table>" + "".join(kept) + "</table>")
        self.assertIsNone(pr.macos_problem(section, br.timestamp, br.plain))
        self.assertEqual(section["current"], ["27.0.1", "26.7.1"])
        versions = [r["version"] for r in section["releases"]]
        self.assertEqual(versions, sorted(versions, key=pr.macos_version, reverse=True))
        self.assertIn("26.7.1", versions)
        self.assertTrue(len(rows) > len(section["releases"]))

    def test_a_truncated_note_is_refused_not_counted_short(self):
        # Kyle, 19 October: the 26.2 note cut after its first CVE read as 1 CVE, 0 exploited.
        page = fixture("apple-note-125886.html")
        name = "macOS Tahoe 26.2"
        full_cves, full_exploited = pr.note_fixes(page, name)
        self.assertEqual(len(full_exploited), 2)
        cut = page.index("CVE-", page.index("<h3")) + 20
        cut = page.index("</p>", cut)
        with self.assertRaises(pr.SourceError):
            pr.note_fixes(page[:cut], name)
        with self.assertRaises(pr.SourceError):
            pr.note_fixes(page[:cut] + "</p></html>", name)
        notes = {n: fixture("apple-note-%s.html" % n) for n in ("149228", "125886", "148281")}
        notes["125886"] = page[:cut]
        with self.assertRaises(pr.SourceError):
            macos_from_fixtures(index=captured_index(), notes=notes)

    def test_an_index_that_lost_a_current_versions_row_is_refused(self):
        self.assertEqual(macos_from_fixtures(index=captured_index())["current"], ["27.0.1", "26.7.1"])
        with self.assertRaises(pr.SourceError):
            macos_from_fixtures(index=captured_index(drop="27.0.1"))
        with self.assertRaises(pr.SourceError):
            macos_from_fixtures(index=captured_index(drop="26.7.1"))

    def test_a_fresh_macos_section_that_lost_most_of_yesterdays_counts_is_not_used(self):
        old = macos_from_fixtures(index=captured_index())
        fresh = copy.deepcopy(old)
        r = next(r for r in fresh["releases"] if r["version"] == "26.2")
        self.assertEqual(len(r["exploited"]), 2)
        r["cves"], r["exploited"] = r["cves"][:1], []
        self.assertIsNone(pr.macos_problem(fresh, br.timestamp, br.plain))
        self.assertIn("26.2", pr.macos_regression(fresh, old))
        section, problems = br.platform_section({"macOS": fresh}, {"platform": {"macOS": old}})
        self.assertEqual(section["macOS"], old)
        self.assertTrue(any("kept from the previous report" in p for p in problems))
        shorter = copy.deepcopy(old)  # rows cut off the end of the index
        shorter["releases"] = [x for x in shorter["releases"] if x["version"] != "26.7.1"]
        self.assertIn("26.7.1", pr.macos_regression(shorter, old))
        self.assertIsNone(pr.macos_regression(old, old))
        # Releases that gain CVEs, or a new release, are no loss.
        newer = copy.deepcopy(old)
        newer["releases"][0]["cves"] += ["CVE-2026-0001"]
        self.assertIsNone(pr.macos_regression(newer, old))

    def test_most_of_yesterdays_releases_vanishing_is_refused(self):
        old = macos_from_fixtures(index=captured_index())
        self.assertGreater(len(old["releases"]), 3)
        cut = copy.deepcopy(old)  # a truncated index: only the newest two rows survive
        cut["releases"] = cut["releases"][:2]
        self.assertIn("lost", pr.macos_regression(cut, old))
        aged = copy.deepcopy(old)  # one old release ageing out is normal
        aged["releases"] = aged["releases"][:-1]
        self.assertIsNone(pr.macos_regression(aged, old))

    def test_the_platform_section_goes_before_any_finding_does(self):
        many = [match("CVE-%06d" % n, "High" if n % 2 else "Critical", name="pkg%d" % n) for n in range(300)]
        platform = {"macOS": macos_from_fixtures(index=captured_index())}
        bare, _ = br.build(library("docker.io/library/nats:2.15.0"), [scan(matches=many)], "2026-10-18T07:00:00Z")
        size = len(br.encode(bare))
        small = br.MAX_BYTES
        try:
            br.MAX_BYTES = size + 64  # the findings fit alone, not with the platform section
            report, problems = br.build(library("docker.io/library/nats:2.15.0"), [scan(matches=many)],
                                        "2026-10-18T07:00:00Z", platform_sources=platform)
        finally:
            br.MAX_BYTES = small
        self.assertNotIn("platform", report)
        self.assertNotIn("omitted", report)
        self.assertEqual(len(report["images"][0]["findings"]), 300)
        self.assertTrue(any("platform left out" in p for p in problems))

    def test_versions_compare_as_numbers(self):
        self.assertLess(pr.macos_version("26.9"), pr.macos_version("26.10"))
        self.assertEqual(pr.macos_version("26"), (26, 0, 0))
        for bad in ("26.", "26.0.0.1", " 26", "26a", "", None, "\u0662\u0666"):
            self.assertIsNone(pr.macos_version(bad))
        self.assertLess(pr.kernel_version("7.3-rc1"), pr.kernel_version("7.3"))
        self.assertLess(pr.kernel_version("6.18.15"), pr.kernel_version("6.18.35"))
        self.assertEqual(pr.kernel_version("6.15"), pr.kernel_version("6.15.0"))
        self.assertEqual(pr.kernel_version("7.3-rc1.0"), pr.kernel_version("7.3-rc1"))
        self.assertLess(pr.kernel_version("0"), pr.kernel_version("2.6.39.2"))
        self.assertIsNone(pr.kernel_version("6.18.35-debug"))

    def test_kernel_release_names(self):
        for name, release in KERNEL_NAMES:
            self.assertEqual(pr.kernel_release(name), release, name)

    def test_the_recommended_kernel_from_each_releases_configuration(self):
        self.assertEqual(pr.recommended_binary(configs()["1.5.0"]), "vmlinux-6.18.35-197-debug")
        self.assertEqual(pr.recommended_binary(configs()["1.2.2"]), "vmlinux-6.18.15-186")
        with self.assertRaises(pr.SourceError):
            pr.recommended_binary(configs()["1.5.0"].replace("defaultBinaryPath", "otherPath"))
        doubled = configs()["1.5.0"] + 'public static let defaultBinaryPath = "opt/kata/share/kata-containers/vmlinux-9.9.9-1"'
        with self.assertRaises(pr.SourceError):
            pr.recommended_binary(doubled)

    def test_release_tags_and_the_latest(self):
        latest = pr.latest_container("https://github.com/apple/container/releases/tag/1.5.0\n")
        tags = pr.release_tags(fixture("container-ls-remote-tags.txt"), latest)
        self.assertEqual(tags[0], "1.0.0")
        self.assertEqual(tags[-1], "1.5.0")
        self.assertNotIn("0.12.3", tags)
        for bad in ("", "https://github.com/apple/container/releases/tag/1.5.0-beta",
                    "https://evil.example/apple/container/releases/tag/1.5.0"):
            with self.assertRaises(pr.SourceError):
                pr.latest_container(bad)
        with self.assertRaises(pr.SourceError):
            pr.release_tags(fixture("container-ls-remote-tags.txt"), "9.9.9")

    def test_cvss_scores(self):
        self.assertEqual(pr.cvss3_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), 7.8)
        self.assertEqual(pr.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(pr.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(pr.cvss3_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"), 5.5)
        self.assertEqual(pr.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)
        for bad in ("", None, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F"):
            self.assertIsNone(pr.cvss3_score(bad), bad)

    def test_osv_ranges(self):
        record = {"affected": [{"package": {"ecosystem": "Linux", "name": "Kernel"}, "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "6.12.0"}, {"fixed": "6.12.31"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "6.13.0"}, {"fixed": "6.18.20"}]},
            {"type": "GIT", "events": [{"introduced": "abc"}, {"fixed": "def"}]}]}]}
        version = pr.kernel_version
        self.assertTrue(pr.osv_affects(record, version("6.18.15")))
        self.assertFalse(pr.osv_affects(record, version("6.18.35")))
        self.assertFalse(pr.osv_affects(record, version("6.12.31")))
        self.assertTrue(pr.osv_affects(record, version("6.12.0")))
        open_ended = {"affected": [{"package": {"ecosystem": "Linux"}, "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
        self.assertTrue(pr.osv_affects(open_ended, version("6.18.35")))
        odd = {"affected": [{"package": {"ecosystem": "Linux"}, "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "6.1"}, {"last_affected": "6.2"}]}]}]}
        self.assertIsNone(pr.osv_affects(odd, version("6.1.5")))
        for wrong in ({"affected": "x"}, {"affected": [["x"]]}, {"affected": [{"package": "Linux"}]},
                      {"affected": [{"package": {"ecosystem": "Linux"}, "ranges": [{"type": "ECOSYSTEM", "events": [7]}]}]}):
            self.assertIsNone(pr.osv_affects(wrong, version("6.1.5")), wrong)

    def test_the_kernel_section_from_captured_osv_records(self):
        section = kernel_from_fixtures()
        self.assertIsNone(pr.kernel_problem(section, br.timestamp, br.plain))
        self.assertEqual(section["recommended"], {"release": "6.18.35", "binary": "vmlinux-6.18.35-197-debug"})
        self.assertEqual(section["container"], "1.5.0")
        [older] = section["kernels"]
        self.assertEqual((older["release"], older["binary"]), ("6.18.15", "vmlinux-6.18.15-186"))
        # The sample's records, by what each says about 6.18.15 and 6.18.35 (CAPTURED.md).
        self.assertEqual((older["critical"], older["high"], older["unscored"]), (3, 4, 2))
        self.assertEqual([t["id"] for t in older["top"]],
                         ["CVE-2026-23240", "CVE-2026-31402", "CVE-2026-23455", "CVE-2026-23246", "CVE-2026-23239"])
        self.assertEqual([t["score"] for t in older["top"]], [9.8, 9.8, 9.1, 8.8, 7.8])
        ids = {t["id"] for t in older["top"]}
        self.assertFalse(ids & {"CVE-2026-100075", "CVE-2026-23270", "CVE-2026-22980", "CVE-2026-22984"})

    def test_a_truncated_osv_export_or_a_bad_member_fails_the_section(self):
        with self.assertRaises(pr.SourceError):
            kernel_from_fixtures(min_records=pr.MIN_OSV_RECORDS)
        import tempfile, zipfile
        with tempfile.TemporaryDirectory() as folder:
            for name, data in (("../evil.json", b"{}"), ("CVE-2026-1.json", b"not json")):
                path = os.path.join(folder, "x.zip")
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(name, data)
                with self.assertRaises(pr.SourceError):
                    pr.kernel_section(configs(), "1.5.0", path, CHECKED, br.clip, min_records=0)

    def sample_with(self, folder, change):
        """A copy of the sample OSV export in `folder` with record CVE-2026-23240 changed by `change`."""
        import zipfile
        path = os.path.join(folder, "changed.zip")
        with zipfile.ZipFile(os.path.join(FIXTURES, "osv-linux-sample.zip")) as source, zipfile.ZipFile(path, "w") as out:
            for member in source.infolist():
                data = source.read(member)
                if member.filename == "CVE-2026-23240.json":
                    record = json.loads(data)
                    change(record)
                    data = json.dumps(record).encode()
                out.writestr(member.filename, data)
        return path

    def test_an_osv_range_that_cant_be_read_fails_the_section_rather_than_count_short(self):
        # Kyle, 19 October: one critical record with a last_affected range took the count from 3 to 2.
        import tempfile

        def last_affected(record):
            for affected in record["affected"]:
                for span in affected.get("ranges", []):
                    if span["type"] == "ECOSYSTEM":
                        span["events"] = [{"introduced": "6.1"}, {"last_affected": "6.18.20"}]
        with tempfile.TemporaryDirectory() as folder:
            path = self.sample_with(folder, last_affected)
            with self.assertRaises(pr.SourceError) as caught:
                pr.kernel_section(configs(), "1.5.0", path, CHECKED, br.clip, min_records=1)
            self.assertIn("CVE-2026-23240", str(caught.exception))
            sources_folder(os.path.join(folder, "s"), osv=path)
            section, problems = br.read_platform_sources(os.path.join(folder, "s"), CHECKED, min_records=1)
            self.assertNotIn("kernel", section)
            self.assertTrue(any("can't be read" in p for p in problems))

    def test_a_missing_historical_configuration_fails_the_kernel_section(self):
        # Kyle, 19 October: without 1.2.2's configuration the table came out empty, and valid.
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            sources_folder(os.path.join(folder, "all"))
            section, problems = br.read_platform_sources(os.path.join(folder, "all"), CHECKED, min_records=1)
            self.assertEqual(len(section["kernel"]["kernels"]), 1)
            sources_folder(os.path.join(folder, "gone"))
            os.remove(os.path.join(folder, "gone", "container-config", "1.2.2.swift"))
            section, problems = br.read_platform_sources(os.path.join(folder, "gone"), CHECKED, min_records=1)
            self.assertNotIn("kernel", section)
            self.assertTrue(any("1.2.2" in p for p in problems))

    def test_without_the_latest_configuration_there_is_no_kernel_section(self):
        with self.assertRaises(pr.SourceError):
            kernel_from_fixtures(configs={"1.2.2": configs()["1.2.2"]})

    def test_nasty_summaries_are_made_plain(self):
        section = kernel_from_fixtures()
        for text in NASTY:
            section["kernels"][0]["top"][0]["summary"] = br.clip(text)
            self.assertIsNone(pr.kernel_problem(section, br.timestamp, br.plain), repr(text))
            self.assertTrue(consumer_accepts(section["kernels"][0]["top"][0]["summary"]), repr(text))
            section["kernels"][0]["top"][0]["summary"] = text
            if br.plain(text) != text or len(text.encode("utf-8")) > 256:
                self.assertIsNotNone(pr.kernel_problem(section, br.timestamp, br.plain), repr(text))

    def test_the_checks_refuse_what_the_app_refuses(self):
        good = kernel_from_fixtures()
        for change in (lambda s: s["kernels"][0].update(critical=-1),
                       lambda s: s["kernels"][0].update(high=True),
                       lambda s: s["kernels"][0]["top"][0].update(score=6.9),
                       lambda s: s["kernels"][0]["top"][0].update(score=10),
                       lambda s: s["kernels"][0]["top"][0].update(id="GHSA-1"),
                       lambda s: s["kernels"][0].update(critical=0),
                       lambda s: s["kernels"][0].update(release="6.18.16"),
                       lambda s: s["recommended"].update(release="6.18.36"),
                       lambda s: s.update(container="1.5"),
                       lambda s: s.update(checked="yesterday"),
                       lambda s: s.update(extra=1),
                       lambda s: s["kernels"].append(copy.deepcopy(s["kernels"][0]))):
            bad = copy.deepcopy(good)
            change(bad)
            self.assertIsNotNone(pr.kernel_problem(bad, br.timestamp, br.plain))
        release = {"version": "26.7.1", "name": "macOS Tahoe 26.7.1", "released": "2026-09-28",
                   "cves": ["CVE-2026-86950"], "exploited": ["CVE-2026-86950"]}
        macos = {"checked": CHECKED, "current": ["26.7.1"], "releases": [release]}
        self.assertIsNone(pr.macos_problem(macos, br.timestamp, br.plain))
        for change in (lambda s: s["releases"][0].update(exploited=["CVE-2026-1111"]),
                       lambda s: s["releases"][0].update(released="2026-02-30"),
                       lambda s: s["releases"][0].update(name="macOS\u202e"),
                       lambda s: s["releases"][0].update(cves=["CVE-2026-86950", "CVE-2026-86950"]),
                       lambda s: s["releases"][0].update(cves=["CVE-%d-1234" % 2026] * 0 + ["cve-2026-86950"]),
                       lambda s: s["releases"].append(copy.deepcopy(s["releases"][0])),
                       lambda s: s.update(current=[]),
                       lambda s: s.update(current=["26.7.1", "26.7.1"])):
            bad = copy.deepcopy(macos)
            change(bad)
            self.assertIsNotNone(pr.macos_problem(bad, br.timestamp, br.plain))


class PlatformInTheReport(unittest.TestCase):
    def build(self, platform=None, previous=None):
        return br.build(library("docker.io/library/nats:2.15.0"), [scan()], "2026-10-19T07:00:00Z", platform, previous)

    def test_no_platform_is_the_report_as_before(self):
        report, problems = self.build()
        self.assertNotIn("platform", report)
        self.assertEqual(report["schema"], 1)

    def test_a_good_section_is_published_and_schema_stays_1(self):
        kernel = kernel_from_fixtures()
        report, _ = self.build({"kernel": kernel})
        self.assertEqual(report["platform"], {"kernel": kernel})
        self.assertEqual(report["schema"], 1)

    def test_a_bad_section_keeps_yesterdays(self):
        kernel = kernel_from_fixtures()
        yesterday = {"platform": {"kernel": kernel}}
        broken = copy.deepcopy(kernel)
        broken["kernels"][0]["critical"] = -1
        report, problems = self.build({"kernel": broken}, yesterday)
        self.assertEqual(report["platform"]["kernel"], kernel)
        self.assertTrue(any("kept from the previous report" in p for p in problems))
        report, problems = self.build({}, yesterday)
        self.assertEqual(report["platform"]["kernel"], kernel)
        # Neither good: nothing, rather than nonsense.
        report, problems = self.build({"kernel": broken}, {"platform": {"kernel": broken}})
        self.assertNotIn("platform", report)
        report, problems = self.build("not a dict", "neither")
        self.assertNotIn("platform", report)

    def big_macos(self, releases=30, cves=1000):
        """Structurally valid, within every declared cap, and over the platform byte budget."""
        return {"checked": CHECKED, "current": ["26.7.1"], "releases": [
            {"version": "26.%d" % n, "name": "macOS Tahoe 26.%d" % n, "released": "2026-01-01",
             "cves": ["CVE-2026-%d" % (10000 + n * 1000 + i) for i in range(cves)], "exploited": []}
            for n in range(releases)]}

    def test_the_platform_section_has_its_own_size_cap_and_gives_way_to_yesterdays_copy(self):
        # Kyle, 19 October: 30 releases of 1,000 CVEs raised, so no image finding published either.
        big = self.big_macos()
        self.assertIsNone(pr.macos_problem(big, br.timestamp, br.plain))
        self.assertGreater(len(br.encode({"macOS": big})), br.MAX_PLATFORM_BYTES)
        kernel = kernel_from_fixtures()
        old = {"checked": "2026-10-18T10:00:00Z", "current": ["26.7"], "releases": [
            {"version": "26.7", "name": "macOS Tahoe 26.7", "released": "2026-09-14",
             "cves": ["CVE-2026-1000"], "exploited": []}]}
        report, problems = self.build({"macOS": big, "kernel": kernel}, {"platform": {"macOS": old}})
        self.assertEqual(report["platform"], {"macOS": old, "kernel": kernel})
        self.assertEqual(len(report["images"]), 1)
        self.assertTrue(any("over %d bytes" % br.MAX_PLATFORM_BYTES in p for p in problems))
        self.assertLessEqual(len(br.encode(report["platform"])), br.MAX_PLATFORM_BYTES)
        # With no previous copy, the part is left out: still no error, and the kernel part stays.
        report, problems = self.build({"macOS": big, "kernel": kernel})
        self.assertEqual(report["platform"], {"kernel": kernel})
        self.assertEqual(len(report["images"]), 1)
        # A previous copy that is itself too big is not trusted either.
        report, _ = self.build({"macOS": big}, {"platform": {"macOS": big}})
        self.assertNotIn("platform", report)
        self.assertEqual(len(report["images"]), 1)

    def test_a_small_byte_budget_never_raises(self):
        kernel = kernel_from_fixtures()
        cap = br.MAX_PLATFORM_BYTES
        try:
            br.MAX_PLATFORM_BYTES = 100
            report, _ = self.build({"kernel": kernel})
            self.assertNotIn("platform", report)
        finally:
            br.MAX_PLATFORM_BYTES = cap

    def test_a_day_when_only_checked_moved_is_not_a_change(self):
        kernel = kernel_from_fixtures()
        a, _ = self.build({"kernel": kernel})
        later = copy.deepcopy(kernel)
        later["checked"] = "2026-10-20T10:00:00Z"
        b, _ = self.build({"kernel": later})
        self.assertTrue(br.same_apart_from_generated(a, b))
        later["kernels"][0]["high"] += 1
        c, _ = self.build({"kernel": later})
        self.assertFalse(br.same_apart_from_generated(a, c))

    def test_sources_folder_with_nothing_in_it_gives_nothing_and_says_why(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            section, problems = br.read_platform_sources(folder, CHECKED)
        self.assertEqual(section, {})
        self.assertEqual(len(problems), 2)


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
