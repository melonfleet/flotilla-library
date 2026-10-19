#!/usr/bin/env python3
"""Turn Grype's JSON into report.json (Flotilla's Q62 vulnerability report).

  python3 tools/build_report.py images  library.json            # one image reference per line
  python3 tools/build_report.py build   library.json SCANS_DIR  # writes report.json

`build` reads every `*.json` in SCANS_DIR (one `grype -o json` result per image, scanned for
linux/arm64), keeps the ones whose image the library really lists, and writes `report.json`:
the critical and high findings of each image, counts of every severity, and both digests a local
`container` image can report: the index digest (`repoDigests`) and the arm64 manifest digest
(`manifestDigest`). Flotilla matches by digest only. It is advisory: nothing in the app acts on it.

The output is deterministic: images, digests and findings are sorted, keys are sorted, and the only
thing that changes between two runs on the same input is `generated`. The file is capped at 2 MB;
if it would be larger, high findings are dropped first, then critical ones (from the last image
backwards), and `omitted` says how many. Counts always cover everything.

The limits here match `VulnerabilityReport` in Flotilla's FlotillaCore; change both together
(test_report.py compares them with the app's source when it can find it). The builder enforces every
one of them: the app refuses a report that breaks a structural cap, and repairs only free text.
"""
import argparse
import datetime
import json
import os
import re
import sys
import unicodedata

MAX_BYTES = 2 * 1024 * 1024
MAX_IMAGES = 2_000
MAX_FINDINGS_PER_IMAGE = 500
MAX_DIGESTS = 8
MAX_STRING = 256  # UTF-8 bytes, not characters: the consumer counts bytes
MAX_ID = 64
MAX_REFERENCE = 256  # the app allows 512 (VulnerabilityReport.maxReference); the library's own limit is tighter
MAX_APP_REFERENCE = 512
MAX_COUNT = 10_000_000
MAX_OMITTED = 100_000_000
SEVERITIES = ("critical", "high", "medium", "low")
SHOWN = ("Critical", "High")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# The exact timestamp form Flotilla accepts; anything else is not published.
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
# An image reference as the library writes it (at most MAX_REFERENCE bytes, which is what Flotilla
# accepts); refuses anything that could be read as an option.
REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-/:@]{0,255}")


def library_images(library):
    """Every distinct image reference of every entry, sorted."""
    found = set()
    for entry in library.get("entries", []):
        if entry.get("container"):
            found.add(entry["container"]["image"])
        for service in (entry.get("stack") or {}).get("services", []):
            found.add(service["image"])
    bad = [i for i in found if "{{" in i or REFERENCE.fullmatch(i) is None]
    if bad:
        raise ValueError("not a plain image reference: " + ", ".join(sorted(bad)))
    return sorted(found)


# Default_Ignorable_Code_Point (DerivedCoreProperties, Unicode 15): the same ranges as
# `VulnerabilityReport.defaultIgnorableRanges` in the app. Invisible characters such as U+034F would
# let "open\u034fssl" pass for "openssl" (Kyle, 19 October); Python has no such property to ask.
DEFAULT_IGNORABLE = [(0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
                     (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
                     (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
                     (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF)]


def default_ignorable(c):
    code = ord(c)
    return any(low <= code <= high for low, high in DEFAULT_IGNORABLE)


def plain(text):
    """Single-line plain text, by the consumer's rule (`VulnerabilityReport.isText`): control, format
    and unassigned characters and every whitespace other than a space become a space, then runs
    collapse. Unassigned (`Cn`) is by *this* Python's Unicode database, which may be older or newer
    than the app's, so it cannot be the only guard; the app replaces what it dislikes too."""
    return " ".join("".join(
        " " if unicodedata.category(c) in ("Cc", "Cf", "Cn", "Cs", "Zl", "Zp", "Zs") or c.isspace()
        or default_ignorable(c) else c
        for c in str(text)).split())


def clip(text, limit=MAX_STRING):
    """`plain` text of at most `limit` UTF-8 bytes, cut on a character boundary with an ellipsis."""
    text = plain(text)
    if len(text.encode("utf-8")) <= limit:
        return text
    return text.encode("utf-8")[: limit - 3].decode("utf-8", "ignore").rstrip() + "…"


def required(text, limit=MAX_STRING):
    """Like `clip`, for a field Flotilla refuses to see empty."""
    return clip(text, limit) or "unknown"


def timestamp(text):
    """`text` if it is exactly `YYYY-MM-DDTHH:MM:SSZ` and a real moment, else None."""
    if not isinstance(text, str) or TIMESTAMP.fullmatch(text) is None:
        return None
    try:
        datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    return text


def finding_id(vulnerability, related):
    """A CVE id where there is one: Grype's own id can be a GHSA or Go advisory number."""
    vid = vulnerability.get("id", "")
    if vid.startswith("CVE-"):
        return vid
    cves = sorted(r["id"] for r in related if str(r.get("id", "")).startswith("CVE-"))
    return cves[0] if cves else vid


def fix_versions(vulnerability):
    """The versions that fix it, as a set; empty if none is known."""
    fix = vulnerability.get("fix") or {}
    return {str(v) for v in fix.get("versions") or []} if fix.get("state") == "fixed" else set()


def image_entry(scan):
    """One report image from one Grype result, or None if it names no digest."""
    target = scan["source"]["target"]
    digests = {target.get("manifestDigest", "")}
    for repo_digest in target.get("repoDigests") or []:
        digests.add(repo_digest.rpartition("@")[2])
    digests = sorted(d for d in digests if DIGEST.fullmatch(d))
    if not digests:
        return None
    if len(digests) > MAX_DIGESTS:
        raise ValueError("%s has more than %d digests" % (target["userInput"], MAX_DIGESTS))
    # One finding per raw (id, package, installed version): the same package found at two paths, or
    # matched twice. Duplicates merge so the result never depends on which came first: the highest
    # severity wins and the fixes are the sorted union of every duplicate's. The key is the raw
    # identity, clipped only afterwards: distinct ids that share their first 61 bytes stay distinct.
    merged = {}
    for match in scan.get("matches", []):
        vulnerability = match["vulnerability"]
        severity = str(vulnerability.get("severity", "")).lower()
        if severity not in SEVERITIES:
            continue  # negligible and unknown are in neither the counts nor the list
        artifact = match["artifact"]
        key = (str(finding_id(vulnerability, match.get("relatedVulnerabilities") or [])),
               str(artifact.get("name", "")), str(artifact.get("version", "")))
        entry = merged.setdefault(key, {"rank": len(SEVERITIES), "fixes": set()})
        entry["rank"] = min(entry["rank"], SEVERITIES.index(severity))
        entry["fixes"] |= fix_versions(vulnerability)
    counts = dict.fromkeys(SEVERITIES, 0)
    findings = []
    for (raw_id, raw_package, raw_installed), entry in merged.items():
        vid, package, installed = required(raw_id, MAX_ID), required(raw_package), clip(raw_installed)
        severity = SEVERITIES[entry["rank"]]
        counts[severity] += 1
        if severity.capitalize() in SHOWN:
            fixed = clip(", ".join(sorted(entry["fixes"])[:3])) if entry["fixes"] else ""
            findings.append({"id": vid, "severity": severity.capitalize(), "package": package,
                             "installed": installed, "fixed": fixed or None})
    if any(n > MAX_COUNT for n in counts.values()):
        raise ValueError("%s has more than %d findings of one severity" % (target["userInput"], MAX_COUNT))
    findings.sort(key=lambda f: (SHOWN.index(f["severity"]), f["id"], f["package"], f["installed"], f["fixed"] or ""))
    return {"reference": target["userInput"], "digests": digests, "counts": counts, "findings": findings}


def encode(report):
    return (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def fit(report):
    """Drops findings until the file fits; returns the dropped counts, empty if none were."""
    dropped = {"high": 0, "critical": 0}

    def drop(image, severity):
        kept = [f for f in image["findings"] if f["severity"].lower() != severity]
        dropped[severity] += len(image["findings"]) - len(kept)
        image["findings"] = kept

    for image in report["images"]:
        if len(image["findings"]) > MAX_FINDINGS_PER_IMAGE:  # critical come first
            for f in image["findings"][MAX_FINDINGS_PER_IMAGE:]:
                dropped[f["severity"].lower()] += 1
            image["findings"] = image["findings"][:MAX_FINDINGS_PER_IMAGE]

    def size():
        if any(dropped.values()):
            report["omitted"] = {k: v for k, v in dropped.items() if v}
        return len(encode(report))

    for severity in ("high", "critical"):
        for image in reversed(report["images"]):
            if size() <= MAX_BYTES:
                return {k: v for k, v in dropped.items() if v}
            drop(image, severity)
    if size() > MAX_BYTES:
        raise ValueError("report.json is over 2 MB even without findings")
    return {k: v for k, v in dropped.items() if v}


def build(library, scans, generated):
    """`scans` are decoded Grype results. Returns (report, problems)."""
    if timestamp(generated) is None:
        raise ValueError("generated must be YYYY-MM-DDTHH:MM:SSZ")
    wanted = set(library_images(library))
    images, problems, seen = [], [], set()
    for scan in scans:
        try:
            if scan["descriptor"]["name"] != "grype":
                raise ValueError("not a Grype result")
            platform = scan["source"]["target"].get("architecture"), scan["source"]["target"].get("os")
            reference = scan["source"]["target"]["userInput"]
            if platform != ("arm64", "linux"):
                raise ValueError("%s was scanned as %s/%s, not linux/arm64" % ((reference,) + platform[::-1]))
            if reference not in wanted:
                raise ValueError("%s is not an image of the library" % reference)
            if reference in seen:
                raise ValueError("%s was scanned twice" % reference)
            entry = image_entry(scan)
            if entry is None:
                raise ValueError("%s has no digest" % reference)
        except (KeyError, TypeError, ValueError) as error:
            problems.append("skipped a scan: %s" % (error if isinstance(error, ValueError) else "missing %s" % error))
            continue
        seen.add(reference)
        images.append(entry)
    images.sort(key=lambda i: i["reference"])
    if len(images) > MAX_IMAGES:
        raise ValueError("%d images is over the %d the app reads" % (len(images), MAX_IMAGES))
    for reference in sorted(wanted - seen):
        problems.append("%s has no scan, so it is not in the report" % reference)
    if not images:
        raise ValueError("no scan could be used; there is nothing to report")
    first = scans[0]["descriptor"]
    scanner = {
        "name": "grype",
        "version": required(first["version"]),
        "dbBuilt": timestamp((first.get("db") or {}).get("status", {}).get("built", "")) or "",
    }
    report = {"schema": 1, "generated": generated, "scanner": scanner, "images": images}
    dropped = fit(report)
    if dropped:
        problems.append("over 2 MB, so findings were dropped: %s" % ", ".join("%d %s" % (n, k) for k, n in sorted(dropped.items())))
    return report, problems


def same_apart_from_generated(a, b):
    strip = lambda r: {k: v for k, v in r.items() if k != "generated"}
    return strip(a) == strip(b)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("images").add_argument("library")
    b = sub.add_parser("build")
    b.add_argument("library")
    b.add_argument("scans")
    b.add_argument("--out", default="report.json")
    b.add_argument("--generated", help="ISO 8601, default now (UTC)")
    c = sub.add_parser("same", help="exit 0 if two reports differ only in `generated`")
    c.add_argument("a")
    c.add_argument("b")
    args = parser.parse_args(argv)
    if args.command == "same":
        try:
            ok = same_apart_from_generated(json.load(open(args.a)), json.load(open(args.b)))
        except (OSError, ValueError):
            ok = False
        return 0 if ok else 1
    library = json.load(open(args.library))
    if args.command == "images":
        print("\n".join(library_images(library)))
        return 0
    scans = []
    for name in sorted(os.listdir(args.scans)):
        if name.endswith(".json"):
            with open(os.path.join(args.scans, name)) as handle:
                scans.append(json.load(handle))
    generated = args.generated or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report, problems = build(library, scans, generated)
    with open(args.out, "wb") as handle:
        handle.write(encode(report))
    for problem in problems:
        print("warning:", problem, file=sys.stderr)
    print("%s: %d images, %d findings" % (args.out, len(report["images"]), sum(len(i["findings"]) for i in report["images"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
