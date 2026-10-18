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

The limits here match `VulnerabilityReport` in Flotilla's FlotillaCore; change both together.
"""
import argparse
import datetime
import json
import os
import re
import sys

MAX_BYTES = 2 * 1024 * 1024
MAX_FINDINGS_PER_IMAGE = 500
MAX_STRING = 256
SEVERITIES = ("critical", "high", "medium", "low")
SHOWN = ("Critical", "High")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# An image reference as the library writes it; refuses anything that could be read as an option.
REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-/:@]{0,511}")


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


def clip(text):
    text = " ".join(str(text).split())
    return text if len(text) <= MAX_STRING else text[: MAX_STRING - 1] + "…"


def finding_id(vulnerability, related):
    """A CVE id where there is one: Grype's own id can be a GHSA or Go advisory number."""
    vid = vulnerability.get("id", "")
    if vid.startswith("CVE-"):
        return vid
    cves = sorted(r["id"] for r in related if str(r.get("id", "")).startswith("CVE-"))
    return cves[0] if cves else vid


def fixed_version(vulnerability):
    fix = vulnerability.get("fix") or {}
    versions = sorted(str(v) for v in fix.get("versions") or [])
    if fix.get("state") == "fixed" and versions:
        return clip(", ".join(versions[:3]))
    return None


def image_entry(scan):
    """One report image from one Grype result, or None if it names no digest."""
    target = scan["source"]["target"]
    digests = {target.get("manifestDigest", "")}
    for repo_digest in target.get("repoDigests") or []:
        digests.add(repo_digest.rpartition("@")[2])
    digests = sorted(d for d in digests if DIGEST.fullmatch(d))
    if not digests:
        return None
    counts = dict.fromkeys(SEVERITIES, 0)
    seen = set()
    findings = []
    for match in scan.get("matches", []):
        vulnerability = match["vulnerability"]
        severity = str(vulnerability.get("severity", "")).lower()
        if severity not in counts:
            continue  # negligible and unknown are in neither the counts nor the list
        artifact = match["artifact"]
        found = {
            "id": clip(finding_id(vulnerability, match.get("relatedVulnerabilities") or [])),
            "severity": severity.capitalize(),
            "package": clip(artifact.get("name", "")),
            "installed": clip(artifact.get("version", "")),
            "fixed": fixed_version(vulnerability),
        }
        # The same package found at two paths is one finding.
        key = (found["id"], found["package"], found["installed"])
        if key in seen:
            continue
        seen.add(key)
        counts[severity] += 1
        if found["severity"] in SHOWN:
            findings.append(found)
    findings.sort(key=lambda f: (SHOWN.index(f["severity"]), f["id"], f["package"], f["installed"]))
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
    for reference in sorted(wanted - seen):
        problems.append("%s has no scan, so it is not in the report" % reference)
    if not images:
        raise ValueError("no scan could be used; there is nothing to report")
    first = scans[0]["descriptor"]
    scanner = {
        "name": "grype",
        "version": first["version"],
        "dbBuilt": (first.get("db") or {}).get("status", {}).get("built", ""),
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
