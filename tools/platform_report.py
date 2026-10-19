#!/usr/bin/env python3
"""The report's `platform` section: macOS and the container kernel (follow-ups 2 and 5).

Read by build_report.py; nothing here touches the network. The scan job downloads the sources
(see scan.yml) into one folder, and `build_report.py platform` turns that folder into
platform.json. Every source is untrusted text: each parse is capped, checked against what the
page says about itself, and a section that fails in any way is left out, so the publish job keeps
the previous report's copy rather than publishing nonsense.

macOS (`macos_section`):
  - the current versions: Apple's MDM version feed, https://gdmf.apple.com/v2/pmv
    (`PublicAssetSets.macOS`), the versions Apple offers devices now;
  - the CVEs each release fixes: Apple security releases, https://support.apple.com/en-us/100100,
    and the per-release note it links. An entry whose text says Apple "is aware of a report that
    this issue may have been exploited" makes its CVEs `exploited`.
  Only macOS 26 and later (Flotilla's own minimum).

Kernel (`kernel_section`):
  - the recommended kernel: `KernelConfig.defaultBinaryPath` in the latest apple/container
    release's Sources/ContainerPersistence/ContainerSystemConfig.swift. That is what
    `container system kernel set --recommended` installs, and the only way Flotilla installs one;
  - the kernels older releases (1.0.0 and later, Flotilla's minimum) recommended, which a host
    keeps after upgrading `container`;
  - CVEs: OSV's Linux ecosystem (https://osv-vulnerabilities.storage.googleapis.com/Linux/all.zip),
    whose ECOSYSTEM ranges are the kernel CNA's own "unaffected from" versions, and whose CVSS
    v3.1 vector is the score in the CVE record. A CVE with no vector is counted as unscored, never
    guessed. For each older kernel: how many high (7.0-8.9) and critical (9.0+) CVEs affect it
    and not the recommended one, and the top few by score.

The caps match `VulnerabilityReport.Platform` in Flotilla's PlatformAdvisory.swift; change both
together (test_report.py compares them).
"""
import datetime
import html
import html.parser
import json
import math
import re
import zipfile

MIN_MACOS_MAJOR = 26
MIN_CONTAINER = (1, 0, 0)

MAX_RELEASES = 200
MAX_CVES_PER_RELEASE = 1000
MAX_EXPLOITED_PER_RELEASE = 100
MAX_CURRENT_VERSIONS = 20
MAX_KERNELS = 50
MAX_KERNEL_TOP = 5
MAX_VERSION = 32
MAX_ID = 64
MAX_STRING = 256
MAX_COUNT = 10_000_000

# Input limits (builder only): a source bigger than these is refused rather than parsed.
MAX_HTML_BYTES = 4 * 1024 * 1024
MAX_PMV_BYTES = 4 * 1024 * 1024
MAX_CONFIG_BYTES = 256 * 1024
MAX_OSV_MEMBERS = 500_000
MAX_OSV_MEMBER_BYTES = 4 * 1024 * 1024
MAX_OSV_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
# A real OSV Linux export has tens of thousands of records; far fewer means a truncated download.
MIN_OSV_RECORDS = 10_000

CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")
MACOS_VERSION = re.compile(r"[0-9]{1,3}(\.[0-9]{1,3}){0,2}")
KERNEL_RELEASE = re.compile(r"[0-9]{1,2}\.[0-9]{1,3}(\.[0-9]{1,4}){0,2}(-rc[0-9]{1,3})?")
KERNEL_BINARY = re.compile(r"vmlinux-[0-9][A-Za-z0-9._\-]{0,119}")
CONTAINER_TAG = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}")
DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
NOTE_URL = re.compile(r"https://support\.apple\.com/en-us/([0-9]{1,9})")
EXPLOITED = re.compile(r"\bmay have been (actively )?exploited\b", re.I)


class SourceError(ValueError):
    """A source that can't be trusted to say what it seems to; its section is left out."""


# MARK: Versions

def macos_version(text):
    """`26.0.1` as (26, 0, 1); `26` as (26, 0, 0). None if it isn't a plain macOS version."""
    if not isinstance(text, str) or MACOS_VERSION.fullmatch(text) is None:
        return None
    parts = [int(p) for p in text.split(".")]
    return tuple(parts + [0] * (3 - len(parts)))


def kernel_version(text):
    """A kernel version as OSV writes it, comparable: 6.18.35, 6.15, 2.6.39.2, 7.3-rc1, 7.3-rc1.0
    and "0". An -rc sorts before its release. None for any other shape."""
    m = re.fullmatch(r"([0-9]{1,4}(?:\.[0-9]{1,6}){0,3})(?:-rc([0-9]{1,3})(?:\.0)?)?", text or "")
    if m is None:
        return None
    numbers = [int(p) for p in m.group(1).split(".")]
    numbers += [0] * (4 - len(numbers))
    rc = m.group(2)
    return tuple(numbers) + ((0, int(rc)) if rc is not None else (1, 0))


def kernel_release(binary):
    """The release `uname -r` reports for a Kata kernel file name, by apple/container's own rule
    (TestCLIKernelSetSerial): `vmlinux-6.18.35-197-debug` is `6.18.35`. None if not that shape."""
    if not isinstance(binary, str) or KERNEL_BINARY.fullmatch(binary) is None:
        return None
    parts = binary[len("vmlinux-"):].split("-")
    for index in range(1, len(parts)):
        if parts[index].isdigit():
            parts = parts[:index]
            break
    release = "-".join(parts)
    return release if KERNEL_RELEASE.fullmatch(release) else None


def container_tag(text):
    return tuple(int(p) for p in text.split(".")) if CONTAINER_TAG.fullmatch(text or "") else None


# MARK: HTML

class _Blocks(html.parser.HTMLParser):
    """Flattens a support.apple.com page into blocks in order: ("h2"|"h3"|"p", text, links), and
    ("tr", None, None) / ("td", None, None) markers. Text is unescaped and whitespace collapsed."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.blocks = []
        self._tag = None
        self._text = []
        self._links = []

    def handle_starttag(self, tag, attrs):
        if tag in ("tr", "td", "th"):
            self._flush()
            self.blocks.append((tag, None, None))
        elif tag in ("h2", "h3", "p"):
            self._flush()
            self._tag = tag
        elif tag == "a" and self._tag is not None:
            href = dict(attrs).get("href") or ""
            self._links.append(href)
        elif tag == "br" and self._tag is not None:
            self._text.append(" ")

    def handle_endtag(self, tag):
        if tag == self._tag:
            self._flush()

    def handle_data(self, data):
        if self._tag is not None:
            self._text.append(data)

    def _flush(self):
        if self._tag is not None:
            text = " ".join("".join(self._text).split())
            self.blocks.append((self._tag, text, list(self._links)))
        self._tag, self._text, self._links = None, [], []


def blocks(page):
    if not isinstance(page, str) or len(page.encode("utf-8")) > MAX_HTML_BYTES:
        raise SourceError("a page is missing or larger than %d bytes" % MAX_HTML_BYTES)
    parser = _Blocks()
    parser.feed(page)
    parser.close()
    parser._flush()
    return parser.blocks


def _day(text):
    """`28 Sep 2026` (the index) or `September 28, 2026` (a note) as 2026-09-28."""
    for form in ("%d %b %Y", "%B %d, %Y"):
        try:
            return datetime.datetime.strptime(text.strip(), form).strftime("%Y-%m-%d")
        except ValueError:
            pass
    return None


ROW_NAME = re.compile(r"macOS ([A-Z][A-Za-z]{1,20}(?: [A-Z][A-Za-z]{1,20}){0,2}) ([0-9]{1,3}(?:\.[0-9]{1,3}){0,2})")


def security_releases(page, pending=None):
    """The macOS rows of Apple's security releases page, newest first as listed:
    [{"name", "version", "released", "note" (id or None), "noCVEs" (bool)}]. Rows for other
    products, and macOS rows older than MIN_MACOS_MAJOR, are skipped. A "details coming soon" row is
    left out of the result, but its version is added to `pending` if a list is given."""
    rows, current = [], None
    for tag, text, links in blocks(page):
        if tag == "tr":
            current = {"cells": []}
            rows.append(current)
        elif tag in ("td", "th") and current is not None:
            current["cells"].append([])
        elif tag == "p" and current is not None and current["cells"]:
            current["cells"][-1].append((text, links))
    found = []
    for row in rows:
        cells = row["cells"]
        if len(cells) != 3 or not cells[0] or not cells[2]:
            continue
        name = cells[0][0][0]
        match = ROW_NAME.fullmatch(name)
        if match is None or not name.startswith("macOS "):
            continue
        version = macos_version(match.group(2))
        if version is None or version[0] < MIN_MACOS_MAJOR:
            continue
        released = _day(cells[2][0][0])
        if released is None:
            raise SourceError("%s has no readable release date" % name)
        notes = [m.group(1) for link in cells[0][0][1] for m in [NOTE_URL.fullmatch(link)] if m]
        no_cves = any("no published CVE entries" in text for text, _ in cells[0][1:])
        if not notes and not no_cves:
            if pending is not None:
                pending.append(match.group(2))
            continue  # "details coming soon": not yet a release with a known list
        found.append({"name": name, "version": match.group(2), "released": released,
                      "note": notes[0] if notes else None, "noCVEs": not notes})
    if not found:
        raise SourceError("the security releases page lists no macOS release")
    if len(found) > MAX_RELEASES:
        raise SourceError("more than %d macOS releases" % MAX_RELEASES)
    return found


def note_fixes(page, name):
    """The CVEs a release note fixes, and which of them Apple says may have been exploited.

    The note must be for `name` (its first <h2>), and is read up to the next <h2> ("Additional
    recognition" has credits, not fixes). An entry begins at each <h3>; its CVEs are the paragraphs
    that *begin* with a CVE id, so "CVE-2025-14174 was also issued in response" in an Impact line is
    not counted. A note with no CVE at all is refused: a linked note always has some, and so is one
    with no <h2> after the security section (it was cut short)."""
    items = blocks(page)
    headings = [i for i, (tag, _, _) in enumerate(items) if tag == "h2"]
    start = next((i for i in headings if items[i][1] == name), None)
    if start is None:
        raise SourceError("the note for %s is about something else" % name)
    end = next((i for i in headings if i > start), None)
    if end is None:
        # Apple's notes close with "Additional recognition" and the footer, both <h2>. A page that ends
        # inside the security section was cut short, and would count fewer CVEs without saying so.
        raise SourceError("the note for %s ends inside its security section; it looks truncated" % name)
    cves, exploited = set(), set()
    entry_cves, entry_exploited = set(), False

    def close():
        cves.update(entry_cves)
        if entry_exploited:
            exploited.update(entry_cves)

    for tag, text, _ in items[start + 1:end]:
        if tag == "h3":
            close()
            entry_cves, entry_exploited = set(), False
        elif tag == "p":
            lead = CVE.match(text)
            if lead and (len(text) == lead.end() or text[lead.end()] in ": "):
                entry_cves.add(lead.group(0))
            elif EXPLOITED.search(text):
                entry_exploited = True
    close()
    if not cves:
        raise SourceError("the note for %s names no CVE" % name)
    if len(cves) > MAX_CVES_PER_RELEASE or len(exploited) > MAX_EXPLOITED_PER_RELEASE:
        raise SourceError("the note for %s names more CVEs than the report carries" % name)
    return cves, exploited


def current_versions(pmv_bytes):
    """The macOS versions Apple's version feed offers now, MIN_MACOS_MAJOR and later, newest first."""
    if len(pmv_bytes) > MAX_PMV_BYTES:
        raise SourceError("the version feed is too large")
    try:
        feed = json.loads(pmv_bytes.decode("utf-8"))
        entries = feed["PublicAssetSets"]["macOS"]
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        raise SourceError("the version feed isn't the shape it was")
    versions = set()
    for entry in entries if isinstance(entries, list) else []:
        text = entry.get("ProductVersion") if isinstance(entry, dict) else None
        version = macos_version(text)
        if version is None:
            raise SourceError("the version feed has an odd version")
        if version[0] >= MIN_MACOS_MAJOR:
            versions.add(text)
    if not versions or len(versions) > MAX_CURRENT_VERSIONS:
        raise SourceError("the version feed lists no current macOS, or too many")
    return sorted(versions, key=macos_version, reverse=True)


def macos_section(index_page, notes, pmv_bytes, checked):
    """`notes` maps a note id to its page. Raises SourceError on anything doubtful."""
    current = current_versions(pmv_bytes)
    releases, seen, pending = [], set(), []
    for row in security_releases(index_page, pending):
        key = macos_version(row["version"])
        if key in seen:
            raise SourceError("%s is listed twice" % row["name"])
        seen.add(key)
        if row["noCVEs"]:
            cves, exploited = set(), set()
        else:
            if row["note"] not in notes:
                raise SourceError("the note for %s wasn't downloaded" % row["name"])
            cves, exploited = note_fixes(notes[row["note"]], row["name"])
        releases.append({"version": row["version"], "name": row["name"], "released": row["released"],
                         "cves": sorted(cves), "exploited": sorted(exploited)})
    # Coverage: an index that lost rows (cut short, or reshaped) must not keep the current versions
    # and lose their security rows. Each version Apple offers now has a row, or is announced there.
    listed = {macos_version(r["version"]) for r in releases} | {macos_version(v) for v in pending}
    missing = [v for v in current if macos_version(v) not in listed]
    if missing:
        raise SourceError("the security releases page has no row for current macOS %s" % ", ".join(missing))
    releases.sort(key=lambda r: macos_version(r["version"]), reverse=True)
    return {"checked": checked, "current": current, "releases": releases}


# MARK: Kernel

CONFIG_BINARY = re.compile(r'public static let defaultBinaryPath = "opt/kata/share/kata-containers/(vmlinux-[^"/]{1,120})"')
CONFIG_URL = re.compile(r'"https://github\.com/kata-containers/kata-containers/releases/download/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/kata-static-\1-arm64\.tar\.(?:zst|xz)"')
LATEST = re.compile(r"https://github\.com/apple/container/releases/tag/([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4})")


def recommended_binary(config):
    """The kernel file name a release of apple/container recommends, from its
    ContainerSystemConfig.swift. Exactly one definition, a Kata file name, and a Kata release URL."""
    if len(config.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise SourceError("ContainerSystemConfig.swift is too large")
    binaries = CONFIG_BINARY.findall(config)
    if len(binaries) != 1 or len(CONFIG_URL.findall(config)) != 1:
        raise SourceError("ContainerSystemConfig.swift no longer says which kernel it recommends")
    if kernel_release(binaries[0]) is None:
        raise SourceError("the recommended kernel %r has no release we can read" % binaries[0][:40])
    return binaries[0]


def latest_container(redirect):
    """The tag of apple/container's latest release, from where /releases/latest redirects."""
    match = LATEST.fullmatch((redirect or "").strip())
    if match is None:
        raise SourceError("couldn't tell apple/container's latest release")
    return match.group(1)


def release_tags(ls_remote, latest):
    """Release tags from `git ls-remote --tags --refs`, MIN_CONTAINER through `latest`, oldest first."""
    top = container_tag(latest)
    tags = set()
    for line in ls_remote.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].startswith("refs/tags/"):
            version = container_tag(parts[1][len("refs/tags/"):])
            if version is not None and MIN_CONTAINER <= version <= top:
                tags.add(parts[1][len("refs/tags/"):])
    if latest not in tags:
        raise SourceError("the latest release %s isn't among the tags" % latest)
    return sorted(tags, key=container_tag)


METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": None, "C": None},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    "PR": {"N": None, "L": None, "H": None},
}


def _roundup(value):
    """CVSS v3.1's Roundup: the smallest one-decimal number not below `value`, without float drift."""
    whole = int(round(value * 100000))
    return whole / 100000.0 if whole % 10000 == 0 else (math.floor(whole / 10000) + 1) / 10.0


def cvss3_score(vector):
    """The base score of a CVSS v3.0 or v3.1 vector, or None if it isn't exactly one well-formed
    base vector (temporal and environmental metrics are refused rather than half-read)."""
    if not isinstance(vector, str) or not re.fullmatch(r"CVSS:3\.[01](/[A-Z]{1,2}:[A-Z])+", vector):
        return None
    pairs = [p.split(":") for p in vector.split("/")[1:]]
    metrics = dict(pairs)
    if len(pairs) != 8 or set(metrics) != set(METRICS) or any(metrics[k] not in METRICS[k] for k in metrics):
        return None
    changed = metrics["S"] == "C"
    privileges = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[metrics["PR"]]
    iss = 1 - (1 - METRICS["C"][metrics["C"]]) * (1 - METRICS["I"][metrics["I"]]) * (1 - METRICS["A"][metrics["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploitability = 8.22 * METRICS["AV"][metrics["AV"]] * METRICS["AC"][metrics["AC"]] * privileges * METRICS["UI"][metrics["UI"]]
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + exploitability), 10)) if changed else _roundup(min(impact + exploitability, 10))


def osv_affects(record, version):
    """Whether an OSV Linux record says kernel `version` (a `kernel_version` tuple) is affected:
    True, False, or None when a range can't be read; `kernel_section` then refuses the section rather than count short."""
    try:
        return _osv_affects(record, version)
    except (AttributeError, TypeError, KeyError):
        return None  # a field of another type than OSV's schema says


def _osv_affects(record, version):
    found = False
    for affected in record.get("affected") or []:
        package = affected.get("package") or {}
        if package.get("ecosystem") != "Linux":
            continue
        for span in affected.get("ranges") or []:
            if span.get("type") != "ECOSYSTEM":
                continue
            introduced, closed = None, False
            for event in span.get("events") or []:
                if set(event) == {"introduced"}:
                    introduced = kernel_version(event["introduced"])
                    if introduced is None:
                        return None
                elif set(event) == {"fixed"}:
                    fixed = kernel_version(event["fixed"])
                    if fixed is None or (introduced is None and not closed):
                        return None
                    if introduced is not None:  # the kernel CNA lists one fix per branch after the first
                        found = found or introduced <= version < fixed
                    introduced, closed = None, True
                else:
                    return None  # last_affected, limit, or anything else: not read, so not judged
            if introduced is not None and introduced <= version:
                found = True
    return found


def osv_records(path):
    """Each OSV record in the Linux export, decoded. Capped by count and size; names that aren't
    `<ID>.json` are refused."""
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_OSV_MEMBERS:
            raise SourceError("the OSV export has more than %d records" % MAX_OSV_MEMBERS)
        if sum(m.file_size for m in members) > MAX_OSV_TOTAL_BYTES:
            raise SourceError("the OSV export is too large")
        for member in members:
            if not re.fullmatch(r"[A-Za-z0-9.\-]{1,64}\.json", member.filename):
                raise SourceError("the OSV export has an odd member name")
            if member.file_size > MAX_OSV_MEMBER_BYTES:
                raise SourceError("an OSV record is too large")
            with archive.open(member) as handle:
                data = handle.read(MAX_OSV_MEMBER_BYTES + 1)
            if len(data) > MAX_OSV_MEMBER_BYTES:
                raise SourceError("an OSV record is too large")
            try:
                yield json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise SourceError("an OSV record isn't JSON")


def kernel_section(configs, latest, osv_path, checked, clip, min_records=MIN_OSV_RECORDS):
    """`configs` maps each release tag to its ContainerSystemConfig.swift. `clip` is the report's
    free-text cleaner. Raises SourceError on anything doubtful."""
    if latest not in configs:
        raise SourceError("the latest release's configuration wasn't downloaded")
    recommended = recommended_binary(configs[latest])
    target = kernel_version(kernel_release(recommended))
    older = {}
    for tag in sorted(configs, key=container_tag, reverse=True):
        if tag == latest:
            continue
        try:
            binary = recommended_binary(configs[tag])
        except SourceError:
            continue  # an older tag that defined it elsewhere: that kernel just isn't covered
        release = kernel_release(binary)
        if release != kernel_release(recommended) and release not in older:
            older[release] = binary
    if len(older) > MAX_KERNELS:
        raise SourceError("more than %d older kernels" % MAX_KERNELS)
    uncertain = []
    tallies = {release: {"critical": 0, "high": 0, "unscored": 0, "scored": []} for release in older}
    versions = {release: kernel_version(release) for release in older}
    records = 0
    for record in osv_records(osv_path):
        records += 1
        rid = record.get("id") if isinstance(record, dict) else None
        if not isinstance(rid, str) or CVE.fullmatch(rid) is None:
            continue
        on_target = osv_affects(record, target)
        if on_target:
            continue  # the recommended kernel has it too
        if on_target is None:
            uncertain.append(rid)
            continue
        severity = record.get("severity")
        vectors = [s.get("score") for s in (severity if isinstance(severity, list) else [])
                   if isinstance(s, dict) and s.get("type") == "CVSS_V3"]
        score = cvss3_score(vectors[0]) if len(vectors) == 1 else None
        for release, version in versions.items():
            affects = osv_affects(record, version)
            if affects is None:
                uncertain.append(rid)  # not judged: the totals would be "at least", which the section can't say
                break
            if not affects:
                continue
            tally = tallies[release]
            if score is None:
                tally["unscored"] += 1
            elif score >= 7.0:
                tally["critical" if score >= 9.0 else "high"] += 1
                tally["scored"].append((score, rid, record.get("summary") or ""))
    if records < min_records:
        raise SourceError("the OSV export has only %d records; it looks truncated" % records)
    if uncertain:
        raise SourceError("%d CVE records have a range that can't be read (%s...), so the counts would be incomplete"
                          % (len(uncertain), ", ".join(sorted(set(uncertain))[:3])))
    kernels = []
    for release in sorted(older, key=kernel_version, reverse=True):
        tally = tallies[release]
        top = sorted(tally["scored"], key=lambda s: (-s[0], s[1]))[:MAX_KERNEL_TOP]
        kernels.append({"release": release, "binary": older[release], "critical": tally["critical"],
                        "high": tally["high"], "unscored": tally["unscored"],
                        "top": [{"id": rid, "score": score, "summary": clip(summary)} for score, rid, summary in top]})
    return {"checked": checked, "container": latest,
            "recommended": {"release": kernel_release(recommended), "binary": recommended},
            "kernels": kernels}


# MARK: Checking (the app's rules, applied before anything is published)

def _real_day(text):
    if not isinstance(text, str) or DAY.fullmatch(text) is None:
        return False
    try:
        datetime.datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        return False
    return True


def _timestamp_ok(text, timestamp):
    return timestamp(text) is not None


def macos_problem(section, timestamp, plain):
    """Why a macOS section can't be published, or None. Mirrors `Platform.MacOS.problem()`."""
    try:
        if set(section) != {"checked", "current", "releases"} or not _timestamp_ok(section["checked"], timestamp):
            return "its keys or date"
        current = section["current"]
        if not (1 <= len(current) <= MAX_CURRENT_VERSIONS) or any(macos_version(v) is None for v in current) \
                or len(set(current)) != len(current):
            return "its current versions"
        releases = section["releases"]
        if len(releases) > MAX_RELEASES or len({r["version"] for r in releases}) != len(releases):
            return "its releases"
        for r in releases:
            if set(r) != {"version", "name", "released", "cves", "exploited"} or macos_version(r["version"]) is None \
                    or len(r["version"]) > MAX_VERSION or not _real_day(r["released"]) \
                    or not r["name"] or plain(r["name"]) != r["name"] or len(r["name"].encode("utf-8")) > MAX_STRING:
                return "a release's fields"
            cves, exploited = r["cves"], r["exploited"]
            if len(cves) > MAX_CVES_PER_RELEASE or len(exploited) > MAX_EXPLOITED_PER_RELEASE \
                    or not all(isinstance(c, str) and CVE.fullmatch(c) for c in cves + exploited) \
                    or len(set(cves)) != len(cves) or not set(exploited) <= set(cves):
                return "a release's CVEs"
    except (KeyError, TypeError, AttributeError):
        return "its shape"
    return None


def macos_regression(fresh, old):
    """Why a fresh macOS section looks like a loss against yesterday's valid copy, or None. A release
    both list must not lose more than half its CVEs (of four or more), nor more than half its
    exploited ones; and a release of yesterday's that is as new as the oldest of today's must still be
    there. Both sections have passed `macos_problem`."""
    today = {r["version"]: r for r in fresh["releases"]}
    if not today:
        return "it lists no release" if old["releases"] else None
    oldest = min(macos_version(v) for v in today)
    # Older releases may age out of Apple's index one or two at a time, never most of them at once:
    # a truncated index that keeps only the current rows must not replace yesterday's history
    # (Kyle, 19 October).
    gone = [r for r in old["releases"] if r["version"] not in today]
    if len(gone) > 2:
        return "it lost %d of yesterday's %d releases" % (len(gone), len(old["releases"]))
    for r in old["releases"]:
        new = today.get(r["version"])
        if new is None:
            if macos_version(r["version"]) >= oldest:
                return "it lost release %s" % r["version"]
        elif (len(r["cves"]) >= 4 and len(new["cves"]) * 2 < len(r["cves"])) \
                or (r["exploited"] and len(new["exploited"]) * 2 < len(r["exploited"])):
            return "release %s dropped from %d CVEs (%d exploited) to %d (%d)" % (
                r["version"], len(r["cves"]), len(r["exploited"]), len(new["cves"]), len(new["exploited"]))
    return None


def kernel_problem(section, timestamp, plain):
    """Why a kernel section can't be published, or None. Mirrors `Platform.Kernel.problem()`."""
    try:
        if set(section) != {"checked", "container", "recommended", "kernels"} \
                or not _timestamp_ok(section["checked"], timestamp) or container_tag(section["container"]) is None:
            return "its keys, date or release"
        rec = section["recommended"]
        if set(rec) != {"release", "binary"} or kernel_release(rec["binary"]) != rec["release"]:
            return "its recommended kernel"
        kernels = section["kernels"]
        if len(kernels) > MAX_KERNELS or len({k["release"] for k in kernels}) != len(kernels):
            return "its kernels"
        for k in kernels:
            if set(k) != {"release", "binary", "critical", "high", "unscored", "top"} \
                    or kernel_release(k["binary"]) != k["release"] or k["release"] == rec["release"]:
                return "a kernel's fields"
            counts = [k["critical"], k["high"], k["unscored"]]
            if not all(type(n) is int and 0 <= n <= MAX_COUNT for n in counts):
                return "a kernel's counts"
            top = k["top"]
            if len(top) > MAX_KERNEL_TOP or len(top) > k["critical"] + k["high"]:
                return "a kernel's top list"
            for t in top:
                if set(t) != {"id", "score", "summary"} or CVE.fullmatch(t["id"]) is None \
                        or type(t["score"]) is not float or not 7.0 <= t["score"] <= 10.0 \
                        or plain(t["summary"]) != t["summary"] or len(t["summary"].encode("utf-8")) > MAX_STRING:
                    return "a kernel's top list"
            if sum(t["score"] >= 9.0 for t in top) > k["critical"] or sum(t["score"] < 9.0 for t in top) > k["high"]:
                return "a kernel's top list outnumbers its counts"
    except (KeyError, TypeError, AttributeError):
        return "its shape"
    return None
