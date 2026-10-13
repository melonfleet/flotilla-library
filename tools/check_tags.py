#!/usr/bin/env python3
"""Look up newer stable tags (and arm64 support) for every image in entries/.

    python3 tools/check_tags.py                         report only
    python3 tools/check_tags.py --apply --report R.md   also edit the entry files, write the PR body
    python3 tools/check_tags.py --only a,b              just those entry ids
    python3 tools/check_tags.py --offline --cache DIR   use a saved cache, no network

What it changes: an image's tag, in the entry files only, when a newer stable tag has the same prefix
and suffix as the current one (see `pick_newest`) and linux/arm64. A changed entry gets `tested: null`,
because a bump is untested; Flotilla drops an untested entry, so the check fails until it is re-run.
What it flags (never changes): an image or tag that has vanished, a current tag without arm64, a newer
tag without arm64 and nothing newer with it, a lookup that was refused or couldn't be made.
It never touches VERSION, library.json or library.json.sig.

The lookup code is Terry's registry checker from the import step (import_library.py), copied.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

import entries as layout

# --- copied from import_library.py -----------------------------------------------------------

def parse_image(ref: str):
    """Split an image reference into (registry, repo, tag, digest)."""
    ref = str(ref).strip()
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, repo = parts[0], "/".join(parts[1:])
    else:
        registry, repo = "docker.io", "/".join(parts)
    if registry in ("index.docker.io", "registry-1.docker.io"):
        registry = "docker.io"
    if registry == "docker.io" and "/" not in repo:
        repo = "library/" + repo
    return registry, repo, tag, digest



TAG_RE = re.compile(r"^(?P<prefix>\D*?)(?P<ver>\d+(?:[._-]\d+)*)(?P<suffix>.*)$")
PRERELEASE_RE = re.compile(
    r"(?i)(^|[-._])(rc|beta|alpha|dev|pre|preview|nightly|snapshot|canary|unstable|test|next|edge|nilla)"
    r"(\d*)($|[-._])|(?<=\d)(rc|a|b|alpha|beta)\d+")


def parse_tag(tag: str):
    """Split a tag into a comparable pattern: (prefix, seps, nums, suffix)."""
    m = TAG_RE.match(tag or "")
    if not m:
        return None
    ver = m.group("ver")
    seps = tuple(re.findall(r"[._-]", ver))
    nums = tuple(int(x) for x in re.split(r"[._-]", ver))
    suffix = re.sub(r"\d+", "#", m.group("suffix"))
    return m.group("prefix"), seps, nums, suffix


def is_prerelease(tag: str) -> bool:
    return bool(PRERELEASE_RE.search(tag))


def pick_newest(gemini_tag: str, names):
    """Newest stable tag in the same pattern as gemini_tag, or None.

    Same pattern means the same prefix (`v`, `version-`), the same suffix
    (`-apache`, `-management`; digits in a suffix are wildcards), the same
    separators and the same number of numeric parts.
    """
    g = parse_tag(gemini_tag)
    if g is None:
        return None
    best, best_nums = None, None
    for name in names:
        if is_prerelease(name) and name != gemini_tag:
            continue
        p = parse_tag(name)
        if p is None or (p[0], p[1], len(p[2]), p[3]) != (g[0], g[1], len(g[2]), g[3]):
            continue
        # a calendar-versioned look-alike (2024.11) is not a newer semver
        if g[2][0] < 1000 <= p[2][0]:
            continue
        if best_nums is None or p[2] > best_nums:
            best, best_nums = name, p[2]
    if best is None:
        # images that tag releases as 9.4-0 where Gemini wrote 9.4
        for name in names:
            if is_prerelease(name):
                continue
            p = parse_tag(name)
            if p is None or (p[0], p[3]) != (g[0], g[3]) or p[1] != g[1] + ("-",) \
                    or len(p[2]) != len(g[2]) + 1:
                continue
            if g[2][0] < 1000 <= p[2][0]:
                continue
            if best_nums is None or p[2] > best_nums:
                best, best_nums = name, p[2]
    return best


def default_pattern_newest(names):
    """For `latest` / untagged images: newest plain dotted release tag."""
    plain = [n for n in names if re.fullmatch(r"v?\d+\.\d+(\.\d+)?", n) and not is_prerelease(n)]
    if not plain:
        return None
    return max(plain, key=lambda n: tuple(int(x) for x in re.findall(r"\d+", n)))


# --------------------------------------------------------------- registry

class Http:
    """requests wrapper with an on-disk cache and a polite delay."""

    def __init__(self, cache_dir: Path, sleep: float = 0.3, refresh: bool = False, offline: bool = False):
        import requests
        self.requests = requests
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "flotilla-suggestions-import/1.0"
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.sleep = sleep
        self.refresh = refresh
        self.offline = offline
        self.tokens = {}
        self.calls = 0
        self.cache_hits = 0

    def _key(self, url, accept):
        return hashlib.sha1(f"{url}\n{accept or ''}".encode()).hexdigest()

    def get(self, url, accept=None, headers=None, use_cache=True):
        """Return dict(status, headers, text); status 0 means a network error."""
        path = self.cache_dir / (self._key(url, accept) + ".json")
        if use_cache and not self.refresh and path.exists():
            self.cache_hits += 1
            return json.loads(path.read_text())
        if self.offline:
            return {"status": 0, "headers": {}, "text": "offline: not in cache"}
        hdrs = dict(headers or {})
        if accept:
            hdrs["Accept"] = accept
        result = None
        for attempt in range(4):
            time.sleep(self.sleep)
            self.calls += 1
            try:
                r = self.session.get(url, headers=hdrs, timeout=30)
            except self.requests.RequestException as exc:
                result = {"status": 0, "headers": {}, "text": f"{type(exc).__name__}: {exc}"}
                time.sleep(2 * (attempt + 1))
                continue
            keep = ("link", "www-authenticate", "content-type", "docker-content-digest", "retry-after")
            result = {
                "status": r.status_code,
                "headers": {k: v for k, v in ((h.lower(), r.headers.get(h)) for h in keep) if v},
                "text": r.text,
            }
            if r.status_code == 429 or r.status_code >= 500:
                wait = 5.0 * (attempt + 1)
                ra = r.headers.get("Retry-After", "")
                if ra.isdigit():
                    wait = min(float(ra), 60)
                time.sleep(wait)
                continue
            break
        if result["status"] not in (0, 429) and result["status"] < 500 and use_cache:
            path.write_text(json.dumps(result))
        return result

    # --- OCI distribution API with anonymous bearer tokens
    def oci_get(self, registry, repo, path, accept=None):
        url = f"https://{registry}{path}"
        path_c = self.cache_dir / (self._key(url, accept) + ".json")
        if not self.refresh and path_c.exists():
            self.cache_hits += 1
            return json.loads(path_c.read_text())
        if self.offline:
            return {"status": 0, "headers": {}, "text": "offline: not in cache"}
        tok = self.tokens.get((registry, repo))
        headers = {"Authorization": f"Bearer {tok}"} if tok else {}
        res = self.get(url, accept=accept, headers=headers, use_cache=False)
        if res["status"] == 401:
            chal = res["headers"].get("www-authenticate", "")
            if chal.lower().startswith("bearer"):
                params = dict(re.findall(r'(\w+)="([^"]*)"', chal))
                realm = params.get("realm")
                if realm:
                    q = {"service": params.get("service", ""), "scope": params.get("scope") or f"repository:{repo}:pull"}
                    tr = self.get(realm + "?" + "&".join(f"{k}={v}" for k, v in q.items() if v), use_cache=False)
                    if tr["status"] == 200:
                        try:
                            body = json.loads(tr["text"])
                            tok = body.get("token") or body.get("access_token")
                        except ValueError:
                            tok = None
                        if tok:
                            self.tokens[(registry, repo)] = tok
                            res = self.get(url, accept=accept, headers={"Authorization": f"Bearer {tok}"}, use_cache=False)
        if res["status"] not in (0, 429) and res["status"] < 500:
            path_c.write_text(json.dumps(res))
        return res


MANIFEST_ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


def _blank_result(ref, registry, repo, tag):
    return {
        "ref": ref, "registry": registry, "repo": repo, "gemini_tag": tag,
        "repo_found": None, "tag_exists": None, "newest_stable": None,
        "suggested_ref": None, "arm64": None, "gemini_tag_arm64": None,
        "tags_seen": 0, "refused": False, "inaccessible": False, "newest_with_arm64": None, "error": None, "notes": [],
    }


def _archs_has_arm64(images):
    """True/False, or None when Hub lists no platforms yet (tag still publishing)."""
    if not images:
        return None
    return any(i.get("architecture") == "arm64" and i.get("os", "linux") == "linux" for i in images or [])


def check_hub(http: Http, ref, repo, tag, res):
    ns, name = repo.split("/", 1)
    base = f"https://hub.docker.com/v2/repositories/{ns}/{name}"
    arm_by_tag = {}
    if tag:
        d = http.get(f"{base}/tags/{tag}")
        if d["status"] == 200:
            body = json.loads(d["text"])
            res["repo_found"] = True
            res["tag_exists"] = True
            arm_by_tag[tag] = _archs_has_arm64(body.get("images"))
            res["gemini_tag_arm64"] = arm_by_tag[tag]
            if arm_by_tag[tag] is None:
                res["notes"].append("Gemini's tag lists no platforms on Docker Hub")
        elif d["status"] == 404:
            res["tag_exists"] = False
        else:
            return _refused(res, d, "Docker Hub tag lookup")
    if res["repo_found"] is None:
        d = http.get(base)
        if d["status"] == 200:
            res["repo_found"] = True
        elif d["status"] == 404:
            res["repo_found"] = False
            res["error"] = "repository not found on Docker Hub"
            return res
        else:
            return _refused(res, d, "Docker Hub repository lookup")

    parsed = parse_tag(tag) if tag else None
    names = []
    query = "page_size=100&ordering=last_updated"
    suffix_filter = re.sub(r"[#\d]+.*$", "", parsed[3]).lstrip("-._") if parsed else ""
    if suffix_filter:
        query += "&name=" + suffix_filter
    url = f"{base}/tags?{query}"
    for _ in range(5):
        d = http.get(url)
        if d["status"] != 200:
            if not names:
                return _refused(res, d, "Docker Hub tag listing")
            break
        body = json.loads(d["text"])
        for t in body.get("results", []):
            arm = _archs_has_arm64(t.get("images"))
            if arm is None:
                continue  # no platform data: tag is mid-publish, not a candidate
            names.append(t["name"])
            arm_by_tag[t["name"]] = arm
        url = body.get("next")
        if not url:
            break
    res["tags_seen"] = len(names)
    if tag and res["tag_exists"] and tag not in names:
        names.append(tag)
    _suggest(http, res, tag, names, arm_by_tag)
    return res


def _refused(res, d, what):
    res["refused"] = True
    res["error"] = f"{what}: HTTP {d['status']} {d['text'][:120].strip()}" if d["status"] else f"{what}: {d['text'][:160]}"
    return res


def _suggest(http, res, tag, names, arm_by_tag, manifest_check=None):
    if tag in (None, "latest"):
        newest = default_pattern_newest(names)
        if newest:
            res["notes"].append("Gemini gave no pinned tag; picked newest plain release tag")
    else:
        newest = pick_newest(tag, names)
        if newest is None and parse_tag(tag) is None:
            res["notes"].append(f"tag {tag!r} is a floating alias; no version pattern to compare")
            newest = tag if res["tag_exists"] else None
    res["newest_stable"] = newest
    if newest is None:
        return
    repo_ref = res["ref"].rsplit(":", 1)[0] if tag and res["ref"].endswith(":" + tag) else res["ref"].split("@")[0]
    res["suggested_ref"] = f"{repo_ref}:{newest}"
    if newest in arm_by_tag:
        res["arm64"] = arm_by_tag[newest]
    elif manifest_check:
        res["arm64"] = manifest_check(newest)
    if res["tag_exists"] is None and tag:
        res["tag_exists"] = tag in names if names else None
    if res["arm64"] is False:
        if res["gemini_tag_arm64"]:
            res["notes"].append("newest tag lacks arm64 but Gemini's tag has it")
        older = [n for n in names if arm_by_tag.get(n) and pick_newest(newest, [n]) == n]
        if older:
            best = max(older, key=lambda n: parse_tag(n)[2])
            res["newest_with_arm64"] = best
            res["notes"].append(f"newest tag with linux/arm64 is {best}")


def check_oci(http: Http, ref, registry, repo, tag, res):
    pages, names, url_path = 0, [], f"/v2/{repo}/tags/list?n=1000"
    while url_path and pages < 60:
        d = http.oci_get(registry, repo, url_path)
        if d["status"] == 404:
            res["repo_found"] = False
            res["error"] = f"repository not found on {registry}"
            return res
        if d["status"] in (401, 403):
            # ghcr/quay answer 401/403 for names that do not exist as well as private ones
            res["inaccessible"] = True
            res["error"] = (f"{registry} denied anonymous access (HTTP {d['status']}): "
                            "repository does not exist or is private")
            return res
        if d["status"] != 200:
            return _refused(res, d, f"{registry} tag listing")
        res["repo_found"] = True
        try:
            body = json.loads(d["text"])
        except ValueError:
            return _refused(res, d, f"{registry} tag listing (bad JSON)")
        names.extend(body.get("tags") or [])
        link = d["headers"].get("link", "")
        m = re.search(r"<([^>]+)>", link)
        url_path = None
        if m:
            nxt = m.group(1)
            url_path = nxt if nxt.startswith("/") else re.sub(r"^https?://[^/]+", "", nxt)
        pages += 1
    res["tags_seen"] = len(names)
    if tag:
        res["tag_exists"] = tag in names
        if not res["tag_exists"]:
            # the listing may be truncated; ask for the manifest itself
            m = http.oci_get(registry, repo, f"/v2/{repo}/manifests/{tag}", accept=MANIFEST_ACCEPT)
            res["tag_exists"] = m["status"] == 200
            if res["tag_exists"]:
                names.append(tag)
                res["notes"].append("tag found by manifest lookup but missing from the tag listing")

    def manifest_arm64(t):
        return oci_arm64(http, registry, repo, t)

    arm_by_tag = {}
    if tag and res["tag_exists"]:
        res["gemini_tag_arm64"] = oci_arm64(http, registry, repo, tag)
        arm_by_tag[tag] = res["gemini_tag_arm64"]
    _suggest(http, res, tag, names, arm_by_tag, manifest_check=manifest_arm64)
    return res


def oci_arm64(http: Http, registry, repo, tag):
    """True/False/None (None when the manifest could not be read)."""
    d = http.oci_get(registry, repo, f"/v2/{repo}/manifests/{tag}", accept=MANIFEST_ACCEPT)
    if d["status"] != 200:
        return None
    try:
        body = json.loads(d["text"])
    except ValueError:
        return None
    if body.get("manifests"):
        return any(
            (m.get("platform") or {}).get("architecture") == "arm64"
            and (m.get("platform") or {}).get("os") == "linux"
            for m in body["manifests"]
        )
    cfg = (body.get("config") or {}).get("digest")
    if not cfg:
        return None
    b = http.oci_get(registry, repo, f"/v2/{repo}/blobs/{cfg}")
    if b["status"] != 200:
        return None
    try:
        conf = json.loads(b["text"])
    except ValueError:
        return None
    return conf.get("architecture") == "arm64" and conf.get("os", "linux") == "linux"


def check_image(http: Http, ref: str):
    registry, repo, tag, digest = parse_image(ref)
    res = _blank_result(ref, registry, repo, tag)
    if "{{" in ref:
        res["error"] = "image reference contains a placeholder; not checked"
        return res
    if digest and not tag:
        res["notes"].append("pinned by digest; not checked")
        return res
    try:
        if registry == "docker.io":
            return check_hub(http, ref, repo, tag, res)
        return check_oci(http, ref, registry, repo, tag, res)
    except Exception as exc:  # keep one bad image from sinking the run
        res["error"] = f"{type(exc).__name__}: {exc}"
        res["refused"] = True
        return res


# --- what this tool adds -----------------------------------------------------------------------


def key_nums(tag):
    p = parse_tag(tag)
    return p[2] if p else ()


def entry_images(entry):
    """[(json path, image)] for each image the entry pulls."""
    if entry.get("container"):
        return [(("container", "image"), entry["container"]["image"])]
    out = []
    for i, svc in enumerate((entry.get("stack") or {}).get("services", [])):
        out.append((("stack", "services", i, "image"), svc["image"]))
    return out


def set_at(obj, path, value):
    for step in path[:-1]:
        obj = obj[step]
    obj[path[-1]] = value


def judge(ref, res):
    """('bump', new_ref, why) | ('flag', None, why) | ('same', None, '')."""
    _registry, _repo, tag, digest = parse_image(ref)
    if "{{" in ref or (digest and not tag):
        return ("same", None, "")
    if res["refused"] or res["error"] and res["repo_found"] is None and not res["inaccessible"]:
        return ("flag", None, f"couldn't look it up: {res['error']}")
    if res["inaccessible"]:
        return ("flag", None, f"vanished or private: {res['error']}")
    if res["repo_found"] is False:
        return ("flag", None, "the repository has vanished")
    if tag and res["tag_exists"] is False:
        return ("flag", None, f"the tag {tag} has vanished")
    if tag and res["gemini_tag_arm64"] is False:
        return ("flag", None, f"{tag} has lost its linux/arm64 image")
    if tag and res["gemini_tag_arm64"] is None and res["tag_exists"]:
        return ("flag", None, f"{tag} lists no platforms, so arm64 isn't confirmed")
    newest, current = res["newest_stable"], tag
    if not newest or not current:
        return ("same", None, "")
    best = None
    if key_nums(newest) > key_nums(current):
        if res["arm64"] is True:
            best = newest
        elif res["arm64"] is False:
            alt = res.get("newest_with_arm64")
            if alt and key_nums(alt) > key_nums(current):
                best = alt
            else:
                return ("flag", None, f"newer tag {newest} has no linux/arm64 image; kept {current}")
        else:
            return ("flag", None, f"newer tag {newest} found but its arm64 support couldn't be read; kept {current}")
    if best is None:
        return ("same", None, "")
    prefix = ref.split("@")[0].rsplit(":", 1)[0]
    return ("bump", f"{prefix}:{best}", f"{current} → {best}")


def run(args):
    cache = Path(args.cache or tempfile.mkdtemp(prefix="flotilla-tags-"))
    http = Http(cache, sleep=args.sleep, offline=args.offline)
    only = set(filter(None, (args.only or "").split(",")))
    bumps, flags, changed, looked = [], [], 0, {}
    for path in layout.entry_files():
        entry = layout.read_json(path)
        if only and entry["id"] not in only:
            continue
        touched = False
        for where, ref in entry_images(entry):
            if ref not in looked:
                looked[ref] = check_image(http, ref)
            verdict, new_ref, why = judge(ref, looked[ref])
            if verdict == "bump":
                bumps.append((entry["id"], ref, new_ref, why))
                set_at(entry, where, new_ref)
                touched = True
            elif verdict == "flag":
                flags.append((entry["id"], ref, why))
        if touched:
            changed += 1
            entry["tested"] = None
            if args.apply:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(layout.dump_entry(entry))
    return bumps, flags, changed, len(looked)


def report(bumps, flags, changed, images):
    lines = ["## Newer image tags", ""]
    if bumps:
        lines += [f"**{len(bumps)} bump(s) in {changed} entr{'y' if changed == 1 else 'ies'}**; each is stable, "
                  "has the same tag prefix and suffix, and has a linux/arm64 image.", "",
                  "| Entry | Image | Change |", "|---|---|---|"]
        lines += [f"| `{i}` | `{old.rsplit(':', 1)[0]}` | `{why}` |" for i, old, _new, why in bumps]
        lines += ["", "**These entries are now untested** (`tested: null`). Flotilla drops an untested entry, "
                  "so the CI check fails until each one is re-run on real Macs and its `tested` filled in. "
                  "That is intended.", ""]
    else:
        lines += ["No bumps.", ""]
    lines += ["## Flags (nothing changed for these)", ""]
    if flags:
        lines += ["| Entry | Image | Finding |", "|---|---|---|"]
        lines += [f"| `{i}` | `{ref}` | {why} |" for i, ref, why in flags]
    else:
        lines += ["None."]
    lines += ["", f"Checked {images} distinct image(s). `VERSION` and `library.json.sig` are untouched: "
              "the version is bumped and the library signed at publish, on Kamal's Mac.", ""]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="edit entry files (default: report only)")
    ap.add_argument("--report", help="write the markdown report here")
    ap.add_argument("--only", help="comma-separated entry ids")
    ap.add_argument("--cache", help="directory for registry responses (default: a temp dir)")
    ap.add_argument("--offline", action="store_true", help="cache only; no network")
    ap.add_argument("--sleep", type=float, default=0.3, help="seconds between registry calls")
    args = ap.parse_args(argv)
    bumps, flags, changed, images = run(args)
    text = report(bumps, flags, changed, images)
    if args.report:
        Path(args.report).write_text(text, encoding="utf-8")
    print(text)
    print(f"{len(bumps)} bump(s), {len(flags)} flag(s)" + ("" if args.apply else " (dry run: no files changed)"))


if __name__ == "__main__":
    main()
