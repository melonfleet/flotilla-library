#!/usr/bin/env python3
"""Check entries/ before the Swift check does: python3 tools/check_entries.py [--library library.json]

Every entry file is read, shape-checked (what Swift's Decodable demands), then run through a Python
port of FlotillaCore's `LibraryEntry.problem()` rules. It also checks the repo's own layout: one
entry per `entries/<first-category-slug>/<id>.json`, written with sorted keys, and a VERSION Flotilla
accepts. Icons too: an entry's `icon` is `icons/<id>.png`, a PNG Flotilla accepts (64 KiB, 512×512,
one image), listed in icons/SOURCES.md; icons/ holds nothing else. With --library, each icon in the built
file must match the PNG beside it, byte count and SHA-256. Exits 1 and names every problem. It is a pre-check for a pull request, not a replacement
for `swift test --filter aLibraryFile`, which stays the authority.

The rules are ported from experiments' make_library.py; when Flotilla's rules change, change both.
"""
import argparse
import hashlib
import os
import re
import sys
import unicodedata

import entries as layout

CATEGORIES = [
    "Education", "Business & Office", "Finance & Accounting", "E-commerce", "Software Development",
    "Databases", "Data & Analytics", "AI & Machine Learning", "Monitoring & Operations",
    "Security & Identity", "Networking & Web Servers", "Content & Publishing",
    "Communication & Collaboration", "Storage & Files", "Media & Photos", "Home & Personal",
    "Science & Research", "Messaging & Queues",
]
MAX_ENTRIES = 1000
PASSWORD_WORDS = ("PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY")
NEWLINES = "\n\r\x0b\x0c\x85  "


def is_identifier(value):
    """Allowlist `.identifier`: ASCII alphanumeric first, then alphanumerics, `_`, `.`, `-`; 1...128."""
    return re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}", value) is not None


def is_image_reference(value):
    """Allowlist `.imageReference`: `[registry[:port]/]name[:tag][@sha256:...]`."""
    if not 1 <= len(value) <= 512 or not re.fullmatch(r"[A-Za-z0-9]", value[0]):
        return False
    if not re.fullmatch(r"[A-Za-z0-9_.\-/:@]+", value):
        return False
    path = value.split("@", 1)[0]
    parts = path.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return False
    if parts[-1].endswith(":"):
        return False
    digest = value.split("@")
    if len(digest) > 2:
        return False
    if len(digest) == 2:
        if not digest[1].startswith("sha256:"):
            return False
        if re.fullmatch(r"[0-9a-f]{64}", digest[1][len("sha256:"):]) is None:
            return False
    return True


def is_env_name(name):
    return len(name) <= 64 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is not None


def is_email(value):
    parts = value.split("@")
    if len(parts) != 2 or not parts[0] or "." not in parts[1] or parts[1].startswith(".") or parts[1].endswith("."):
        return False
    return all(ord(c) < 128 and not c.isspace() and c not in "\"'<>(),;:\\[]" for c in value)


def placeholders(value):
    found, rest = [], value
    while True:
        open_ = rest.find("{{")
        if open_ < 0:
            return found
        close = rest.find("}}", open_ + 2)
        if close < 0:
            return found
        found.append(rest[open_ + 2:close])
        rest = rest[close + 2:]


def image_problem(image):
    if not is_image_reference(image):
        return f"“{image}” isn't an image reference."
    last = [p for p in image.split("/") if p][-1]
    pieces = [p for p in last.split(":") if p]
    if len(pieces) < 2 or pieces[1] == "latest":
        return f"“{image}” isn't pinned to a version."
    return None


def port_problem(spec):
    parts = spec.split(":")
    if len(parts) == 2 and re.fullmatch(r"[0-9]+", parts[0]) and re.fullmatch(r"[0-9]+", parts[1]):
        host, inside = int(parts[0]), int(parts[1])
        if 1024 <= host <= 65535 and 1 <= inside <= 65535:
            return None
    return f"“{spec}” isn't a port pair with a port from 1024 on this Mac."


def env_problem(value, templates):
    parts = value.split("=", 1)
    if len(parts) != 2 or not is_env_name(parts[0]):
        return f"“{value[:40]}” isn't NAME=value."
    if len(value) > 512 or any(c in NEWLINES for c in value):
        return "A variable's value is too long."
    if not templates and "{{" in value:
        return "A container entry can't use placeholders."
    name = parts[0].upper()
    if any(w in name for w in PASSWORD_WORDS) and not parts[1].startswith("{{"):
        return f"{parts[0]} looks like a password: it must be generated, not written in the library."
    return None


def command_problem(command):
    if len(command) > 16 or any(len(c) > 256 or any(n in c for n in NEWLINES) for c in command):
        return "Its command is too long."
    if any("$(" in c or "${" in c or "`" in c for c in command):
        return "Its command expects a shell, and none runs it."
    return None


UID_GID_MAX = 2147483647


def volume_owner_problem(owner):
    """`VolumeOwner.isValid`: both `uid` and `gid`, JSON integers from 0 to 2147483647."""
    if not isinstance(owner, dict) or set(owner) != {"uid", "gid"}:
        return "A volume owner must give both uid and gid, and nothing else."
    if not all(isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= UID_GID_MAX for v in owner.values()):
        return f"A volume owner must use UID and GID from 0 to {UID_GID_MAX}."
    return None


def volume_problem(volume):
    if volume.get("volumeOwner") is not None:
        problem = volume_owner_problem(volume["volumeOwner"])
        if problem:
            return problem
    if not is_identifier(volume["suffix"]):
        return "A volume's name isn't a plain name."
    path = volume["path"]
    if (not path.startswith("/") or len(path) > 200 or ".." in [p for p in path.split("/") if p]
            or any(c.isspace() or c == ":" for c in path)):
        return "A volume path isn't an absolute path inside the container."
    return None


def first(problems):
    return next((p for p in problems if p), None)


def container_problem(c):
    for check in (
        lambda: image_problem(c["image"]),
        lambda: None if is_identifier(c["name"]) else "Its container name isn't a plain name.",
        lambda: first(port_problem(p) for p in c["ports"]),
        lambda: first(env_problem(v, False) for v in c["env"]),
        lambda: None if all(is_env_name(n) for n in c["secretEnv"])
        else "A password variable's name isn't a variable name.",
        lambda: first(volume_problem(v) for v in c["volumes"]),
        lambda: command_problem(c["command"]),
        lambda: "Its note is too long." if len(c.get("note") or "") > 400 else None,
    ):
        problem = check()
        if problem:
            return problem
    return None


def stack_problem(s):
    services = s["services"]
    if not 1 <= len(services) <= 6:
        return "A stack has one to six services."
    roles = [v["role"] for v in services]
    if len(set(roles)) != len(roles) or not all(is_identifier(r) and len(r) <= 24 for r in roles):
        return "Its service roles aren't distinct plain names."
    for o in s["options"]:
        if not (is_identifier(o["id"]) and o["label"] and len(o["label"]) <= 60 and len(o["help"]) <= 240):
            return "One of its settings is malformed."
        ok = is_email(o["defaultValue"]) if o["email"] else is_identifier(o["defaultValue"])
        if not ok:
            return f"{o['label']}: {'Expected an email address such as admin@example.com.' if o['email'] else 'Not a plain name.'}"
    option_ids = {o["id"] for o in s["options"]}
    for v in services:
        problem = image_problem(v["image"])
        if problem:
            return problem
        if not v["title"] or len(v["title"]) > 60:
            return "A service's title is missing or too long."
        for key in ("webPort", "wiredPort", "readyPort"):
            port = v.get(key)
            if port is not None and not 1 <= port <= 65535:
                return f"{port} isn't a port."
        for value in v["env"]:
            problem = env_problem(value, True)
            if problem:
                return problem
            for token in placeholders(value):
                problem = placeholder_problem(token, option_ids, services)
                if problem:
                    return problem
        if not all(is_env_name(x["name"]) and is_identifier(x["secret"]) for x in v["secretEnv"]):
            return "A password variable is malformed."
        problem = first(volume_problem(x) for x in v["volumes"]) or command_problem(v["command"])
        if problem:
            return problem
    if s.get("opens") is not None and s["opens"] not in roles:
        return "It opens a service it doesn't have."
    if len(s["notes"]) > 8 or any(len(n) > 400 for n in s["notes"]):
        return "Its notes are too long."
    return None


def placeholder_problem(token, option_ids, services):
    parts = token.split(":", 1)
    if len(parts) != 2:
        return f"“{{{{{token}}}}}” isn't a placeholder Flotilla fills."
    if parts[0] == "option" and parts[1] in option_ids:
        return None
    if parts[0] in ("host", "port"):
        target = next((v for v in services if v["role"] == parts[1]), None)
        if target is None or target.get("wiredPort") is None:
            return f"“{{{{{token}}}}}” names a service other services can't reach."
        return None
    return f"“{{{{{token}}}}}” isn't a placeholder Flotilla fills."


def entry_problem(e):
    """Why `e` can't be offered, or None. A port of `LibraryEntry.problem()`."""
    if not (is_identifier(e["id"]) and len(e["id"]) <= 64):
        return "Its id isn't a plain name."
    if not (1 <= len(e["title"]) <= 80 and len(e["summary"]) <= 240):
        return "Its title or summary is too long."
    cats = e["categories"]
    if not (1 <= len(cats) <= 3 and all(c in CATEGORIES for c in cats)):
        return "Its categories aren't from the library's list."
    if len(e.get("licenceNote") or "") > 400:
        return "Its licence note is too long."
    if e["kind"] == "container":
        if e.get("container") is None or e.get("stack") is not None:
            return "A container entry must describe one container."
        return container_problem(e["container"])
    if e["kind"] == "stack":
        if e.get("stack") is None or e.get("container") is not None:
            return "A stack entry must describe its services."
        return stack_problem(e["stack"])
    return "Its kind isn't container or stack."


def icon_problem(icon):
    """A port of `LibraryIcon.problem()`. Swift decodes a malformed icon as empty fields, never failing."""
    icon = icon if isinstance(icon, dict) else {}
    file, sha256, size = icon.get("file"), icon.get("sha256"), icon.get("bytes")
    if layout.icon_name_problem(file if isinstance(file, str) else ""):
        return "Its file isn't a PNG name inside icons/."
    if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
        return "Its SHA-256 isn't 64 lowercase hexadecimal digits."
    if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= layout.ICON_MAX_BYTES:
        return "Its size isn't between 1 and 65536 bytes."
    return None


def checked(library):
    """A port of `SuggestionLibrary.checked()`: (kept entries, [(id, problem)]). A bad icon drops only
    the icon, as in Swift, but is still named, so the check fails."""
    kept, dropped, seen = [], [], set()
    for e in library["entries"][:MAX_ENTRIES]:
        problem = entry_problem(e)
        if problem:
            dropped.append((e["id"], problem))
        elif e["id"] in seen:
            dropped.append((e["id"], "Its id is used twice."))
        else:
            seen.add(e["id"])
            if e.get("icon") is not None and icon_problem(e["icon"]):
                dropped.append((e["id"], "Icon ignored: " + icon_problem(e["icon"])))
            kept.append(e)
    if len(library["entries"]) > MAX_ENTRIES:
        dropped.append(("…", f"More than {MAX_ENTRIES} entries; the rest were ignored."))
    return kept, dropped


# What Swift's synthesized Decodable demands: every non-optional key present, no wrong types. A file
# that misses one is refused whole ("The library couldn't be read"), so check it here too.
SHAPES = {
    "library": ({"schema": int, "version": str, "entries": list}, {}),
    "entry": ({"id": str, "title": str, "summary": str, "categories": list, "kind": str},
              {"licenceNote": str, "tested": dict, "container": dict, "stack": dict, "icon": (str, dict)}),
    "tested": ({"date": str, "macs": int}, {}),
    "container": ({"image": str, "name": str, "ports": list, "env": list, "secretEnv": list,
                   "volumes": list, "command": list}, {"note": str}),
    "volume": ({"suffix": str, "path": str}, {"volumeOwner": dict}),
    "stack": ({"options": list, "services": list, "notes": list}, {"opens": str}),
    "option": ({"id": str, "label": str, "defaultValue": str, "help": str, "email": bool}, {}),
    "service": ({"role": str, "title": str, "image": str, "env": list, "secretEnv": list, "volumes": list,
                 "command": list}, {"webPort": int, "wiredPort": int, "readyPort": int}),
    "secret": ({"name": str, "secret": str}, {}),
}


def shape_problems(obj, kind="library", where="library"):
    required, optional = SHAPES[kind]
    out = []
    if not isinstance(obj, dict):
        return [f"{where}: not an object"]
    for key, typ in {**required, **optional}.items():
        if key in obj and obj[key] is None and key in optional:
            continue  # Swift reads an optional's null as absent; `tested: null` is named by tested_problem
        if key in obj:
            ok = isinstance(obj[key], typ) and not (typ is int and isinstance(obj[key], bool))
            if not ok:
                out.append(f"{where}.{key}: wrong type")
        elif key in required:
            out.append(f"{where}.{key}: missing")
    for key in obj:
        if key not in required and key not in optional:
            out.append(f"{where}.{key}: unknown key")
    if out:
        return out
    children = {
        "library": [("entries", "entry")],
        "entry": [("tested", "tested"), ("container", "container"), ("stack", "stack")],
        "container": [("volumes", "volume")],
        "stack": [("options", "option"), ("services", "service")],
        "service": [("volumes", "volume"), ("secretEnv", "secret")],
    }.get(kind, [])
    for key, child in children:
        if obj.get(key) is None:
            continue
        for i, item in enumerate(obj[key] if isinstance(obj[key], list) else [obj[key]]):
            out += shape_problems(item, child, f"{where}.{key}[{i}]")
    if kind in ("container", "service", "stack", "entry"):
        for key in ("ports", "env", "command", "notes", "categories"):
            if isinstance(obj.get(key), list) and not all(isinstance(x, str) for x in obj[key]):
                out.append(f"{where}.{key}: not all strings")
        if kind == "container" and not all(isinstance(x, str) for x in obj.get("secretEnv", [])):
            out.append(f"{where}.secretEnv: not all strings")
    return out


# --- Checks added for the repo ------------------------------------------------------------------

SCHEMA = 2  # what build_library.py writes; 2 since `volumeOwner`
BAD_CATEGORIES = {"Cc", "Cf", "Co", "Cn", "Cs", "Zl", "Zp"}


def plain_text(text, limit, required=False):
    """Port of `Library.isPlainText`: NFC, bounded, and no control, format, private-use or unassigned scalars."""
    if (required and not text) or len(text) > limit or len(text.encode("utf-8")) > limit * 4:
        return False
    if unicodedata.normalize("NFC", text) != text:
        return False
    return not any(unicodedata.category(c) in BAD_CATEGORIES for c in text)


def tested_problem(t):
    if t is None:
        return "It hasn't been tested."
    if not 1 <= t["macs"] <= 20:
        return f"It says it was tested on {t['macs']} Macs."
    d = t["date"]
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", d) is None:
        return "Its test date isn't a date written YYYY-MM-DD."
    y, m, day = int(d[:4]), int(d[5:7]), int(d[8:])
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if not (1 <= m <= 12 and 1 <= day <= days[m - 1]):
        return "Its test date isn't a date written YYYY-MM-DD."
    return None


def text_problems(e):
    """The plain-text rules Swift applies to every human-readable field."""
    out = []
    if not plain_text(e["title"], 80, True) or not plain_text(e["summary"], 240):
        out.append("Its title or summary is too long, or has characters that aren't plain text.")
    if e.get("licenceNote") is not None and not plain_text(e["licenceNote"], 400):
        out.append("Its licence note is too long, or has characters that aren't plain text.")
    c, s = e.get("container"), e.get("stack")
    if c and c.get("note") is not None and not plain_text(c["note"], 400):
        out.append("Its note isn't plain text.")
    if s:
        for o in s["options"]:
            if not (plain_text(o["label"], 60, True) and plain_text(o["help"], 240)):
                out.append("A setting's label or help isn't plain text.")
        for v in s["services"]:
            if not plain_text(v["title"], 60, True):
                out.append("A service's title isn't plain text.")
        if not all(plain_text(n, 400, True) for n in s["notes"]):
            out.append("A stack note isn't plain text.")
    return out


def valid_version(version):
    parts = version.split(".")
    return len(parts) == 4 and all(re.fullmatch(r"(0|[1-9][0-9]{0,3})", p) for p in parts)


def check_entry_file(path):
    rel = os.path.relpath(path, layout.ROOT)
    try:
        e = layout.read_json(path)
        raw = open(path, encoding="utf-8").read()
    except (OSError, ValueError) as err:
        return [f"{rel}: can't be read: {err}"]
    shape = shape_problems(e, "entry", "entry")
    if shape:
        return [f"{rel}: {p}" for p in shape]
    problems = []
    if e["id"] != os.path.basename(path)[:-len(".json")]:
        problems.append(f"{rel}: the file name must be the entry's id ({e['id']}.json)")
    if e["categories"]:
        want = layout.slug(e["categories"][0])
        if os.path.basename(os.path.dirname(path)) != want:
            problems.append(f"{rel}: its first category “{e['categories'][0]}” puts it in entries/{want}/")
    if raw != layout.dump_entry(e):
        problems.append(f"{rel}: not written the standard way (two-space indent, sorted keys, final newline)")
    for message in [entry_problem(e), tested_problem(e.get("tested"))] + text_problems(e) + entry_icon_problems(e):
        if message:
            problems.append(f"{rel}: {message}")
    return problems


def entry_icon_problems(e):
    """An entry file's `icon`: the path icons/<id>.png, to a PNG that passes Flotilla's limits and has
    a line in icons/SOURCES.md. No icon is fine: Flotilla shows the category's symbol."""
    if e.get("icon") is None:
        return []
    want = f"icons/{e['id']}.png"
    if e["icon"] != want:
        return [f"its icon must be “{want}” (just the path; the build adds the hash and size)"]
    problems = layout.icon_problems(want)
    if not problems and f"`{want}`" not in _sources():
        problems.append(f"{want} has no line in icons/SOURCES.md saying where it came from")
    return problems


def _sources():
    try:
        with open(os.path.join(layout.ICONS, "SOURCES.md"), encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def icons_dir_problems(referenced):
    """icons/ holds the referenced PNGs and SOURCES.md, nothing else: whatever is there gets published."""
    out = []
    for path in _all_files(layout.ICONS):
        rel = os.path.relpath(path, layout.ROOT).replace(os.sep, "/")
        if rel == "icons/SOURCES.md":
            continue
        if rel not in referenced:
            out.append(f"{rel}: not the icon of any entry (icons/ holds only entries' icons and SOURCES.md)")
    return out


def library_icon_problems(lib, library_path):
    """Each icon in a built library must be the PNG beside it, as Flotilla will fetch it from published."""
    out, base = [], os.path.dirname(os.path.abspath(library_path))
    for e in lib["entries"]:
        icon = e.get("icon")
        if icon is None or icon_problem(icon):
            continue  # named by checked()
        path = os.path.join(base, icon["file"])
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            out.append(f"{library_path}: {e['id']}: {icon['file']} isn't beside it")
            continue
        if len(data) != icon["bytes"] or hashlib.sha256(data).hexdigest() != icon["sha256"]:
            out.append(f"{library_path}: {e['id']}: {icon['file']} isn't the file whose size and SHA-256 it lists")
        elif layout.png_problem(data):
            out.append(f"{library_path}: {e['id']}: {icon['file']} {layout.png_problem(data)}")
    return out


def check_all(library_path=None):
    problems, seen, icons = [], {}, set()
    files = layout.entry_files()
    stray = [p for p in _all_files(layout.ENTRIES) if p not in files]
    problems += [f"{os.path.relpath(p, layout.ROOT)}: not an entries/<category>/<id>.json file" for p in stray]
    for path in files:
        problems += check_entry_file(path)
        try:
            entry = layout.read_json(path)
            eid = entry["id"]
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if isinstance(entry.get("icon"), str):
            icons.add(entry["icon"])
        if eid in seen:
            problems.append(f"{os.path.relpath(path, layout.ROOT)}: id {eid} is also in {os.path.relpath(seen[eid], layout.ROOT)}")
        seen[eid] = path
    problems += icons_dir_problems(icons)
    if len(files) > MAX_ENTRIES:
        problems.append(f"{len(files)} entries; Flotilla reads {MAX_ENTRIES}.")
    try:
        version = layout.read_version()
        if not valid_version(version):
            problems.append(f"VERSION: “{version}” isn't four numbers from 0 to 9999, such as 2026.10.13.2.")
    except OSError as err:
        problems.append(f"VERSION: can't be read: {err}")
    if library_path:
        try:
            lib = layout.read_json(library_path)
            problems += shape_problems(lib, "library", "library")
            if lib.get("schema") != SCHEMA:
                problems.append(f"{library_path}: schema isn't {SCHEMA}")
            kept, dropped = checked(lib) if not shape_problems(lib) else ([], [])
            problems += [f"{library_path}: {i}: {p}" for i, p in dropped]
            if not shape_problems(lib):
                problems += library_icon_problems(lib, library_path)
        except (OSError, ValueError) as err:
            problems.append(f"{library_path}: can't be read: {err}")
    return len(files), problems


def _all_files(root):
    out = []
    for base, _dirs, names in os.walk(root):
        out += [os.path.join(base, n) for n in names]
    return sorted(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--library", help="also check a built library.json")
    args = ap.parse_args(argv)
    count, problems = check_all(args.library)
    for p in problems:
        print(p)
    if problems:
        print(f"\n{len(problems)} problem(s) in {count} entries.")
        sys.exit(1)
    print(f"{count} entries pass.")


if __name__ == "__main__":
    main()
