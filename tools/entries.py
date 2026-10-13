"""Shared by the library tools: where an entry lives, how it is written, how library.json is ordered."""
import glob
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRIES = os.path.join(ROOT, "entries")

# The key order library.json has always had (the order of Swift's `LibraryEntry` and friends).
# Entry files are written with sorted keys, so the build puts this order back.
ORDER = {
    "library": ["schema", "version", "entries"],
    "entry": ["id", "title", "summary", "categories", "kind", "licenceNote", "tested", "container", "stack"],
    "tested": ["date", "macs"],
    "container": ["image", "name", "ports", "env", "secretEnv", "volumes", "command", "note"],
    "volume": ["suffix", "path"],
    "stack": ["options", "services", "notes", "opens"],
    "option": ["id", "label", "defaultValue", "help", "email"],
    "service": ["role", "title", "image", "env", "secretEnv", "volumes", "command",
                "webPort", "wiredPort", "readyPort"],
    "secret": ["name", "secret"],
}
CHILDREN = {
    "library": {"entries": "entry"},
    "entry": {"tested": "tested", "container": "container", "stack": "stack"},
    "container": {"volumes": "volume"},
    "stack": {"options": "option", "services": "service"},
    "service": {"volumes": "volume", "secretEnv": "secret"},
}


def slug(category):
    return re.sub(r"[^a-z0-9]+", "-", category.lower()).strip("-")


def entry_path(entry):
    return os.path.join(ENTRIES, slug(entry["categories"][0]), entry["id"] + ".json")


def canonical(obj, kind):
    """`obj` with its keys in library.json's order (unknown keys last, so checks can still name them)."""
    if isinstance(obj, list):
        return [canonical(x, kind) for x in obj]
    if not isinstance(obj, dict) or kind not in ORDER:
        return obj
    known = [k for k in ORDER[kind] if k in obj]
    extra = sorted(k for k in obj if k not in ORDER[kind])
    kids = CHILDREN.get(kind, {})
    return {k: canonical(obj[k], kids.get(k)) for k in known + extra}


def dumps(value):
    """The one encoding: two-space indent, UTF-8 as written, a final newline."""
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def dump_entry(entry):
    """An entry file: pretty-printed with sorted keys."""
    return json.dumps(entry, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def entry_files():
    return sorted(glob.glob(os.path.join(ENTRIES, "*", "*.json")))


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def read_version():
    with open(os.path.join(ROOT, "VERSION"), encoding="utf-8") as f:
        return f.read().strip()
