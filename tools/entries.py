"""Shared by the library tools: where an entry lives, how it is written, how library.json is ordered,
and what makes an icon one Flotilla accepts."""
import glob
import hashlib
import json
import os
import re
import struct
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRIES = os.path.join(ROOT, "entries")
ICONS = os.path.join(ROOT, "icons")

# The key order library.json has always had (the order of Swift's `LibraryEntry` and friends).
# Entry files are written with sorted keys, so the build puts this order back.
ORDER = {
    "library": ["schema", "version", "entries"],
    "entry": ["id", "title", "summary", "categories", "kind", "licenceNote", "tested", "container", "stack",
              "icon"],
    "tested": ["date", "macs"],
    "container": ["image", "name", "ports", "env", "secretEnv", "volumes", "command", "note"],
    "volume": ["suffix", "path", "volumeOwner"],
    "volumeOwner": ["uid", "gid"],
    "stack": ["options", "services", "notes", "opens"],
    "option": ["id", "label", "defaultValue", "help", "email"],
    "service": ["role", "title", "image", "env", "secretEnv", "volumes", "command",
                "webPort", "wiredPort", "readyPort"],
    "secret": ["name", "secret"],
    "icon": ["file", "sha256", "bytes"],
}
CHILDREN = {
    "library": {"entries": "entry"},
    "entry": {"tested": "tested", "container": "container", "stack": "stack", "icon": "icon"},
    "container": {"volumes": "volume"},
    "stack": {"options": "option", "services": "service"},
    "service": {"volumes": "volume", "secretEnv": "secret"},
    "volume": {"volumeOwner": "volumeOwner"},
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


# --- Icons ----------------------------------------------------------------------------------------
# An entry file names its icon by path ("icons/<id>.png"); library.json carries {file, sha256, bytes},
# which the signature then covers. The limits are Flotilla's (`LibraryIcon` and `LibraryUpdater.validIcon`):
# a name inside icons/, at most 64 KiB, a single-image PNG of at most 512×512 that decodes.

ICON_MAX_BYTES = 64 * 1024
ICON_MAX_SIDE = 512
ICON_FILE = re.compile(r"icons/[a-z0-9][a-z0-9.-]{0,63}\.png")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def icon_name_problem(file):
    """A port of the file rule in `LibraryIcon.problem()`, or None."""
    if not isinstance(file, str) or len(file.encode("utf-8")) > 74 or ".." in file \
            or ICON_FILE.fullmatch(file) is None:
        return f"icon “{file}” isn't a PNG name inside icons/ (icons/<a-z0-9.->.png)"
    return None


def png_problem(data):
    """Why `data` isn't a PNG Flotilla shows, or None: signature, chunk CRCs, one image (not APNG),
    1 to 512 pixels a side, and image data that inflates to exactly the size its header says."""
    if not data.startswith(PNG_SIGNATURE):
        return "isn't a PNG"
    pos, chunks = len(PNG_SIGNATURE), []
    while pos < len(data):
        if pos + 12 > len(data):
            return "ends in the middle of a chunk"
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + length]
        if len(body) != length or pos + 12 + length > len(data):
            return "ends in the middle of a chunk"
        (crc,) = struct.unpack(">I", data[pos + 8 + length:pos + 12 + length])
        if zlib.crc32(kind + body) != crc:
            return f"has a bad CRC in its {kind.decode('latin-1')} chunk"
        chunks.append((kind, body))
        pos += 12 + length
        if kind == b"IEND":
            break
    if pos != len(data):
        return "has bytes after its end"
    if not chunks or chunks[0][0] != b"IHDR" or len(chunks[0][1]) != 13 or chunks[-1][0] != b"IEND":
        return "isn't a complete PNG (IHDR first, IEND last)"
    if any(kind in (b"acTL", b"fcTL", b"fdAT") for kind, _ in chunks):
        return "is animated (APNG); Flotilla takes a single image"
    width, height, depth, colour, _compression, _filter, interlace = struct.unpack(">IIBBBBB", chunks[0][1])
    if not (1 <= width <= ICON_MAX_SIDE and 1 <= height <= ICON_MAX_SIDE):
        return f"is {width}×{height}; Flotilla takes at most {ICON_MAX_SIDE}×{ICON_MAX_SIDE}"
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(colour)
    if channels is None or depth not in {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}[colour]:
        return "has a colour type and bit depth PNG doesn't define"
    if colour == 3 and not any(kind == b"PLTE" for kind, _ in chunks):
        return "is palette-based but has no palette"
    if interlace not in (0, 1):
        return "has an unknown interlace method"
    try:
        raw = zlib.decompress(b"".join(body for kind, body in chunks if kind == b"IDAT"))
    except zlib.error:
        return "has image data that doesn't inflate"
    passes = [(0, 0, 1, 1)] if interlace == 0 else \
        [(0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)]
    expected = 0
    for x0, y0, dx, dy in passes:
        w, h = (width - x0 + dx - 1) // dx, (height - y0 + dy - 1) // dy
        if w and h:
            expected += h * (1 + (w * channels * depth + 7) // 8)
    if len(raw) != expected:
        return "has image data of the wrong size for its header"
    return None


def icon_problems(file):
    """Every reason the icon at `file` (relative to the repo root) can't be published."""
    problem = icon_name_problem(file)
    if problem:
        return [problem]
    path = os.path.join(ROOT, file)
    if os.path.islink(path):
        return [f"{file} is a symbolic link; it must be the PNG itself"]
    if not os.path.isfile(path):
        return [f"{file} doesn't exist"]
    size = os.path.getsize(path)
    if not 1 <= size <= ICON_MAX_BYTES:
        return [f"{file} is {size} bytes; Flotilla takes 1 to {ICON_MAX_BYTES} (64 KiB)"]
    with open(path, "rb") as f:
        problem = png_problem(f.read())
    return [f"{file} {problem}"] if problem else []


def icon_object(file):
    """The `icon` library.json carries for `file`: its path, SHA-256 and byte count."""
    with open(os.path.join(ROOT, file), "rb") as f:
        data = f.read()
    return {"file": file, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
