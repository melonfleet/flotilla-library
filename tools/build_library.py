#!/usr/bin/env python3
"""Build library.json from entries/, artwork.json and VERSION.

    python3 tools/build_library.py                 write library.json
    python3 tools/build_library.py --out PATH      write somewhere else
    python3 tools/build_library.py --check         fail if the committed library.json differs

Entries are ordered by id, keys in library.json's usual order, so unchanged entries give a
byte-identical file. An entry's `"icon": "icons/<id>.png"` becomes `{file, sha256, bytes}`, read from
that file, and so does the `icon` inside its `attributedIcon`; the build fails if an icon is missing, isn't a PNG of at most 512×512, is over 64 KiB or
has a bad name. So --check also fails when an icon changed and library.json wasn't rebuilt.
It never reads, writes or makes library.json.sig.
"""
import argparse
import os
import sys

import entries
from check_entries import check_artwork_file

# 2 since `volumeOwner` (18 October): Flotilla builds before it read 1 only, so they refuse this
# library rather than install recipes whose volumes they wouldn't set up.
SCHEMA = 2


def build():
    found, problems = [], []
    problems += check_artwork_file()
    for path in entries.entry_files():
        entry = entries.read_json(path)
        # `attributedIcon` is hashed like `icon`, so the signature covers it too.
        for holder in [entry] + ([entry["attributedIcon"]] if isinstance(entry.get("attributedIcon"), dict) else []):
            if "icon" not in holder:
                continue
            icon_problems = entries.icon_problems(holder["icon"])
            if icon_problems:
                problems += [f"{os.path.relpath(path, entries.ROOT)}: {p}" for p in icon_problems]
            else:
                holder["icon"] = entries.icon_object(holder["icon"])
        found.append(entry)
    if problems:
        sys.exit("\n".join(problems) + "\nlibrary.json can't be built with these icons.")
    found.sort(key=lambda e: e["id"])
    artwork = entries.read_artwork()
    artwork.sort(key=lambda a: a["id"])
    for item in artwork:
        item["icon"] = entries.icon_object(item["icon"])
    library = {"schema": SCHEMA, "version": entries.read_version(), "entries": found,
               "artwork": artwork}
    return entries.dumps(entries.canonical(library, "library"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(entries.ROOT, "library.json"))
    ap.add_argument("--check", action="store_true", help="compare with the committed library.json; write nothing")
    args = ap.parse_args(argv)
    text = build().encode("utf-8")
    if args.check:
        committed = os.path.join(entries.ROOT, "library.json")
        with open(committed, "rb") as f:
            if f.read() != text:
                sys.exit("library.json is not what entries/, artwork.json and VERSION build. "
                         "Run: python3 tools/build_library.py")
        print("library.json matches entries/, artwork.json and VERSION")
        return
    with open(args.out, "wb") as f:
        f.write(text)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
