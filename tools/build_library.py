#!/usr/bin/env python3
"""Build library.json from entries/ and VERSION.

    python3 tools/build_library.py                 write library.json
    python3 tools/build_library.py --out PATH      write somewhere else
    python3 tools/build_library.py --check         fail if the committed library.json differs

Entries are ordered by id, keys in library.json's usual order, so unchanged entries give a
byte-identical file. It never reads, writes or makes library.json.sig.
"""
import argparse
import os
import sys

import entries

SCHEMA = 1


def build():
    found = []
    for path in entries.entry_files():
        found.append(entries.read_json(path))
    found.sort(key=lambda e: e["id"])
    library = {"schema": SCHEMA, "version": entries.read_version(), "entries": found}
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
                sys.exit("library.json is not what entries/ and VERSION build. "
                         "Run: python3 tools/build_library.py")
        print("library.json matches entries/ and VERSION")
        return
    with open(args.out, "wb") as f:
        f.write(text)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
