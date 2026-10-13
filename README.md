# Flotilla suggestions library

Ready-made containers and stacks for [Flotilla](https://github.com/melonfleet/flotilla), the Mac app
for Apple's `container`. Flotilla shows them in **Suggestions**, by category.

## What's here

- `library.json`: the library, in the format defined by `SuggestionLibrary` in Flotilla's
  `Sources/FlotillaCore/SuggestionLibrary.swift`.
- `library.json.sig`: its Ed25519 signature, base64. Both are on the **`published`** branch,
  which is what Flotilla downloads; `main` holds the entries and tools they're built from.
- `entries/<category>/<id>.json`: one file per entry, where `library.json` is built from.
- `VERSION`: the library's version, four numbers (`2026.10.13.2`).
- `tools/`: `build_library.py`, `check_entries.py` and `check_tags.py`, used by CI and the
  publish step below. `.github/workflows/` holds the two workflows.

## How Flotilla trusts it

- **When it checks:** Flotilla checks for a newer library once a day, when the setting is on.
  The request carries nothing about the Mac.
- **What it accepts:** only a file whose signature verifies against the public key built into
  the app, in a format the app reads, and newer than the copy it has.
- **What it checks first:** every entry, before it is shown. The image must be pinned to a
  version, there must be no folders from the Mac, no password written in the file, and ports
  from 1024 up. Anything that fails is dropped.
- **What it never does:** run anything. An entry fills in Flotilla's Run form or a stack's form,
  which check it again like anything typed.

Only entries that have been run and checked on real Apple silicon Macs are published. Each entry
says when, and on how many Macs.

## Maintaining

1. **A pull request** adds an entry or changes one, by editing files in `entries/`. Then:
   `python3 tools/build_library.py` rebuilds `library.json` (commit it with the entries; it must
   match). A weekly workflow (`tags.yml`) opens a pull request with newer stable image tags; it
   marks each bumped entry `tested: null`.
2. **CI checks it** (`check.yml`, on every pull request): `library.json` is what `entries/` and
   `VERSION` build; `tools/check_entries.py` passes; and Flotilla's own check
   (`swift test --filter aLibraryFile`) passes on Linux. An untested entry fails it, on purpose.
3. **The live test**, on real Apple silicon Macs, by hand for now: start it, answer on its port,
   write its data folder, clean up. Put the result in the entry's `tested` (date, number of Macs).
4. **Merge** once CI is green and the live test passed.
5. **Publish**, on Kamal's Mac only (the signing key is in his login Keychain; no workflow signs).
   Flotilla downloads from the **`published`** branch, which holds only the signed `library.json`
   and `library.json.sig`. So `main` can change by pull request without any Mac ever seeing a
   file that doesn't match its signature. From this repo's root, with the Flotilla checkout beside
   it:

   ```sh
   git checkout main && git pull
   # set VERSION to the new version, e.g. 2026.10.14.1, and commit it to main
   python3 tools/build_library.py
   python3 tools/check_entries.py --library library.json
   (cd ../Flotilla && FLOTILLA_LIBRARY_CHECK="$OLDPWD/library.json" swift test --filter aLibraryFile)
   cp library.json /tmp/library.json
   git checkout published && cp /tmp/library.json library.json
   swift ../Flotilla/Scripts/sign-library.swift library.json
   git add library.json library.json.sig
   git commit -m "Library $(python3 -c 'import json;print(json.load(open("library.json"))["version"])')" && git push
   git checkout main
   ```

   `sign-library.swift` asks to read the key from the Keychain: choose **Allow**, not Always
   Allow. Sign last: the signature covers `library.json`'s exact bytes, so any later change to it
   needs signing again.

## Licence

The library's own text is available under the Apache License 2.0, like Flotilla. Each image keeps
its own licence. Entries say so where a licence isn't a permissive open-source one.
