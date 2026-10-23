# Flotilla suggestions library

Ready-made containers and stacks for [Flotilla](https://github.com/melonfleet/flotilla), the Mac app
for Apple's `container`. Flotilla shows them in **Suggestions**, by category.

## What's here

- `library.json`: the library, in the format defined by `SuggestionLibrary` in Flotilla's
  `Sources/FlotillaCore/SuggestionLibrary.swift`. It is **schema 2**. Schema 2 added `volumeOwner` to a
  volume, for an image that runs as a user other than root:
  `{"suffix": "data", "path": "/var/lib/grafana", "volumeOwner": {"uid": 472, "gid": 0}}`.
  Both numbers are required, as JSON integers from 0 to 2147483647. When Flotilla has just created
  the volume, it sets the owner of the volume's top folder to that UID:GID once. It does this
  with a BusyBox image whose digest is pinned in the app, only if the folder holds nothing but
  `lost+found`, and never recursively. The setup can't be chosen in the library: there's no
  command, image or flag for it. Flotilla builds that read only schema 1, including public beta 4,
  refuse a schema-2 library and keep the copy they have. Without the bump, they would ignore
  `volumeOwner` and install recipes that can't write to their volumes.
- `library.json.sig`: its Ed25519 signature, base64. Both are on the **`published`** branch, with
  `icons/`, which is what Flotilla downloads; `main` holds the entries and tools they're built from.
- `entries/<category>/<id>.json`: one file per entry, where `library.json` is built from.
- `artwork.json`: distribution and registry artwork definitions (`id`, an `icon` path, and optional
  plain-text `attribution`, at most 300 characters). The build sorts them by id and adds each PNG's
  SHA-256 and size to the library's optional `artwork` array. These use the same icon limits and
  source documentation as entry logos. The app shows credits in Settings ▸ About ▸ Logos.
- `icons/<id>.png`: an entry's logo, 128×128, named by the entry's `"icon": "icons/<id>.png"`.
  `icons/SOURCES.md` says where each one came from and under what licence or trademark terms;
  entries without one show their category's symbol. A logo whose owner requires an attribution is
  named by `"attributedIcon": {"icon": "icons/<id>.png", "attribution": "…"}` instead, which builds
  before it (beta 5) ignore, so they never show it without the attribution.
- `VERSION`: the library's version, four numbers (`2026.10.13.2`).
- `report.json` and `report.json.sig`, also on `published`: the daily vulnerability report (below).
- `tools/`: `build_library.py`, `check_entries.py` and `check_tags.py`, used by CI and the
  publish step below; `build_report.py`, `platform_report.py`, `sign_report.py` and
  `make-report-key.sh` for reports.
  `.github/workflows/` holds the workflows.

## How Flotilla trusts it

- **When it checks:** Flotilla checks for a newer library once a day, when the setting is on.
  The request carries nothing about the Mac.
- **What it accepts:** only a file whose signature verifies against the public key built into
  the app, in a format the app reads, and newer than the copy it has.
- **What it checks first:** every entry, before it is shown. The image must be pinned to a
  version, there must be no folders from the Mac, no password written in the file, ports
  from 1024 up, and a volume owner must be a valid UID:GID. Anything that fails is dropped.
- **Icons:** `library.json` lists each icon's SHA-256 and size, so the signature covers the icons
  too. Flotilla fetches them from the same `published` branch, keeps one only if it matches and is a
  PNG of at most 64 KiB and 512×512, and shows the category's symbol otherwise.
- **What it never does:** run anything. An entry fills in Flotilla's Run form or a stack's form,
  which check it again like anything typed.

Only entries that have been run and checked on real Apple silicon Macs are published. Each entry
says when, and on how many Macs.

## Maintaining

1. **A pull request** adds an entry or changes one, by editing files in `entries/`. Then:
   `python3 tools/build_library.py` rebuilds `library.json` (commit it with the entries; it must
   match). A logo goes in `icons/<id>.png` with a row in `icons/SOURCES.md` (how, in that file);
   the build reads its hash and size, and fails on an icon Flotilla wouldn't show. A weekly workflow (`tags.yml`) opens a pull request with newer stable image tags; it
   marks each bumped entry `tested: null`.
2. **CI checks it** (`check.yml`, on every pull request): `library.json` is what `entries/` and
   `artwork.json` and `VERSION` build (icons included); `tools/check_entries.py` passes, icons and all; and Flotilla's own check
   (`swift test --filter aLibraryFile`) passes on Linux. An untested entry fails it, on purpose.
3. **The live test**, on real Apple silicon Macs, by hand for now: start it, answer on its port,
   write its data folder, clean up. For an entry with `volumeOwner`, do what Flotilla does:
   create the volume, run the pinned BusyBox chown on it, then run the entry. Put the result in the entry's `tested` (date, number of Macs).
4. **Merge** once CI is green and the live test passed.
5. **Publish**, on Kamal's Mac only (the signing key is in his login Keychain; no workflow signs).
   Flotilla downloads from the **`published`** branch, which holds only the signed `library.json`,
   `library.json.sig` and `icons/`. So `main` can change by pull request without any Mac ever
   seeing a file that doesn't match its signature. From this repo's root, with the Flotilla
   checkout beside it:

   ```sh
   git checkout main && git pull
   # set VERSION to the new version, e.g. 2026.10.14.1, and commit it to main
   python3 tools/build_library.py
   python3 tools/check_entries.py --library library.json
   (cd ../Flotilla && FLOTILLA_LIBRARY_CHECK="$OLDPWD/library.json" swift test --filter aLibraryFile)
   stage=$(mktemp -d) && cp -R library.json icons "$stage/"
   python3 tools/check_entries.py --library "$stage/library.json"
   git checkout published && rm -rf icons && cp -R "$stage/library.json" "$stage/icons" .
   swift ../Flotilla/Scripts/sign-library.swift library.json
   git add -A library.json library.json.sig icons
   git commit -m "Library $(python3 -c 'import json;print(json.load(open("library.json"))["version"])')" && git push
   git checkout main
   ```

   The staged copy is checked on its own, so every icon `library.json` lists is beside it with
   the hash and size it lists; `rm -rf icons` drops any icon no entry uses any more. Nothing new
   is signed: the icons are covered by the hashes in `library.json`. `sign-library.swift` asks to
   read the key from the Keychain: choose **Allow**, not Always Allow. Sign last: the signature
   covers `library.json`'s exact bytes, so any later change to it needs signing again.

## Vulnerability reports

`scan.yml` runs once a day (and on demand from the Actions tab). It scans the **linux/arm64** build of
every image in the published `library.json` with [Grype](https://github.com/anchore/grype), at a
version pinned in the workflow and checked against a SHA-256 written in it, and commits a signed
`report.json` and `report.json.sig` to `published`. For each image the report has both digests a
local `container` image can show (the index digest and the arm64 manifest digest), counts of
critical, high, medium and low findings, and the critical and high ones with the version that fixes
them. Flotilla downloads it beside the library, with the same anonymous request, and matches it
against your images **on your Mac, by digest**; nothing about your images is sent anywhere. An image
the library doesn't list has no report, and Flotilla then shows nothing, not "no vulnerabilities".

- **A second key.** Reports are signed with their own Ed25519 key, held as the Actions secret
  `REPORT_SIGNING_KEY` and used only by the publish job. The library key stays in the owner's
  Keychain and no workflow touches it. Flotilla accepts the report key for reports only and the
  library key for the library only, so a leaked report key can at worst show a false or missing
  warning; it can never change a recipe. Make the key once, on the owner's Mac, with
  `sh tools/make-report-key.sh`: it sends the private half straight to GitHub without showing or saving
  it, and prints the public half for the app.
- **Advisory only.** A finding never stops, pulls, rebuilds or restarts anything. A scanner reports what its
  database knows about the packages it can see: no finding is not a promise of safety, and a finding
  may not be reachable in how you run the image.
- **Least privilege.** The scan job reads and has no secret; the publish job is the only one that can
  write, only to `published`, and only `report.json` and `report.json.sig`. A run whose report differs
  from the last only in `generated` commits nothing.
- **macOS and the container kernel.** The same report has an optional `platform` section
  (`tools/platform_report.py`), which older Flotillas ignore, so the format stays `schema` 1. The
  scan job fetches the sources:
  - Apple's version feed (`gdmf.apple.com/v2/pmv`, read trusting only the Apple Root CA in
    `tools/apple-root-ca.pem`, whose hash the workflow checks);
  - Apple's security releases page (`support.apple.com/100100`) and each macOS 26+ note it links;
  - apple/container's release tags and the kernel each release recommends;
  - OSV's Linux export.

  The section lists each macOS release's CVEs and the exploited ones. For the kernel it gives
  `container`'s recommended kernel, and for each older kernel a `container` release recommended,
  how many high and critical CVEs the recommended one fixes there, plus the top five. Flotilla
  matches a host's macOS version and kernel against it on the admin Mac. A source that fails to
  parse leaves that section as it was the day before. The captured sources the tests use are in
  `tools/fixtures/platform/` (see its `CAPTURED.md`).
- **Tests.** `python3 -m unittest discover -s tools -p 'test_*.py'` (the signing tests need
  `pip install -r tools/requirements-sign.txt`); CI runs them.

## Licence

The library's own text is available under the Apache License 2.0, like Flotilla. Each image keeps
its own licence. Entries say so where a licence isn't a permissive open-source one. The logos in
`icons/` aren't covered by the Apache licence: they are their projects' trademarks, used to name
the software, each on the terms in `icons/SOURCES.md`.
