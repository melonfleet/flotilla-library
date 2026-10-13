# Flotilla suggestions library

Ready-made containers and stacks for [Flotilla](https://github.com/melonfleet/flotilla), the Mac app
for Apple's `container`. Flotilla shows them in **Suggestions**, by category.

## What's here

- `library.json`: the library, in the format defined by `SuggestionLibrary` in Flotilla's
  `Sources/FlotillaCore/SuggestionLibrary.swift`.
- `library.json.sig`: its Ed25519 signature, base64.

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

## Licence

The library's own text is available under the Apache License 2.0, like Flotilla. Each image keeps
its own licence. Entries say so where a licence isn't a permissive open-source one.
