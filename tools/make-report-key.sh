#!/bin/sh
# Makes the report signing key (once, on the owner's Mac) and stores it as the GitHub Actions
# secret REPORT_SIGNING_KEY. Prints only the public key, for Flotilla's `ReportUpdater.reportPublicKey`.
#
#   sh tools/make-report-key.sh
#
# Needs `gh` signed in with rights to set secrets on the repo, and `swift` (Xcode's command line
# tools), which the library's other signing script needs too. The private seed lives in a shell
# variable and in a pipe: it is never written to disk and never shown. Running this again makes a
# NEW key and replaces the secret, so the app must then carry the new public key.
set -eu
REPO="melonfleet/flotilla-library"
here=$(cd "$(dirname "$0")" && pwd)
command -v gh >/dev/null || { echo "gh (GitHub CLI) is needed" >&2; exit 1; }
command -v swift >/dev/null || { echo "swift is needed" >&2; exit 1; }

pair=$(swift "$here/make-report-key.swift")
set -- $pair
[ "$#" -eq 2 ] || { echo "could not make a key" >&2; exit 1; }
seed=$1 public=$2
unset pair
[ "$(printf %s "$seed" | wc -c | tr -d ' ')" -eq 44 ] || { echo "could not make a key" >&2; exit 1; }

printf %s "$seed" | gh secret set REPORT_SIGNING_KEY -R "$REPO"
unset seed
echo "Set REPORT_SIGNING_KEY on $REPO."
echo "Public key (put this in ReportUpdater.reportPublicKey):"
echo "$public"
