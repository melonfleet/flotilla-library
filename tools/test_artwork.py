#!/usr/bin/env python3
"""Artwork validation and build tests: python3 tools/test_artwork.py."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build_library as build
import check_entries as check
import entries


class Artwork(unittest.TestCase):
    def setUp(self):
        self.png = Path(entries.ICONS, "wordpress.png").read_bytes()
        self.other_png = Path(entries.ICONS, "nats.png").read_bytes()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "entries").mkdir()
        (self.root / "icons").mkdir()
        (self.root / "icons/test.png").write_bytes(self.png)
        (self.root / "icons/SOURCES.md").write_text("`icons/test.png`\n", encoding="utf-8")
        (self.root / "VERSION").write_text("2026.10.19.1\n", encoding="utf-8")
        self.addCleanup(patch.stopall)
        patch.multiple(entries, ROOT=str(self.root), ENTRIES=str(self.root / "entries"),
                       ICONS=str(self.root / "icons"), ARTWORK=str(self.root / "artwork.json")).start()
        self.item = {"id": "distro.debian", "icon": "icons/test.png", "attribution": "Logo © Owner."}
        self.write_artwork([self.item])

    def write_artwork(self, items):
        (self.root / "artwork.json").write_text(entries.dumps(items), encoding="utf-8")

    def built_item(self):
        return {**self.item, "icon": entries.icon_object(self.item["icon"])}

    def test_all_requested_ids(self):
        for aid in ("distro.debian", "distro.mint", "distro.void", "distro.arch", "distro.kali",
                    "registry.registry.k8s.io", "distro.fallback"):
            with self.subTest(aid=aid):
                self.assertEqual(check.artwork_problems([{**self.item, "id": aid}], source=True), [])

    def test_id_pattern_and_bounds(self):
        for aid in ("debian", "entry.debian", "distro.", "distro.Debian", "distro.a/b",
                    "registry.host:5000", "distro." + "a" * 81):
            with self.subTest(aid=aid):
                self.assertTrue(check.artwork_problems([{**self.item, "id": aid}], source=True))
        self.assertEqual(check.artwork_problems([{**self.item, "id": "distro." + "a" * 80}], source=True), [])

    def test_duplicate_ids(self):
        self.assertTrue(any("used twice" in p for p in check.artwork_problems([self.item] * 2, source=True)))

    def test_attribution_plain_text_and_length(self):
        for attribution in ("", "a" * 301, "credit\nowner", "credit\u202eowner", "e\u0301", "\ud800", 42):
            with self.subTest(attribution=attribution):
                self.assertTrue(check.artwork_problems([{**self.item, "attribution": attribution}], source=True))
        for attribution in (None, "é" * 300):
            self.assertEqual(check.artwork_problems([{**self.item, "attribution": attribution}], source=True), [])
        item = dict(self.item)
        del item["attribution"]
        self.assertEqual(check.artwork_problems([item], source=True), [])

    def test_malformed_definitions(self):
        for items in (None, {}, [None], [{}], [{"id": "distro.debian"}],
                      [{**self.item, "icon": None}], [{**self.item, "extra": True}]):
            with self.subTest(items=items):
                self.assertTrue(check.artwork_problems(items, source=True))
        self.assertTrue(check.artwork_problems([self.item] * (check.MAX_ENTRIES + 1), source=True))

    def test_source_icon_validation(self):
        for icon in ("../test.png", "icons/missing.png", {}, "icons/test.svg"):
            with self.subTest(icon=icon):
                self.assertTrue(check.artwork_problems([{**self.item, "icon": icon}], source=True))
        icon_path = self.root / self.item["icon"]
        for data in (b"not a PNG", b"x" * (entries.ICON_MAX_BYTES + 1)):
            icon_path.write_bytes(data)
            self.assertTrue(check.check_artwork_file())
        icon_path.unlink()
        icon_path.symlink_to(self.root / "icons/SOURCES.md")
        self.assertTrue(check.check_artwork_file())

    def test_source_credit_and_orphan_icons(self):
        self.assertEqual(check.check_all()[1], [])
        (self.root / "icons/SOURCES.md").write_text("", encoding="utf-8")
        self.assertTrue(any("no line" in p for p in check.check_artwork_file()))
        self.write_artwork([])
        self.assertTrue(any("not the icon" in p for p in check.check_all()[1]))

    def test_built_icon_fields(self):
        item = self.built_item()
        self.assertEqual(check.artwork_problems([item]), [])
        for field, value in (("file", "../test.png"), ("sha256", "A" * 64),
                             ("bytes", True), ("bytes", 65537), ("bytes", 0)):
            bad = copy.deepcopy(item)
            bad["icon"][field] = value
            with self.subTest(field=field, value=value):
                self.assertTrue(check.artwork_problems([bad]))
        self.assertTrue(check.artwork_problems([self.item]))  # built icons must be objects

    def test_build_sorts_and_hashes(self):
        self.write_artwork([{**self.item, "id": "registry.registry.k8s.io"}, self.item])
        text = build.build()
        lib = json.loads(text)
        self.assertEqual([a["id"] for a in lib["artwork"]], ["distro.debian", "registry.registry.k8s.io"])
        self.assertEqual(lib["artwork"][0], self.built_item())
        self.assertEqual(text, build.build())
        self.assertEqual(check.shape_problems(lib), [])
        (self.root / "library.json").write_text(text, encoding="utf-8")
        self.assertEqual(check.check_all(str(self.root / "library.json"))[1], [])
        build.main(["--check"])
        self.write_artwork([{**self.item, "attribution": "Changed credit"}])
        with self.assertRaises(SystemExit):
            build.main(["--check"])

    def test_changed_icon_fails_check_and_staged_validation(self):
        (self.root / "library.json").write_text(build.build(), encoding="utf-8")
        (self.root / self.item["icon"]).write_bytes(self.other_png)
        with self.assertRaises(SystemExit):
            build.main(["--check"])
        self.assertTrue(any("SHA-256" in p for p in check.check_all(str(self.root / "library.json"))[1]))
        lib = {"entries": [], "artwork": [self.built_item()]}
        (self.root / self.item["icon"]).unlink()
        self.assertTrue(any("isn't beside" in p for p in check.library_icon_problems(lib, str(self.root / "library.json"))))

    def test_invalid_source_fails_build_and_check(self):
        for content in ("{", "{}", '[{"id":"bad"}]'):
            (self.root / "artwork.json").write_text(content, encoding="utf-8")
            self.assertTrue(check.check_artwork_file())
            with self.assertRaises(SystemExit):
                build.build()

    def test_optional_built_artwork(self):
        for value in ({}, {"artwork": None}, {"artwork": []}):
            lib = {"schema": 2, "version": "2026.10.19.1", "entries": [], **value}
            self.assertEqual(check.shape_problems(lib), [])
            self.assertEqual(check.library_icon_problems(lib, str(self.root / "library.json")), [])
            self.assertEqual(check.checked(lib), ([], []))
        self.assertTrue(check.checked({**lib, "artwork": [self.item]})[1])



class ArtworkIdMatchesTheApp(unittest.TestCase):
    """The app refuses these ids (`LibraryArtwork`), so the library must too (Kyle, 19 October)."""

    def test_ids_follow_the_apps_rule(self):
        import re
        def ok(aid):
            return len(aid.encode("utf-8")) <= 64 and \
                re.fullmatch(r"(distro|registry)(\.[a-z0-9]+(-[a-z0-9]+)*)+", aid) is not None
        for good in ("distro.debian", "distro.fallback", "registry.registry.k8s.io", "registry.ghcr.io"):
            self.assertTrue(ok(good), good)
        for bad in ("distro.a..b", "distro.-", "distro.a-", "registry.", "distro." + "a" * 60, "Distro.debian"):
            self.assertFalse(ok(bad), bad)

if __name__ == "__main__":
    unittest.main()
