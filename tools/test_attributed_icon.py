#!/usr/bin/env python3
"""`attributedIcon` validation and build tests: python3 tools/test_attributed_icon.py."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build_library as build
import check_entries as check
import entries

ATTRIBUTION = "Redis is a registered trademark of Redis Ltd. Any rights therein are reserved to Redis Ltd."


class AttributedIcon(unittest.TestCase):
    def setUp(self):
        self.png = Path(entries.ICONS, "wordpress.png").read_bytes()
        self.other_png = Path(entries.ICONS, "nats.png").read_bytes()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "entries").mkdir()
        (self.root / "icons").mkdir()
        (self.root / "icons/cache.png").write_bytes(self.png)
        (self.root / "icons/SOURCES.md").write_text("`icons/cache.png`\n", encoding="utf-8")
        (self.root / "VERSION").write_text("2026.10.23.1\n", encoding="utf-8")
        (self.root / "artwork.json").write_text("[]\n", encoding="utf-8")
        self.addCleanup(patch.stopall)
        patch.multiple(entries, ROOT=str(self.root), ENTRIES=str(self.root / "entries"),
                       ICONS=str(self.root / "icons"), ARTWORK=str(self.root / "artwork.json")).start()
        self.entry = {
            "id": "cache", "title": "Cache", "summary": "", "categories": ["Databases"], "kind": "container",
            "tested": {"date": "2026-10-20", "macs": 1},
            "container": {"image": "docker.io/library/redis:8.10.2", "name": "cache", "ports": [], "env": [],
                          "secretEnv": [], "volumes": [], "command": []},
            "attributedIcon": {"icon": "icons/cache.png", "attribution": ATTRIBUTION},
        }

    def write(self, entry):
        path = Path(entries.entry_path(entry))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(entries.dump_entry(entry), encoding="utf-8")
        return path

    def problems(self, entry):
        return check.check_entry_file(str(self.write(entry)))

    def test_a_good_one_passes_and_is_hashed_into_the_build(self):
        self.assertEqual(self.problems(self.entry), [])
        self.assertEqual(check.check_all()[1], [])
        lib = json.loads(build.build())
        built = lib["entries"][0]
        self.assertNotIn("icon", built)
        self.assertEqual(built["attributedIcon"],
                         {"icon": entries.icon_object("icons/cache.png"), "attribution": ATTRIBUTION})
        self.assertEqual(list(built)[-1], "attributedIcon")
        self.assertEqual(check.shape_problems(lib), [])
        self.assertEqual(check.checked(lib)[1], [])
        (self.root / "library.json").write_text(build.build(), encoding="utf-8")
        self.assertEqual(check.check_all(str(self.root / "library.json"))[1], [])
        # The signature covers it: a changed PNG no longer matches the library.
        (self.root / "icons/cache.png").write_bytes(self.other_png)
        self.assertTrue(any("SHA-256" in p for p in check.check_all(str(self.root / "library.json"))[1]))

    def test_the_attribution_is_plain_text_up_to_300(self):
        for attribution in ("", "a" * 301, "credit\nowner", "credit‮owner", "é"):
            with self.subTest(attribution=attribution):
                entry = copy.deepcopy(self.entry)
                entry["attributedIcon"]["attribution"] = attribution
                self.assertTrue(self.problems(entry))
        entry = copy.deepcopy(self.entry)
        entry["attributedIcon"]["attribution"] = "é" * 300
        self.assertEqual(self.problems(entry), [])

    def test_its_shape_and_icon_follow_the_icon_rules(self):
        for attributed in ({"icon": "icons/cache.png"}, {"attribution": ATTRIBUTION},
                           {"icon": "icons/other.png", "attribution": ATTRIBUTION},
                           {"icon": "icons/cache.png", "attribution": ATTRIBUTION, "extra": 1},
                           {"icon": "icons/cache.png", "attribution": 42}, "icons/cache.png"):
            with self.subTest(attributed=attributed):
                self.assertTrue(self.problems({**self.entry, "attributedIcon": attributed}))
        (self.root / "icons/SOURCES.md").write_text("", encoding="utf-8")
        self.assertTrue(any("no line" in p for p in self.problems(self.entry)))

    def test_never_beside_a_plain_icon(self):
        # Beta 5 would draw `icon` without the attribution.
        self.assertTrue(self.problems({**self.entry, "icon": "icons/cache.png"}))

    def test_its_icon_is_referenced(self):
        self.write(self.entry)
        self.assertFalse(any("not the icon" in p for p in check.check_all()[1]))
        entry = dict(self.entry)
        del entry["attributedIcon"]
        self.write(entry)
        self.assertTrue(any("not the icon" in p for p in check.check_all()[1]))

    def test_a_bad_built_one_is_named_like_the_app(self):
        self.write(self.entry)
        lib = json.loads(build.build())
        for attributed in ({**lib["entries"][0]["attributedIcon"], "attribution": ""},
                           {**lib["entries"][0]["attributedIcon"], "icon": {"file": "../x.png"}}):
            bad = copy.deepcopy(lib)
            bad["entries"][0]["attributedIcon"] = attributed
            dropped = check.checked(bad)[1]
            self.assertEqual([i for i, _ in dropped], ["cache"])
            self.assertTrue(dropped[0][1].startswith("Attributed icon ignored: "))


if __name__ == "__main__":
    unittest.main()
