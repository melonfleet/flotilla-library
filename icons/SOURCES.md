# Where each icon comes from

Every PNG here is a project's own logo, taken from the project's own repository or brand page, or
sent by its owner (never Docker Hub or an icon pack), so Flotilla can show it beside the suggestion. Each one is used unaltered
to name the software the suggestion runs, without suggesting that the project endorses Flotilla. The
logos are the projects' trademarks; the licence column is for the file itself, and the repo's Apache
2.0 licence doesn't cover them.

**How they're made:** the source is rendered (SVG at 1024 px) or read (PNG), trimmed to the mark, scaled
to fit 112×112 and centred on a transparent 128×128 canvas, then optimised (oxipng, metadata stripped).
Colours and shapes are left as they are. The two noted below are opaque square app icons, so their
corners are rounded to match the tile Flotilla draws. Only the final PNGs are kept here.

**Adding one:** put `icons/<id>.png` here (128×128, ≤ 64 KiB, at most 512×512), add
`"icon": "icons/<id>.png"` to the entry, add a row below and run `python3 tools/build_library.py`.
`tools/check_entries.py` fails for an icon without a row here. A logo whose owner requires an
attribution wherever it appears goes in `"attributedIcon": {"icon": "icons/<id>.png", "attribution":
"…"}` instead (plain text, at most 300 characters), never in `icon`: Flotilla beta 5 reads only `icon`
and can't show the attribution, so it must not get the logo. Later builds show the attribution under
Suggestions, under a group's Add Service picker and in About. Distribution and registry icons instead
go in root `artwork.json` as `{ "id": "distro.debian", "icon": "icons/distro-debian.png",
"attribution": "…" }`; the attribution is optional, plain text, and at most 300 characters.

| Icon | Project | Source (pinned) | Licence or trademark note |
|---|---|---|---|
| `icons/actual-budget.png` | Actual Budget | [actualbudget/actual `packages/desktop-client/public/maskable-512x512.png`](https://github.com/actualbudget/actual/blob/8c2fa0e86be19c4630be5bc93e03096b5b1f7c0b/packages/desktop-client/public/maskable-512x512.png) | MIT (repository licence). The app's own icon; corners rounded. |
| `icons/audiobookshelf.png` | Audiobookshelf | [advplyr/audiobookshelf `client/static/icon.svg`](https://github.com/advplyr/audiobookshelf/blob/743d9152208507a1dbf7c95c94290071338f44bd/client/static/icon.svg) | GPL-3.0 (repository licence). |
| `icons/chromadb.png` | Chroma | [chroma-core/chroma `docs/mintlify/images/favicon.svg`](https://github.com/chroma-core/chroma/blob/ddc17cd7c508f15f237c965e74e536ff64396ddb/docs/mintlify/images/favicon.svg) | Apache-2.0 (repository licence). The Chroma mark without its wordmark. |
| `icons/docker-registry.png` | CNCF Distribution (the `registry` image) | [cncf/artwork `projects/distribution/icon/color/cncf-distribution-icon-color.svg`](https://github.com/cncf/artwork/blob/fedb3dbbf74327337fb750eae0a4ec7c8b7398c0/projects/distribution/icon/color/cncf-distribution-icon-color.svg) | Linux Foundation trademark; made available under the [LF trademark usage guidelines](https://www.linuxfoundation.org/legal/trademark-usage) (no recolouring or alteration). CNCF's artwork repository is where Distribution's own README logo is published without the wordmark. Not Docker's logo: the image is Distribution's. |
| `icons/drawio.png` | draw.io | [jgraph/drawio `src/main/webapp/images/drawlogo.svg`](https://github.com/jgraph/drawio/blob/17b367b91dbab91804f852645788d7ffb46dcb79/src/main/webapp/images/drawlogo.svg) | Apache-2.0 (repository licence). |
| `icons/firefly-iii-mariadb.png` | Firefly III (stack with MariaDB) | [firefly-iii/firefly-iii `.github/assets/img/logo-small.png`](https://github.com/firefly-iii/firefly-iii/blob/b9c31006e8d3008df3d12e23de86b66088c9480e/.github/assets/img/logo-small.png) | AGPL-3.0 (repository licence). The README's logo. |
| `icons/flowise-postgres.png` | Flowise (stack with PostgreSQL) | [FlowiseAI/Flowise `packages/ui/public/logo512.png`](https://github.com/FlowiseAI/Flowise/blob/9291856d1ea4a4ceea9f8fef8ce14f4f6c81e8eb/packages/ui/public/logo512.png) | Apache-2.0 (repository licence, outside its enterprise directory). The app's own icon, since Flowise has no transparent square mark; corners rounded. |
| `icons/freshrss.png` | FreshRSS | [FreshRSS/FreshRSS `p/themes/icons/icon.svg`](https://github.com/FreshRSS/FreshRSS/blob/859a2ad0396a90d05b3b2c2fce123b0329e3823b/p/themes/icons/icon.svg) | AGPL-3.0 (repository licence). |
| `icons/gatus.png` | Gatus | [TwiN/gatus `.github/assets/logo.svg`](https://github.com/TwiN/gatus/blob/a911d7296f33edf14693785bef373e3d4a8579a3/.github/assets/logo.svg) | Apache-2.0 (repository licence). The README's logo. |
| `icons/gitea-postgres.png` | Gitea (stack with PostgreSQL) | [go-gitea/gitea `assets/logo.svg`](https://github.com/go-gitea/gitea/blob/f690ea8efd4cd712d6e8039ab6b91bf9cecad479/assets/logo.svg) | MIT (repository licence). |
| `icons/home-assistant.png` | Home Assistant | [home-assistant/assets `logo/home-assistant-logo.zip`](https://github.com/home-assistant/assets/blob/8d4090f492d60841a0db4b3b26585184b29333ba/logo/home-assistant-logo.zip), file `home-assistant-logomark-color-on-light.svg` | CC BY-NC-SA 4.0 (repository licence), and a trademark of the Open Home Foundation: “not available for commercial use without express written permission”, commercial meaning marketing or promoting something for sale ([logo/README.md](https://github.com/home-assistant/assets/blob/8d4090f492d60841a0db4b3b26585184b29333ba/logo/README.md)). Fine while Flotilla is free; remove it (or ask partner@openhomefoundation.org) if Flotilla is ever sold. |
| `icons/jellyfin.png` | Jellyfin | [jellyfin/jellyfin-ux `branding/SVG/icon-transparent.svg`](https://github.com/jellyfin/jellyfin-ux/blob/69a2b7b1237732a134dd501ff55b9404cf2d1601/branding/SVG/icon-transparent.svg) | CC BY-SA 4.0 (repository licence): attribution to the Jellyfin project; this PNG is shared under the same licence. |
| `icons/kopia.png` | Kopia | [kopia/kopia `icons/kopia-app-1024.svg`](https://github.com/kopia/kopia/blob/01938f966dc379a74de8b5ba9fc96c2048f64232/icons/kopia-app-1024.svg) | Apache-2.0 (repository licence). |
| `icons/mailpit.png` | Mailpit | [axllent/mailpit `server/ui/favicon.svg`](https://github.com/axllent/mailpit/blob/4045859fe6422a4bbdbc1b87e643903b609b3667/server/ui/favicon.svg) | MIT (repository licence). |
| `icons/mealie.png` | Mealie | [mealie-recipes/mealie `frontend/public/icon.png`](https://github.com/mealie-recipes/mealie/blob/3f9f280eed316b9eebd5b06cae39b2eb49462df1/frontend/public/icon.png) | AGPL-3.0 (repository licence). |
| `icons/metabase-postgres.png` | Metabase (stack with PostgreSQL) | [metabase/metabase `resources/frontend_client/app/assets/img/logo.svg`](https://github.com/metabase/metabase/blob/ba35fd1af0c98b8ed39254d5f11b184223b3916d/resources/frontend_client/app/assets/img/logo.svg) | AGPL-3.0 (repository licence; outside its enterprise directory). |
| `icons/nats.png` | NATS | [cncf/artwork `projects/nats/icon/color/nats-icon-color.svg`](https://github.com/cncf/artwork/blob/fedb3dbbf74327337fb750eae0a4ec7c8b7398c0/projects/nats/icon/color/nats-icon-color.svg) | Linux Foundation trademark; made available under the [LF trademark usage guidelines](https://www.linuxfoundation.org/legal/trademark-usage) (no recolouring or alteration). |
| `icons/navidrome.png` | Navidrome | [navidrome/navidrome `ui/public/android-chrome-512x512.png`](https://github.com/navidrome/navidrome/blob/df77c462e85dfb732b3a366693088bef2cff4bcb/ui/public/android-chrome-512x512.png) | GPL-3.0 (repository licence). |
| `icons/ollama.png` | Ollama | [ollama/ollama `docs/ollama-logo.svg`](https://github.com/ollama/ollama/blob/36a6e994d2f6c4ab94b3555185154d069e5dba87/docs/ollama-logo.svg) | MIT (repository licence). |
| `icons/photoprism-mariadb.png` | PhotoPrism (stack with MariaDB) | [photoprism/photoprism `assets/static/icons/logo.svg`](https://github.com/photoprism/photoprism/blob/1b075ef0f568fd6029a67f3a5f44766e128128f4/assets/static/icons/logo.svg) | PhotoPrism® trademark. Its [brand guidelines](https://www.photoprism.app/trademark) allow, as fair use, “indicating that software we distribute is available for installation without implying affiliation or endorsement”, with the official logo unaltered; never as the logo of another app. |
| `icons/redis.png` | Redis (`attributedIcon`) | The official standalone R logomark (`redis-official.png`, 80×80 PNG), sent by Redis Ltd. with its written permission of 23 October 2026 (sha256 `aec1d661e36762dcd2bd19cec1cfff45835422ce49be8a74355c1a0ab5dfeb9b`). The source is only 80 px, so the mark (70×60 once trimmed) is enlarged to 112×96. | Redis Ltd. trademark, used with its written permission on gallery and search tiles and beside containers and images running the official `redis` image. Its attribution is required, so it is shown at the foot of Suggestions (and the Add Service picker) and in About ▸ Acknowledgements: “Redis is a registered trademark of Redis Ltd. Any rights therein are reserved to Redis Ltd.” |
| `icons/stirling-pdf.png` | Stirling-PDF | [Stirling-Tools/Stirling-PDF `app/core/src/main/resources/static/favicon.svg`](https://github.com/Stirling-Tools/Stirling-PDF/blob/30dab558887f14872dc6dd7b17b59a51fb35dee4/app/core/src/main/resources/static/favicon.svg) | MIT (repository licence; `app/core` isn't one of its proprietary directories). |
| `icons/uptime-kuma.png` | Uptime Kuma | [louislam/uptime-kuma `public/icon.svg`](https://github.com/louislam/uptime-kuma/blob/b092505f894d66669b67f46e1da72b51016eceab/public/icon.svg) | MIT (repository licence). |
| `icons/valkey.png` | Valkey | [valkey-io/valkey-website `static/img/Valkey-logo.svg`](https://github.com/valkey-io/valkey-website/blob/e8759953258687a5c6e7e3c360f5e4cacaf14649/static/img/Valkey-logo.svg) | BSD-3-Clause (website repository licence). “Valkey and the Valkey logo are trademarks of LF Projects, LLC”, used under its [trademark policy](https://lfprojects.org/policies/trademark-policy/) (no recolouring or alteration). |
| `icons/vaultwarden.png` | Vaultwarden | [dani-garcia/vaultwarden `resources/vaultwarden-icon.svg`](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/resources/vaultwarden-icon.svg) | AGPL-3.0 (repository licence). |
| `icons/wordpress.png` | WordPress | [wordpress.org/about/logos](https://wordpress.org/about/logos/): [W mark, BaseGray on transparent](https://s.w.org/style/images/about/WordPress-logotype-wmark.png) | WordPress Foundation trademark. Its [trademark policy](https://wordpressfoundation.org/trademark-policy/) lets anyone use the name and logo “to refer to and explain their services”, but not as part of a product's name or branding, nor to suggest endorsement. |

## Distribution and registry artwork

**Fetched 19 October 2026.** GitHub and GitLab sources are pinned to the commit fetched (for GitHub,
the latest commit touching the file; Mint's and the CNCF pin are the earlier pins, the Mint file being
identical at the latest commit). Debian's and Arch's come from their websites, which have no
revisions, so the SHA-256 of the SVG fetched is recorded instead. Processed as described above.

Use the same render/read, trim, fit 112×112, transparent 128×128 canvas and oxipng process described
above. Do not recolour the marks or bake in a background: Flotilla supplies the light tile for dark
marks. Keep Debian's © 1999 SPI credit in the attribution; distribute its PNG under CC BY-SA 3.0.

The ids were checked against the adjacent Flotilla checkout's
`Sources/FlotillaCore/LinuxDistribution.swift` (`id` is `distro.` plus the raw value; fallback is
`distro.fallback`) and `Sources/Flotilla/SuggestionLogo.swift` (`registry.` plus the normalised host).

| Id / intended icon | Official source | Licence or trademark note | Attribution |
|---|---|---|---|
| `distro.debian` / `icons/distro-debian.png` | [Debian Open Use logo](https://www.debian.org/logos/openlogo-nd.svg) (SVG sha256 `89a3ca1a1bc91610edcc637457e7275a159309f4621829b2a0170e28970cac20`) | CC BY-SA 3.0; retain the ©1999 SPI credit. Resizing and rasterisation only. | Debian is a registered trademark owned by Software in the Public Interest, Inc. Debian Open Use Logo © 1999 Software in the Public Interest, Inc., CC BY-SA 3.0: https://creativecommons.org/licenses/by-sa/3.0/ |
| `distro.mint` / `icons/distro-mint.png` | [linuxmint/brand-logo badge.svg](https://github.com/linuxmint/brand-logo/blob/540ac3b08e987866d77a340f557f994c988ac2ae/badge.svg) | Official Linux Mint badge; no attribution required. | None required. |
| `distro.void` / `icons/distro-void.png` | [void-linux/void-packages void-logo-notext.svg](https://github.com/void-linux/void-packages/blob/f578bc2984db3c9afddc992100388e4e6f9840d0/srcpkgs/void-artwork/files/icons/void-logo-notext.svg) | Public domain. | None. |
| `distro.arch` / `icons/distro-arch.png` | [Arch Linux crystal icon](https://archlinux.org/logos/archlinux-icon-crystal-64.svg) (SVG sha256 `ed1ebed24f527f9c4db2cff78e7c4ebb2d4f20243c90196f1d0ea0996d800758`) | Non-commercial use under the Arch Linux trademark policy. | Arch Linux and the Arch Linux logo are used under the Arch Linux trademark policy. |
| `distro.kali` / `icons/distro-kali.png` | [Kali press pack black transparent dragon](https://gitlab.com/kalilinux/documentation/press-pack/-/raw/360c018b5cf65179ad3883d393b8ccbdfa674bc7/Kali/Logomark/kali-dragon-black-transparent.png) | Non-commercial use. KALI LINUX ™ is a trademark of OffSec. | KALI LINUX ™ is a trademark of OffSec. |
| `registry.registry.k8s.io` / `icons/registry-k8s.png` | [cncf/artwork Kubernetes colour icon](https://github.com/cncf/artwork/blob/fedb3dbbf74327337fb750eae0a4ec7c8b7398c0/projects/kubernetes/icon/color/kubernetes-icon-color.svg) | Linux Foundation trademarks; use under the LF trademark usage guidelines, without recolouring or alteration. | Kubernetes and the Kubernetes logo are registered trademarks of The Linux Foundation. |
| `distro.fallback` / `icons/distro-fallback.png` | [garrett/Tux tux.svg](https://github.com/garrett/Tux/blob/c2618b0cc4832166ef95828dde369356cf32f116/tux.svg) | Larry Ewing's original permits use with credit to him and the GIMP; credit Garrett LeSage for the vector. | Tux by Larry Ewing (original, made with the GIMP) and Garrett LeSage (vector). |

**Left out:** NixOS. Its brand guide calls for about 36pt including clear space; Flotilla's rows
are 20pt, so the mark cannot meet that minimum here.

## Entries without an icon

They keep their category's symbol. Each could get one later, with the owner's permission.

| Entry | Why not |
|---|---|
| `clickhouse` | ClickHouse, Inc.'s [trademark policy](https://clickhouse.com/legal/trademark-policy) allows the word mark but not the logo to describe related software; logo use needs a licence from them. |
| `jupyterhub-postgres` | JupyterHub publishes only a wordmark (`docs/source/_static/images/logo/logo.png`) and a 32×32 favicon; there is no square mark to use. |
| `mariadb` | The MariaDB Foundation's logos (CC BY-SA, [mariadb.org/about](https://mariadb.org/about/#logos-and-badges)) come only as lockups with the words “MariaDB Foundation”, must not be altered, and are offered to refer to the Foundation, not to the server. |
| `mongodb` | MongoDB's [brand resources](https://www.mongodb.com/company/newsroom/brand-resources): any use of the logo is subject to its Trademark Standards, and they ask you to request approval. |
| `postgres` | The PostgreSQL [trademark policy](https://www.postgresql.org/about/policies/trademarks/) allows the names in factual statements without approval; the Slonik logo needs permission for “pretty much any use not discussed”. |
| `rabbitmq` | Broadcom's [RabbitMQ trademark guidelines](https://www.rabbitmq.com/trademark-guidelines): nominative use “does not allow you to use the logo”, which is “reserved solely for use by Broadcom”. |
