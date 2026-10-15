# Brand Reference + Annotation Dataset

Separate from the multimodal post dataset (`dataset_metadata.jsonl`).
This catalog holds **legitimate** brand identity used later for logo / brand
detection. Phishing page assets from Zenodo are **not** reference logos.

## Paths

| Kind | Path | Git |
| --- | --- | --- |
| Brand catalog | `data/annotations/brand_catalog.jsonl` | tracked |
| Checklist status | `data/annotations/brand_checklist_status.json` | tracked |
| Logo annotations | `data/annotations/logo_annotations.jsonl` | tracked |
| Logo boxes | `data/annotations/logo_boxes.jsonl` | tracked |
| Brand classes | `data/annotations/brand_classes.json` | tracked |
| Reference logos | `data/reference/brands/` | ignored (`.gitkeep` only) |
| Official screenshots | `data/reference/brand_screenshots/` | ignored (`.gitkeep` only) |

## `brand_catalog.jsonl` (one brand per line)

| Field | Meaning |
| --- | --- |
| `brand_id` | Stable id from Zenodo `identifier` (e.g. `paypal`) |
| `display_name` | Official brand name |
| `aliases` | Extra strings that may appear as `claimed_brand` |
| `official_domain` | e.g. `paypal.com` |
| `official_website` | Official homepage URL |
| `category` | Zenodo category |
| `source` | Provenance of metadata |
| `collection_method` | `public_dataset` \| `manual` \| `research_archive` |
| `reference_images` | Relative paths under `data/reference/brands/` |
| `screenshot_files` | Relative paths under `data/reference/brand_screenshots/` |
| `status` | `metadata_only` until logos exist |

## Linking to posts

Posts keep free-text `brand.claimed_brand`. Match it to `brand_id` / `aliases`
when labelling brand impersonation. Do not fill `detected_brand` until the
detection model exists.

## Logo collection

Run `python scripts/collect_brand_logos.py`. Files land in
`data/reference/brands/{brand_id}_primary.png` (or `.svg`). Sources are
Clearbit / Simple Icons / DuckDuckGo icons / the official site — never Zenodo
phishing assets.

## Official screenshots

Run with Chromium available:

```text
set PLAYWRIGHT_BROWSERS_PATH=%LOCALAPPDATA%\ms-playwright
python scripts/collect_brand_screenshots.py
```

Files land in `data/reference/brand_screenshots/{brand_id}_home.png`. Only
`official_website` URLs from the catalog are opened.

## Normalize + dedupe

Run `python scripts/normalize_brand_logos.py`. Writes
`{brand_id}_normalized.png` (256×256 RGB on white). Near-duplicates need
matching pHash / aHash / dHash / colorHash (or identical SHA-256).

## Logo annotations + boxes

Run `python scripts/annotate_brand_logos.py`.

- `logo_annotations.jsonl`: one class label per normalized logo (`brand_id`).
- `logo_boxes.jsonl`: tight non-white content box with `bbox_xyxy`, `bbox_xywh`,
  and YOLO `bbox_yolo_cxcywh` (values 0–1).
- `brand_classes.json`: ordered class list / `class_to_id` map.

Screenshot pages are linked for context; logo boxes on screenshots are **not**
auto-drawn (manual or detector later).

## Splits + statistics

```text
python scripts/split_brand_dataset.py
python scripts/generate_brand_statistics.py
```

- `brand_splits.jsonl` / `brand_splits.json`: each `brand_id` in exactly one of
  train / val / test (default 70/15/15, seed 42).
- `data/statistics/brand_dataset_statistics.json`: counts from files on disk.

## Rules

- Store only **legitimate** logos and official homepage screenshots.
- Do not copy Zenodo phishing `assets/` into the reference set.
- Do not scrape social networks for logos.
- Do not invent brand counts; generate statistics from the catalog and files.
