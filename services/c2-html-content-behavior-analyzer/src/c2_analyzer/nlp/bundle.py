"""Colab round trip: export-bundle (repo -> Colab) and import-model (Colab -> repo).

Part 6: XLM-R content classification (6A, page level).

Why: fine-tuning XLM-R base needs a GPU (a free Colab T4 does it in minutes; a laptop
CPU would take many hours). The bundle is everything Colab needs and nothing more:

    data/{train,val,test}.jsonl     the page_text examples of the SHARED split
    data/label_mapping.json         Part 4's label encoding
    data/examples_meta.json         dataset version, manifest + split fingerprints,
                                    text schema / rules hash, git commit
    configs/xlmr.yaml               this repo's config + the resolved model_name
    c2_nlp/{tokenizer,model,train}.py   the PORTABLE training code (copied as is)
    run_train.py                    python run_train.py [--seeds ..] [--smoke]
    requirements-colab.txt          transformers & co. pinned to the LOCAL versions
                                    (Colab keeps its own CUDA torch)
    README.txt

No raw HTML, URLs or metadata leave the laptop - only the masked Part 5A page_text.

import-model unpacks the downloaded zip into ``models/xlmr/<version>/`` only if every
model in it was trained on the CURRENT split (fingerprint) with the CURRENT label
mapping; otherwise it refuses (a model of another split would silently be scored on
pages it was trained on). Zip members that would land outside the target are refused.
"""

from __future__ import annotations

import json
import shutil
import zipfile
from importlib import metadata
from pathlib import Path, PurePosixPath

from c2_analyzer.nlp.common import XlmrConfig
from c2_analyzer.nlp.dataset import TextExamples, build_examples, export_examples
from c2_analyzer.nlp.train import LABEL_MAPPING_FILE

PORTABLE_MODULES = ("tokenizer.py", "model.py", "train.py")
COLAB_PACKAGES = ("transformers", "tokenizers", "accelerate", "safetensors", "sentencepiece")
NLP_DIR = Path(__file__).parent

RUN_TRAIN = '''"""Fine-tune XLM-R on this bundle (Part 6A). See README.txt."""

from c2_nlp.train import main

if __name__ == "__main__":
    main()
'''

README = """C2 Part 6A - XLM-R page_text classifier, Colab bundle ({version})

Made by: python scripts/train_xlmr.py export-bundle --version {version}
Split fingerprint: {fingerprint}
Pages: {counts}

  pip install -r requirements-colab.txt
  python run_train.py                     # 3 seeds -> models/xlmr/{version}/
  python run_train.py --smoke             # 1-step pipeline check

Training and the seed selection never use data/test.jsonl; after the final model is
chosen on VAL, every seed writes val + test probabilities (predictions.jsonl) for the
local evaluation.
Zip models/xlmr/{version} and run import-model + evaluate_xlmr.py locally.
"""


class ImportRefused(RuntimeError):
    """The downloaded models do not belong to the current split / label mapping."""


def pinned_requirements() -> str:
    lines = ["# Pinned to the versions of the local .venv (same code reads the model)."]
    for name in COLAB_PACKAGES:
        try:
            lines.append(f"{name}=={metadata.version(name)}")
        except metadata.PackageNotFoundError:
            lines.append(name)
    return "\n".join(lines) + "\n"


def export_bundle(
    version: str,
    config: XlmrConfig | None = None,
    data: TextExamples | None = None,
    out_zip: Path | None = None,
) -> tuple[Path, list[tuple[str, int]]]:
    """Write data/tmp/xlmr_bundle_<version>.zip; returns (path, [(member, bytes)])."""
    config = config or XlmrConfig.load()
    data = data or build_examples(version)
    out_zip = Path(out_zip or config.bundle_dir / f"xlmr_bundle_{version}.zip")
    staging = out_zip.with_suffix("")
    shutil.rmtree(staging, ignore_errors=True)
    export_examples(data, staging / "data", model_name=config.model_name)
    stage_code(staging, config)
    (staging / "README.txt").write_text(
        README.format(
            version=version, fingerprint=data.meta["split_fingerprint"], counts=data.meta["counts"]
        ),
        encoding="utf-8",
    )
    return out_zip, zip_folder(staging, out_zip)


def stage_code(staging: Path, config: XlmrConfig) -> None:
    """configs/xlmr.yaml (+ model_name), c2_nlp/ portable code, run_train.py, requirements."""
    configs = staging / "configs"
    configs.mkdir(parents=True)
    source = config.source.read_text(encoding="utf-8").rstrip()
    (configs / "xlmr.yaml").write_text(
        f"{source}\n\n# added by export-bundle (from .env XLMR_MODEL_NAME)\n"
        f"model_name: {config.model_name}\n",
        encoding="utf-8",
    )
    package = staging / "c2_nlp"
    package.mkdir()
    (package / "__init__.py").write_text(
        '"""Portable copy of c2_analyzer.nlp training code (Part 6A)."""\n', encoding="utf-8"
    )
    for name in PORTABLE_MODULES:
        shutil.copyfile(NLP_DIR / name, package / name)
    (staging / "run_train.py").write_text(RUN_TRAIN, encoding="utf-8")
    (staging / "requirements-colab.txt").write_text(pinned_requirements(), encoding="utf-8")


def zip_folder(staging: Path, out_zip: Path) -> list[tuple[str, int]]:
    """Zip ``staging`` into ``out_zip`` (sorted members), delete staging; [(member, bytes)]."""
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    members = []
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(p for p in staging.rglob("*") if p.is_file()):
            name = path.relative_to(staging).as_posix()
            archive.write(path, name)
            members.append((name, path.stat().st_size))
    shutil.rmtree(staging, ignore_errors=True)
    return members


# ---- import ----------------------------------------------------------------------------------


def _safe_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """Refuse absolute paths, '..', drive letters and symlinks (zip slip)."""
    members = []
    for info in archive.infolist():
        name = PurePosixPath(info.filename.replace("\\", "/"))
        if name.is_absolute() or ".." in name.parts or ":" in info.filename:
            raise ImportRefused(f"unsafe path in zip: {info.filename!r}")
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            raise ImportRefused(f"symlink in zip: {info.filename!r}")
        members.append(info)
    return members


def _model_root(names: list[str]) -> str:
    """The folder inside the zip that holds final/ (zip of models/xlmr/v0.3, v0.3/ or flat)."""
    roots = {n[: -len("final/config.json")] for n in names if n.endswith("final/config.json")}
    if len(roots) != 1:
        raise ImportRefused("the zip must contain exactly one final/ model folder")
    return roots.pop()


def check_imported(folder: Path, data: TextExamples) -> list[str]:
    """Problems of an unpacked model folder vs the current data (empty = OK)."""
    problems = []
    expected = data.label_mapping
    targets = [folder / "final"] + sorted(p for p in folder.glob("seed_*") if p.is_dir())
    for target in targets:
        try:
            metrics = json.loads((target / "metrics.json").read_text(encoding="utf-8"))
            mapping = json.loads((target / LABEL_MAPPING_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            problems.append(f"{target.name}: metrics.json / label_mapping.json missing or broken")
            continue
        if metrics.get("split_fingerprint") != data.meta["split_fingerprint"]:
            problems.append(
                f"{target.name}: split fingerprint {str(metrics.get('split_fingerprint'))[:12]} "
                f"!= current {data.meta['split_fingerprint'][:12]}"
            )
        if metrics.get("dataset_version") != data.version:
            problems.append(f"{target.name}: dataset version {metrics.get('dataset_version')}")
        if (
            mapping.get("classes") != expected["classes"]
            or mapping.get("index") != expected["index"]
        ):
            problems.append(f"{target.name}: label mapping {mapping.get('classes')} differs")
    if not (folder / "final" / "model.safetensors").is_file():
        problems.append("final/model.safetensors is missing")
    return problems


def import_model(
    zip_path: Path,
    version: str,
    config: XlmrConfig | None = None,
    data: TextExamples | None = None,
    target: Path | None = None,
    force: bool = False,
) -> dict:
    """Verify + unpack a Colab zip into models/xlmr/<version>/. Raises ImportRefused."""
    config = config or XlmrConfig.load()
    data = data or build_examples(version)
    target = Path(target or config.models_dir(version))
    if (target / "final").exists() and not force:
        raise ImportRefused(f"{target} already holds a model - pass --force to replace it")
    staging = config.bundle_dir / f"xlmr_import_{version}"
    shutil.rmtree(staging, ignore_errors=True)
    with zipfile.ZipFile(zip_path) as archive:
        members = _safe_members(archive)
        root = _model_root([m.filename.replace("\\", "/") for m in members])
        for info in members:
            name = info.filename.replace("\\", "/")
            if not name.startswith(root) or name.endswith("/"):
                continue
            destination = staging / name[len(root) :]
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, destination.open("wb") as sink:
                shutil.copyfileobj(source, sink, 1 << 20)
    problems = check_imported(staging, data)
    if problems:
        shutil.rmtree(staging, ignore_errors=True)
        raise ImportRefused("refused: " + "; ".join(problems))
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(staging), str(target))
    selection = json.loads((target / "final" / "selection.json").read_text(encoding="utf-8"))
    seeds = sorted(p.name for p in target.glob("seed_*"))
    return {
        "target": str(target),
        "final_seed": selection.get("final_seed"),
        "seeds": seeds,
        "seed_weights": [s for s in seeds if (target / s / "model.safetensors").is_file()],
        "split_fingerprint": data.meta["split_fingerprint"],
    }
