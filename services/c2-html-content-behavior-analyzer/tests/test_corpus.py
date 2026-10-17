"""Tests for Part 5 (Batch B): intent taxonomy, scam-text corpus, review tool, peer kappa.

Part 5: Multilingual scam content analyzer.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from c2_analyzer.content import corpus_builder
from c2_analyzer.content.corpus import (
    CorpusPaths,
    ReviewStore,
    dedup_key,
    freeze_corpus,
    load_corpus,
    make_text_id,
)
from c2_analyzer.content.corpus_builder import build_corpus, clean_text, export_mt_input
from c2_analyzer.content.corpus_review import (
    CorpusReviewSession,
    export_peer_sheet,
    import_peer_sheet,
    parse_intent_choice,
    select_rows,
)
from c2_analyzer.content.corpus_stats import compute_stats, to_markdown
from c2_analyzer.content.language import script_ratios
from c2_analyzer.content.taxonomy import load_taxonomy, parse_taxonomy, weak_label
from c2_analyzer.schemas.content import PageText, PageTextMeta, TextSegment

SERVICE = Path(__file__).parents[1]
VERSION = "v9.9"


def fake_detect(text: str) -> str:
    """Script-based stand-in for Part 5A language ID (tests must not need fastText)."""
    ratios = script_ratios(text)
    return max(("si", "ta"), key=ratios.get) if max(ratios["si"], ratios["ta"]) > 0.5 else "en"


def write_page(text_dir: Path, sample_id: str, segments: list[tuple[str, str]]) -> None:
    page = PageText(
        meta=PageTextMeta(sample_id=sample_id, dataset_version=VERSION),
        segments=[
            TextSegment(
                segment_id=f"s{i:04d}",
                field=field,
                text=text,
                order=i,
                chars=len(text),
                language=fake_detect(text),
            )
            for i, (field, text) in enumerate(segments, start=1)
        ],
    )
    text_dir.mkdir(parents=True, exist_ok=True)
    (text_dir / f"{sample_id}.json").write_text(page.model_dump_json(), encoding="utf-8")


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A tiny dataset: 4 pages in train / val / test + a split + the synthetic templates."""
    monkeypatch.setattr(corpus_builder, "detect", fake_detect)
    paths = CorpusPaths.under(tmp_path)
    paths.corpus_dir.mkdir(parents=True)
    text_dir, splits_root = tmp_path / "text", tmp_path / "splits"
    pages = [
        ("c2_phishing_000001", "phishing", "cl_000001", "train"),
        ("c2_phishing_000002", "phishing", "cl_000001", "train"),  # same cluster as 000001
        ("c2_benign_000001", "benign", "cl_000002", "train"),
        ("c2_phishing_000003", "phishing", "cl_000003", "test"),
        ("c2_crypto_scam_000001", "crypto_scam", "cl_000004", "val"),
    ]
    split = pd.DataFrame(
        [
            {"sample_id": s, "label": lab, "language": "en", "cluster_id": c, "split": sp}
            for s, lab, c, sp in pages
        ]
    )
    (splits_root / VERSION).mkdir(parents=True)
    split.to_csv(splits_root / VERSION / "split.csv", index=False)
    (splits_root / VERSION / "split.json").write_text("{}", encoding="utf-8")

    write_page(
        text_dir,
        "c2_phishing_000001",
        [
            ("title", "Account verification centre"),
            ("cta", "Verify your password now"),
            ("form_label", "Card number"),
            ("heading", "Sign in to continue"),
        ],
    )
    write_page(text_dir, "c2_phishing_000002", [("cta", "Verify your password now")])
    write_page(
        text_dir,
        "c2_benign_000001",
        [
            ("cta", "Verify your account"),
            ("alert_banner", "Your account is suspended. Verify your password within 24 hours."),
            ("heading", "Shared footer heading text"),
        ],
    )
    write_page(
        text_dir,
        "c2_phishing_000003",
        [
            ("heading", "Shared footer heading text"),
            ("alert_banner", "ඔබගේ ගිණුම අත්හිටුවා ඇත. වහාම මුරපදය ඇතුළත් කරන්න."),
        ],
    )
    write_page(
        text_dir,
        "c2_crypto_scam_000001",
        [
            ("heading", "Guaranteed profit every day with our trading bot"),
        ],
    )
    synthetic = pd.DataFrame(
        [
            {
                "text": "You have won a prize! Claim your reward today.",
                "language": "en",
                "intent": "fake_reward",
                "source": "synthetic_template",
                "notes": "",
                "template_group": "tg_001",
            },
            {
                "text": "உங்கள் கணக்கு உடனடியாக முடக்கப்படும். கடவுச்சொல் உள்ளிடவும்.",
                "language": "ta",
                "intent": "credential_request",
                "source": "synthetic_template",
                "notes": "",
                "template_group": "tg_002",
            },
        ]
    )
    synthetic.to_csv(paths.synthetic_texts, index=False, encoding="utf-8-sig")
    return SimpleNamespace(paths=paths, text_dir=text_dir, splits_root=splits_root)


def build(env):
    return build_corpus(
        VERSION, env.paths, text_dir=env.text_dir, splits_root=env.splits_root, seed=42
    )


def row_of(frame: pd.DataFrame, text: str) -> pd.Series:
    rows = frame[frame["text"] == text]
    assert len(rows) == 1, f"{text!r} found {len(rows)} times"
    return rows.iloc[0]


def write_real(paths: CorpusPaths, rows: list[dict]) -> None:
    pd.DataFrame(rows, columns=["text", "language", "intent", "source", "notes"]).to_csv(
        paths.real_texts, index=False, encoding="utf-8-sig"
    )


# ---- taxonomy + weak labelling ----------------------------------------------------------------


def test_taxonomy_is_valid_and_documented():
    taxonomy = load_taxonomy()
    assert taxonomy.ids == [
        "credential_request",
        "payment_request",
        "investment_lure",
        "fake_security_warning",
        "fake_reward",
        "urgency_threat",
        "impersonation",
        "benign",
    ]
    assert taxonomy.priority[-1] == "benign"
    for intent in taxonomy.intents.values():
        assert len(intent.examples) >= 2 and intent.definition and intent.include
        if intent.id != "benign":
            assert all(intent.cues[lang] for lang in ("en", "si", "ta")), intent.id
    guide = (SERVICE / "docs" / "annotation_guide.md").read_text(encoding="utf-8")
    for intent_id in taxonomy.ids:
        assert f"`{intent_id}`" in guide, f"{intent_id} missing from docs/annotation_guide.md"


def test_taxonomy_validation_rejects_bad_files():
    data = {
        "priority": ["benign"],
        "intents": [
            {
                "id": "benign",
                "definition": "x",
                "include": ["a"],
                "exclude": ["b"],
                "examples": ["one"],
                "cues": {},
            }
        ],
    }
    with pytest.raises(ValueError, match="2 English examples"):
        parse_taxonomy(data)
    data["intents"][0]["examples"] = ["one", "two"]
    data["intents"][0]["cues"] = {"en": ["hello"]}
    with pytest.raises(ValueError, match="benign has no cue"):
        parse_taxonomy(data)


WEAK_CASES = [
    ("credential_request", "Please verify your password to keep access."),
    ("credential_request", "ඔබගේ මුරපදය මෙහි ඇතුළත් කරන්න."),
    ("credential_request", "உங்கள் கடவுச்சொல் இங்கே உள்ளிடவும்."),
    ("payment_request", "Your parcel is held. Pay the customs fee to release it."),
    ("payment_request", "පාර්සලය සඳහා බෙදාහැරීමේ ගාස්තු ගෙවන්න."),
    ("payment_request", "பார்சலுக்கு விநியோக கட்டணம் செலுத்தவும்."),
    ("investment_lure", "Guaranteed profit of 5% every day."),
    ("investment_lure", "සෑම දිනකම සහතික ලාභ ලබාගන්න."),
    ("investment_lure", "ஒவ்வொரு நாளும் உத்தரவாத லாபம் பெறுங்கள்."),
    ("fake_security_warning", "Your computer is infected. Call support now."),
    ("fake_security_warning", "ඔබගේ දුරකථනයට වෛරස් ආසාදනය වී ඇත."),
    ("fake_security_warning", "உங்கள் கணினியில் வைரஸ் உள்ளது."),
    ("fake_reward", "Congratulations, you have won a free gift!"),
    ("fake_reward", "ඔබට ලොතරැයි ත්‍යාගයක් හිමි වී ඇත."),
    ("fake_reward", "நீங்கள் பரிசு வென்றுள்ளீர்கள்!"),
    ("urgency_threat", "Your account will be blocked within 24 hours."),
    ("urgency_threat", "ඔබගේ ගිණුම අත්හිටුවා ඇත, වහාම ක්‍රියා කරන්න."),
    ("urgency_threat", "உங்கள் கணக்கு உடனடியாக முடக்கப்படும்."),
    ("impersonation", "Dear customer, this is Sri Lanka Post."),
    ("impersonation", "ශ්‍රී ලංකා තැපැල් සේවයෙන් දැනුම්දීමකි."),
    ("impersonation", "இலங்கை தபால் சேவையின் அறிவிப்பு."),
]


@pytest.mark.parametrize(("intent", "text"), WEAK_CASES)
def test_weak_label_finds_each_intent_in_en_si_ta(intent, text):
    assert intent in weak_label(text).intents


def test_weak_label_rules():
    assert weak_label("Hotpot recipes and more").intents == ["benign"]  # "otp" is a whole word
    assert weak_label("You won't believe this view").intents == ["benign"]
    both = weak_label("Act now: verify your password within 24 hours")
    assert both.primary == "credential_request" and "urgency_threat" in both.intents
    # ZWJ-less spelling of ශ්‍රී still matches the cue written with ZWJ
    assert "impersonation" in weak_label("ශ්රී ලංකා තැපැල් දැනුම්දීම").intents
    benign = weak_label("Verify your account", benign_page=True)
    assert (
        benign.intents == ["benign"]
        and not benign.needs_review
        and benign.cue_intents != ["benign"]
    )
    strong = weak_label("Account suspended - verify your password", benign_page=True)
    assert strong.needs_review and strong.primary == "credential_request"


def test_parse_intent_choice():
    taxonomy = load_taxonomy()
    assert parse_intent_choice("6 1", taxonomy) == ["urgency_threat", "credential_request"]
    assert parse_intent_choice("8 1", taxonomy) is None  # benign cannot be combined
    assert parse_intent_choice("0", taxonomy) is None and parse_intent_choice("x", taxonomy) is None


# ---- the build -------------------------------------------------------------------------------


def test_page_segments_weak_labels_split_and_groups(env):
    frame, info = build(env)
    pages = frame[frame["source_type"] == "page_segment"]
    split = pd.read_csv(env.splits_root / VERSION / "split.csv", dtype=str).set_index("sample_id")
    for row in pages.to_dict("records"):
        sample_id = row["source_ref"].split(":")[0]
        assert row["split"] == split.at[sample_id, "split"]  # never re-split
        assert row["group_id"] == split.at[sample_id, "cluster_id"]
        assert row["is_synthetic"] == "false" and row["page_label"] == split.at[sample_id, "label"]

    cta = row_of(frame, "Verify your password now")  # on 2 pages of one cluster -> 1 row
    assert cta["dup_count"] == "2" and cta["primary_intent"] == "credential_request"
    assert info["sources"]["page_segment"]["duplicates_merged_in_group"] == 1
    assert row_of(frame, "Card number")["primary_intent"] == "credential_request"
    assert row_of(frame, "Sign in to continue")["primary_intent"] == "benign"

    weak_on_benign = row_of(frame, "Verify your account")  # one cue on a benign page
    assert weak_on_benign["intents"] == "benign" and weak_on_benign["needs_review"] == "false"
    strong = row_of(frame, "Your account is suspended. Verify your password within 24 hours.")
    assert strong["primary_intent"] == "credential_request" and strong["needs_review"] == "true"

    sinhala = frame[frame["language"] == "si"].iloc[0]
    assert sinhala["split"] == "test" and sinhala["primary_intent"] == "credential_request"
    assert (env.paths.language_file("si")).exists() and env.paths.corpus_jsonl.exists()


def test_cross_split_duplicate_kept_only_in_held_out_split(env):
    frame, info = build(env)
    shared = frame[frame["text"] == "Shared footer heading text"]
    assert shared["split"].tolist() == ["test"]  # the train copy (benign page) was dropped
    assert info["sources"]["page_segment"]["dropped_duplicate_of_test"] == 1
    assert info["leakage_resolved"] == 1


def test_synthetic_always_train_and_language_checked(env):
    frame, _ = build(env)
    synthetic = frame[frame["source_type"] == "synthetic_template"]
    assert len(synthetic) == 2 and set(synthetic["split"]) == {"train"}
    assert set(synthetic["is_synthetic"]) == {"true"}
    assert set(synthetic["group_id"]) == {"tg_001", "tg_002"}
    tamil = synthetic[synthetic["language_given"] == "ta"].iloc[0]
    assert tamil["language"] == "ta" and tamil["intent_source"] == "given"


def test_machine_translations_train_only_and_no_leakage(env):
    env.paths.mt_dir.mkdir(parents=True)
    train_id = make_text_id("page_segment", "c2_phishing_000001", dedup_key("Card number"))
    test_id = make_text_id(
        "page_segment", "c2_phishing_000003", dedup_key("Shared footer heading text")
    )
    pd.DataFrame(
        [
            {
                "text": "කාඩ්පත් අංකය",
                "language": "si",
                "intent": "credential_request",
                "source_text_id": train_id,
            },
            {
                "text": "பகிரப்பட்ட அடிக்குறிப்பு தலைப்பு",
                "language": "ta",
                "intent": "benign",
                "source_text_id": test_id,
            },
            {
                "text": "இல்லாத வரிசை உரை",
                "language": "ta",
                "intent": "benign",
                "source_text_id": "pg_000000000000",
            },
        ]
    ).to_csv(env.paths.mt_dir / "mt_si.csv", index=False)
    frame, info = build(env)
    mt = frame[frame["source_type"] == "machine_translation"]
    assert mt["text"].tolist() == ["කාඩ්පත් අංකය"]
    assert mt.iloc[0]["split"] == "train" and mt.iloc[0]["is_synthetic"] == "true"
    assert mt.iloc[0]["group_id"] == "cl_000001"  # stays with its source page cluster
    counts = info["sources"]["machine_translation"]
    assert counts["dropped_source_in_val_test"] == 1 and counts["dropped_source_missing"] == 1


def test_missing_real_texts_still_builds(env):
    assert not env.paths.real_texts.exists()
    frame, info = build(env)
    assert info["sources"]["real_message"] == {"file_missing": 1}
    assert not frame.empty and "real_message" not in set(frame["source_type"])


def test_real_messages_pii_masked_grouped_and_stratified(env):
    messages = [
        {
            "text": f"Dear [NAME], you have won Rs. {1000 * (i + 1)} in lucky draw number {i}! "
            "Call 0771234567 or mail winner@example.com https://win.example/c?u=v%40mail.com",
            "language": "en",
            "intent": "fake_reward",
            "source": "sms",
            "notes": "",
        }
        for i in range(3)
    ]  # three copies that differ only in numbers -> one message (near-duplicate)
    messages += [
        {
            "text": f"Message {word}: your parcel is held, pay the customs fee to release it",
            "language": "en",
            "intent": "payment_request",
            "source": "sms",
            "notes": "",
        }
        for word in [
            "alpha",
            "bravo",
            "charlie",
            "delta",
            "echo",
            "foxtrot",
            "golf",
            "hotel",
            "india",
            "juliet",
            "kilo",
            "lima",
            "mike",
            "november",
            "oscar",
            "papa",
            "quebec",
            "romeo",
            "sierra",
            "tango",
        ]
    ]
    messages.append(
        {
            "text": "ඔබට ලොතරැයි ත්‍යාගයක් හිමි වී ඇත",
            "language": "si",
            "intent": "fake_reward;urgency_threat",
            "source": "whatsapp",
            "notes": "",
        }
    )
    messages.append(
        {"text": "bad intent row", "language": "en", "intent": "spam", "source": "", "notes": ""}
    )
    write_real(env.paths, messages)
    frame, info = build(env)
    real = frame[frame["source_type"] == "real_message"]

    reward = real[real["primary_intent"] == "fake_reward"]
    english = reward[reward["language"] == "en"].iloc[0]
    assert "[NAME]" in english["text"] and "[PHONE]" in english["text"]
    assert english["text"].count("[EMAIL]") == 2 and "%40" not in english["text"]
    assert "0771234567" not in english["text"] and "win.example" in english["text"]
    assert english["dup_count"] == "3" and english["group_id"].startswith("rg_")
    assert info["sources"]["real_message"]["skipped_bad_intent"] == 1

    parcel = real[real["primary_intent"] == "payment_request"]
    assert parcel["split"].value_counts().to_dict() == {"train": 14, "val": 3, "test": 3}
    cells = {(c["language"], c["intent"]): c for c in info["real_split_cells"]}
    assert cells[("en", "payment_request")]["status"] == "ok"
    assert cells[("si", "fake_reward")]["status"] == "train_only"  # 1 group: cannot split
    sinhala = real[real["language"] == "si"].iloc[0]
    assert sinhala["intents"] == "fake_reward;urgency_threat" and sinhala["split"] == "train"

    again, _ = build(env)  # same seed -> same split
    assert again.set_index("text_id")["split"].equals(frame.set_index("text_id")["split"])


def test_real_message_language_mismatch_needs_review(env):
    write_real(
        env.paths,
        [
            {
                "text": "This is clearly English text about a prize you have won",
                "language": "ta",
                "intent": "fake_reward",
                "source": "",
                "notes": "",
            }
        ],
    )
    frame, info = build(env)
    row = frame[frame["source_type"] == "real_message"].iloc[0]
    assert row["language"] == "en" and row["language_given"] == "ta"
    assert row["needs_review"] == "true" and "language given ta" in row["notes"]
    assert info["sources"]["real_message"]["language_mismatch"] == 1


def test_clean_text_masks_pii_but_keeps_placeholders():
    text = clean_text(
        "Hi [NAME], card 4111 1111 1111 1111, NIC 199012345678, see "
        "https://x.example/p?e=a%40b.com&lang=si"
    )
    assert "[NAME]" in text and "[CARD]" in text and "[NIC]" in text
    assert "e=[EMAIL]&lang=si" in text and "x.example/p" in text  # encoded email in the URL


# ---- stats ----------------------------------------------------------------------------------


def test_stats_integrity_synthetic_share_and_gap(env):
    build(env)
    stats = compute_stats(env.paths)
    assert stats["integrity"]["passed"]
    share = stats["synthetic_share_per_split"]
    assert share["val"]["synthetic"] == 0 and share["test"]["synthetic"] == 0
    assert share["train"]["synthetic"] == 2
    si = stats["real_text_gap"]["si"]["per_intent"]["credential_request"]
    assert si == {
        "count": 1,
        "by_source": {"page_segment": 1, "real_message": 0},
        "target": 30,
        "gap": 29,
    }
    markdown = to_markdown(stats)
    assert "Integrity checks: PASSED" in markdown and "Verify your password" not in markdown


def test_stats_detects_leakage(env):
    build(env)
    frame = pd.read_csv(env.paths.corpus_csv, dtype=str, keep_default_na=False)
    frame.loc[frame["source_type"] == "synthetic_template", "split"] = "test"
    frame.to_csv(env.paths.corpus_csv, index=False)
    check = compute_stats(env.paths)["integrity"]
    assert not check["passed"] and check["synthetic_rows_in_val_test"] == 2


# ---- review tool, peer agreement, freeze, MT input -------------------------------------------


def scripted(answers: list[str]):
    queue = iter(answers)
    return lambda prompt: next(queue)


def test_review_session_scripted_and_survives_rebuild(env):
    build(env)
    frame = load_corpus(env.paths)
    ids = select_rows(frame, source_type="page_segment", split="train")
    first, second, third = ids[:3]
    store = ReviewStore(env.paths.reviews_csv)
    output: list[str] = []
    session = CorpusReviewSession(
        frame,
        store,
        "tester",
        ids,
        ask=scripted(["c", "i", "6 7", "x", "2", "q"]),
        show=output.append,
    )
    decisions = session.run()
    assert decisions == {
        first: "confirmed",
        second: "intents urgency_threat;impersonation",
        third: "excluded (not_a_message)",
    }
    assert any("[c]onfirm" in line for line in output)

    rebuilt, info = build(env)  # decisions are re-applied after a rebuild
    assert info["reviews_applied"] == 3
    rows = rebuilt.set_index("text_id")
    assert rows.at[first, "verified"] == "true" and rows.at[first, "verified_by"] == "tester"
    assert rows.at[second, "intents"] == "urgency_threat;impersonation"
    assert rows.at[second, "primary_intent"] == "urgency_threat"
    assert rows.at[second, "intent_source"] == "reviewer"
    assert rows.at[third, "excluded"] == "true"
    assert rows.at[third, "exclusion_reason"] == "not_a_message"
    assert first not in select_rows(load_corpus(env.paths))  # only unverified by default
    language_file = pd.read_csv(env.paths.language_file("en"), dtype=str)
    assert third not in set(language_file["text_id"])  # excluded rows are not exported


def test_review_language_change_and_back(env):
    build(env)
    frame = load_corpus(env.paths)
    ids = select_rows(frame, source_type="page_segment")
    store = ReviewStore(env.paths.reviews_csv)
    session = CorpusReviewSession(
        frame,
        store,
        "tester",
        ids,
        ask=scripted(["l", "7", "s", "b", "c", "q"]),
        show=lambda line: None,
    )
    session.run()
    saved = store.get(ids[0])
    assert saved["language"] == "other" and saved["verified"] == "true"


def test_peer_kappa_known_example(tmp_path):
    frame = pd.DataFrame(
        {
            "text_id": ["a", "b", "c", "d"],
            "language": ["en", "en", "si", "si"],
            "primary_intent": ["fake_reward", "fake_reward", "benign", "benign"],
        }
    )
    sheet = pd.DataFrame(
        {
            "text_id": ["a", "b", "c", "d"],
            "peer_primary_intent": ["fake_reward", "benign", "benign", "benign"],
        }
    )
    sheet.to_csv(tmp_path / "sheet.csv", index=False)
    report = import_peer_sheet(frame, tmp_path / "sheet.csv", tmp_path / "out.json")
    # p_o = 3/4, p_e = 0.5*0.25 + 0.5*0.75 = 0.5 -> kappa = (0.75 - 0.5) / 0.5 = 0.5
    assert report["agreement_percent"] == 75.0 and report["cohen_kappa"] == 0.5
    assert report["per_language"]["si"]["agreement_percent"] == 100.0
    assert report["per_language"]["si"]["cohen_kappa"] is None  # one label only: undefined
    assert report["disagreements"] == [
        {"text_id": "b", "language": "en", "my_intent": "fake_reward", "peer_intent": "benign"}
    ]
    assert json.loads((tmp_path / "out.json").read_text())["cohen_kappa"] == 0.5


def test_export_peer_hides_labels_and_samples_per_language(env, tmp_path):
    build(env)
    frame = load_corpus(env.paths)
    with pytest.raises(ValueError, match="No verified"):
        export_peer_sheet(frame, tmp_path / "peer.csv")
    frame["verified"] = "true"
    sheet = export_peer_sheet(frame, tmp_path / "peer.csv", fraction=0.1, seed=42)
    assert set(sheet["language"]) == set(frame["language"])  # at least one per language
    written = pd.read_csv(tmp_path / "peer.csv", dtype=str, encoding="utf-8-sig")
    assert list(written.columns) == [
        "text_id",
        "language",
        "text",
        "peer_primary_intent",
        "peer_intents",
    ]
    assert (tmp_path / "peer.csv").read_bytes().startswith(b"\xef\xbb\xbf")  # BOM for Excel


def test_freeze_refuses_overwrite(env):
    build(env)
    path, info = freeze_corpus(env.paths, "corpus_v1", notes="test")
    manifest = pd.read_csv(path, dtype=str)
    assert "text" not in manifest.columns and len(manifest) == info["rows"]
    assert info["dataset_version"] == VERSION and len(info["fingerprint"]) == 64
    with pytest.raises(FileExistsError):
        freeze_corpus(env.paths, "corpus_v1")
    with pytest.raises(ValueError):
        freeze_corpus(env.paths, "../evil")


def test_export_mt_input_only_english_train_rows(env):
    frame, _ = build(env)
    path, count = export_mt_input(env.paths)
    exported = pd.read_csv(path, dtype=str, keep_default_na=False)
    rows = frame.set_index("text_id").loc[exported["source_text_id"]]
    assert count == len(exported) > 0
    assert set(rows["split"]) == {"train"} and set(rows["language"]) == {"en"}
    assert list(exported.columns) == ["source_text_id", "text", "intent", "source_type"]
    build(env)  # the input file in mt/ is never read back as a translation
    assert "machine_translation" not in set(load_corpus(env.paths)["source_type"])


def test_mt_notebook_is_valid_json():
    notebook = json.loads(
        (SERVICE / "notebooks" / "05_corpus_mt_colab.ipynb").read_text(encoding="utf-8")
    )
    source = "".join("".join(cell["source"]) for cell in notebook["cells"])
    assert "facebook/nllb-200-distilled-600M" in source
    assert "sin_Sinh" in source and "tam_Taml" in source and "source_text_id" in source
