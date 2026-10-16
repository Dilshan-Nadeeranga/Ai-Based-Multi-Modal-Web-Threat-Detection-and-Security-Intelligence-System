"""XLM-R sequence classification model: build, load, predict (task 5).

Part 6: XLM-R content classification (6A, page level). PORTABLE module: copied into
the Colab bundle, so it must not import ``c2_analyzer`` (see ``nlp/__init__.py``).

- ``build_model``: pre-trained encoder + a NEW, randomly initialised classification
  head with one output per threat class; ``id2label`` / ``label2id`` are stored in the
  checkpoint's config.json so the saved model says what its outputs mean.
- ``predict_proba``: fp32, ``torch.no_grad``, batches sorted by length (less padding),
  original order restored. The same function makes the Colab predictions and the
  local CPU ones, so the two can be compared number by number.
- ``build_tiny_model_dir``: a 2-layer, random-init XLM-R encoder with a small Unigram
  (SentencePiece-style) tokenizer trained on the given texts, built entirely in code.
  Used by ``--smoke`` and the tests: no download, runs on CPU in seconds, proves the
  pipeline works and NOTHING about accuracy.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path
from typing import Any

import numpy as np

SPECIAL_TOKENS = ["<s>", "<pad>", "</s>", "<unk>", "<mask>"]  # XLM-R ids 0..4


def build_model(model_name: str, labels: list[str]) -> Any:
    """AutoModelForSequenceClassification with ``len(labels)`` outputs."""
    from transformers import AutoModelForSequenceClassification

    return AutoModelForSequenceClassification.from_pretrained(
        str(model_name),
        num_labels=len(labels),
        id2label=dict(enumerate(labels)),
        label2id={label: i for i, label in enumerate(labels)},
    )


def load_classifier(path: str | Path, device: str = "cpu") -> tuple[Any, Any]:
    """(model in eval mode on ``device``, tokenizer) of a saved checkpoint folder."""
    from transformers import AutoModelForSequenceClassification

    from .tokenizer import load_tokenizer  # drops the false "fix_mistral_regex" warning

    tokenizer = load_tokenizer(str(path))
    model = AutoModelForSequenceClassification.from_pretrained(str(path))
    model.to(device)
    model.eval()
    return model, tokenizer


def predict_proba(
    model: Any,
    tokenizer: Any,
    texts: list[str],
    max_length: int = 512,
    batch_size: int = 8,
    device: str | None = None,
) -> np.ndarray:
    """Softmax probabilities, shape (len(texts), num_labels), rows in input order."""
    import torch

    n_labels = int(model.config.num_labels)
    if not texts:
        return np.zeros((0, n_labels), dtype=np.float64)
    device = device or str(next(model.parameters()).device)
    lengths = [len(text) for text in texts]
    order = np.argsort(lengths, kind="stable")
    out = np.zeros((len(texts), n_labels), dtype=np.float64)
    model.eval()
    with torch.no_grad():
        for start in range(0, len(texts), batch_size):
            index = order[start : start + batch_size]
            batch = tokenizer(
                [texts[i] for i in index],
                truncation=True,
                max_length=max_length,
                padding=True,
                return_tensors="pt",
            ).to(device)
            logits = model(**batch).logits.float()
            out[index] = torch.softmax(logits, dim=-1).cpu().numpy()
    return out


def build_tiny_model_dir(
    path: str | Path,
    texts: list[str],
    labels: list[str] | None = None,
    vocab_size: int = 300,
    seed: int = 0,
) -> Path:
    """Save a tiny random-init XLM-R encoder + tokenizer to ``path`` (offline).

    ``labels`` is accepted for symmetry with build_model; the head is added there."""
    import torch
    from tokenizers import Tokenizer, decoders, normalizers, pre_tokenizers, processors, trainers
    from tokenizers import models as tok_models
    from transformers import XLMRobertaConfig, XLMRobertaModel, XLMRobertaTokenizerFast

    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    corpus = [text for text in texts if text.strip()] or ["empty page"]
    # Unigram needs every character of the corpus in the vocabulary (Sinhala, Tamil,
    # CJK ... pages bring hundreds), so the vocabulary grows with the alphabet.
    alphabet = {char for text in corpus for char in unicodedata.normalize("NFKC", text)}
    vocab_size = max(vocab_size, len(alphabet) + len(SPECIAL_TOKENS) + 100)
    tokenizer = Tokenizer(tok_models.Unigram())
    tokenizer.normalizer = normalizers.NFKC()
    tokenizer.pre_tokenizer = pre_tokenizers.Metaspace()
    tokenizer.decoder = decoders.Metaspace()
    tokenizer.train_from_iterator(
        corpus,
        trainers.UnigramTrainer(
            vocab_size=vocab_size, special_tokens=SPECIAL_TOKENS, unk_token="<unk>"
        ),
    )
    bos, eos = tokenizer.token_to_id("<s>"), tokenizer.token_to_id("</s>")
    tokenizer.post_processor = processors.TemplateProcessing(
        single="<s> $A </s>",
        pair="<s> $A </s> </s> $B </s>",
        special_tokens=[("<s>", bos), ("</s>", eos)],
    )
    fast = XLMRobertaTokenizerFast(
        tokenizer_object=tokenizer,
        bos_token="<s>",
        eos_token="</s>",
        sep_token="</s>",
        cls_token="<s>",
        unk_token="<unk>",
        pad_token="<pad>",
        mask_token="<mask>",
        model_max_length=512,
    )
    torch.manual_seed(seed)
    config = XLMRobertaConfig(
        vocab_size=tokenizer.get_vocab_size(),
        hidden_size=32,
        num_hidden_layers=2,
        num_attention_heads=2,
        intermediate_size=64,
        max_position_embeddings=514,  # 512 tokens + XLM-R's padding offset of 2
        pad_token_id=SPECIAL_TOKENS.index("<pad>"),
        bos_token_id=bos,
        eos_token_id=eos,
    )
    # encoder only, like the hub checkpoint: build_model then adds a NEW head per seed
    XLMRobertaModel(config, add_pooling_layer=False).save_pretrained(path)
    fast.save_pretrained(path)
    return path
