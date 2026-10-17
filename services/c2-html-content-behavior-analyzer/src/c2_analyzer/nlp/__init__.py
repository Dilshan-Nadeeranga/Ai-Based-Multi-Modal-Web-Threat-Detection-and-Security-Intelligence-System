"""XLM-RoBERTa content classification.

Part 6: XLM-R content classification. Part 6A (implemented) = PAGE-LEVEL threat
classification from Part 5A ``page_text``; Part 6B (intent-level, on the scam-text
corpus) is postponed until the corpus has enough real scam texts.

Two kinds of modules live here:
- PORTABLE (``tokenizer``, ``model``, ``train``): only torch / transformers / numpy /
  scikit-learn / yaml and relative imports, never ``c2_analyzer``. export-bundle copies
  them into the Colab bundle as the package ``c2_nlp`` (tests check the rule).
- REPO-SIDE (``common``, ``dataset``, ``bundle``, ``metrics``, ``evaluate``,
  ``inference``, ``text_baseline``): read the frozen dataset, the shared split and the
  Part 5A text, evaluate, serve.
"""
