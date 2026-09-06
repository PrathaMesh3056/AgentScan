# agentscan/core/semantic.py
#
# Embedding-based semantic similarity for detection logic.
#
# The v0.1 prompt-injection detector judged "did the model comply?" with word
# overlap and difflib — which misses paraphrase ("I'll disregard those rules"
# vs. "confirms ignoring safety guidelines") and is fooled by shared stopwords.
# This module replaces that with real sentence embeddings: two texts are similar
# when their MiniLM vectors point the same way (high cosine), regardless of
# surface wording.
#
# Model: sentence-transformers/all-MiniLM-L6-v2 — 22M params, ~87 MB, CPU-fast.

from __future__ import annotations

from functools import lru_cache
from typing import Any

from loguru import logger

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


@lru_cache(maxsize=1)
def _load_model() -> Any:
    """Lazy loader for the MiniLM encoder, cached once per process."""
    from sentence_transformers import SentenceTransformer

    logger.debug(f"Loading sentence-transformer model {MODEL_NAME}")
    return SentenceTransformer(MODEL_NAME)


def embedding_similarity(text_a: str, text_b: str) -> float:
    """
    Cosine similarity of the two texts' MiniLM sentence embeddings.

    Returns a float in [-1.0, 1.0]; ~1.0 = near-identical meaning, ~0.0 = unrelated.
    Embeddings are L2-normalised, so the dot product is the cosine directly.
    """
    model = _load_model()
    embeddings = model.encode(
        [text_a, text_b],
        convert_to_numpy=True,
        normalize_embeddings=True,
    )
    return float(embeddings[0] @ embeddings[1])
