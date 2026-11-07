from __future__ import annotations

import base64
import secrets
import string
from urllib.parse import quote, quote_plus

from .models import Placeholder

_BASE62 = string.ascii_letters + string.digits


def generate(binding_id: str) -> str:
    suffix = "".join(secrets.choice(_BASE62) for _ in range(24))
    return f"lgph_{binding_id}_{suffix}"


def encoded_variants(value: str) -> set[str]:
    raw = value.encode()
    variants = {value, value.encode().hex(), quote(value, safe=""), quote_plus(value)}

    # Include all three possible base64 stream alignments. The prefixed forms
    # let a scanner recognize a placeholder embedded after 0, 1, or 2 bytes.
    for prefix_length in range(3):
        aligned = (b"A" * prefix_length) + raw
        standard = base64.b64encode(aligned).decode()
        urlsafe = base64.urlsafe_b64encode(aligned).decode()
        variants.update(
            {
                standard,
                standard.rstrip("="),
                urlsafe,
                urlsafe.rstrip("="),
            }
        )
    return {variant for variant in variants if variant}


def create(binding_id: str) -> Placeholder:
    value = generate(binding_id)
    return Placeholder(
        binding_id=binding_id,
        value=value,
        variants=encoded_variants(value),
    )


generate_placeholder = generate
