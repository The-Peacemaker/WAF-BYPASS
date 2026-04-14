from __future__ import annotations

import itertools
import random
from dataclasses import dataclass

from .encoders import ENCODERS
from .mutations import MUTATIONS
from .patterns import SAFE_BASE_PATTERNS


@dataclass(slots=True)
class GeneratedPattern:
    raw: str
    mutated: str
    encoded: str
    mutation: str
    encoder: str


class SafePatternGenerator:
    def __init__(
        self,
        seed: int | None = None,
        encoders: list[str] | None = None,
        mutations: list[str] | None = None,
    ) -> None:
        self.random = random.Random(seed)
        self.encoders = encoders or list(ENCODERS.keys())
        self.mutations = mutations or list(MUTATIONS.keys())

    def _apply(self, value: str, mutation_name: str, encoder_name: str) -> GeneratedPattern:
        mutated = MUTATIONS[mutation_name](value)
        encoded = ENCODERS[encoder_name](mutated)
        return GeneratedPattern(
            raw=value,
            mutated=mutated,
            encoded=encoded,
            mutation=mutation_name,
            encoder=encoder_name,
        )

    def generate_exhaustive(self, limit: int = 500) -> list[GeneratedPattern]:
        combinations = itertools.product(SAFE_BASE_PATTERNS, self.mutations, self.encoders)
        results: list[GeneratedPattern] = []
        for raw, mutation, encoder in combinations:
            results.append(self._apply(raw, mutation, encoder))
            if len(results) >= limit:
                break
        return results

    def generate_fuzzed(self, count: int = 250) -> list[GeneratedPattern]:
        results: list[GeneratedPattern] = []
        for _ in range(count):
            raw = self.random.choice(SAFE_BASE_PATTERNS)
            mutation = self.random.choice(self.mutations)
            encoder = self.random.choice(self.encoders)
            generated = self._apply(raw, mutation, encoder)

            # Layer an additional random pass to mimic multi-stage obfuscation behavior safely.
            if self.random.random() > 0.5:
                extra_mutation = self.random.choice(self.mutations)
                generated = self._apply(generated.encoded, extra_mutation, "identity")
            results.append(generated)
        return results
