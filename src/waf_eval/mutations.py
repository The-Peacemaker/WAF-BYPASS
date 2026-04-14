import random
from typing import Callable


MutationFn = Callable[[str], str]


def identity(value: str) -> str:
    return value


def case_flip(value: str) -> str:
    output = []
    for ch in value:
        if ch.isalpha():
            output.append(ch.upper() if random.random() > 0.5 else ch.lower())
        else:
            output.append(ch)
    return "".join(output)


def keyword_fragment(value: str) -> str:
    # Fragments suspicious-looking words into benign separator-delimited chunks.
    replacements = {
        "script": "sc_ri_pt",
        "onerror": "on_er_ror",
        "onload": "on_lo_ad",
        "javascript": "java_script",
        "alert": "al_ert",
    }
    lowered = value.lower()
    for key, replacement in replacements.items():
        lowered = lowered.replace(key, replacement)
    return lowered


def add_noise(value: str) -> str:
    noise_tokens = ["/*SAFE*/", "--SAFE--", "__SAFE__", "[SAFE]"]
    token = random.choice(noise_tokens)
    mid = len(value) // 2
    return f"{value[:mid]}{token}{value[mid:]}"


def separator_shuffle(value: str) -> str:
    chars = list(value)
    separators = [":", ";", "|", " ", "\t"]
    insert_count = max(1, min(3, len(chars) // 8))
    for _ in range(insert_count):
        index = random.randint(1, max(1, len(chars) - 1))
        chars.insert(index, random.choice(separators))
    return "".join(chars)


MUTATIONS: dict[str, MutationFn] = {
    "identity": identity,
    "case_flip": case_flip,
    "keyword_fragment": keyword_fragment,
    "add_noise": add_noise,
    "separator_shuffle": separator_shuffle,
}
