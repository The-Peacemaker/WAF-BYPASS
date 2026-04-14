# WAF-BYPASS (Defensive Security Validation Framework)

A professional, ethical framework for validating how well WAF rules and application input filters detect and block **safe, non-executing XSS-like test patterns**.

This project is designed for secure coding teams, AppSec engineers, and blue teams who want measurable evidence of filter quality.

## Ethical Scope

- This framework intentionally uses only harmless markers such as `TEST_XSS_MARKER`.
- It does **not** ship exploit payloads.
- Use only in authorized environments.

## Why This Exists

WAF and filter logic often fails in predictable ways:

- Single-pass decoding misses nested or multi-stage encodings.
- Case-sensitive or rigid regex rules miss mutated patterns.
- Blacklists focus on tokens, not output context.
- Input filtering is used as a primary control instead of contextual output encoding.

The framework helps teams detect these gaps quickly and consistently.

## How WAFs Detect XSS-Like Patterns (Practical View)

1. Pattern matching
   Rule engines inspect raw or normalized inputs for suspicious markers/tokens.
2. Encoding checks
   Better systems decode URL/HTML entities before evaluating signatures.
3. Context awareness
   Mature defenses map data flow into HTML, attribute, JavaScript, URL, and DOM contexts.
4. Behavioral and anomaly logic
   Some engines score unusual structure, entropy, or token mixing rather than exact signatures.

## Common Weaknesses in Character-Based Filtering

- Blocklist-only regex with no canonicalization pipeline.
- Inconsistent decoding order between edge WAF and app layer.
- Token checks without grammar awareness.
- No distinction between inbound filtering and outbound encoding.

## Architecture

- `src/waf_eval/patterns.py`
  Safe corpus and category definitions.
- `src/waf_eval/encoders.py`
  URL, double-URL, HTML, Unicode, and safe base64 marker wrapping.
- `src/waf_eval/mutations.py`
  Case flips, fragmentation, separators, and safe noise insertion.
- `src/waf_eval/generator.py`
  Exhaustive and fuzzing generation modes.
- `src/waf_eval/reporting.py`
  Strength scoring, weighted exposure, recommendations, CSV/JSON report writing.
- `src/waf_eval/cli.py`
  CLI workflow that generates patterns, sends tests, and writes reports.
- `lab/app.py`, `lab/waf.py`
  Local Flask test target and intentionally weak regex WAF simulation.

## Features

- Safe pattern generation at scale (hundreds+ variants).
- Multi-encoding and mutation simulation.
- Fuzzing mode for randomized corpus expansion.
- JSON + CSV output.
- Scoring model for filter strength.
- Actionable remediation recommendations.
- CI workflow with tests.

## Setup

```bash
python -m venv .venv
. .venv/Scripts/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Running the Local Lab

```bash
cd lab
python app.py
```

Lab endpoint: `http://127.0.0.1:5000/submit`

## Running the Framework

From project root:

```bash
$env:PYTHONPATH="src"
python run_framework.py --mode fuzz --count 400 --target http://127.0.0.1:5000/submit
```

Exhaustive mode:

```bash
$env:PYTHONPATH="src"
python run_framework.py --mode exhaustive --count 600
```

## Example Output (Summary)

```json
{
  "total": 400,
  "blocked": 276,
  "allowed": 124,
  "block_rate": 0.69,
  "weighted_exposure": 0.41,
  "strength_score": 59.0
}
```

Interpretation:

- High `allowed` count means weak signature coverage or poor normalization.
- High `weighted_exposure` means higher-risk categories pass too often.
- `strength_score` near 100 indicates stronger defensive performance.

## Report Artifacts

- `reports/results.json`
- `reports/results.csv`

JSON includes:

- Summary metrics
- Per-input evaluation records
- Recommendations

## Testing Workflow

1. Start local lab.
2. Run framework in `fuzz` mode.
3. Inspect summary and allowed rows.
4. Tighten WAF normalization and rule logic.
5. Re-run and compare score changes.

## Security Recommendations

- Normalize inputs with multi-pass decoding limits and strict safeguards.
- Use allowlists and structured parsing where possible.
- Enforce context-specific output encoding by default.
- Treat WAF as detection/mitigation layer, not sole protection.
- Add CI gates for regression on filter coverage metrics.

## CI/CD Integration Ideas

- Run this tool in staging against instrumented test endpoints.
- Fail pipeline when `strength_score` falls below policy threshold.
- Track trend of `weighted_exposure` over time.

## Screenshots To Capture (for GitHub)

- Terminal run showing generation + summary metrics.
- Snippet of `results.json` recommendations section.
- Lab response examples for blocked vs allowed test strings.

## Disclaimer

This repository is for defensive security validation and secure coding improvement only. Do not use it against systems without explicit authorization.
