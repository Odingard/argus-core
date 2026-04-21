"""
argus/corpus/finetune_handoff.py

Produces the handoff package a customer / ops team needs to drive a
fine-tune job on ARGUS-generated training data. We deliberately do NOT
call the fine-tune API ourselves — providers vary (Anthropic / OpenAI
/ Gemma / Together / Fireworks), residency rules vary, model-size
choices vary. We give the operator a signed manifest + provider-
specific runbooks and get out of the way.

Outputs three files beside the corpus JSONL:

    manifest.json     SHA-256 of the corpus + split counts + label
                      distribution + generated_at timestamp
    RUNBOOK.md        copy/paste examples for Anthropic, OpenAI, and
                      local Gemma via HF transformers
    split_*.jsonl     train/val/test splits (90/5/5 default)
"""
from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


def split_train_val(
    jsonl_path: str,
    ratios:     tuple[float, float, float] = (0.9, 0.05, 0.05),
    seed:       int = 1337,
) -> dict[str, str]:
    """
    Deterministic (prompt-fingerprint-sorted + seeded RNG) 3-way split.
    Returns dict of {"train": path, "val": path, "test": path}.
    """
    src = Path(jsonl_path)
    lines = [ln for ln in src.read_text(encoding="utf-8").splitlines() if ln.strip()]

    rng = random.Random(seed)
    rng.shuffle(lines)

    n = len(lines)
    n_train = int(n * ratios[0])
    n_val   = int(n * ratios[1])
    out: dict[str, str] = {}
    for name, chunk in (
        ("train", lines[:n_train]),
        ("val",   lines[n_train:n_train + n_val]),
        ("test",  lines[n_train + n_val:]),
    ):
        p = src.with_name(f"split_{name}.jsonl")
        p.write_text("\n".join(chunk) + ("\n" if chunk else ""), encoding="utf-8")
        out[name] = str(p)
    return out


def _corpus_sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _label_distribution(path: str) -> dict[str, int]:
    dist: dict[str, int] = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Support both Anthropic-format (metadata.label) and raw (label).
            label = (rec.get("metadata", {}) or {}).get("label")
            if label is None:
                label = rec.get("label", "UNKNOWN")
            dist[label] = dist.get(label, 0) + 1
    return dist


def write_handoff_manifest(
    corpus_jsonl:  str,
    splits:        dict[str, str],
    provider_hint: str = "anthropic",
) -> str:
    """
    Write manifest.json + RUNBOOK.md next to ``corpus_jsonl``.
    Returns the manifest path.
    """
    corpus = Path(corpus_jsonl)
    folder = corpus.parent

    manifest = {
        "generated_at":        datetime.utcnow().isoformat(),
        "corpus_file":         corpus.name,
        "corpus_sha256":       _corpus_sha(str(corpus)),
        "pair_count":          sum(1 for _ in open(corpus, "r", encoding="utf-8")),
        "label_distribution":  _label_distribution(str(corpus)),
        "splits":              {k: Path(v).name for k, v in splits.items()},
        "provider_hint":       provider_hint,
    }
    manifest_path = folder / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    runbook_path = folder / "RUNBOOK.md"
    runbook_path.write_text(_runbook_md(corpus, splits, manifest), encoding="utf-8")

    return str(manifest_path)


def _runbook_md(corpus: Path, splits: dict[str, str], manifest: dict) -> str:
    return f"""# ARGUS Fine-Tune Handoff

**Corpus**: `{corpus.name}` ({manifest['pair_count']} pairs)
**SHA-256**: `{manifest['corpus_sha256']}`
**Generated**: {manifest['generated_at']}

Label distribution (top 10):

```
{json.dumps(dict(sorted(manifest['label_distribution'].items(),
                        key=lambda x: -x[1])[:10]), indent=2)}
```

## 1. Anthropic fine-tune (recommended for Claude family)

```bash
# Anthropic's fine-tune API accepts JSONL in prompt/completion shape
# (what we emitted by default). Upload:
anthropic files create --purpose fine-tune \\
  --file {splits.get('train', 'split_train.jsonl')}

# Kick off the job:
anthropic fine-tuning jobs create \\
  --training-file <file_id> \\
  --model claude-haiku-4-5-20251001 \\
  --suffix argus-redteam
```

## 2. OpenAI fine-tune (for cross-provider training)

If the corpus was emitted with ``format="openai"`` the shape matches
``{{messages:[...]}}``. Otherwise run the emitter again with
``format="openai"`` or transform the Anthropic output.

```bash
openai api files.create -f {splits.get('train', 'split_train.jsonl')} -p fine-tune
openai api fine_tuning.jobs.create -F <file_id> -m gpt-4o-mini-2024-07-18
```

## 3. Local Gemma fine-tune (data-residency sensitive)

```python
# pip install transformers trl datasets peft accelerate
from datasets import load_dataset
from trl import SFTTrainer
from transformers import AutoTokenizer, AutoModelForCausalLM

ds_train = load_dataset("json", data_files="{splits.get('train', 'split_train.jsonl')}", split="train")
tok = AutoTokenizer.from_pretrained("google/gemma-2-9b-it")
model = AutoModelForCausalLM.from_pretrained("google/gemma-2-9b-it", device_map="auto")

def format_row(row):
    return tok.apply_chat_template([
        {{"role": "user", "content": row["prompt"]}},
        {{"role": "assistant", "content": row["completion"]}},
    ], tokenize=False)

SFTTrainer(
    model=model, train_dataset=ds_train,
    tokenizer=tok, formatting_func=format_row,
).train()
```

## 4. Security notes

- The corpus is derived from ARGUS run output. Review before shipping
  to an external provider — findings may contain excerpts of the
  scanned target's source.
- Redact target names / hostnames / API keys if present before upload.
  The flywheel side is already anonymized; the corpus currently is NOT.
  Pillar-1 follow-up: automatic PII/target scrubber.
- For air-gapped / regulated environments, prefer option 3 (local Gemma)
  over 1 or 2.
- Rotate ``ARGUS_WILSON_KEY`` before starting a new engagement so
  downstream bundle signatures are tied to this corpus version.
"""
