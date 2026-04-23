# argus-redteam — DEPRECATED

> **This package has been renamed to [`argus-core`](https://pypi.org/project/argus-core/).**
> This `0.4.1` release is a compatibility shim — installing it pulls
> `argus-core` so existing `requirements.txt` and `pip install argus-redteam`
> commands keep working without code changes.

## What to do

Replace `argus-redteam` with `argus-core` in your dependency pins at your
convenience:

```diff
- argus-redteam
+ argus-core
```

The Python import path did **not** change:

```python
import argus
from argus.adapter import MCPAdapter
```

…still works identically under either package name.

## Why the rename

ARGUS is now open-core:

- **`argus-core`** — MIT-licensed, the OSS Autonomous AI Red Team
  Platform (all 12 offensive agents, coordinated swarm runtime, harness,
  Wilson forensic bundles, sandboxed engagements).
- **`argus-pro`** — commercial source-available tier for MCTS exploit-
  chain planning, multi-model consensus for CRITICAL findings, L7 pcap,
  and fleet-scale webhook infrastructure.

`argus-redteam` predated the core/pro split and is retained only for
install-path compatibility.

## Links

- **Replacement package:** https://pypi.org/project/argus-core/
- **Source code + docs:** https://github.com/Odingard/argus-core
- **Responsible-disclosure contact:** security@sixsenseenterprise.com

Last maintained release: `0.4.0` (source-complete). `0.4.1` (this) is
meta-only.
