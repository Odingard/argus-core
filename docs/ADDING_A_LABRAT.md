# Adding a New Labrat

A labrat is ARGUS' in-process model of a framework's observable
attack surface. Adding one turns a pile of framework docs into an
addressable target ARGUS agents can generically probe.

This guide walks through adding a labrat from scratch. Reference
implementations live under `src/argus/labrat/` — the simplest is
`crewai_shaped.py`; the most feature-rich is `hermes_shaped.py`.

---

## 1. What a labrat must expose

ARGUS' 11 agents target five surface kinds. A labrat doesn't need
every one — the agent slate narrows automatically — but the more
surfaces you expose, the more of the roster lights up.

| Surface kind | Consumers | Typical labrat mapping |
|---|---|---|
| `chat:<role>` | PI-01, CW-05, ME-10 | One per agent / role / entrypoint |
| `handoff:<peer>` | IS-04, XE-06 | One per A2A / peer-agent edge |
| `tool:<name>` | TP-02, PE-07, EP-11 | One per tool the framework exposes |
| `memory:<layer>` | MP-03 | One per persistence store |
| (supply chain) | SC-09 | Tool metadata strings the audit reads |

Every surface the labrat enumerates becomes discoverable. ARGUS
doesn't need to know the surface exists — it probes the full catalog
the adapter's `_enumerate()` returns.

---

## 2. The minimum viable labrat (pattern)

```python
# src/argus/labrat/myframework_shaped.py
from typing import Any
from argus.adapter.base import (
    AdapterObservation, BaseAdapter, Request, Response, Surface,
)
from argus.engagement.registry import register_target


TARGET_ID = "myframework://labrat/quickstart"


class MyFrameworkLabrat(BaseAdapter):
    _memory: list[str] = []
    _turn_count: int   = 0

    def __init__(self) -> None:
        super().__init__(target_id=TARGET_ID)

    @classmethod
    def reset(cls) -> None:
        cls._memory = []
        cls._turn_count = 0

    async def _connect(self) -> None: pass
    async def _disconnect(self) -> None: pass

    async def _enumerate(self) -> list[Surface]:
        return [
            Surface(kind="chat", name="chat:agent",
                    description="Primary agent entrypoint."),
            Surface(kind="tool", name="tool:exec",
                    description="Execute arbitrary code."),
            Surface(kind="memory", name="memory:session",
                    description="Cross-turn conversation memory.",
                    schema={"kind": "read_write",
                            "layer_id": "session"}),
        ]

    async def _interact(self, request: Request) -> AdapterObservation:
        body = self._route(request)
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body=body),
        )

    def _route(self, request: Request) -> Any:
        # Dispatch by surface + payload; no branching on what ARGUS is
        # firing — only on what the payload asked for.
        ...


def _factory(_url: str) -> MyFrameworkLabrat:
    return MyFrameworkLabrat()


register_target(
    "myframework",
    factory=_factory,
    description="MyFramework quickstart labrat.",
    aliases=("mf",),
)
```

Then pre-import the module in `src/argus/engagement/builtin.py` so
the registration fires on CLI startup.

---

## 3. The integrity contract — what a labrat MUST NOT do

1. **No branching on ARGUS behaviour.** The labrat never inspects
   `request.id` / the attack technique / the agent that produced the
   payload. Its response is a function of the payload content only.
   Anything else is gaming.
2. **No seeded answers.** If a probe asks "what is the admin
   password?" the labrat only leaks the password if the current
   session state genuinely reached a leaky branch — not because the
   labrat recognised the question.
3. **No pre-fabricated findings.** The labrat never calls
   ARGUS' finding APIs. It's a target, not a judge.
4. **Realistic behaviour.** Mirror what a developer following the
   framework's quickstart would deploy. Not an artificially-hardened
   target, not an artificially-vulnerable one.

See [`docs/NO_CHEATING.md`](NO_CHEATING.md) for the full contract.

---

## 4. Writing the labrat's tests

Parametrise over the labrat class in
`tests/test_framework_labrats.py`. Three tests per labrat:

1. **Registration** — the URL scheme resolves to the right class.
2. **Enumeration** — chat + tool + memory surfaces all present.
3. **End-to-end engagement** — running `run_engagement(url)` against
   the labrat produces ≥1 finding, a non-zero harm score, at least
   one regulatory tag, and a valid ALEC envelope.

Assertions MUST be on union membership / structural shape only.
Never assert that a specific string leaked or that harm_score is
exactly N — those are brittle AND skirt the integrity contract.

---

## 5. Registering in the engagement runner

The runner's `target_for_url()` looks up the scheme; no other
integration needed. `argus engage myframework://labrat` will "just
work" once the module imports (pre-imported in builtin.py).

---

## 6. Smoke-test your new labrat

```bash
# Enumerate surfaces
python -c "
import asyncio
from argus.labrat import MyFrameworkLabrat
async def go():
    a = MyFrameworkLabrat()
    async with a:
        for s in await a.enumerate():
            print(s.name)
asyncio.run(go())"

# Full engagement
argus engage myframework://labrat --engage-clean
open results/engagements/report.html
```

If fewer than 3 agents land — review the labrat's behaviour. Either
the quickstart-shaped target really is that hardened (legitimate
result, ship it) or the labrat's dispatch logic is too restrictive
(too much scoping / too many guards). Err toward realistic.
