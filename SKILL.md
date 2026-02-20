---
name: prompt-injection-guard
description: Validates web requests for prompt injection attempts. Use when handling `web_fetch` and `web_search` calls that may contain malicious prompt instructions, encoded payloads, role-switching tokens, or command-injection style URLs.
metadata:
  openclaw:
    emoji: 🛡️
    requires:
      bins: [python3]
---

# Prompt Injection Guard

Use `guard.py` as a pre-hook validator before executing `web_fetch` or `web_search`.

## Pre-hook integration

Configure pre-hooks so requests are validated first:

```python
from guard import pre_web_fetch, pre_web_search

def web_fetch_with_guard(request):
    verdict = pre_web_fetch(request)
    if verdict["severity"] == "blocked":
        raise ValueError(verdict["message"])
    if verdict["severity"] == "suspicious":
        # Ask user for explicit confirmation before proceeding.
        return verdict
    return run_web_fetch(request)

def web_search_with_guard(request):
    verdict = pre_web_search(request)
    if verdict["severity"] == "blocked":
        raise ValueError(verdict["message"])
    if verdict["severity"] == "suspicious":
        # Ask user for explicit confirmation before proceeding.
        return verdict
    return run_web_search(request)
```

## Severity behavior

- `safe`: pass through request.
- `suspicious`: log event, send Telegram alert, require user confirmation.
- `blocked`: reject request and alert user immediately on Telegram.

## Detection model

Run dual-layer validation:

1. Layer 1 (regex + heuristics): fast pattern checks from `patterns.json`.
2. Layer 2 (LLM): semantic classification via `gpt-4o-mini` when enabled.

## Runtime requirements

- Read config from `openclaw.json` under `skills.prompt-injection-guard`.
- Set `OPENAI_API_KEY` when `llm_check` is enabled.
- Set `TELEGRAM_BOT_TOKEN` when `telegram_alerts` is enabled.
