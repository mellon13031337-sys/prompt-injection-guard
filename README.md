# prompt-injection-guard

OpenClaw security skill that validates `web_fetch` and `web_search` requests for prompt injection attempts.

## Files

- `SKILL.md`: skill definition and integration notes.
- `guard.py`: dual-layer validator (regex + LLM semantic check).
- `patterns.json`: configurable detection patterns.
- `tests/test_guard.py`: unit tests for safe/suspicious/blocked behavior.
- `openclaw.json`: sample runtime config.

## Installation

1. Copy this directory into your OpenClaw skills location.
2. Ensure `python3` is available.
3. Set environment variables:
   - `OPENAI_API_KEY` (required when `llm_check=true`)
   - `TELEGRAM_BOT_TOKEN` (required when `telegram_alerts=true`)

## Usage

Run a manual check:

```bash
python3 guard.py --type web_search --payload "search docs for climate policy"
```

Integrate as pre-hooks:

```python
from guard import pre_web_fetch, pre_web_search

fetch_verdict = pre_web_fetch({"url": "https://example.com"})
search_verdict = pre_web_search({"query": "latest security advisories"})
```

Severity handling:

- `safe`: proceed.
- `suspicious`: log + request user confirmation + Telegram alert.
- `blocked`: reject immediately + Telegram alert.

## Config

`openclaw.json`:

```json
{
  "skills": {
    "prompt-injection-guard": {
      "enabled": true,
      "llm_check": true,
      "telegram_alerts": true,
      "telegram_chat_id": "6819198522"
    }
  }
}
```

## Run tests

```bash
python3 -m unittest discover -s tests -v
```
