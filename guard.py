#!/usr/bin/env python3
"""Prompt injection guard for OpenClaw web requests."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"safe": 0, "suspicious": 1, "blocked": 2}

DEFAULT_CONFIG = {
    "enabled": True,
    "llm_check": True,
    "telegram_alerts": True,
    "telegram_chat_id": "6819198522",
}


class PromptInjectionGuard:
    def __init__(self, config_path: str = "openclaw.json", patterns_path: str = "patterns.json") -> None:
        self.config_path = Path(config_path)
        self.patterns_path = Path(patterns_path)
        self.config = self._load_config()
        self.patterns = self._load_patterns()
        self.compiled_patterns = [
            {
                "id": p["id"],
                "severity": p["severity"],
                "description": p["description"],
                "regex": re.compile(p["regex"], re.IGNORECASE),
            }
            for p in self.patterns.get("patterns", [])
        ]
        self.max_prompt_length = int(self.patterns.get("max_prompt_length", 2000))
        self.command_keywords = [
            "eval",
            "exec",
            "system(",
            "subprocess",
            "shell",
            "bash",
            "powershell",
            "cmd.exe",
            "os.system",
        ]

    def _load_config(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return dict(DEFAULT_CONFIG)

        with self.config_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        skill_config = (
            data.get("skills", {})
            .get("prompt-injection-guard", {})
        )

        merged = dict(DEFAULT_CONFIG)
        merged.update(skill_config)
        return merged

    def _load_patterns(self) -> dict[str, Any]:
        with self.patterns_path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def analyze(self, request_type: str, request: Any) -> dict[str, Any]:
        if not self.config.get("enabled", True):
            return self._result("safe", "Guard disabled", [])

        payload = self._request_to_text(request)
        findings = []

        layer1 = self._layer1_check(payload)
        findings.extend(layer1["findings"])
        severity = layer1["severity"]

        if self.config.get("llm_check", True) and severity != "blocked":
            layer2 = self._layer2_llm_check(payload, request_type)
            findings.extend(layer2["findings"])
            severity = self._max_severity(severity, layer2["severity"])

        if severity == "suspicious":
            message = "Suspicious request detected; user confirmation required."
            self._send_telegram_alert(request_type, severity, payload, findings)
        elif severity == "blocked":
            message = "Prompt injection attempt blocked."
            self._send_telegram_alert(request_type, severity, payload, findings)
        else:
            message = "Request is safe."

        return self._result(severity, message, findings)

    def _layer1_check(self, payload: str) -> dict[str, Any]:
        findings = []
        severity = "safe"

        if len(payload) > self.max_prompt_length:
            findings.append(
                {
                    "id": "excessive_length",
                    "severity": "suspicious",
                    "description": f"Payload length {len(payload)} exceeds {self.max_prompt_length}.",
                }
            )
            severity = self._max_severity(severity, "suspicious")

        for pattern in self.compiled_patterns:
            if pattern["regex"].search(payload):
                findings.append(
                    {
                        "id": pattern["id"],
                        "severity": pattern["severity"],
                        "description": pattern["description"],
                    }
                )
                severity = self._max_severity(severity, pattern["severity"])

        encoding_findings = self._check_encoded_payloads(payload)
        findings.extend(encoding_findings)
        for finding in encoding_findings:
            severity = self._max_severity(severity, finding["severity"])

        url_findings = self._check_suspicious_urls(payload)
        findings.extend(url_findings)
        for finding in url_findings:
            severity = self._max_severity(severity, finding["severity"])

        return {"severity": severity, "findings": findings}

    def _check_encoded_payloads(self, payload: str) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []
        b64_candidates = re.findall(
            r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
            payload,
        )
        for candidate in b64_candidates:
            decoded = self._safe_b64_decode(candidate)
            if decoded and self._contains_injection_language(decoded):
                findings.append(
                    {
                        "id": "encoded_base64_injection",
                        "severity": "blocked",
                        "description": "Base64 payload decodes to prompt-injection style content.",
                    }
                )

        hex_candidates = re.findall(r"\b(?:[0-9a-fA-F]{2}){16,}\b", payload)
        for candidate in hex_candidates:
            decoded = self._safe_hex_decode(candidate)
            if decoded and self._contains_injection_language(decoded):
                findings.append(
                    {
                        "id": "encoded_hex_injection",
                        "severity": "blocked",
                        "description": "Hex payload decodes to prompt-injection style content.",
                    }
                )

        return findings

    def _check_suspicious_urls(self, payload: str) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []
        urls = re.findall(r"https?://[^\s\"']+", payload, re.IGNORECASE)
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for key, values in params.items():
                joined = f"{key} {' '.join(values)}".lower()
                if any(keyword in joined for keyword in self.command_keywords):
                    findings.append(
                        {
                            "id": "suspicious_url_query",
                            "severity": "blocked",
                            "description": "URL query params contain command-execution style keywords.",
                        }
                    )
                    break
        return findings

    def _layer2_llm_check(self, payload: str, request_type: str) -> dict[str, Any]:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return {"severity": "safe", "findings": []}

        prompt = (
            "Classify this web tool request for prompt injection risk. "
            "Return strict JSON with keys: severity (safe|suspicious|blocked), reason. "
            f"request_type={request_type}\n"
            f"payload={payload[:4000]}"
        )
        body = {
            "model": "gpt-4o-mini",
            "temperature": 0,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a security classifier for prompt injection attempts in web requests. "
                        "Be conservative and escalate only when evidence exists."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
        }
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                response_data = json.loads(resp.read().decode("utf-8"))
            content = response_data["choices"][0]["message"]["content"]
            parsed = self._parse_json_object(content)
            severity = parsed.get("severity", "safe")
            if severity not in SEVERITY_ORDER:
                severity = "safe"
            reason = parsed.get("reason", "No reason provided.")
            if severity == "safe":
                return {"severity": "safe", "findings": []}
            return {
                "severity": severity,
                "findings": [
                    {
                        "id": "llm_semantic_flag",
                        "severity": severity,
                        "description": f"LLM semantic analysis: {reason}",
                    }
                ],
            }
        except Exception:
            return {"severity": "safe", "findings": []}

    def _send_telegram_alert(
        self,
        request_type: str,
        severity: str,
        payload: str,
        findings: list[dict[str, Any]],
    ) -> None:
        if not self.config.get("telegram_alerts", False):
            return

        token = os.getenv("TELEGRAM_BOT_TOKEN")
        chat_id = self.config.get("telegram_chat_id")
        if not token or not chat_id:
            return

        summary = ", ".join(sorted({f["id"] for f in findings})) or "none"
        text = (
            f"[prompt-injection-guard] {severity.upper()} in {request_type}\n"
            f"Findings: {summary}\n"
            f"Payload preview: {payload[:500]}"
        )
        body = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode("utf-8")
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=body,
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=8).read()
        except Exception:
            pass

    @staticmethod
    def _parse_json_object(value: str) -> dict[str, Any]:
        value = value.strip()
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            start = value.find("{")
            end = value.rfind("}")
            if start >= 0 and end > start:
                try:
                    return json.loads(value[start:end + 1])
                except json.JSONDecodeError:
                    return {}
            return {}

    @staticmethod
    def _safe_b64_decode(value: str) -> str | None:
        try:
            decoded = base64.b64decode(value, validate=True)
            text = decoded.decode("utf-8", errors="ignore")
            return text if text else None
        except Exception:
            return None

    @staticmethod
    def _safe_hex_decode(value: str) -> str | None:
        try:
            decoded = bytes.fromhex(value).decode("utf-8", errors="ignore")
            return decoded if decoded else None
        except Exception:
            return None

    @staticmethod
    def _contains_injection_language(value: str) -> bool:
        lowered = value.lower()
        needles = [
            "ignore previous instructions",
            "system:",
            "assistant:",
            "developer:",
            "<|endoftext|>",
        ]
        return any(needle in lowered for needle in needles)

    @staticmethod
    def _request_to_text(request: Any) -> str:
        if isinstance(request, str):
            return request
        if isinstance(request, dict):
            return json.dumps(request, ensure_ascii=False)
        return str(request)

    @staticmethod
    def _result(severity: str, message: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "severity": severity,
            "message": message,
            "findings": findings,
            "allow": severity == "safe",
            "requires_confirmation": severity == "suspicious",
        }

    @staticmethod
    def _max_severity(a: str, b: str) -> str:
        return a if SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] else b


def pre_web_fetch(request: Any) -> dict[str, Any]:
    guard = PromptInjectionGuard()
    return guard.analyze("web_fetch", request)


def pre_web_search(request: Any) -> dict[str, Any]:
    guard = PromptInjectionGuard()
    return guard.analyze("web_search", request)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prompt Injection Guard")
    parser.add_argument("--type", choices=["web_fetch", "web_search"], default="web_fetch")
    parser.add_argument("--payload", help="Raw request payload to inspect.")
    parser.add_argument("--config", default="openclaw.json")
    parser.add_argument("--patterns", default="patterns.json")
    args = parser.parse_args()

    payload = args.payload if args.payload is not None else ""
    guard = PromptInjectionGuard(config_path=args.config, patterns_path=args.patterns)
    result = guard.analyze(args.type, payload)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
