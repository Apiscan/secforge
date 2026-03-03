"""
AI Triage — Anthropic-powered finding analysis.

Adds three layers of intelligence on top of raw scanner findings:
1. False positive detection — flags likely scanner artifacts
2. Prioritization — ranks findings by real-world exploitability
3. Executive summary — plain-language overview for non-technical stakeholders

Requires ANTHROPIC_API_KEY or SECFORGE_AI_KEY env var.
Uses the cheapest capable model (claude-haiku) by default to keep costs low.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from secforge.models.finding import Finding
from secforge.models.enums import Severity, FindingStatus
from secforge.core.reporter import ScanResult


DEFAULT_MODEL = "claude-haiku-4-5"
MAX_FINDINGS_FOR_TRIAGE = 30  # Don't burn tokens on huge finding sets


def get_api_key() -> Optional[str]:
    return os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("SECFORGE_AI_KEY")


async def triage_findings(result: ScanResult, model: str = DEFAULT_MODEL) -> "TriageResult":
    """
    Run AI triage on scan findings. Returns enriched findings + executive summary.
    Falls back gracefully if no API key is present.
    """
    api_key = get_api_key()
    if not api_key:
        return TriageResult(
            findings=result.findings,
            executive_summary=None,
            skipped=True,
            skip_reason="No API key (set ANTHROPIC_API_KEY or SECFORGE_AI_KEY)",
        )

    try:
        import anthropic
    except ImportError:
        return TriageResult(
            findings=result.findings,
            executive_summary=None,
            skipped=True,
            skip_reason="anthropic package not installed (pip install anthropic)",
        )

    client = anthropic.AsyncAnthropic(api_key=api_key)

    findings_to_triage = result.findings[:MAX_FINDINGS_FOR_TRIAGE]

    # Build the triage prompt
    findings_text = _format_findings_for_prompt(findings_to_triage)

    prompt = f"""You are a senior application security engineer reviewing automated API security scan results.

Target: {result.target.url} ({result.target.name or 'unnamed'})
Scan Date: {result.timestamp[:10]}
Total Findings: {len(result.findings)}

## Raw Findings

{findings_text}

## Your Tasks

1. **False Positive Analysis**: Identify any findings that are likely false positives given the context. 
   Be specific — explain WHY each flagged finding might be a false positive.

2. **Risk Prioritization**: Rank the TOP 3 most critical findings by real-world exploitability 
   (not just severity label). Consider: Is it actually exploitable? Does it require auth? 
   What's the blast radius?

3. **Executive Summary**: Write a 3-5 sentence plain-language summary suitable for a 
   non-technical stakeholder (CTO/CEO). No jargon. Focus on business risk.

Respond in this exact JSON format:
{{
  "false_positives": [
    {{"title": "...", "reason": "..."}}
  ],
  "top_risks": [
    {{"rank": 1, "title": "...", "why": "...", "blast_radius": "..."}}
  ],
  "executive_summary": "..."
}}"""

    try:
        response = await client.messages.create(
            model=model,
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}],
        )

        raw = response.content[0].text.strip()

        # Extract JSON from response (handle markdown code blocks)
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        triage_data = json.loads(raw.strip())

        false_positive_titles = {fp["title"] for fp in triage_data.get("false_positives", [])}

        # Mark findings as speculative if AI flagged them as likely FPs
        enriched = []
        for f in result.findings:
            if f.title in false_positive_titles:
                fp_reason = next(
                    (fp["reason"] for fp in triage_data["false_positives"] if fp["title"] == f.title),
                    "Flagged as likely false positive by AI triage"
                )
                enriched.append(f.model_copy(update={
                    "status": FindingStatus.SPECULATIVE,
                    "description": f.description + f"\n\n🤖 AI Triage: {fp_reason}",
                }))
            else:
                enriched.append(f)

        return TriageResult(
            findings=enriched,
            executive_summary=triage_data.get("executive_summary"),
            top_risks=triage_data.get("top_risks", []),
            false_positives=triage_data.get("false_positives", []),
            model_used=model,
            skipped=False,
        )

    except Exception as e:
        return TriageResult(
            findings=result.findings,
            executive_summary=None,
            skipped=True,
            skip_reason=f"AI triage failed: {e}",
        )


class TriageResult:
    def __init__(
        self,
        findings: list[Finding],
        executive_summary: Optional[str],
        top_risks: list[dict] = None,
        false_positives: list[dict] = None,
        model_used: str = "",
        skipped: bool = False,
        skip_reason: str = "",
    ):
        self.findings = findings
        self.executive_summary = executive_summary
        self.top_risks = top_risks or []
        self.false_positives = false_positives or []
        self.model_used = model_used
        self.skipped = skipped
        self.skip_reason = skip_reason


def _format_findings_for_prompt(findings: list[Finding]) -> str:
    lines = []
    for i, f in enumerate(findings, 1):
        lines.append(
            f"{i}. [{f.severity.value}] {f.title}\n"
            f"   Status: {f.status.value} | Plugin: {f.plugin} | Endpoint: {f.endpoint}\n"
            f"   {f.description[:300]}{'...' if len(f.description) > 300 else ''}\n"
        )
    return "\n".join(lines)
