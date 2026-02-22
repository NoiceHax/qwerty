"""Prompt templates for Gemini AI security analysis.

Frames Gemini as a security analyst / risk advisor, NOT a chatbot.
"""

SYSTEM_PROMPT = """You are a senior application security analyst conducting a professional
security assessment. You are reviewing automated scan results and providing
an expert interpretation for the development team.

STRICT RULES:
- Never claim a vulnerability is definitively exploitable without proof of exploitation
- Always respect confidence levels — low confidence means "potential", not "confirmed"
- Use professional, consultative security-analyst language
- Prioritize findings by real-world business impact, not just severity scores
- Acknowledge scanner limitations and false-positive potential
- Do NOT invent, hallucinate, or reference vulnerabilities not present in the scan data
- Frame all recommendations as specific, actionable engineering tasks
- If the scan confidence is low overall, clearly state that manual review is needed
"""

SUMMARY_TEMPLATE = """## Security Scan Intelligence

**Target:** {target}
**Scan Type:** {scan_type}
**Overall Risk Score:** {risk_score}/10
**Security Posture:** {posture_rating}
**Total Findings:** {total_findings}

## Severity Distribution
| Level | Count |
|-------|-------|
| Critical | {critical_count} |
| High | {high_count} |
| Medium | {medium_count} |
| Low | {low_count} |
| Info | {info_count} |

## Confidence Distribution
| Level | Count |
|-------|-------|
| High Confidence | {conf_high} |
| Medium Confidence | {conf_medium} |
| Low Confidence | {conf_low} |

## Top Findings (Most Critical)
{top_findings_block}

## Detection Sources
{sources_block}

## Security Observations
{observations_block}

{repo_context_block}

---

## YOUR TASK

Generate a professional security assessment report with EXACTLY these sections.
Use markdown formatting. Be specific, not generic.

### 1. Executive Summary
Write 3-5 sentences summarizing the security posture for a non-technical stakeholder.
Include the risk score interpretation and the most critical concern.

### 2. Risk Narrative
Provide technical context: what attack chains are possible, which compound risks
exist, and what the scanner results mean in practice.

### 3. Prioritized Remediation Actions
List up to 7 specific actions ordered by real-world impact. Each action must be
a concrete engineering task (not "improve security").

### 4. Positive Observations
List security strengths identified (things done correctly).

### 5. Confidence Notes
State what the scanner may have missed, which findings need manual verification,
and any limitations of the automated analysis.

### 6. Use-Case Advice
Tailor recommendations based on the apparent project type (startup MVP, enterprise
app, portfolio project, open-source library, etc.).
"""


def build_summary_prompt(scan_input: "AIScanInput") -> str:
    """Build the full prompt from scan data."""
    from app.analysis.ai_schemas import AIScanInput

    # Format top findings
    findings_lines = []
    for i, f in enumerate(scan_input.top_findings[:10], 1):
        loc = f" at `{f.location}`" if f.location else ""
        findings_lines.append(
            f"{i}. **[{f.severity.upper()}]** {f.title}{loc} "
            f"(confidence: {f.confidence}, type: {f.vuln_type})"
        )
    top_findings_block = "\n".join(findings_lines) if findings_lines else "No findings detected."

    # Sources
    sources_block = ", ".join(scan_input.detection_sources) if scan_input.detection_sources else "N/A"

    # Observations
    observations_block = "\n".join(
        f"- {obs}" for obs in scan_input.security_observations
    ) if scan_input.security_observations else "No additional observations."

    # Repo context
    repo_context_block = ""
    if scan_input.repo_context:
        rc = scan_input.repo_context
        repo_context_block = f"""## Repository Context
- **Tech Stack:** {', '.join(rc.tech_stack)}
- **Primary Language:** {rc.primary_language or 'Unknown'}
- **Complexity:** {rc.complexity}
- **CI/CD:** {'Yes' if rc.has_ci else 'No'}
- **Docker:** {'Yes' if rc.has_docker else 'No'}
- **Description:** {rc.description or 'N/A'}"""

    sev = scan_input.severity_distribution
    conf = scan_input.confidence_distribution

    return SUMMARY_TEMPLATE.format(
        target=scan_input.target,
        scan_type=scan_input.scan_type,
        risk_score=scan_input.risk_score,
        posture_rating=scan_input.posture_rating,
        total_findings=scan_input.total_findings,
        critical_count=sev.get("critical", 0),
        high_count=sev.get("high", 0),
        medium_count=sev.get("medium", 0),
        low_count=sev.get("low", 0),
        info_count=sev.get("info", 0),
        conf_high=conf.get("high", 0),
        conf_medium=conf.get("medium", 0),
        conf_low=conf.get("low", 0),
        top_findings_block=top_findings_block,
        sources_block=sources_block,
        observations_block=observations_block,
        repo_context_block=repo_context_block,
    )
