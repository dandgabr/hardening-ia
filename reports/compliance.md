# Hardening IA Enterprise Compliance Report

**Generated at (UTC):** `2026-08-29T18:45:30.517054+00:00`

## Executive Summary

| Metric | Value |
| :--- | :--- |
| **Global Compliance Score** | **94.92%** |
| **Tools Evaluated** | 21 |
| **Installed on Host** | 3 |
| **Passed Checks** | 56 |
| **Failed Checks** | 3 |

## Tool Compliance Matrix

| Tool | Status | Score | Findings |
| :--- | :--- | :--- | :--- |
| `augment/augment` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `tabnine/tabnine` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `amazon/amazon-q` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `aider/aider` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `continuedev/continue` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `codeium/windsurf` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `zai/zai` | ✅ Installed | **96.2%** (25/26) | 1 discrepancy(ies) |
| `xai/grok` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `qoder/qoder` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `opencode/opencode` | ✅ Installed | **100.0%** (13/13) | 100% Compliant |
| `openai/codex` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `nousresearch/hermes-agent` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `moonshot/kimi` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `kilo/kilo-code` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `google/antigravity` | ✅ Installed | **90.0%** (18/20) | 2 discrepancy(ies) |
| `github/copilot` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `codebuddy/codebuddy` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `clinepass/clinepass` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `cline/cline` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `anysphere/cursor` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |
| `anthropic/claude-code` | ⚪ Not Found | **0.0%** (0/0) | 0 discrepancy(ies) |

## Governance Framework Mappings

| Control Domain | OWASP Top 10 for LLM | NIST AI RMF | ISO/IEC 42001 |
| :--- | :--- | :--- | :--- |
| **TELEMETRY** | `LLM02: Sensitive Information Disclosure` | `GOVERN-1.1 / MEASURE-2.3` | `A.6.2 Data Security & Privacy Controls` |
| **SANDBOX** | `LLM06: Excessive Agency & Uncontrolled Execution` | `MANAGE-1.2 Risk Treatment` | `A.8.4 AI System Boundary Isolation` |
| **MCP** | `LLM01: Prompt Injection / Tool Exploitation` | `MAP-1.5 Third-Party Integrations` | `A.9.3 Access Control & Protocol Verification` |
| **DLP** | `LLM02: Sensitive Information Disclosure / LLM07: System Prompt Leakage` | `MEASURE-2.3 Privacy Safeguards` | `A.6.2 Sensitive Data Protection` |
| **SUBAGENTS** | `LLM06: Excessive Agency & Uncontrolled Autonomy` | `GOVERN-1.1 Workload Governance` | `A.8.4 Process Orchestration & Guardrails` |
| **APPROVALS** | `LLM06: Excessive Agency` | `MANAGE-1.2 Human-in-the-Loop Oversight` | `A.9.3 Human Authorization` |
| **RATE_LIMITS** | `LLM10: Unbounded Consumption & Denial of Service` | `MEASURE-2.3 Resource Governance` | `A.8.4 Availability Controls` |