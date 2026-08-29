# ClinePass Security & Hardening Guide

## 1. Overview
- **Vendor:** `clinepass`
- **Tool Name:** `clinepass`
- **Category:** `Security Wrapper & Vault`

ClinePass provides managed authentication, an encrypted credential vault, and security proxy for Cline agents.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `vault.enforce_encryption` | `true` | Encrypts stored LLM API keys at rest. |
| `vault.zero_plaintext_cache` | `true` | Prevents caching credentials in plaintext memory. |
| `proxy.block_unapproved_hosts` | `true` | Blocks outgoing connections to unapproved endpoints. |
| `proxy.block_ssrf_metadata` | `true` | Blocks SSRF requests to cloud metadata endpoints. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/clinepass/clinepass/hardening_policy.yaml`](file:///configs/tools/clinepass/clinepass/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool clinepass/clinepass --apply

# Dry run simulation:
python main.py --tool clinepass/clinepass --apply --dry-run
```
