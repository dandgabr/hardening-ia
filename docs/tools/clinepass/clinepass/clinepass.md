# ClinePass Security & Hardening Guide

## 1. Overview
- **Vendor:** `clinepass`
- **Tool Name:** `clinepass`
- **Category:** `Security Wrapper & Credential Vault`

ClinePass provides a secure proxy, credential vault, and guardrails wrapper for autonomous coding agents.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `vault.enforce_encryption` | `true` | Enforces AES-256 encryption on all stored API keys. |
| `vault.zero_plaintext_cache` | `true` | Prevents credentials from ever being written to disk unencrypted. |
| `proxy.block_unapproved_hosts` | `true` | Blocks outbound connections to untrusted endpoints. |
| `proxy.block_ssrf_metadata` | `true` | Blocks access to cloud metadata IP 169.254.169.254. |
| `proxy.mask_tokens_in_logs` | `true` | Masks secrets in audit logs. |

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
