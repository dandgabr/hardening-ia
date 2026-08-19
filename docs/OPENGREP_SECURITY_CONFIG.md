# OpenGrep SAST & SCA Configuration Specification 🛡️🔍

This document specifies the default **OpenGrep** static application security testing (SAST) and software composition analysis (SCA) rulesets bundled within **Hardening IA**.

---

## 📊 Coverage Matrix Overview

| Standard / Framework | Scope & Threat Surface | Bundled Ruleset File | Target Languages / Files |
|---|---|---|---|
| **OWASP Top 10 Web (2021)** | A01 to A10 (Injection, Broken Auth, Crypto, XSS, SSRF, Deserialization) | [`owasp-top10-web.yaml`](../configs/opengrep-rules/owasp-top10-web.yaml) | Python, JS, TS, Java, C#, PHP, Go, Ruby |
| **OWASP API Security Top 10 (2023)** | API1 to API10 (BOLA, BFLA, Mass Assignment, Unprotected Endpoints, Introspection) | [`owasp-top10-api.yaml`](../configs/opengrep-rules/owasp-top10-api.yaml) | REST, GraphQL, gRPC (Python, TS, Go, Java, C#) |
| **OWASP Mobile / Android** | M1 to M10 (Hardcoded keys, Insecure TrustManager, World-readable SharedPrefs) | [`owasp-mobile-android.yaml`](../configs/opengrep-rules/owasp-mobile-android.yaml) | Java, Kotlin, AndroidManifest, Dart |
| **CWE Top 25 Most Dangerous** | Buffer Overflows, Use-After-Free, TOCTOU, Code Injections, CSRF, Integer Overflow | [`cwe-top25.yaml`](../configs/opengrep-rules/cwe-top25.yaml) | C, C++, Rust, Go, Python, Java, C#, PHP |
| **Software Composition Analysis (SCA)** | Supply chain security, insecure HTTP registries, unpinned wildcard packages, untracked git repos | [`sca-dependencies.yaml`](../configs/opengrep-rules/sca-dependencies.yaml) | `requirements.txt`, `package.json`, `pom.xml`, `go.mod`, `Cargo.toml`, `Gemfile` |
| **TIOBE Top 20 Languages SAST** | Multi-language security analysis (Memory bounds, TLS skip verify, RFI/LFI, dynamic SQL) | [`tiobe-languages-sast.yaml`](../configs/opengrep-rules/tiobe-languages-sast.yaml) | Top 20 TIOBE programming languages |
| **Unified Master Config** | Complete aggregated enterprise baseline | [`default-opengrep-config.yaml`](../configs/opengrep-rules/default-opengrep-config.yaml) | All supported formats |

---

## 🌐 TIOBE Top 20 Languages Mapping

The OpenGrep engine is configured with rules targeting the primary languages of the TIOBE index:

1. **Python** (SQLi, Command Injection, Insecure Deserialization, SSRF, Hardcoded Secrets)
2. **C** (Buffer Overflows, Out-of-bounds Write CWE-787, gets/strcpy misuse, Use After Free)
3. **C++** (Heap memory safety, NULL dereference, integer overflow in allocation)
4. **Java** (X509TrustManager bypasses, XML External Entity, Path Traversal, ObjectInputStream)
5. **C# (.NET)** (BinaryFormatter, Disabled Certificate Validation, CSRF Antiforgery suppressions)
6. **JavaScript** (DOM XSS, prototype pollution, eval, insecure child_process)
7. **TypeScript** (Mass assignment, dangerouslySetInnerHTML, unvalidated fetch)
8. **Go** (InsecureSkipVerify, unbounded queries, race conditions)
9. **Rust** (Unsafe pointer dereferencing, boundary verification)
10. **PHP** (Remote/Local File Inclusion, unserialize, dynamic SQL queries)
11. **SQL** (Dynamic SQL injection in stored procedures, string concatenation)
12. **Ruby** (Marshal.load deserialization, mass assignment in ActiveRecord)
13. **Swift** (Insecure Keychain access, TLS validation bypass)
14. **Kotlin** (Android Logcat leakage, world-readable file modes)
15. **R & MATLAB** (Insecure eval and external data source ingestion)
16. **Dart / Flutter** (Insecure local storage and cleartext network calls)
17. **Fortran / Assembly** (Memory buffer safety and bounds enforcement)

---

## 🚀 Execution & Automation

### Running via CLI
```bash
# Scan the current codebase with the default master ruleset:
python main.py --scan-code

# Scan a specific subfolder or file:
python main.py --scan-code ./src

# Install and verify OpenGrep binary:
python main.py --install-extra opengrep
```

### Running via OpenGrep CLI directly
```bash
opengrep scan --config configs/opengrep-rules/default-opengrep-config.yaml
```

---

## 📝 Structured Audit Logging

Every execution of the scanner logs timestamped findings into `logs/audit.jsonl`:
```json
{
  "timestamp": "2026-08-19T17:00:00Z",
  "event": "CODE_SCAN",
  "tool": "opengrep",
  "vendor": "opengrep",
  "status": "SUCCESS",
  "details": {
    "target": "B:\\Code\\hardening-ia",
    "total_findings": 0
  }
}
```
