# ☁️ Cloud Misconfiguration Hunter

> **Production-grade AWS IaC security scanner — zero dependencies, CIS-mapped, context-aware.**
> A free, self-hosted alternative to Wiz, Prisma Cloud, Lacework, and Checkov Pro for teams that want cloud security without the enterprise price tag.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?logo=github-actions&logoColor=white)](./.github/workflows/iac-scan.yml)
[![CIS](https://img.shields.io/badge/CIS%20AWS-Benchmark%20mapped-1F4E79)](https://www.cisecurity.org/benchmark/amazon_web_services)

---

## What it does

Scans Terraform, CloudFormation, and IAM policy JSON for AWS misconfigurations.
Every finding maps to a **CIS AWS Foundations Benchmark** control with a
remediation hint and a context-aware risk score (production vs. test).

```
============================================================
  [Cloud Misconfiguration Hunter v1.0]
============================================================
[*] Files scanned : 2
[*] Total findings: 19
[*] By severity   : {'CRITICAL': 7, 'HIGH': 9, 'MEDIUM': 3, 'LOW': 0}
[*] By service    : {'S3': 5, 'EC2': 4, 'RDS': 2, 'CloudTrail': 2, 'VPC': 1, 'IAM': 4, 'KMS': 1}

[CRITICAL] IAM policy with wildcard Action + Resource (CIS AWS 1.16)
   samples/iam_policy.json:6 (risk=90, service=IAM)
   > "Action": "*"
   ↳ Never grant Action:* + Resource:*. This is effectively AdministratorAccess.

[CRITICAL] S3 bucket with public-read ACL (CIS AWS 2.1.5)
   samples/main.tf:13 (risk=88, service=S3)
   > acl = "public-read"
   ↳ Set acl to 'private' and use bucket policies with explicit principals.
```

---

## Why you want this

Cloud misconfigurations are the #1 root cause of breaches — IBM's 2024 Cost of
a Data Breach Report put them at 15% of all incidents. Catching them **before**
deployment is the cheapest place on the kill chain.

| | **Cloud Misconfig Hunter** | Wiz | Prisma Cloud | Checkov OSS |
|---|---|---|---|---|
| **Price** | Free (MIT) | $$$$ | $$$$ | Free |
| **Runtime deps** | **None** — pure stdlib | Cloud platform | Cloud platform | Python + deps |
| **Install time** | `git clone` | SaaS onboarding | SaaS onboarding | `pip install checkov` |
| **Self-hosted** | Yes | No | Limited | Yes |
| **CIS mapping** | Per rule | Yes | Yes | Yes |
| **Interactive HTML report** | Bundled | Yes (SaaS) | Yes (SaaS) | No |
| **Production vs test context** | Yes (built-in) | Yes | Yes | No |
| **Extend with Python regex** | 5 lines | No | No | YAML DSL |

---

## 60-second quickstart

```bash
git clone https://github.com/CyberEnthusiastic/cloud-misconfig-hunter.git
cd cloud-misconfig-hunter
python hunter.py samples/
start reports/cloud_report.html   # Windows ; open/xdg-open on Mac/Linux
```

### One-command installer

```bash
./install.sh          # Linux / macOS / WSL / Git Bash
.\install.ps1         # Windows PowerShell
```

### Docker

```bash
docker build -t cloud-hunter .
docker run --rm -v "$PWD:/app/target" cloud-hunter hunter.py target/samples/
```

---

## Open in VS Code (2 clicks)

```bash
code .
```

Accept the extension prompt (Python, Pylance, YAML, Docker), then:
- **F5** → debug-scan the bundled samples
- **Ctrl+Shift+B** → default task (scan + open report)
- The repo ships with `.vscode/launch.json` + `tasks.json` + `extensions.json` + `settings.json`.

---

## 15 CIS-mapped detection rules

| ID | Rule | Severity | CIS |
|----|------|----------|-----|
| S3-001 | S3 public-read / public-read-write ACL | CRITICAL | 2.1.5 |
| S3-002 | S3 without server-side encryption | HIGH | 2.1.1 |
| S3-003 | S3 versioning disabled | MEDIUM | 2.1.3 |
| SG-001 | SG open 0.0.0.0/0 on SSH (22) | CRITICAL | 5.2 |
| SG-002 | SG open 0.0.0.0/0 on RDP (3389) | CRITICAL | 5.3 |
| SG-003 | SG open 0.0.0.0/0 on 0–65535 | CRITICAL | 5.2 |
| IAM-001 | IAM wildcard Action | HIGH | 1.16 |
| IAM-002 | IAM wildcard Action + Resource | CRITICAL | 1.16 |
| RDS-001 | RDS publicly accessible | CRITICAL | 2.3.3 |
| RDS-002 | RDS storage unencrypted | HIGH | 2.3.1 |
| CW-001 | CloudTrail not multi-region / logging off | HIGH | 3.1 |
| EBS-001 | EBS volume unencrypted | HIGH | 2.2.1 |
| LOG-001 | VPC Flow Logs disabled | MEDIUM | 3.9 |
| ROOT-001 | IAM user with AdministratorAccess | HIGH | 1.15 |
| KMS-001 | KMS key rotation disabled | MEDIUM | 3.8 |

---

## Context-aware risk scoring

- **Severity base** — CRITICAL 90, HIGH 70, MEDIUM 45, LOW 20
- **Production boost** — `+8` if the file contains `prod` or `production`
- **Test decay** — `−10` if the file contains `test`, `dev`, `example`, or `sandbox`

A public S3 bucket in `prod-data.tf` scores 98; the same rule in `example/` scores 80.

---

## Scan your own IaC

```bash
python hunter.py infrastructure/main.tf        # single file
python hunter.py ~/my-aws-infra/                # recursive (*.tf, *.json, *.yaml)
python hunter.py ./iac -o prod.json --html prod.html
```

---

## CI/CD integration

See `.github/workflows/iac-scan.yml` — runs on every push/PR, uploads JSON +
HTML reports as artifacts, and prints a severity summary to the Actions log.

---

## Extending

Add a rule to `RULES` in `hunter.py`:

```python
{
    "id": "LAMBDA-001",
    "name": "Lambda function with wildcard invoke permission",
    "severity": "HIGH",
    "service": "Lambda",
    "cis": "CIS AWS 1.22",
    "regex": r'principal\s*=\s*"\*".*?action\s*=\s*"lambda:InvokeFunction"',
    "remediation": "Restrict principal to specific AWS accounts or services.",
},
```

---

## Roadmap

- [ ] HCL2 parser (beyond regex) for nested block accuracy
- [ ] Azure ARM + GCP Deployment Manager support
- [ ] SARIF output for GitHub code scanning
- [ ] Auto-fix PR generation via GitHub Actions
- [ ] Drift detection — deployed state vs IaC

## License · Security · Contributing

- [LICENSE](./LICENSE) — MIT
- [NOTICE](./NOTICE) — attribution
- [SECURITY.md](./SECURITY.md) — vulnerability disclosure
- [CONTRIBUTING.md](./CONTRIBUTING.md) — how to add rules / send PRs

---

Built by **[Mohith Vasamsetti (CyberEnthusiastic)](https://github.com/CyberEnthusiastic)** as part of the [AI Security Projects](https://github.com/CyberEnthusiastic?tab=repositories) suite.
