# ☁️ Cloud Misconfiguration Hunter

A zero-dependency IaC security scanner that finds AWS misconfigurations in Terraform, CloudFormation, and raw JSON policies. Every finding is mapped to the **CIS AWS Foundations Benchmark** with a remediation hint and a severity-weighted risk score.

## Why this matters

Cloud misconfigurations are the #1 root cause of breaches — IBM Cost of a Data Breach 2024 put them at 15% of all incidents. Catching them **before** deployment is the cheapest place on the kill chain.

## Detections (15 rules)

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

## Quickstart

```bash
git clone https://github.com/CyberEnthusiastic/cloud-misconfig-hunter.git
cd cloud-misconfig-hunter

# Scan bundled samples (Terraform + IAM policy JSON)
python hunter.py samples/

# Open the HTML report
start reports/cloud_report.html      # Windows
open  reports/cloud_report.html      # macOS
xdg-open reports/cloud_report.html   # Linux
```

## Scan your own IaC

```bash
# Single Terraform file
python hunter.py infrastructure/main.tf

# Entire directory (recursively picks up *.tf, *.json, *.yaml)
python hunter.py ~/my-aws-infra/

# Custom output paths
python hunter.py ./iac -o reports/prod.json --html reports/prod.html
```

## Risk scoring

The risk score blends:

- **Severity base** — CRITICAL 90, HIGH 70, MEDIUM 45, LOW 20
- **Context boost** — `+8` if the file contains the word `prod` or `production`
- **Context decay** — `−10` if the file contains `test`, `dev`, `example`, or `sandbox`

That way, a public S3 bucket in `prod-data.tf` scores 98, the same rule in `example/` scores 80.

## CI/CD integration

```yaml
# .github/workflows/iac-security.yml
name: IaC Security
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - name: Run Cloud Misconfiguration Hunter
        run: |
          git clone https://github.com/CyberEnthusiastic/cloud-misconfig-hunter.git /tmp/hunter
          python /tmp/hunter/hunter.py .
      - name: Fail on critical
        run: |
          python -c "import json; r=json.load(open('reports/cloud_report.json')); exit(1 if r['summary']['by_severity']['CRITICAL']>0 else 0)"
```

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

## Roadmap

- [ ] HCL2 parser (beyond regex) for nested block accuracy
- [ ] Azure ARM + GCP Deployment Manager support
- [ ] SARIF output for GitHub code scanning
- [ ] Auto-fix PR generation via GitHub Actions
- [ ] Drift detection — compare deployed state vs IaC

## License

MIT

---

Built by [CyberEnthusiastic](https://github.com/CyberEnthusiastic) · Part of the AI Security Projects series
