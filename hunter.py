"""
Cloud Misconfiguration Hunter
Scans Terraform / CloudFormation / raw JSON for AWS security misconfigurations.
Maps findings to CIS AWS Benchmark + AWS Well-Architected Security Pillar.

Author: Adithya Vasamsetti (CyberEnthusiastic)
"""
import re
import os
import json
import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import List, Dict


# -----------------------------------------------------------
# CIS-mapped misconfiguration rules
# Each rule has a detector callable that receives the full text
# plus a parsed dict (if JSON) and returns a list of (line, evidence).
# -----------------------------------------------------------
RULES: List[Dict] = [
    {
        "id": "S3-001",
        "name": "S3 bucket with public-read ACL",
        "severity": "CRITICAL",
        "service": "S3",
        "cis": "CIS AWS 2.1.5",
        "regex": r'acl\s*=\s*"public-read(?:-write)?"|"AccessControl"\s*:\s*"PublicRead(?:Write)?"',
        "remediation": "Set acl to 'private' and use bucket policies with explicit principals.",
    },
    {
        "id": "S3-002",
        "name": "S3 bucket without server-side encryption",
        "severity": "HIGH",
        "service": "S3",
        "cis": "CIS AWS 2.1.1",
        "regex": r'resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{(?:(?!server_side_encryption_configuration)[\s\S])*?\}',
        "remediation": "Add aws_s3_bucket_server_side_encryption_configuration with AES256 or KMS.",
        "multiline": True,
    },
    {
        "id": "S3-003",
        "name": "S3 bucket versioning disabled",
        "severity": "MEDIUM",
        "service": "S3",
        "cis": "CIS AWS 2.1.3",
        "regex": r'versioning\s*\{\s*enabled\s*=\s*false',
        "remediation": "Enable versioning to protect against accidental deletion.",
    },
    {
        "id": "SG-001",
        "name": "Security group open to 0.0.0.0/0 on SSH (22)",
        "severity": "CRITICAL",
        "service": "EC2",
        "cis": "CIS AWS 5.2",
        "regex": r'(?s)from_port\s*=\s*22\s*\n[\s\S]*?to_port\s*=\s*22[\s\S]*?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"',
        "remediation": "Restrict SSH to specific bastion/VPN CIDRs. Never expose port 22 to the internet.",
    },
    {
        "id": "SG-002",
        "name": "Security group open to 0.0.0.0/0 on RDP (3389)",
        "severity": "CRITICAL",
        "service": "EC2",
        "cis": "CIS AWS 5.3",
        "regex": r'(?s)from_port\s*=\s*3389[\s\S]*?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"',
        "remediation": "Restrict RDP to specific bastion/VPN CIDRs.",
    },
    {
        "id": "SG-003",
        "name": "Security group allows all traffic (0-65535) from internet",
        "severity": "CRITICAL",
        "service": "EC2",
        "cis": "CIS AWS 5.2",
        "regex": r'(?s)from_port\s*=\s*0[\s\S]*?to_port\s*=\s*65535[\s\S]*?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"',
        "remediation": "Explicit allow-list of ports and source CIDRs only.",
    },
    {
        "id": "IAM-001",
        "name": "IAM policy with wildcard Action (*)",
        "severity": "HIGH",
        "service": "IAM",
        "cis": "CIS AWS 1.16",
        "regex": r'"Action"\s*:\s*"\*"',
        "remediation": "Grant least privilege — specify exact actions (e.g. s3:GetObject).",
    },
    {
        "id": "IAM-002",
        "name": "IAM policy with wildcard Resource (*) AND wildcard Action",
        "severity": "CRITICAL",
        "service": "IAM",
        "cis": "CIS AWS 1.16",
        "regex": r'"Effect"\s*:\s*"Allow"[\s\S]*?"Action"\s*:\s*"\*"[\s\S]*?"Resource"\s*:\s*"\*"',
        "remediation": "Never grant Action:* + Resource:*. This is effectively AdministratorAccess.",
    },
    {
        "id": "RDS-001",
        "name": "RDS instance publicly accessible",
        "severity": "CRITICAL",
        "service": "RDS",
        "cis": "CIS AWS 2.3.3",
        "regex": r'publicly_accessible\s*=\s*true',
        "remediation": "Set publicly_accessible = false. Use VPC peering or bastion to reach DB.",
    },
    {
        "id": "RDS-002",
        "name": "RDS instance without storage encryption",
        "severity": "HIGH",
        "service": "RDS",
        "cis": "CIS AWS 2.3.1",
        "regex": r'storage_encrypted\s*=\s*false',
        "remediation": "Set storage_encrypted = true and specify kms_key_id.",
    },
    {
        "id": "CW-001",
        "name": "CloudTrail not enabled / not multi-region",
        "severity": "HIGH",
        "service": "CloudTrail",
        "cis": "CIS AWS 3.1",
        "regex": r'is_multi_region_trail\s*=\s*false|enable_logging\s*=\s*false',
        "remediation": "Enable is_multi_region_trail = true and enable_logging = true.",
    },
    {
        "id": "EBS-001",
        "name": "EBS volume unencrypted",
        "severity": "HIGH",
        "service": "EC2",
        "cis": "CIS AWS 2.2.1",
        "regex": r'resource\s+"aws_ebs_volume"[\s\S]*?encrypted\s*=\s*false',
        "remediation": "Set encrypted = true (enable EBS encryption-by-default at the account level).",
    },
    {
        "id": "LOG-001",
        "name": "VPC Flow Logs disabled",
        "severity": "MEDIUM",
        "service": "VPC",
        "cis": "CIS AWS 3.9",
        "regex": r'enable_flow_log\s*=\s*false',
        "remediation": "Enable VPC flow logs for all VPCs and ship to CloudWatch or S3.",
    },
    {
        "id": "ROOT-001",
        "name": "IAM user with AdministratorAccess attached",
        "severity": "HIGH",
        "service": "IAM",
        "cis": "CIS AWS 1.15",
        "regex": r'policy_arn\s*=\s*"arn:aws:iam::aws:policy/AdministratorAccess"',
        "remediation": "Attach job-specific managed policies instead of AdministratorAccess.",
    },
    {
        "id": "KMS-001",
        "name": "KMS key rotation disabled",
        "severity": "MEDIUM",
        "service": "KMS",
        "cis": "CIS AWS 3.8",
        "regex": r'enable_key_rotation\s*=\s*false',
        "remediation": "Set enable_key_rotation = true for customer-managed KMS keys.",
    },
]


@dataclass
class Finding:
    id: str
    name: str
    severity: str
    service: str
    cis: str
    file: str
    line: int
    evidence: str
    remediation: str
    risk_score: float = 0.0
    fingerprint: str = ""


class RiskCalculator:
    SEV_WEIGHT = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 45, "LOW": 20}

    def score(self, finding: Finding, content: str) -> float:
        base = self.SEV_WEIGHT[finding.severity]
        # Boost if finding appears in a "production" / "prod" context
        if re.search(r"prod|production", content[:4000], re.I):
            base += 8
        # Reduce if in test / dev / example context
        if re.search(r"test|dev|example|sandbox", content[:4000], re.I):
            base -= 10
        return max(0.0, min(100.0, base))


class MisconfigHunter:
    def __init__(self):
        self.findings: List[Finding] = []
        self.files_scanned = 0
        self.risk = RiskCalculator()

    def scan(self, target: str) -> List[Finding]:
        p = Path(target)
        if p.is_file():
            self._scan_file(p)
        elif p.is_dir():
            for ext in ("*.tf", "*.json", "*.yaml", "*.yml"):
                for f in p.rglob(ext):
                    self._scan_file(f)
        return self.findings

    def _scan_file(self, path: Path):
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return
        self.files_scanned += 1
        lines = content.splitlines()

        for rule in RULES:
            flags = re.MULTILINE | re.IGNORECASE
            if rule.get("multiline"):
                flags |= re.DOTALL
            for m in re.finditer(rule["regex"], content, flags):
                line_no = content[: m.start()].count("\n") + 1
                evidence = lines[line_no - 1].strip() if line_no <= len(lines) else m.group(0)[:120]

                finding = Finding(
                    id=rule["id"],
                    name=rule["name"],
                    severity=rule["severity"],
                    service=rule["service"],
                    cis=rule["cis"],
                    file=str(path),
                    line=line_no,
                    evidence=evidence[:200],
                    remediation=rule["remediation"],
                )
                finding.risk_score = self.risk.score(finding, content)
                finding.fingerprint = hashlib.sha1(
                    f"{path}:{line_no}:{rule['id']}".encode()
                ).hexdigest()[:12]
                self.findings.append(finding)

    def summary(self) -> Dict:
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_svc: Dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_svc[f.service] = by_svc.get(f.service, 0) + 1
        return {
            "files_scanned": self.files_scanned,
            "total_findings": len(self.findings),
            "by_severity": by_sev,
            "by_service": by_svc,
            "scanned_at": datetime.now(tz=timezone.utc).isoformat(),
        }


def main():
    from license_guard import verify_license, print_banner
    verify_license()
    print_banner("Cloud Misconfiguration Hunter")
    import argparse, sys
    # Force UTF-8 on Windows consoles so emoji and box chars render
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="Cloud Misconfiguration Hunter - CIS-mapped IaC scanner"
    )
    parser.add_argument("target", help="File or directory containing Terraform/CFN/JSON")
    parser.add_argument("-o", "--output", default="reports/cloud_report.json")
    parser.add_argument("--html", default="reports/cloud_report.html")
    args = parser.parse_args()

    print("=" * 60)
    print("  [Cloud Misconfiguration Hunter v1.0]")
    print("=" * 60)
    print(f"[*] Target: {args.target}")

    hunter = MisconfigHunter()
    findings = hunter.scan(args.target)
    summary = hunter.summary()

    print(f"[*] Files scanned : {summary['files_scanned']}")
    print(f"[*] Total findings: {summary['total_findings']}")
    print(f"[*] By severity   : {summary['by_severity']}")
    print(f"[*] By service    : {summary['by_service']}")
    print()

    for f in sorted(findings, key=lambda x: -x.risk_score):
        color = "\033[91m" if f.severity == "CRITICAL" else "\033[93m"
        reset = "\033[0m"
        print(f"{color}[{f.severity}]{reset} {f.name}  ({f.cis})")
        print(f"   {f.file}:{f.line} (risk={f.risk_score}, service={f.service})")
        print(f"   > {f.evidence}")
        print(f"   ↳ {f.remediation}")
        print()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as fp:
        json.dump({
            "summary": summary,
            "findings": [asdict(f) for f in findings]
        }, fp, indent=2)
    print(f"[+] JSON report: {args.output}")

    from report_generator import generate_html
    generate_html(summary, findings, args.html)
    print(f"[+] HTML report: {args.html}")


if __name__ == "__main__":
    main()
