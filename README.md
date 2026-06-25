# ICT Risk Assessment Project
## Comparative Evaluation of Prowler and ScoutSuite for AWS Security Analysis

> **Course:** ICT Risk Assessment  
> **Option:** 2 — Experimental Comparison of Security Tools  
---

## Project Overview

This project experimentally compares two AWS cloud security tools:

| Tool | Approach | Output |
|------|----------|--------|
| **Prowler** | Rule-based compliance checks (CIS, NIST) | CSV / JSON |
| **ScoutSuite** | Attack surface analysis | Interactive HTML |

We build a **real intentionally vulnerable AWS lab**, run both tools on the same environment, collect findings, and compare their effectiveness.

---

## Project Structure

```
ict-risk-assessment/
│
├── terraform/                  # AWS infrastructure (intentional misconfigs)
│   ├── main.tf                 # All AWS resources
├── analysis/                   # Python analysis scripts
│   ├── analysis.py             # Main comparison script
│   ├── charts/                 # Generated chart images (auto-created)
│   └── results/                # Scan output files go here
│       ├── prowler/            # Prowler CSV/JSON output
│       └── scoutsuite/         # ScoutSuite HTML report
├── README.md                   # This file
├── requirements.txt            # Python dependencies
└── .gitignore                  # Files to exclude from Git
```

---

## Prerequisites

Before starting, install these tools on your machine:

| Tool | Install Link | Check Command |
|------|-------------|---------------|
| Python 3.10+ | https://www.python.org/downloads/ | `python --version` |
| AWS CLI | https://aws.amazon.com/cli/ | `aws --version` |
| Terraform | https://developer.hashicorp.com/terraform/downloads | `terraform --version` |
| Git | https://git-scm.com/download/win | `git --version` |

---

## Step-by-Step: Run the Project from Zero

### STEP 1 — Clone the project

```bash
git clone git@github.com:Sagorhowlader/ict-risk-assessment.git
cd ict-risk-project
```

---

### STEP 2 — Install Python dependencies

```bash
pip install -r requirements.txt
```

---

### STEP 3 — Configure AWS credentials

Go to AWS Console → your name (top right) → Security Credentials → Access Keys → Create new key.

Then run:

```bash
aws configure
```

Enter when prompted:
```
AWS Access Key ID:     → your key
AWS Secret Access Key: → your secret
Default region name:   → eu-west-3
Default output format: → json
```

Verify it works:
```bash
aws sts get-caller-identity
```

You should see your Account ID printed.

---

### STEP 4 — Deploy AWS Lab (intentionally vulnerable)

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

Type `yes` when asked to confirm.

This creates:
- S3 bucket with public access (misconfiguration)
- IAM user with AdministratorAccess (misconfiguration)
- EC2 instance with open SSH/RDP ports (misconfiguration)
- VPC, subnet, internet gateway, security group

### STEP 5 — Run Prowler Scan

```bash
prowler aws \
  --region eu-west-3 \
  --services s3 iam ec2 \
  --output-formats csv json-ocsf \
  --output-directory analysis/results/prowler
```

This takes ~10 minutes. Results saved to `analysis/results/prowler/`

---

### STEP 6 — Run ScoutSuite Scan

```bash
scout aws \
  --region eu-west-3 \
  --services ec2 s3 iam \
  --output-directory analysis/results/scoutsuite
```

This takes ~5 minutes. Open the HTML report:
```
analysis/results/scoutsuite/scoutsuite-report/scoutsuite-report.html
```

---

### STEP 7 — Run Analysis and Generate Charts

```bash
cd analysis
python analysis.py
```

Charts saved to `analysis/charts/`

---

### STEP 8 — Destroy AWS Lab (IMPORTANT — avoid charges)

When you are done for the day, always destroy the lab:

```bash
cd terraform
terraform destroy
```

Type `yes` to confirm. This deletes EVERYTHING created in Step 4.

**Verify everything is gone:**
```bash
aws s3 ls
aws ec2 describe-instances --region eu-west-3 --output table
```

---

## Intentional Misconfigurations Created

| # | Resource | Misconfiguration | Severity | Why |
|---|----------|-----------------|----------|-----|
| 1 | S3 Bucket | Public read access | HIGH | Tools detect exposed data |
| 2 | IAM User | AdministratorAccess policy | CRITICAL | Violates least privilege |
| 3 | Security Group | SSH port 22 open to 0.0.0.0/0 | CRITICAL | Remote login exposure |
| 4 | Security Group | RDP port 3389 open to 0.0.0.0/0 | CRITICAL | Remote desktop exposure |
| 5 | EC2 Instance | EBS not encrypted | MEDIUM | Data at rest unprotected |
| 6 | EC2 Instance | IMDSv2 not enforced | MEDIUM | Credential theft risk |
| 7 | Account | No CloudTrail enabled | HIGH | No audit logging |

---

## Scan Results Summary

### Prowler
```
Total checks:   172
Failed:          65  (37.8%)
Passed:         107  (62.2%)

Severity breakdown:
  CRITICAL:   8
  HIGH:      16
  MEDIUM:    26
  LOW:       15

Service breakdown:
  EC2:  27 failures
  IAM:  27 failures
  S3:   11 failures
```

### ScoutSuite
```
Total findings:  138
Dangers:          25
Warnings:         84
Info:             29

Service breakdown:
  EC2:  9 danger + 29 warning
  IAM: 15 danger + 37 warning
  S3:   1 danger + 18 warning
```

---

## Key Comparison

| Metric | Prowler | ScoutSuite |
|--------|---------|------------|
| Approach | Rule-based compliance | Attack surface analysis |
| Total findings | 65 failures | 25 dangers + 84 warnings |
| Critical/Danger | 8 critical | 25 danger |
| Output format | CSV / JSON | HTML dashboard |
| Execution time | ~10 min | ~5 min |
| Best for | CI/CD compliance | Security reporting |

---

## Tools Used

- **Prowler** — https://github.com/prowler-cloud/prowler
- **ScoutSuite** — https://github.com/nccgroup/ScoutSuite
- **Terraform** — https://www.terraform.io
- **AWS Free Tier** — https://aws.amazon.com/free

---

## Important Security Notes

- Never commit AWS credentials to Git (covered by .gitignore)
- Always run `terraform destroy` after each session
- This lab is for educational purposes only
- Delete IAM access keys after the project is complete

