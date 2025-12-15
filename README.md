# Cloud Security Audit Tool

Python-based cloud security audit tool for **AWS and Azure** that detects common
misconfigurations in cloud storage and identity/access configurations.

## Overview
This tool performs automated security checks to identify **high-risk access control
misconfigurations** across cloud environments. It is designed as a **read-only audit**
utility and does not modify any cloud resources.

## Features

### AWS
- Scans **S3 buckets** for:
  - Public bucket policies
  - Public ACL grants
  - Weak or missing Public Access Block configurations
- Analyzes **IAM customer-managed policies** for:
  - Admin-like wildcard permissions
  - Dangerous actions (e.g. `iam:PassRole`) with `Resource="*"`

### Azure
- Scans **Azure Storage Accounts** for:
  - Public Blob access enabled (`allowBlobPublicAccess`)
- Inspects **Blob containers** for:
  - Public access levels (`blob` or `container`)
- Gracefully handles limited RBAC permissions and reports partial visibility

## Output
- `reports/report.json` — machine-readable security findings
- `reports/report.md` — human-readable audit report

## Tech Stack
- Python 3
- AWS SDK (`boto3`)
- Azure SDK (`azure-identity`, `azure-mgmt-storage`, `azure-storage-blob`)
- Azure CLI
- JSON & Markdown reporting

## Setup

### Python Environment
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
