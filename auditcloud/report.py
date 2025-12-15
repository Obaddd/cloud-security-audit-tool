def to_markdown(report: dict) -> str:
    lines = []
    lines.append("# Cloud Security Audit Report\n")

    aws = report.get("aws", {})
    s3_summary = aws.get("summary", {})
    s3_findings = aws.get("findings", [])
    iam = aws.get("iam", {})
    iam_summary = iam.get("summary", {})
    iam_findings = iam.get("findings", [])

    lines.append("## AWS – S3\n")
    if s3_summary:
        for k, v in s3_summary.items():
            lines.append(f"- **{k}**: {v}")
    lines.append("\n### Findings\n")
    if not s3_findings:
        lines.append("- None\n")
    else:
        for f in s3_findings:
            lines.append(f"- **[{f.get('severity')}]** `{f.get('resource')}` — {f.get('issue')}")

    lines.append("\n## AWS – IAM\n")
    if iam_summary:
        for k, v in iam_summary.items():
            lines.append(f"- **{k}**: {v}")
    lines.append("\n### Findings\n")
    if not iam_findings:
        lines.append("- None\n")
    else:
        for f in iam_findings:
            lines.append(f"- **[{f.get('severity')}]** `{f.get('resource')}` — {f.get('issue')}")

    return "\n".join(lines)