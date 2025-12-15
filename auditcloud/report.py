def _section(lines, title, data):
    lines.append(f"## {title}\n")
    if not data:
        lines.append("- Not run\n")
        return

    summ = data.get("summary", {})
    if summ:
        lines.append("**Summary**\n")
        for k, v in summ.items():
            lines.append(f"- **{k}**: {v}")
        lines.append("")

    findings = data.get("findings", [])
    lines.append("**Findings**\n")
    if not findings:
        lines.append("- None\n")
    else:
        for f in findings:
            lines.append(f"- **[{f.get('severity')}]** `{f.get('service')}` `{f.get('resource')}` — {f.get('issue')}")
    lines.append("")

def to_markdown(report: dict) -> str:
    lines = []
    lines.append("# Cloud Security Audit Report\n")
    _section(lines, "AWS", report.get("aws"))

    # If AWS includes nested IAM results, show them too
    aws = report.get("aws") or {}
    iam = aws.get("iam")
    if iam:
        _section(lines, "AWS – IAM", iam)

    _section(lines, "Azure", report.get("azure"))
    return "\n".join(lines)