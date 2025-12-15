import argparse
import json
from pathlib import Path
from rich import print

from auditcloud.aws_audit import run_aws_audit
from auditcloud.azure_audit import run_azure_audit
from auditcloud.report import to_markdown

def main():
    p = argparse.ArgumentParser(prog="auditcloud", description="Cloud Security Audit Tool (AWS + Azure)")
    p.add_argument("--aws", action="store_true", help="Run AWS audit")
    p.add_argument("--azure", action="store_true", help="Run Azure audit")
    p.add_argument("--azure-subscription-id", type=str, default=None, help="Azure subscription id (required for --azure)")
    args = p.parse_args()

    # default: run both
    if not args.aws and not args.azure:
        args.aws = True
        args.azure = True

    report = {"meta": {"tool": "auditcloud", "version": "1.0"}, "aws": None, "azure": None}

    if args.aws:
        print("[cyan]Running AWS audit...[/cyan]")
        report["aws"] = run_aws_audit()

    if args.azure:
        if not args.azure_subscription_id:
            raise SystemExit("ERROR: --azure-subscription-id is required for --azure")
        print("[cyan]Running Azure audit...[/cyan]")
        report["azure"] = run_azure_audit(subscription_id=args.azure_subscription_id)

    outdir = Path("reports")
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (outdir / "report.md").write_text(to_markdown(report), encoding="utf-8")

    print("[bold green]Done[/bold green] Wrote reports/report.json and reports/report.md")

if __name__ == "__main__":
    main()