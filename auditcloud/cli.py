import json
from pathlib import Path
from rich import print
from auditcloud.aws_audit import run_aws_audit

def main():
    print("[cyan]Running AWS audit...[/cyan]")

    aws_results = run_aws_audit()

    report = {
        "meta": {"tool": "auditcloud", "version": "1.0"},
        "aws": aws_results
    }

    outdir = Path("reports")
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("[bold green]Done[/bold green] Wrote reports/report.json")

if __name__ == "__main__":
    main()