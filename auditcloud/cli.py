import json
from pathlib import Path
from rich import print

def main():
    report = {
        "meta": {"tool": "auditcloud", "version": "1.0"},
        "aws": {"summary": {"status": "not run"}, "findings": []},
        "azure": {"summary": {"status": "not run"}, "findings": []},
    }

    outdir = Path("reports")
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("[bold green]OK[/bold green] Generated reports/report.json")

if __name__ == "__main__":
    main()