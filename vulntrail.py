
#!/usr/bin/env python3

import argparse
import sqlite3
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "vulntrail.db"
REPORT_DIR = BASE_DIR / "reports"
EVIDENCE_DIR = BASE_DIR / "evidence"


def connect_db():
    return sqlite3.connect(DB_FILE)


def initialize():
    with connect_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                likelihood INTEGER NOT NULL,
                impact INTEGER NOT NULL,
                score INTEGER NOT NULL,
                severity TEXT NOT NULL,
                evidence TEXT,
                remediation TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


def calculate_risk(likelihood, impact):
    score = likelihood * impact

    if score >= 20:
        severity = "Critical"
    elif score >= 15:
        severity = "High"
    elif score >= 8:
        severity = "Medium"
    else:
        severity = "Low"

    return score, severity


def add_finding(args):
    score, severity = calculate_risk(
        args.likelihood, args.impact
    )

    evidence = args.evidence or ""

    if evidence:
        evidence_path = (BASE_DIR / evidence).resolve()

        if not evidence_path.is_relative_to(BASE_DIR):
            raise ValueError(
                "Evidence path must stay inside the project."
            )

        if not evidence_path.is_file():
            raise ValueError("Evidence file does not exist.")

        evidence = str(evidence_path.relative_to(BASE_DIR))

    with connect_db() as db:
        cursor = db.execute("""
            INSERT INTO findings
            (target, title, description, likelihood, impact,
             score, severity, evidence, remediation, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            args.target,
            args.title,
            args.description,
            args.likelihood,
            args.impact,
            score,
            severity,
            evidence,
            args.remediation,
            datetime.now().isoformat(timespec="seconds")
        ))

        finding_id = cursor.lastrowid

    print(f"Finding #{finding_id} saved successfully.")
    print(f"Risk score: {score}/25 | Severity: {severity}")


def list_findings(_args):
    with connect_db() as db:
        rows = db.execute("""
            SELECT id, target, title, score, severity, evidence
            FROM findings ORDER BY id
        """).fetchall()

    if not rows:
        print("No findings recorded yet.")
        return

    print("\nVulnTrail Findings")
    print("-" * 75)

    for row in rows:
        evidence_status = "Attached" if row[5] else "Missing"

        if row[5] and not (BASE_DIR / row[5]).is_file():
            evidence_status = "File missing"

        print(
            f"#{row[0]} | {row[1]} | {row[2]}\n"
            f"   Risk: {row[3]}/25 ({row[4]})"
            f" | Evidence: {evidence_status}"
        )


def delete_finding(args):
    with connect_db() as db:
        row = db.execute(
            "SELECT id, title FROM findings WHERE id = ?",
            (args.finding_id,)
        ).fetchone()

        if row is None:
            print(f"Finding #{args.finding_id} not found.")
            return

        db.execute(
            "DELETE FROM findings WHERE id = ?",
            (args.finding_id,)
        )

    print(f"Finding #{row[0]} deleted: {row[1]}")


def generate_report(_args):
    REPORT_DIR.mkdir(exist_ok=True)

    with connect_db() as db:
        rows = db.execute("""
            SELECT id, target, title, description, likelihood,
                   impact, score, severity, evidence, remediation,
                   created_at
            FROM findings ORDER BY id
        """).fetchall()

    if not rows:
        print("No findings available. Add a finding first.")
        return

    lines = [
        "# VulnTrail Security Assessment Report",
        "",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        "",
        f"Total findings: {len(rows)}",
        ""
    ]

    for row in rows:
        (
            fid, target, title, description, likelihood, impact,
            score, severity, evidence, remediation, created_at
        ) = row

        if evidence:
            evidence_path = (BASE_DIR / evidence).resolve()

            if not evidence_path.is_relative_to(BASE_DIR):
                evidence_display = "Invalid evidence path"
            elif evidence_path.is_file():
                evidence_display = evidence
            else:
                evidence_display = f"{evidence} (file missing)"
        else:
            evidence_display = "Not attached"

        lines.extend([
            f"## Finding {fid}: {title}",
            "",
            f"- **Target:** {target}",
            f"- **Severity:** {severity}",
            f"- **Risk score:** {score}/25",
            f"- **Likelihood:** {likelihood}/5",
            f"- **Impact:** {impact}/5",
            f"- **Recorded:** {created_at}",
            f"- **Evidence:** {evidence_display}",
            "",
            "### Description",
            "",
            description,
            "",
            "### Remediation",
            "",
            remediation,
            ""
        ])

    report_path = REPORT_DIR / "assessment.md"
    report_path.write_text(
        "\n".join(lines), encoding="utf-8"
    )

    print(f"Report generated: {report_path}")


def main():
    parser = argparse.ArgumentParser(
        description="VulnTrail - Security Assessment & Evidence Manager"
    )

    commands = parser.add_subparsers(
        dest="command", required=True
    )

    add = commands.add_parser(
        "add", help="Record a vulnerability finding"
    )
    add.add_argument("--target", required=True)
    add.add_argument("--title", required=True)
    add.add_argument("--description", required=True)
    add.add_argument(
        "--likelihood", type=int, choices=range(1, 6),
        required=True
    )
    add.add_argument(
        "--impact", type=int, choices=range(1, 6),
        required=True
    )
    add.add_argument(
        "--evidence",
        help="Evidence file relative to the project folder"
    )
    add.add_argument("--remediation", required=True)
    add.set_defaults(func=add_finding)

    listing = commands.add_parser(
        "list", help="List recorded findings"
    )
    listing.set_defaults(func=list_findings)

    delete = commands.add_parser(
        "delete", help="Delete a finding by its ID"
    )
    delete.add_argument(
        "--id", dest="finding_id", type=int, required=True,
        help="ID of the finding to delete"
    )
    delete.set_defaults(func=delete_finding)

    report = commands.add_parser(
        "report", help="Generate Markdown report"
    )
    report.set_defaults(func=generate_report)

    args = parser.parse_args()
    initialize()

    try:
        args.func(args)
    except (OSError, sqlite3.Error, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
