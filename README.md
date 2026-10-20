# VulnTrail

**Security Assessment & Evidence Manager**

VulnTrail is a lightweight Python command-line tool for recording security findings, calculating risk scores, checking evidence files, and generating Markdown assessment reports.

## Features

- Record security findings in an SQLite database.
- Calculate risk scores using likelihood and impact.
- Classify findings as Low, Medium, High, or Critical.
- Attach and verify evidence files.
- List and delete findings by ID.
- Generate Markdown assessment reports.
- Validate evidence paths to prevent references outside the project directory.
- Run automated unit tests.

## Requirements

- Python 3.9 or newer
- SQLite support included with Python
- No third-party Python packages required

## Setup

Clone the repository or download the project files.

Change to the project directory:

    cd WAPT_PHASE-2-VulnTrail

Check the command options:

    python3 vulntrail.py --help

## Usage

### Add a finding

    python3 vulntrail.py add \
      --target 192.168.1.3 \
      --title "Example Security Finding" \
      --description "Describe the verified security issue." \
      --likelihood 4 \
      --impact 4 \
      --evidence evidence/example.png \
      --remediation "Apply the recommended security fix."

The evidence file must already exist inside the project directory.

### List findings

    python3 vulntrail.py list

### Delete a finding

Replace 2 with the ID you want to delete.

    python3 vulntrail.py delete --id 2

Deletion is permanent for that database record.

### Generate a report

    python3 vulntrail.py report

The report is saved to `reports/assessment.md`.

### Run tests

    python3 -m unittest discover -s tests -v

## Risk Scoring

VulnTrail multiplies likelihood by impact. Both values range from 1 to 5.

| Score | Severity |
|---|---|
| 1–7 | Low |
| 8–14 | Medium |
| 15–19 | High |
| 20–25 | Critical |

This is a simple prioritization model, not a substitute for a complete risk assessment.

## Project Structure

    recon-tool/
    ├── vulntrail.py
    ├── tests/
    │   └── test_risk.py
    ├── evidence/
    ├── reports/
    ├── README.md
    ├── LICENSE
    └── .gitignore

The SQLite database is created automatically when the tool runs.

## Limitations

- Intended for small assessments and learning projects.
- Does not independently discover or exploit vulnerabilities.
- Users must verify findings and provide their own evidence.
- Reports contain the findings recorded in the local database.

## Responsible Use

Use VulnTrail only for authorized security assessments and systems you have permission to test. Do not include passwords, private keys, personal information, or other sensitive data in evidence or public reports.

## License

Released under the MIT License. See `LICENSE` for details.

