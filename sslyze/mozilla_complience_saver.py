import json
from pathlib import Path
from typing import Dict


class MozillaComplianceSaver:
    @staticmethod
    def update_report_file(issues: Dict[str, str], json_file_path: Path) -> None:
        report = json.loads(json_file_path.read_text())

        mozilla_compliance_issuses = {}

        for criteria, error_description in issues.items():
            mozilla_compliance_issuses[criteria] = error_description

        report['mozilla_compliance_issues'] = mozilla_compliance_issuses

        updated_report_text = json.dumps(report, indent=2)
        json_file_path.write_text(updated_report_text)
