from sslyze import ServerScanResult
from sslyze.json.json_output import MozillaCompliance, MozillaComplianceIssue
from sslyze.mozilla_tls_profile.mozilla_config_checker import (
    MozillaTlsConfigurationChecker,
    ServerNotCompliantWithMozillaTlsConfiguration,
    ServerScanResultIncomplete, MozillaTlsConfigurationEnum,
)


class MozillaComplianceChecker:
    def __init__(self, mozilla_config_checker: MozillaTlsConfigurationChecker):
        self._mozilla_config_checker = mozilla_config_checker

    def check(self, server_scan_results: list[ServerScanResult]) -> list[MozillaCompliance]:
        results = []

        for server_scan_result in server_scan_results:
            results.append(MozillaCompliance(
                server=server_scan_result.server_location.display_string,
                issues=self._issues_for_server(server_scan_result),
            ))

        return results


    def _issues_for_server(self, server_scan_result: ServerScanResult) -> list[MozillaComplianceIssue]:
        issues = []

        for mozilla_config in [
            MozillaTlsConfigurationEnum.OLD,
            MozillaTlsConfigurationEnum.INTERMEDIATE,
            MozillaTlsConfigurationEnum.MODERN
        ]:
            try:
                self._mozilla_config_checker.check_server(
                    against_config=mozilla_config,
                    server_scan_result=server_scan_result,
                )
            except ServerNotCompliantWithMozillaTlsConfiguration as e:
                for criteria, error_description in e.issues.items():
                    issues.append(MozillaComplianceIssue(
                        mozilla_config=mozilla_config,
                        criteria=criteria,
                        description=error_description,
                    ))
            except ServerScanResultIncomplete:
                print(
                    f"    {server_scan_result.server_location.display_string}: ERROR - Scan did not run successfully;"
                    f" review the scan logs above."
                )
                break

        return issues