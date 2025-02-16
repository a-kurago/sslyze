import sys
from datetime import datetime
from typing import Optional, TextIO

from sslyze.mozilla_compliance import MozillaComplianceChecker
from sslyze.cli.console_output import ObserverToGenerateConsoleOutput
from sslyze.__version__ import __version__
from sslyze.cli.command_line_parser import CommandLineParsingError, CommandLineParser

from sslyze import (
    Scanner,
    ServerScanRequest,
    SslyzeOutputAsJson,
    ServerScanResultAsJson,
    ServerConnectivityStatusEnum,
)
from sslyze.json.json_output import InvalidServerStringAsJson, MozillaComplianceIssue
from sslyze.mozilla_tls_profile.mozilla_config_checker import (
    MozillaTlsConfigurationChecker,
)


def main() -> None:
    # Parse the supplied command line
    date_scans_started = datetime.utcnow()
    sslyze_parser = CommandLineParser(__version__)
    try:
        parsed_command_line = sslyze_parser.parse_command_line()
    except CommandLineParsingError as e:
        print(e.get_error_msg())
        return

    # Setup the observer to print to the console, if needed
    scanner_observers = []
    if not parsed_command_line.should_disable_console_output:
        observer_for_console_output = ObserverToGenerateConsoleOutput(
            file_to=sys.stdout, json_path_out=parsed_command_line.json_path_out
        )
        observer_for_console_output.command_line_parsed(parsed_command_line=parsed_command_line)

        scanner_observers.append(observer_for_console_output)

    # Setup the scanner
    sslyze_scanner = Scanner(
        per_server_concurrent_connections_limit=parsed_command_line.per_server_concurrent_connections_limit,
        concurrent_server_scans_limit=parsed_command_line.concurrent_server_scans_limit,
        observers=scanner_observers,
    )

    # Queue the scans
    all_server_scan_requests = []
    for server_location, network_config in parsed_command_line.servers_to_scans:
        scan_request = ServerScanRequest(
            server_location=server_location,
            network_configuration=network_config,
            scan_commands=parsed_command_line.scan_commands,
            scan_commands_extra_arguments=parsed_command_line.scan_commands_extra_arguments,
        )
        all_server_scan_requests.append(scan_request)

    # If there are servers that we were able to resolve, scan them
    all_server_scan_results = []
    if all_server_scan_requests:
        sslyze_scanner.queue_scans(all_server_scan_requests)
        for result in sslyze_scanner.get_results():
            # Results are actually displayed by the observer; here we just store them
            all_server_scan_results.append(result)

    mozilla_compliance_checker = MozillaComplianceChecker(
        MozillaTlsConfigurationChecker.get_default()
    )

    mozilla_compliance = mozilla_compliance_checker.check(all_server_scan_results)

    # Write results to a JSON file if needed
    json_file_out: Optional[TextIO] = None
    if parsed_command_line.should_print_json_to_console:
        json_file_out = sys.stdout
    elif parsed_command_line.json_path_out:
        json_file_out = parsed_command_line.json_path_out.open("wt", encoding="utf-8")

    if json_file_out:
        json_output = SslyzeOutputAsJson(
            server_scan_results=[ServerScanResultAsJson.model_validate(result) for result in all_server_scan_results],
            invalid_server_strings=[
                InvalidServerStringAsJson.model_validate(bad_server)
                for bad_server in parsed_command_line.invalid_servers
            ],
            date_scans_started=date_scans_started,
            date_scans_completed=datetime.utcnow(),
            mozilla_compliance=mozilla_compliance,
        )
        json_output_as_str = json_output.model_dump_json(indent=2)
        json_file_out.write(json_output_as_str)

    # If we printed the JSON results to the console, don't run the Mozilla compliance check so we return valid JSON
    if parsed_command_line.should_print_json_to_console:
        sys.exit(0)

    if {res.connectivity_status for res in all_server_scan_results} in [set(), {ServerConnectivityStatusEnum.ERROR}]:
        # There are no results to present: all supplied server strings were invalid?
        sys.exit(0)

    # Check the results against the Mozilla config if needed
    are_all_servers_compliant = True
    # TODO(AD): Expose format_title method
    title = ObserverToGenerateConsoleOutput._format_title("Compliance against Mozilla TLS configuration")
    print()
    print(title)

    for result in mozilla_compliance:
        if result.issues:
            print(f"    {result.server}: FAILED - Not compliant.")
            print_issues(result.issues)
        else:
            print(f"    {result.server}: OK - Compliant.")


def print_issues(issues: list[MozillaComplianceIssue]) -> None:
    for config in ['old', 'intermediate', 'modern']:
        print(f"\n    Issues for {config} configuration:")
        for issue in issues:
            if issue.mozilla_config == config:
                print(f"    * {issue.criteria}: {issue.description}")


if __name__ == "__main__":
    main()
