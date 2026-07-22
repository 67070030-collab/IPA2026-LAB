import os
import re
import sys
import warnings
from typing import Dict, List, Optional, Tuple

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# SSH settings
# ---------------------------------------------------------------------------
KEY_PATH = os.path.expanduser(
    r"C:\Users\user002\Downloads\windows_user.ppk"
)
USERNAME = "WINDOWS_USER"
ENABLE_SECRET = os.getenv("NETMIKO_ENABLE_SECRET", "")

COMMON_DEVICE: Dict[str, object] = {
    "device_type": "cisco_ios",
    "username": USERNAME,
    "use_keys": True,
    "key_file": KEY_PATH,
    "fast_cli": False,
    "conn_timeout": 30,
    "auth_timeout": 30,
    "banner_timeout": 30,
    "read_timeout_override": 120,
    "global_delay_factor": 2,
    "keepalive": 30,
    "disabled_algorithms": {
        "pubkeys": [
            "rsa-sha2-512",
            "rsa-sha2-256",
        ]
    },
}

DEVICES = {
    "R1": {**COMMON_DEVICE, "host": "172.31.2.4"},
    "R2": {**COMMON_DEVICE, "host": "172.31.2.5"},
}


def ensure_privileged_mode(connection) -> None:
    """Ensure that the SSH session is in privileged EXEC mode."""
    if connection.check_enable_mode():
        return

    if not ENABLE_SECRET:
        raise RuntimeError(
            "The SSH account is not privilege 15. "
            "Set NETMIKO_ENABLE_SECRET before running the script."
        )

    connection.secret = ENABLE_SECRET
    connection.enable()


def send_show_command(connection, command: str) -> str:
    """Run a show command without relying heavily on prompt matching."""
    return connection.send_command_timing(
        command,
        read_timeout=120,
        last_read=2.0,
        strip_prompt=False,
        strip_command=False,
    )


def parse_router_uptime(show_version_output: str) -> str:
    """Extract router uptime from 'show version' using regular expression."""
    match = re.search(
        r"(?mi)^\S+\s+uptime\s+is\s+(.+?)\s*$",
        show_version_output,
    )

    if match:
        return match.group(1).strip()

    return "Not found"


def parse_active_interfaces(
    show_ip_interface_brief_output: str,
) -> List[Tuple[str, str]]:
    """
    Extract interfaces whose Status and Protocol are both up.

    Expected IOS columns:
        Interface  IP-Address  OK?  Method  Status  Protocol
    """
    pattern = re.compile(
        r"(?m)^"
        r"(?P<interface>\S+)\s+"
        r"(?P<ip_address>\S+)\s+"
        r"\S+\s+"
        r"\S+\s+"
        r"up\s+"
        r"up\s*$",
        re.IGNORECASE,
    )

    return [
        (
            match.group("interface"),
            match.group("ip_address"),
        )
        for match in pattern.finditer(show_ip_interface_brief_output)
    ]


def parse_last_link_flapped(
    show_interfaces_output: str,
    interface_name: str,
) -> Optional[str]:
    """
    Extract the 'Last link flapped' value for an active interface.

    Some IOS/IOSv versions do not provide this field. In that case,
    the function returns None.
    """
    escaped_interface = re.escape(interface_name)

    interface_block_pattern = re.compile(
        rf"(?ms)^"
        rf"{escaped_interface}\s+is\s+up,\s+line\s+protocol\s+is\s+up"
        rf"(?P<body>.*?)"
        rf"(?=^\S+\s+is\s+|\Z)",
        re.IGNORECASE,
    )

    block_match = interface_block_pattern.search(show_interfaces_output)
    if not block_match:
        return None

    flap_match = re.search(
        r"(?mi)^\s*Last\s+link\s+flapped\s+(.+?)\s*$",
        block_match.group("body"),
    )

    if flap_match:
        return flap_match.group(1).strip()

    return None


def display_results(
    device_name: str,
    router_uptime: str,
    active_interfaces: List[Tuple[str, str]],
    show_interfaces_output: str,
) -> None:
    """Display the router uptime and its active interfaces."""
    print(f"\n{'=' * 72}")
    print(device_name)
    print(f"{'=' * 72}")
    print(f"Router uptime: {router_uptime}")

    if not active_interfaces:
        print("No active interfaces were found.")
        return

    headers = ("Interface", "IP address", "Interface uptime")
    rows: List[Tuple[str, str, str]] = []

    for interface_name, ip_address in active_interfaces:
        interface_uptime = parse_last_link_flapped(
            show_interfaces_output,
            interface_name,
        )

        rows.append(
            (
                interface_name,
                ip_address,
                interface_uptime or "Not provided by IOS",
            )
        )

    interface_width = max(
        len(headers[0]),
        *(len(row[0]) for row in rows),
    )
    ip_width = max(
        len(headers[1]),
        *(len(row[1]) for row in rows),
    )
    uptime_width = max(
        len(headers[2]),
        *(len(row[2]) for row in rows),
    )

    separator = (
        f"+-{'-' * interface_width}-"
        f"+-{'-' * ip_width}-"
        f"+-{'-' * uptime_width}-+"
    )

    print(separator)
    print(
        f"| {headers[0]:<{interface_width}} "
        f"| {headers[1]:<{ip_width}} "
        f"| {headers[2]:<{uptime_width}} |"
    )
    print(separator)

    for interface_name, ip_address, interface_uptime in rows:
        print(
            f"| {interface_name:<{interface_width}} "
            f"| {ip_address:<{ip_width}} "
            f"| {interface_uptime:<{uptime_width}} |"
        )

    print(separator)
    print(f"Total active interfaces: {len(rows)}")


def check_device(
    device_name: str,
    parameters: Dict[str, object],
) -> None:
    """Connect to one router, collect data, parse it, and display results."""
    connection_parameters = dict(parameters)
    connection_parameters["session_log"] = f"netmiko-re_{device_name}.log"

    print(f"\nConnecting to {device_name} ({parameters['host']})...")

    connection = ConnectHandler(**connection_parameters)

    try:
        ensure_privileged_mode(connection)

        show_version_output = send_show_command(
            connection,
            "show version",
        )
        show_ip_brief_output = send_show_command(
            connection,
            "show ip interface brief",
        )
        show_interfaces_output = send_show_command(
            connection,
            "show interfaces",
        )

        router_uptime = parse_router_uptime(show_version_output)
        active_interfaces = parse_active_interfaces(
            show_ip_brief_output,
        )

        display_results(
            device_name,
            router_uptime,
            active_interfaces,
            show_interfaces_output,
        )

    finally:
        connection.disconnect()


def main() -> int:
    """Check all active interfaces and uptime on R1 and R2."""
    if not os.path.isfile(KEY_PATH):
        print(f"ERROR: SSH key file was not found: {KEY_PATH}")
        return 1

    failed_devices: List[str] = []

    for device_name, parameters in DEVICES.items():
        try:
            check_device(device_name, parameters)
        except (
            NetmikoTimeoutException,
            NetmikoAuthenticationException,
        ) as error:
            failed_devices.append(device_name)
            print(f"\nERROR on {device_name}: {error}")
        except Exception as error:
            failed_devices.append(device_name)
            print(
                f"\nERROR on {device_name}: "
                f"{type(error).__name__}: {error}"
            )

    if failed_devices:
        print("\nFailed devices: " + ", ".join(failed_devices))
        print("Check netmiko-re_<device>.log for session details.")
        return 1

    print("\nInterface and uptime check completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())