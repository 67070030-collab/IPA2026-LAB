import os
import re
import sys
import time
import warnings
from typing import Any, Dict, Iterable, List, Mapping

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# SSH settings
# ---------------------------------------------------------------------------
KEY_PATH = os.path.expanduser(
    r"C:\Users\user002\Downloads\windows_user.ppk"
)
USERNAME = "WINDOWS_USER"
ENABLE_SECRET = os.getenv("NETMIKO_ENABLE_SECRET", "")

COMMON_DEVICE: Dict[str, Any] = {
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

DEVICES: Dict[str, Dict[str, Any]] = {
    "R1": {**COMMON_DEVICE, "host": "172.31.2.4"},
    "R2": {**COMMON_DEVICE, "host": "172.31.2.5"},
    "S1": {**COMMON_DEVICE, "host": "172.31.2.3"},
}

# Only interfaces in the control/data plane are changed.
CONTROL_DATA_INTERFACES: Dict[str, List[str]] = {
    "R1": [
        "GigabitEthernet0/1",
        "GigabitEthernet0/2",
    ],
    "R2": [
        "GigabitEthernet0/1",
        "GigabitEthernet0/2",
        "GigabitEthernet0/3",
    ],
    "S1": [
        "GigabitEthernet0/1",
        "GigabitEthernet1/1",
    ],
}

# Interfaces connected to non-Cisco endpoints cannot be discovered through CDP.
STATIC_DESCRIPTIONS: Dict[str, Dict[str, str]] = {
    "R1": {
        "GigabitEthernet0/1": "Connect to PC",
    },
    "R2": {
        "GigabitEthernet0/3": "Connect to WAN",
    },
    "S1": {
        "GigabitEthernet1/1": "Connect to PC",
    },
}


class TopologyError(RuntimeError):
    """Raised when CDP data does not match the expected lab topology."""


def ensure_privileged_mode(connection: Any) -> None:
    """Ensure that the current SSH session is in privileged EXEC mode."""
    if connection.check_enable_mode():
        return

    if not ENABLE_SECRET:
        raise RuntimeError(
            "The SSH account is not privilege 15. "
            "Set NETMIKO_ENABLE_SECRET before running the script."
        )

    connection.secret = ENABLE_SECRET
    connection.enable()


def short_device_name(device_name: str) -> str:
    """Remove a DNS suffix from a CDP device ID."""
    return device_name.strip().split(".", maxsplit=1)[0]


def short_interface(interface_name: str) -> str:
    """
    Normalize Cisco interface names into the format used in descriptions.

    Examples:
        GigabitEthernet0/2 -> G0/2
        Gig 0/2            -> G0/2
        Gi0/2              -> G0/2
    """
    compact = re.sub(r"\s+", "", interface_name.strip())

    prefix_patterns = [
        (r"^(?:TenGigabitEthernet|TenGigabitEth|TenGig|Te)(.+)$", "Te"),
        (r"^(?:GigabitEthernet|GigabitEth|Gig|Gi)(.+)$", "G"),
        (r"^(?:FastEthernet|FastEth|Fa)(.+)$", "F"),
        (r"^(?:Ethernet|Eth|Et)(.+)$", "E"),
        (r"^(?:Port-channel|PortChannel|Po)(.+)$", "Po"),
        (r"^(?:Loopback|Lo)(.+)$", "Lo"),
    ]

    for pattern, replacement in prefix_patterns:
        match = re.match(pattern, compact, flags=re.IGNORECASE)
        if match:
            return f"{replacement}{match.group(1)}"

    return compact


def find_local_interface(
    device_name: str,
    cdp_local_interface: str,
) -> str | None:
    """Map a CDP local-interface abbreviation to the full topology name."""
    wanted_short_name = short_interface(cdp_local_interface)

    for full_name in CONTROL_DATA_INTERFACES[device_name]:
        if short_interface(full_name) == wanted_short_name:
            return full_name

    return None


def discover_cdp_neighbors(connection: Any) -> List[Dict[str, str]]:
    """
    Run CDP and parse it with the NTC TextFSM template.

    Netmiko returns a list of dictionaries when a matching NTC template is
    available. Returning raw text means that TextFSM parsing did not occur.
    """
    result = connection.send_command(
        "show cdp neighbors",
        use_textfsm=True,
        read_timeout=120,
    )

    if not isinstance(result, list):
        raise RuntimeError(
            "TextFSM did not parse 'show cdp neighbors'. "
            "Install textfsm and ntc-templates in the active virtual "
            "environment and run the full command 'show cdp neighbors'."
        )

    normalized_rows: List[Dict[str, str]] = []

    for row in result:
        if not isinstance(row, Mapping):
            raise RuntimeError("Unexpected TextFSM result format.")

        # Current NTC template field: neighbor_name.
        # The fallback 'neighbor' supports some older template versions.
        neighbor_name = str(
            row.get("neighbor_name") or row.get("neighbor") or ""
        ).strip()
        local_interface = str(row.get("local_interface") or "").strip()
        neighbor_interface = str(
            row.get("neighbor_interface") or ""
        ).strip()

        if not all(
            [
                neighbor_name,
                local_interface,
                neighbor_interface,
            ]
        ):
            raise RuntimeError(
                f"Incomplete CDP TextFSM record: {dict(row)}"
            )

        normalized_rows.append(
            {
                "neighbor_name": neighbor_name,
                "local_interface": local_interface,
                "neighbor_interface": neighbor_interface,
            }
        )

    return normalized_rows


def build_descriptions(
    device_name: str,
    cdp_neighbors: Iterable[Mapping[str, str]],
) -> Dict[str, str]:
    """
    Build all required descriptions for one device.

    Cisco-to-Cisco links come from CDP. PC and WAN links come from the
    topology's static endpoint rules.
    """
    if device_name not in CONTROL_DATA_INTERFACES:
        raise ValueError(f"Unsupported device: {device_name}")

    descriptions = dict(STATIC_DESCRIPTIONS.get(device_name, {}))

    for neighbor in cdp_neighbors:
        local_interface = find_local_interface(
            device_name,
            str(neighbor["local_interface"]),
        )

        # Ignore management-plane CDP neighbors and unrelated interfaces.
        if local_interface is None:
            continue

        # A static endpoint rule has higher priority.
        if local_interface in descriptions:
            continue

        remote_device = short_device_name(
            str(neighbor["neighbor_name"])
        )
        remote_interface = short_interface(
            str(neighbor["neighbor_interface"])
        )

        descriptions[local_interface] = (
            f"Connect to {remote_interface} of {remote_device}"
        )

    missing_interfaces = [
        interface
        for interface in CONTROL_DATA_INTERFACES[device_name]
        if interface not in descriptions
    ]

    if missing_interfaces:
        missing_text = ", ".join(missing_interfaces)
        raise TopologyError(
            f"{device_name}: CDP did not discover all expected Cisco "
            f"connections. Missing descriptions for: {missing_text}"
        )

    return {
        interface: descriptions[interface]
        for interface in CONTROL_DATA_INTERFACES[device_name]
    }


def build_config_commands(
    descriptions: Mapping[str, str],
) -> List[str]:
    """Convert an interface-description mapping to IOS commands."""
    commands: List[str] = []

    for interface, description in descriptions.items():
        commands.extend(
            [
                f"interface {interface}",
                f"description {description}",
                "exit",
            ]
        )

    return commands


def apply_descriptions(
    connection: Any,
    descriptions: Mapping[str, str],
) -> str:
    """Apply descriptions to one Cisco IOS device."""
    commands = build_config_commands(descriptions)

    return connection.send_config_set(
        commands,
        cmd_verify=False,
        read_timeout=120,
    )


def verify_descriptions(connection: Any) -> str:
    """Return the interface-description table after configuration."""
    return connection.send_command_timing(
        "show interfaces description",
        read_timeout=120,
        last_read=2.0,
    )


def configure_device(
    device_name: str,
    parameters: Mapping[str, Any],
) -> None:
    """Discover CDP topology, configure descriptions, save, and verify."""
    # Lazy import prevents the local tests from requiring a live device.
    from netmiko import ConnectHandler

    connection_parameters = dict(parameters)
    connection_parameters["session_log"] = (
        f"textfsm_{device_name}.log"
    )

    print(f"\n{'#' * 72}")
    print(
        f"Connecting to {device_name} "
        f"({connection_parameters['host']})"
    )
    print(f"{'#' * 72}")

    connection = ConnectHandler(**connection_parameters)

    try:
        ensure_privileged_mode(connection)

        cdp_neighbors = discover_cdp_neighbors(connection)
        descriptions = build_descriptions(
            device_name,
            cdp_neighbors,
        )

        print("\nGenerated descriptions:")
        for interface, description in descriptions.items():
            print(f"  {interface}: {description}")

        output = apply_descriptions(connection, descriptions)
        print("\nConfiguration output:")
        print(output)

        connection.save_config()
        time.sleep(1)

        print("\nVerification:")
        print(verify_descriptions(connection))

    finally:
        connection.disconnect()


def main() -> int:
    """Configure interface descriptions on R1, R2, and S1."""
    if not os.path.isfile(KEY_PATH):
        print(f"ERROR: SSH key file was not found: {KEY_PATH}")
        return 1

    # Lazy imports keep unit tests isolated from Netmiko installation.
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
    )

    failed_devices: List[str] = []

    for device_name, parameters in DEVICES.items():
        try:
            configure_device(device_name, parameters)
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
        return 1

    print("\nAll interface descriptions were configured successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())