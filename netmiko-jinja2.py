import os
import re
import sys
import time
import warnings
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Paths and SSH settings
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"

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
    "S1": {
        **COMMON_DEVICE,
        "host": "172.31.2.3",
        "template": "s1.j2",
    },
    "R1": {
        **COMMON_DEVICE,
        "host": "172.31.2.4",
        "template": "r1.j2",
    },
    "R2": {
        **COMMON_DEVICE,
        "host": "172.31.2.5",
        "template": "r2.j2",
    },
}

# ---------------------------------------------------------------------------
# Lab variables
# ---------------------------------------------------------------------------
MGMT_NETWORK = "172.31.2.0 0.0.0.15"       # 172.31.2.0/28
LAB306_NETWORK = "192.168.0.0 0.0.255.255" 
CONTROL_VRF = "control-data"
OSPF_PROCESS = 1

JINJA_ENV = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
)


def ensure_privileged_mode(connection) -> None:
    """Ensure that the current session has privileged EXEC access."""
    if connection.check_enable_mode():
        return

    if not ENABLE_SECRET:
        raise RuntimeError(
            "The SSH account is not privilege 15. "
            "Set NETMIKO_ENABLE_SECRET before running the script."
        )

    connection.secret = ENABLE_SECRET
    connection.enable()


def send_timing(connection, command: str, read_timeout: int = 60) -> str:
    """Run a show command without depending heavily on prompt matching."""
    return connection.send_command_timing(
        command,
        read_timeout=read_timeout,
        last_read=2.0,
        strip_prompt=False,
        strip_command=False,
    )


def get_loopbacks(connection) -> List[str]:
    """Return all Loopback interfaces currently configured on a router."""
    output = send_timing(
        connection,
        "show ip interface brief | include ^Loopback",
    )
    loopbacks: List[str] = []

    for line in output.splitlines():
        match = re.match(r"^(Loopback\S+)", line.strip(), re.IGNORECASE)
        if match:
            loopbacks.append(match.group(1))

    return loopbacks


def build_context(name: str, connection) -> Dict[str, Any]:
    """Build the variables passed to the selected Jinja2 template."""
    context: Dict[str, Any] = {
        "device_name": name,
        "mgmt_network": MGMT_NETWORK,
        "lab306_network": LAB306_NETWORK,
        "control_vrf": CONTROL_VRF,
        "ospf_process": OSPF_PROCESS,
        "loopbacks": [],
    }

    if name in {"R1", "R2"}:
        context["loopbacks"] = get_loopbacks(connection)

    return context


def render_config(template_name: str, context: Dict[str, Any]) -> str:
    """Render one Cisco IOS configuration from a Jinja2 template."""
    template = JINJA_ENV.get_template(template_name)
    return template.render(**context)


def config_to_commands(rendered_config: str) -> List[str]:
    """Convert rendered configuration text into Netmiko command lines."""
    commands: List[str] = []

    for raw_line in rendered_config.splitlines():
        line = raw_line.strip()

        if not line:
            continue
        if line.startswith("!"):
            continue

        commands.append(line)

    return commands


def verify(connection, name: str) -> None:
    """Display the main verification commands for each device."""
    print(f"\n{'=' * 25} VERIFY {name} {'=' * 25}")

    if name == "S1":
        commands = [
            "show ip interface brief",
            "show vlan brief",
            "show access-lists VTY_ALLOWED",
            "show running-config | section line vty",
        ]
    elif name == "R1":
        commands = [
            "show ip interface brief",
            f"show ip ospf {OSPF_PROCESS} vrf {CONTROL_VRF} interface brief",
            f"show ip ospf {OSPF_PROCESS} vrf {CONTROL_VRF} neighbor",
            f"show ip route vrf {CONTROL_VRF} ospf",
            "show access-lists",
            "show running-config | section line vty",
        ]
    else:
        commands = [
            "show ip interface brief",
            f"show ip route vrf {CONTROL_VRF} 0.0.0.0",
            f"show ip ospf {OSPF_PROCESS} vrf {CONTROL_VRF} interface brief",
            f"show ip ospf {OSPF_PROCESS} vrf {CONTROL_VRF} neighbor",
            f"show ip route vrf {CONTROL_VRF} ospf",
            "show ip nat statistics",
            "show ip nat translations",
            "show access-lists",
            "show running-config | section line vty",
        ]

    for command in commands:
        print(f"\n--- {command} ---")
        print(send_timing(connection, command))


def configure_device(name: str, device: Dict[str, Any]) -> None:
    """Connect, render the template, apply it, save, and verify."""
    template_name = str(device["template"])
    connection_parameters = {
        key: value
        for key, value in device.items()
        if key != "template"
    }
    connection_parameters["session_log"] = str(
        BASE_DIR / f"netmiko_{name}.log"
    )

    print(f"\n{'#' * 70}")
    print(f"Connecting to {name} ({connection_parameters['host']})")
    print(f"Template: {template_name}")
    print(f"{'#' * 70}")

    connection = ConnectHandler(**connection_parameters)

    try:
        ensure_privileged_mode(connection)

        context = build_context(name, connection)
        rendered_config = render_config(template_name, context)
        commands = config_to_commands(rendered_config)

        print(f"\n--- Rendered configuration for {name} ---")
        print(rendered_config)
        print(f"Sending {len(commands)} commands to {name}...")

        output = connection.send_config_set(
            commands,
            cmd_verify=False,
            read_timeout=120,
        )
        print(output)

        print(f"Saving configuration on {name}...")
        connection.save_config()
        time.sleep(2)

        verify(connection, name)

    finally:
        connection.disconnect()


def main() -> int:
    if not os.path.isfile(KEY_PATH):
        print(f"ERROR: SSH key file was not found: {KEY_PATH}")
        return 1

    if not TEMPLATE_DIR.is_dir():
        print(f"ERROR: Template directory was not found: {TEMPLATE_DIR}")
        return 1

    failed_devices: List[str] = []

    for name, device in DEVICES.items():
        try:
            configure_device(name, device)
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as error:
            failed_devices.append(name)
            print(f"\nERROR on {name}: {error}")
        except Exception as error:
            failed_devices.append(name)
            print(f"\nERROR on {name}: {type(error).__name__}: {error}")

    if failed_devices:
        print("\nFailed devices: " + ", ".join(failed_devices))
        print("Check the matching netmiko_<device>.log session file.")
        return 1

    print("\nConfiguration completed successfully on S1, R1, and R2.")
    return 0


if __name__ == "__main__":
    sys.exit(main())