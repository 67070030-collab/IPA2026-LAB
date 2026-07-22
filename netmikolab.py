import os
import re
import sys
import time
import warnings
from typing import Dict, List

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
    "conn_timeout": 15,
    "auth_timeout": 20,
    "banner_timeout": 20,
    "disabled_algorithms":{
                "pubkeys": [
                    "rsa-sha2-512",
                    "rsa-sha2-256",
                ]
            },
}

DEVICES = {
    "S1": {**COMMON_DEVICE, "host": "172.31.2.3"},
    "R1": {**COMMON_DEVICE, "host": "172.31.2.4"},
    "R2": {**COMMON_DEVICE, "host": "172.31.2.5"},
}

MGMT_NETWORK = "172.31.2.0 0.0.0.15"  # 172.31.2.0/28
LAB306_NETWORK = "192.168.0.0 0.0.255.255"  # 10.30.6.0/24


def ensure_privileged_mode(connection) -> None:
    """Make sure the account can enter configuration mode."""
    if connection.check_enable_mode():
        return

    if not ENABLE_SECRET:
        raise RuntimeError(
            "The SSH account is not privilege 15. "
            "Set NETMIKO_ENABLE_SECRET before running the script."
        )

    connection.secret = ENABLE_SECRET
    connection.enable()


def get_loopbacks(connection) -> List[str]:
    """Return all Loopback interfaces currently configured on a router."""
    output = connection.send_command(
        "show ip interface brief | include ^Loopback"
    )
    loopbacks: List[str] = []

    for line in output.splitlines():
        match = re.match(r"^(Loopback\S+)", line.strip(), re.IGNORECASE)
        if match:
            loopbacks.append(match.group(1))

    return loopbacks


def configure_s1(connection) -> None:
    """Separate VLAN 99 management plane from VLAN 101 control/data plane."""
    commands = [
        "vlan 99",
        "name MANAGEMENT",
        "exit",
        "vlan 101",
        "name CONTROL_DATA",
        "exit",
        "interface GigabitEthernet0/0",
        "description MANAGEMENT_TO_S0_G0/3",
        "switchport mode access",
        "switchport access vlan 99",
        "no shutdown",
        "exit",
        "interface GigabitEthernet0/1",
        "description CONTROL_DATA_TO_R2_G0/2",
        "switchport mode access",
        "switchport access vlan 101",
        "no shutdown",
        "exit",
        "interface GigabitEthernet1/1",
        "description CONTROL_DATA_TO_UBUNTU_CLOUD_GUEST",
        "switchport mode access",
        "switchport access vlan 101",
        "spanning-tree portfast",
        "no shutdown",
        "exit",
        "interface Vlan99",
        "description MANAGEMENT_SVI",
        "ip address 172.31.2.3 255.255.255.240",
        "no shutdown",
        "exit",
        "ip default-gateway 172.31.2.1",
        "no ip access-list standard VTY_ALLOWED",
        "ip access-list standard VTY_ALLOWED",
        f"10 permit {MGMT_NETWORK}",
        f"20 permit {LAB306_NETWORK}",
        "90 deny any log",
        "exit",
        "line vty 0 15",
        "access-class VTY_ALLOWED in",
        "login local",
        "transport input ssh telnet",
        "exec-timeout 15 0",
        "exit",
    ]

    print(connection.send_config_set(commands))


def configure_r1(connection) -> None:
    """Configure OSPF and protect the management plane on R1."""
    loopbacks = get_loopbacks(connection)

    commands = [
        "no ip access-list standard VTY_ALLOWED",
        "ip access-list standard VTY_ALLOWED",
        f"10 permit {MGMT_NETWORK}",
        f"20 permit {LAB306_NETWORK}",
        "90 deny any log",
        "exit",
        "no ip access-list extended BLOCK_MGMT_PLANE",
        "ip access-list extended BLOCK_MGMT_PLANE",
        f"10 deny ip any {MGMT_NETWORK}",
        "20 permit ip any any",
        "exit",
        "interface GigabitEthernet0/1",
        "description CONTROL_DATA_TO_UBUNTU_DESKTOP",
        "ip access-group BLOCK_MGMT_PLANE in",
        "ip ospf 1 area 0",
        "no shutdown",
        "exit",
        "interface GigabitEthernet0/2",
        "description CONTROL_DATA_TO_R2_G0/1",
        "ip ospf 1 area 0",
        "no shutdown",
        "exit",
    ]

    for interface in loopbacks:
        commands.extend(
            [
                f"interface {interface}",
                "ip ospf 1 area 0",
                "exit",
            ]
        )

    commands.extend(
        [
            "router ospf 1 vrf control-data",
            "passive-interface default",
            "no passive-interface GigabitEthernet0/2",
            "log-adjacency-changes",
            "exit",
            "line vty 0 15",
            "access-class VTY_ALLOWED in",
            "login local",
            "transport input ssh telnet",
            "exec-timeout 15 0",
            "exit",
        ]
    )

    print(connection.send_config_set(commands))


def configure_r2(connection) -> None:
    """Configure OSPF, DHCP outside interface, PAT, and management protection."""
    loopbacks = get_loopbacks(connection)

    commands = [
        "no ip access-list standard VTY_ALLOWED",
        "ip access-list standard VTY_ALLOWED",
        f"10 permit {MGMT_NETWORK}",
        f"20 permit {LAB306_NETWORK}",
        "90 deny any log",
        "exit",
        "no ip access-list standard NAT_INSIDE",
        "ip access-list standard NAT_INSIDE",
        "10 permit any",
        "exit",
        "no ip access-list extended BLOCK_MGMT_PLANE",
        "ip access-list extended BLOCK_MGMT_PLANE",
        f"10 deny ip any {MGMT_NETWORK}",
        "20 permit ip any any",
        "exit",
        "interface GigabitEthernet0/1",
        "description CONTROL_DATA_TO_R1_G0/2",
        "ip nat inside",
        "ip ospf 1 area 0",
        "no shutdown",
        "exit",
        "interface GigabitEthernet0/2",
        "description CONTROL_DATA_TO_S1_G0/1",
        "ip nat inside",
        "ip access-group BLOCK_MGMT_PLANE in",
        "ip ospf 1 area 0",
        "no shutdown",
        "exit",
        "interface GigabitEthernet0/3",
        "description NAT_CLOUD",
        "ip address dhcp",
        "ip nat outside",
        "no shutdown",
        "exit",
        "ip nat inside source list NAT_INSIDE interface GigabitEthernet0/3 overload",
    ]

    for interface in loopbacks:
        commands.extend(
            [
                f"interface {interface}",
                "ip ospf 1 area 0",
                "exit",
            ]
        )

    commands.extend(
        [
            "router ospf 1 vrf control-data",
            "passive-interface default",
            "no passive-interface GigabitEthernet0/1",
            "default-information originate",
            "log-adjacency-changes",
            "exit",
            "line vty 0 15",
            "access-class VTY_ALLOWED in",
            "login local",
            "transport input ssh telnet",
            "exec-timeout 15 0",
            "exit",
        ]
    )

    print(connection.send_config_set(commands))


def verify(connection, name: str) -> None:
    """Print the main verification commands for each device."""
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
            "show ip ospf interface brief",
            "show ip ospf neighbor",
            "show ip route ospf",
            "show access-lists",
            "show running-config | section line vty",
        ]
    else:
        commands = [
            "show ip interface brief",
            "show ip route 0.0.0.0",
            "show ip ospf interface brief",
            "show ip ospf neighbor",
            "show ip route ospf",
            "show ip nat statistics",
            "show ip nat translations",
            "show access-lists",
            "show running-config | section line vty",
        ]

    for command in commands:
        print(f"\n--- {command} ---")
        print(connection.send_command(command, read_timeout=30))


def configure_device(name: str, parameters: Dict[str, object]) -> None:
    print(f"\n{'#' * 70}")
    print(f"Connecting to {name} ({parameters['host']})")
    print(f"{'#' * 70}")

    connection = ConnectHandler(**parameters)

    try:
        ensure_privileged_mode(connection)

        if name == "S1":
            configure_s1(connection)
        elif name == "R1":
            configure_r1(connection)
        elif name == "R2":
            configure_r2(connection)
        else:
            raise ValueError(f"Unsupported device: {name}")

        connection.save_config()
        time.sleep(2)
        verify(connection, name)

    finally:
        connection.disconnect()


def main() -> int:
    if not os.path.isfile(KEY_PATH):
        print(f"ERROR: SSH key file was not found: {KEY_PATH}")
        return 1

    failed_devices: List[str] = []

    for name, parameters in DEVICES.items():
        try:
            configure_device(name, parameters)
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as error:
            failed_devices.append(name)
            print(f"\nERROR on {name}: {error}")
        except Exception as error:
            failed_devices.append(name)
            print(f"\nERROR on {name}: {type(error).__name__}: {error}")

    if failed_devices:
        print("\nFailed devices: " + ", ".join(failed_devices))
        return 1

    print("\nConfiguration completed successfully on S1, R1, and R2.")
    return 0


if __name__ == "__main__":
    sys.exit(main())