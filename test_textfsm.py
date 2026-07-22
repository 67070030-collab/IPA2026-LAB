import pytest

import textfsmlab


@pytest.mark.parametrize(
    ("raw_name", "expected"),
    [
        ("GigabitEthernet0/2", "G0/2"),
        ("Gig 0/2", "G0/2"),
        ("Gi0/2", "G0/2"),
        ("TenGigabitEthernet1/0/1", "Te1/0/1"),
        ("FastEthernet0/1", "F0/1"),
    ],
)
def test_short_interface(raw_name, expected):
    assert textfsmlab.short_interface(raw_name) == expected


def test_r1_descriptions_match_topology():
    cdp_neighbors = [
        {
            "neighbor_name": "R2.example.local",
            "local_interface": "Gig 0/2",
            "neighbor_interface": "Gig 0/1",
        }
    ]

    assert textfsmlab.build_descriptions(
        "R1",
        cdp_neighbors,
    ) == {
        "GigabitEthernet0/1": "Connect to PC",
        "GigabitEthernet0/2": "Connect to G0/1 of R2",
    }


def test_r2_descriptions_match_topology():
    cdp_neighbors = [
        {
            "neighbor_name": "R1",
            "local_interface": "Gig 0/1",
            "neighbor_interface": "Gig 0/2",
        },
        {
            "neighbor_name": "S1.lab.local",
            "local_interface": "Gig 0/2",
            "neighbor_interface": "Gig 0/1",
        },
    ]

    assert textfsmlab.build_descriptions(
        "R2",
        cdp_neighbors,
    ) == {
        "GigabitEthernet0/1": "Connect to G0/2 of R1",
        "GigabitEthernet0/2": "Connect to G0/1 of S1",
        "GigabitEthernet0/3": "Connect to WAN",
    }


def test_s1_descriptions_match_topology_and_ignore_management_cdp():
    cdp_neighbors = [
        {
            "neighbor_name": "R2",
            "local_interface": "Gig 0/1",
            "neighbor_interface": "Gig 0/2",
        },
        {
            "neighbor_name": "S0",
            "local_interface": "Gig 0/0",
            "neighbor_interface": "Gig 0/3",
        },
    ]

    assert textfsmlab.build_descriptions(
        "S1",
        cdp_neighbors,
    ) == {
        "GigabitEthernet0/1": "Connect to G0/2 of R2",
        "GigabitEthernet1/1": "Connect to PC",
    }


def test_missing_cdp_connection_fails_validation():
    with pytest.raises(
        textfsmlab.TopologyError,
        match="GigabitEthernet0/2",
    ):
        textfsmlab.build_descriptions("R1", [])


def test_build_config_commands():
    descriptions = {
        "GigabitEthernet0/1": "Connect to PC",
        "GigabitEthernet0/2": "Connect to G0/1 of R2",
    }

    assert textfsmlab.build_config_commands(descriptions) == [
        "interface GigabitEthernet0/1",
        "description Connect to PC",
        "exit",
        "interface GigabitEthernet0/2",
        "description Connect to G0/1 of R2",
        "exit",
    ]


def test_discover_cdp_neighbors_uses_textfsm():
    class FakeConnection:
        def __init__(self):
            self.command = None
            self.options = None

        def send_command(self, command, **kwargs):
            self.command = command
            self.options = kwargs
            return [
                {
                    "neighbor_name": "R2",
                    "local_interface": "Gig 0/2",
                    "neighbor_interface": "Gig 0/1",
                }
            ]

    connection = FakeConnection()
    result = textfsmlab.discover_cdp_neighbors(connection)

    assert connection.command == "show cdp neighbors"
    assert connection.options["use_textfsm"] is True
    assert result[0]["neighbor_name"] == "R2"


def test_raw_cdp_output_is_rejected():
    class FakeConnection:
        def send_command(self, command, **kwargs):
            return "Device ID Local Intrfce Holdtme"

    with pytest.raises(RuntimeError, match="TextFSM did not parse"):
        textfsmlab.discover_cdp_neighbors(FakeConnection())


def test_apply_descriptions_sends_expected_commands():
    class FakeConnection:
        def __init__(self):
            self.commands = None
            self.options = None

        def send_config_set(self, commands, **kwargs):
            self.commands = commands
            self.options = kwargs
            return "OK"

    connection = FakeConnection()
    descriptions = {
        "GigabitEthernet0/3": "Connect to WAN",
    }

    result = textfsmlab.apply_descriptions(
        connection,
        descriptions,
    )

    assert result == "OK"
    assert connection.commands == [
        "interface GigabitEthernet0/3",
        "description Connect to WAN",
        "exit",
    ]
    assert connection.options["cmd_verify"] is False