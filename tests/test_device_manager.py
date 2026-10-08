from __future__ import annotations

import logging

import pytest

from aioaquarea import AuthenticationError, AuthenticationErrorCodes, RequestFailedError
from aioaquarea.data import (
    DeviceDirection,
    DeviceInfo,
    DeviceModeStatus,
    ExtendedOperationMode,
    ForceDHW,
    OperationMode,
    OperationStatus,
    PumpDuty,
    QuietMode,
    StatusDataMode,
)
from aioaquarea.errors import InvalidData

from .conftest import load_fixture

BASE = "https://accsmart.panasonic.com"
GROUP = f"{BASE}/device/group"
TRANSFER = f"{BASE}/remote/v1/app/common/transfer"


def info(device_id="009A2W0000000001"):
    return DeviceInfo(device_id, "n", device_id, OperationMode.Heat, True, "N/A", "N/A", [], StatusDataMode.LIVE)


async def test_get_devices_parses_groups(logged_client, mocked):
    mocked.get(GROUP, payload=load_fixture("groups.json"))
    devices = await logged_client.get_devices()
    assert [d.device_id for d in devices] == ["009A2W0000000001", "009A2W0000000002"]
    first, second = devices
    assert first.name == "Aquarea"
    assert first.has_tank is True
    assert [z.zone_id for z in first.zones] == [1, 2]
    assert first.zones[0].cool_mode is True  # coolMin/coolMax present
    assert first.zones[1].cool_mode is False
    assert second.has_tank is False  # empty tankStatus
    assert second.name == "Unknown Device"
    assert second.zones[0].cool_mode is True  # device operationMode 2 = cool
    # cached: no second request
    await logged_client.get_devices()
    assert sum(len(v) for v in mocked.requests.values()) == 1


async def test_get_devices_without_group_list(logged_client, mocked):
    mocked.get(GROUP, payload={})
    assert await logged_client.get_devices() == []


async def test_get_device_status_full(logged_client, mocked):
    mocked.post(TRANSFER, payload=load_fixture("device_status.json"))
    status = await logged_client.get_device_status(info())
    assert status.operation_status == OperationStatus.ON
    assert status.operation_mode == ExtendedOperationMode.HEAT
    assert status.device_status == DeviceModeStatus.NORMAL
    assert status.temperature_outdoor == 21
    assert status.pump_duty == PumpDuty.ON
    assert status.direction == DeviceDirection.PUMP
    assert status.water_pressure == 1.6
    assert status.quiet_mode == QuietMode.LEVEL1
    assert status.force_dhw == ForceDHW.ON
    assert status.fault_status[0].error_code == "H62"
    assert status.fault_status[0].error_message == "Water pressure low"
    tank = status.tank_status[0]
    assert (tank.temperature, tank.heat_max, tank.heat_min, tank.heat_set) == (48, 65, 40, 50)
    z1, z2 = status.zones
    assert (z1.zone_id, z1.temperature, z1.heat_set, z1.cool_set) == (1, 28, 26, 14)
    assert (z1.comfort_heat, z1.eco_cool) == (2, 2)
    assert z2.cool_set is None


async def test_get_device_status_without_tank_and_off_mode(logged_client, mocked):
    mocked.post(TRANSFER, payload=load_fixture("device_status_no_tank.json"))
    status = await logged_client.get_device_status(info())
    assert status.tank_status == []
    assert status.operation_mode == ExtendedOperationMode.OFF
    assert status.fault_status == []
    assert status.device_status == DeviceModeStatus.DEFROST
    assert status.water_pressure is None
    assert status.operation_status == OperationStatus.OFF


async def test_live_failure_falls_back_to_cached(logged_client, mocked):
    mocked.post(TRANSFER, status=500, body="x")
    mocked.post(TRANSFER, payload=load_fixture("device_status.json"))
    status = await logged_client.get_device_status(info())
    assert status.temperature_outdoor == 21
    payloads = [c.kwargs["json"]["apiName"] for v in mocked.requests.values() for c in v]
    assert payloads[0].endswith("deviceDirect=1") and payloads[1].endswith("deviceDirect=0")


async def test_both_attempts_failing(logged_client, mocked):
    mocked.post(TRANSFER, status=500, body="x", repeat=True)
    with pytest.raises(RequestFailedError):
        await logged_client.get_device_status(info())


async def test_auth_error_is_not_swallowed(logged_client, mocked):
    logged_client._refresh_login = False
    mocked.post(
        TRANSFER,
        payload={"message": [{"errorCode": "1", "errorMessage": "Token expires"}]},
        repeat=True,
    )
    with pytest.raises(AuthenticationError) as exc:
        await logged_client.get_device_status(info())
    assert exc.value.error_code == AuthenticationErrorCodes.TOKEN_EXPIRED
    # no fallback request after the auth error
    assert sum(len(v) for v in mocked.requests.values()) == 1


async def test_auth_error_on_cached_attempt_not_swallowed(logged_client, mocked):
    logged_client._refresh_login = False
    mocked.post(TRANSFER, status=500, body="x")
    mocked.post(TRANSFER, status=401, body="x")
    with pytest.raises(AuthenticationError):
        await logged_client.get_device_status(info())


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"status": None},
        {"status": {"operationMode": 2, "specialStatus": 1, "deiceStatus": "boom"}},
        {"status": {"operationMode": 2, "specialStatus": 1, "deiceStatus": 0, "faultStatus": [{"x": 1}]}},
        {"status": {"operationMode": 2, "specialStatus": 1, "deiceStatus": 0, "zoneStatus": ["bad"], "direction": 99}},
    ],
)
async def test_invalid_status_json_raises_invalid_data(logged_client, mocked, payload):
    mocked.post(TRANSFER, payload=payload)
    with pytest.raises(InvalidData):
        await logged_client.get_device_status(info())


async def test_status_logs_do_not_dump_payload(logged_client, mocked, caplog):
    caplog.set_level(logging.DEBUG)
    status = load_fixture("device_status.json")
    status["a2wName"] = "VERY-SPECIFIC-NAME"
    mocked.post(TRANSFER, payload=status)
    await logged_client.get_device_status(info())
    mocked.get(GROUP, payload=load_fixture("groups.json"))
    await logged_client.get_devices()
    assert "VERY-SPECIFIC-NAME" not in caplog.text
    assert "temperatureNow" not in caplog.text
    assert all(r.levelno <= logging.DEBUG for r in caplog.records if "aioaquarea.device_manager" in r.name)


async def test_device_status_on_without_preset(logged_client, mocked):
    """A zone heating with no eco/comfort preset (specialStatus 0) is on and heating."""
    payload = load_fixture("device_status.json")
    payload["status"]["specialStatus"] = 0
    mocked.post(TRANSFER, payload=payload)
    status = await logged_client.get_device_status(info())
    assert status.operation_status == OperationStatus.ON


async def test_device_status_on_with_only_tank(logged_client, mocked):
    payload = load_fixture("device_status.json")
    payload["status"]["specialStatus"] = 0
    for zone in payload["status"]["zoneStatus"]:
        zone["operationStatus"] = 0
    mocked.post(TRANSFER, payload=payload)
    status = await logged_client.get_device_status(info())
    assert status.operation_status == OperationStatus.ON


async def test_device_status_off_with_eco_preset(logged_client, mocked):
    """specialStatus 1 (eco) must not make a device with everything off look on."""
    payload = load_fixture("device_status_no_tank.json")
    payload["status"]["specialStatus"] = 1
    mocked.post(TRANSFER, payload=payload)
    status = await logged_client.get_device_status(info())
    assert status.operation_status == OperationStatus.OFF
