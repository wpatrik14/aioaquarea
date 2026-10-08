from __future__ import annotations

import datetime as dt
import logging

import pytest

from aioaquarea import AuthenticationError, DateType, Device
from aioaquarea.data import (
    ForceDHW,
    ForceHeater,
    HolidayTimer,
    OperationStatus,
    PowerfulTime,
    QuietMode,
    SpecialStatus,
    UpdateOperationMode,
    ZoneTemperatureSetUpdate,
)

from .conftest import NEW_ACCESS_TOKEN, load_fixture, mock_refresh_flow

BASE = "https://accsmart.panasonic.com"
TRANSFER = f"{BASE}/remote/v1/app/common/transfer"
LONG_ID = "009A2W0000000001"
DEVICE_URL = f"{BASE}/remote/v1/api/devices/{LONG_ID}"


def sent(mocked):
    return [c.kwargs["json"] for v in mocked.requests.values() for c in v if "json" in c.kwargs]


async def test_operation_status(logged_client, mocked):
    mocked.post(DEVICE_URL, payload={})
    await logged_client.post_device_operation_status(LONG_ID, OperationStatus.ON)
    assert sent(mocked) == [{"status": [{"deviceGuid": LONG_ID, "operationStatus": 1}]}]


async def test_tank_temperature(logged_client, mocked):
    mocked.post(TRANSFER, payload={})
    await logged_client.post_device_tank_temperature(LONG_ID, 52)
    (body,) = sent(mocked)
    assert body["apiName"] == "/remote/v1/api/devices"
    assert body["bodyParam"]["gwid"] == LONG_ID
    assert body["bodyParam"]["tankStatus"]["heatSet"] == 52


async def test_tank_operation_status(logged_client, mocked):
    z = [await _zone_status(logged_client, mocked)]
    mocked.post(TRANSFER, payload={})
    await logged_client.post_device_tank_operation_status(LONG_ID, OperationStatus.OFF, z)
    body = sent(mocked)[-1]
    assert body["bodyParam"]["tankStatus"]["operationStatus"] == 0


async def _zone_status(client, mocked):
    mocked.post(TRANSFER, payload=load_fixture("device_status.json"))
    from aioaquarea.data import DeviceInfo, OperationMode, StatusDataMode

    status = await client.get_device_status(
        DeviceInfo(LONG_ID, "n", LONG_ID, OperationMode.Heat, True, "", "", [], StatusDataMode.LIVE)
    )
    return status.zones[0]


async def test_operation_update_with_temperatures(logged_client, mocked):
    mocked.post(TRANSFER, payload={})
    await logged_client.post_device_operation_update(
        LONG_ID,
        UpdateOperationMode.HEAT,
        {1: OperationStatus.ON, 2: OperationStatus.OFF},
        OperationStatus.ON,
        OperationStatus.OFF,
        [ZoneTemperatureSetUpdate(1, cool_set=15, heat_set=27), ZoneTemperatureSetUpdate(2, None, None)],
    )
    (body,) = sent(mocked)
    assert body["bodyParam"] == {
        "gwid": LONG_ID,
        "operationMode": 2,
        "operationStatus": 1,
        "zoneStatus": [
            {"zoneId": 1, "operationStatus": 1, "heatSet": 27, "coolSet": 15},
            {"zoneId": 2, "operationStatus": 0},
        ],
        "tankStatus": {"operationStatus": 0},
    }


async def test_special_status(logged_client, mocked):
    mocked.post(DEVICE_URL, payload={})
    await logged_client.post_device_set_special_status(
        LONG_ID,
        SpecialStatus.ECO,
        [ZoneTemperatureSetUpdate(1, cool_set=None, heat_set=24), ZoneTemperatureSetUpdate(2, 12, 23)],
    )
    mocked.post(DEVICE_URL, payload={})
    await logged_client.post_device_set_special_status(LONG_ID, None, [])
    first, second = sent(mocked)
    assert first["status"][0]["specialStatus"] == 1
    assert first["status"][0]["zoneStatus"] == [
        {"zoneId": 1, "heatSet": 24},
        {"zoneId": 2, "heatSet": 23, "coolSet": 12},
    ]
    assert second["status"][0]["specialStatus"] == 0


@pytest.mark.parametrize(
    ("method", "key"),
    [("post_device_zone_heat_temperature", "heatSet"), ("post_device_zone_cool_temperature", "coolSet")],
)
async def test_zone_temperatures(logged_client, mocked, method, key):
    mocked.post(TRANSFER, payload={})
    await getattr(logged_client, method)(LONG_ID, 2, 21)
    (body,) = sent(mocked)
    assert body["bodyParam"] == {"gwid": LONG_ID, "zoneStatus": [{"zoneId": 2, key: 21}]}


@pytest.mark.parametrize(
    ("method", "arg", "param"),
    [
        ("post_device_set_quiet_mode", QuietMode.LEVEL2, {"quietMode": 2}),
        ("post_device_force_dhw", ForceDHW.ON, {"forceDHW": 1}),
        ("post_device_force_heater", ForceHeater.ON, {"forceHeater": 1}),
        ("post_device_holiday_timer", HolidayTimer.ON, {"holidayTimer": 1}),
        ("post_device_set_powerful_time", PowerfulTime.ON_60MIN, {"powerfulRequest": 2}),
    ],
)
async def test_simple_commands(logged_client, mocked, method, arg, param):
    mocked.post(TRANSFER, payload={})
    await getattr(logged_client, method)(LONG_ID, arg)
    (body,) = sent(mocked)
    assert body["apiName"] == "/remote/v1/api/devices"
    assert body["requestMethod"] == "POST"
    assert body["bodyParam"] == {"gwid": LONG_ID, **param}


async def test_defrost(logged_client, mocked):
    mocked.post(TRANSFER, payload={})
    await logged_client.post_device_request_defrost(LONG_ID)
    assert sent(mocked)[0]["bodyParam"] == {"gwid": LONG_ID, "forcedefrost": 1}


async def test_command_relogins_on_token_expiry(logged_client, mocked):
    mocked.post(TRANSFER, payload={"message": [{"errorCode": "1", "errorMessage": "Token expires"}]})
    mock_refresh_flow(mocked)
    mocked.post(TRANSFER, payload={})
    logged_client._last_login = dt.datetime.min
    await logged_client.post_device_request_defrost(LONG_ID)
    assert logged_client._settings.access_token == NEW_ACCESS_TOKEN


async def test_command_http_401_triggers_relogin(logged_client, mocked):
    mocked.post(TRANSFER, status=401, body="")
    mock_refresh_flow(mocked)
    mocked.post(TRANSFER, payload={})
    logged_client._last_login = dt.datetime.min
    await logged_client.post_device_zone_heat_temperature(LONG_ID, 1, 20)
    assert logged_client._settings.access_token == NEW_ACCESS_TOKEN


async def test_login_error_propagates_from_command(logged_client, mocked):
    logged_client._refresh_login = False
    mocked.post(TRANSFER, status=401, body="")
    with pytest.raises(AuthenticationError):
        await logged_client.post_device_request_defrost(LONG_ID)


# ---------------------------------------------------------------- consumption


async def test_consumption_month(logged_client, mocked):
    mocked.post(TRANSFER, payload=load_fixture("consumption_month.json"))
    items = await logged_client.get_device_consumption(LONG_ID, DateType.MONTH, "20250501")
    assert [i.data_time for i in items] == ["20250513", "20250514"]
    first, second = items
    assert first.heat_consumption == 4.522
    assert first.cool_consumption is None
    assert first.total_consumption == pytest.approx(6.043)
    assert second.total_consumption == pytest.approx(4.5)
    assert first.outdoor_temp == 9.90625
    assert first.heat_cost == 11.19756 and first.tank_cost == 2.00772
    assert second.cool_cost == 1.0 and first.cool_cost is None
    assert first.tank_consumption == 1.521
    assert first.raw_data["dataTime"] == "20250513"
    (body,) = sent(mocked)
    assert body["bodyParam"] == {
        "gwid": LONG_ID, "dataMode": 1, "date": "20250501", "osTimezone": "+00:00"
    }


@pytest.mark.parametrize(("agg", "mode"), [(DateType.DAY, 0), (DateType.YEAR, 2), (DateType.WEEK, 0)])
async def test_consumption_modes(logged_client, mocked, agg, mode):
    mocked.post(TRANSFER, payload=load_fixture("consumption_month.json"))
    await logged_client.get_device_consumption(LONG_ID, agg, "20250513")
    assert sent(mocked)[0]["bodyParam"]["dataMode"] == mode


async def test_consumption_empty_returns_none(logged_client, mocked):
    mocked.post(TRANSFER, payload={"historyDataList": []})
    assert await logged_client.get_device_consumption(LONG_ID, DateType.DAY, "20250513") is None


async def test_consumption_empty_item_total_is_none(logged_client, mocked):
    from aioaquarea.statistics import Consumption

    assert Consumption({}).total_consumption is None


async def test_consumption_api_error_returns_none(logged_client, mocked):
    mocked.post(TRANSFER, payload={"message": [{"errorCode": "5000", "errorMessage": "bad"}]})
    assert await logged_client.get_device_consumption(LONG_ID, DateType.DAY, "20250513") is None


async def test_consumption_unexpected_error_returns_none(logged_client, mocked, caplog):
    mocked.post(TRANSFER, payload=[1], repeat=False)
    with caplog.at_level(logging.WARNING):
        assert await logged_client.get_device_consumption(LONG_ID, DateType.DAY, "20250513") is None


async def test_consumption_auth_error_not_swallowed(logged_client, mocked):
    logged_client._refresh_login = False
    mocked.post(TRANSFER, status=401, body="")
    with pytest.raises(AuthenticationError):
        await logged_client.get_device_consumption(LONG_ID, DateType.DAY, "20250513")


# ------------------------------------------------------------------- entities


async def make_device(client, mocked, status_fixture="device_status.json", interval=None) -> Device:
    Device._zones = {}  # class-level dict shared between instances
    mocked.get(f"{BASE}/device/group", payload=load_fixture("groups.json"))
    mocked.post(TRANSFER, payload=load_fixture(status_fixture))
    if interval:
        mocked.post(TRANSFER, payload=load_fixture("consumption_month.json"))
    infos = await client.get_devices()
    return await client.get_device(
        device_info=infos[0], consumption_refresh_interval=interval
    )


async def test_device_properties(logged_client, mocked):
    from aioaquarea.data import (
        DeviceAction,
        DeviceDirection,
        DeviceModeStatus,
        ExtendedOperationMode,
    )

    dev = await make_device(logged_client, mocked)
    assert dev.mode == ExtendedOperationMode.HEAT
    assert dev.temperature_outdoor == 21
    assert dev.is_on_error and dev.current_error.error_code == "H62"
    assert dev.operation_status == OperationStatus.ON
    assert dev.device_id == LONG_ID and dev.long_id == LONG_ID
    assert dev.device_name == "Aquarea" and dev.model == "N/A" and dev.firmware_version == "N/A"
    assert dev.has_tank and dev.water_pressure == 1.6 and dev.pump_duty == 1
    assert dev.current_direction == DeviceDirection.PUMP
    assert dev.current_action == DeviceAction.HEATING
    assert dev.quiet_mode == QuietMode.LEVEL1 and dev.force_dhw == ForceDHW.ON
    assert dev.force_heater == ForceHeater.OFF and dev.holiday_timer == HolidayTimer.OFF
    assert dev.powerful_time == PowerfulTime.ON_30MIN
    assert dev.device_mode_status == DeviceModeStatus.NORMAL
    assert dev.special_status is None
    assert dev.support_cooling(1) and not dev.support_cooling(2) and not dev.support_cooling(9)
    assert dev.support_special_status in (True, False)
    assert dev.heat_max == 30 and dev.cool_max == 20
    tank = dev.tank
    assert (tank.temperature, tank.heat_max, tank.heat_min, tank.target_temperature) == (48, 65, 40, 50)
    assert tank.operation_status == OperationStatus.ON
    zone = dev.zones[1]
    assert (zone.zone_id, zone.name, zone.temperature) == (1, "Zone 1", 28)
    assert zone.cool_mode and zone.supports_set_temperature
    assert zone.heat_target_temperature == 26 and zone.cool_target_temperature == 14
    assert (zone.heat_min, zone.heat_max, zone.cool_min, zone.cool_max) == (20, 30, 10, 20)
    assert zone.type and zone.sensor_mode and zone.heat_sensor_mode and zone.cool_sensor_mode
    assert zone.eco.heat == -2 and zone.comfort.cool == -2
    assert set(zone.temperature_modifiers) == {SpecialStatus.ECO, SpecialStatus.COMFORT}
    assert zone.operation_status == OperationStatus.ON
    assert isinstance(zone.supports_special_status, bool)


async def test_device_actions(logged_client, mocked):
    dev = await make_device(logged_client, mocked)
    mocked.post(TRANSFER, payload={}, repeat=True)
    mocked.post(DEVICE_URL, payload={}, repeat=True)
    await dev.turn_on()  # already on: no-op
    await dev.turn_off()
    await dev.set_mode(UpdateOperationMode.COOL, zone_id=1)
    await dev.set_mode(UpdateOperationMode.OFF)
    await dev.set_temperature(23, zone_id=1)
    await dev.set_temperature(23)  # no zone: ignored
    await dev.set_temperature(23, zone_id=9)  # unknown zone: ignored
    await dev.set_quiet_mode(QuietMode.OFF)
    await dev.set_force_dhw(ForceDHW.OFF)
    await dev.set_force_heater(ForceHeater.ON)
    await dev.set_force_heater(ForceHeater.OFF)  # unchanged: no-op
    await dev.request_defrost()
    await dev.set_holiday_timer(HolidayTimer.ON)
    await dev.set_powerful_time(PowerfulTime.ON_90MIN)
    await dev.set_powerful_time(PowerfulTime.ON_30MIN)  # unchanged
    await dev.tank.set_target_temperature(55)
    await dev.tank.turn_off()
    await dev.tank.turn_on()
    bodies = sent(mocked)
    assert {"status": [{"deviceGuid": LONG_ID, "operationStatus": 0}]} in bodies
    assert any(b.get("bodyParam", {}).get("operationMode") == 3 for b in bodies)
    assert any(b.get("bodyParam", {}).get("zoneStatus") == [{"zoneId": 1, "heatSet": 23}] for b in bodies)
    assert any(b.get("bodyParam", {}).get("forcedefrost") == 1 for b in bodies)
    assert not any(b.get("bodyParam", {}).get("powerfulRequest") == 1 for b in bodies)


async def test_set_temperature_in_cool_mode(logged_client, mocked):
    dev = await make_device(logged_client, mocked)
    dev._status.operation_mode = __import__("aioaquarea").ExtendedOperationMode.COOL
    mocked.post(TRANSFER, payload={})
    await dev.set_temperature(16, zone_id=1)
    assert sent(mocked)[-1]["bodyParam"]["zoneStatus"] == [{"zoneId": 1, "coolSet": 16}]


async def test_device_special_status(logged_client, mocked):
    dev = await make_device(logged_client, mocked)
    mocked.post(DEVICE_URL, payload={}, repeat=True)
    if dev.support_special_status:
        await dev.set_special_status(SpecialStatus.ECO)
        assert sent(mocked)[-1]["status"][0]["specialStatus"] == 1
        dev._status.special_status = SpecialStatus.ECO
        await dev.set_special_status(SpecialStatus.COMFORT)
        await dev.set_special_status(None)
    else:
        with pytest.raises(Exception, match="special status"):
            await dev.set_special_status(SpecialStatus.ECO)


async def test_refresh_data_and_consumption(logged_client, mocked):
    from aioaquarea.errors import DataNotAvailableError
    from aioaquarea.statistics import ConsumptionType

    interval = dt.timedelta(minutes=30)
    dev = await make_device(logged_client, mocked, interval=interval)
    day = dt.datetime(2025, 5, 13)
    assert dev.get_or_schedule_consumption(day, ConsumptionType.HEAT) == 4.522
    assert dev.get_or_schedule_consumption(day, ConsumptionType.COOL) is None
    assert dev.get_or_schedule_consumption(day, ConsumptionType.WATER_TANK) == 1.521
    assert dev.get_or_schedule_consumption(day, ConsumptionType.TOTAL) == pytest.approx(6.043)
    with pytest.raises(DataNotAvailableError):
        dev.get_or_schedule_consumption(dt.datetime(2020, 1, 1), ConsumptionType.HEAT)

    mocked.post(TRANSFER, payload=load_fixture("consumption_month.json"))
    mocked.post(TRANSFER, payload=load_fixture("consumption_month.json"))
    dev._last_consumption_refresh = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)
    dev._consumption.clear()
    assert await dev.get_and_refresh_consumption(day, ConsumptionType.HEAT) == 4.522
    with pytest.raises(DataNotAvailableError):
        await dev.get_and_refresh_consumption(dt.datetime(2020, 1, 1), ConsumptionType.HEAT)
    mocked.post(TRANSFER, payload=load_fixture("device_status.json"))
    mocked.post(TRANSFER, payload=load_fixture("consumption_month.json"))
    await dev.refresh_data()


async def test_consumption_lock_and_disabled(logged_client, mocked):
    dev = await make_device(logged_client, mocked)
    await dev.__refresh_consumption__()  # no interval: no-op
    dev._consumption_refresh_interval = dt.timedelta(minutes=1)
    await dev._consumption_refresh_lock.acquire()
    await dev.__refresh_consumption__()  # locked: skipped
    dev._consumption_refresh_lock.release()


async def test_device_without_tank_and_idle(logged_client, mocked):
    from aioaquarea.data import DeviceAction

    dev = await make_device(logged_client, mocked, "device_status_no_tank.json")
    assert dev.tank is None
    assert dev.current_action == DeviceAction.OFF
    assert not dev.is_on_error and dev.current_error is None
    await dev.turn_off()  # already off
    mocked.post(TRANSFER, payload={}, repeat=True)
    mocked.post(DEVICE_URL, payload={}, repeat=True)
    await dev.turn_on()


async def test_get_device_by_id(logged_client, mocked):
    Device._zones = {}
    mocked.get(f"{BASE}/device/group", payload=load_fixture("groups.json"))
    mocked.post(TRANSFER, payload=load_fixture("device_status.json"))
    dev = await logged_client.get_device(device_id="009A2W0000000001")
    assert dev.device_id == "009A2W0000000001"
    with pytest.raises(ValueError):
        await logged_client.get_device(device_id="missing")
    with pytest.raises(ValueError):
        await logged_client.get_device()
