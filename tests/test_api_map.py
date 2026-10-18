"""Tests built from the (sanitized) live API map responses in fixtures/live.

See docs/api-map.md for where these shapes come from.
"""

from __future__ import annotations

import copy
import datetime as dt

import pytest

from aioaquarea import (
    AgreementNotAcceptedError,
    ApiError,
    DateType,
    RequestFailedError,
    SpecialStatus,
    StatusDataMode,
    ZoneSensor,
    ZoneType,
)
from aioaquarea.api_client import AquareaAPIClient
from aioaquarea.data import (
    DeviceAction,
    DeviceDirection,
    DeviceInfo,
    DeviceZoneInfo,
    OperationMode,
    OperationStatus,
    SensorMode,
    parse_special_status,
)
from aioaquarea.device_manager import parse_device_status
from aioaquarea.errors import InvalidData
from aioaquarea.statistics import Consumption, ConsumptionReport, ConsumptionType
from aioaquarea.util import limit_range

from .conftest import load_fixture

BASE = "https://accsmart.panasonic.com"
GROUP = f"{BASE}/device/group"
TRANSFER = f"{BASE}/remote/v1/app/common/transfer"
AGREEMENT = f"{BASE}/auth/v2/agreement/status"
LONG_ID = "009A2W0000000001"


def live(name):
    return load_fixture(f"live/{name}.json")


def sent(mocked):
    return [c.kwargs["json"] for v in mocked.requests.values() for c in v if "json" in c.kwargs]


def info(zones=None, has_tank=True):
    return DeviceInfo(
        LONG_ID, "n", LONG_ID, OperationMode.Heat, has_tank, "N/A", "N/A", zones or [], StatusDataMode.LIVE
    )


async def make_device(client, mocked, status=None, group=None):
    mocked.get(GROUP, payload=group or live("device_group"))
    mocked.post(TRANSFER, payload=status or live("status_direct1"))
    (device_info,) = await client.get_devices()
    return await client.get_device(device_info=device_info)


# ------------------------------------------------------------- device list


async def test_device_list_fields_and_no_phantom_zone(logged_client, mocked):
    mocked.get(GROUP, payload=live("device_group"))
    (device,) = await logged_client.get_devices()
    assert device.connection_status == 0
    assert device.dhw_flag is False
    assert device.has_tank is True
    # the unconfigured zone 2 ({"zoneId": 2}) is not a zone
    assert [z.zone_id for z in device.zones] == [1]
    assert device.zones[0].type == ZoneType.UNKNOWN == "Unknown"
    assert device.zones[0].zone_sensor == ZoneSensor.UNKNOWN


async def test_device_list_tolerates_missing_keys(logged_client, mocked):
    group = live("device_group")
    dev = group["groupList"][0]["deviceList"][0]
    for key in ("connectionStatus", "dhwFlg", "zoneStatus", "tankStatus"):
        del dev[key]
    mocked.get(GROUP, payload=group)
    (device,) = await logged_client.get_devices()
    assert device.connection_status is None and device.dhw_flag is None
    assert device.zones == [] and device.has_tank is False


# ------------------------------------------------------------- device status


async def test_live_status_fields(logged_client, mocked):
    mocked.post(TRANSFER, payload=live("status_direct1"))
    status = await logged_client.get_device_status(info())
    assert status.data_mode == StatusDataMode.LIVE
    assert status.special_status is None  # specialStatus 0 = no preset
    assert status.operation_status == OperationStatus.OFF  # zone and tank off
    assert status.water_pressure == 0
    assert status.direction == DeviceDirection.PUMP
    assert (status.cool_mode, status.tank_flag) == (2, 1)
    assert status.service_type == "STD_ADP-TAW1"
    assert status.uncontrollable is False
    assert (status.bivalent, status.bivalent_actual, status.external_heater) == (0, 0, 0)
    assert (status.electric_anode, status.control_box, status.stand_alone) == (0, 0, 0)
    assert (status.multi_od_connection, status.model_series_selection) == (0, 1)
    (zone,) = status.zones
    assert (zone.name, zone.zone_type_id, zone.zone_sensor_id) == ("Buffer", 0, 0)
    assert (zone.heat_set, zone.cool_set, zone.eco_heat, zone.comfort_heat) == (30, 16, -5, 5)
    payload = sent(mocked)[0]
    assert payload["apiName"] == f"/remote/v1/api/devices?gwid={LONG_ID}&deviceDirect=1"


async def test_cached_fallback_has_no_water_pressure(logged_client, mocked):
    mocked.post(TRANSFER, status=500, body="x")
    mocked.post(TRANSFER, payload=live("status_direct0"))
    status = await logged_client.get_device_status(info())
    assert status.data_mode == StatusDataMode.CACHED
    assert status.water_pressure is None
    assert status.direction == DeviceDirection.IDLE
    assert sent(mocked)[1]["apiName"].endswith("deviceDirect=0")


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0, None), (1, SpecialStatus.ECO), (2, SpecialStatus.COMFORT), (7, None), (None, None), ("x", None)],
)
def test_parse_special_status(value, expected):
    assert parse_special_status(value) is expected


def _status(**changes):
    body = live("status_direct1")
    zone = body["status"]["zoneStatus"][0]
    for key, value in changes.items():
        if key.startswith("zone_"):
            zone[key[5:]] = value
        elif key.startswith("tank_"):
            body["status"]["tankStatus"][key[5:]] = value
        else:
            body["status"][key] = value
    return body


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({}, OperationStatus.OFF),
        ({"zone_operationStatus": 1}, OperationStatus.ON),
        ({"tank_operationStatus": 1}, OperationStatus.ON),
        ({"specialStatus": 1}, OperationStatus.OFF),  # a preset is not "on"
        ({"specialStatus": 2, "zone_operationStatus": 1}, OperationStatus.ON),
        ({"operationStatus": 1}, OperationStatus.ON),  # explicit value wins
    ],
)
def test_device_on_off_from_zones_and_tank(changes, expected):
    status = parse_device_status(LONG_ID, _status(**changes))
    assert status.operation_status == expected


def test_status_tolerates_missing_optional_keys():
    body = {"status": {"operationMode": 1, "deiceStatus": 0, "direction": 0, "pumpDuty": 0}}
    status = parse_device_status(LONG_ID, body)
    assert status.special_status is None and status.operation_status == OperationStatus.OFF
    assert status.zones == [] and status.tank_status == [] and status.fault_status == []
    for attr in ("cool_mode", "tank_flag", "bivalent", "uncontrollable", "service_type", "stand_alone"):
        assert getattr(status, attr) is None


# ------------------------------------------------------------- Device entity


async def test_device_from_live_status(logged_client, mocked):
    dev = await make_device(logged_client, mocked)
    assert list(dev.zones) == [1]
    zone = dev.zones[1]
    assert zone.name == "Buffer"
    assert zone.sensor_mode == ZoneSensor.WATER_TEMPERATURE
    assert (zone.zone_type_id, zone.zone_sensor_id) == (0, 0)
    assert zone.type == ZoneType.UNKNOWN
    assert zone.supports_set_temperature and zone.supports_special_status
    assert dev.support_cooling(1)  # coolMode 2
    assert dev.has_tank and dev.tank.target_temperature == 48
    assert dev.operation_status == OperationStatus.OFF
    assert dev.current_action == DeviceAction.OFF
    assert dev.special_status is None
    assert dev.status_data_mode == StatusDataMode.LIVE
    assert (dev.connection_status, dev.dhw_flag) == (0, False)
    assert dev.cool_mode == 2 and dev.service_type == "STD_ADP-TAW1"
    assert dev.uncontrollable is False
    assert (dev.bivalent, dev.bivalent_actual, dev.external_heater, dev.electric_anode) == (0, 0, 0, 0)
    assert (dev.control_box, dev.multi_od_connection, dev.model_series_selection, dev.stand_alone) == (0, 0, 1, 0)


async def test_device_heating_reported_without_preset(logged_client, mocked):
    dev = await make_device(logged_client, mocked, _status(zone_operationStatus=1))
    assert dev.operation_status == OperationStatus.ON
    assert dev.current_action == DeviceAction.HEATING  # direction 1 + heat mode
    # turn_off is no longer a no-op for a running device without a preset
    mocked.post(TRANSFER, payload={})
    await dev.turn_off()
    assert sent(mocked)[-1]["bodyParam"] == {"gwid": LONG_ID, "operationStatus": 0}


async def test_zones_come_from_status(logged_client, mocked):
    body = live("status_direct1")
    second = copy.deepcopy(body["status"]["zoneStatus"][0])
    second.update(zoneId=2, zoneName="", zoneSensor=3)
    body["status"]["zoneStatus"].append(second)
    dev = await make_device(logged_client, mocked, body)
    assert list(dev.zones) == [1, 2]  # zone 2 only in the status: still a zone
    assert dev.zones[2].name == "Zone 2"  # empty zoneName
    assert dev.zones[2].sensor_mode == ZoneSensor.UNKNOWN  # unmapped id
    assert dev.zones[2].zone_sensor_id == 3


async def test_zones_fall_back_to_device_list_without_status_zones(logged_client, mocked):
    body = live("status_direct1")
    del body["status"]["zoneStatus"]
    dev = await make_device(logged_client, mocked, body)
    assert list(dev.zones) == [1]
    assert dev.zones[1].name == "Zone 1"


async def test_zones_are_per_device_and_refreshed(logged_client, mocked):
    dev = await make_device(logged_client, mocked)
    other = await make_device(logged_client, mocked, _status(zoneStatus=[]))
    assert dev.zones is not other.zones
    assert dev.zones[1].temperature == 26
    mocked.post(TRANSFER, payload=_status(zone_temperatureNow=31, zone_operationStatus=1))
    await dev.refresh_data()
    assert dev.zones[1].temperature == 31
    assert dev.zones[1].operation_status == OperationStatus.ON


@pytest.mark.parametrize(
    ("cool_mode", "group_mode", "expected"),
    [(0, 1, False), (2, 1, True), (None, 1, True), (None, 2, True)],
)
async def test_cooling_detection(logged_client, mocked, cool_mode, group_mode, expected):
    body = live("status_direct1")
    if cool_mode is None:
        del body["status"]["coolMode"]  # falls back to the old heuristic
    else:
        body["status"]["coolMode"] = cool_mode
    group = live("device_group")
    group["groupList"][0]["deviceList"][0]["operationMode"] = group_mode
    dev = await make_device(logged_client, mocked, body, group)
    assert dev.support_cooling(1) is expected


async def test_cooling_heuristic_without_cool_range(logged_client, mocked):
    body = live("status_direct1")
    del body["status"]["coolMode"]
    del body["status"]["zoneStatus"][0]["coolMin"]
    dev = await make_device(logged_client, mocked, body)
    assert dev.support_cooling(1) is False


async def test_tank_flag_decides_has_tank(logged_client, mocked):
    dev = await make_device(logged_client, mocked, _status(tank=0))
    assert dev.has_tank is False and dev.tank is None
    body = live("status_direct1")
    del body["status"]["tank"]
    dev = await make_device(logged_client, mocked, body)
    assert dev.has_tank is True  # no flag: device list decides


# ------------------------------------------------------------- eco / comfort


async def _preset_device(client, mocked, special_status=0, heat_set=30):
    body = _status(specialStatus=special_status, zone_heatSet=heat_set, zone_operationStatus=1)
    dev = await make_device(client, mocked, body)
    mocked.post(TRANSFER, payload={}, repeat=True)
    return dev


async def test_preset_none_to_eco_applies_offset(logged_client, mocked):
    dev = await _preset_device(logged_client, mocked)
    await dev.set_special_status(SpecialStatus.ECO)
    body = sent(mocked)[-1]
    assert body["apiName"] == "/remote/v1/api/devices"
    # heat 30 + ecoHeat(-5) = 25, cool 16 + ecoCool(5) = 20 (max 20)
    assert body["bodyParam"] == {
        "gwid": LONG_ID,
        "specialStatus": 1,
        "zoneStatus": [{"zoneId": 1, "heatSet": 25, "coolSet": 20}],
    }
    assert dev.special_status == SpecialStatus.ECO
    assert dev.zones[1].heat_target_temperature == 25  # local state follows


async def test_preset_eco_to_comfort_undoes_eco_first(logged_client, mocked):
    dev = await _preset_device(logged_client, mocked, special_status=1, heat_set=25)
    await dev.set_special_status(SpecialStatus.COMFORT)
    # 25 - eco(-5) = 30, + comfort(5) = 35; cool 16 - eco(5) = 11, + comfort(-5) = 6
    assert sent(mocked)[-1]["bodyParam"]["zoneStatus"] == [
        {"zoneId": 1, "heatSet": 35, "coolSet": 6}
    ]
    # and back to no preset: comfort's offset is reverted
    await dev.set_special_status(None)
    assert sent(mocked)[-1]["bodyParam"] == {
        "gwid": LONG_ID,
        "specialStatus": 0,
        "zoneStatus": [{"zoneId": 1, "heatSet": 30, "coolSet": 11}],
    }


async def test_preset_offset_is_clamped(logged_client, mocked):
    dev = await _preset_device(logged_client, mocked, heat_set=53)
    await dev.set_special_status(SpecialStatus.COMFORT)
    assert sent(mocked)[-1]["bodyParam"]["zoneStatus"][0]["heatSet"] == 55  # heatMax


@pytest.mark.parametrize(("current", "requested"), [(0, None), (2, SpecialStatus.COMFORT)])
async def test_preset_unchanged_sends_nothing(logged_client, mocked, current, requested):
    dev = await _preset_device(logged_client, mocked, special_status=current)
    before = len(sent(mocked))
    await dev.set_special_status(requested)
    assert len(sent(mocked)) == before


async def test_preset_missing_modifiers(logged_client, mocked):
    body = _status(zone_operationStatus=1)
    for key in ("ecoHeat", "ecoCool", "comfortHeat", "comfortCool"):
        del body["status"]["zoneStatus"][0][key]
    dev = await make_device(logged_client, mocked, body)
    mocked.post(TRANSFER, payload={})
    await dev.set_special_status(SpecialStatus.ECO)
    assert sent(mocked)[-1]["bodyParam"]["zoneStatus"] == [{"zoneId": 1, "heatSet": 30, "coolSet": 16}]


async def test_preset_skips_external_sensor_zones(logged_client, mocked):
    from aioaquarea.entities import DeviceImpl

    body = live("status_direct1")
    second = copy.deepcopy(body["status"]["zoneStatus"][0])
    second["zoneId"] = 2
    del second["zoneSensor"]
    body["status"]["zoneStatus"].append(second)
    status = parse_device_status(LONG_ID, body)
    zones = [
        DeviceZoneInfo(2, "Z2", ZoneType.ROOM, True, ZoneSensor.EXTERNAL, SensorMode.DIRECT, None)
    ]
    dev = DeviceImpl(LONG_ID, LONG_ID, "n", "", "", True, zones, status, logged_client)
    assert not dev.zones[2].supports_special_status and dev.zones[1].supports_special_status
    mocked.post(TRANSFER, payload={})
    await dev.set_special_status(SpecialStatus.ECO)
    assert [z["zoneId"] for z in sent(mocked)[-1]["bodyParam"]["zoneStatus"]] == [1]


def test_limit_range_without_bounds():
    assert limit_range(5, None, None) == 5
    assert limit_range(5, 6, None) == 6
    assert limit_range(5, None, 4) == 4


# ------------------------------------------------------------- consumption


async def test_consumption_day_report(logged_client, mocked):
    mocked.post(TRANSFER, payload=live("consumption_day"))
    report = await logged_client.get_device_consumption_report(LONG_ID, DateType.DAY, "20261018")
    assert isinstance(report, ConsumptionReport)
    assert len(report.history) == 24 and report.last_year_history == []
    assert report.history[0].data_time == "20261018 00"
    assert [b.is_future for b in report.history].index(True) == 13
    assert sum(b.is_future for b in report.history) == 11
    assert report.currency == "EUR"
    assert report.electric_rate.weekday_base_rate == 0.25
    assert report.electric_rate.weekend_base_rate == 0.25
    assert report.device_register_time == "20240801"
    assert (report.elec_meter_hp, report.multi_od_connection) == (0, 0)
    assert report.raw_data["ownerFlg"] is True


async def test_consumption_month_cost_is_rate_times_kwh(logged_client, mocked):
    mocked.post(TRANSFER, payload=live("consumption_month"))
    items = await logged_client.get_device_consumption(LONG_ID, DateType.MONTH, "20261001")
    assert len(items) == 31
    first = items[0]
    assert first.tank_cost == pytest.approx(first.tank_consumption * 0.25, abs=1e-3)
    assert not first.is_future and items[-1].is_future


async def test_consumption_year_rolling_window(logged_client, mocked):
    mocked.post(TRANSFER, payload=live("consumption_year"))
    report = await logged_client.get_device_consumption_report(LONG_ID, DateType.YEAR, "20260101")
    assert sent(mocked)[0]["bodyParam"]["dataMode"] == 2
    assert [b.data_time for b in report.history][::11] == ["202502", "202601"]
    assert [b.data_time for b in report.last_year_history][::11] == ["202402", "202501"]
    # months before the registration have no outdoorTemp
    assert report.last_year_history[0].is_future
    assert not report.last_year_history[6].is_future


async def test_consumption_report_none_when_empty(logged_client, mocked):
    mocked.post(TRANSFER, payload={"historyDataList": []})
    assert await logged_client.get_device_consumption_report(LONG_ID, DateType.DAY, "20261018") is None


def test_consumption_report_tolerates_missing_keys():
    report = ConsumptionReport.from_dict({"historyDataList": [{"dataTime": "x"}, "bad"], "electricRate": "?"})
    assert len(report.history) == 1 and report.electric_rate is None and report.currency is None
    assert Consumption({"outdoorTemp": 1}).is_future is False


async def test_device_consumption_skips_future_days(logged_client, mocked):
    mocked.get(GROUP, payload=live("device_group"))
    mocked.post(TRANSFER, payload=live("status_direct1"))
    mocked.post(TRANSFER, payload=live("consumption_month"))
    (device_info,) = await logged_client.get_devices()
    dev = await logged_client.get_device(
        device_info=device_info, consumption_refresh_interval=dt.timedelta(minutes=30)
    )
    assert dev.get_or_schedule_consumption(dt.datetime(2026, 10, 1), ConsumptionType.WATER_TANK) > 0
    from aioaquarea import DataNotAvailableError

    with pytest.raises(DataNotAvailableError):
        dev.get_or_schedule_consumption(dt.datetime(2026, 10, 25), ConsumptionType.HEAT)


# ------------------------------------------------------------- weekly timer


async def test_weekly_timer(logged_client, mocked):
    mocked.post(TRANSFER, payload=live("weekly_timer"))
    timer = await logged_client.get_weekly_timer(LONG_ID)
    assert sent(mocked) == [
        {"apiName": f"/remote/v1/api/data/weeklyTimer?gwid={LONG_ID}", "requestMethod": "GET"}
    ]
    assert timer.operation == 0 and timer.enabled is False
    assert len(timer.days) == 7 and timer.days[0].name == "Monday" and timer.days[6].name == "Sunday"
    monday = timer.days[0]
    assert len(monday.slots) == 6 and monday.slots[2:] == [None] * 4
    first, second = monday.active_slots
    assert (first.start_time, first.mode, first.tank_on, first.tank_temperature) == ("16:45", 3, True, 45)
    assert second.tank_on is False
    zone = first.zones[1]
    assert (zone.on, zone.heat_set, zone.cool_set) == (True, 31, 18)
    assert 2 not in first.zones  # one-zone unit: no zone2* keys
    assert first.raw_data["startTime"] == "16:45"
    limits = timer.zone_limits
    assert (limits[1].heat_min, limits[1].heat_max, limits[1].cool_min, limits[1].cool_max) == (20, 55, 5, 20)
    assert (limits[2].heat_min, limits[2].heat_max) == (-5, 5)
    assert (timer.tank_limits.heat_min, timer.tank_limits.heat_max) == (40, 75)
    assert timer.tank_limits.cool_min is None


async def test_weekly_timer_enabled_and_sparse(logged_client, mocked):
    body = {"weeklyTimer": {"operation": 1, "timer": [{"patternList": [{"startTime": "06:00", "zone2OnOff": 0}]}]}}
    mocked.post(TRANSFER, payload=body)
    timer = await logged_client.get_weekly_timer(LONG_ID)
    assert timer.enabled
    assert timer.days[0].slots[0].zones[2].on is False
    assert timer.days[0].slots[0].tank_on is None
    assert all(day.active_slots == [] for day in timer.days[1:])
    assert timer.zone_limits == {} and timer.tank_limits is None


@pytest.mark.parametrize("payload", [[], {}, {"weeklyTimer": {"timer": "x"}}])
async def test_weekly_timer_invalid(logged_client, mocked, payload):
    mocked.post(TRANSFER, payload=payload)
    with pytest.raises(InvalidData):
        await logged_client.get_weekly_timer(LONG_ID)


async def test_device_weekly_timer(logged_client, mocked):
    dev = await make_device(logged_client, mocked)
    mocked.post(TRANSFER, payload=live("weekly_timer"))
    timer = await dev.get_weekly_timer()
    assert len(timer.days[3].active_slots) == 2


# ------------------------------------------------------------- agreements / errors


async def test_agreement_status(logged_client, mocked):
    mocked.get(AGREEMENT, payload=live("agreement_status"))
    assert await logged_client.get_agreement_status() == [
        {"type": 1, "version": "1.0.0"},
        {"type": 2, "version": "1.0.0"},
    ]


@pytest.mark.parametrize("payload", [[1], {"agreementList": "x"}])
async def test_agreement_status_invalid(logged_client, mocked, payload):
    mocked.get(AGREEMENT, payload=payload)
    with pytest.raises(InvalidData):
        await logged_client.get_agreement_status()


AGREEMENT_ERROR = {"code": 4103, "message": "Terms and policies have been updated"}


async def test_4103_on_status_is_a_clear_error(logged_client, mocked):
    mocked.post(TRANSFER, status=403, payload=AGREEMENT_ERROR)
    with pytest.raises(AgreementNotAcceptedError) as exc:
        await logged_client.get_device_status(info())
    assert exc.value.error_code == "4103"
    assert "Comfort Cloud app" in str(exc.value)
    assert isinstance(exc.value, ApiError)
    assert len(sent(mocked)) == 1  # no cached fallback, no re-login


async def test_4103_on_consumption_is_raised(logged_client, mocked):
    mocked.post(TRANSFER, payload=AGREEMENT_ERROR)
    with pytest.raises(AgreementNotAcceptedError):
        await logged_client.get_device_consumption(LONG_ID, DateType.DAY, "20261018")


async def test_4103_on_device_list(logged_client, mocked):
    mocked.get(GROUP, status=403, payload={"code": "4103", "message": "x"})
    with pytest.raises(AgreementNotAcceptedError):
        await logged_client.get_devices()


async def test_gateway_error_codes(session):
    from aioaquarea.auth import CCAppVersion, PanasonicSettings
    from aioaquarea.const import AquareaEnvironment

    api = AquareaAPIClient(session, PanasonicSettings(), CCAppVersion(), AquareaEnvironment.PRODUCTION)
    (error,) = await api.look_for_errors(
        {"code": 4000, "message": "Missing required header parameter or bad request for header"}
    )
    assert type(error) is ApiError and error.error_code == "4000"
    (error,) = await api.look_for_errors({"code": 4300, "message": "Have no authority to the request"})
    assert error.error_code == "4300"
    (error,) = await api.look_for_errors({"message": "Missing Authentication Token"})
    assert error.error_code == "unknown_error_code"  # unchanged: route not registered
    (error,) = await api.look_for_errors(AGREEMENT_ERROR)
    assert isinstance(error, AgreementNotAcceptedError)


async def test_status_failure_still_request_failed(logged_client, mocked):
    mocked.post(TRANSFER, status=400, payload={"code": 4000, "message": "bad"}, repeat=True)
    with pytest.raises(RequestFailedError):
        await logged_client.get_device_status(info())
