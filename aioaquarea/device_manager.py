import logging
from typing import TYPE_CHECKING, Any

from .auth import CCAppVersion, PanasonicRequestHeader, PanasonicSettings
from .const import BASE_PATH_ACC
from .data import (
    DeviceDirection,
    DeviceInfo,
    DeviceModeStatus,
    DeviceStatus,
    DeviceZoneInfo,
    DeviceZoneStatus,
    ExtendedOperationMode,
    FaultError,
    ForceDHW,
    ForceHeater,
    HolidayTimer,
    OperationMode,
    OperationStatus,
    PowerfulTime,
    PumpDuty,
    QuietMode,
    SensorMode,
    StatusDataMode,
    TankStatus,
    ZoneSensor,
    ZoneType,
    parse_special_status,
)
from .errors import (
    AgreementNotAcceptedError,
    AuthenticationError,
    InvalidData,
    RequestFailedError,
)
from .weekly_timer import WeeklyTimer

if TYPE_CHECKING:
    from .core import AquareaClient

_LOGGER = logging.getLogger(__name__)


class DeviceManager:
    def __init__(
        self,
        client: "AquareaClient",
        settings: PanasonicSettings,
        app_version: CCAppVersion,
        logger: logging.Logger,
    ):
        self._client = client
        self._settings = settings
        self._app_version = app_version
        self._logger = logger
        self._groups = None
        self._devices: list[DeviceInfo] | None = None
        self._unknown_devices: list[DeviceInfo] = []
        self._device_indexer = {}

    async def get_devices(self) -> list[DeviceInfo]:
        """Get list of devices and its configuration, without status."""
        if self._devices is None:
            self._devices = []
            self._unknown_devices = []
            # Assuming self._client.request can be called directly or passed through
            # and BASE_PATH_ACC is accessible.
            # This part needs to be carefully integrated with the actual Client class.
            groups_response = await self._client._api_client.request(  # Changed to _api_client.request
                "GET",
                external_url=f"{BASE_PATH_ACC}/device/group",
                headers=await PanasonicRequestHeader.get(
                    self._settings, self._app_version
                ),
            )
            self._groups = await groups_response.json()

            if self._groups is not None and "groupList" in self._groups:
                for group in self._groups["groupList"]:
                    device_list = group.get("deviceList", [])
                    if not device_list:
                        device_list = group.get("deviceIdList", [])

                    for device_raw in device_list:
                        if device_raw and device_raw.get("deviceType") == "2":
                            _LOGGER.debug("Raw device response keys: %s", sorted(device_raw))
                            device_id = device_raw.get("deviceGuid")
                            device_name = device_raw.get("deviceName", "Unknown Device")
                            operation_mode = OperationMode(
                                device_raw.get("operationMode", 0)
                            )  # Default to 0 if not found
                            # Check if tankStatus exists, is not None, and is not an empty dict
                            tank_status = device_raw.get("tankStatus")
                            has_tank = bool(tank_status and tank_status != {})
                            firmware_version = (
                                "N/A"  # Mock data as it's not in the new structure
                            )
                            model = "N/A"  # Get model or use default

                            zones: list[DeviceZoneInfo] = []
                            device_operation_mode = device_raw.get("operationMode")
                            # Check if the device's overall operation mode indicates cooling support
                            device_supports_cooling = device_operation_mode in [
                                OperationMode.Cool.value,
                                ExtendedOperationMode.COOL.value,
                                ExtendedOperationMode.AUTO_COOL.value,
                            ]

                            zone_records = [
                                z
                                for z in device_raw.get("zoneStatus") or []
                                if isinstance(z, dict) and z.get("zoneId") is not None
                            ]
                            # An unconfigured zone is listed as a bare
                            # {"zoneId": N} placeholder: skip those when other
                            # zones carry data. The device status decides the
                            # real zones anyway (see data.merge_zone_infos).
                            if any(set(z) != {"zoneId"} for z in zone_records):
                                zone_records = [
                                    z for z in zone_records if set(z) != {"zoneId"}
                                ]
                            for zone_record in zone_records:
                                zone_id = zone_record["zoneId"]
                                # The device list has no names, types or sensors;
                                # these are filled in from the device status.
                                has_cool_mode = (
                                    "coolMin" in zone_record and "coolMax" in zone_record
                                ) or device_supports_cooling
                                zones.append(
                                    DeviceZoneInfo(
                                        zone_id,
                                        f"Zone {zone_id}",
                                        ZoneType.UNKNOWN,
                                        has_cool_mode,
                                        ZoneSensor.UNKNOWN,
                                        SensorMode.DIRECT,
                                        SensorMode.DIRECT,
                                    )
                                )

                            device_info = DeviceInfo(
                                device_id,
                                device_name,
                                device_id,  # long_id
                                operation_mode,
                                has_tank,
                                firmware_version,
                                model,  # Added model
                                zones,
                                StatusDataMode.LIVE,  # Added status_data_mode
                                connection_status=device_raw.get("connectionStatus"),
                                dhw_flag=device_raw.get("dhwFlg"),
                            )
                            _LOGGER.debug(
                                "get_devices: Device %s has_tank: %s", device_id, has_tank
                            )
                            self._device_indexer[device_id] = device_id
                            self._devices.append(device_info)
        return self._devices + self._unknown_devices

    async def get_device_status(self, device_info: DeviceInfo) -> DeviceStatus:
        """Retrieve the device status.

        Reads the live status (``deviceDirect=1``) and falls back to the cloud's
        cached status (``deviceDirect=0``) when that fails. The cached status
        has no ``waterPressure`` (``water_pressure`` is None then) and its
        ``direction`` can differ from the live one; ``DeviceStatus.data_mode``
        says which one was used.
        """
        json_response = None
        data_mode = StatusDataMode.LIVE
        try:
            payload = {
                "apiName": f"/remote/v1/api/devices?gwid={device_info.device_id}&deviceDirect=1",
                "requestMethod": "GET",
            }
            response = await self._client._api_client.request(
                "POST",
                url="remote/v1/app/common/transfer",
                json=payload,
                throw_on_error=True,
            )
            json_response = await response.json()
            self._logger.debug(
                "get_device_status (live): response for device %s has keys %s",
                device_info.device_id,
                sorted(json_response) if isinstance(json_response, dict) else type(json_response).__name__,
            )
        except (AuthenticationError, AgreementNotAcceptedError):
            raise
        except Exception as e:
            self._logger.warning(
                "Failed to get live status for device {}: {}".format(
                    device_info.device_id, e
                )
            )
            # If live data fails, try cached data as a fallback
            try:
                payload = {
                    "apiName": f"/remote/v1/api/devices?gwid={device_info.device_id}&deviceDirect=0",
                    "requestMethod": "GET",
                }
                response = await self._client._api_client.request(
                    "POST",
                    url="remote/v1/app/common/transfer",
                    json=payload,
                    throw_on_error=True,
                )
                json_response = await response.json()
                data_mode = StatusDataMode.CACHED
                self._logger.debug(
                    "Retrieved cached status for device %s after live data failure "
                    "(no water pressure in cached data)",
                    device_info.device_id,
                )
            except (AuthenticationError, AgreementNotAcceptedError):
                raise
            except Exception as e_cached:
                self._logger.error(
                    "Failed to get cached status for device {}: {}".format(
                        device_info.device_id, e_cached
                    )
                )
                raise RequestFailedError(
                    "Failed to retrieve device status after multiple attempts."
                ) from e_cached

        if json_response is None:
            raise RequestFailedError(
                "Failed to retrieve device status after multiple attempts."
            )

        try:
            return parse_device_status(device_info.device_id, json_response, data_mode)
        except (AttributeError, KeyError, TypeError, ValueError) as err:
            raise InvalidData(json_response) from err

    async def get_weekly_timer(self, long_id: str) -> WeeklyTimer:
        """Read the weekly schedule (``/remote/v1/api/data/weeklyTimer``)."""
        response = await self._client._api_client.request(
            "POST",
            url="remote/v1/app/common/transfer",
            json={
                "apiName": f"/remote/v1/api/data/weeklyTimer?gwid={long_id}",
                "requestMethod": "GET",
            },
            throw_on_error=True,
        )
        json_response = await response.json()
        try:
            return WeeklyTimer.from_dict(json_response)
        except (AttributeError, KeyError, TypeError, ValueError) as err:
            raise InvalidData(json_response) from err

    async def get_agreement_status(self) -> list[dict]:
        """Agreement types and versions the account has accepted.

        ``GET /auth/v2/agreement/status`` returns for example
        ``[{"type": 1, "version": "1.0.0"}, {"type": 2, "version": "1.0.0"}]``
        (1 = terms of use, 2 = privacy policy, per the Comfort Cloud app).
        """
        response = await self._client._api_client.request(
            "GET",
            external_url=f"{BASE_PATH_ACC}/auth/v2/agreement/status",
            throw_on_error=True,
        )
        json_response = await response.json()
        if not isinstance(json_response, dict):
            raise InvalidData(json_response)
        agreements = json_response.get("agreementList") or []
        if not isinstance(agreements, list):
            raise InvalidData(json_response)
        return [a for a in agreements if isinstance(a, dict)]


def _parse_zone_status(zone_status: Any) -> DeviceZoneStatus:
    return DeviceZoneStatus(
        zone_id=zone_status.get("zoneId"),
        temperature=zone_status.get("temperatureNow"),
        operation_status=OperationStatus(zone_status.get("operationStatus")),
        heat_max=zone_status.get("heatMax"),
        heat_min=zone_status.get("heatMin"),
        heat_set=zone_status.get("heatSet"),
        cool_max=zone_status.get("coolMax"),
        cool_min=zone_status.get("coolMin"),
        cool_set=zone_status.get("coolSet"),
        comfort_cool=zone_status.get("comfortCool"),
        comfort_heat=zone_status.get("comfortHeat"),
        eco_cool=zone_status.get("ecoCool"),
        eco_heat=zone_status.get("ecoHeat"),
        name=zone_status.get("zoneName") or None,
        zone_type_id=zone_status.get("zoneType"),
        zone_sensor_id=zone_status.get("zoneSensor"),
    )


def _device_operation_status(
    device: Any, zones: list[DeviceZoneStatus], tank: Any
) -> OperationStatus:
    """Whole-device on/off.

    The status has no device-level ``operationStatus`` (an explicit one is
    still honoured if present). ``operationMode`` stays at the last heat/cool
    mode while everything is off, so it cannot tell on from off either: the
    device is on while any zone or the tank is on. (``specialStatus`` is the
    eco/comfort preset, not the on/off state.)
    """
    if device.get("operationStatus") is not None:
        return OperationStatus(device["operationStatus"])
    on = any(zone.operation_status == OperationStatus.ON for zone in zones) or (
        tank.get("operationStatus") == OperationStatus.ON
    )
    return OperationStatus.ON if on else OperationStatus.OFF


def _optional_bool(value) -> bool | None:
    return None if value is None else bool(value)


def parse_device_status(
    long_id: str,
    json_response: Any,
    data_mode: StatusDataMode = StatusDataMode.LIVE,
) -> DeviceStatus:
    """Build a ``DeviceStatus`` from a ``/remote/v1/api/devices`` response.

    Raises AttributeError/KeyError/TypeError/ValueError on malformed data.
    """
    device: Any = json_response.get("status")
    operation_mode_value = device.get("operationMode")
    tank_json: Any = device.get("tankStatus") or {}
    zones = [
        _parse_zone_status(zone_status)
        for zone_status in device.get("zoneStatus") or []
        if isinstance(zone_status, dict)
    ]

    return DeviceStatus(
        long_id=long_id,
        operation_status=_device_operation_status(device, zones, tank_json),
        device_status=DeviceModeStatus(device.get("deiceStatus")),
        temperature_outdoor=device.get("outdoorNow"),
        operation_mode=(
            ExtendedOperationMode.OFF
            if operation_mode_value == 99
            else ExtendedOperationMode(operation_mode_value)
        ),
        fault_status=[
            FaultError(fault_status["errorMessage"], fault_status["errorCode"])
            for fault_status in device.get("faultStatus") or []
        ],
        direction=DeviceDirection(device.get("direction")),
        pump_duty=PumpDuty(device.get("pumpDuty")),
        tank_status=(
            [
                TankStatus(
                    OperationStatus(tank_json.get("operationStatus")),
                    tank_json.get("temperatureNow"),
                    tank_json.get("heatMax"),
                    tank_json.get("heatMin"),
                    tank_json.get("heatSet"),
                )
            ]
            if tank_json
            else []
        ),
        zones=zones,
        quiet_mode=QuietMode(device.get("quietMode", 0)),
        force_dhw=ForceDHW(device.get("forceDHW", 0)),
        force_heater=ForceHeater(device.get("forceHeater", 0)),
        holiday_timer=HolidayTimer(device.get("holidayTimer", 0)),
        powerful_time=PowerfulTime(device.get("powerful", 0)),
        special_status=parse_special_status(device.get("specialStatus")),
        water_pressure=device.get("waterPressure"),
        data_mode=data_mode,
        cool_mode=device.get("coolMode"),
        tank_flag=device.get("tank"),
        bivalent=device.get("bivalent"),
        bivalent_actual=device.get("bivalentActual"),
        external_heater=device.get("externalHeater"),
        electric_anode=device.get("electricAnode"),
        control_box=device.get("controlBox"),
        uncontrollable=_optional_bool(device.get("uncontrollableTaw1Flg")),
        service_type=device.get("serviceType"),
        multi_od_connection=device.get("multiOdConnection"),
        model_series_selection=device.get("modelSeriesSelection"),
        stand_alone=device.get("standAlone"),
    )
