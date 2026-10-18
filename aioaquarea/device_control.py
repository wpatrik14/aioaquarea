from __future__ import annotations

from typing import TYPE_CHECKING

from .data import (
    DeviceZoneStatus,
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

if TYPE_CHECKING:
    from .api_client import AquareaAPIClient


class AquareaDeviceControl:
    """Handles device control operations."""

    def __init__(self, api_client: AquareaAPIClient, base_url: str):
        self._api_client = api_client
        self._base_url = base_url

    async def _post_transfer_update(self, long_device_id: str, body: dict) -> None:
        """Send a partial device update through the common/transfer proxy."""
        await self._api_client.request(
            "POST",
            url="remote/v1/app/common/transfer",
            json={
                "apiName": "/remote/v1/api/devices",
                "requestMethod": "POST",
                "bodyParam": {"gwid": long_device_id, **body},
            },
            throw_on_error=True,
        )

    async def post_device_operation_status(
        self, long_device_id: str, new_operation_status: OperationStatus
    ) -> None:
        """Turn the whole device on or off.

        Sent through the common/transfer proxy like every other control: the
        old ``/remote/v1/api/devices/{id}`` route of Aquarea Smart Cloud is
        gone (see docs/api-map.md). Not verified against a live unit.
        """
        await self._post_transfer_update(
            long_device_id, {"operationStatus": new_operation_status.value}
        )

    async def post_device_tank_temperature(
        self, long_device_id: str, new_temperature: int
    ) -> None:
        """Post device tank temperature."""
        data = {
            "apiName": "/remote/v1/api/devices",
            "requestMethod": "POST",
            "bodyParam": {
                "gwid": long_device_id,
                "tankStatus": {
                    "heatSet": new_temperature,
                },
            },
        }

        await self._api_client.request(
            "POST",
            url="remote/v1/app/common/transfer",  # Specific URL for transfer API
            json=data,
            throw_on_error=True,
        )

    async def post_device_tank_operation_status(
        self,
        long_device_id: str,
        new_operation_status: OperationStatus,
        zones: list[DeviceZoneStatus],
    ) -> None:
        """Post device tank operation status."""
        zone_status_list = []
        for zone in zones:
            zone_status_list.append(
                {
                    "zoneId": zone.zone_id,
                    "operationStatus": zone.operation_status.value,
                }
            )

        data = {
            "apiName": "/remote/v1/api/devices",
            "requestMethod": "POST",
            "bodyParam": {
                "gwid": long_device_id,
                "zoneStatus": zone_status_list,
                "tankStatus": {"operationStatus": new_operation_status.value},
            },
        }

        await self._api_client.request(
            "POST",
            url="remote/v1/app/common/transfer",  # Specific URL for transfer API
            json=data,
            throw_on_error=True,
        )

    async def post_device_operation_update(
        self,
        long_id: str,
        mode: UpdateOperationMode,
        zones: dict[int, OperationStatus],
        operation_status: OperationStatus,
        tank_operation_status: OperationStatus,
        zone_temperature_updates: list[ZoneTemperatureSetUpdate]
        | None = None,  # New parameter
    ) -> None:
        """Post device operation update."""
        # Construct zoneStatus list based on provided zones and optional temperature updates
        zone_status_list = []
        for zone_id, op_status in zones.items():
            zone_data = {
                "zoneId": zone_id,
                "operationStatus": op_status.value,
            }
            if zone_temperature_updates:
                for temp_update in zone_temperature_updates:
                    if temp_update.zone_id == zone_id:
                        if temp_update.heat_set is not None:
                            zone_data["heatSet"] = temp_update.heat_set
                        if temp_update.cool_set is not None:
                            zone_data["coolSet"] = temp_update.cool_set
                        break
            zone_status_list.append(zone_data)

        data = {
            "apiName": "/remote/v1/api/devices",
            "requestMethod": "POST",
            "bodyParam": {
                "gwid": long_id,
                "operationMode": mode.value,
                "operationStatus": operation_status.value,
                "zoneStatus": zone_status_list,
                "tankStatus": {"operationStatus": tank_operation_status.value},
            },
        }

        await self._api_client.request(
            "POST",
            url="remote/v1/app/common/transfer",  # Specific URL for transfer API
            json=data,
            throw_on_error=True,
        )

    async def post_device_set_special_status(
        self,
        long_id: str,
        special_status: SpecialStatus | None,
        zones: list[ZoneTemperatureSetUpdate],
    ) -> None:
        """Set the eco/comfort preset (None = no preset) with the zone setpoints.

        The app sends the preset together with each zone's recalculated
        setpoints. Sent through the common/transfer proxy like the other
        controls (the old ``/remote/v1/api/devices/{id}`` route is gone). Not
        verified against a live unit.
        """
        zone_status = []
        for zone in zones:
            zone_update: dict = {"zoneId": zone.zone_id}
            if zone.heat_set is not None:
                zone_update["heatSet"] = zone.heat_set
            if zone.cool_set is not None:
                zone_update["coolSet"] = zone.cool_set
            zone_status.append(zone_update)

        body: dict = {"specialStatus": special_status.value if special_status else 0}
        if zone_status:
            body["zoneStatus"] = zone_status
        await self._post_transfer_update(long_id, body)

    async def post_device_zone_heat_temperature(
        self, long_id: str, zone_id: int, temperature: int
    ) -> None:
        """Post device zone heat temperature."""
        return await self._post_device_zone_temperature(
            long_id, zone_id, temperature, "heatSet"
        )

    async def post_device_zone_cool_temperature(
        self, long_id: str, zone_id: int, temperature: int
    ) -> None:
        """Post device zone cool temperature."""
        return await self._post_device_zone_temperature(
            long_id, zone_id, temperature, "coolSet"
        )

    async def _post_device_zone_temperature(
        self, long_id: str, zone_id: int, temperature: int, key: str
    ) -> None:
        """Post device zone temperature."""
        data = {
            "apiName": "/remote/v1/api/devices",
            "requestMethod": "POST",
            "bodyParam": {
                "gwid": long_id,
                "zoneStatus": [
                    {
                        "zoneId": zone_id,
                        key: temperature,
                    }
                ],
            },
        }

        await self._api_client.request(
            "POST",
            "/remote/v1/app/common/transfer",
            headers={},
            json=data,
        )

    async def post_device_set_quiet_mode(self, long_id: str, mode: QuietMode) -> None:
        """Post quiet mode."""
        data = {
            "apiName": "/remote/v1/api/devices",
            "requestMethod": "POST",
            "bodyParam": {"gwid": long_id, "quietMode": mode.value},
        }

        await self._api_client.request(
            "POST",
            "remote/v1/app/common/transfer",
            json=data,
            throw_on_error=True,
        )

    async def post_device_force_dhw(self, long_id: str, force_dhw: ForceDHW) -> None:
        """Post force DHW command."""
        data = {
            "apiName": "/remote/v1/api/devices",
            "requestMethod": "POST",
            "bodyParam": {"gwid": long_id, "forceDHW": force_dhw.value},
        }

        await self._api_client.request(
            "POST",
            "remote/v1/app/common/transfer",
            json=data,
            throw_on_error=True,
        )

    async def post_device_force_heater(
        self, long_id: str, force_heater: ForceHeater
    ) -> None:
        """Post force heater command."""
        data = {
            "apiName": "/remote/v1/api/devices",
            "requestMethod": "POST",
            "bodyParam": {"gwid": long_id, "forceHeater": force_heater.value},
        }

        await self._api_client.request(
            "POST",
            "remote/v1/app/common/transfer",
            json=data,
            throw_on_error=True,
        )

    async def post_device_holiday_timer(
        self, long_id: str, holiday_timer: HolidayTimer
    ) -> None:
        """Post holidayTimer command."""
        data = {
            "apiName": "/remote/v1/api/devices",
            "requestMethod": "POST",
            "bodyParam": {"gwid": long_id, "holidayTimer": holiday_timer.value},
        }

        await self._api_client.request(
            "POST",
            "remote/v1/app/common/transfer",
            json=data,
            throw_on_error=True,
        )

    async def post_device_request_defrost(self, long_id: str) -> None:
        """Post forcedefrost command."""
        data = {
            "apiName": "/remote/v1/api/devices",
            "requestMethod": "POST",
            "bodyParam": {"gwid": long_id, "forcedefrost": 1},
        }

        await self._api_client.request(
            "POST",
            "remote/v1/app/common/transfer",
            json=data,
            throw_on_error=True,
        )

    async def post_device_set_powerful_time(
        self, long_id: str, powerful_time: PowerfulTime
    ) -> None:
        """Post powerful time."""
        data = {
            "apiName": "/remote/v1/api/devices",
            "requestMethod": "POST",
            "bodyParam": {"gwid": long_id, "powerfulRequest": powerful_time.value},
        }

        await self._api_client.request(
            "POST",
            "remote/v1/app/common/transfer",
            json=data,
            throw_on_error=True,
        )
