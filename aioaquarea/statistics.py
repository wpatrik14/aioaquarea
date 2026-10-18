"""Statistics models for Aquarea"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class DateType(StrEnum):
    """Date types"""

    DAY = "date"
    WEEK = "week"
    MONTH = "month"
    YEAR = "year"


class AggregationType(StrEnum):
    """Aggregation type"""

    HOURLY = "hourly"
    DAILY = "daily"
    MONTHLY = "monthly"


class ConsumptionType(StrEnum):
    """Data type"""

    HEAT = "Heat"
    COOL = "AC"
    WATER_TANK = "HW"
    TOTAL = "Consume"


class Consumption:
    """Consumption"""

    def __init__(self, data: dict[str, object]):
        self._data = data
        self._heat_consumption = data.get("heatConsumption")
        self._cool_consumption = data.get("coolConsumption")
        self._tank_consumption = data.get("tankConsumption")
        self._heat_cost = data.get("heatCost")
        self._cool_cost = data.get("coolCost")
        self._tank_cost = data.get("tankCost")
        self._data_time = data.get("dataTime")
        self._outdoor_temp = data.get("outdoorTemp")

    @property
    def heat_consumption(self) -> float | None:
        """Heat consumption in kWh"""
        return self._heat_consumption

    @property
    def cool_consumption(self) -> float | None:
        """Cool consumption in kWh"""
        return self._cool_consumption

    @property
    def tank_consumption(self) -> float | None:
        """Tank consumption in kWh"""
        return self._tank_consumption

    @property
    def heat_cost(self) -> float | None:
        """Heat cost in configured currency"""
        return self._heat_cost

    @property
    def cool_cost(self) -> float | None:
        """Cool cost in configured currency"""
        return self._cool_cost

    @property
    def tank_cost(self) -> float | None:
        """Tank cost in configured currency"""
        return self._tank_cost

    @property
    def data_time(self) -> str | None:
        """Time of the data point"""
        return self._data_time

    @property
    def outdoor_temp(self) -> float | None:
        """Outdoor temperature"""
        return self._outdoor_temp

    @property
    def is_future(self) -> bool:
        """True for a bucket without ``outdoorTemp``.

        The cloud returns buckets after the current hour/day/month (and before
        the device was registered) with zero values and no ``outdoorTemp``;
        that missing key is the only way to tell them from real zero
        consumption.
        """
        return "outdoorTemp" not in self._data

    @property
    def total_consumption(self) -> float | None:
        """Total consumption in kWh (sum of heat, cool, and tank consumption)"""
        total = 0.0
        if self._heat_consumption is not None:
            total += self._heat_consumption
        if self._cool_consumption is not None:
            total += self._cool_consumption
        if self._tank_consumption is not None:
            total += self._tank_consumption
        return total if total > 0 else None

    @property
    def raw_data(self) -> dict[str, object]:
        """Raw data from the API response"""
        return self._data


@dataclass
class ElectricRate:
    """Electricity tariff the user entered in the app (``electricRate``).

    The ``*_cost`` values of the consumption buckets are this rate times the
    consumption, computed by the cloud, not metered.
    """

    weekday_base_rate: float | None
    weekend_base_rate: float | None
    currency: str | None

    @classmethod
    def from_dict(cls, data: Any) -> ElectricRate | None:
        if not isinstance(data, dict):
            return None
        return cls(
            data.get("weekdayBaseRate"),
            data.get("weekendBaseRate"),
            data.get("currency"),
        )


@dataclass
class ConsumptionReport:
    """A full ``/remote/v1/api/consumption`` response.

    ``history`` holds the requested period's buckets:

    - DAY (``dataMode`` 0, date ``YYYYMMDD``): 24 hourly buckets, ``dataTime``
      ``"YYYYMMDD HH"`` in the requested time zone; the current hour is partial.
    - MONTH (``dataMode`` 1, date ``YYYYMM01``): one bucket per calendar day.
    - YEAR (``dataMode`` 2, date ``YYYYMM01``): 12 monthly buckets (``dataTime``
      ``"YYYYMM"``) of a rolling window **ending** with the month of the date
      sent (so ``20260101`` returns 2025-02 .. 2026-01), and
      ``last_year_history`` with the 12 months before that window.

    Buckets in the future have no ``outdoorTemp`` (see ``Consumption.is_future``).
    """

    history: list[Consumption]
    last_year_history: list[Consumption] = field(default_factory=list)
    electric_rate: ElectricRate | None = None
    device_register_time: str | None = None
    """Date (``YYYYMMDD``) the unit was registered in the cloud; earlier buckets are empty."""
    elec_meter_hp: int | None = None
    """Raw ``elecMeterHp`` (probably an external electricity meter; unverified)."""
    multi_od_connection: int | None = None
    raw_data: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def currency(self) -> str | None:
        """Currency of the ``*_cost`` values, as entered in the app"""
        return self.electric_rate.currency if self.electric_rate else None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConsumptionReport:
        def buckets(key: str) -> list[Consumption]:
            items = data.get(key)
            if not isinstance(items, list):
                return []
            return [Consumption(item) for item in items if isinstance(item, dict)]

        return cls(
            history=buckets("historyDataList"),
            last_year_history=buckets("lastYearHistoryDataList"),
            electric_rate=ElectricRate.from_dict(data.get("electricRate")),
            device_register_time=data.get("deviceRegisterTime"),
            elec_meter_hp=data.get("elecMeterHp"),
            multi_od_connection=data.get("multiOdConnection"),
            raw_data=data,
        )
