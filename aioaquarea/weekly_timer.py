"""Read-only models of the Aquarea weekly timer (weekly schedule).

Read through the common/transfer proxy from
``GET /remote/v1/api/data/weeklyTimer?gwid=<device id>``. The response has
seven days (Monday first) of six slots each; an unused slot is ``{}``. A slot
holds a start time, a ``mode`` and the on/off state and setpoints of zone 1,
zone 2 and the tank (keys of zones or a tank the unit does not have are
absent). The response also carries the allowed setpoint ranges.

Writing the schedule (``requestMethod: "POST"`` to the same path) is not
implemented: it could not be tested against a live unit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
SLOTS_PER_DAY = 6
_ZONE_IDS = (1, 2)


def _optional_bool(value: object) -> bool | None:
    return None if value is None else bool(value)


@dataclass
class WeeklyTimerZoneSetting:
    """Settings of one zone in a weekly timer slot."""

    zone_id: int
    on: bool | None
    """``zoneNOnOff``"""
    heat_set: int | None
    """``zoneNHeat``"""
    cool_set: int | None
    """``zoneNCool``"""


@dataclass
class WeeklyTimerSlot:
    """One scheduled change: from ``start_time`` the unit uses these settings."""

    start_time: str
    """``HH:MM``"""
    mode: int | None
    """Raw ``mode``. 3 was seen with both heat and cool setpoints filled. If it
    uses the operation-update encoding (``UpdateOperationMode``: 0 off, 2 heat,
    3 cool, 8 auto) 3 is cool; that is unverified."""
    zones: dict[int, WeeklyTimerZoneSetting] = field(default_factory=dict)
    tank_on: bool | None = None
    """``tankOnOff``"""
    tank_temperature: int | None = None
    """``tankTemperature``"""
    raw_data: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, data: dict) -> WeeklyTimerSlot | None:
        """Parse a slot; an unused slot (``{}`` or no start time) gives None."""
        if not isinstance(data, dict) or not data.get("startTime"):
            return None
        zones: dict[int, WeeklyTimerZoneSetting] = {}
        for zone_id in _ZONE_IDS:
            keys = (f"zone{zone_id}OnOff", f"zone{zone_id}Heat", f"zone{zone_id}Cool")
            if any(key in data for key in keys):
                zones[zone_id] = WeeklyTimerZoneSetting(
                    zone_id,
                    _optional_bool(data.get(keys[0])),
                    data.get(keys[1]),
                    data.get(keys[2]),
                )
        return cls(
            start_time=data["startTime"],
            mode=data.get("mode"),
            zones=zones,
            tank_on=_optional_bool(data.get("tankOnOff")),
            tank_temperature=data.get("tankTemperature"),
            raw_data=data,
        )


@dataclass
class WeeklyTimerDay:
    """The slots of one weekday (index 0 = Monday)."""

    weekday: int
    slots: list[WeeklyTimerSlot | None]
    """Always ``SLOTS_PER_DAY`` entries; None for an unused slot."""

    @property
    def name(self) -> str:
        """English weekday name"""
        return WEEKDAYS[self.weekday] if 0 <= self.weekday < len(WEEKDAYS) else str(self.weekday)

    @property
    def active_slots(self) -> list[WeeklyTimerSlot]:
        """The used slots, in order"""
        return [slot for slot in self.slots if slot is not None]


@dataclass
class SetpointLimits:
    """Allowed setpoint range of a zone or the tank for the weekly timer."""

    heat_min: int | None
    heat_max: int | None
    cool_min: int | None = None
    cool_max: int | None = None


@dataclass
class WeeklyTimer:
    """The weekly schedule of a device."""

    operation: int | None
    """Raw ``weeklyTimer.operation`` (0 = schedule disabled, 1 = enabled)."""
    days: list[WeeklyTimerDay]
    """Seven days, Monday first."""
    zone_limits: dict[int, SetpointLimits] = field(default_factory=dict)
    """Setpoint ranges per zone id. The response lists zone 2 even on one-zone
    units, with -5..5 limits that look like a compensation-curve shift range
    rather than a real zone."""
    tank_limits: SetpointLimits | None = None
    raw_data: dict = field(default_factory=dict, repr=False)

    @property
    def enabled(self) -> bool:
        """True when the schedule is switched on"""
        return self.operation == 1

    @classmethod
    def from_dict(cls, data: dict) -> WeeklyTimer:
        """Parse a weekly timer response; raises ValueError on malformed data."""
        if not isinstance(data, dict):
            raise ValueError("weekly timer response must be an object")
        timer = data.get("weeklyTimer")
        if not isinstance(timer, dict):
            raise ValueError("weekly timer response has no weeklyTimer object")
        day_list = timer.get("timer") or []
        if not isinstance(day_list, list):
            raise ValueError("weeklyTimer.timer must be a list")

        days: list[WeeklyTimerDay] = []
        for index in range(len(WEEKDAYS)):
            day = day_list[index] if index < len(day_list) else {}
            patterns = day.get("patternList") if isinstance(day, dict) else None
            patterns = patterns if isinstance(patterns, list) else []
            slots = [WeeklyTimerSlot.from_dict(p) for p in patterns[:SLOTS_PER_DAY]]
            slots += [None] * (SLOTS_PER_DAY - len(slots))
            days.append(WeeklyTimerDay(index, slots))

        status: Any = data.get("status") if isinstance(data.get("status"), dict) else {}
        zone_limits: dict[int, SetpointLimits] = {}
        for zone in status.get("zoneStatus") or []:
            if isinstance(zone, dict) and zone.get("zoneId") is not None:
                zone_limits[zone["zoneId"]] = SetpointLimits(
                    zone.get("heatMin"),
                    zone.get("heatMax"),
                    zone.get("coolMin"),
                    zone.get("coolMax"),
                )
        tank = status.get("tankStatus")
        tank_limits = (
            SetpointLimits(tank.get("heatMin"), tank.get("heatMax"))
            if isinstance(tank, dict) and tank
            else None
        )
        return cls(
            operation=timer.get("operation"),
            days=days,
            zone_limits=zone_limits,
            tank_limits=tank_limits,
            raw_data=data,
        )
