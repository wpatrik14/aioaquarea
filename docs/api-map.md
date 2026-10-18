# Aquarea Smart Cloud API map (Comfort Cloud transfer proxy)

Observed against one live account on 2026-10-18 with aioaquarea-ng 1.3.1 as the
auth/transport layer. The "aioaquarea 1.3.1" column below describes the library
before the changes listed in [Support in this library](#support-in-this-library). Read-only: one login, 19 requests, at least 3 s apart, no
control or write endpoint was called. Identifiers are redacted (`<deviceGuid>`
and similar). "Verified" means seen in a live response; everything else is
marked as inferred or unverified.

Test unit: one Aquarea heat pump on an `STD_ADP-TAW1` (CZ-TAW1 style) adapter,
one configured zone (water temperature / buffer tank), DHW tank, cooling
capable. The unit was idle during the whole session (zone and tank off, pump
off), so values that only move while running could not be observed changing.

## Transport

- Base: `https://accsmart.panasonic.com`
- Headers: the Comfort Cloud app headers built by
  `PanasonicRequestHeader.get()` (`x-app-version`, `x-cfc-api-key`,
  `x-user-authorization-v2: Bearer <token>`, `x-client-id`, ...).
- Aquarea calls go through one proxy:
  `POST /remote/v1/app/common/transfer` with body
  `{"apiName": "<path?query>", "requestMethod": "GET"|"POST", "bodyParam": {...}}`.
  The response body is the target endpoint's JSON, unwrapped.
- The proxy forwards to an API Gateway. Error shapes seen:

| Situation | HTTP | Body |
|---|---|---|
| `apiName` route not registered | 403 | `{"message": "Missing Authentication Token"}` (API Gateway's generic "no such route"; it does not mean the token is bad) |
| Registered route, required query parameter missing | 400 | `{"code": 4000, "message": "Missing required header parameter or bad request for header"}` |
| Comfort Cloud AC endpoint used with an Aquarea guid | 403 | `{"code": 4300, "message": "Have no authority to the request"}` |

## Endpoints

| # | Endpoint (request shape) | HTTP | Result | Status |
|---|---|---|---|---|
| 1 | `GET /device/group` | 200 | Device list, Aquarea is `deviceType: "2"` | verified |
| 2 | transfer `GET /remote/v1/api/devices?gwid=<guid>&deviceDirect=1` | 200 | Full live status | verified |
| 3 | transfer `GET /remote/v1/api/devices?gwid=<guid>&deviceDirect=0` | 200 | Cached status, see differences below | verified |
| 4 | transfer `POST /remote/v1/api/consumption` body `{gwid, dataMode: 0, date: "YYYYMMDD", osTimezone: "+02:00"}` | 200 | 24 hourly buckets | verified |
| 5 | same, `dataMode: 1`, `date: "YYYYMM01"` | 200 | One bucket per day of the month | verified |
| 6 | same, `dataMode: 2`, `date: "YYYY0101"` | 200 | 12 monthly buckets + `lastYearHistoryDataList` | verified |
| 7 | transfer `GET /remote/v1/api/data/weeklyTimer?gwid=<guid>` | 200 | Weekly schedule + setpoint limits | verified (read only; the write is `requestMethod: "POST"` to the same path, not tested) |
| 8 | `GET /device/a2wInfo/<guid>` (direct, no proxy; URL builder exists in aio-panasonic-comfort-cloud but is unused there) | 200 | `{"result": 0}` only | verified, no useful data |
| 9 | `GET /deviceStatus/<guid>` (Comfort Cloud AC status) | 403 | code 4300 | verified: not for Aquarea |
| 10 | `GET /auth/v2/agreement/status` | 200 | `{"agreementList": [{"type": 1, "version": "1.0.0"}, {"type": 2, "version": "1.0.0"}]}` | verified (account-level; useful for error 4103 "re-accept terms" handling) |
| 11 | transfer `GET /remote/v1/api/devices` (no query) | 400 | code 4000 | route exists, needs `gwid` |
| 12 | transfer `GET /remote/v1/api/devices?gwid=<guid>` (no `deviceDirect`) | 400 | code 4000 | `deviceDirect` is **mandatory** |
| 13 | transfer `GET /remote/v1/api/devices/<guid>` (old Aquarea Smart path style) | 403 | no route | gone |
| 14 | transfer `GET /remote/v1/api/consumption/<guid>?date=YYYY-MM-DD` (old style) | 403 | no route | gone |
| 15 | transfer `GET /remote/v1/api/data/holidayTimer?gwid=<guid>` | 403 | no route | does not exist |
| 16 | transfer `GET /remote/v1/api/data/errorHistory?gwid=<guid>` | 403 | no route | does not exist |
| 17 | transfer `GET /remote/v1/api/data/doesNotExist?gwid=<guid>` (control probe) | 403 | no route | confirms the 403 meaning |

No fault history, notification, firmware, or holiday-timer read endpoint was
found. The only known `/remote/v1/api/*` routes are `devices`, `consumption`
and `data/weeklyTimer` (plus `auth/login`, which is not used any more).

## 1. `GET /device/group`

```json
{"a2wStatus": {"statusCode": 200}, "uiFlg": false, "groupCount": 1,
 "groupList": [{"groupId": "<groupId>", "groupName": "<groupName>", "pairingList": [],
   "deviceList": [{"deviceGuid": "<deviceGuid>", "deviceType": "2", "deviceName": "<deviceName>",
     "a2wOwnerFlg": true, "dhwFlg": false, "connectionStatus": 0, "operationMode": 1,
     "zoneStatus": [{"zoneId": 1, "operationStatus": 0, "temperature": 30}, {"zoneId": 2}],
     "tankStatus": {"operationStatus": 0, "temperature": 48, "temperatureNow": 32}}]}]}
```

- `zoneStatus[].temperature` and `tankStatus.temperature` are the **setpoints**
  (equal to `heatSet` in the full status), `tankStatus.temperatureNow` is the
  actual tank temperature.
- An unconfigured zone 2 is still listed as a bare `{"zoneId": 2}`. The full
  status (`/remote/v1/api/devices`) lists only zone 1. A client that builds
  zones from this list gets a phantom zone 2.
- `connectionStatus` (0 here while the unit was reachable; meaning of other
  values not observed), `dhwFlg` (false although the unit has a tank; likely
  "DHW-only unit"), `a2wOwnerFlg`: unverified semantics.

## 2./3. Device status (`/remote/v1/api/devices`)

Full response with `deviceDirect=1` (redacted, unit idle):

```json
{"operation": "FFFFFFFF", "ownerFlg": true, "a2wName": "<deviceName>",
 "step2ApplicationStatusFlg": false,
 "status": {
  "serviceType": "STD_ADP-TAW1", "uncontrollableTaw1Flg": false,
  "operationMode": 1, "coolMode": 2, "direction": 1, "quietMode": 0, "powerful": 0,
  "forceDHW": 0, "forceHeater": 0, "tank": 1, "multiOdConnection": 0, "pumpDuty": 0,
  "bivalent": 0, "bivalentActual": 0, "waterPressure": 0, "electricAnode": 0,
  "deiceStatus": 0, "specialStatus": 0, "outdoorNow": 18, "holidayTimer": 0,
  "modelSeriesSelection": 1, "standAlone": 0, "controlBox": 0, "externalHeater": 0,
  "zoneStatus": [{"zoneId": 1, "zoneName": "<user zone name>", "zoneType": 0, "zoneSensor": 0,
    "operationStatus": 0, "temperatureNow": 26, "heatMin": 20, "heatMax": 55,
    "coolMin": 5, "coolMax": 20, "heatSet": 30, "coolSet": 16,
    "ecoHeat": -5, "ecoCool": 5, "comfortHeat": 5, "comfortCool": -5}],
  "tankStatus": {"operationStatus": 0, "temperatureNow": 32, "heatMin": 40, "heatMax": 75, "heatSet": 48}}}
```

Not present in this response: top-level `operationStatus`, `faultStatus`
(absent when there is no fault, rather than an empty list), and any power,
current, compressor frequency, flow rate, inlet/outlet water temperature or
energy counter. The cloud status has **no** analog run-time telemetry beyond
`outdoorNow`, zone `temperatureNow`, tank `temperatureNow` and `waterPressure`.

### deviceDirect=1 vs 0 (taken 6 s apart)

| Key | direct=1 | direct=0 |
|---|---|---|
| `status.direction` | 1 | 0 |
| `status.waterPressure` | 0 | *absent* |
| everything else | identical | identical |

`direction` disagrees between the two sources while the unit is idle
(`pumpDuty` 0, zone and tank off). `waterPressure` is only delivered by the
live read; it is 0 on this unit (probably no pressure sensor, unverified).

### Field reference

| Key | Seen | aioaquarea 1.3.1 | Notes |
|---|---|---|---|
| `operation` (top) | `"FFFFFFFF"` | not parsed | Looks like a permission/capability bitmask; unverified |
| `ownerFlg`, `step2ApplicationStatusFlg` (top) | true / false | not parsed | |
| `a2wName` (top) | device name | not parsed | Same as `deviceName` from `/device/group` |
| `serviceType` | `STD_ADP-TAW1` | not parsed | Adapter / service type; good model hint |
| `uncontrollableTaw1Flg` | false | not parsed | Presumably "adapter is in a state that cannot be controlled"; would be a useful availability/read-only flag; unverified |
| `operationMode` | 1 | parsed (`ExtendedOperationMode`, 99 = off) | |
| `coolMode` | 2 | not parsed | Unit has cooled before (Aug 2024 cooling kWh), so likely "cooling available"; value meaning unverified |
| `direction` | 1 / 0 | parsed (`DeviceDirection`) | Unreliable while idle (see above) |
| `quietMode`, `powerful`, `forceDHW`, `forceHeater`, `holidayTimer` | 0 | parsed | |
| `tank` | 1 | not parsed | Explicit "has tank" flag; library infers it from `tankStatus` in `/device/group` |
| `multiOdConnection` | 0 | not parsed | Also in consumption response; multiple outdoor units |
| `pumpDuty` | 0 | parsed (`PumpDuty`, 0/1) | Only 0 seen; whether it is a 0/1 flag or a duty level is unverified |
| `bivalent`, `bivalentActual` | 0 / 0 | not parsed | Bivalent (second heat source) configured / currently active |
| `waterPressure` | 0 | parsed | Only with `deviceDirect=1` |
| `electricAnode` | 0 | not parsed | Tank anti-corrosion anode |
| `deiceStatus` | 0 | parsed (`DeviceModeStatus`, defrost) | |
| `specialStatus` | 0 | **mis-parsed** | Library feeds it into `operation_status` (`OperationStatus(specialStatus)`: 0 → OFF, 1 → ON, 2 → UNKNOWN) and hard-codes `special_status=None`. Values per community clients: 0 normal, 1 eco, 2 comfort |
| `outdoorNow` | 18 | parsed | Integer °C |
| `modelSeriesSelection` | 1 | not parsed | |
| `standAlone` | 0 | not parsed | |
| `controlBox` | 0 | not parsed | Optional control box present |
| `externalHeater` | 0 | not parsed | |
| `faultStatus` | absent | parsed (`[{errorCode, errorMessage}]`, default `[]`) | |
| `zoneStatus[].zoneName` | user label | **not parsed** (library uses `"Zone N"`) | |
| `zoneStatus[].zoneType` | 0 | **not parsed** (library uses `"Unknown"`) | Enum mapping unverified (0 = room or water?) |
| `zoneStatus[].zoneSensor` | 0 | **not parsed** (library assumes direct) | Decides whether eco/comfort modifiers apply (`ZoneSensor.EXTERNAL`) |
| `zoneStatus[].temperatureNow/heat*/cool*/eco*/comfort*/operationStatus` | | parsed | |
| `tankStatus.*` | | parsed | |

## 4.-6. Consumption (`/remote/v1/api/consumption`, transfer `POST`)

Response envelope (all three modes):

```json
{"ownerFlg": true, "deviceRegisterTime": "YYYYMMDD", "elecMeterHp": 0, "multiOdConnection": 0,
 "electricRate": {"weekdayBaseRate": 36, "weekendBaseRate": 36, "currency": "<currency>"},
 "historyDataList": [ ... ]}
```

Bucket: `{"dataTime": ..., "heatConsumption", "coolConsumption", "tankConsumption", "heatCost", "coolCost", "tankCost", "outdoorTemp"}`
(kWh, currency units, °C).

| dataMode | `date` sent | `dataTime` format | Buckets |
|---|---|---|---|
| 0 day | `20261018` | `"20261018 HH"` | 24, hour-of-day in the `osTimezone` sent; the current hour is included (partial) |
| 1 month | `20261001` | `"20261001"` | One per calendar day of the month (31) |
| 2 year | `20260101` | `"202601"` | 12 months **ending at the month of `date`** (here 2025-02 .. 2026-01), plus `lastYearHistoryDataList` for the 12 months before that (2024-02 .. 2025-01). Inferred from one call: a rolling window, not a calendar year |

- Future buckets are present with zero values and **no `outdoorTemp` key**.
  The missing `outdoorTemp` is the only way to tell "future" from "zero
  consumption".
- `*Cost` = consumption x `electricRate` (for example 1.2 kWh x 36 = 43.2), so
  cost is computed by the cloud from the user-entered tariff, not metered.
- `outdoorTemp` is an average with sub-degree resolution (hourly values in
  0.25 °C steps; today's daily average was 506/49, consistent with a
  15-minute sample interval). `outdoorNow` in the status is an integer.
- `deviceRegisterTime`: date the unit was registered in the cloud; months
  before that are zeros without `outdoorTemp`.
- `elecMeterHp`: probably "external electricity meter configured"; unverified.

## 7. Weekly timer (`/remote/v1/api/data/weeklyTimer`)

Request: transfer `{"apiName": "/remote/v1/api/data/weeklyTimer?gwid=<guid>", "requestMethod": "GET"}`.

```json
{"weeklyTimer": {"operation": 0, "timer": [
   {"patternList": [
     {"startTime": "16:45", "mode": 3, "zone1OnOff": 1, "zone1Heat": 31, "zone1Cool": 18,
      "tankOnOff": 1, "tankTemperature": 45},
     {"startTime": "19:00", "mode": 3, "zone1OnOff": 1, "zone1Heat": 31, "zone1Cool": 18,
      "tankOnOff": 0, "tankTemperature": 45},
     {}, {}, {}, {}]},
   "... 7 day entries in total (Monday first per aio-panasonic-comfort-cloud), 6 slots each, unused slots are {}"]},
 "status": {"zoneStatus": [{"zoneId": 1, "heatMin": 20, "heatMax": 55, "coolMin": 5, "coolMax": 20},
                           {"zoneId": 2, "heatMin": -5, "heatMax": 5, "coolMin": -5, "coolMax": 5}],
            "tankStatus": {"heatMin": 40, "heatMax": 75}}}
```

- `weeklyTimer.operation`: 0 = schedule disabled, 1 = enabled (per
  aio-panasonic-comfort-cloud; 0 seen here).
- `mode` 3 was seen with heat and cool setpoints both filled. In the
  operation-update enum 3 is COOL (`OFF 0, HEAT 2, COOL 3, AUTO 8`); whether
  the timer uses the same encoding is **unverified**.
- Zone 2 keys (`zone2OnOff`, `zone2Heat`, `zone2Cool`) are absent for a
  one-zone unit, and the zone 2 limits of -5..5 look like the
  compensation-curve shift range, not a real zone.

## Status re-read (analog values)

Three `deviceDirect=1` reads at t=0, t+109 s and t+170 s: identical
`status` objects. The unit was idle, so this shows
nothing about update rate while running. The status has no power, current,
frequency or flow fields in any case.

## Session notes

- One password login served all 19 requests (token lifetime well above the
  ~4 minute session). Panasonic sends a login notification email on every
  password login.
- A second session on the same account did not log Home Assistant's
  aioaquarea session out within the observation window (HA entities stayed
  available).

## Support in this library

What aioaquarea-ng does with the above (sanitized copies of the responses are
in `tests/fixtures/live/`):

| Map item | Library |
|---|---|
| `specialStatus` | `Device.special_status`: 0 -> `None`, 1 -> `SpecialStatus.ECO`, 2 -> `SpecialStatus.COMFORT` |
| Device on/off | `Device.operation_status`: an explicit top-level `operationStatus` if present, else ON while any zone or the tank is on |
| `set_special_status` | Undoes the current preset's offset, applies the new one (clamped), sends `specialStatus` + zone setpoints through the transfer proxy (`POST /remote/v1/api/devices`). Not verified live |
| `turn_on` / `turn_off` | `{"operationStatus": 0/1}` through the transfer proxy (the old `/remote/v1/api/devices/<guid>` route is gone). Not verified live |
| Zones | Built from the status `zoneStatus[]`; bare `{"zoneId": N}` placeholders in `/device/group` are skipped. `DeviceZone.name` = `zoneName`, raw `zone_type_id` / `zone_sensor_id`; `zoneSensor` 0 -> `ZoneSensor.WATER_TEMPERATURE`, other values -> `ZoneSensor.UNKNOWN` until confirmed |
| `coolMode` | Non-zero -> zones support cooling; without `coolMode` the old heuristic (device list / zone cooling range) is used |
| `tank` | `Device.has_tank` = `tank` flag and a reported `tankStatus`; without the flag the device list decides |
| Other status fields | `Device.bivalent`, `bivalent_actual`, `external_heater`, `electric_anode`, `control_box`, `uncontrollable` (`uncontrollableTaw1Flg`), `service_type`, `multi_od_connection`, `model_series_selection`, `stand_alone`, `cool_mode` (raw values, None when missing) |
| `/device/group` fields | `DeviceInfo.connection_status`, `DeviceInfo.dhw_flag` (also on `Device`) |
| `deviceDirect=0` fallback | `Device.status_data_mode` / `DeviceStatus.data_mode` = `CACHED`; `water_pressure` is None then |
| Consumption | `Client.get_device_consumption_report()` -> `ConsumptionReport` (`history`, `last_year_history`, `electric_rate`, `currency`, `device_register_time`, ...); `Consumption.is_future` for buckets without `outdoorTemp` |
| Weekly timer | `Client.get_weekly_timer()` / `Device.get_weekly_timer()` -> `WeeklyTimer` (read only) |
| Agreements | `Client.get_agreement_status()`; error code 4103 raises `AgreementNotAcceptedError` |
| Gateway errors | `{"code": N, "message": ...}` bodies raise `ApiError` with `error_code` `"N"` |

