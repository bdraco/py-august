import os
import unittest
from datetime import datetime

import requests_mock
import dateutil.parser
from dateutil.tz import tzutc, tzlocal
from requests.exceptions import HTTPError
from requests.models import Response
from requests.structures import CaseInsensitiveDict
from aioresponses import aioresponses

from august.api_common import (
    API_GET_DOORBELL_URL,
    API_GET_DOORBELLS_URL,
    API_GET_HOUSE_ACTIVITIES_URL,
    API_GET_LOCK_STATUS_URL,
    API_GET_LOCK_URL,
    API_GET_LOCKS_URL,
    API_GET_PINS_URL,
    API_LOCK_URL,
    API_UNLOCK_URL,
    _raise_response_exceptions,
)

from august.api_async import (
    AsyncApi
)
from august.bridge import BridgeDetail, BridgeStatus, BridgeStatusDetail
from august.exceptions import AugustApiHTTPError
from august.lock import LockDoorStatus, LockStatus

ACCESS_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"


def load_fixture(filename):
    """Load a fixture."""
    path = os.path.join(os.path.dirname(__file__), "fixtures", filename)
    with open(path) as fptr:
        return fptr.read()


def utc_of(year, month, day, hour, minute, second, microsecond):
    return datetime(year, month, day, hour, minute, second, microsecond, tzinfo=tzutc())


class TestAsyncApi(unittest.TestCase):
    @aioresponses()
    async def test_async_get_doorbells(self, mock):
        mock.register_uri(
            "get", API_GET_DOORBELLS_URL, text=load_fixture("get_doorbells.json")
        )

        api = AsyncApi()
        doorbells = sorted(api.get_doorbells(ACCESS_TOKEN), key=lambda d: d.device_id)

        self.assertEqual(2, len(doorbells))

        first = doorbells[0]
        self.assertEqual("1KDAbJH89XYZ", first.device_id)
        self.assertEqual("aaaaR08888", first.serial_number)
        self.assertEqual("Back Door", first.device_name)
        self.assertEqual("doorbell_call_status_offline", first.status)
        self.assertEqual(False, first.has_subscription)
        self.assertEqual(None, first.image_url)
        self.assertEqual("3dd2accadddd", first.house_id)

        second = doorbells[1]
        self.assertEqual("K98GiDT45GUL", second.device_id)
        self.assertEqual("tBXZR0Z35E", second.serial_number)
        self.assertEqual("Front Door", second.device_name)
        self.assertEqual("doorbell_call_status_online", second.status)
        self.assertEqual(True, second.has_subscription)
        self.assertEqual("https://image.com/vmk16naaaa7ibuey7sar.jpg", second.image_url)
        self.assertEqual("3dd2accaea08", second.house_id)

    @aioresponses()
    async def test_async_get_doorbell_detail(self, mock):
        expected_doorbell_image_url = "https://image.com/vmk16naaaa7ibuey7sar.jpg"
        mock.register_uri(
            "get",
            API_GET_DOORBELL_URL.format(doorbell_id="K98GiDT45GUL"),
            text=load_fixture("get_doorbell.json"),
        )
        mock.register_uri(
            "get", expected_doorbell_image_url, text="doorbell_image_mocked"
        )

        api = AsyncApi()
        doorbell = api.get_doorbell_detail(ACCESS_TOKEN, "K98GiDT45GUL")

        self.assertEqual("K98GiDT45GUL", doorbell.device_id)
        self.assertEqual("Front Door", doorbell.device_name)
        self.assertEqual("3dd2accaea08", doorbell.house_id)
        self.assertEqual("tBXZR0Z35E", doorbell.serial_number)
        self.assertEqual("2.3.0-RC153+201711151527", doorbell.firmware_version)
        self.assertEqual("doorbell_call_status_online", doorbell.status)
        self.assertEqual(96, doorbell.battery_level)
        self.assertEqual("gen1", doorbell.model)
        self.assertEqual(True, doorbell.is_online)
        self.assertEqual(False, doorbell.is_standby)
        self.assertEqual(
            dateutil.parser.parse("2017-12-10T08:01:35Z"),
            doorbell.image_created_at_datetime,
        )
        self.assertEqual(True, doorbell.has_subscription)
        self.assertEqual(expected_doorbell_image_url, doorbell.image_url)
        self.assertEqual(doorbell.get_doorbell_image(), b"doorbell_image_mocked")
        self.assertEqual(
            doorbell.get_doorbell_image(timeout=50), b"doorbell_image_mocked"
        )

    @aioresponses()
    async def test_async_get_doorbell_detail_missing_image(self, mock):
        mock.register_uri(
            "get",
            API_GET_DOORBELL_URL.format(doorbell_id="K98GiDT45GUL"),
            text=load_fixture("get_doorbell_missing_image.json"),
        )

        api = AsyncApi()
        doorbell = api.get_doorbell_detail(ACCESS_TOKEN, "K98GiDT45GUL")

        self.assertEqual("K98GiDT45GUL", doorbell.device_id)
        self.assertEqual("Front Door", doorbell.device_name)
        self.assertEqual("3dd2accaea08", doorbell.house_id)
        self.assertEqual("tBXZR0Z35E", doorbell.serial_number)
        self.assertEqual("2.3.0-RC153+201711151527", doorbell.firmware_version)
        self.assertEqual("doorbell_call_status_online", doorbell.status)
        self.assertEqual(96, doorbell.battery_level)
        self.assertEqual(True, doorbell.is_online)
        self.assertEqual(False, doorbell.is_standby)
        self.assertEqual(None, doorbell.image_created_at_datetime)
        self.assertEqual(True, doorbell.has_subscription)
        self.assertEqual(None, doorbell.image_url)

    @requests_mock.Mocker()
    async def test_async_get_doorbell_offline(self, mock):
        mock.register_uri(
            "get",
            API_GET_DOORBELL_URL.format(doorbell_id="231ee2168dd0"),
            text=load_fixture("get_doorbell.offline.json"),
        )

        api = AsyncApi()
        doorbell = api.get_doorbell_detail(ACCESS_TOKEN, "231ee2168dd0")

        self.assertEqual("231ee2168dd0", doorbell.device_id)
        self.assertEqual("My Door", doorbell.device_name)
        self.assertEqual("houseid", doorbell.house_id)
        self.assertEqual("abcd", doorbell.serial_number)
        self.assertEqual("3.1.0-HYDRC75+201909251139", doorbell.firmware_version)
        self.assertEqual("doorbell_offline", doorbell.status)
        self.assertEqual(81, doorbell.battery_level)
        self.assertEqual(False, doorbell.is_online)
        self.assertEqual(False, doorbell.is_standby)
        self.assertEqual(
            dateutil.parser.parse("2019-02-20T23:52:46Z"),
            doorbell.image_created_at_datetime,
        )
        self.assertEqual(True, doorbell.has_subscription)
        self.assertEqual("https://res.cloudinary.com/x.jpg", doorbell.image_url)
        self.assertEqual("hydra1", doorbell.model)

    @aioresponses()
    async def test_async_get_doorbell_gen2_full_battery_detail(self, mock):
        mock.register_uri(
            "get",
            API_GET_DOORBELL_URL.format(doorbell_id="did"),
            text=load_fixture("get_doorbell.battery_full.json"),
        )

        api = AsyncApi()
        doorbell = api.get_doorbell_detail(ACCESS_TOKEN, "did")

        self.assertEqual(100, doorbell.battery_level)

    @aioresponses()
    async def test_async_get_doorbell_gen2_medium_battery_detail(self, mock):
        mock.register_uri(
            "get",
            API_GET_DOORBELL_URL.format(doorbell_id="did"),
            text=load_fixture("get_doorbell.battery_medium.json"),
        )

        api = AsyncApi()
        doorbell = api.get_doorbell_detail(ACCESS_TOKEN, "did")

        self.assertEqual(75, doorbell.battery_level)

    @aioresponses()
    async def test_async_get_doorbell_gen2_low_battery_detail(self, mock):
        mock.register_uri(
            "get",
            API_GET_DOORBELL_URL.format(doorbell_id="did"),
            text=load_fixture("get_doorbell.battery_low.json"),
        )

        api = AsyncApi()
        doorbell = api.get_doorbell_detail(ACCESS_TOKEN, "did")

        self.assertEqual(10, doorbell.battery_level)

    @aioresponses()
    async def test_async_get_locks(self, mock):
        mock.register_uri("get", API_GET_LOCKS_URL, text=load_fixture("get_locks.json"))

        api = AsyncApi()
        locks = sorted(api.get_locks(ACCESS_TOKEN), key=lambda d: d.device_id)

        self.assertEqual(2, len(locks))

        first = locks[0]
        self.assertEqual("A6697750D607098BAE8D6BAA11EF8063", first.device_id)
        self.assertEqual("Front Door Lock", first.device_name)
        self.assertEqual("000000000000", first.house_id)
        self.assertEqual(True, first.is_operable)

        second = locks[1]
        self.assertEqual("A6697750D607098BAE8D6BAA11EF9999", second.device_id)
        self.assertEqual("Back Door Lock", second.device_name)
        self.assertEqual("000000000011", second.house_id)
        self.assertEqual(False, second.is_operable)

    @aioresponses()
    async def test_async_get_operable_locks(self, mock):
        mock.register_uri("get", API_GET_LOCKS_URL, text=load_fixture("get_locks.json"))

        api = AsyncApi()
        locks = api.get_operable_locks(ACCESS_TOKEN)

        self.assertEqual(1, len(locks))

        first = locks[0]
        self.assertEqual("A6697750D607098BAE8D6BAA11EF8063", first.device_id)
        self.assertEqual("Front Door Lock", first.device_name)
        self.assertEqual("000000000000", first.house_id)
        self.assertEqual(True, first.is_operable)

    @aioresponses()
    async def test_async_get_lock_detail_with_doorsense_bridge_online(self, mock):
        mock.register_uri(
            "get",
            API_GET_LOCK_URL.format(lock_id="ABC"),
            text=load_fixture("get_lock.online_with_doorsense.json"),
        )

        api = AsyncApi()
        lock = api.get_lock_detail(ACCESS_TOKEN, "ABC")

        self.assertEqual("ABC", lock.device_id)
        self.assertEqual("Online door with doorsense", lock.device_name)
        self.assertEqual("123", lock.house_id)
        self.assertEqual("XY", lock.serial_number)
        self.assertEqual("undefined-4.3.0-1.8.14", lock.firmware_version)
        self.assertEqual(92, lock.battery_level)
        self.assertEqual("AUG-MD01", lock.model)
        self.assertEqual(None, lock.keypad)
        self.assertIsInstance(lock.bridge, BridgeDetail)
        self.assertIsInstance(lock.bridge.status, BridgeStatusDetail)
        self.assertEqual(BridgeStatus.ONLINE, lock.bridge.status.current)
        self.assertEqual(True, lock.bridge_is_online)
        self.assertEqual(True, lock.bridge.operative)
        self.assertEqual(True, lock.doorsense)

        self.assertEqual(LockStatus.LOCKED, lock.lock_status)
        self.assertEqual(LockDoorStatus.OPEN, lock.door_state)
        self.assertEqual(
            dateutil.parser.parse("2017-12-10T04:48:30.272Z"), lock.lock_status_datetime
        )
        self.assertEqual(
            dateutil.parser.parse("2017-12-10T04:48:30.272Z"), lock.door_state_datetime
        )

    @aioresponses()
    async def test_async_get_lock_detail_bridge_online(self, mock):
        mock.register_uri(
            "get",
            API_GET_LOCK_URL.format(lock_id="A6697750D607098BAE8D6BAA11EF8063"),
            text=load_fixture("get_lock.online.json"),
        )

        api = AsyncApi()
        lock = api.get_lock_detail(ACCESS_TOKEN, "A6697750D607098BAE8D6BAA11EF8063")

        self.assertEqual("A6697750D607098BAE8D6BAA11EF8063", lock.device_id)
        self.assertEqual("Front Door Lock", lock.device_name)
        self.assertEqual("000000000000", lock.house_id)
        self.assertEqual("X2FSW05DGA", lock.serial_number)
        self.assertEqual("109717e9-3.0.44-3.0.30", lock.firmware_version)
        self.assertEqual(88, lock.battery_level)
        self.assertEqual("AUG-SL02-M02-S02", lock.model)
        self.assertEqual("Medium", lock.keypad.battery_level)
        self.assertEqual(60, lock.keypad.battery_percentage)
        self.assertEqual("5bc65c24e6ef2a263e1450a8", lock.keypad.device_id)
        self.assertIsInstance(lock.bridge, BridgeDetail)
        self.assertEqual(True, lock.bridge_is_online)
        self.assertEqual(True, lock.bridge.operative)
        self.assertEqual(True, lock.doorsense)

        self.assertEqual(LockStatus.LOCKED, lock.lock_status)
        self.assertEqual(LockDoorStatus.CLOSED, lock.door_state)
        self.assertEqual(
            dateutil.parser.parse("2017-12-10T04:48:30.272Z"), lock.lock_status_datetime
        )
        self.assertEqual(
            dateutil.parser.parse("2017-12-10T04:48:30.272Z"), lock.door_state_datetime
        )

    @aioresponses()
    async def test_async_get_lock_detail_bridge_offline(self, mock):
        mock.register_uri(
            "get",
            API_GET_LOCK_URL.format(lock_id="ABC"),
            text=load_fixture("get_lock.offline.json"),
        )

        api = AsyncApi()
        lock = api.get_lock_detail(ACCESS_TOKEN, "ABC")

        self.assertEqual("ABC", lock.device_id)
        self.assertEqual("Test", lock.device_name)
        self.assertEqual("houseid", lock.house_id)
        self.assertEqual("ABC", lock.serial_number)
        self.assertEqual("undefined-1.59.0-1.13.2", lock.firmware_version)
        self.assertEqual(-100, lock.battery_level)
        self.assertEqual("AUG-X", lock.model)
        self.assertEqual(False, lock.bridge_is_online)
        self.assertEqual(None, lock.keypad)
        self.assertEqual(None, lock.bridge)
        self.assertEqual(False, lock.doorsense)

        self.assertEqual(LockStatus.UNKNOWN, lock.lock_status)
        self.assertEqual(LockDoorStatus.UNKNOWN, lock.door_state)
        self.assertEqual(None, lock.lock_status_datetime)
        self.assertEqual(None, lock.door_state_datetime)

    @aioresponses()
    async def test_async_get_lock_detail_doorsense_init_state(self, mock):
        mock.register_uri(
            "get",
            API_GET_LOCK_URL.format(lock_id="A6697750D607098BAE8D6BAA11EF8063"),
            text=load_fixture("get_lock.doorsense_init.json"),
        )

        api = AsyncApi()
        lock = api.get_lock_detail(ACCESS_TOKEN, "A6697750D607098BAE8D6BAA11EF8063")

        self.assertEqual("A6697750D607098BAE8D6BAA11EF8063", lock.device_id)
        self.assertEqual("Front Door Lock", lock.device_name)
        self.assertEqual("000000000000", lock.house_id)
        self.assertEqual("X2FSW05DGA", lock.serial_number)
        self.assertEqual("109717e9-3.0.44-3.0.30", lock.firmware_version)
        self.assertEqual(88, lock.battery_level)
        self.assertEqual("Medium", lock.keypad.battery_level)
        self.assertEqual("5bc65c24e6ef2a263e1450a8", lock.keypad.device_id)
        self.assertEqual("AK-R1", lock.keypad.model)
        self.assertEqual("Front Door Lock Keypad", lock.keypad.device_name)
        self.assertIsInstance(lock.bridge, BridgeDetail)
        self.assertEqual(True, lock.bridge_is_online)
        self.assertEqual(True, lock.bridge.operative)
        self.assertEqual(False, lock.doorsense)

        self.assertEqual(LockStatus.LOCKED, lock.lock_status)
        self.assertEqual(LockDoorStatus.UNKNOWN, lock.door_state)
        self.assertEqual(
            dateutil.parser.parse("2017-12-10T04:48:30.272Z"), lock.lock_status_datetime
        )
        self.assertEqual(
            dateutil.parser.parse("2017-12-10T04:48:30.272Z"), lock.door_state_datetime
        )

        lock.lock_status = LockStatus.UNLOCKED
        self.assertEqual(LockStatus.UNLOCKED, lock.lock_status)

        lock.door_state = LockDoorStatus.OPEN
        self.assertEqual(LockDoorStatus.OPEN, lock.door_state)

        lock.lock_status_datetime = dateutil.parser.parse("2020-12-10T04:48:30.272Z")
        self.assertEqual(
            dateutil.parser.parse("2020-12-10T04:48:30.272Z"), lock.lock_status_datetime
        )
        lock.door_state_datetime = dateutil.parser.parse("2019-12-10T04:48:30.272Z")
        self.assertEqual(
            dateutil.parser.parse("2019-12-10T04:48:30.272Z"), lock.door_state_datetime
        )

    @aioresponses()
    async def test_async_get_lock_status_with_locked_response(self, mock):
        lock_id = 1234
        mock.register_uri(
            "get",
            API_GET_LOCK_STATUS_URL.format(lock_id=lock_id),
            text='{"status": "kAugLockState_Locked"}',
        )

        api = AsyncApi()
        status = api.get_lock_status(ACCESS_TOKEN, lock_id)

        self.assertEqual(LockStatus.LOCKED, status)

    @aioresponses()
    async def test_async_get_lock_and_door_status_with_locked_response(self, mock):
        lock_id = 1234
        mock.register_uri(
            "get",
            API_GET_LOCK_STATUS_URL.format(lock_id=lock_id),
            text='{"status": "kAugLockState_Locked"'
            ',"doorState": "kAugLockDoorState_Closed"}',
        )

        api = AsyncApi()
        status, door_status = api.get_lock_status(ACCESS_TOKEN, lock_id, True)

        self.assertEqual(LockStatus.LOCKED, status)
        self.assertEqual(LockDoorStatus.CLOSED, door_status)

    @aioresponses()
    async def test_async_get_lock_status_with_unlocked_response(self, mock):
        lock_id = 1234
        mock.register_uri(
            "get",
            API_GET_LOCK_STATUS_URL.format(lock_id=lock_id),
            text='{"status": "kAugLockState_Unlocked"}',
        )

        api = AsyncApi()
        status = api.get_lock_status(ACCESS_TOKEN, lock_id)

        self.assertEqual(LockStatus.UNLOCKED, status)

    @aioresponses()
    async def test_async_get_lock_status_with_unknown_status_response(self, mock):
        lock_id = 1234
        mock.register_uri(
            "get",
            API_GET_LOCK_STATUS_URL.format(lock_id=lock_id),
            text='{"status": "not_advertising"}',
        )

        api = AsyncApi()
        status = api.get_lock_status(ACCESS_TOKEN, lock_id)

        self.assertEqual(LockStatus.UNKNOWN, status)

    @aioresponses()
    async def test_async_get_lock_door_status_with_closed_response(self, mock):
        lock_id = 1234
        mock.register_uri(
            "get",
            API_GET_LOCK_STATUS_URL.format(lock_id=lock_id),
            text='{"doorState": "kAugLockDoorState_Closed"}',
        )

        api = AsyncApi()
        door_status = api.get_lock_door_status(ACCESS_TOKEN, lock_id)

        self.assertEqual(LockDoorStatus.CLOSED, door_status)

    @aioresponses()
    async def test_async_get_lock_door_status_with_open_response(self, mock):
        lock_id = 1234
        mock.register_uri(
            "get",
            API_GET_LOCK_STATUS_URL.format(lock_id=lock_id),
            text='{"doorState": "kAugLockDoorState_Open"}',
        )

        api = AsyncApi()
        door_status = api.get_lock_door_status(ACCESS_TOKEN, lock_id)

        self.assertEqual(LockDoorStatus.OPEN, door_status)

    @aioresponses()
    async def test_async_get_lock_and_door_status_with_open_response(self, mock):
        lock_id = 1234
        mock.register_uri(
            "get",
            API_GET_LOCK_STATUS_URL.format(lock_id=lock_id),
            text='{"status": "kAugLockState_Unlocked"'
            ',"doorState": "kAugLockDoorState_Open"}',
        )

        api = AsyncApi()
        door_status, status = api.get_lock_door_status(ACCESS_TOKEN, lock_id, True)

        self.assertEqual(LockDoorStatus.OPEN, door_status)
        self.assertEqual(LockStatus.UNLOCKED, status)

    @aioresponses()
    async def test_async_get_lock_door_status_with_unknown_response(self, mock):
        lock_id = 1234
        mock.register_uri(
            "get",
            API_GET_LOCK_STATUS_URL.format(lock_id=lock_id),
            text='{"doorState": "not_advertising"}',
        )

        api = AsyncApi()
        door_status = api.get_lock_door_status(ACCESS_TOKEN, lock_id)

        self.assertEqual(LockDoorStatus.UNKNOWN, door_status)

    @aioresponses()
    async def test_async_lock_from_fixture(self, mock):
        lock_id = 1234
        mock.register_uri(
            "put", API_LOCK_URL.format(lock_id=lock_id), text=load_fixture("lock.json")
        )

        api = AsyncApi()
        status = api.lock(ACCESS_TOKEN, lock_id)

        self.assertEqual(LockStatus.LOCKED, status)

    @aioresponses()
    async def test_async_unlock_from_fixture(self, mock):
        lock_id = 1234
        mock.register_uri(
            "put",
            API_UNLOCK_URL.format(lock_id=lock_id),
            text=load_fixture("unlock.json"),
        )

        api = AsyncApi()
        status = api.unlock(ACCESS_TOKEN, lock_id)

        self.assertEqual(LockStatus.UNLOCKED, status)

    @aioresponses()
    async def test_async_lock_return_activities_from_fixture(self, mock):
        lock_id = 1234
        mock.register_uri(
            "put", API_LOCK_URL.format(lock_id=lock_id), text=load_fixture("lock.json")
        )

        api = AsyncApi()
        activities = api.lock_return_activities(ACCESS_TOKEN, lock_id)
        expected_lock_dt = (
            dateutil.parser.parse("2020-02-19T19:44:54.371Z")
            .astimezone(tz=tzlocal())
            .replace(tzinfo=None)
        )

        self.assertEqual(len(activities), 2)
        self.assertIsInstance(activities[0], august.activity.LockOperationActivity)
        self.assertEqual(activities[0].device_id, "ABC123")
        self.assertEqual(activities[0].device_type, "lock")
        self.assertEqual(activities[0].action, "lock")
        self.assertEqual(activities[0].activity_start_time, expected_lock_dt)
        self.assertEqual(activities[0].activity_end_time, expected_lock_dt)
        self.assertIsInstance(activities[1], august.activity.DoorOperationActivity)
        self.assertEqual(activities[1].device_id, "ABC123")
        self.assertEqual(activities[1].device_type, "lock")
        self.assertEqual(activities[1].action, "doorclosed")
        self.assertEqual(activities[0].activity_start_time, expected_lock_dt)
        self.assertEqual(activities[0].activity_end_time, expected_lock_dt)

    @aioresponses()
    async def test_async_unlock_return_activities_from_fixture(self, mock):
        lock_id = 1234
        mock.register_uri(
            "put",
            API_UNLOCK_URL.format(lock_id=lock_id),
            text=load_fixture("unlock.json"),
        )

        api = AsyncApi()
        activities = api.unlock_return_activities(ACCESS_TOKEN, lock_id)
        expected_unlock_dt = (
            dateutil.parser.parse("2020-02-19T19:44:26.745Z")
            .astimezone(tz=tzlocal())
            .replace(tzinfo=None)
        )

        self.assertEqual(len(activities), 2)
        self.assertIsInstance(activities[0], august.activity.LockOperationActivity)
        self.assertEqual(activities[0].device_id, "ABC")
        self.assertEqual(activities[0].device_type, "lock")
        self.assertEqual(activities[0].action, "unlock")
        self.assertEqual(activities[0].activity_start_time, expected_unlock_dt)
        self.assertEqual(activities[0].activity_end_time, expected_unlock_dt)
        self.assertIsInstance(activities[1], august.activity.DoorOperationActivity)
        self.assertEqual(activities[1].device_id, "ABC")
        self.assertEqual(activities[1].device_type, "lock")
        self.assertEqual(activities[1].action, "doorclosed")
        self.assertEqual(activities[1].activity_start_time, expected_unlock_dt)
        self.assertEqual(activities[1].activity_end_time, expected_unlock_dt)

    @aioresponses()
    async def test_async_lock_return_activities_from_fixture_with_no_doorstate(self, mock):
        lock_id = 1234
        mock.register_uri(
            "put",
            API_LOCK_URL.format(lock_id=lock_id),
            text=load_fixture("lock_without_doorstate.json"),
        )

        api = AsyncApi()
        activities = api.lock_return_activities(ACCESS_TOKEN, lock_id)
        expected_lock_dt = (
            dateutil.parser.parse("2020-02-19T19:44:54.371Z")
            .astimezone(tz=tzlocal())
            .replace(tzinfo=None)
        )

        self.assertEqual(len(activities), 1)
        self.assertIsInstance(activities[0], august.activity.LockOperationActivity)
        self.assertEqual(activities[0].device_id, "ABC123")
        self.assertEqual(activities[0].device_type, "lock")
        self.assertEqual(activities[0].action, "lock")
        self.assertEqual(activities[0].activity_start_time, expected_lock_dt)
        self.assertEqual(activities[0].activity_end_time, expected_lock_dt)

    @aioresponses()
    async def test_async_unlock_return_activities_from_fixture_with_no_doorstate(self, mock):
        lock_id = 1234
        mock.register_uri(
            "put",
            API_UNLOCK_URL.format(lock_id=lock_id),
            text=load_fixture("unlock_without_doorstate.json"),
        )

        api = AsyncApi()
        activities = api.unlock_return_activities(ACCESS_TOKEN, lock_id)
        expected_unlock_dt = (
            dateutil.parser.parse("2020-02-19T19:44:26.745Z")
            .astimezone(tz=tzlocal())
            .replace(tzinfo=None)
        )

        self.assertEqual(len(activities), 1)
        self.assertIsInstance(activities[0], august.activity.LockOperationActivity)
        self.assertEqual(activities[0].device_id, "ABC123")
        self.assertEqual(activities[0].device_type, "lock")
        self.assertEqual(activities[0].action, "unlock")
        self.assertEqual(activities[0].activity_start_time, expected_unlock_dt)
        self.assertEqual(activities[0].activity_end_time, expected_unlock_dt)

    @aioresponses()
    async def test_async_lock(self, mock):
        lock_id = 1234
        mock.register_uri(
            "put",
            API_LOCK_URL.format(lock_id=lock_id),
            text='{"status":"locked",'
            '"dateTime":"2017-12-10T07:43:39.056Z",'
            '"isLockStatusChanged":false,'
            '"valid":true}',
        )

        api = AsyncApi()
        status = api.lock(ACCESS_TOKEN, lock_id)

        self.assertEqual(LockStatus.LOCKED, status)

    @aioresponses()
    async def test_async_unlock(self, mock):
        lock_id = 1234
        mock.register_uri(
            "put", API_UNLOCK_URL.format(lock_id=lock_id), text='{"status": "unlocked"}'
        )

        api = AsyncApi()
        status = api.unlock(ACCESS_TOKEN, lock_id)

        self.assertEqual(LockStatus.UNLOCKED, status)

    @aioresponses()
    async def test_async_get_pins(self, mock):
        lock_id = 1234
        mock.register_uri(
            "get",
            API_GET_PINS_URL.format(lock_id=lock_id),
            text=load_fixture("get_pins.json"),
        )

        api = AsyncApi()
        pins = api.get_pins(ACCESS_TOKEN, lock_id)

        self.assertEqual(1, len(pins))

        first = pins[0]
        self.assertEqual("epoZ87XSPqxlFdsaYyJiRRVR", first.pin_id)
        self.assertEqual("A6697750D607098BAE8D6BAA11EF8063", first.lock_id)
        self.assertEqual("c3b3a94f-473z-61a3-a8d1-a6e99482787a", first.user_id)
        self.assertEqual("in-use", first.state)
        self.assertEqual("123456", first.pin)
        self.assertEqual(646545456465161, first.slot)
        self.assertEqual("one-time", first.access_type)
        self.assertEqual("John", first.first_name)
        self.assertEqual("Doe", first.last_name)
        self.assertEqual(True, first.unverified)
        self.assertEqual(utc_of(2016, 11, 26, 22, 27, 11, 176000), first.created_at)
        self.assertEqual(utc_of(2017, 11, 23, 00, 42, 19, 470000), first.updated_at)
        self.assertEqual(utc_of(2017, 12, 10, 3, 12, 55, 563000), first.loaded_date)
        self.assertEqual(utc_of(2018, 1, 1, 1, 1, 1, 563000), first.access_start_time)
        self.assertEqual(utc_of(2018, 12, 1, 1, 1, 1, 563000), first.access_end_time)
        self.assertEqual(utc_of(2018, 11, 5, 10, 2, 41, 684000), first.access_times)

    @aioresponses()
    async def test_async_get_house_activities(self, mock):
        house_id = 1234
        mock.register_uri(
            "get",
            API_GET_HOUSE_ACTIVITIES_URL.format(house_id=house_id),
            text=load_fixture("get_house_activities.json"),
        )

        api = AsyncApi()
        activities = api.get_house_activities(ACCESS_TOKEN, house_id)

        self.assertEqual(10, len(activities))

        self.assertIsInstance(activities[0], august.activity.LockOperationActivity)
        self.assertIsInstance(activities[1], august.activity.LockOperationActivity)
        self.assertIsInstance(activities[2], august.activity.LockOperationActivity)
        self.assertIsInstance(activities[3], august.activity.LockOperationActivity)
        self.assertIsInstance(activities[4], august.activity.LockOperationActivity)
        self.assertIsInstance(activities[5], august.activity.DoorOperationActivity)
        self.assertIsInstance(activities[6], august.activity.DoorOperationActivity)
        self.assertIsInstance(activities[7], august.activity.DoorOperationActivity)
        self.assertIsInstance(activities[8], august.activity.LockOperationActivity)
        self.assertIsInstance(activities[9], august.activity.LockOperationActivity)

class MockedResponse(Response):
    def __init__(self, *args, **kwargs):
        content = kwargs.pop("content", None)
        super(MockedResponse, self).__init__(*args, **kwargs)
        self._mocked_content = content

    @property
    def content(self):
        return self._mocked_content
