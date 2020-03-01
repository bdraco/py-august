import json
import logging
import time

import dateutil.parser
from requests import Session, request
from requests.exceptions import HTTPError

from august.activity import (
    ACTIVITY_ACTIONS_DOOR_OPERATION,
    ACTIVITY_ACTIONS_DOORBELL_DING,
    ACTIVITY_ACTIONS_DOORBELL_MOTION,
    ACTIVITY_ACTIONS_DOORBELL_VIEW,
    ACTIVITY_ACTIONS_LOCK_OPERATION,
    DoorbellDingActivity,
    DoorbellMotionActivity,
    DoorbellViewActivity,
    DoorOperationActivity,
    LockOperationActivity,
)
from august.doorbell import Doorbell, DoorbellDetail
from august.exceptions import AugustApiHTTPError
from august.lock import (
    Lock,
    LockDetail,
    LockDoorStatus,
    determine_door_state,
    determine_lock_status,
    door_state_to_string,
)
from august.pin import Pin

from .api.common import (
    _raise_response_exceptions,
    _convert_lock_result_to_activities,
    _activity_from_dict,
    _map_lock_result_to_activity,
    _datetime_string_to_epoch,
    _process_activity_json,
    _process_doorbells_json,
    _process_locks_json,
)

from .api.common import (
    HEADER_ACCEPT_VERSION,
    HEADER_AUGUST_ACCESS_TOKEN,
    HEADER_AUGUST_API_KEY,
    HEADER_KEASE_API_KEY,
    HEADER_CONTENT_TYPE,
    HEADER_USER_AGENT,
    HEADER_VALUE_API_KEY,
    HEADER_VALUE_CONTENT_TYPE,
    HEADER_VALUE_USER_AGENT,
    HEADER_VALUE_ACCEPT_VERSION,
    API_RETRY_ATTEMPTS,
    API_RETRY_TIME,
    API_BASE_URL,
    API_GET_SESSION_URL,
    API_SEND_VERIFICATION_CODE_URLS,
    API_VALIDATE_VERIFICATION_CODE_URLS,
    API_GET_HOUSE_ACTIVITIES_URL,
    API_GET_DOORBELLS_URL,
    API_GET_DOORBELL_URL,
    API_WAKEUP_DOORBELL_URL,
    API_GET_HOUSES_URL,
    API_GET_HOUSE_URL,
    API_GET_LOCKS_URL,
    API_GET_LOCK_URL,
    API_GET_LOCK_STATUS_URL,
    API_GET_PINS_URL,
    API_LOCK_URL,
    API_UNLOCK_URL,
)


class Api:
    def __init__(self, timeout=10, command_timeout=60, http_session: Session = None):
        self._timeout = timeout
        self._command_timeout = command_timeout
        self._http_session = http_session

    def get_session(self, install_id, identifier, password):
        response = self._call_api(
            "post",
            API_GET_SESSION_URL,
            json={
                "installId": install_id,
                "identifier": identifier,
                "password": password,
            },
        )

        return response

    def send_verification_code(self, access_token, login_method, username):
        response = self._call_api(
            "post",
            API_SEND_VERIFICATION_CODE_URLS[login_method],
            access_token=access_token,
            json={"value": username},
        )

        return response

    def validate_verification_code(
        self, access_token, login_method, username, verification_code
    ):
        response = self._call_api(
            "post",
            API_VALIDATE_VERIFICATION_CODE_URLS[login_method],
            access_token=access_token,
            json={login_method: username, "code": str(verification_code)},
        )

        return response

    def get_doorbells(self, access_token):
        json_dict = self._call_api(
            "get", API_GET_DOORBELLS_URL, access_token=access_token
        ).json()

        return _process_doorbells_json(json_dict)

    def get_doorbell_detail(self, access_token, doorbell_id):
        response = self._call_api(
            "get",
            API_GET_DOORBELL_URL.format(doorbell_id=doorbell_id),
            access_token=access_token,
        )

        return DoorbellDetail(response.json())

    def wakeup_doorbell(self, access_token, doorbell_id):
        self._call_api(
            "put",
            API_WAKEUP_DOORBELL_URL.format(doorbell_id=doorbell_id),
            access_token=access_token,
        )

        return True

    def get_houses(self, access_token):
        response = self._call_api("get", API_GET_HOUSES_URL, access_token=access_token)

        return response.json()

    def get_house(self, access_token, house_id):
        response = self._call_api(
            "get",
            API_GET_HOUSE_URL.format(house_id=house_id),
            access_token=access_token,
        )

        return response.json()

    def get_house_activities(self, access_token, house_id, limit=8):
        response = self._call_api(
            "get",
            API_GET_HOUSE_ACTIVITIES_URL.format(house_id=house_id),
            access_token=access_token,
            params={"limit": limit},
        )

        return _process_activity_json(activity_json)

    def get_locks(self, access_token):
        json_dict = self._call_api(
            "get", API_GET_LOCKS_URL, access_token=access_token
        ).json()

        return _process_locks_json(activity_json)

    def get_operable_locks(self, access_token):
        locks = self.get_locks(access_token)

        return [lock for lock in locks if lock.is_operable]

    def get_lock_detail(self, access_token, lock_id):
        response = self._call_api(
            "get", API_GET_LOCK_URL.format(lock_id=lock_id), access_token=access_token
        )

        return LockDetail(response.json())

    def get_lock_status(self, access_token, lock_id, door_status=False):
        json_dict = self._call_api(
            "get",
            API_GET_LOCK_STATUS_URL.format(lock_id=lock_id),
            access_token=access_token,
        ).json()

        if door_status:
            return (
                determine_lock_status(json_dict.get("status")),
                determine_door_state(json_dict.get("doorState")),
            )

        return determine_lock_status(json_dict.get("status"))

    def get_lock_door_status(self, access_token, lock_id, lock_status=False):
        json_dict = self._call_api(
            "get",
            API_GET_LOCK_STATUS_URL.format(lock_id=lock_id),
            access_token=access_token,
        ).json()

        if lock_status:
            return (
                determine_door_state(json_dict.get("doorState")),
                determine_lock_status(json_dict.get("status")),
            )

        return determine_door_state(json_dict.get("doorState"))

    def get_pins(self, access_token, lock_id):
        json_dict = self._call_api(
            "get", API_GET_PINS_URL.format(lock_id=lock_id), access_token=access_token
        ).json()

        return [Pin(pin_json) for pin_json in json_dict.get("loaded", [])]

    def _call_lock_operation(self, url_str, access_token, lock_id):
        return self._call_api(
            "put",
            url_str.format(lock_id=lock_id),
            access_token=access_token,
            timeout=self._command_timeout,
        ).json()

    def _lock(self, access_token, lock_id):
        return self._call_lock_operation(API_LOCK_URL, access_token, lock_id)

    def lock(self, access_token, lock_id):
        """Execute a remote lock operation.

        Returns a LockStatus state.
        """
        json_dict = self._lock(access_token, lock_id)
        return determine_lock_status(json_dict.get("status"))

    def lock_return_activities(self, access_token, lock_id):
        """Execute a remote lock operation.

        Returns an array of one or more august.activity.Activity objects

        If the lock supports door sense one of the activities
        will include the current door state.
        """
        json_dict = self._lock(access_token, lock_id)
        return _convert_lock_result_to_activities(json_dict)

    def _unlock(self, access_token, lock_id):
        return self._call_lock_operation(API_UNLOCK_URL, access_token, lock_id)

    def unlock(self, access_token, lock_id):
        """Execute a remote unlock operation.

        Returns a LockStatus state.
        """
        json_dict = self._unlock(access_token, lock_id)
        return determine_lock_status(json_dict.get("status"))

    def unlock_return_activities(self, access_token, lock_id):
        """Execute a remote lock operation.

        Returns an array of one or more august.activity.Activity objects

        If the lock supports door sense one of the activities
        will include the current door state.
        """
        json_dict = self._unlock(access_token, lock_id)
        return _convert_lock_result_to_activities(json_dict)

    def refresh_access_token(self, access_token):
        response = self._call_api("get", API_GET_HOUSES_URL, access_token=access_token)

        return response.headers[HEADER_AUGUST_ACCESS_TOKEN]

    def _call_api(self, method, url, access_token=None, **kwargs):
        payload = kwargs.get("params") or kwargs.get("json")

        if "headers" not in kwargs:
            kwargs["headers"] = _api_headers(access_token=access_token)

        if "timeout" not in kwargs:
            kwargs["timeout"] = self._timeout

        _LOGGER.debug(
            "About to call %s with header=%s and payload=%s",
            url,
            kwargs["headers"],
            payload,
        )

        attempts = 0
        while attempts < API_RETRY_ATTEMPTS:
            attempts += 1
            response = (
                self._http_session.request(method, url, **kwargs)
                if self._http_session is not None
                else request(method, url, **kwargs)
            )
            _LOGGER.debug(
                "Received API response: %s, %s", response.status_code, response.content
            )
            if response.status_code == 429:
                _LOGGER.debug(
                    "August sent a 429 (attempt: %d), sleeping and trying again",
                    attempts,
                )
                time.sleep(API_RETRY_TIME)
                continue
            break

        _raise_response_exceptions(response)

        return response
