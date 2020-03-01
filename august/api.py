"""Api base calls for sync and async."""

import json
import logging
import time

from requests import Session, request

from august.doorbell import DoorbellDetail
from august.lock import (
    LockDetail,
    determine_door_state,
    determine_lock_status,
)
from august.pin import Pin

from august.api.common import (
    _raise_response_exceptions,
    _convert_lock_result_to_activities,
    _datetime_string_to_epoch,
    _process_activity_json,
    _process_doorbells_json,
    _process_locks_json,
    API_RETRY_TIME,
    API_RETRY_ATTEMPTS,
)

_LOGGER = logging.getLogger(__name__)


class Api(ApiCommon):
    def __init__(self, timeout=10, command_timeout=60, http_session: Session = None):
        self._timeout = timeout
        self._command_timeout = command_timeout
        self._http_session = http_session

    def get_session(self, install_id, identifier, password):
        return self._dict_to_api(
            self._build_get_session_request(install_id, identifier, password)
        )

    def send_verification_code(self, access_token, login_method, username):
        return self._dict_to_api(
            self._build_send_verification_code_request(
                access_token, login_method, username
            )
        )

    def validate_verification_code(
        self, access_token, login_method, username, verification_code
    ):
        return self._dict_to_api(
            self._build_send_verification_code_request(
                access_token, login_method, username, verification_code
            )
        )

    def get_doorbells(self, access_token):
        return _process_doorbells_json(
            self._dict_to_api(self._build_get_doorbells_request(access_token)).json()
        )

    def get_doorbell_detail(self, access_token, doorbell_id):
        return DoorbellDetail(
            self._dict_to_api(
                self._build_get_doorbell_detail_request(access_token, doorbell_id)
            ).json()
        )

    def wakeup_doorbell(self, access_token, doorbell_id):
        self._dict_to_api(
            self._build_wakeup_doorbell_request(access_token, doorbell_id)
        )
        return True

    def get_houses(self, access_token):
        return self._dict_to_api(self._build_get_houses_request(access_token))

    def get_house(self, access_token, house_id):
        return self._dict_to_api(
            self._build_get_house_request(access_token, house_id)
        ).json()

    def get_house_activities(self, access_token, house_id, limit=8):
        return _process_activity_json(
            self._dict_to_api(
                self._build_get_house_activities_request(
                    access_token, house_id, limit=limit
                )
            ).json()
        )

    def get_locks(self, access_token):
        return _process_locks_json(
            self._build_get_locks_request(
                self._dict_to_api(
                    self._build_get_doorbells_request(access_token)
                ).json()
            )
        )

    def get_operable_locks(self, access_token):
        locks = self.get_locks(access_token)

        return [lock for lock in locks if lock.is_operable]

    def get_lock_detail(self, access_token, lock_id):
        return LockDetail(
            self._dict_to_api(
                self._build_get_lock_detail_request(access_token, lock_id)
            ).json()
        )

    def get_lock_status(self, access_token, lock_id, door_status=False):
        json_dict = self._dict_to_api(
            self._build_get_lock_status_request(access_token, lock_id)
        ).json()

        if door_status:
            return (
                determine_lock_status(json_dict.get("status")),
                determine_door_state(json_dict.get("doorState")),
            )

        return determine_lock_status(json_dict.get("status"))

    def get_lock_door_status(self, access_token, lock_id, lock_status=False):
        json_dict = self._dict_to_api(
            self._build_get_lock_status_request(access_token, lock_id)
        ).json()

        if lock_status:
            return (
                determine_door_state(json_dict.get("doorState")),
                determine_lock_status(json_dict.get("status")),
            )

        return determine_door_state(json_dict.get("doorState"))

    def get_pins(self, access_token, lock_id):
        json_dict = self._dict_to_api(
            self._build_get_pins(access_token, lock_id)
        ).json()

        return [Pin(pin_json) for pin_json in json_dict.get("loaded", [])]

    def _call_lock_operation(self, url_str, access_token, lock_id):
        return self._dict_to_api(
            self._build_call_lock_operation(url_str, access_token, house_id)
        ).json()

    def _lock(self, access_token, lock_id):
        return self._call_lock_operation(API_LOCK_URL, access_token, lock_id)

    def lock(self, access_token, lock_id):
        """Execute a remote lock operation.

        Returns a LockStatus state.
        """
        return determine_lock_status(self._lock(access_token, lock_id).get("status"))

    def lock_return_activities(self, access_token, lock_id):
        """Execute a remote lock operation.

        Returns an array of one or more august.activity.Activity objects

        If the lock supports door sense one of the activities
        will include the current door state.
        """
        return _convert_lock_result_to_activities(self._lock(access_token, lock_id))

    def _unlock(self, access_token, lock_id):
        return self._call_lock_operation(API_UNLOCK_URL, access_token, lock_id)

    def unlock(self, access_token, lock_id):
        """Execute a remote unlock operation.

        Returns a LockStatus state.
        """
        return determine_lock_status(self._unlock(access_token, lock_id).get("status"))

    def unlock_return_activities(self, access_token, lock_id):
        """Execute a remote lock operation.

        Returns an array of one or more august.activity.Activity objects

        If the lock supports door sense one of the activities
        will include the current door state.
        """
        return _convert_lock_result_to_activities(self._unlock(access_token, lock_id))

    def refresh_access_token(self, access_token):
        response = self._call_api("get", API_GET_HOUSES_URL, access_token=access_token)

        return response.headers[HEADER_AUGUST_ACCESS_TOKEN]

    def _dict_to_api(api_dict):
        kwargs = []
        if json in "api_dict":
            kwargs["json"] = api_dict["json"]
        if params in "api_dict":
            kwargs["params"] = api_dict["params"]

        return self._call_api(
            api_dict["method"],
            api_dict["url"],
            access_token=(
                api_dict["access_token"] if "access_token" in api_dict else None
            ),
            **kwargs
        )

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
