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

API_RETRY_TIME = 2.5
API_RETRY_ATTEMPTS = 10

HEADER_ACCEPT_VERSION = "Accept-Version"
HEADER_AUGUST_ACCESS_TOKEN = "x-august-access-token"
HEADER_AUGUST_API_KEY = "x-august-api-key"
HEADER_KEASE_API_KEY = "x-kease-api-key"
HEADER_CONTENT_TYPE = "Content-Type"
HEADER_USER_AGENT = "User-Agent"

HEADER_VALUE_API_KEY = "79fd0eb6-381d-4adf-95a0-47721289d1d9"
HEADER_VALUE_CONTENT_TYPE = "application/json"
HEADER_VALUE_USER_AGENT = "August/2019.12.16.4708 CFNetwork/1121.2.2 Darwin/19.3.0"
HEADER_VALUE_ACCEPT_VERSION = "0.0.1"

API_BASE_URL = "https://api-production.august.com"
API_GET_SESSION_URL = API_BASE_URL + "/session"
API_SEND_VERIFICATION_CODE_URLS = {
    "phone": API_BASE_URL + "/validation/phone",
    "email": API_BASE_URL + "/validation/email",
}
API_VALIDATE_VERIFICATION_CODE_URLS = {
    "phone": API_BASE_URL + "/validate/phone",
    "email": API_BASE_URL + "/validate/email",
}
API_GET_HOUSE_ACTIVITIES_URL = API_BASE_URL + "/houses/{house_id}/activities"
API_GET_DOORBELLS_URL = API_BASE_URL + "/users/doorbells/mine"
API_GET_DOORBELL_URL = API_BASE_URL + "/doorbells/{doorbell_id}"
API_WAKEUP_DOORBELL_URL = API_BASE_URL + "/doorbells/{doorbell_id}/wakeup"
API_GET_HOUSES_URL = API_BASE_URL + "/users/houses/mine"
API_GET_HOUSE_URL = API_BASE_URL + "/houses/{house_id}"
API_GET_LOCKS_URL = API_BASE_URL + "/users/locks/mine"
API_GET_LOCK_URL = API_BASE_URL + "/locks/{lock_id}"
API_GET_LOCK_STATUS_URL = API_BASE_URL + "/locks/{lock_id}/status"
API_GET_PINS_URL = API_BASE_URL + "/locks/{lock_id}/pins"
API_LOCK_URL = API_BASE_URL + "/remoteoperate/{lock_id}/lock"
API_UNLOCK_URL = API_BASE_URL + "/remoteoperate/{lock_id}/unlock"

_LOGGER = logging.getLogger(__name__)

def _api_headers(access_token=None):
    headers = {
        HEADER_ACCEPT_VERSION: HEADER_VALUE_ACCEPT_VERSION,
        HEADER_AUGUST_API_KEY: HEADER_VALUE_API_KEY,
        HEADER_KEASE_API_KEY: HEADER_VALUE_API_KEY,
        HEADER_CONTENT_TYPE: HEADER_VALUE_CONTENT_TYPE,
        HEADER_USER_AGENT: HEADER_VALUE_USER_AGENT,
    }

    if access_token:
        headers[HEADER_AUGUST_ACCESS_TOKEN] = access_token

    return headers

def _raise_response_exceptions(response):
    try:
        response.raise_for_status()
    except HTTPError as err:
        if err.response.status_code == 422:
            raise AugustApiHTTPError(
                "The operation failed because the bridge (connect) is offline.",
                response=err.response,
            ) from err
        if err.response.status_code == 423:
            raise AugustApiHTTPError(
                "The operation failed because the bridge (connect) is in use.",
                response=err.response,
            ) from err
        if err.response.status_code == 408:
            raise AugustApiHTTPError(
                "The operation timed out because the bridge (connect) failed to respond.",
                response=err.response,
            ) from err
        if err.response.headers.get("content-type") == "application/json":
            # 4XX and 5XX errors return a json error
            # like b'{"code":97,"message":"Bridge in use"}'
            # that is user consumable
            json_dict = json.loads(err.response.content)
            failure_message = json_dict.get("message")
            raise AugustApiHTTPError(
                "The operation failed because: " + failure_message,
                response=err.response,
            ) from err
        raise err


def _convert_lock_result_to_activities(lock_json_dict):
    activities = []
    lock_info_json_dict = lock_json_dict.get("info", {})
    lock_id = lock_info_json_dict.get("lockID")
    lock_action_text = lock_info_json_dict.get("action")
    activity_epoch = _datetime_string_to_epoch(lock_info_json_dict.get("startTime"))
    activity_lock_dict = _map_lock_result_to_activity(
        lock_id, activity_epoch, lock_action_text
    )
    activities.append(activity_lock_dict)

    door_state = determine_door_state(lock_json_dict.get("doorState"))
    if door_state != LockDoorStatus.UNKNOWN:
        activity_door_dict = _map_lock_result_to_activity(
            lock_id, activity_epoch, door_state_to_string(door_state)
        )
        activities.append(activity_door_dict)

    return activities


def _activity_from_dict(activity_dict):
    action = activity_dict.get("action")

    if action in ACTIVITY_ACTIONS_DOORBELL_DING:
        return DoorbellDingActivity(activity_dict)
    if action in ACTIVITY_ACTIONS_DOORBELL_MOTION:
        return DoorbellMotionActivity(activity_dict)
    if action in ACTIVITY_ACTIONS_DOORBELL_VIEW:
        return DoorbellViewActivity(activity_dict)
    if action in ACTIVITY_ACTIONS_LOCK_OPERATION:
        return LockOperationActivity(activity_dict)
    if action in ACTIVITY_ACTIONS_DOOR_OPERATION:
        return DoorOperationActivity(activity_dict)
    return None


def _map_lock_result_to_activity(lock_id, activity_epoch, action_text):
    """Create an august activity from a lock result."""
    mapped_dict = {
        "dateTime": activity_epoch,
        "deviceID": lock_id,
        "deviceType": "lock",
        "action": action_text,
    }
    return _activity_from_dict(mapped_dict)


def _datetime_string_to_epoch(datetime_string):
    return dateutil.parser.parse(datetime_string).timestamp() * 1000

def _process_activity_json(activity_json):
    activities = []
    for activity_json in response.json():
        activity = _activity_from_dict(activity_json)
        if activity:
            activities.append(activity)

    return activities

def _process_doorbells_json(json_dict):
        return [Doorbell(device_id, data) for device_id, data in json_dict.items()]

def _process_locks_json(json_dict):
        return [Lock(device_id, data) for device_id, data in json_dict.items()]

