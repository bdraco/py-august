import datetime

from august.activity import (
    ACTIVITY_ACTION_STATES,
    DoorbellMotionActivity,
    DoorOperationActivity,
    LockOperationActivity,
)
from august.lock import (
    DOOR_STATE_KEY,
    LOCK_STATUS_KEY,
    LockDoorStatus,
    LockStatus,
    determine_door_state,
    determine_lock_status,
)


def update_lock_detail_from_activity(lock_detail, activity):
    """Update the LockDetail from an activity."""
    activity_end_time_utc = as_utc_from_local(activity.activity_end_time)
    if activity.device_id != lock_detail.device_id:
        raise ValueError
    if isinstance(activity, LockOperationActivity):
        if lock_detail.lock_status_datetime >= activity_end_time_utc:
            return False
        lock_detail.lock_status = ACTIVITY_ACTION_STATES[activity.action]
        lock_detail.lock_status_datetime = activity_end_time_utc
    elif isinstance(activity, DoorOperationActivity):
        if lock_detail.door_state_datetime >= activity_end_time_utc:
            return False
        lock_detail.door_state = ACTIVITY_ACTION_STATES[activity.action]
        lock_detail.door_state_datetime = activity_end_time_utc
    else:
        raise ValueError

    return True


def update_lock_details_from_pubnub_message(lock_detail, date_time, message):
    """Update lock details from pubnub."""
    updated = False

    if LOCK_STATUS_KEY in message and lock_detail.lock_status_datetime < date_time:
        lock_status = determine_lock_status(message[LOCK_STATUS_KEY])
        if lock_status != LockStatus.UNKNOWN:
            lock_detail.lock_status = determine_lock_status(message[LOCK_STATUS_KEY])
            lock_detail.lock_status_datetime = date_time
            updated = True

    if DOOR_STATE_KEY in message and lock_detail.door_state_datetime < date_time:
        door_state = determine_door_state(message[DOOR_STATE_KEY])
        if door_state != LockDoorStatus.UNKNOWN:
            lock_detail.door_state = determine_door_state(message[DOOR_STATE_KEY])
            lock_detail.door_state_datetime = date_time
            updated = True

    return updated


def update_doorbell_image_from_activity(doorbell_detail, activity):
    """Update the DoorDetail from an activity with a new image."""
    if activity.device_id != doorbell_detail.device_id:
        raise ValueError
    if isinstance(activity, DoorbellMotionActivity):
        if activity.image_created_at_datetime is None:
            return False

        if (
            doorbell_detail.image_created_at_datetime is None
            or doorbell_detail.image_created_at_datetime
            < activity.image_created_at_datetime
        ):
            doorbell_detail.image_url = activity.image_url
            doorbell_detail.image_created_at_datetime = (
                activity.image_created_at_datetime
            )
        else:
            return False
    else:
        raise ValueError

    return True


def as_utc_from_local(dtime):
    """Converts the datetime returned from an activity to UTC."""
    return dtime.astimezone(tz=datetime.timezone.utc)
