from datetime import datetime, timedelta, timezone

import aiounittest
from august.api_async import ApiAsync
from august.authenticator_async import (
    AuthenticationState,
    AuthenticatorAsync,
    ValidationResult,
)
from dateutil.tz import tzutc
from aiohttp import ClientError, ClientResponseError, ClientSession
from aioresponses import aioresponses
import json

from august.api_common import (API_GET_SESSION_URL, API_VALIDATE_VERIFICATION_CODE_URLS)

def format_datetime(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


class TestAuthenticatorAsync(aiounittest.AsyncTestCase):
    def setUp(self):
        """Setup things to be run when tests are started."""

    async def _async_create_authenticator_async(self, mock_aioresponses):
        authenticator = AuthenticatorAsync(
            ApiAsync(ClientSession()), "phone", "user", "pass", install_id="install_id"
        )
        await authenticator.async_setup_authentication()
        return authenticator

    def _setup_session_response(
        self,
        mock_aioresponses,
        v_password,
        v_install_id,
        expires_at=format_datetime(datetime.utcnow()),
    ):
        mock_aioresponses.post(
            API_GET_SESSION_URL,
            headers={"x-august-access-token": "access_token"},
            body=json.dumps(
                {
                    "expiresAt": expires_at,
                    "vPassword": v_password,
                    "vInstallId": v_install_id,
                }
            ),
        )

    @aioresponses()
    async def test_async_should_refresh_when_token_expiry_is_after_renewal_threshold(
        self, mock_aioresponses
    ):
        expired_expires_at = format_datetime(
            datetime.now(timezone.utc) + timedelta(days=6)
        )
        self._setup_session_response(
            mock_aioresponses, True, True, expires_at=expired_expires_at
        )

        authenticator = await self._async_create_authenticator_async(mock_aioresponses)
        await authenticator.async_authenticate()

        should_refresh = authenticator.should_refresh()

        self.assertEqual(True, should_refresh)

    @aioresponses()
    async def test_async_should_refresh_when_token_expiry_is_before_renewal_threshold(
        self, mock_aioresponses
    ):
        not_expired_expires_at = format_datetime(
            datetime.now(timezone.utc) + timedelta(days=8)
        )
        self._setup_session_response(
            mock_aioresponses, True, True, expires_at=not_expired_expires_at
        )

        authenticator = await self._async_create_authenticator_async(mock_aioresponses)
        await authenticator.async_authenticate()

        should_refresh = authenticator.should_refresh()

        self.assertEqual(False, should_refresh)

    @aioresponses()
    async def test_async_refresh_token(self, mock_aioresponses):
        self._setup_session_response(mock_aioresponses, True, True)

        authenticator = await self._async_create_authenticator_async(mock_aioresponses)
        await authenticator.async_authenticate()

        token = "e30=.eyJleHAiOjEzMzd9.e30="
        mock_aioresponses.refresh_access_token.return_value = token

        access_token = authenticator.refresh_access_token(force=False)

        self.assertEqual(token, access_token.access_token)
        self.assertEqual(
            datetime.fromtimestamp(1337, tz=tzutc()),
            access_token.parsed_expiration_time(),
        )

    @aioresponses()
    async def test_async_get_session_with_authenticated_response(self, mock_aioresponses):
        self._setup_session_response(mock_aioresponses, True, True)

        authenticator = await self._async_create_authenticator_async(mock_aioresponses)
        await authenticator.async_authenticate()

        mock_aioresponses.get_session.assert_called_once_with("install_id", "phone:user", "pass")

        self.assertEqual("access_token", authentication.access_token)
        self.assertEqual("install_id", authentication.install_id)
        self.assertEqual(AuthenticationState.AUTHENTICATED, authentication.state)

    @aioresponses()
    async def test_async_get_session_with_bad_password_response(self, mock_aioresponses):
        self._setup_session_response(mock_aioresponses, False, True)

        authenticator = await self._async_create_authenticator_async(mock_aioresponses)
        await authenticator.async_authenticate()

        mock_aioresponses.get_session.assert_called_once_with("install_id", "phone:user", "pass")

        self.assertEqual("access_token", authentication.access_token)
        self.assertEqual("install_id", authentication.install_id)
        self.assertEqual(AuthenticationState.BAD_PASSWORD, authentication.state)

    @aioresponses()
    async def test_async_get_session_with_requires_validation_response(self, mock_aioresponses):
        self._setup_session_response(mock_aioresponses, True, False)

        authenticator = await self._async_create_authenticator_async(mock_aioresponses)
        await authenticator.async_authenticate()

        #mock_aioresponses.put(API_GET_SESSION_URL,body='')
        #mock_aioresponses.get_session.assert_called_once_with("install_id", "phone:user", "pass")

        self.assertEqual("access_token", authentication.access_token)
        self.assertEqual("install_id", authentication.install_id)
        self.assertEqual(AuthenticationState.REQUIRES_VALIDATION, authentication.state)

    @aioresponses()
    async def test_async_get_session_with_already_authenticated_state(self, mock_aioresponses):
        self._setup_session_response(mock_aioresponses, True, True)

        authenticator = await self._async_create_authenticator_async(mock_aioresponses)
        # this will set authentication state to AUTHENTICATED
        await authenticator.async_authenticate()
        # call authenticate() again
        authentication = await authenticator.async_authenticate()

        mock_aioresponses.get_session.assert_called_once_with("install_id", "phone:user", "pass")

        self.assertEqual("access_token", authentication.access_token)
        self.assertEqual("install_id", authentication.install_id)
        self.assertEqual(AuthenticationState.AUTHENTICATED, authentication.state)

    @aioresponses()
    async def test_async_send_verification_code(self, mock_aioresponses):
        self._setup_session_response(mock_aioresponses, True, False)

        authenticator = await self._async_create_authenticator_async(mock_aioresponses)
        await authenticator.async_authenticate()
        await authenticator.async_send_verification_code()

        mock_aioresponses.send_verification_code.assert_called_once_with(
            "access_token", "phone", "user"
        )

    @aioresponses()
    async def test_async_validate_verification_code_with_no_code(self, mock_aioresponses):
        self._setup_session_response(mock_aioresponses, True, False)

        authenticator = await self._async_create_authenticator_async(mock_aioresponses)
        await authenticator.async_authenticate()

        mock_aioresponses.post(API_VALIDATE_VERIFICATION_CODE_URLS["email"],body='{}')
        mock_aioresponses.post(API_VALIDATE_VERIFICATION_CODE_URLS["phone"],body='{}')
        result = await authenticator.async_validate_verification_code("")

        #mock_aioresponses.async_validate_verification_code.assert_not_called()

        self.assertEqual(ValidationResult.INVALID_VERIFICATION_CODE, result)

    @aioresponses()
    async def test_async_validate_verification_code_with_validated_response(
        self, mock_aioresponses
    ):
        self._setup_session_response(mock_aioresponses, True, False)

        mock_aioresponses.post(API_VALIDATE_VERIFICATION_CODE_URLS["email"],body='{}')
        mock_aioresponses.post(API_VALIDATE_VERIFICATION_CODE_URLS["phone"],body='{}')

        authenticator = await self._async_create_authenticator_async(mock_aioresponses)
        await authenticator.async_authenticate()
        result = await authenticator.async_validate_verification_code("123456")

        self.assertEqual(ValidationResult.VALIDATED, result)

    @aioresponses()
    async def test_async_validate_verification_code_with_invalid_code_response(
        self, mock_aioresponses
    ):
        self._setup_session_response(mock_aioresponses, True, False)

        mock_aioresponses.post(API_VALIDATE_VERIFICATION_CODE_URLS["email"],exception=ClientError())
        mock_aioresponses.post(API_VALIDATE_VERIFICATION_CODE_URLS["phone"],exception=ClientError())

        authenticator = await self._async_create_authenticator_async(mock_aioresponses)
        await authenticator.async_authenticate()
        result = await authenticator.async_validate_verification_code("123456")

        self.assertEqual(ValidationResult.INVALID_VERIFICATION_CODE, result)
