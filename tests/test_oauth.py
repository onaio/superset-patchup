# -*- coding: utf-8 -*-
"""
This module tests oauth
"""
import unittest

from unittest.mock import MagicMock, patch, call, PropertyMock

from flask_appbuilder import SQLA
from superset import app

from superset_patchup.oauth import AuthOAuthView, CustomSecurityManager

from .base_tests import SupersetTestCase


class TestLoginPreferHTTPS(unittest.TestCase):
    """Some test"""

    def setUp(self):
        from flask import Flask  # pylint: disable=C0415,E0401
        from flask_appbuilder import AppBuilder  # pylint: disable=C0415,E0401

        self.app = Flask(__name__)
        self.app.config.from_object("tests.test_config")
        self.app.config["PREFERRED_URL_SCHEME"] = "https"

        self.db = SQLA(self.app)  # pylint: disable=invalid-name
        self.appbuilder = AppBuilder(
            self.app, self.db.session, security_manager_class=CustomSecurityManager
        )

    def test_login(self):
        """Test /login/<provider>"""
        self.appbuilder.add_view(AuthOAuthView(), "KetchupAuthOAuthView")
        client = self.app.test_client()
        response = client.get("/login/onadata")
        self.assertEqual(response.status_code, 302)
        # Confirm Redirect URL has https
        self.assertIn("redirect_uri=https%3A", response.headers["Location"])

    def tearDown(self):
        self.db = None
        self.app = None
        self.appbuilder = None


class TestOauth(SupersetTestCase):
    """
    Class to test the oauth module
    """

    def test_get_oauth_redirect_url_when_not_set(self):  # pylint: disable=R0201
        """
        Test that when custom_redirect_url key is not set in the provider
        None is returned
        """
        appbuilder = MagicMock()
        CustomSecurityManager.oauth_providers = [{"name": "onadata"}]
        csm = CustomSecurityManager(appbuilder=appbuilder)
        redirect_url = csm.get_oauth_redirect_url(provider="onadata")
        assert redirect_url is None

    def test_get_oauth_redirect_url_when_set(self):  # pylint: disable=R0201
        """
        Test that when custom_redirect_url key is set in the provider
        it returns the right value
        """
        appbuilder = MagicMock()
        CustomSecurityManager.oauth_providers = [
            {"name": "onadata", "custom_redirect_url": "http://google.com"}
        ]
        csm = CustomSecurityManager(appbuilder=appbuilder)
        redirect_url = csm.get_oauth_redirect_url(provider="onadata")
        assert redirect_url == "http://google.com"

    def test_oauth_user_info_onadata_provider(self):  # pylint: disable=R0201
        """
        Test that we get the right user information
        with the onadata provider
        """
        # Sample data returned from endpoints
        user_endpoint = {"username": "testauth", "name": "test"}
        profiles_endpoint = {
            "id": 58863,
            "is_org": False,
            "first_name": "test",
            "name": "test auth",
            "last_name": "auth",
            "email": "testauth@ona.io",
        }

        # Expected result
        result_info = {
            "name": "test auth",
            "email": "testauth@ona.io",
            "id": 58863,
            "username": "testauth",
            "first_name": "test",
            "last_name": "auth",
        }

        appbuilder = MagicMock()
        user_mock = MagicMock()
        user_mock.json.return_value = user_endpoint
        profile_mock = MagicMock()
        profile_mock.json.return_value = profiles_endpoint
        request_mock = MagicMock(side_effect=[user_mock, profile_mock])
        appbuilder.sm.oauth_remotes["onadata"].get = request_mock
        csm = CustomSecurityManager(appbuilder=appbuilder)
        user_info = csm.oauth_user_info(provider="onadata")
        assert request_mock.call_count == 2
        user_info_call, _ = request_mock.call_args_list[0]
        userprofile_call, _ = request_mock.call_args_list[1]
        assert user_info_call[0] == "api/v1/user.json"
        assert userprofile_call[0] == "api/v1/profiles/testauth.json"
        assert user_info == result_info

    def test_oauth_user_info_openlmis_provider(self):  # pylint: disable=R0201
        """
        Test that we get the right user information
        with the openlmis provider
        """
        # Data returned from userContactDetails endpoint
        contacts_endpoint = {"emailDetails": {"email": "testauth@openlmis.org"}}

        # Data returned from users endpoint in openlmis
        users_endpoint = {
            "username": "testauth",
            "firstName": "test",
            "lastName": "auth",
            "active": True,
            "id": "a337ec45-31a0-4f2b-9b2e-a105c4b669bb",
        }

        # Result expected
        result_info = {
            "name": "testauth",
            "email": "testauth@openlmis.org",
            "id": "a337ec45-31a0-4f2b-9b2e-a105c4b669bb",
            "username": "testauth",
            "first_name": "test",
            "last_name": "auth",
        }

        appbuilder = MagicMock()
        reference_user = MagicMock()
        reference_user.json.return_value = {
            "referenceDataUserId": "a337ec45-31a0-4f2b-9b2e-a105c4b669bb"
        }

        user_data = MagicMock()
        user_data.json.return_value = users_endpoint

        user_email = MagicMock()
        user_email.json.return_value = contacts_endpoint

        request_post_mock = MagicMock(side_effect=[reference_user])
        request_get_mock = MagicMock(side_effect=[user_data, user_email])

        appbuilder.sm.oauth_remotes["openlmis"].get = request_get_mock
        appbuilder.sm.oauth_remotes["openlmis"].post = request_post_mock
        csm = CustomSecurityManager(appbuilder=appbuilder)
        csm.oauth_tokengetter = MagicMock(
            return_value=["a337ec45-31a0-4f2b-9b2e-a105c4b669bb"]
        )
        user_info = csm.oauth_user_info(provider="openlmis")

        assert request_get_mock.call_count == 2
        assert request_post_mock.call_count == 1
        check_token_call, _ = request_post_mock.call_args_list[0]
        user_call, _ = request_get_mock.call_args_list[0]
        contacts_call, _ = request_get_mock.call_args_list[1]
        assert check_token_call[0] == "oauth/check_token"
        assert user_call[0] == "users/a337ec45-31a0-4f2b-9b2e-a105c4b669bb"
        assert (
            contacts_call[0]
            == "userContactDetails/a337ec45-31a0-4f2b-9b2e-a105c4b669bb"
        )

        assert user_info == result_info

    def test_oauth_user_info_opensrp_provider(self):  # pylint: disable=R0201
        """
        Test that we get the right user information
        with the OpenSRP provider
        """
        # set test configs
        app.config["PATCHUP_EMAIL_BASE"] = "noreply@example.com"

        # Sample data returned OpenSRP
        data = {"userName": "tlv1", "roles": ["Privilege Level: Full"]}

        # Expected result
        result_info = {"email": "noreply+tlv1@example.com", "username": "tlv1"}

        appbuilder = MagicMock()
        user_mock = MagicMock()
        user_mock.json.return_value = data
        appbuilder.sm.oauth_remotes["OpenSRP"].get = MagicMock(side_effect=[user_mock])
        csm = CustomSecurityManager(appbuilder=appbuilder)
        user_info = csm.oauth_user_info(provider="OpenSRP")
        assert user_info == result_info

        # Sample data returned OpenSRP with preferredName
        data2 = {
            "preferredName": "mosh",
            "userName": "mosh",
            "roles": ["Privilege Level: Full"],
        }

        # Expected result
        result_info2 = {
            "email": "noreply+mosh@example.com",
            "name": "mosh",
            "username": "mosh",
        }

        appbuilder2 = MagicMock()
        user_mock2 = MagicMock()
        request_mock = MagicMock(side_effect=[user_mock2])
        user_mock2.json.return_value = data2
        appbuilder2.sm.oauth_remotes["OpenSRP"].get = request_mock
        csm2 = CustomSecurityManager(appbuilder=appbuilder2)
        user_info2 = csm2.oauth_user_info(provider="OpenSRP")
        request_mock.assert_called_once_with("user-details", token=None)
        assert user_info2 == result_info2

        # Sample data returned OpenSRP v2
        data3 = {"username": "mosh", "roles": ["Privilege Level: Full"]}

        # Expected result
        result_info3 = {"email": "noreply+mosh@example.com", "username": "mosh"}

        appbuilder3 = MagicMock()
        user_mock3 = MagicMock()
        user_mock3.json.return_value = data3
        appbuilder3.sm.oauth_remotes["OpenSRP"].get = MagicMock(
            side_effect=[user_mock3]
        )
        csm3 = CustomSecurityManager(appbuilder=appbuilder3)
        user_info3 = csm3.oauth_user_info(provider="OpenSRP")
        assert user_info3 == result_info3

    def test_oauth_user_info_no_provider(self):  # pylint: disable=R0201
        """
        Test that when no provider is provided
        None is returned
        """
        appbuilder = MagicMock()
        csm = CustomSecurityManager(appbuilder=appbuilder)
        user_info = csm.oauth_user_info(provider=None)
        assert user_info is None

    @patch("superset_patchup.oauth.SupersetSecurityManager.clean_perms")
    @patch("superset_patchup.oauth.SupersetSecurityManager.get_session")
    @patch("superset_patchup.oauth.SupersetSecurityManager.create_missing_perms")
    @patch("superset_patchup.oauth.CustomSecurityManager.is_custom_pvm")
    @patch("superset_patchup.oauth.CustomSecurityManager.set_custom_role")
    @patch("superset_patchup.oauth.SupersetSecurityManager.sync_role_definitions")
    def test_custom_roles(
        self,
        mock_sync_role_definitions,
        mock_set_custom_role,
        mock_is_custom_pvm,
        mock_create_missing_perms,  # pylint: disable=unused-argument
        mock_get_session,  # pylint: disable=unused-argument
        mock_clean_perms,
    ):  # pylint: disable=R0201,R0913
        """
        Test that when add custom roles is set to true, the roles specified
        in the configs are created
        """
        # set test configs
        app.config["ADD_CUSTOM_ROLES"] = True
        app.config["CUSTOM_ROLES"] = {"Test_role": {"all_datasource_access"}}

        appbuilder = MagicMock()
        csm = CustomSecurityManager(appbuilder=appbuilder)
        csm.sync_role_definitions()
        assert mock_sync_role_definitions.call_count == 1
        assert mock_set_custom_role.call_count == 1

        mock_args = mock_set_custom_role.call_args_list[0]
        assert mock_args[0][0] == "Test_role"
        assert mock_args[0][1] == mock_is_custom_pvm
        assert mock_args[0][2] == {"all_datasource_access"}
        assert mock_clean_perms.call_count == 1

    @patch("superset_patchup.oauth.redirect")
    @patch("superset_patchup.oauth.is_safe_url")
    @patch("superset_patchup.oauth.request.args.get")
    @patch("superset_patchup.oauth.login_user")
    @patch("superset_patchup.oauth.request")
    def test_oauth_authorized(
        self,
        mock_request,
        mock_login,
        mock_request_redirect,
        mock_safe_url,
        mock_redirect,
    ):  # pylint: disable=R0201,R0913
        """
        This test checks that
        1. The access token is used when passed in the request header
        2. Redirect is called with the url passed in the request args
        """
        # Sample authorized response
        mock_authorized_response = {
            "access_token": "cZpwCzYjpzuSqzekM",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "Sui6j4nQtbmU9P",
            "scope": "read write",
        }

        # Sample user info from onadata
        mock_user_info = {
            "name": "test auth",
            "email": "testauth@ona.io",
            "id": 58863,
            "username": "testauth",
            "first_name": "test",
            "last_name": "auth",
            "is_active": True,
        }

        oauth_view = AuthOAuthView()
        oauth_view.appbuilder = MagicMock()
        oauth_view.appbuilder.sm.oauth_remotes[
            "onadata"
        ].authorized_response = MagicMock(return_value=mock_authorized_response)
        mock_request.headers = {"Custom-Api-Token": "cZpwCzYjpzuSqzekM"}
        auth_session_mock = MagicMock()
        oauth_view.appbuilder.sm.set_oauth_session = auth_session_mock
        oauth_view.appbuilder.sm.oauth_user_info = MagicMock(
            return_value=mock_user_info
        )
        oauth_view.appbuilder.sm.oauth_whitelists = MagicMock()
        oauth_view.appbuilder.sm.auth_user_oauth = MagicMock(
            return_value=mock_user_info
        )
        oauth_view.appbuilder.sm.get_oauth_redirect_url = MagicMock()
        mock_request_redirect.return_value = "http://example.com"
        mock_safe_url.return_value = True
        oauth_view.oauth_authorized(provider="onadata")
        auth_session_mock.assert_called_with(
            "onadata", {"access_token": "cZpwCzYjpzuSqzekM"}
        )
        assert mock_login.call_count == 1
        mock_redirect.assert_called_once_with("http://example.com")

    @patch("superset_patchup.oauth.redirect")
    @patch("superset_patchup.oauth.g")
    @patch("superset_patchup.oauth.is_safe_url")
    @patch("superset_patchup.oauth.request.args.get")
    @patch("superset_patchup.oauth.request")
    def test_login_redirect(
        self, mock_request, mock_redirect_arg, mock_safe_url, mock_g, mock_redirect
    ):  # pylint: disable=R0201,R0913,W0613
        """
        Test that we are redirected to the redirect url when it is passed
        as an argument to /login
        """
        oauth_view = AuthOAuthView()
        oauth_view.appbuilder = MagicMock()

        mock_redirect_arg.return_value = "/superset/dashboard/3"
        mock_safe_url.return_value = True
        mock_g.user.is_authenticated.return_value = True

        oauth_view.login(provider="onadata")
        mock_redirect.assert_called_once_with("/superset/dashboard/3")

    @patch("superset_patchup.oauth.is_valid_provider")
    def test_is_valid_provider_is_called_for_opendata(self, function_mock):
        """
        Test that is_valid_provider function is called for all provider names
        """
        function_mock.return_value = False
        appbuilder = MagicMock()
        csm = CustomSecurityManager(appbuilder=appbuilder)
        csm.oauth_user_info(provider="Onadata")
        self.assertIn(call("Onadata", "onadata"), function_mock.call_args_list)
        csm.oauth_user_info(provider="opensrp")
        self.assertIn(call("opensrp", "OpenSRP"), function_mock.call_args_list)
        csm.oauth_user_info(provider="OPENLMIS")
        self.assertIn(call("OPENLMIS", "openlmis"), function_mock.call_args_list)

    @patch("superset_patchup.oauth.jwt")
    @patch("superset_patchup.oauth.jsonify")
    @patch("superset_patchup.oauth.make_response")
    @patch("superset_patchup.oauth.g")
    @patch("superset_patchup.oauth.is_safe_url")
    @patch("superset_patchup.oauth.request.args.get")
    @patch("superset_patchup.oauth.request")
    def test_init_login_result_for_not_authorized_user(
        self,
        mock_request,
        mock_redirect_arg,
        mock_safe_url,
        mock_g,
        mock_make_response,
        mock_jsonify,
        mock_jwt,
    ):  # pylint: disable=R0201,R0913,W0613
        """
        Test that checks if the correct response for a not authorized user
        is returned.
        """
        oauth_view = AuthOAuthView()
        oauth_view.appbuilder = MagicMock()

        provider = "OPENLMIS"
        redirect_url = "/superset/dashboard/3"
        state = "12345"

        with patch("superset_patchup.oauth.g.user.is_authenticated", False):
            with patch("superset_patchup.oauth.session", dict()) as session:
                mock_redirect_arg.return_value = redirect_url
                mock_jwt.encode.return_value = state

                oauth_view.login_init(provider=provider)

                mock_make_response.assert_called()
                assert (
                    call(isAuthorized=False, state=state) in mock_jsonify.call_args_list
                )
                assert session.get("%s_oauthredir" % provider) == redirect_url

    @patch("superset_patchup.oauth.jsonify")
    @patch("superset_patchup.oauth.make_response")
    @patch("superset_patchup.oauth.g")
    def test_init_login_result_for_already_authorized_user(
        self, mock_g, mock_make_response, mock_jsonify
    ):  # pylint: disable=R0201,W0613
        """
        Test that checks if the correct response for an already authorized
        user is returned.
        """
        oauth_view = AuthOAuthView()
        oauth_view.appbuilder = MagicMock()
        provider = "OPENLMIS"

        with patch("superset_patchup.oauth.g.user.is_authenticated", True):
            with patch("superset_patchup.oauth.session", dict()) as session:

                oauth_view.login_init(provider=provider)

                mock_make_response.assert_called()
                assert call(isAuthorized=True) in mock_jsonify.call_args_list
                assert (("%s_oauthredir" % provider) in session) is False

    @patch("superset_patchup.oauth.request")
    def test_generate_state_result(self, mock_request):  # pylint: disable=R0201
        """
        Test that checks if a valid state is returned.
        """
        oauth_view = AuthOAuthView()
        oauth_view.appbuilder = MagicMock()
        app_config = dict(SECRET_KEY="secret_key")
        request_args = dict(dummy_parameter="dummy_parameter_value")

        type(oauth_view.appbuilder.app).config = PropertyMock(return_value=app_config)
        mock_request.args.to_dict.return_value = request_args

        state = oauth_view.generate_state()

        assert len(state) > 0
