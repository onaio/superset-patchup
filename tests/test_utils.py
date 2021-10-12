"""
This module tests utils
"""
from unittest.mock import patch

from superset_patchup.utils import (
    get_complex_env_var,
    is_safe_url,
    is_valid_provider
)
from .base_tests import SupersetTestCase


class TestUtils(SupersetTestCase):
    """
    Class to test the utils module
    """

    @patch("superset_patchup.utils.request")
    def test_is_safe_url(self, mock):  # pylint: disable=R0201
        """
        Test that only urls from the same domain are set as safe
        by the is_safe_url function
        """
        mock.host_url = "https://example.com"
        assert is_safe_url("https://example.com") is True
        assert is_safe_url("https://google.com") is False

    @patch("superset_patchup.utils.os.getenv")
    def test_get_complex_env_var_default(self, mock):  # pylint: disable=R0201
        """
        Test that the get_complex_env_var function returns the default value
        when the variable is not set
        """
        mock.return_value = None
        default_params = {"bean": "bag"}
        params = get_complex_env_var("PARAMS", default_params)
        # assert that the value returned is a dictionary
        assert isinstance(params, dict)
        # assert that the value returned is the default
        assert params == default_params

    @patch("superset_patchup.utils.os.getenv")
    def test_get_complex_env_var(self, mock):  # pylint: disable=R0201
        """
        Test that the get_complex_env_var function is able to return a
        complex variable
        """
        default_params = {"bean": "bag"}

        # dict variable
        params_value = {"spring": "bean"}
        mock.return_value = str(params_value)
        params = get_complex_env_var("PARAMS", default_params)
        assert isinstance(params, dict)
        assert params == params_value

        # bool variable
        mock.return_value = "True"
        bool_params = get_complex_env_var("PARAMS", default_params)
        assert isinstance(bool_params, bool)
        assert bool_params is True

    def test_case_insensitivity_for_provider(self):  # pylint: disable=R0201
        """
        Test that provider information form user can be case insesitive,
        to static standard strings that  they will be checked against
        """
        assert is_valid_provider("opensrp", "OpenSRP")
        assert is_valid_provider("OnaData", 'onadata')
        assert is_valid_provider("OpenlMis", "openlmis")
        assert is_valid_provider("Opensrp-preview", "opensrp")
        assert not is_valid_provider("oensrp", "OpenSrp")
