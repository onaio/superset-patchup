"""
This module tests utils
"""
import os
import sys

from superset_patchup.utils import is_safe_url, get_complex_env_var

from unittest.mock import patch

sys.path = [os.path.abspath("")] + sys.path


class TestUtils:
    """
    Class to test the utils module
    """

    @patch("superset_patchup.utils.request")
    def test_is_safe_url(self, mock):
        """
        Test that only urls from the same domain are set as safe
        by the is_safe_url function
        """
        mock.host_url = "https://example.com"
        assert is_safe_url("https://example.com") is True
        assert is_safe_url("https://google.com") is False

    @patch("superset_patchup.utils.os.getenv")
    def test_get_complex_env_var_default(self, mock):
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
    def test_get_complex_env_var(self, mock):
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
        mock.return_value = 'True'
        bool_params = get_complex_env_var("PARAMS", default_params)
        assert isinstance(bool_params, bool)
        assert bool_params is True
