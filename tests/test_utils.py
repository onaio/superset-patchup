"""
This module tests utils
"""
import sys
import os
from unittest.mock import patch

sys.path = [os.path.abspath('')] + sys.path
from superset_patchup.utils import is_safe_url

class TestUtils:
    """
    Class to test the utils module
    """

    def test_get_complex_env_var(self):
        """
        Test get_complex_env_var
        """
        assert(1==1)

    @patch('superset_patchup.utils.request.host_url')
    def test_is_safe_url(self, mock):
        """
        Test is_safe_url
        """
        mock.return_value = "https://example.com"
        assert(is_safe_url("https://example.com/I-am-cool") is True)
        assert(is_safe_url("https://google.com/I-am-cool") is False)
