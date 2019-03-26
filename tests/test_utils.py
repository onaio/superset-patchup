"""
This module tests utils
"""
import os
import sys
from unittest.mock import patch

sys.path = [os.path.abspath('')] + sys.path
from superset_patchup.utils import is_safe_url


class TestUtils:
    """
    Class to test the utils module
    """

    @patch('superset_patchup.utils.request')
    def test_is_safe_url(self, mock):
        """
        Test is_safe_url
        """
        mock.host_url = "https://example.com"
        assert(is_safe_url("https://example.com") is True)
        assert(is_safe_url("https://google.com") is False)
