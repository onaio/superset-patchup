# -*- coding: utf-8 -*-
"""
Base TestCase class
"""

import os
import shutil

from flask_appbuilder import SQLA
from flask_testing import TestCase
from superset.app import create_app

superset_test_home = os.path.join(os.path.dirname(__file__), ".superset")
shutil.rmtree(superset_test_home, ignore_errors=True)
os.environ["SUPERSET_HOME"] = superset_test_home
os.environ["SUPERSET_CONFIG"] = "tests.test_config.ketchup_config"
app = create_app()


class SupersetTestCase(TestCase):
    """The base TestCase class for all tests relying on Flask app context"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.maxDiff = None
        self.db = SQLA()

    def create_app(self):
        return app

    def setUp(self):
        self.db.create_all()

    def tearDown(self):
        self.db.session.remove()
        self.db.drop_all()
