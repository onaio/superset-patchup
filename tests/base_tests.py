# -*- coding: utf-8 -*-
"""
Base TestCase class
"""

import os
import shutil

from flask_testing import TestCase
from superset.app import create_app, db

superset_test_home = os.path.join(os.path.dirname(__file__), '.superset')
shutil.rmtree(superset_test_home, ignore_errors=True)
os.environ['SUPERSET_HOME'] = superset_test_home
os.environ['SUPERSET_CONFIG'] = 'tests.test_config.ketchup_config'
app = create_app()


class SupersetTestCase(TestCase):
    """The base TestCase class for all tests relying on Flask app context"""

    def __init__(self, *args, **kwargs):
        super(SupersetTestCase, self).__init__(*args, **kwargs)
        self.maxDiff = None

    def create_app(self):
        return app

    def setUp(self):
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
