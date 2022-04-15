# -*- coding: utf-8 -*-
"""
This module tests views module.
"""
import json
import celery
import superset

from superset_patchup.views import SupersetKetchupApiView

from . import helpers
from .base_tests import SupersetTestCase

logger = celery.utils.log.get_task_logger(__name__)


class TestApiViews(SupersetTestCase):

    """Tests of -ketchup API extensions"""

    def setUp(self):
        superset.db.create_all()
        superset.utils.core.get_or_create_db("main", "sqlite:///main.db")
        superset.appbuilder.add_permissions(update_perms=True)
        superset.security_manager.sync_role_definitions()

        # Initialize test user and role
        test_role = superset.security_manager.add_role("test_role")
        superset.security_manager.get_session.commit()

        superset.security_manager.add_user(
            "test_user", "Test", "User", "test@user.org", test_role, password="password"
        )
        superset.security_manager.get_session.commit()
        test_role = superset.security_manager.find_role("test_role")
        helpers.grant_api_permission_to_role(
            test_role, SupersetKetchupApiView, "all_dashboards"
        )
        self.client = superset.app.test_client()

    def tearDown(self):
        """Cleanup test data"""
        helpers.cleanup_data()
        superset.db.drop_all()

    def login(self, username, password="password"):
        """Login test user"""
        login_response = self.client.post(
            "/login/",
            data=dict(username=username, password=password),
            follow_redirects=True,
        )
        assert "User confirmation needed" not in login_response.response
        assert login_response.status_code == 200

    def test_ketchup_version(self):  # pylint: disable=R0201

        """Test basic version endpoint exists"""

        client = superset.app.test_client()
        response = _jsonify(client.get("/superset-ketchup/api/version/"))
        assert "version" in response

    def test_all_dashboards_owned(self):  # pylint: disable=R0201

        """Make sure owned dashboards show up in all_dash-"""

        dashboard = helpers.create_dashboard()
        test_user = superset.security_manager.find_user("test_user")

        helpers.add_owner_to_dashboard(dashboard, test_user)

        logger.info(test_user)
        self.login(test_user.username)

        response = _jsonify(self.client.get("/superset-ketchup/api/all_dashboards/"))
        assert len(response) == 1

    def test_all_dashboards_slice_access(self):  # pylint: disable=R0201

        """Make sure slice-accessible dashboards show up in all_dash-"""

        dashboard = helpers.create_dashboard()
        slyce = dashboard.slices[0]
        test_user = superset.security_manager.find_user("test_user")
        test_role = superset.security_manager.find_role("test_role")

        helpers.grant_slice_access_to_role(test_role, slyce)

        self.login(test_user.username)
        response = _jsonify(self.client.get("/superset-ketchup/api/all_dashboards/"))
        assert len(response) == 1

    def test_all_dashboards_no_access(self):  # pylint: disable=R0201

        """Make sure other dashboards don't show up in all_dash-"""
        superset.db.create_all()

        dashboard = helpers.create_dashboard()
        assert len(dashboard.slices) > 0

        response = _jsonify(self.client.get("/superset-ketchup/api/all_dashboards/"))
        assert response == {"message": "Access is Denied", "severity": "danger"}

        test_user = superset.security_manager.find_user("test_user")
        self.login(test_user.username)
        response = _jsonify(self.client.get("/superset-ketchup/api/all_dashboards/"))
        assert len(response) == 0


def _jsonify(http_response):
    return json.loads(http_response.data.decode("utf-8"))
