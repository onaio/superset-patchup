import json
import celery
import superset
from .. import helpers

#superset.app.config['SQLALCHEMY_ECHO'] = True
logger = celery.utils.log.get_task_logger(__name__)

class TestApiViews:

    """Tests of -ketchup API extensions"""

    def setup_method(self, method):
        helpers.cleanup_data()

    def teardown_method(self, method):
        helpers.cleanup_data()

    def test_ketchup_version(self):

        """Test basic version endpoint exists"""

        client = superset.app.test_client()
        response = _jsonify(client.get("/superset-ketchup/api/version/"))
        assert 'version' in response

    def test_all_dashboards_owned(self):

        """Make sure owned dashboards show up in all_dash-"""

        dashboard = helpers.create_dashboard()
        test_user = superset.security_manager.find_user('test_user')

        helpers.add_owner_to_dashboard(dashboard, test_user)

        client = superset.app.test_client()
        logger.info(test_user)
        client.get("/test/login/%s" % test_user.username)

        response = _jsonify(client.get("/superset-ketchup/api/all_dashboards/"))
        assert len(response) == 1

    def test_all_dashboards_slice_access(self):

        """Make sure slice-accessible dashboards show up in all_dash-"""

        dashboard = helpers.create_dashboard()
        slyce = dashboard.slices[0]
        test_user = superset.security_manager.find_user('test_user')
        test_role = superset.security_manager.find_role('test_role')

        helpers.grant_slice_access_to_role(test_role, slyce)

        client = superset.app.test_client()
        client.get("/test/login/%s" % test_user.username)

        response = _jsonify(client.get("/superset-ketchup/api/all_dashboards/"))
        assert len(response) == 1

    def test_all_dashboards_no_access(self):

        """Make sure other dashboards don't show up in all_dash-"""

        dashboard = helpers.create_dashboard()
        slyce = dashboard.slices[0]

        client = superset.app.test_client()
        response = _jsonify(client.get("/superset-ketchup/api/all_dashboards/"))
        assert len(response) == 0


def _jsonify(http_response):
    return json.loads(http_response.data.decode("utf-8"))
