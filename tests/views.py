# -*- coding: utf-8 -*-
"""
Creates TestView class
"""
import flask_login
from flask_appbuilder import expose
import superset


class TestView(superset.views.base.BaseSupersetView):

    """
    Extra view extensions required for view testing
    """

    def __init__(self):
        self.route_base = "/test"

    @superset.views.base.api
    @expose('/login/<username>', methods=['GET'])
    def login(self, username):

        """
        Test login which does no authentication.

        This needs to exist to fully test user access - we need an endpoint
        that actually sets cookies, etc. so that the flask app.test_client()
        can work nicely.
        """

        user = superset.security_manager.find_user(username)
        flask_login.login_user(user)
        return self.json_response({'id': user.id, 'username': username})

    @superset.views.base.api
    @expose('/logout', methods=['GET'])
    def logout(self):
        """Test logout"""
        flask_login.logout_user()


# Add test views
superset.appbuilder.add_view_no_menu(TestView)
