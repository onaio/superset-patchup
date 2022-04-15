"""
Additional extensions to SuperSet views
"""

from flask_appbuilder import expose
from flask_appbuilder.security.decorators import has_access_api
from flask_appbuilder.models.sqla.interface import SQLAInterface
import superset.views

from .version import VERSION, __version__


class SupersetKetchupApiView(superset.views.base.BaseSupersetView):

    """
    Extensions to Superset API
    """

    def __init__(self):
        self.route_base = "/superset-ketchup/api"
        super().__init__()

    @superset.views.base.api
    @expose("/version/", methods=["GET"])
    def version(self):
        """Returns *superset-patchup* api version"""
        return self.json_response({"version": VERSION, "versionStr": __version__})

    @superset.views.base.api
    @has_access_api
    @expose("/all_dashboards/", methods=["GET"])
    def all_dashboards(self):

        """
        Extension to allow API access to information *about* dashboards.
        See: /fave_dashboards/, etc.
        Returns the ids, links, names, and URLs of the dashboards a user has
        access to.
        """
        dashboards = superset.db.session.query(superset.models.dashboard.Dashboard)

        # Query only dashboards where we have at least some access - note that
        # this exact query filter is used in the core Superset view to prune
        # visible dashboards.
        # Logic is basically "dashboard owned by user or at least one slice
        # accessible by user"
        # See: https://github.com/apache/incubator-superset/blob/0.27/
        # superset/views/core.py#L154
        view_filter = superset.dashboards.filters.DashboardAccessFilter(
            "slice", SQLAInterface(superset.models.dashboard.Dashboard)
        )

        dashboards = view_filter.apply(dashboards, lambda: None)

        payload = []
        for dashboard in dashboards:

            value = {
                "id": dashboard.id,
                "dashboard_link": dashboard.dashboard_link(),
                "dashboard_title": dashboard.dashboard_title,
                "url": dashboard.url,
            }

            payload.append(value)

        return self.json_response(payload)


# pylint: disable=unused-argument
def add_ketchup_views(superset_app):
    """Hook up the views (*after* other initialization of superset)"""
    # NOTE: Is there a way to get the superset instance from the app obj?
    superset.appbuilder.add_view_no_menu(SupersetKetchupApiView)
