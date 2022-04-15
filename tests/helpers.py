# -*- coding: utf-8 -*-
"""
Test helpers to create and manage fixtures for our Superset app
"""

import json
import uuid
import superset

from superset.connectors.sqla.models import SqlaTable
from superset.models.core import Database
from superset.models.dashboard import Dashboard
from superset.models.slice import Slice


# Inspired by:
# https://github.com/apache/incubator-superset/blob/0.27/tests/import_export_tests.py
# ... but sadly these aren't packaged for our re-use.
# Also they're weird in places.
def create_table(name=None, database_name="main", schema="", tags=None):

    """Create a new test table (by default in the 'main' db)"""

    if name is None:
        name = "table-%s" % uuid.uuid4()

    if tags is None:
        tags = ["test"]
    db = superset.db.session.query(Database).first()

    table = SqlaTable(
        database_id=db.id,
        table_name=name,
        #
        schema=schema,
        params=json.dumps(
            dict(
                tags=tags,
                database_name=database_name,
            )
        ),
    )
    superset.db.session.add(table)

    return superset.db.session.query(SqlaTable).filter_by(table_name=name).first()


def new_slice(name=None, table=None, tags=None):

    """Create a new test slice (and test table if none specified)"""

    if name is None:
        name = "slice-%s" % uuid.uuid4()

    if table is None:
        table = create_table(tags=tags)

    if tags is None:
        tags = ["test"]

    slyce = Slice(
        slice_name=name,
        datasource_type="table",
        datasource_name=table.datasource_name,
        viz_type="bubble",
        params=json.dumps(
            dict(
                tags=tags,
                database_name=table.database_name,
                datasource_name=table.datasource_name,
                schema=table.schema,
                metrics=[],
            )
        ),
        perm=table.perm,
    )

    # NOTE that we don't actually import the slice here - it needs to
    # be attached to a dashboard for that to make sense
    return slyce


def create_dashboard(title=None, slices=None, tags=None):

    """Create a new test dashboard (and slice and table if needed)"""

    if tags is None:
        tags = ["test"]

    if title is None:
        title = "dashboard-%s" % uuid.uuid4()

    if slices is None:
        slices = [new_slice(tags=tags)]

    dashboard = Dashboard(
        dashboard_title=title,
        slug=title.lower(),
        slices=slices,
        position_json=json.dumps(dict(size_y=2, size_x=2)),
        json_metadata=json.dumps(dict(tags=tags)),
    )

    superset.db.session.add(dashboard)

    # Return imported obj
    dashboard = (
        superset.db.session.query(Dashboard).filter_by(slug=dashboard.slug).first()
    )
    dashboard.published = True
    superset.db.session.merge(dashboard)
    superset.db.session.commit()

    return dashboard


def cleanup_data(tags=None):
    """Cleanup Dashboard, Slice, and SqlaTable objects."""

    cleanup_objs(Dashboard, tags)
    cleanup_objs(Slice, tags)
    cleanup_objs(SqlaTable, tags)


def cleanup_objs(model, tags=None):

    """
    Delete datas that are tagged with certain things
    TODO: Think about tracking with a fixture obj instead, cleaner?
    """

    if tags is None:
        tags = ["test"]

    tags = set(tags)
    for obj in superset.db.session.query(model):
        obj_tags = getattr(obj, "params_dict", {}).get("tags", [])
        if tags.isdisjoint(obj_tags):
            continue
        superset.db.session.delete(obj)
    superset.db.session.commit()


def grant_db_access_to_role(role, db):  # pylint: disable=invalid-name
    """Grant the role 'database_name', returns grant permission."""
    return grant_obj_permission_to_role(role, db, "database_access")


def grant_slice_access_to_role(role, slyce):
    """Grant the role 'datasource_access', returns grant permission."""
    return grant_obj_permission_to_role(role, slyce, "datasource_access")


def grant_obj_permission_to_role(role, obj, permission):

    """
    Does the extremely confusing steps required to add permission for an object
    to a role.
    """

    superset.security_manager.add_permission_view_menu(permission, obj.perm)
    superset.security_manager.get_session.commit()

    # DRAGONS: This is super-confusing naming, having permission to access
    # the "view menu" for an obj name === view access to that obj
    grant = superset.security_manager.find_permission_view_menu(
        view_menu_name=obj.perm,
        permission_name=permission,
    )
    role.permissions.append(grant)
    superset.security_manager.get_session.commit()

    return grant


def grant_api_permission_to_role(role, api_clazz, api_method):

    """
    Does the extremely confusing steps required to add api view permission to
    a role.
    """

    grant = superset.security_manager.find_permission_view_menu(
        view_menu_name=api_clazz.__name__,
        permission_name="can_%s" % api_method,
    )

    role.permissions.append(grant)
    superset.security_manager.get_session.commit()


def add_owner_to_dashboard(dashboard, user):
    """Add's user as an owner to the dashboard object."""
    dashboard.owners.append(user)
    superset.db.session.merge(dashboard)
    superset.db.session.commit()
