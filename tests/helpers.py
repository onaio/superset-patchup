"""
Test helpers to create and manage fixtures for our Superset app
"""

import json
import uuid
import superset

from superset.connectors.sqla.models import SqlaTable
from superset.models.core import (Slice, Dashboard)

# Inspired by:
# https://github.com/apache/incubator-superset/blob/0.27/tests/import_export_tests.py
# ... but sadly these aren't packaged for our re-use.  Also they're weird in places.

def create_table(name=None, database_name='main', schema='', tags=['test']):

    """Create a new test table (by default in the 'main' db)"""

    if name is None:
        name = "table-%s" % uuid.uuid4()

    table = SqlaTable(
        table_name=name,
        #
        schema=schema,
        params=json.dumps(dict(
            tags=tags,
            database_name=database_name,
        )),
    )

    # Return imported obj
    return superset.db.session.query(SqlaTable).filter_by(
        id=SqlaTable.import_obj(table)).first()


def new_slice(name=None, table=None, tags=['test']):

    """Create a new test slice (and test table if none specified)"""

    if name is None:
        name = "slice-%s" % uuid.uuid4()

    if table is None:
        table = create_table(tags=tags)

    slyce = Slice(
        slice_name=name,
        datasource_type='table',
        datasource_name=table.datasource_name,
        viz_type='bubble',
        params=json.dumps(dict(
            tags=tags,
            database_name=table.database_name,
            datasource_name=table.datasource_name,
            schema=table.schema,
            metrics=[],
        )),
    )

    # NOTE that we don't actually import the slice here - it needs to
    # be attached to a dashboard for that to make sense
    return slyce


def create_dashboard(title=None, slices=None, tags=['test']):

    """Create a new test dashboard (and slice and table if needed)"""

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

    # Return imported obj
    return superset.db.session.query(Dashboard).filter_by(
        id=Dashboard.import_obj(dashboard)).first()


def cleanup_data(tags=['test']):
    cleanup_objs(Dashboard, tags)
    cleanup_objs(Slice, tags)
    cleanup_objs(SqlaTable, tags)


def cleanup_objs(model, tags=['test']):

    """
    Delete datas that are tagged with certain things
    TODO: Think about tracking with a fixture obj instead, cleaner?
    """

    import celery
    logger = celery.utils.log.get_task_logger(__name__)

    tags = set(tags)
    for obj in superset.db.session.query(model):
        obj_tags = getattr(obj, 'params_dict', {}).get('tags', [])
        if tags.isdisjoint(obj_tags):
            continue
        superset.db.session.delete(obj)
    superset.db.session.commit()

def grant_db_access_to_role(role, db):
    return grant_obj_permission_to_role(role, db, 'database_access')


def grant_slice_access_to_role(role, slyce):
    return grant_obj_permission_to_role(role, slyce, 'datasource_access')


def grant_obj_permission_to_role(role, obj, permission):

    """
    Does the extremely confusing steps required to add permission for a role
    to an object.
    """

    superset.security_manager.merge_perm(permission, obj.perm)
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


def add_owner_to_dashboard(dashboard, user):
    dashboard.owners.append(user)
    superset.db.session.merge(dashboard)
    superset.db.session.commit()
