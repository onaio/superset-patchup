"""
Main init file for superset_patchup
"""
from . import oauth
from . import views
from .version import (VERSION, __version__)

#pylint: disable=unused-argument
def patch_app(superset_app):
    """Hook called once superset is initialized"""
    views.patch_views()
