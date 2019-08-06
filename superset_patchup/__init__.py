"""
Main init file for superset_patchup
"""
from .version import (VERSION, __version__) # noqa


# pylint: disable=unused-argument
def patch_app(superset_app):
    """Hook called once superset is initialized"""
    # DRAGONS - import here, otherwise we add dependencies for packaging which
    # needs __version__
    from . import views
    # NOTE: Is there a way to get the superset instance from the app obj?
    views.patch_views()
