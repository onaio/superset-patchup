"""
Main init file for superset_patchup

Generally the flow for patching superset is intended to be:
1) Superset starts initting
2) Superset loads config
  2a) Config instrumented with add_ketchup
3) Superset finishes initting
  3a) app instrumented with add_ketchup_post
"""
from .version import (VERSION, __version__)  # noqa


def add_ketchup(superset_config, ketchup_security=True, ketchup_views=True):

    """
    Add -ketchup/-patchup extensions to superset
    Note that we initialize the configuration stuff here, and then anything
    that modifies the superset app itself (i.e. views) goes in
    add_ketchup_post(), where the app itself is ready.
    """

    if ketchup_security:

        # DRAGONS - import here because packaging script must have minimal
        # default dependencies
        from . import oauth  # pylint: disable=import-outside-toplevel

        superset_config.CUSTOM_SECURITY_MANAGER = oauth.CustomSecurityManager

    def add_ketchup_post(superset_app):

        """Hook called once superset is initialized"""

        if ketchup_views:

            # DRAGONS - import here, because superset must be initialized
            # to use superset.views
            from . import views  # pylint: disable=import-outside-toplevel

            views.add_ketchup_views(superset_app)

    superset_config.FLASK_APP_MUTATOR = add_ketchup_post
