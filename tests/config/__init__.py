"""
Testing configuration for superset-patchup
"""

# DRAGONS: Superset likes to configure initialization via the config -
# so we only import (and init) the -patchup module here so we're sure
# superset is already initializing.
# This also mimics our deployments where we add_ketchup inside the
# custom config itself.
import superset_patchup

KETCHUP_CONFIG = __import__('superset').config
superset_patchup.add_ketchup(KETCHUP_CONFIG)