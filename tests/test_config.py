# -*- coding: utf-8 -*-
"""
Ketchup test config
"""

import superset_patchup

from superset import config as ketchup_config

ketchup_config.WTF_CSRF_ENABLED = False
ketchup_config.TESTING = True
superset_patchup.add_ketchup(ketchup_config)
