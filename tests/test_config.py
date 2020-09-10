# -*- coding: utf-8 -*-
"""
Ketchup test config
"""

import superset_patchup

from flask_appbuilder.security.manager import AUTH_OAUTH
from superset import config as ketchup_config

ketchup_config.WTF_CSRF_ENABLED = False
ketchup_config.TESTING = True
ketchup_config.SECRET_KEY = 'abc'
superset_patchup.add_ketchup(ketchup_config)
SECRET_KEY = ketchup_config.SECRET_KEY
AUTH_TYPE = AUTH_OAUTH
OAUTH_PROVIDERS = [
    {
        'name': 'onadata',
        'remote_app': {
            'client_id': 'consumer key goes here',
            'client_secret': 'consumer secret goes here',
            'api_base_url': 'https://stage-api.ona.io/',
            'access_token_url': 'https://stage-api.ona.io/o/token/',
            'authorize_url': 'https://stage-api.ona.io/o/authorize/',
        }
    }
]
SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
SQLALCHEMY_TRACK_MODIFICATIONS = False
