# superset-patchup (Ketchup)

Superset-patchup is a python package that "patches" [Superset](https://superset.incubator.apache.org/) to add custom functionality that we find to be useful.

## How it works

Superset-patchup is meant to be installed alongside Superset.

This can be done this way:

```sh
# to install version 0.1.0
pip install git+https://github.com/onaio/superset-patchup.git@v0.1.0  
```

Once installed, you would need to modify the `superset_config.py` to configure Superset using Superset-patchup.

## Features

Currently Superset-patchup adds a CustomSecurityManager class that holds all of its functionality.  This CustomSecurityManager class also uses a custom AuthOAuthView class.

### Allow access to superset using oAuth access tokens

This functionality is provided by the custom AuthOAuthView introduced by Superset-patchup.  It primarily allows you to access most Superset API endpoints using an oAuth access token.

To configure this, you would add the following to your `superset_config.py` file:

```python
# superset_config.py
from superset_patchup.oauth import CustomSecurityManager


# standard Superset oAuth settings go here
AUTH_TYPE = AUTH_OAUTH
OAUTH_PROVIDERS = [
{
    'name': 'onadata',
    'icon': 'fa-rebel',
        'token_key': 'access_token',
        'remote_app': {
            'consumer_key': 'consumer key goes here',
            'consumer_secret': 'consumer secret goes here'
            'base_url': 'https://stage-api.ona.io/',
            'access_token_url': 'https://stage-api.ona.io/o/token/',
            'authorize_url': 'https://stage-api.ona.io/o/authorize/'
        }
}
]
# end of standard Superset oAuth settings
CUSTOM_SECURITY_MANAGER = CustomSecurityManager
```

### Custom redirect url after oAuth sign in

This functionality is provided by the custom AuthOAuthView introduced by Superset-patchup.  It allows you to set a custom redirect url that the user will be sent to after they sign in using oAuth.

To configure this, you would add the following to your `superset_config.py` file:

```python
# superset_config.py
from superset_patchup.oauth import CustomSecurityManager


# standard Superset oAuth settings go here
AUTH_TYPE = AUTH_OAUTH
OAUTH_PROVIDERS = [
{
    'name': 'onadata',
    'icon': 'fa-eercast',
        'token_key': 'access_token',
        'remote_app': {
            'consumer_key': 'consumer key goes here',
            'consumer_secret': 'consumer secret goes here'
            'base_url': 'https://stage-api.ona.io/',
            'access_token_url': 'https://stage-api.ona.io/o/token/',
            'authorize_url': 'https://stage-api.ona.io/o/authorize/',
            # the redirect url is set below, it needs to be on the same domain as superset
            'custom_redirect_url': 'https://example.com/superset/sqllab'
        }
}
]
# end of standard Superset oAuth settings
CUSTOM_SECURITY_MANAGER = CustomSecurityManager
```

As an alternative, you can also simply add a redirect variable to the url so as to redirect after logging in. This can be added as below

```
'https://example.com/login/provider?redirect=/superset/dashboard/3/'
```

### Add custom roles

This feature allows you to add custom roles to Superset on initialization.  This is useful when you want to add custom roles to Superset during an automated deployment.

To configure this, you would add the following to your `superset_config.py` file:

```python
# superset_config.py
from superset_patchup.oauth import CustomSecurityManager


CUSTOM_SECURITY_MANAGER = CustomSecurityManager
ADD_CUSTOM_ROLES = True
CUSTOM_ROLES = {
  'Custom_Role_1': {'all_datasource_access'},
  'Custom_Role_2': {'all_datasource_access', 'SQL Lab'}
}
```

### Custom oAuth user info methods

Ketchup's CustomSecurityManager class includes a custom `oauth_user_info` method that correctly sets user information when a user authenticates with Superset using any of the following oAuth providers:

- `onadata`
- `openlmis`
- `OpenSRP`

#### PATCHUP_EMAIL_BASE

In cases where an oAuth provider does not provide an email address for its users, Superset's oAuth process might fail.  To remedy this, Superset-patchup you can set the `PATCHUP_EMAIL_BASE` variable in `superset_config.py`.

When this is set, Superset-patchup will try to generate sensible email address for each authenticated user, like so:

```python
# superset_config.py
PATCHUP_EMAIL_BASE = "ketchup@example.com"
```

With this in place, Superset-patchup will assign each user an email in the form of `ketchup+USERNAME@example.com`.  So, for example, if a user named `bobbie` signed in, his email would be set as `ketchup+bobbie@example.com`.
