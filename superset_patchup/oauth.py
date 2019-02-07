"""This module holds OAuth Provider profiles"""
import inspect
import logging
import os
import re
import sys

from flask import abort, flash, redirect, request

from flask_appbuilder._compat import as_unicode
from flask_appbuilder.security.views import \
    AuthOAuthView as SupersetAuthOAuthView
from flask_appbuilder.security.views import expose

from superset.security import SupersetSecurityManager

from flask_login import login_user

from superset_patchup.utils import get_complex_env_var, is_safe_url

PROVIDERS = {
    "openlmis": {
        "name":
        os.getenv("SUPERSET_OPENLMIS_OAUTH_NAME", "openlmis"),
        "icon":
        os.getenv("SUPERSET_OPENLMIS_OAUTH_ICON", "fa-sign-in"),
        "token_key":
        os.getenv("SUPERSET_OPENLMIS_OAUTH_ACCESS_TOKEN", "access_token"),
        "custom_redirect_url":
        os.getenv("SUPERSET_OPENLMIS_REDIRECT_URL"),
        "remote_app": {
            "consumer_key":
            os.getenv("SUPERSET_OPENLMIS_OAUTH_CONSUMER_KEY", "superset"),
            "consumer_secret":
            os.getenv("SUPERSET_OPENLMIS_OAUTH_CONSUMER_SECRET", "changeme"),
            "request_token_params":
            get_complex_env_var("SUPERSET_OPENLMIS_OAUTH_REQUEST_TOKEN_PARAMS",
                                {"scope": "read write"}),
            "access_token_method":
            os.getenv("SUPERSET_OPENLMIS_OAUTH_ACCESS_TOKEN_METHOD", "POST"),
            "access_token_headers":
            get_complex_env_var(
                "SUPERSET_OPENLMIS_OAUTH_ACCESS_TOKEN_HEADERS",
                {"Authorization": "Basic c3VwZXJzZXQ6Y2hhbmdlbWU="},
            ),
            "base_url":
            os.getenv("SUPERSET_OPENLMIS_OAUTH_BASE_URL",
                      "https://uat.openlmis.org/api/oauth"),
            "access_token_url":
            os.getenv(
                "SUPERSET_OPENLMIS_OAUTH_ACCESS_TOKEN_URL",
                "https://uat.openlmis.org/api/oauth/token?grant_type=authorization_code",  # noqa
            ),
            "authorize_url":
            os.getenv(
                "SUPERSET_OPENLMIS_OAUTH_AUTHORIZE_URL",
                "https://uat.openlmis.org/api/oauth/authorize?",
            ),
        },
    },
    "google": {
        "name": os.getenv("SUPERSET_GOOGLE_OAUTH_NAME", "google"),
        "icon": os.getenv("SUPERSET_GOOGLE_OAUTH_ICON", "fa-google"),
        "token_key": os.getenv("SUPERSET_GOOGLE_OAUTH_TOKEN_KEY", "token_key"),
        "custom_redirect_url": os.getenv("SUPERSET_GOOGLE_REDIRECT_URL"),
        "remote_app": {
            "base_url":
            os.getenv(
                "SUPERSET_ONADATA_OAUTH_BASE_URL",
                "'https://www.googleapis.com/oauth2/v2/'",
            ),
            "request_token_params":
            get_complex_env_var("SUPERSET_GOOGLE_OAUTH_REQUEST_TOKEN_PARAMS",
                                {"scope": "email profile"}),
            "request_token_url":
            os.getenv("SUPERSET_GOOGLE_OAUTH_REQUEST_TOKEN_URL", None),
            "access_token_url":
            os.getenv(
                "SUPERSET_GOOGLE_OAUTH_ACCESS_TOKEN_URL",
                "https://accounts.google.com/o/oauth2/token",
            ),
            "authorize_url":
            os.getenv(
                "SUPERSET_GOOGLE_OAUTH_AUTHORIZE_URL",
                "https://accounts.google.com/o/oauth2/auth",
            ),
            "consumer_key":
            os.getenv("SUPERSET_GOOGLE_OAUTH_CONSUMER_KEY",
                      "GOOGLE_OAUTH_KEY"),
            "consumer_secret":
            os.getenv("SUPERSET_GOOGLE_OAUTH_CONSUMER_SECRET",
                      "GOOGLE_OAUTH_SECRET"),
        },
    },
    "onadata": {
        "name":
        os.getenv("SUPERSET_ONADATA_OAUTH_NAME", "onadata"),
        "icon":
        os.getenv("SUPERSET_ONADATA_OAUTH_ICON", "fa-eercast"),
        "token_key":
        os.getenv("SUPERSET_ONADATA_OAUTH_ACCESS_TOKEN", "access_token"),
        "custom_redirect_url":
        os.getenv("SUPERSET_ONADATA_REDIRECT_URL"),
        "remote_app": {
            "consumer_key":
            os.getenv("SUPERSET_ONADATA_OAUTH_CONSUMER_KEY", "superset"),
            "consumer_secret":
            os.getenv("SUPERSET_ONADATA_OAUTH_CONSUMER_SECRET", "changeme"),
            "request_token_params":
            get_complex_env_var("SUPERSET_ONADATA_OAUTH_REQUEST_TOKEN_PARAMS",
                                {"scope": "read write"}),
            "access_token_method":
            os.getenv("SUPERSET_ONADATA_OAUTH_ACCESS_TOKEN_METHOD", "POST"),
            "base_url":
            os.getenv("SUPERSET_ONADATA_OAUTH_BASE_URL", "https://api.ona.io"),
            "access_token_url":
            os.getenv("SUPERSET_ONADATA_OAUTH_ACCESS_TOKEN_URL",
                      "https://api.ona.io/o/token/"),
            "authorize_url":
            os.getenv("SUPERSET_ONADATA_OAUTH_AUTHORIZE_URL",
                      "https://api.ona.io/o/authorize"),
        },
    },
}


class AuthOAuthView(SupersetAuthOAuthView):
    """something"""

    @expose("/oauth-authorized/<provider>")
    def oauth_authorized(self, provider):
        """View that a user is redirected to from the Oauth server"""

        logging.debug("Authorized init")
        resp = self.appbuilder.sm.oauth_remotes[provider].authorized_response()
        if "Custom-Api-Token" in request.headers:
            resp = {"access_token": request.headers.get("Custom-Api-Token")}
        if resp is None:
            flash(u"You denied the request to sign in.", "warning")
            return redirect("login")

        logging.debug("OAUTH Authorized resp: {0}".format(resp))

        # Retrieves specific user info from the provider
        try:
            self.appbuilder.sm.set_oauth_session(provider, resp)
            userinfo = self.appbuilder.sm.oauth_user_info(provider, resp)
        except Exception as e:
            logging.error("Error returning OAuth user info: {0}".format(e))
            user = None
        else:
            logging.debug("User info retrieved from {0}: {1}".format(
                provider, userinfo))
            # User email is not whitelisted
            if provider in self.appbuilder.sm.oauth_whitelists:
                whitelist = self.appbuilder.sm.oauth_whitelists[provider]
                allow = False
                for e in whitelist:
                    if re.search(e, userinfo["email"]):
                        allow = True
                        break
                if not allow:
                    flash(u"You are not authorized.", "warning")
                    return redirect("login")
            else:
                logging.debug("No whitelist for OAuth provider")
            user = self.appbuilder.sm.auth_user_oauth(userinfo)

        if user is None:
            flash(as_unicode(self.invalid_login_message), "warning")
            return redirect("login")
        else:
            login_user(user)

            # handle custom redirection
            # first try redirection via a request arg
            redirect_url = request.args.get("redirect_url")
            # if we dont yet have a direct url, try and get it from configs
            if not redirect_url:
                redirect_url = self.appbuilder.sm.get_oauth_redirect_url(
                    provider)
            # if we have it, do the redirection
            if redirect_url:
                # check if the url is safe for redirects.
                if not is_safe_url(redirect_url):
                    return abort(400)

                return redirect(redirect_url)

            return redirect(self.appbuilder.get_url_for_index)


class CustomSecurityManager(SupersetSecurityManager):
    """Custom Security Manager Class"""

    authoauthview = AuthOAuthView

    def get_oauth_redirect_url(self, provider):
        """
        Returns the custom_redirect_url for the oauth provider
        if none is configured defaults toNone
        this is configured using OAUTH_PROVIDERS and custom_redirect_url key.
        """
        for _provider in self.oauth_providers:
            if _provider["name"] == provider:
                return _provider.get("custom_redirect_url")

        return None

    def oauth_user_info(self, provider, response=None):
        """Get user info"""

        if provider == "onadata":
            user = (self.appbuilder.sm.oauth_remotes[provider].get(
                "api/v1/user.json").data)
            username = user["username"]

            me = (self.appbuilder.sm.oauth_remotes[provider].get(
                "api/v1/profiles/{0}.json".format(username)).data)

            return {
                "name": me["name"],
                "email": me["email"],
                "id": me["id"],
                "username": username,
                "first_name": me["first_name"],
                "last_name": me["last_name"],
            }

        if provider == "openlmis":
            # get access token
            my_token = self.oauth_tokengetter()[0]
            # get referenceDataUserId
            reference_user_id = self.appbuilder.sm.oauth_remotes[provider].get(
                "oauth/check_token", data={"token": my_token})
            reference_data_user_id = reference_user_id.data[
                "referenceDataUserId"]
            # get user details
            endpoint = "users/{}".format(reference_data_user_id)
            user_info = self.appbuilder.sm.oauth_remotes[provider].get(
                endpoint)
            me = user_info.data
            # get email
            email_endpoint = "userContactDetails/{}".format(
                reference_data_user_id)
            email = self.appbuilder.sm.oauth_remotes[provider].get(
                email_endpoint)
            return {
                "name": me["username"],
                "email": email.data["emailDetails"]["email"],
                "id": me["id"],
                "username": me["username"],
                "first_name": me["firstName"],
                "last_name": me["lastName"],
            }
