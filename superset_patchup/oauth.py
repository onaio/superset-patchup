"""This module holds OAuth Provider profiles"""
import logging
import re

from flask import (
    abort,
    flash,
    g,
    redirect,
    request,
    session,
    url_for,
    jsonify,
    make_response,
)

from flask_appbuilder._compat import as_unicode
from flask_appbuilder.security.sqla import models as ab_models
from flask_appbuilder.security.views import AuthOAuthView as SupersetAuthOAuthView
from flask_appbuilder.security.views import expose

from superset.security import SupersetSecurityManager

import jwt
from flask_login import login_user

from superset_patchup.utils import is_safe_url, is_valid_provider


class AuthOAuthView(SupersetAuthOAuthView):
    """Flask-AppBuilder's Authentication OAuth view"""

    login_template = "appbuilder/general/security/login_oauth.html"

    @expose("/login/")
    @expose("/login/<provider>")
    @expose("/login/<provider>/<register>")
    # pylint: disable=logging-fstring-interpolation
    def login(self, provider=None, register=None):
        """The login view from AuthOAuthView"""
        logging.debug(f"Provider: {provider}")

        # handle redirect
        redirect_url = self.appbuilder.get_url_for_index
        if request.args.get("redirect_url") is not None:
            redirect_url = request.args.get("redirect_url")
            if not is_safe_url(redirect_url):
                return abort(400)

        if g.user is not None and g.user.is_authenticated:
            logging.debug(f"Already authenticated {g.user}")
            return redirect(redirect_url)

        if provider is None:
            return self.render_template(
                self.login_template,
                providers=self.appbuilder.sm.oauth_providers,
                title=self.title,
                appbuilder=self.appbuilder,
            )
        logging.debug(f"Going to call authorize for: {provider}")
        state = self.generate_state()
        try:
            scheme = self.appbuilder.app.config.get("PREFERRED_URL_SCHEME", "https")
            if register:
                logging.debug("Login to Register")
                session["register"] = True
            if provider == "twitter":
                return self.appbuilder.sm.oauth_remotes[provider].authorize_redirect(
                    redirect_uri=url_for(
                        ".oauth_authorized",
                        provider=provider,
                        _external=True,
                        _scheme=scheme,
                        state=state,
                    )
                )
            callback = url_for(
                ".oauth_authorized", provider=provider, _external=True, _scheme=scheme
            )
            return self.appbuilder.sm.oauth_remotes[provider].authorize_redirect(
                redirect_uri=callback,
            )
        except Exception as err:  # pylint: disable=broad-except
            logging.error(f"Error on OAuth authorize: {err}")
            flash(as_unicode(self.invalid_login_message), "warning")
            return redirect(redirect_url)

    @expose("/oauth-init/<provider>")
    def login_init(self, provider=None):
        """
        Checks authorization and if a user is not authorized,
        inits the sign-in process and returns a state
        """
        logging.debug("Provider: %s", provider)

        if g.user is not None and g.user.is_authenticated:
            logging.debug("Provider %s is already authorized by %s", provider, g.user)
            return make_response(jsonify(isAuthorized=True))

        redirect_url = request.args.get("redirect_url")
        if not redirect_url or not is_safe_url(redirect_url):
            logging.debug("The arg redirect_url not found or not safe")
            return abort(400)

        logging.debug("Initialization of authorization process for: %s", provider)

        # libraries assume that
        # 'redirect_url' should be available in the session
        session[f"{provider}_oauthredir"] = redirect_url

        state = self.generate_state()

        # Newest version of Superset for OpenLMIS
        session[f"_{provider}_authlib_state_"] = state
        session[f"_{provider}_authlib_redirect_uri_"] = redirect_url

        return make_response(jsonify(isAuthorized=False, state=state))

    @expose("/oauth-authorized/<provider>")
    # pylint: disable=too-many-branches
    # pylint: disable=logging-fstring-interpolation
    def oauth_authorized(self, provider):
        """View that a user is redirected to from the Oauth server"""

        logging.debug("Authorized init")
        if "Custom-Api-Token" in request.headers:
            logging.debug("Custom-Api-Token is present")
            resp = {"access_token": request.headers.get("Custom-Api-Token")}
        else:
            resp = self.appbuilder.sm.oauth_remotes[provider].authorize_access_token()
        if resp is None:
            flash("You denied the request to sign in.", "warning")
            return redirect("/login")

        logging.debug(f"OAUTH Authorized resp: {resp}")

        # Retrieves specific user info from the provider
        try:
            self.appbuilder.sm.set_oauth_session(provider, resp)
            userinfo = self.appbuilder.sm.oauth_user_info(provider, resp)
        except Exception as no_user:  # pylint: disable=broad-except
            logging.error(f"Error returning user info: {no_user}")
            user = None
        else:
            logging.debug(f"User info retrieved from {provider}: {userinfo}")
            # User email is not whitelisted
            if provider in self.appbuilder.sm.oauth_whitelists:
                whitelist = self.appbuilder.sm.oauth_whitelists[provider]
                allow = False
                for item in whitelist:
                    if re.search(item, userinfo["email"]):
                        allow = True
                        break
                if not allow:
                    flash("You are not authorized.", "warning")
                    return redirect("/login")
            else:
                logging.debug("No whitelist for OAuth provider")
            user = self.appbuilder.sm.auth_user_oauth(userinfo)

        if user is None:
            flash(as_unicode(self.invalid_login_message), "warning")
            return redirect("/login")
        login_user(user)

        # handle custom redirection
        # first try redirection via a request arg
        redirect_url = request.args.get("redirect_url")
        # if we dont yet have a direct url, try and get it from configs
        if not redirect_url:
            redirect_url = self.appbuilder.sm.get_oauth_redirect_url(provider)
        # if we have it, do the redirection
        if redirect_url:
            # check if the url is safe for redirects.
            if not is_safe_url(redirect_url):
                return abort(400)

            return redirect(redirect_url)

        return redirect(self.appbuilder.get_url_for_index)

    def generate_state(self):
        """
        Generates a state which is required during the OAuth sign-in process
        """
        return jwt.encode(
            request.args.to_dict(flat=False),
            self.appbuilder.app.config["SECRET_KEY"],
            algorithm="HS256",
        )


class CustomSecurityManager(SupersetSecurityManager):
    """Custom Security Manager Class"""

    authoauthview = AuthOAuthView

    # pylint: disable=no-self-use
    def is_custom_defined_permission(self, perm, role_perms):
        """
        Returns the list of permissions in role_perms
        """
        return perm.permission.name in role_perms

    def is_custom_pvm(self, pvm, role_perms):
        """
        Checks if the permission should be granted or not for the custom role
        returns a boolean value
        """
        return not (
            self._is_user_defined_permission(pvm)
            or self._is_admin_only(pvm)
            or self._is_alpha_only(pvm)
        ) or (self.is_custom_defined_permission(pvm, role_perms))

    def set_custom_role(self, role_name, pvm_check, role_perms):
        """
        Assign permissions to a role
        """
        logging.info("Syncing %s perms", role_name)
        sesh = self.get_session
        pvms = sesh.query(ab_models.PermissionView).all()
        pvms = [p for p in pvms if p.permission and p.view_menu]
        role = self.add_role(role_name)
        role_pvms = [p for p in pvms if pvm_check(p, role_perms)]
        role.permissions = role_pvms
        sesh.merge(role)
        sesh.commit()

    def sync_role_definitions(self):
        """Inits the Superset application with security roles and such"""
        super().sync_role_definitions()

        # dirty hack.  We need to load the app from here because at the top
        # of the file superset is not yet initialized with an app property
        from superset import app  # pylint: disable=import-outside-toplevel

        add_custom_roles = app.config.get("ADD_CUSTOM_ROLES", False)
        custom_roles = app.config.get("CUSTOM_ROLES", {})

        if add_custom_roles is True:
            for role, role_perms in custom_roles.items():
                self.set_custom_role(role, self.is_custom_pvm, role_perms)

        self.create_missing_perms()

        # commit role and view menu updates
        self.get_session.commit()
        self.clean_perms()

    def get_oauth_redirect_url(self, provider):
        """
        Returns the custom_redirect_url for the oauth provider
        if none is configured defaults to None
        this is configured using OAUTH_PROVIDERS and custom_redirect_url key.
        """
        for _provider in self.oauth_providers:
            if _provider["name"] == provider:
                return _provider.get("custom_redirect_url")

        return None

    # pylint: disable=method-hidden
    # pylint: disable=unused-argument
    # pylint: disable=too-many-locals
    def oauth_user_info(self, provider, response=None):
        """Get user info"""

        # dirty hack.  We need to load the app from here because at the top
        # of the file superset is not yet initialized with an app property
        from superset import app  # pylint: disable=import-outside-toplevel

        # this is used for provider's whose users do not have an email address
        # superset requires an email address and so we need to provide it
        # the email base should be a string e.g. superset@example.com
        # we then use it to construct email addresses for the user logging in
        # that look like superset+username@example.com (if the base was as set
        # above)
        email_base = app.config.get("PATCHUP_EMAIL_BASE")

        onadata_provider = app.config.get("ONADATA_PROVIDER_NAME", "onadata")
        if is_valid_provider(provider, onadata_provider):
            user = (
                self.appbuilder.sm.oauth_remotes[provider]
                .get("api/v1/user.json", token=response)
                .json()
            )

            user_data = (
                self.appbuilder.sm.oauth_remotes[provider]
                .get(f"api/v1/profiles/{user['username']}.json", token=response)
                .json()
            )

            return {
                "name": user_data["name"],
                "email": user_data["email"],
                "id": user_data["id"],
                "username": user["username"],
                "first_name": user_data["first_name"],
                "last_name": user_data["last_name"],
            }

        if is_valid_provider(provider, "OpenSRP"):
            user_object = (
                self.appbuilder.sm.oauth_remotes[provider]
                .get("user-details", token=response)
                .json()
            )

            username = user_object.get("username") or user_object.get("userName")

            result = {"username": username}

            if user_object.get("preferredName"):
                result["name"] = user_object.get("preferredName")

            if email_base:
                # change emails from name@xyz.com to name+username@xyz.com
                result["email"] = email_base.replace("@", f"+{username}@")

            return result

        if is_valid_provider(provider, "openlmis"):
            # get access token
            my_token = self.oauth_tokengetter()[0]
            # get referenceDataUserId
            reference_user = self.appbuilder.sm.oauth_remotes[provider].post(
                "oauth/check_token", data={"token": my_token}
            )
            reference_data_user_id = reference_user.json()["referenceDataUserId"]
            # get user details
            endpoint = f"users/{reference_data_user_id}"
            user_data = (
                self.appbuilder.sm.oauth_remotes[provider]
                .get(endpoint, token=response)
                .json()
            )
            # get email
            email_endpoint = f"userContactDetails/{reference_data_user_id}"
            email = (
                self.appbuilder.sm.oauth_remotes[provider]
                .get(email_endpoint, token=response)
                .json()
            )
            return {
                "name": user_data["username"],
                "email": email["emailDetails"]["email"],
                "id": user_data["id"],
                "username": user_data["username"],
                "first_name": user_data["firstName"],
                "last_name": user_data["lastName"],
            }

        return None
