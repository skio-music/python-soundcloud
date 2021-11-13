import typing as t
import typing_extensions as te
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode

from soundcloud.resource import Resource, ResourceList, wrapped_resource
from soundcloud.request import make_request


class TokenResponseP(te.Protocol):
    access_token: str
    refresh_token: str
    expires_in: int    # seconds
    token_type: str
    scope: str


class TokenResponse(Resource, TokenResponseP):
    pass


class Client(object):
    """A client for interacting with Soundcloud resources."""

    host = 'api.soundcloud.com'

    access_token: t.Optional[str]
    refresh_token: t.Optional[str]
    token: t.Optional[Resource]

    def __init__(self, **kwargs):
        """Create a client instance with the provided options. Options should
        be passed in as kwargs.
        """
        self.host = kwargs.get('host', self.host)
        self.scheme = 'https://'
        self.options = kwargs
        self._authorize_url = None

        self.client_id = kwargs.get('client_id')

        if 'access_token' in kwargs:
            self.access_token = kwargs.get('access_token')
            return

        if 'client_id' not in kwargs:
            raise TypeError("At least a client_id must be provided.")

        if 'scope' in kwargs:
            self.scope = kwargs.get('scope')

        # decide which protocol flow to follow based on the arguments
        # provided by the caller.
        if self._options_for_authorization_code_flow_present():
            self._authorization_code_flow()
        elif self._options_for_credentials_flow_present():
            self._credentials_flow()
        elif self._options_for_token_refresh_present():
            self._refresh_token_flow()

    def exchange_token(self, code):
        """Given the value of the code parameter, request an access token."""
        url = '%s%s/oauth2/token' % (self.scheme, self.host)
        options = {
            'grant_type': 'authorization_code',
            'redirect_uri': self._redirect_uri(),
            'client_id': self.options.get('client_id'),
            'client_secret': self.options.get('client_secret'),
            'code': code,
        }
        options.update({
            'verify_ssl': self.options.get('verify_ssl', True),
            'proxies': self.options.get('proxies', None)
        })
        self.token = wrapped_resource(
            make_request('post', url, options))
        self.access_token = self.token.access_token
        return self.token

    def authorize_url(self):
        """Return the authorization URL for OAuth2 authorization code flow."""
        return self._authorize_url

    def _authorization_code_flow(self):
        """Build the the auth URL so the user can authorize the app."""
        options = {
            'scope': getattr(self, 'scope', 'non-expiring'),
            'client_id': self.options.get('client_id'),
            'response_type': 'code',
            'redirect_uri': self._redirect_uri()
        }
        url = '%s%s/connect' % (self.scheme, self.host)
        self._authorize_url = '%s?%s' % (url, urlencode(options))

    def _refresh_token_flow(self):
        """Given a refresh token, obtain a new access token."""
        url = '%s%s/oauth2/token' % (self.scheme, self.host)
        options = {
            'grant_type': 'refresh_token',
            'client_id': self.options.get('client_id'),
            'client_secret': self.options.get('client_secret'),
            'refresh_token': self.options.get('refresh_token')
        }
        options.update({
            'verify_ssl': self.options.get('verify_ssl', True),
            'proxies': self.options.get('proxies', None)
        })
        self.token = wrapped_resource(
            make_request('post', url, options))
        self.access_token = self.token.access_token

    def _credentials_flow(self):
        """Given a username and password, obtain an access token."""
        url = '%s%s/oauth2/token' % (self.scheme, self.host)
        options = {
            'client_id': self.options.get('client_id'),
            'client_secret': self.options.get('client_secret'),
            'username': self.options.get('username'),
            'password': self.options.get('password'),
            'scope': getattr(self, 'scope', ''),
            'grant_type': 'password'
        }
        options.update({
            'verify_ssl': self.options.get('verify_ssl', True),
            'proxies': self.options.get('proxies', None)
        })
        self.token = wrapped_resource(
            make_request('post', url, options))
        self.access_token = self.token.access_token

    def client_credentials_flow(self) -> TokenResponse:
        """
        Given an app's client id and client secret, obtain an access token.

        "Please be aware there is a rate limiting on amount of token you can request
        through the Client Credentials Flow: 50 tokens in 12h per app, and 30 tokens
        in 1h per IP address. In order to not hit the limit we highly recommend
        reusing one token between instances of your service and implementing
        the Refresh Token flow to renew tokens."

        https://developers.soundcloud.com/docs/api/guide#client-creds

        :returns: Token:
                    access_token: str
                    refresh_token: str
                    expires_in: int    # seconds
                    token_type: str
                    scope: str
        """
        url = '%s%s/oauth2/token' % (self.scheme, self.host)
        options = {
            'client_id': self.options.get('client_id'),
            'client_secret': self.options.get('client_secret'),
            'grant_type': 'client_credentials'
        }
        options.update({
            'verify_ssl': self.options.get('verify_ssl', True),
            'proxies': self.options.get('proxies', None)
        })
        return wrapped_resource(
            make_request('post', url, options))

    def _request(self, method, resource, **kwargs) -> t.Union[Resource, ResourceList]:
        """Given an HTTP method, a resource name and kwargs, construct a
        request and return the response.
        """
        url = self._resolve_resource_name(resource)

        if hasattr(self, 'access_token'):
            # Updated 2021-09: pass OAuth token as header instead of query param in URL.
            kwargs['headers'] = kwargs.get('headers') or {}
            kwargs['headers']['Authorization'] = f'OAuth {self.access_token}'
        if hasattr(self, 'client_id'):
            kwargs.update(dict(client_id=self.client_id))

        kwargs.update({
            'verify_ssl': self.options.get('verify_ssl', True),
            'proxies': self.options.get('proxies', None)
        })
        return wrapped_resource(make_request(method, url, kwargs))

    def get(self, resource: str, **kwargs):
        return self._request('get', resource, **kwargs)

    def post(self, resource: str, **kwargs):
        return self._request('post', resource, **kwargs)

    def put(self, resource: str, **kwargs):
        return self._request('put', resource, **kwargs)

    def head(self, resource: str, **kwargs):
        return self._request('head', resource, **kwargs)

    def delete(self, resource: str, **kwargs):
        return self._request('delete', resource, **kwargs)

    def _resolve_resource_name(self, name):
        """Convert a resource name (e.g. tracks) into a URI."""
        if name[:4] == 'http':  # already a url
            return name
        name = name.rstrip('/').lstrip('/')
        return '%s%s/%s' % (self.scheme, self.host, name)

    def _redirect_uri(self):
        """
        Return the redirect uri. Checks for ``redirect_uri`` or common typo,
        ``redirect_url``
        """
        return self.options.get(
            'redirect_uri',
            self.options.get('redirect_url', None))

    # Helper functions for testing arguments provided to the constructor.
    def _options_present(self, options, kwargs):
        return all(map(lambda k: k in kwargs, options))

    def _options_for_credentials_flow_present(self):
        required = ('client_id', 'client_secret', 'username', 'password')
        return self._options_present(required, self.options)

    def _options_for_authorization_code_flow_present(self):
        required = ('client_id', 'redirect_uri')
        or_required = ('client_id', 'redirect_url')
        return (self._options_present(required, self.options) or
                self._options_present(or_required, self.options))

    def _options_for_token_refresh_present(self):
        required = ('client_id', 'client_secret', 'refresh_token')
        return self._options_present(required, self.options)
