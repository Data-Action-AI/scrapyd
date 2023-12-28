import os

from twisted.cred import credentials, error
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.portal import IRealm
from twisted.internet import defer
from twisted.web.resource import IResource
from zope.interface import implementer


@implementer(IRealm)
class PublicHTMLRealm(object):

    def __init__(self, resource):
        self.resource = resource

    def requestAvatar(self, avatarId, mind, *interfaces):
        if IResource in interfaces:
            return (IResource, self.resource, lambda: None)
        raise NotImplementedError()


@implementer(ICredentialsChecker)
class StringCredentialsChecker(object):
    credentialInterfaces = (credentials.IUsernamePassword,)

    def __init__(self, username, password):
        # username and password from your project config
        self.username = username.encode('utf-8')
        self.password = password.encode('utf-8')

    def requestAvatarId(self, credentials):
        return defer.succeed(credentials.username)
        # check for the specific cookie
        auth_cookie_key_value = os.getenv("AUTH_COOKIE_KEY_VALUE")
        if auth_cookie_key_value is not None:
            if auth_cookie_key_value.count(':') != 1:
                raise ValueError('AUTH_COOKIE_KEY_VALUE should be \'KEY:VALUE\'')
            auth_cookie_key, auth_cookie_value = auth_cookie_key_value.split(':')
            if self.is_cookie_equals(auth_cookie_key, auth_cookie_value):
                return defer.succeed(credentials.username)
        # check for the ip-address
        whitelisted_ips = os.getenv("WHITELISTED_IPS")
        if whitelisted_ips is not None:
            whitelisted_ips = whitelisted_ips.split(',')
            if self.is_ip_in_white_list(whitelisted_ips):
                return defer.succeed(credentials.username)
        # credentials.username and credentials.password - what you entered
        if credentials.username == self.username and credentials.password == self.password:
            return defer.succeed(credentials.username)
        else:
            return defer.fail(error.UnauthorizedLogin())

    def is_cookie_equals(
            self,
            config_auth_cookie_key: str,
            config_auth_cookie_value: str
    ):
        ...

    def is_ip_in_white_list(
            self,
            ip_white_list: list
    ):
        ...
