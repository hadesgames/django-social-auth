"""
Bitbucket OAuth support.

This adds support for Bitbucket OAuth service. An application must
be registered first on Bitbucket and the settings BITBUCKET_CONSUMER_KEY
and BITBUCKET_CONSUMER_SECRET must be defined with the corresponding
values.

By default username, email, token expiration time, first name and last name are
stored in extra_data field, check OAuthBackend class for details on how to
extend it.
"""

import pdb

from django.utils import simplejson
from social_auth.backends import ConsumerBasedOAuth, OAuthBackend, USERNAME
from urllib import urlopen
from social_auth.utils import setting

# Digg configuration
DIGG_SERVER = 'services.digg.com'
DIGG_REQUEST_TOKEN_URL = 'http://services.digg.com/oauth/request_token' 
DIGG_ACCESS_TOKEN_URL = 'http://services.digg.com/oauth/access_token'
DIGG_AUTHORIZATION_URL = 'http://digg.com/oauth/authenticate'
DIGG_PROFILE_URL = 'http://services.digg.com/2.0/user.getInfo'



class DiggBackend(OAuthBackend):
    """Digg OAuth authentication backend"""
    name = 'digg'
    EXTRA_DATA = [
        ('username', 'username'),
        ('expires', setting('SOCIAL_AUTH_EXPIRATION', 'expires')),
        ('email', 'email'),
    ]

    def get_user_details(self, response):
        """Return user details from Digg account"""
        user_data = response.get('user')
        return {USERNAME: user_data.get('username'),
                'email': user_data.get('email')}

    def get_user_id(self, details, response):
        """Return the user id """
        return response['user']['user_id']

    @classmethod
    def tokens(cls, instance):
        """Return the tokens needed to authenticate the access to any API the
        service might provide. Bitbucket uses a pair of OAuthToken consisting
        on a oauth_token and oauth_token_secret.

        instance must be a UserSocialAuth instance.
        """
        token = super(DiggBackend, cls).tokens(instance)
        if token and 'access_token' in token:
            token = dict(tok.split('=')
                            for tok in token['access_token'].split('&'))
        return token


class DiggAuth(ConsumerBasedOAuth):
    """Digg OAuth authentication mechanism"""
    AUTHORIZATION_URL = DIGG_AUTHORIZATION_URL
    REQUEST_TOKEN_URL = DIGG_REQUEST_TOKEN_URL
    ACCESS_TOKEN_URL = DIGG_ACCESS_TOKEN_URL
    SERVER_URL = DIGG_SERVER
    AUTH_BACKEND = DiggBackend
    SETTINGS_KEY_NAME = 'DIGG_CONSUMER_KEY'
    SETTINGS_SECRET_NAME = 'DIGG_CONSUMER_SECRET'

    def user_data(self, access_token):
        """Return user data provided"""
    
        url = DIGG_PROFILE_URL
        request = self.oauth_request(access_token, url)
        response = self.fetch_response(request)
        response = simplejson.loads(response)
        return response


# Backend definition
BACKENDS = {
    'digg': DiggAuth,
}
