"""Removes all messages from the inbox.

Largely forked from https://developers.google.com/gmail/api/auth/web-server
Copyright Google, Inc. 2016. under Apache 2 licence.
"""
import os
import json
import logging

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from apiclient.discovery import build
from apiclient.discovery import build
from apiclient import errors

import httplib2



# Path to client_secrets.json which should contain a JSON document such as:
#   {
#     "web": {
#       "client_id": "[[YOUR_CLIENT_ID]]",
#       "client_secret": "[[YOUR_CLIENT_SECRET]]",
#       "redirect_uris": [],
#       "auth_uri": "https://accounts.google.com/o/oauth2/auth",
#       "token_uri": "https://accounts.google.com/o/oauth2/token"
#     }
#   }
CLIENTSECRETS_LOCATION = os.path.join(os.path.dirname(__file__), 'cred.json')
REDIRECT_URI = 'http://localhost:4567'
SCOPES = [
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.labels',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
]

class GetCredentialsException(Exception):
    """Error raised when an error occurred while retrieving credentials.

    Attributes:
    authorization_url: Authorization URL to redirect the user to in order to
                        request offline access.
    """

    def __init__(self, authorization_url):
        """Construct a GetCredentialsException."""
        self.authorization_url = authorization_url


class CodeExchangeException(GetCredentialsException):
    """Error raised when a code exchange has failed."""


class NoRefreshTokenException(GetCredentialsException):
    """Error raised when no refresh token has been found."""


class NoUserIdException(Exception):
    """Error raised when no user ID could be retrieved."""



def exchange_code(authorization_code):
    """Exchange an authorization code for OAuth 2.0 credentials.

    Args:
        authorization_code: Authorization code to exchange for OAuth 2.0
                            credentials.
    Returns:
        oauth2client.client.OAuth2Credentials instance.
    Raises:
        CodeExchangeException: an error occurred.
    """
    flow = flow_from_clientsecrets(CLIENTSECRETS_LOCATION, ' '.join(SCOPES))
    flow.redirect_uri = REDIRECT_URI
    try:
        credentials = flow.step2_exchange(authorization_code)
        return credentials
    except FlowExchangeError, error:
        logging.error('An error occurred: %s', error)
        raise CodeExchangeException(None)


def get_user_info(credentials):
    """Send a request to the UserInfo API to retrieve the user's information.

    Args:
        credentials: oauth2client.client.OAuth2Credentials instance to authorize the
                    request.
    Returns:
        User information as a dict.
    """
    user_info_service = build(
        serviceName='oauth2', version='v2',
        http=credentials.authorize(httplib2.Http()))
    user_info = None
    try:
        user_info = user_info_service.userinfo().get().execute()
    except errors.HttpError, e:
        logging.error('An error occurred: %s', e)
    if user_info and user_info.get('id'):
        return user_info
    else:
        raise NoUserIdException()


def get_authorization_url(email_address, state):
    """Retrieve the authorization URL.

    Args:
        email_address: User's e-mail address.
        state: State for the authorization URL.
    Returns:
        Authorization URL to redirect the user to.
    """
    flow = flow_from_clientsecrets(CLIENTSECRETS_LOCATION, ' '.join(SCOPES))
    flow.params['access_type'] = 'offline'
    flow.params['approval_prompt'] = 'force'
    flow.params['user_id'] = email_address
    flow.params['state'] = state
    return flow.step1_get_authorize_url(REDIRECT_URI)


def get_credentials(authorization_code, state):
    """Retrieve credentials using the provided authorization code.

    This function exchanges the authorization code for an access token and queries
    the UserInfo API to retrieve the user's e-mail address.
    If a refresh token has been retrieved along with an access token, it is stored
    in the application database using the user's e-mail address as key.
    If no refresh token has been retrieved, the function checks in the application
    database for one and returns it if found or raises a NoRefreshTokenException
    with the authorization URL to redirect the user to.

    Args:
        authorization_code: Authorization code to use to retrieve an access token.
        state: State to set to the authorization URL in case of error.
    Returns:
        oauth2client.client.OAuth2Credentials instance containing an access and
        refresh token.
    Raises:
        CodeExchangeError: Could not exchange the authorization code.
        NoRefreshTokenException: No refresh token could be retrieved from the
                                 available sources.
    """
    email_address = ''
    try:
        credentials = exchange_code(authorization_code)
        user_info = get_user_info(credentials)
        email_address = user_info.get('email')
        user_id = user_info.get('id')
        if credentials.refresh_token is not None:
            #store_credentials(user_id, credentials)
            return credentials
        else:
            #credentials = get_stored_credentials(user_id)
            if credentials and credentials.refresh_token is not None:
                return credentials
    except CodeExchangeException, error:
        logging.error('An error occurred during code exchange.')
        # Drive apps should try to retrieve the user and credentials for the current
        # session.
        # If none is available, redirect the user to the authorization URL.
        error.authorization_url = get_authorization_url(email_address, state)
        raise error
    except NoUserIdException:
        logging.error('No user ID could be retrieved.')
    # No refresh token has been retrieved.
    authorization_url = get_authorization_url(email_address, state)
    raise NoRefreshTokenException(authorization_url)


def update_thread_labels(service, user_id):
    """Updates the lables in a thread.

    Args:
        service: Authorized Gmail API service instance.
        user_id: User's email address. The special value "me"
        can be used to indicate the authenticated user.
        thread_id: The id of the thread to be modified.
    msg_labels: The change in labels.

    Returns:
        Thread with modified Labels.
    """
    query = 'in:inbox'
    try:
        response = service.users().threads().list(userId=user_id, q=query).execute()
        threads = []
        if 'threads' in response:
            threads.extend(response['threads'])

        while 'nextPageToken' in response:
            page_token = response['nextPageToken']
            response = service.users().threads().list(userId=user_id, q=query,
                                                      pageToken=page_token).execute()
            threads.extend(response['threads'])
        print(threads)

        #thread = service.users().threads().modify(userId=user_id, id=thread_id,
        #                                      body=msg_labels).execute()
        #thread_id = thread['id']
        #label_ids = thread['messages'][0]['labelIds']

        #print 'Thread ID: %s - With Label IDs %s' % (thread_id, label_ids)
        #return thread
    except errors.HttpError, error:
        print 'An error occurred: %s' % error


#def CreateMsgLabels():
#  """Create object to update labels.
#
#  Returns:
#    A label update object.
#  """
#  return {'removeLabelIds': [], 'addLabelIds': ['UNREAD', 'Label_2']}


def gmail_service(credentials):
    """Creates an Inbox / GMail service."""
    http = httplib2.Http()
    http = credentials.authorize(http)
    return build('gmail', 'v1', http=http)


def main(args):
    credentials = get_credentials()
    service = gmail_service(credentials)
    user_info = get_user_info(credentials)
    user_id = user_info.get('id')
    update_thread_labels(service, user_id)



if __name__ == '__main__':
    main()
