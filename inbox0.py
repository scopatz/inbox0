"""Removes all messages from the inbox.

Largely forked from https://developers.google.com/gmail/api/auth/web-server
Copyright Google, Inc. 2016. under Apache 2 licence.
"""
import os
import json
import logging
from pprint import pprint

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
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
REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"
SCOPES = [
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.labels',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
]

from oauth2client.client import OAuth2WebServerFlow
from oauth2client.tools import run_flow
from oauth2client.file import Storage

CLIENT_ID = None
CLIENT_SECRET = None

def load_client_id_secret():
    global CLIENT_ID, CLIENT_SECRET
    with open('cred.json', 'r') as f:
        cred = json.load(f)
    CLIENT_ID = cred["web"]["client_id"]
    CLIENT_SECRET = cred["web"]["client_secret"]


def store_token():
    flow = OAuth2WebServerFlow(client_id=CLIENT_ID,
                               client_secret=CLIENT_SECRET,
                               scope=' '.join(SCOPES),
                               redirect_uri='http://example.com/auth_return')
    storage = Storage('creds.data')
    credentials = run_flow(flow, storage)
    print("access_token: %s" % credentials.access_token)
    return storage, credentials


def load_token():
    storage = Storage('creds.data')
    credentials = storage.get()
    return storage, credentials


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
    try:
        credentials = flow.step2_exchange(authorization_code)
        return credentials
    except FlowExchangeError as error:
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
    except errors.HttpError as e:
        logging.error('An error occurred: %s', e)
    if user_info and user_info.get('id'):
        return user_info
    else:
        raise NoUserIdException()


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
    labels = {'removeLabelIds': ['INBOX'], 'addLabelIds': []}
    # obtain threads
    threads = []
    try:
        response = service.users().threads().list(userId=user_id, q=query).execute()
    except errors.HttpError as error:
        print('An error occurred: {0}'.format(error))
    if 'threads' in response:
        threads.extend(response['threads'])
    while 'nextPageToken' in response:
        page_token = response['nextPageToken']
        try:
            response = service.users().threads().list(userId=user_id, q=query,
                                                      pageToken=page_token).execute()
        except errors.HttpError as error:
            print('An error occurred: {0}'.format(error))
        threads.extend(response['threads'])
    # remove from inbox
    for thread in threads:
        msg = "Archiving thread {id}: {snippet!r}".format(**thread)
        try:
            response = service.users().threads().modify(userId=user_id, id=thread['id'],
                                                        body=labels).execute()
        except errors.HttpError as error:
            print('An error occurred: {0}'.format(error))


def gmail_service(credentials):
    """Creates an Inbox / GMail service."""
    http = httplib2.Http()
    http = credentials.authorize(http)
    return build('gmail', 'v1', http=http)


def main(args=None):
    load_client_id_secret()
    if os.path.isfile('creds.data'):
        storage, credentials = load_token()
    else:
        storage, credentials = store_token()
    service = gmail_service(credentials)
    user_info = get_user_info(credentials)
    user_id = user_info.get('id')
    update_thread_labels(service, user_id)



if __name__ == '__main__':
    main()
