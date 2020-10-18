from googleapiclient import discovery
from httplib2 import Http
from oauth2client import file, client, tools

import google.oauth2.credentials
import google_auth_oauthlib.flow

SCOPES = (
        'https://www.googleapis.com/auth/drive.appdata',
        'https://www.googleapis.com/auth/drive.file',
        'https://www.googleapis.com/auth/drive.install',
        'https://www.googleapis.com/auth/drive.readonly.metadata',
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile'
    )
store = file.Storage('storage.json')
credentials = store.get()
if not credentials or credentials.invalid:
    flow = client.flow_from_clientsecrets('google_drive_api_client.json', SCOPES)
    # flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
    #     'path_to_directory/google_drive_api_client.json',
    #     scopes=SCOPES)

    # flow.redirect_uri = 'https://localhost:8000/oauth2callback'
    credentials = tools.run_flow(flow, store)



