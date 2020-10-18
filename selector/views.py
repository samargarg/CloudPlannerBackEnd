from __future__ import print_function

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.utils import json
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

import requests
from . import models
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.models import User

from googleapiclient import discovery
from httplib2 import Http
from oauth2client import file, client, tools

import google.oauth2.credentials
import google_auth_oauthlib.flow


def refreshToken(refresh_token):
    client_id = "1046798208571-l1qrn714dgs9gfk7786frl1v3ak8hreh.apps.googleusercontent.com"
    client_secret = "WvlS-OdA9mnl9cB0c9sfwlYv"
    params = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token
    }

    authorization_url = "https://www.googleapis.com/oauth2/v4/token"

    r = requests.post(authorization_url, data=params)

    if r.ok:
        return r.json()['access_token']
    else:
        return None


class GoogleCreateUser(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        payload = {'access_token': request.data.get("access_token")}
        r = requests.get('https://www.googleapis.com/oauth2/v2/userinfo', params=payload)
        data = json.loads(r.text)

        if 'error' in data:
            content = {'message': 'Invalid Token!'}
            return Response(content, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=data['email'])
            token = Token.objects.get(user=user)
            new_user = False
        except User.DoesNotExist:
            new_user = True
            user = User.objects.create_user(data['given_name'], data['email'])
            user.first_name = data['given_name']
            user.last_name = data['family_name']
            user.save()
            access_request_token = models.UserAuth(user=user, access_token=request.data.get("access_token"),
                                                   refresh_token=request.data.get("refresh_token"))
            access_request_token.save()
            token = Token.objects.create(user=user)

        response = {'username': user.username, 'first_name': user.first_name, 'last_name': user.last_name,
                    'email': user.email, 'token': token.key}

        if new_user:
            return_status = status.HTTP_201_CREATED
        else:
            return_status = status.HTTP_200_OK
        return Response(response, status=return_status)


class ListFiles(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = Token.objects.get(key=request.auth.key).user
        tokens = models.UserAuth.objects.get(user=user)
        tokens.access_token = refreshToken(tokens.refresh_token)
        tokens.save()
        credentials = google.oauth2.credentials.Credentials(tokens.access_token)
        DRIVE = discovery.build('drive', 'v3', credentials=credentials)

        files = DRIVE.files().list().execute().get('files', [])
        file_list = []
        for f in files:
            file_list.append({"name": f['name'], "type": f['mimeType']})

        return JsonResponse(file_list, status=status.HTTP_200_OK, safe=False)















def get_credentials():
    store = file.Storage('storage.json')
    credentials = store.get()
    return credentials


def get_user_consent(request):
    SCOPES = (
        'https://www.googleapis.com/auth/drive.appdata',
        'https://www.googleapis.com/auth/drive.file',
        'https://www.googleapis.com/auth/drive.install',
        'https://www.googleapis.com/auth/drive.readonly.metadata'
    )
    store = file.Storage('storage.json')
    credentials = store.get()
    if not credentials or credentials.invalid:
        # flow = client.flow_from_clientsecrets('google_drive_api_client.json', SCOPES)
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            'path_to_directory/google_drive_api_client.json',
            scopes=SCOPES)

        flow.redirect_uri = 'https://localhost:8000/oauth2callback'
        credentials = tools.run_flow(flow, store)

    return HttpResponse(credentials, status=status.HTTP_201_CREATED)


def list_files(request):
    credentials = get_credentials()
    HTTP = credentials.authorize(Http())
    DRIVE = discovery.build('drive', 'v3', http=HTTP)

    files = DRIVE.files().list().execute().get('files', [])
    file_list = []
    for f in files:
        file_list.append({"name": f['name'], "type": f['mimeType']})

    return JsonResponse(file_list, status=status.HTTP_200_OK, safe=False)

# from googleapiclient.discovery import build
#
# with build('drive', 'v3') as service:
#     collection = service.stamps
#     nested_collection = service.featured().stamps()
#     request = collection.list(cents=5)
#     response = request.execute()