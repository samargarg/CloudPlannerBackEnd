from __future__ import print_function

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.utils import json
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

import os
from pydrive.drive import GoogleDrive
from pydrive.auth import GoogleAuth
from oauth2client.client import OAuth2Credentials

import requests
from . import models
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.models import User
from dateutil import parser

from googleapiclient import discovery
from httplib2 import Http
from oauth2client import file, client, tools

import google.oauth2.credentials
import google_auth_oauthlib.flow


client_id = "1046798208571-l1qrn714dgs9gfk7786frl1v3ak8hreh.apps.googleusercontent.com"
client_secret = "WvlS-OdA9mnl9cB0c9sfwlYv"

def get_access_token(refresh_token):
    params = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token
    }

    authorization_url = "https://oauth2.googleapis.com/token"

    r = requests.post(authorization_url, data=params)

    if r.ok:
        print(r.json()['access_token'])
        return r.json()['access_token']
    else:
        print("None!")
        return None


class GoogleCreateUser(APIView):

    def post(self, request):
        access_token = get_access_token(request.data.get("refresh_token"))
        payload = {'access_token': access_token}
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
            user = User.objects.create_user(data['email'], data['email'])
            user.first_name = data['given_name']
            user.last_name = data['family_name']
            user.save()
            access_request_token = models.UserAuth(user=user,
                                                   access_token=access_token,
                                                   refresh_token=request.data.get("refresh_token"),
                                                   token_expiry=request.data.get("token_expiry"))
            access_request_token.save()
            token = Token.objects.create(user=user)

        response = {'username': user.username, 'first_name': user.first_name, 'last_name': user.last_name,
                    'email': user.email, 'token': token.key}

        if new_user:
            return_status = status.HTTP_201_CREATED
        else:
            return_status = status.HTTP_200_OK
        return Response(response, status=return_status)


def authenticate(request):
    user = Token.objects.get(key=request.auth.key).user
    tokens = models.UserAuth.objects.get(user=user)
    tokens.access_token = get_access_token(tokens.refresh_token)
    tokens.save()

    gauth = GoogleAuth()
    with open("storage.json") as f:
        gauth.credentials = OAuth2Credentials.from_json(json.dumps(
            {
                "access_token": tokens.access_token,
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": tokens.refresh_token,
                "token_expiry": str(tokens.token_expiry),
                "token_uri": "https://oauth2.googleapis.com/token",
                "user_agent": "null",
                "invalid": "false"
            }
        ))

    gauth.LocalWebserverAuth()
    drive = GoogleDrive(gauth)
    return drive


class ListFiles(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        drive = authenticate(request)

        files = drive.ListFile({'q': "'root' in parents and trashed=false"}).GetList()
        file_list = []
        for f in files:
            file_list.append({"id": f['id'], "name": f['title'], "type": f['mimeType']})

        return Response(file_list, status=status.HTTP_200_OK)


class UploadFiles(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        drive = authenticate(request)

        path = r"/Users/samargarg/Documents/Probability"

        for x in os.listdir(path):
            f = drive.CreateFile({'title': x})
            f.SetContentFile(os.path.join(path, x))
            f.Upload()

            f = None
        return Response(os.listdir(path), status=status.HTTP_200_OK)


class UpdateFolder(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        drive = authenticate(request)
        files = drive.ListFile({'q': "'root' in parents and trashed=false"}).GetList()
        default_app_folder_id = None
        for file in files:
            if file['title'] is "CloudPlanner":
                default_app_folder_id = file['id']
        if default_app_folder_id is None:
            default_app_folder = drive.CreateFile({'title': 'CloudPlanner',
                                                   'mimeType': "application/vnd.google-apps.folder"})
            default_app_folder.Upload()
            default_app_folder_id = default_app_folder['id']

        path = request.data.get('path')

        new_folder = drive.CreateFile({'title': path.split('/')[-1],
                                       'parents': [{'kind': "drive#fileLink", 'id': default_app_folder_id}],
                                       'mimeType': "application/vnd.google-apps.folder"})
        new_folder.Upload()

        for x in os.listdir(path):
            f = drive.CreateFile({'title': x,
                                  'parents': [{'id': new_folder['id']}]})
            f.SetContentFile(os.path.join(path, x))
            f.Upload()

            f = None
        return Response(new_folder, status=status.HTTP_200_OK)


def folder_browser(folder_list, parent_id):
    for element in folder_list:
        if type(element) is dict:
            print(element['title'])
        else:
            print(element)
            print("Enter Name of Folder You Want to Use OR Enter '/' to use current folder OR Enter ':' to create New Folder and use that")
            inp = input()

            if inp == '/':
                return parent_id
            elif inp == ':':
                print("Enter Name of Folder You Want to Create")
                inp = input()
                newfolder = create_folder(parent_id, inp)
                if not os.path.exists("HOME_DIRECTORY + ROOT_FOLDER_NAME + os.path.sep + USERNAME"):
                    os.makedirs("HOME_DIRECTORY + ROOT_FOLDER_NAME + os.path.sep + USERNAME")
                    return newfolder['id']

            else:
                folder_selected = inp
    for element in folder_list:
        if type(element) is dict:
            if element["title"] == folder_selected:
                struc = element["list"]
                browsed.append(folder_selected)
                print("Inside " + folder_selected)
                return folder_browser(struc,element['id'])














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