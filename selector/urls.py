from django.urls import path

from . import views

urlpatterns = [
    path("create_user/", views.GoogleCreateUser.as_view(), name="create_user"),
    path("list_files/", views.ListFiles.as_view(), name="list_files"),
    path("upload_files/", views.UploadFiles.as_view(), name="upload_files"),
    path("update_folder/", views.UpdateFolder.as_view(), name="update_folder")
]