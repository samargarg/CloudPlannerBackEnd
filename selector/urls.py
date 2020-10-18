from django.urls import path

from . import views

urlpatterns = [
    path("create_user/", views.GoogleCreateUser.as_view(), name="create_user"),
    path("list_files/", views.ListFiles.as_view(), name="list_files"),
]