from django.db import models
from django.contrib.auth.models import User

class UserAuth(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="tokens")
    access_token = models.CharField(max_length=500, blank=True, null=True)
    refresh_token = models.CharField(max_length=500, blank=True, null=True)
    token_expiry = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.user.username
