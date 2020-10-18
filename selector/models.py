from django.db import models

class UserAuth(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    access_token = models.CharField(max_length=500, blank=True, null=True)
    refresh_token = models.CharField(max_length=500, blank=True, null=True)

    def __str__(self):
        return self.user.username
