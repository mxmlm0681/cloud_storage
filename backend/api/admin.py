from django.contrib import admin
from django.contrib.admin import site

from . import models

site.register(models.User, site=admin.site)
site.register(models.Storage, site=models.Storage)
