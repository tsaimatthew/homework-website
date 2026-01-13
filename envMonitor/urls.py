from . import views
from django.urls import path, include

urlpatterns = [
    path("", views.index, name="env_index"),
    path("addDevice", views.addDevice, name="addDevice")
]
