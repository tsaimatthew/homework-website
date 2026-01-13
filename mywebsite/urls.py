"""mywebsite URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.http.response import Http404
from django.urls import path, include
admin.site.site_header = 'Homework App Dashboard'
admin.site.site_title  =  "Homework App Dashboard"
admin.site.index_title  =  "User Data"
def redirect_404(request):
    raise Http404
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('hwapp.urls')),
    path('integrations/', include('integrations.urls')),
    path('home/', include('external.urls')),
    path('spotify/', include('spotify.urls')),
    path('environment/', include('envMonitor.urls'))
]




