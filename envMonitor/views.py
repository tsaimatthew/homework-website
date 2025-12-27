from django.shortcuts import render, HttpResponseRedirect
from django.urls import reverse
from django.http.response import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone

import re
import json
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes

from .models import Device, TemperatureReading, HumidityReading, PressureReading
from .helper import DeviceSerializer, validateDevSerializer
# Create your views here.

def index(request):
    if len(Device.objects.filter(user=request.user)) > 0:
        return True
    else:
        return HttpResponseRedirect(reverse("addDevice"))

@csrf_exempt
def addDevice(request):
    if request.method == "GET":
        return render(request, "envMonitor/addDev.html")
    elif request.method == "POST":
        d = json.loads(request.body)
        if not validateDevSerializer(d):
            print(d)
            return JsonResponse({"Error": "Invalid request"})
        with open("envMonitor/keys/rootCA.key", "rb") as f:
            ca_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
        with open("envMonitor/keys/rootCA.pem", "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if not re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", d['macAddr'].lower()):
            return JsonResponse({"error": "Invalid MAC Address. Please format as aa:bb:cc:dd:ee:ff"}, status=400)
        macStripped = str(d['macAddr']).lower().replace(":", "")
        client_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{macStripped}")])
        client_cert = (
            x509.CertificateBuilder()
            .subject_name(client_subject)
            .issuer_name(ca_cert.subject)
            .public_key(client_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now())
            .not_valid_after(datetime.now() + timedelta(days=365))
            .sign(ca_key, hashes.SHA256())
        )
        client_cert_pem = client_cert.public_bytes(serialization.Encoding.PEM)
        client_key_pem = client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        # public_key = private_key.public_key().public_bytes(
        #     encoding=serialization.Encoding.PEM,
        #     format=serialization.PublicFormat.SubjectPublicKeyInfo
        # )
        # private_key = private_key.private_bytes(
        #     encoding=serialization.Encoding.DER,
        #     format=serialization.PrivateFormat.PKCS8,
        #     encryption_algorithm=serialization.NoEncryption()
        # )
        dev = Device(user=request.user, macAddr=macStripped, deviceName=d['deviceName'], \
                     location=d['location'], dateAdded=timezone.now(), private_key=client_key_pem.decode(), \
                        public_key=client_cert_pem.decode())
        dev.save()
        return JsonResponse(DeviceSerializer(dev))