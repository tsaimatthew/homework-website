from django.utils import timezone

from paho.mqtt import client as mqtt_client
from .models import Device, RfidAction, TemperatureReading
from datetime import datetime
import os
import sys
from random import randint
# import logging

sys.path.append('..')
from django.conf import settings

# logger = logging.getLogger(__name__)

# Generate a Client ID with the subscribe prefix.
client_id = f'HWAPPServer-{randint(0, 100)}'

def connect_mqtt(client_id=client_id):
    client = mqtt_client.Client(client_id)
    client.tls_set(
        ca_certs=os.path.join(settings.BASE_DIR, "envMonitor", "keys", "rootCA.pem"),
        certfile=os.path.join(settings.BASE_DIR, "envMonitor", "keys", "client.crt"),
        keyfile=os.path.join(settings.BASE_DIR, "envMonitor", "keys", "client.key")
    )
    client.tls_insecure_set(False)
    client.connect("mqtt.matthewtsai.uk", 1883)
    return client

def store(msg):

    macAddr, subtopic = str(msg.topic).split("/", 1)
    payload = round(float(msg.payload.decode()), 3)
    # print(macAddr)
    # print(subtopic)
    # print(payload)
    try:
        dev = Device.objects.get(macAddr = macAddr)
    except Device.DoesNotExist:
        print("Device not registered")
        return False
    except Device.MultipleObjectsReturned:
        print("Too many devices added under the same MAC address. Please remove one")
        return False
    match subtopic:
        case "temperature":
            t = TemperatureReading.objects.create(device=dev, temperature=payload, date=timezone.now())
            print(t.temperature)

def topicsGen():
    ret = []
    allDevs = Device.objects.filter(active=True)
    for dev in allDevs:
        for topic in ["temperature", "rfid", "pressure", "humidity", "system"]:
            ret.append(f"{dev.macAddr}/{topic}")
    return ret

def subscribe(topic, client):
    def on_message(client, userdata, msg):
        store(msg)
    client.subscribe(topic)
    client.on_message = on_message

def run():

    client = connect_mqtt()
    topics = topicsGen()
    for topic in topics:
        subscribe(topic, client)
    client.loop_forever()


def publish(client, topic, message):
    client.publish(topic, message)