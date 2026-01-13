from .models import Device
import json

def DeviceSerializer(dev):
    ret = {}
    ret["user"] = dev.user.username
    ret["deviceName"] = dev.deviceName
    ret["private_key"] = dev.private_key
    ret["macAddr"] = dev.macAddr
    return ret

def validateDevSerializer(devJson):
    keys = ["macAddr", "deviceName", "location"]
    for key in keys:
        if key not in devJson.keys():
            return False
    return True