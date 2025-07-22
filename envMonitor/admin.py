from django.contrib import admin
from .models import Device, TemperatureReading, RfidAction, PressureReading, HumidityReading
# Register your models here.
admin.site.register(Device)
admin.site.register(TemperatureReading)
admin.site.register(RfidAction)
admin.site.register(PressureReading)
admin.site.register(HumidityReading)

