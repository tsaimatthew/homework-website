from django.db import models

# Create your models here.
class Device(models.Model):
    user = models.ForeignKey('hwapp.User', on_delete=models.CASCADE)
    macAddr = models.CharField(max_length = 18)
    deviceName = models.CharField(max_length=28)
    location = models.CharField(max_length = 30)
    dateAdded = models.DateTimeField()
    public_key = models.TextField()
    private_key = models.TextField()
    active = models.BooleanField(default=True, null=True, blank=True)
    def __str__(self):
        return f"{self.deviceName}"

class RfidAction(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    action = models.CharField(max_length=30, choices=(("webhook", "webhook"), ("custom", "custom")))
    data = models.TextField()

class TemperatureReading(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    temperature = models.IntegerField()
    date = models.DateTimeField()
    unit = models.CharField(max_length=11 ,choices=(("Celsius","Celsius"), ("Fahrenheit", "Fahrenheit")))

class PressureReading(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    pressure = models.IntegerField()
    date = models.DateTimeField()

class HumidityReading(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    humidity = models.IntegerField()
    date = models.DateTimeField()