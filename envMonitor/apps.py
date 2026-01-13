from django.apps import AppConfig
import threading


class EnvmonitorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'envMonitor'
    mqtt_thread = None
    mqtt_thread_lock = threading.Lock()

    def ready(self):
        # Only start the MQTT thread once using a singleton pattern
        # This prevents multiple threads from being created during app reloads
        with self.mqtt_thread_lock:
            if EnvmonitorConfig.mqtt_thread is None:
                from .mqtt import run
                EnvmonitorConfig.mqtt_thread = threading.Thread(
                    target=run, 
                    name="MQTT_Subscribe", 
                    daemon=True
                )
                EnvmonitorConfig.mqtt_thread.start()
