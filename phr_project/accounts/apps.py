from django.apps import AppConfig
import logging

logger = logging.getLogger(__name__)

class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    def ready(self):
        # Import signals to register signal handlers
        try:
            import accounts.signals  # noqa: F401
            logger.info("Signals imported successfully.")
        except ImportError as e:
            logger.error(f"Failed to import signals: {e}")