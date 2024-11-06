from django.db.models.signals import post_migrate
from django.dispatch import receiver
import logging

logger = logging.getLogger(__name__)


@receiver(post_migrate)
def post_migration_callback(sender, **kwargs):
    logger.info("post_migrate signal received. Running initialization tasks.")

    # Import your services here to avoid circular imports
    from accounts.services.ma_abe_service import MAABEService
    from accounts.services.user_service import (
        patients_are_init,
        __patients_init,
        authority_reps_are_init,
        __auth_reps_init,
        patient_reps_are_init,
        __assign_auth_reps_to_patients,
    )

    MAABEService() # init auth and parameters

    # Initialize data if necessary
    if not patients_are_init():
        __patients_init()
        logger.info("Patients initialized.")
    if not authority_reps_are_init():
        __auth_reps_init()
        logger.info("Authority reps initialized.")
    if not patient_reps_are_init():
        __assign_auth_reps_to_patients()
        logger.info("Patient reps assigned to authorities.")