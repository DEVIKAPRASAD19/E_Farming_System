import six
from django.contrib.auth.tokens import PasswordResetTokenGenerator


class CustomPasswordResetTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk) + six.text_type(timestamp)
        )

custom_token_generator = CustomPasswordResetTokenGenerator()

