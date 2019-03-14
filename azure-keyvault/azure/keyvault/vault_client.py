from .keys.key_client import KeyClient
from .secrets.secret_client import SecretClient


class VaultClient(object):

    def __init__(self, vault_url, credentials, config=None, **kwargs):
        self._keys = KeyClient(vault_url, credentials, config=config, **kwargs)
        self._secrets = SecretClient(vault_url, credentials, config=config, **kwargs)

    @property
    def secrets(self):
        """
        :rtype:`azure.security.keyvault.SecretClient`
        """
        return self._secrets

    @property
    def keys(self):
        """
        :rtype:`azure.security.keyvault.KeyClient`
        """
        return self._keys

    @property
    def certificates(self):
        """
        :rtype:`azure.security.keyvault.CertificateClient`
        """
        pass
