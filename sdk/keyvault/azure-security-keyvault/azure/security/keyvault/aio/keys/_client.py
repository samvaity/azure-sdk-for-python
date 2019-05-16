# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE.txt in the project root for
# license information.
# --------------------------------------------------------------------------
from typing import Any, Mapping, Optional, AsyncGenerator, Dict

from azure.core.configuration import Configuration
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.core.pipeline.policies import UserAgentPolicy, AsyncRetryPolicy, AsyncRedirectPolicy
from azure.core.pipeline.transport import AsyncioRequestsTransport
from azure.core.pipeline import AsyncPipeline

from azure.keyvault._internal import _BearerTokenCredentialPolicy
from azure.keyvault._generated import KeyVaultClientAsync

from ...keys._models import Key, DeletedKey, KeyBase
from datetime import datetime

# TODO: update all returns and raises


class KeyClient:
    """The KeyClient class defines a high level interface for managing keys in the specified vault.

    :param credentials:  A credential or credential provider which can be used to authenticate to the vault,
        a ValueError will be raised if the entity is not provided
    :type credentials: azure.authentication.Credential or azure.authentication.CredentialProvider
    :param str vault_url: The url of the vault to which the client will connect,
        a ValueError will be raised if the entity is not provided
    :param ~azure.core.configuration.Configuration config:  The configuration for the KeyClient

    Example:
        .. literalinclude:: ../tests/test_examples_keys.py
            :start-after: [START create_key_client]
            :end-before: [END create_key_client]
            :language: python
            :dedent: 4
            :caption: Creates a new instance of the Key client
    """

    def __init__(self, vault_url: str, credentials: Any, config=None, api_version: Optional[str]=None, **kwargs: Optional[Mapping[str, Any]])-> None:
        if not credentials:
            raise ValueError("credentials")

        if not vault_url:
            raise ValueError("vault_url")

        self._vault_url = vault_url

        if api_version is None:
            api_version = KeyVaultClientAsync.DEFAULT_API_VERSION
        config = config or KeyVaultClientAsync.get_configuration_class(api_version)(credentials)

        # TODO generated default pipeline should be fine when token policy isn't necessary
        policies = [
            _BearerTokenCredentialPolicy(credentials),
            config.headers_policy,
            config.user_agent_policy,
            config.proxy_policy,
            config.redirect_policy,
            config.retry_policy,
            config.logging_policy,
        ]
        transport = AsyncioRequestsTransport(config)
        pipeline = AsyncPipeline(transport, policies=policies)

        self._client = KeyVaultClientAsync(credentials, api_version=api_version, pipeline=pipeline)

    @property
    def vault_url(self) -> str:
        return self._vault_url

    async def get_key(self, name: str, version: str, **kwargs: Mapping[str, Any]) -> Key:
        """Get a specified key from the vault.

        The GET operation is applicable to any key stored in Azure Key
        Vault. This operation requires the Keys/get permission.

        :param str name: The name of the Key.
        :param str version: The version of the Key. If version is None or an empty string, the latest version of
            the Key is returned.
        :returns: An instance of Key
        :rtype: ~azure.keyvault.Keys._models.Key
        :raises:
         :class:`KeyVaultErrorException<azure.keyvault.KeyVaultErrorException>`

        Example:
            .. literalinclude:: ../tests/test_examples_keys_async.py
                :start-after: [START get_Key]
                :end-before: [END get_Key]
                :language: python
                :dedent: 4
                :caption: Get Key from the key vault
        """
        bundle = await self._client.get_Key(self.vault_url, name, version, error_map={404: ResourceNotFoundError})
        return Key._from_key_bundle(bundle)

    async def create_key(
        self,
        name: str,
        key_type,
        size: Optional[int] = None,
        enabled: Optional[bool] = None,
        not_before: Optional[datetime] = None,
        expires: Optional[datetime] = None,
        tags: Optional[Dict[str, str]] = None,
        curve: Optional[str]=None,
        **kwargs: Mapping[str, Any]
    ) -> Key:
        """Creates a new key, stores it, then returns key attributes to the client.
        The create key operation can be used to create any key type in Azure
        Key Vault. If the named key already exists, Azure Key Vault creates a
        new version of the key. It requires the keys/create permission.
        :param name: The name for the new key. The system will generate
         the version name for the new key.
        :type name
        :param key_type: The type of key to create. For valid values, see
         JsonWebKeyType. Possible values include: 'EC', 'EC-HSM', 'RSA',
         'RSA-HSM', 'oct'
        :type key_type: str or ~azure.keyvault._generated.v7_0.models.JsonWebKeyType
        :param size: The key size in bits. For example: 2048, 3072, or
         4096 for RSA.
        :type size: int
        :param key_ops: Supported key operations.
        :type key_ops: list[str or
         ~~azure.keyvault._generated.v7_0.models.JsonWebKeyOperation]
        :param enabled: Determines whether the object is enabled.
        :type enabled: bool
        :param expires: Expiry date of the key  in UTC.
        :type expires: datetime.datetime
        :param not_before: Not before date of the key in UTC
        :type not_before: datetime.datetime
        :param tags: Application specific metadata in the form of key-value
         pairs.
        :type tags: Dict[str, str]
        :param curve: Elliptic curve name. For valid values, see
         JsonWebKeyCurveName. Possible values include: 'P-256', 'P-384',
         'P-521', 'SECP256K1'
        :type curve: str or
         ~~azure.keyvault._generated.v7_0.models.JsonWebKeyCurveName
        :returns: The created key
        :rtype: ~azure.keyvault.keys._models.Key
        :raises: ~azure.core.exceptions.ClientRequestError if the client failed to create the key
        Example:
            .. literalinclude:: ../tests/test_examples_keys_async.py
                :start-after: [START create_key]
                :end-before: [END create_key]
                :language: python
                :dedent: 4
                :caption: Creates a key in the key vault
        """
        if enabled is not None or not_before is not None or expires is not None:
            attributes = self._client.models.KeyBase(enabled=enabled, not_before=not_before, expires=expires)
        else:
            attributes = None
        bundle = await self._client.set_Key(
            self.vault_url, name, value, Key_attributes=attributes, content_type=content_type, tags=tags
        )
        return Key.from_Key_bundle(bundle)

    async def update_Key_attributes(
        self,
        name: str,
        version: str,
        content_type: Optional[str] = None,
        enabled: Optional[bool] = None,
        not_before: Optional[datetime] = None,
        expires: Optional[datetime] = None,
        tags: Optional[Dict[str, str]] = None,
        **kwargs: Mapping[str, Any]
    ) -> KeyBase:
        """Updates the attributes associated with a specified Key in the key vault.

        The UPDATE operation changes specified attributes of an existing stored Key.
        Attributes that are not specified in the request are left unchanged. The value
        of a Key itself cannot be changed. This operation requires the Keys/set permission.

        :param str name: The name of the Key
        :param str version: The version of the Key.
        :param str content_type: Type of the Key value such as a password
        :param enabled: Determines whether the object is enabled.
        :type enabled: bool
        :param not_before: Not before date of the Key  in UTC
        :type not_before: datetime.datetime
        :param expires: Expiry date  of the Key in UTC.
        :type expires: datetime.datetime
        :param tags: Application specific metadata in the form of key-value pairs.
        :type tags: dict(str, str)
        :returns: The created Key
        :rtype: ~azure.keyvault.Keys._models.KeyBase
        :raises: ~azure.core.exceptions.ClientRequestError if the client failed to create the Key

        Example:
            .. literalinclude:: ../tests/test_examples_keys_async_async.py
                :start-after: [START update_Key_attributes]
                :end-before: [END update_Key_attributes]
                :language: python
                :dedent: 4
                :caption: Updates the attributes associated with a specified Key in the key vault
        """
        if enabled is not None or not_before is not None or expires is not None:
            attributes = self._client.models.KeyBase(enabled=enabled, not_before=not_before, expires=expires)
        else:
            attributes = None
        bundle = await self._client.update_Key(
            self.vault_url,
            name,
            Key_version=version,
            content_type=content_type,
            tags=tags,
            Key_attributes=attributes,
            error_map={404: ResourceNotFoundError},
        )
        return KeyBase.from_Key_bundle(bundle)  # pylint: disable=protected-access

    async def list_Keys(self, **kwargs: Mapping[str, Any]) -> AsyncGenerator[KeyBase, None]:
        """List Keys in the vault.

        The Get Keys operation is applicable to the entire vault. However,
        only the latest Key identifier and its attributes are provided in the
        response. No Key values are returned and individual Key versions are
        not listed in the response.  This operation requires the Keys/list permission.

        :returns: An iterator like instance of Keys
        :rtype:
         typing.AsyncGenerator[~azure.keyvault.Keys._models.KeyBase]
        :raises:
         :class:`HttpRequestError<azure.core.HttpRequestError>`

        Example:
            .. literalinclude:: ../tests/test_examples_keys_async_async.py
                :start-after: [START list_Keys]
                :end-before: [END list_Keys]
                :language: python
                :dedent: 4
                :caption: Lists all the Keys in the vault
        """
        max_results = kwargs.get("max_page_size")
        pages = self._client.get_Keys(self.vault_url, maxresults=max_results)
        async for item in pages:
            yield KeyBase.from_Key_item(item)

    async def list_Key_versions(
        self, name: str, **kwargs: Mapping[str, Any]
    ) -> AsyncGenerator[KeyBase, None]:
        """List all versions of the specified Key.

        The full Key identifier and attributes are provided in the response.
        No values are returned for the Keys. This operation requires the
        Keys/list permission.

        :param str name: The name of the Key.
        :returns: An iterator like instance of Key
        :rtype:
         typing.AsyncGenerator[~azure.keyvault.Keys._models.KeyBase]
        :raises:
         :class:`HttpRequestError<azure.core.HttpRequestError>`

        Example:
        .. literalinclude:: ../tests/test_examples_keys_async_async.py
            :start-after: [START list_Key_versions]
            :end-before: [END list_Key_versions]
            :language: python
            :dedent: 4
            :caption: List all versions of the specified Key
        """
        max_results = kwargs.get("max_page_size")
        pages = self._client.get_Key_versions(self.vault_url, name, maxresults=max_results)
        async for item in pages:
            yield KeyBase.from_Key_item(item)

    async def backup_Key(self, name: str, **kwargs: Mapping[str, Any]) -> bytes:
        """Backs up the specified Key.

        Requests that a backup of the specified Key be downloaded to the
        client. All versions of the Key will be downloaded. This operation
        requires the Keys/backup permission.

        :param str name: The name of the Key.
        :returns: The raw bytes of the Key backup.
        :rtype: bytes
        :raises:
         :class:azure.core.HttpRequestError

         Example:
            .. literalinclude:: ../tests/test_examples_keys_async_async.py
                :start-after: [START backup_Key]
                :end-before: [END backup_Key]
                :language: python
                :dedent: 4
                :caption: Backs up the specified Key
        """
        backup_result = await self._client.backup_Key(self.vault_url, name, error_map={404: ResourceNotFoundError})
        return backup_result.value

    async def restore_Key(self, backup: bytes, **kwargs: Mapping[str, Any]) -> KeyBase:
        """Restores a backed up Key to a vault.

        Restores a backed up Key, and all its versions, to a vault. This
        operation requires the Keys/restore permission.

        :param bytes backup: The raw bytes of the Key backup
        :returns: The restored Key
        :rtype: ~azure.keyvault.Keys._models.KeyBase
        :raises:
         :class:azure.core.HttpRequestError

        Example:
            .. literalinclude:: ../tests/test_examples_keys_async_async.py
                :start-after: [START restore_Key]
                :end-before: [END restore_Key]
                :language: python
                :dedent: 4
                :caption: Restores a backed up Key to the vault
        """
        bundle = await self._client.restore_Key(self.vault_url, backup, error_map={409: ResourceExistsError})
        return KeyBase.from_Key_bundle(bundle)

    async def delete_Key(self, name: str, **kwargs: Mapping[str, Any]) -> DeletedKey:
        """Deletes a Key from the vault.

        The DELETE operation applies to any Key stored in Azure Key Vault.
        DELETE cannot be applied to an individual version of a Key. This
        operation requires the Keys/delete permission.

        :param str name: The name of the Key
        :returns: The deleted Key.
        :rtype: ~azure.keyvault.Keys._models.DeletedKey
        :raises: ~azure.core.exceptions.ClientRequestError, if client failed to delete the Key

        Example:
            .. literalinclude:: ../tests/test_examples_keys_async_async.py
                :start-after: [START delete_Key]
                :end-before: [END delete_Key]
                :language: python
                :dedent: 4
                :caption: Deletes a Key
        """
        bundle = await self._client.delete_Key(self.vault_url, name, error_map={404: ResourceNotFoundError})
        return DeletedKey.from_deleted_Key_bundle(bundle)

    async def get_deleted_Key(self, name: str, **kwargs: Mapping[str, Any]) -> DeletedKey:
        """Gets the specified deleted Key.

        The Get Deleted Key operation returns the specified deleted Key
        along with its attributes. This operation requires the Keys/get permission.

        :param str name: The name of the Key
        :returns: The deleted Key.
        :rtype: ~azure.keyvault.Keys._models.DeletedKey
        :raises: ~azure.core.exceptions.ClientRequestError, if client failed to get the deleted Key

        Example:
            .. literalinclude:: ../tests/test_examples_keys_async_async.py
                :start-after: [START get_deleted_Key]
                :end-before: [END get_deleted_Key]
                :language: python
                :dedent: 4
                :caption: Gets the deleted Key
        """
        bundle = await self._client.get_deleted_Key(self.vault_url, name, error_map={404: ResourceNotFoundError})
        return DeletedKey.from_deleted_Key_bundle(bundle)

    async def list_deleted_Keys(self, **kwargs: Mapping[str, Any]) -> AsyncGenerator[DeletedKey, None]:
        """Lists deleted Keys of the vault.

        The Get Deleted Keys operation returns the Keys that have
        been deleted for a vault enabled for soft-delete. This
        operation requires the Keys/list permission.

        :returns: An iterator like instance of DeletedKeys
        :rtype:
         typing.AsyncGenerator[~azure.keyvault.Keys._models.DeletedKey]

        Example:
            .. literalinclude:: ../tests/test_examples_keys_async_async.py
                :start-after: [START list_deleted_Keys]
                :end-before: [END list_deleted_Keys]
                :language: python
                :dedent: 4
                :caption: Lists the deleted Keys of the vault
        """
        max_results = kwargs.get("max_page_size")
        pages = self._client.get_deleted_Keys(self.vault_url, maxresults=max_results)
        async for item in pages:
            yield DeletedKey.from_deleted_Key_item(item)

    async def purge_deleted_Key(self, name: str, **kwargs: Mapping[str, Any]) -> None:
        """Permanently deletes the specified Key.

        The purge deleted Key operation removes the Key permanently, without the
        possibility of recovery. This operation can only be enabled on a soft-delete enabled
        vault. This operation requires the Keys/purge permission.

        :param str name: The name of the Key
        :returns: None
        :raises: ~azure.core.exceptions.ClientRequestError, if client failed to return the purged Key

        Example:
            .. literalinclude:: ../tests/test_examples_keys_async_async.py
                :start-after: [START purge_deleted_Key]
                :end-before: [END purge_deleted_Key]
                :language: python
                :dedent: 4
                :caption: Restores a backed up Key to the vault
        """
        await self._client.purge_deleted_Key(self.vault_url, name)

    async def recover_deleted_Key(self, name: str, **kwargs: Mapping[str, Any]) -> KeyBase:
        """Recovers the deleted Key to the latest version.

        Recovers the deleted Key in the specified vault.
        This operation can only be performed on a soft-delete enabled
        vault. This operation requires the Keys/recover permission.

        :param str name: The name of the Key
        :returns: The recovered deleted Key
        :rtype: ~azure.keyvault.Keys._models.KeyBase
        :raises: ~azure.core.exceptions.ClientRequestError, if client failed to recover the deleted Key

        Example:
            .. literalinclude:: ../tests/test_examples_keys_async_async.py
                :start-after: [START recover_deleted_Key]
                :end-before: [END recover_deleted_Key]
                :language: python
                :dedent: 4
                :caption: Restores a backed up Key to the vault
        """
        bundle = await self._client.recover_deleted_Key(self.vault_url, name)
        return KeyBase.from_Key_bundle(bundle)