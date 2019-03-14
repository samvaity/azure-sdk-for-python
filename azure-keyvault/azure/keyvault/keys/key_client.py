from typing import Optional
import uuid

from .models import (
    Attributes,
    DeletedKey,
    JsonWebKey,
    Key,
    KeyAttributes,
    KeyCreateParameters,
    KeyItem,
    KeyItemPaged,
)
from azure.core.configuration import Configuration
from azure.core.exceptions import ClientRequestError
from azure.core.pipeline import Pipeline
from azure.core.pipeline.policies import (
    HTTPPolicy,
    UserAgentPolicy,
    HeadersPolicy,
    RetryPolicy,
    RedirectPolicy,
    ContentDecodePolicy,
)
from azure.core.pipeline.transport import RequestsTransport, HttpRequest
from msrest import Serializer, Deserializer


class BearerTokenCredentialPolicy(HTTPPolicy):
    def __init__(self, credentials):
        self._credentials = credentials

    def send(self, request, **kwargs):
        auth_header = "Bearer " + self._credentials.token["access_token"]
        request.http_request.headers["Authorization"] = auth_header

        return self.next.send(request, **kwargs)


class KeyClient:
    API_VERSION = "7.0"

    @staticmethod
    def create_config(**kwargs):
        config = Configuration(**kwargs)
        config.user_agent = UserAgentPolicy("KeyClient", **kwargs)
        headers = {"x-ms-client-request-id": str(uuid.uuid1())}
        config.headers = HeadersPolicy(headers)
        config.retry = RetryPolicy(**kwargs)
        config.redirect = RedirectPolicy(**kwargs)
        config.verify = config.timeout = config.cert = None
        return config

    def __init__(self, vault_url, credentials, config=None, transport=None):
        self.vault_url = vault_url.strip("/")
        config = config or KeyClient.create_config()
        transport = RequestsTransport(config)
        policies = [
            config.user_agent,
            config.headers,
            BearerTokenCredentialPolicy(credentials),
            # ContentDecodePolicy(),
            config.redirect,
            config.retry,
            # config.logging, # TODO: no default logging policy
        ]
        self._pipeline = Pipeline(transport, policies=policies)
        models = {
            "Attributes": Attributes,
            "DeletedKey": DeletedKey,
            "JsonWebKey": JsonWebKey,
            "Key": Key,
            "KeyAttributes": KeyAttributes,
            "KeyCreateParameters": KeyCreateParameters,
            "KeyItem": KeyItem,
            "KeyItemPaged": KeyItemPaged,
        }
        self._deserialize = Deserializer(models)
        self._serialize = Serializer(models)

    def backup_key(self, name, **kwargs):
        pass

    def create_key(
        self,
        name,
        key_type,
        size=None,
        key_ops=None,
        attributes=None,
        tags=None,
        curve=None,
        **kwargs,
    ):
        url = "/".join([self.vault_url, "keys", name, "create"])
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "x-ms-client-request-id": str(uuid.uuid1()),
        }
        create_params = KeyCreateParameters(
            kty=key_type,
            key_size=size,
            key_ops=key_ops,
            key_attributes=attributes,
            tags=tags,
            curve=curve,
            **kwargs,
        )
        body = self._serialize.body(create_params, "KeyCreateParameters")
        request = HttpRequest("POST", url, headers, data=body)
        request.format_parameters({"api-version": self.API_VERSION})

        response = self._pipeline.run(request, **kwargs).http_response
        if response.status_code != 200:
            raise ClientRequestError(
                "Request failed with code {}: '{}'".format(
                    response.status_code, response.text()
                )
            )

        key = self._deserialize("Key", response)

        return key

    def delete_key(self, name, **kwargs):
        url = "/".join([self.vault_url, "keys", name])

        request = HttpRequest("DELETE", url)
        request.format_parameters({"api-version": self.API_VERSION})
        response = self._pipeline.run(request, **kwargs)

        bundle = self._deserialize("DeletedKey", response.http_response)

        return bundle

    def get_key(self, name, version="", **kwargs):
        # type: (str, str, **bool) -> Key
        """Gets the public part of a stored key.

        The get key operation is applicable to all key types. If the requested
        key is symmetric, then no key material is released in the response.
        This operation requires the keys/get permission.

        :param name: The name of the key to get.
        :type name: str
        :param version: Adding the version parameter retrieves a specific
         version of the key.
        :type version: str
        :return: Key
        :rtype: ~azure.keyvault.keys.Key
        """
        url = "/".join([self.vault_url, "keys", name, version])

        request = HttpRequest("GET", url)
        request.format_parameters({"api-version": self.API_VERSION})
        response = self._pipeline.run(request, **kwargs)

        key = self._deserialize("Key", response.http_response)

        return key

    def get_deleted_key(self, name, **kwargs):
        pass

    def get_all_deleted_keys(self, maxresults=None, **kwargs):
        pass

    def get_all_keys(self, max_page_size=None, **kwargs):
        # type: (Optional[int], **bool) -> KeyItemPaged

        def internal_paging(next_link=None, raw=False):
            if not next_link:
                url = "{}/{}".format(self.vault_url, "keys")
                query_parameters = {"api-version": self.API_VERSION}
                if max_page_size is not None:
                    query_parameters["maxresults"] = str(max_page_size)
            else:
                url = next_link
                query_parameters = {}

            headers = {
                "Content-Type": "application/json; charset=utf-8",
                "x-ms-client-request-id": str(uuid.uuid1()),
            }

            request = HttpRequest("GET", url, headers)
            request.format_parameters(query_parameters)

            response = self._pipeline.run(request, **kwargs).http_response

            if response.status_code != 200:
                raise ClientRequestError(
                    "Request failed with code {}: '{}'".format(
                        response.status_code, response.text()
                    )
                )

            return response

        return KeyItemPaged(internal_paging, self._deserialize.dependencies)

    def get_key_versions(self, name, maxresults=None, **kwargs):
        pass

    def import_key(self, name, key, hsm=None, attributes=None, tags=None, **kwargs):
        pass

    def purge_deleted_key(self, name, **kwargs):
        pass

    def recover_deleted_key(self, name, **kwargs):
        pass

    def restore_key(self, key_bundle_backup, **kwargs):
        pass

    # def unwrap_key(self, name, version, algorithm, value, **kwargs):
    #     pass

    def update_key(
        self, name, version, key_ops=None, attributes=None, tags=None, **kwargs
    ):
        pass

    # def wrap_key(self, name, version, algorithm, value, **kwargs):
    #     pass
