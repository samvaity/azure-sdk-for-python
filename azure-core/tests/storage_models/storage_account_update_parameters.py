# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from azure.core.serialization import Model


class StorageAccountUpdateParameters(Model):
    """The parameters that can be provided when updating the storage account
    properties.

    :param sku: Gets or sets the SKU name. Note that the SKU name cannot be
     updated to Standard_ZRS or Premium_LRS, nor can accounts of those sku
     names be updated to any other value.
    :type sku: :class:`Sku <azure.mgmt.storage.v2016_12_01.models.Sku>`
    :param tags: Gets or sets a list of key value pairs that describe the
     resource. These tags can be used in viewing and grouping this resource
     (across resource groups). A maximum of 15 tags can be provided for a
     resource. Each tag must have a key no greater in length than 128
     characters and a value no greater in length than 256 characters.
    :type tags: dict
    :param custom_domain: Custom domain assigned to the storage account by the
     user. Name is the CNAME source. Only one custom domain is supported per
     storage account at this time. To clear the existing custom domain, use an
     empty string for the custom domain name property.
    :type custom_domain: :class:`CustomDomain
     <azure.mgmt.storage.v2016_12_01.models.CustomDomain>`
    :param encryption: Provides the encryption settings on the account. The
     default setting is unencrypted.
    :type encryption: :class:`Encryption
     <azure.mgmt.storage.v2016_12_01.models.Encryption>`
    :param access_tier: Required for storage accounts where kind =
     BlobStorage. The access tier used for billing. Possible values include:
     'Hot', 'Cool'
    :type access_tier: str or :class:`AccessTier
     <azure.mgmt.storage.v2016_12_01.models.AccessTier>`
    :param enable_https_traffic_only: Allows https traffic only to storage
     service if sets to true. Default value: False .
    :type enable_https_traffic_only: bool
    """

    _attribute_map = {
        'sku': {'key': 'sku', 'type': 'Sku'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'custom_domain': {'key': 'properties.customDomain', 'type': 'CustomDomain'},
        'encryption': {'key': 'properties.encryption', 'type': 'Encryption'},
        'access_tier': {'key': 'properties.accessTier', 'type': 'AccessTier'},
        'enable_https_traffic_only': {'key': 'properties.supportsHttpsTrafficOnly', 'type': 'bool'},
    }

    def __init__(self, sku=None, tags=None, custom_domain=None, encryption=None, access_tier=None, enable_https_traffic_only=False):
        self.sku = sku
        self.tags = tags
        self.custom_domain = custom_domain
        self.encryption = encryption
        self.access_tier = access_tier
        self.enable_https_traffic_only = enable_https_traffic_only
