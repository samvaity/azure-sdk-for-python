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

from msrest.serialization import Model


class SyncActivityStatus(Model):
    """Sync Session status object.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar timestamp: Required. Timestamp when properties were updated
    :vartype timestamp: datetime
    :ivar per_item_error_count: Required. Per item error count
    :vartype per_item_error_count: long
    :ivar applied_item_count: Required. Applied item count.
    :vartype applied_item_count: long
    :ivar total_item_count: Total item count (if available)
    :vartype total_item_count: long
    :ivar applied_bytes: Required. Applied bytes
    :vartype applied_bytes: long
    :ivar total_bytes: Total bytes (if available)
    :vartype total_bytes: long
    """

    _validation = {
        'timestamp': {'required': True, 'readonly': True},
        'per_item_error_count': {'required': True, 'readonly': True},
        'applied_item_count': {'required': True, 'readonly': True},
        'total_item_count': {'readonly': True},
        'applied_bytes': {'required': True, 'readonly': True},
        'total_bytes': {'readonly': True},
    }

    _attribute_map = {
        'timestamp': {'key': 'timestamp', 'type': 'iso-8601'},
        'per_item_error_count': {'key': 'perItemErrorCount', 'type': 'long'},
        'applied_item_count': {'key': 'appliedItemCount', 'type': 'long'},
        'total_item_count': {'key': 'totalItemCount', 'type': 'long'},
        'applied_bytes': {'key': 'appliedBytes', 'type': 'long'},
        'total_bytes': {'key': 'totalBytes', 'type': 'long'},
    }

    def __init__(self, **kwargs):
        super(SyncActivityStatus, self).__init__(**kwargs)
        self.timestamp = None
        self.per_item_error_count = None
        self.applied_item_count = None
        self.total_item_count = None
        self.applied_bytes = None
        self.total_bytes = None
