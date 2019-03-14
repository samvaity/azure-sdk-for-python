# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class SecretAttributes(Model):
    """The secret management attributes.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param enabled: Determines whether the object is enabled.
    :type enabled: bool
    :param not_before: Not before date in UTC.
    :type not_before: datetime
    :param expires: Expiry date in UTC.
    :type expires: datetime
    :ivar created: Creation time in UTC.
    :vartype created: datetime
    :ivar updated: Last updated time in UTC.
    :vartype updated: datetime
    :ivar recovery_level: Reflects the deletion recovery level currently in
     effect for secrets in the current vault. If it contains 'Purgeable', the
     secret can be permanently deleted by a privileged user; otherwise, only
     the system can purge the secret, at the end of the retention interval.
     Possible values include: 'Purgeable', 'Recoverable+Purgeable',
     'Recoverable', 'Recoverable+ProtectedSubscription'
    :vartype recovery_level: str or
     ~azure.keyvault.v7_0.models.DeletionRecoveryLevel
    """

    _validation = {
        'created': {'readonly': True},
        'updated': {'readonly': True},
        'recovery_level': {'readonly': True},
    }

    _attribute_map = {
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'not_before': {'key': 'nbf', 'type': 'unix-time'},
        'expires': {'key': 'exp', 'type': 'unix-time'},
        'created': {'key': 'created', 'type': 'unix-time'},
        'updated': {'key': 'updated', 'type': 'unix-time'},
        'recovery_level': {'key': 'recoveryLevel', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(SecretAttributes, self).__init__(**kwargs)
        self.enabled = kwargs.get('enabled', None)
        self.not_before = kwargs.get('not_before', None)
        self.expires = kwargs.get('expires', None)
        self.created = None
        self.updated = None
        self.recovery_level = None
