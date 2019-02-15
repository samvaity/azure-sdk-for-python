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


class FacialHair(Model):
    """Properties describing facial hair attributes.

    :param moustache:
    :type moustache: float
    :param beard:
    :type beard: float
    :param sideburns:
    :type sideburns: float
    """

    _attribute_map = {
        'moustache': {'key': 'moustache', 'type': 'float'},
        'beard': {'key': 'beard', 'type': 'float'},
        'sideburns': {'key': 'sideburns', 'type': 'float'},
    }

    def __init__(self, *, moustache: float=None, beard: float=None, sideburns: float=None, **kwargs) -> None:
        super(FacialHair, self).__init__(**kwargs)
        self.moustache = moustache
        self.beard = beard
        self.sideburns = sideburns
