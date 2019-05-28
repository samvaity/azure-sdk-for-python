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

from msrest.paging import Paged


class TaskPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Task <azure.mgmt.containerregistry.v2019_04_01.models.Task>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Task]'}
    }

    def __init__(self, *args, **kwargs):

        super(TaskPaged, self).__init__(*args, **kwargs)
