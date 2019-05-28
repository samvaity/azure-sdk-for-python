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


class TriggerUpdateParameters(Model):
    """The properties for updating triggers.

    :param timer_triggers: The collection of timer triggers.
    :type timer_triggers:
     list[~azure.mgmt.containerregistry.v2019_05_01.models.TimerTriggerUpdateParameters]
    :param source_triggers: The collection of triggers based on source code
     repository.
    :type source_triggers:
     list[~azure.mgmt.containerregistry.v2019_05_01.models.SourceTriggerUpdateParameters]
    :param base_image_trigger: The trigger based on base image dependencies.
    :type base_image_trigger:
     ~azure.mgmt.containerregistry.v2019_05_01.models.BaseImageTriggerUpdateParameters
    """

    _attribute_map = {
        'timer_triggers': {'key': 'timerTriggers', 'type': '[TimerTriggerUpdateParameters]'},
        'source_triggers': {'key': 'sourceTriggers', 'type': '[SourceTriggerUpdateParameters]'},
        'base_image_trigger': {'key': 'baseImageTrigger', 'type': 'BaseImageTriggerUpdateParameters'},
    }

    def __init__(self, **kwargs):
        super(TriggerUpdateParameters, self).__init__(**kwargs)
        self.timer_triggers = kwargs.get('timer_triggers', None)
        self.source_triggers = kwargs.get('source_triggers', None)
        self.base_image_trigger = kwargs.get('base_image_trigger', None)
