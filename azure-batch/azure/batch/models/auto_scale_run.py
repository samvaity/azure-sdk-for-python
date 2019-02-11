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


class AutoScaleRun(Model):
    """The results and errors from an execution of a pool autoscale formula.

    All required parameters must be populated in order to send to Azure.

    :param timestamp: Required. The time at which the autoscale formula was
     last evaluated.
    :type timestamp: datetime
    :param results: The final values of all variables used in the evaluation
     of the autoscale formula. Each variable value is returned in the form
     $variable=value, and variables are separated by semicolons.
    :type results: str
    :param error: Details of the error encountered evaluating the autoscale
     formula on the pool, if the evaluation was unsuccessful.
    :type error: ~azure.batch.models.AutoScaleRunError
    """

    _validation = {
        'timestamp': {'required': True},
    }

    _attribute_map = {
        'timestamp': {'key': 'timestamp', 'type': 'iso-8601'},
        'results': {'key': 'results', 'type': 'str'},
        'error': {'key': 'error', 'type': 'AutoScaleRunError'},
    }

    def __init__(self, **kwargs):
        super(AutoScaleRun, self).__init__(**kwargs)
        self.timestamp = kwargs.get('timestamp', None)
        self.results = kwargs.get('results', None)
        self.error = kwargs.get('error', None)