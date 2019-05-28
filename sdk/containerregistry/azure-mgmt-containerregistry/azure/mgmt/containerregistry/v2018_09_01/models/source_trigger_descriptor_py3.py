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


class SourceTriggerDescriptor(Model):
    """The source trigger that caused a run.

    :param id: The unique ID of the trigger.
    :type id: str
    :param event_type: The event type of the trigger.
    :type event_type: str
    :param commit_id: The unique ID that identifies a commit.
    :type commit_id: str
    :param pull_request_id: The unique ID that identifies pull request.
    :type pull_request_id: str
    :param repository_url: The repository URL.
    :type repository_url: str
    :param branch_name: The branch name in the repository.
    :type branch_name: str
    :param provider_type: The source control provider type.
    :type provider_type: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'event_type': {'key': 'eventType', 'type': 'str'},
        'commit_id': {'key': 'commitId', 'type': 'str'},
        'pull_request_id': {'key': 'pullRequestId', 'type': 'str'},
        'repository_url': {'key': 'repositoryUrl', 'type': 'str'},
        'branch_name': {'key': 'branchName', 'type': 'str'},
        'provider_type': {'key': 'providerType', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, event_type: str=None, commit_id: str=None, pull_request_id: str=None, repository_url: str=None, branch_name: str=None, provider_type: str=None, **kwargs) -> None:
        super(SourceTriggerDescriptor, self).__init__(**kwargs)
        self.id = id
        self.event_type = event_type
        self.commit_id = commit_id
        self.pull_request_id = pull_request_id
        self.repository_url = repository_url
        self.branch_name = branch_name
        self.provider_type = provider_type
