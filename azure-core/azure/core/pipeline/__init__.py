# --------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# --------------------------------------------------------------------------

import abc
import json
import logging
import os.path
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from .transport import HTTPSender
from .policies.base import HTTPPolicy, SansIOHTTPPolicy
from typing import TYPE_CHECKING, Generic, TypeVar, cast, IO, List, Union, Any, Mapping, Dict, Optional, Tuple, Callable, Iterator  # pylint: disable=unused-import

HTTPResponseType = TypeVar("HTTPResponseType")
HTTPRequestType = TypeVar("HTTPRequestType")

_LOGGER = logging.getLogger(__name__)

try:
    ABC = abc.ABC
except AttributeError: # Python 2.7, abc exists, but not ABC
    ABC = abc.ABCMeta('ABC', (object,), {'__slots__': ()})  # type: ignore

try:
    from contextlib import AbstractContextManager  # type: ignore
except ImportError: # Python <= 3.5
    class AbstractContextManager(object):  # type: ignore
        def __enter__(self):
            """Return `self` upon entering the runtime context."""
            return self

        @abc.abstractmethod
        def __exit__(self, exc_type, exc_value, traceback):
            """Raise any exception triggered within the runtime context."""
            return None


class _SansIOHTTPPolicyRunner(HTTPPolicy, Generic[HTTPRequestType, HTTPResponseType]):
    """Sync implementation of the SansIO policy.
    """

    def __init__(self, policy):
        # type: (SansIOHTTPPolicy) -> None
        super(_SansIOHTTPPolicyRunner, self).__init__()
        self._policy = policy

    def send(self, request, **kwargs):
        # type: (Request[HTTPRequestType], Any) -> Response[HTTPRequestType, HTTPResponseType]
        self._policy.on_request(request, **kwargs)
        try:
            response = self.next.send(request, **kwargs)
        except Exception:
            if not self._policy.on_exception(request, **kwargs):
                raise
        else:
            self._policy.on_response(request, response, **kwargs)
        return response


class _TransportRunner(HTTPPolicy):

    def __init__(self, sender):
        # type: (HTTPSender) -> None
        super(_TransportRunner, self).__init__()
        self._sender = sender

    def send(self, request, **kwargs):
        return Response(
            request,
            self._sender.send(request.http_request, **kwargs)
        )


class Pipeline(AbstractContextManager, Generic[HTTPRequestType, HTTPResponseType]):
    """A pipeline implementation.

    This is implemented as a context manager, that will activate the context
    of the HTTP sender.
    """

    def __init__(self, sender, policies=None):
        # type: (HTTPSender, List[Union[HTTPPolicy, SansIOHTTPPolicy]]) -> None
        self._impl_policies = []  # type: List[HTTPPolicy]
        self._transport = sender  # type: HTTPPolicy

        for policy in (policies or []):
            if isinstance(policy, SansIOHTTPPolicy):
                self._impl_policies.append(_SansIOHTTPPolicyRunner(policy))
            else:
                self._impl_policies.append(policy)
        for index in range(len(self._impl_policies)-1):
            self._impl_policies[index].next = self._impl_policies[index+1]
        if self._impl_policies:
            self._impl_policies[-1].next = _TransportRunner(self._transport)

    def __enter__(self):
        # type: () -> Pipeline
        self._transport.__enter__()
        return self

    def __exit__(self, *exc_details):  # pylint: disable=arguments-differ
        self._transport.__exit__(*exc_details)

    def run(self, request, **kwargs):
        # type: (HTTPRequestType, Any) -> Response
        context = self._transport.build_context()
        pipeline_request = Request(request, context)  # type: Request[HTTPRequestType]
        first_node = self._impl_policies[0] if self._impl_policies else _TransportRunner(self._transport)
        return first_node.send(pipeline_request, **kwargs)  # type: ignore


class Request(Generic[HTTPRequestType]):
    """Represents a HTTP request in a Pipeline.

    URL can be given without query parameters, to be added later using "format_parameters".

    Instance can be created without data, to be added later using "add_content"

    Instance can be created without files, to be added later using "add_formdata"

    :param str method: HTTP method (GET, HEAD, etc.)
    :param str url: At least complete scheme/host/path
    :param dict[str,str] headers: HTTP headers
    :param files: Files list.
    :param data: Body to be sent.
    :type data: bytes or str.
    """
    def __init__(self, http_request, context=None):
        # type: (HTTPRequestType, Optional[Any]) -> None
        self.http_request = http_request
        self.context = context


class Response(Generic[HTTPRequestType, HTTPResponseType]):
    """A pipeline response object.

    The Response interface exposes an HTTP response object as it returns through the pipeline of Policy objects.
    This ensures that Policy objects have access to the HTTP response.

    This also have a "context" dictionnary where policy can put additional fields.
    Policy SHOULD update the "context" dictionary with additional post-processed field if they create them.
    However, nothing prevents a policy to actually sub-class this class a return it instead of the initial instance.
    """
    def __init__(self, http_request, http_response, context=None):
        # type: (Request[HTTPRequestType], HTTPResponseType, Optional[Dict[str, Any]]) -> None
        self.http_request = http_request
        self.http_response = http_response
        self.history = []
        self.context = context or {}


__all__ = [
    'Request',
    'Response',
    'Pipeline',
    'HTTPPolicy',
    'SansIOHTTPPolicy'
]