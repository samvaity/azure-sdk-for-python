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
from __future__ import absolute_import
import contextlib
import requests
import threading

from oauthlib import oauth2
from .base import (
    TransportResponse,
    _TransportResponseBase,
    HTTPSender
)

from azure.core.exceptions import (
    ClientRequestError,
    TokenExpiredError,
    TokenInvalidError,
    AuthenticationError,
    raise_with_traceback
)

# Matching requests, because why not?
CONTENT_CHUNK_SIZE = 10 * 1024

class RequestsContext(object):
    def __init__(self, session):
        self.session = session


class _RequestsTransportResponseBase(_TransportResponseBase):

    def __init__(self, request, requests_response):
        super(_RequestsTransportResponseBase, self).__init__(request, requests_response)
        self.status_code = requests_response.status_code
        self.headers = requests_response.headers
        self.reason = requests_response.reason

    def body(self):
        return self.internal_response.content

    def text(self, encoding=None):
        if encoding:
            self.internal_response.encoding = encoding
        return self.internal_response.text

    def raise_for_status(self):
        self.internal_response.raise_for_status()


class RequestsTransportResponse(_RequestsTransportResponseBase, TransportResponse):

    def stream_download(self, chunk_size=None, callback=None):
        # type: (Optional[int], Optional[Callable]) -> Iterator[bytes]
        """Generator for streaming request body data.

        :param callback: Custom callback for monitoring progress.
        :param int chunk_size:
        """
        chunk_size = chunk_size or CONTENT_CHUNK_SIZE
        with contextlib.closing(self.internal_response) as response:
            # https://github.com/PyCQA/pylint/issues/1437
            for chunk in response.iter_content(chunk_size):  # pylint: disable=no-member
                if not chunk:
                    break
                if callback and callable(callback):
                    callback(chunk, response=response)
                yield chunk


class RequestsTransport(HTTPSender):
    """Implements a basic requests HTTP sender.

    Since requests team recommends to use one session per requests, you should
    not consider this class as thread-safe, since it will use one Session
    per instance.

    In this simple implementation:
    - You provide the configured session if you want to, or a basic session is created.
    - All kwargs received by "send" are sent to session.request directly
    """

    _protocols = ['http://', 'https://']

    def __init__(self, configuration=None, session=None):
        # type: (Optional[requests.Session]) -> None
        self._session_mapping = threading.local()
        self.config = configuration
        self.session = session or requests.Session()

    def __enter__(self):
        # type: () -> RequestsTransport
        return self

    def __exit__(self, *exc_details):  # pylint: disable=arguments-differ
        self.close()

    def _init_session(self, session):
        # type: (requests.Session) -> None
        """Init session level configuration of requests.

        This is initialization I want to do once only on a session.
        """
        pass  # TODO: Apply configuration

    @property  # type: ignore
    def session(self):
        try:
            return self._session_mapping.session
        except AttributeError:
            self._session_mapping.session = requests.Session()
            self._init_session(self._session_mapping.session)
            return self._session_mapping.session

    @session.setter
    def session(self, value):
        self._init_session(value)
        self._session_mapping.session = value

    def build_context(self):
        # type: () -> RequestsContext
        return RequestsContext(
            session=self.session,
        )

    def close(self):
        self.session.close()

    def send(self, request, **kwargs):
        # type: (TransportRequest, Any) -> TransportResponse
        """Send request object according to configuration.

        Allowed kwargs are:
        - session : will override the driver session and use yours. Should NOT be done unless really required.
        - anything else is sent straight to requests.

        :param TransportRequest request: The request object to be sent.
        """
        try:
            response = self.session.request(
                request.method,
                request.url,
                **kwargs)
        except oauth2.rfc6749.errors.InvalidGrantError as err:
            msg = "Token is invalid."
            raise_with_traceback(TokenInvalidError, msg, err)
        except oauth2.rfc6749.errors.TokenExpiredError as err:
            msg = "Token has expired."
            raise_with_traceback(TokenExpiredError, msg, err)
        except oauth2.rfc6749.errors.OAuth2Error as err:
            msg = "Authentication error occurred in request."
            raise_with_traceback(AuthenticationError, msg, err)
        except requests.RequestException as err:
            msg = "Error occurred in request."
            raise_with_traceback(ClientRequestError, msg, err)

        return RequestsTransportResponse(request, response)
