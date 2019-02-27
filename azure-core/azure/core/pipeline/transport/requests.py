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

class RequestsContext(object):
    def __init__(self, session):
        self.session = session


class RequestsTransportResponseBase(_TransportResponseBase):

    def __init__(self, request, requests_response):
        super(RequestsClientResponse, self).__init__(request, requests_response)
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


class RequestsTransportResponse(RequestsTransportResponseBase, _TransportResponse):

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

    def __init__(self, config, session=None):
        # type: (Optional[requests.Session]) -> None
        self._session_mapping = threading.local()
        self.session = session or requests.Session()
        self.config = config

    def __enter__(self):
        # type: () -> BasicRequestsHTTPSender
        return self

    def __exit__(self, *exc_details):  # pylint: disable=arguments-differ
        self.close()

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
        # type: (ClientRequest, Any) -> ClientResponse
        """Send request object according to configuration.

        Allowed kwargs are:
        - session : will override the driver session and use yours. Should NOT be done unless really required.
        - anything else is sent straight to requests.

        :param ClientRequest request: The request object to be sent.
        """
        try:
            response = self.session.request(
                request.method,
                request.url,
                **kwargs)
        except requests.RequestException as err:
            msg = "Error occurred in request."
            raise_with_traceback(ClientRequestError, msg, err)

        return RequestsClientResponse(request, response)


def _patch_redirect(session):
    # type: (requests.Session) -> None
    """Whether redirect policy should be applied based on status code.

    HTTP spec says that on 301/302 not HEAD/GET, should NOT redirect.
    But requests does, to follow browser more than spec
    https://github.com/requests/requests/blob/f6e13ccfc4b50dc458ee374e5dba347205b9a2da/requests/sessions.py#L305-L314

    This patches "requests" to be more HTTP compliant.

    Note that this is super dangerous, since technically this is not public API.
    """
    def enforce_http_spec(resp, request):
        if resp.status_code in (301, 302) and \
                request.method not in ['GET', 'HEAD']:
            return False
        return True

    redirect_logic = session.resolve_redirects

    def wrapped_redirect(resp, req, **kwargs):
        attempt = enforce_http_spec(resp, req)
        return redirect_logic(resp, req, **kwargs) if attempt else []
    wrapped_redirect.is_msrest_patched = True  # type: ignore

    session.resolve_redirects = wrapped_redirect  # type: ignore