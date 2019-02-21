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
import logging

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

class HTTPPolicy(ABC, Generic[HTTPRequestType, HTTPResponseType]):
    """An http policy ABC.
    """
    def __init__(self):
        self.next = None

    @abc.abstractmethod
    def send(self, request, **kwargs):
        # type: (Request[HTTPRequestType], Any) -> Response[HTTPRequestType, HTTPResponseType]
        """Mutate the request.

        Context content is dependent of the HTTPSender.
        """
        pass

class SansIOHTTPPolicy(Generic[HTTPRequestType, HTTPResponseType]):
    """Represents a sans I/O policy.

    This policy can act before the I/O, and after the I/O.
    Use this policy if the actual I/O in the middle is an implementation
    detail.

    Context is not available, since it's implementation dependent.
    if a policy needs a context of the Sender, it can't be universal.

    Example: setting a UserAgent does not need to be tight to
    sync or async implementation or specific HTTP lib
    """
    def on_request(self, request, **kwargs):
        # type: (Request[HTTPRequestType], Any) -> None
        """Is executed before sending the request to next policy.
        """
        pass

    def on_response(self, request, response, **kwargs):
        # type: (Request[HTTPRequestType], Response[HTTPRequestType, HTTPResponseType], Any) -> None
        """Is executed after the request comes back from the policy.
        """
        pass

    def on_exception(self, request, **kwargs):
        # type: (Request[HTTPRequestType], Any) -> bool
        """Is executed if an exception comes back fron the following
        policy.

        Return True if the exception has been handled and should not
        be forwarded to the caller.

        This method is executed inside the exception handler.
        To get the exception, raise and catch it:

            try:
                raise
            except MyError:
                do_something()

        or use

            exc_type, exc_value, exc_traceback = sys.exc_info()
        """
        return False


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


class Pipeline(AbstractContextManager, Generic[HTTPRequestType, HTTPResponseType]):
    """A pipeline implementation.

    This is implemented as a context manager, that will activate the context
    of the HTTP sender.
    """

    def __init__(self, policies=None, sender=None):
        # type: (List[Union[HTTPPolicy, SansIOHTTPPolicy]], HTTPSender) -> None
        self._impl_policies = []  # type: List[HTTPPolicy]
        if not sender:
            # Import default only if nothing is provided
            from .requests import PipelineRequestsHTTPSender
            self._sender = cast(HTTPSender, PipelineRequestsHTTPSender())
        else:
            self._sender = sender
        for policy in (policies or []):
            if isinstance(policy, SansIOHTTPPolicy):
                self._impl_policies.append(_SansIOHTTPPolicyRunner(policy))
            else:
                self._impl_policies.append(policy)
        for index in range(len(self._impl_policies)-1):
            self._impl_policies[index].next = self._impl_policies[index+1]
        if self._impl_policies:
            self._impl_policies[-1].next = self._sender

    def __enter__(self):
        # type: () -> Pipeline
        self._sender.__enter__()
        return self

    def __exit__(self, *exc_details):  # pylint: disable=arguments-differ
        self._sender.__exit__(*exc_details)

    def run(self, request, **kwargs):
        # type: (HTTPRequestType, Any) -> Response
        context = self._sender.build_context()
        pipeline_request = Request(request, context)  # type: Request[HTTPRequestType]
        first_node = self._impl_policies[0] if self._impl_policies else self._sender
        return first_node.send(pipeline_request, **kwargs)  # type: ignore


class HTTPSender(AbstractContextManager, ABC, Generic[HTTPRequestType, HTTPResponseType]):
    """An http sender ABC.
    """

    @abc.abstractmethod
    def send(self, request, **config):
        # type: (Request[HTTPRequestType], Any) -> Response[HTTPRequestType, HTTPResponseType]
        """Send the request using this HTTP sender.
        """
        pass

    def build_context(self):
        # type: () -> Any
        """Allow the sender to build a context that will be passed
        across the pipeline with the request.

        Return type has no constraints. Implementation is not
        required and None by default.
        """
        return None


class ClientRequest(object):
    """Represents a HTTP request.

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
    def __init__(self, method, url, headers=None, files=None, data=None):
        # type: (str, str, Mapping[str, str], Any, Any) -> None
        self.method = method
        self.url = url
        self.headers = CaseInsensitiveDict(headers)
        self.files = files
        self.data = data

    def __repr__(self):
        return '<ClientRequest [%s]>' % (self.method)

    @property
    def body(self):
        """Alias to data."""
        return self.data

    @body.setter
    def body(self, value):
        self.data = value

    def format_parameters(self, params):
        # type: (Dict[str, str]) -> None
        """Format parameters into a valid query string.
        It's assumed all parameters have already been quoted as
        valid URL strings.

        :param dict params: A dictionary of parameters.
        """
        query = urlparse(self.url).query
        if query:
            self.url = self.url.partition('?')[0]
            existing_params = {
                p[0]: p[-1]
                for p in [p.partition('=') for p in query.split('&')]
            }
            params.update(existing_params)
        query_params = ["{}={}".format(k, v) for k, v in params.items()]
        query = '?' + '&'.join(query_params)
        self.url = self.url + query

    def add_content(self, data):
        # type: (Optional[Union[Dict[str, Any], ET.Element]]) -> None
        """Add a body to the request.

        :param data: Request body data, can be a json serializable
         object (e.g. dictionary) or a generator (e.g. file data).
        """
        if data is None:
            return

        if isinstance(data, ET.Element):
            bytes_data = ET.tostring(data, encoding="utf8")
            self.headers['Content-Length'] = str(len(bytes_data))
            self.data = bytes_data
            return

        # By default, assume JSON
        try:
            self.data = json.dumps(data)
            self.headers['Content-Length'] = str(len(self.data))
        except TypeError:
            self.data = data

    @staticmethod
    def _format_data(data):
        # type: (Union[str, IO]) -> Union[Tuple[None, str], Tuple[Optional[str], IO, str]]
        """Format field data according to whether it is a stream or
        a string for a form-data request.

        :param data: The request field data.
        :type data: str or file-like object.
        """
        if hasattr(data, 'read'):
            data = cast(IO, data)
            data_name = None
            try:
                if data.name[0] != '<' and data.name[-1] != '>':
                    data_name = os.path.basename(data.name)
            except (AttributeError, TypeError):
                pass
            return (data_name, data, "application/octet-stream")
        return (None, cast(str, data))

    def add_formdata(self, content=None):
        # type: (Optional[Dict[str, str]]) -> None
        """Add data as a multipart form-data request to the request.

        We only deal with file-like objects or strings at this point.
        The requests is not yet streamed.

        :param dict headers: Any headers to add to the request.
        :param dict content: Dictionary of the fields of the formdata.
        """
        if content is None:
            content = {}
        content_type = self.headers.pop('Content-Type', None) if self.headers else None

        if content_type and content_type.lower() == 'application/x-www-form-urlencoded':
            # Do NOT use "add_content" that assumes input is JSON
            self.data = {f: d for f, d in content.items() if d is not None}
        else: # Assume "multipart/form-data"
            self.files = {f: self._format_data(d) for f, d in content.items() if d is not None}


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

class ClientResponse(object):
    """Represent a HTTP response.

    No body is defined here on purpose, since async pipeline
    will provide async ways to access the body
    Full in-memory using "body" as bytes.
    """
    def __init__(self, request, internal_response):
        # type: (ClientRequest, Any) -> None
        self.request = request
        self.internal_response = internal_response
        self.status_code = None  # type: Optional[int]
        self.headers = {}  # type: Dict[str, str]
        self.reason = None  # type: Optional[str]

    def body(self):
        # type: () -> bytes
        """Return the whole body as bytes in memory.
        """
        pass

    def text(self, encoding=None):
        # type: (str) -> str
        """Return the whole body as a string.

        :param str encoding: The encoding to apply. If None, use "utf-8".
         Implementation can be smarter if they want (using headers).
        """
        return self.body().decode(encoding or "utf-8")

    def raise_for_status(self):
        """Raise for status. Should be overriden, but basic implementation provided.
        """
        if self.status_code >= 400:
            raise ClientRequestError("Received status code {}".format(self.status_code))


class StreamableClientResponse(ClientResponse):

    def stream_download(self, chunk_size=None, callback=None):
        # type: (Optional[int], Optional[Callable]) -> Iterator[bytes]
        """Generator for streaming request body data.

        Should be implemented by sub-classes if streaming download
        is supported.

        :param callback: Custom callback for monitoring progress.
        :param int chunk_size:
        """
        pass


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
        self.context = context or {}


class ClientRedirectPolicy(object):  # TODO: Reconfigure
    """Redirect configuration settings.
    """

    def __init__(self):
        self.allow = True
        self.max_redirects = 30

    def __bool__(self):
        # type: () -> bool
        """Whether redirects are allowed."""
        return self.allow

    def __call__(self):
        # type: () -> int
        """Return configuration to be applied to connection."""
        debug = "Configuring redirects: allow=%r, max=%r"
        _LOGGER.debug(debug, self.allow, self.max_redirects)
        return self.max_redirects

class ClientRetryPolicy(object):  # TODO: Remove
    """Retry configuration settings.
    Container for retry policy object.
    """

    safe_codes = [i for i in range(500) if i != 408] + [501, 505]

    def __init__(self):
        self.policy = Retry()
        self.policy.total = 3
        self.policy.connect = 3
        self.policy.read = 3
        self.policy.backoff_factor = 0.8
        self.policy.BACKOFF_MAX = 90

        retry_codes = [i for i in range(999) if i not in self.safe_codes]
        self.policy.status_forcelist = retry_codes
        self.policy.method_whitelist = ['HEAD', 'TRACE', 'GET', 'PUT',
                                        'OPTIONS', 'DELETE', 'POST', 'PATCH']

    def __call__(self):
        # type: () -> Retry
        """Return configuration to be applied to connection."""
        debug = ("Configuring retry: max_retries=%r, "
                 "backoff_factor=%r, max_backoff=%r")
        _LOGGER.debug(
            debug, self.retries, self.backoff_factor, self.max_backoff)
        return self.policy

    @property
    def retries(self):
        # type: () -> int
        """Total number of allowed retries."""
        return self.policy.total

    @retries.setter
    def retries(self, value):
        # type: (int) -> None
        self.policy.total = value
        self.policy.connect = value
        self.policy.read = value

    @property
    def backoff_factor(self):
        # type: () -> Union[int, float]
        """Factor by which back-off delay is incementally increased."""
        return self.policy.backoff_factor

    @backoff_factor.setter
    def backoff_factor(self, value):
        # type: (Union[int, float]) -> None
        self.policy.backoff_factor = value

    @property
    def max_backoff(self):
        # type: () -> int
        """Max retry back-off delay."""
        return self.policy.BACKOFF_MAX

    @max_backoff.setter
    def max_backoff(self, value):
        # type: (int) -> None
        self.policy.BACKOFF_MAX = value


class ClientProxies(object):  # TODO: Reconfigure
    """Proxy configuration settings.
    Proxies can also be configured using HTTP_PROXY and HTTPS_PROXY
    environment variables, in which case set use_env_settings to True.
    """

    def __init__(self):
        self.proxies = {}
        self.use_env_settings = True

    def __call__(self):
        # type: () -> Dict[str, str]
        """Return configuration to be applied to connection."""
        proxy_string = "\n".join(
            ["    {}: {}".format(k, v) for k, v in self.proxies.items()])

        _LOGGER.debug("Configuring proxies: %r", proxy_string)
        debug = "Evaluate proxies against ENV settings: %r"
        _LOGGER.debug(debug, self.use_env_settings)
        return self.proxies

    def add(self, protocol, proxy_url):
        # type: (str, str) -> None
        """Add proxy.

        :param str protocol: Protocol for which proxy is to be applied. Can
         be 'http', 'https', etc. Can also include host.
        :param str proxy_url: The proxy URL. Where basic auth is required,
         use the format: http://user:password@host
        """
        self.proxies[protocol] = proxy_url


class ClientConnection(object):  # TODO: Reconfigure
    """Request connection configuration settings.
    """

    def __init__(self):
        self.timeout = 100
        self.verify = True
        self.cert = None
        self.data_block_size = 4096

    def __call__(self):
        # type: () -> Dict[str, Union[str, int]]
        """Return configuration to be applied to connection."""
        debug = "Configuring request: timeout=%r, verify=%r, cert=%r"
        _LOGGER.debug(debug, self.timeout, self.verify, self.cert)
        return {'timeout': self.timeout,
                'verify': self.verify,
                'cert': self.cert}


class HTTPSenderConfiguration(object):
    """HTTP sender configuration.

    This is composed of generic HTTP configuration, and could be use as a common
    HTTP configuration format.

    :param str filepath: Path to existing config file (optional).
    """

    def __init__(self, filepath=None):
        # Communication configuration
        self.connection = ClientConnection()

        # Headers (sent with every requests)
        self.headers = {}  # type: Dict[str, str]

        # ProxyConfiguration
        self.proxies = ClientProxies()

        # Redirect configuration
        self.redirect_policy = ClientRedirectPolicy()

        self._config = configparser.ConfigParser()
        self._config.optionxform = str  # type: ignore

        if filepath:
            self.load(filepath)

    def _clear_config(self):
        # type: () -> None
        """Clearout config object in memory."""
        for section in self._config.sections():
            self._config.remove_section(section)



__all__ = [
    'Request',
    'Response',
    'Pipeline',
    'HTTPPolicy',
    'SansIOHTTPPolicy',
    'HTTPSender'
]