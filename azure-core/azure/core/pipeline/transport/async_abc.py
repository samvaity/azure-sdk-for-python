

class _AsyncTransportResponse(_TransportResponseBase):

    def stream_download(self, chunk_size: Optional[int] = None, callback: Optional[Callable] = None) -> AsyncIterator[bytes]:
        """Generator for streaming request body data.

        Should be implemented by sub-classes if streaming download
        is supported.

        :param callback: Custom callback for monitoring progress.
        :param int chunk_size:
        """
        pass


class AsyncHTTPSender(AbstractAsyncContextManager, abc.ABC, Generic[HTTPRequestType, AsyncHTTPResponseType]):
    """An http sender ABC.
    """

    @abc.abstractmethod
    async def send(self, request: Request[HTTPRequestType], **config: Any) -> Response[HTTPRequestType, AsyncHTTPResponseType]:
        """Send the request using this HTTP sender.
        """
        pass

    def build_context(self) -> Any:
        """Allow the sender to build a context that will be passed
        across the pipeline with the request.

        Return type has no constraints. Implementation is not
        required and None by default.
        """
        return None

    def __enter__(self):
        raise TypeError("Use async with instead")

    def __exit__(self, exc_type, exc_val, exc_tb):
        # __exit__ should exist in pair with __enter__ but never executed
        pass  # pragma: no cover
