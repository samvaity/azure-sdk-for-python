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
import asyncio
from collections.abc import AsyncIterator
import functools
import logging
from typing import Any, Callable, Optional, AsyncIterator as AsyncIteratorType

from oauthlib import oauth2
import requests
from requests.models import CONTENT_CHUNK_SIZE

from ..exceptions import (
    TokenExpiredError,
    ClientRequestError,
    raise_with_traceback
)
from ..universal_http.async_requests import AsyncBasicRequestsHTTPSender
from . import AsyncHTTPSender, AsyncHTTPPolicy, Response, Request
from .requests import RequestsContext


class AsyncRedirectPolicy(AsyncHTTPPolicy):

    def __init__(self, **kwargs):
        self.redirect_allow = kwargs.pop('redirect_allow', True)
        self.redirect_max = kwargs.pop('redirect_max', 30)

    async def send(self, request, **kwargs):
        return await self.next.send(request, **kwargs)