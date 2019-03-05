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


class Configuration(object):
    """Add proxy.

    :param str protocol: Protocol for which proxy is to be applied. Can
        be 'http', 'https', etc. Can also include host.
    :param str proxy_url: The proxy URL. Where basic auth is required,
        use the format: http://user:password@host
    """

    def __iter__(self):
        dict_values = dict(self.__dict__)
        dict_values.pop('to_dict')
        dict_values.pop('from_dict')
        for attr, value in dict_values.items():
            yield attr, value

    @classmethod
    def from_dict(cls, dict_values):
        return cls(**dict_values)

    @classmethod
    def from_file(cls, filepath):
        pass  # TODO: Load from config file.

    def __init__(self, **kwargs):
        # Communication configuration - TODO: applied per session?
        self.connection_timeout = kwargs.pop('connection_timeout', 100)
        self.connection_verify = kwargs.pop('connection_verify', True)
        self.connection_cert = kwargs.pop('connection_cert', None)
        self.connection_data_block_size = kwargs.pop('connection_data_block_size', 4096)
        self.connection_keep_alive = kwargs.pop('connection_keep_alive', False)

        # Headers (sent with every requests)
        self.headers = kwargs.pop('headers', {})  # type: Dict[str, str]

        # ProxyConfiguration (used to configure transport)
        self.proxies = kwargs.pop('proxies', {})
        self.proxies_use_env_settings = kwargs.pop('proxies_use_env_settings', True)

        # Redirect configuration
        self.redirect_allow = kwargs.pop('redirect_allow', True)
        self.redirect_max = kwargs.pop('redirect_max', 30)

        # Retry configuration
        safe_codes = [i for i in range(500) if i != 408] + [501, 505]
        self.retry_status_codes = kwargs.pop('retry_status_codes', [i for i in range(999) if i not in safe_codes])
        self.retry_count_total = kwargs.pop('retry_count_total', 10)
        self.retry_count_connect = kwargs.pop('retry_count_connect', 3)
        self.retry_count_read = kwargs.pop('retry_count_read', 3)
        self.retry_count_status = kwargs.pop('retry_count_status', 3)
        self.retry_backoff_factor = kwargs.pop('retry_backoff_factor', 0.8)  # TODO: Is this value universal
        self.retry_backoff_max = kwargs.pop('retry_backoff_max', 90)  # TODO: Standardized value?

        # Logger configuration
        self.logging_enable = kwargs.pop('logging_enable', False)

        # User Agent configuration
        self.user_agent = kwargs.pop('user_agent', None)
        self.user_agent_overwrite = kwargs.pop('user_agent_overwrite', False)

        if kwargs:
            raise ValueError("Unrecognized configuration settings: {}".format(kwargs))