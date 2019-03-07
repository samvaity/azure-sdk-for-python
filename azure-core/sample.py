

from azure.core import Configuration, CognitiveServicesCredentials
from azure.core.pipeline import Pipeline
from azure.core.pipeline.policies import (
    CredentialsPolicy,
    HeadersPolicy,
    UserAgentPolicy,
    NetworkTraceLoggingPolicy,
    ContentDecodePolicy,
    RetryPolicy,
    RedirectPolicy
)
from azure.core.pipeline.transport import HttpRequest, RequestsTransport


# Customer
credentials = CognitiveServicesCredentials("foobar")

config = FooServiceClient.create_foo_config()
config.retry_policy.total_count = 10
config.retry_policy = MyRetryPolicy(total_count=10) # RetryPolicy.NO_RETRIES

client = FooServiceClient(creds, config)


# SDK Dev
class FooServiceClient():

    @staticmethod
    def create_foo_config(**kwargs):
        config = Configuration(**kwargs)
        config.user_agent = UserAgentPolicy("ServiceUserAgentValue", **kwargs)
        config.headers = HeadersPolicy({"CustomHeader": "Value"})
        config.retry = RetryPolicy(**kwargs)
        config.redirect = RedirectPolicy(**kwargs)

    def __init__(self, credentials, config=None, transport=None):
        config = config or FooServiceClient.create_foo_config()
        transport = RequestsTransport(config)  # TrioRequests, Aiohttp
        policies = [
            config.user_agent,
            config.headers,
            credentials,
            ContentDecodePolicy(),
            config.redirect,
            config.retry,
            config.logging,
        ]
        self._pipeline = Pipeline(transport, policies=policies)

    def get_request(self, **kwargs)
        new_request = HttpRequest("GET", "/")
        response = self._pipeline.run(new_request, **kwargs)
        # deserialize response data


## Notes:
# - How should we distinguish between customer policy config vs SDK author policy configuration
# - Add function to SDK to provide specific configuration defaults to that service.
# - Should we allow one to swap out a specific policy with the configuration and/or provide just a specific policy
# - Make config setting access more robust
# - stack-specific packaging (requests vs aiohttp)
# - Why doesn't AsyncioRequestsTransport take a loop?
# - Should the confoguration object own the policy objects?
# - Proxy as a policy - various ENV settings to support.

# - Potential in future for a "custom" policy ("BeforeSend" etc)