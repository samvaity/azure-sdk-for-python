

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
from azure.core.pipeline.transport import TransportRequest
from azure.core.pipeline.transport.requests import RequestsTransport


# Customer
my_config = Configuration(redirect_allow=True, redirect_max=30)
credentials = CognitiveServicesCredentials("foobar")

config = FooServiceClient.get_config()
config.retry_policy.total_count = 10
config.retry_policy = MyRetryPolicy(total_count=10) # RetryPolicy.NO_RETRIES


# SDK Dev
class FooServiceClient():

    @staticmethod
    def create_config():
        config = Configuration()
        config.add_policies([
            UserAgentPolicy("ServiceUserAgentValue", config=my_config),
            HeadersPolicy({"CustomHeader": "Value"}, config=my_config)
            CredentialsPolicy(credentials, config=my_config),
            ContentDecodePolicy(config=my_config),
            RedirectPolicy(config=my_config),
            RetryPolicy(config=my_config),
            NetworkTraceLoggingPolicy(config=my_config),
        ])

    def __init__(self, config=None, transport=None):
        config = config or FooServiceClient.create_config()
        transport = AsycioRequestsTransport(config)  # TrioRequests, Aiohttp
        self.pipeline = Pipeline(transport, policies=config.get_policies())

    def get_request(self, **kwargs)
        with pipeline:
            new_request = TransportRequest("GET", "/")
            response = pipeline.run(new_request, retry_count_total=10)
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