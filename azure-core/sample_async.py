

from azure.core import Configuration, CognitiveServicesCredentials
from azure.core.pipeline import AsyncPipeline
from azure.core.pipeline.policies import (
    AsyncCredentialsPolicy,
    HeadersPolicy,
    UserAgentPolicy,
    NetworkTraceLoggingPolicy,
    ContentDecodePolicy,
    AsyncRetryPolicy,
    AsyncRedirectPolicy
)
from azure.core.pipeline.transport import TransportRequest
from azure.core.pipeline.transport import (
    AsyncioRequestsTransport,
    TrioRequestsTransport,
    AioHttpTransport)

my_config = Configuration(redirect_allow=True, redirect_max=30)
credentials = CognitiveServicesCredentials("foobar")

policies = [
    UserAgentPolicy(my_config),
    HeadersPolicy({"CustomHeader": "Value"}),
    AsyncCredentialsPolicy(credentials),
    ContentDecodePolicy(my_config),
    AsyncRedirectPolicy(my_config),
    AsyncRetryPolicy(my_config),
    NetworkTraceLoggingPolicy(my_config),
]

transport = AioHttpTransport(my_config)
pipeline = AsyncPipeline(transport, policies=policies)

async with pipeline:
    new_request = TransportRequest("GET", "/")
    response = await pipeline.run(new_request)
    # deserialize response data
