

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

my_config = Configuration(redirect_allow=True, redirect_max=30)
credentials = CognitiveServicesCredentials("foobar")

policies = [
    UserAgentPolicy("ServiceUserAgentValue", config=my_config),
    HeadersPolicy({"CustomHeader": "Value"}, config=my_config)
    CredentialsPolicy(credentials, config=my_config),
    ContentDecodePolicy(config=my_config),
    RedirectPolicy(config=my_config),
    RetryPolicy(config=my_config),
    NetworkTraceLoggingPolicy(config=my_config),
]

transport = RequestsTransport(my_config)
pipeline = Pipeline(transport, policies=policies)

with pipeline:
    new_request = TransportRequest("GET", "/")
    response = pipeline.run(new_request)
    # deserialize response data
