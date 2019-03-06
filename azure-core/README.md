

# Azure Core Library

## Pipeline

The Azure Core pipeline is a re-strucuting of the msrest pipeline introduced in msrest 0.6.0.
Further discussions on the msrest implementation can be found in the [msrest wiki](https://github.com/Azure/msrest-for-python/wiki/msrest-0.6.0---Pipeline).

The Azure Core Pipeline is an implementation of chained policies as described in the [Azure SDK guidelines](https://github.com/Azure/azure-sdk/tree/master/docs/design).

The Python implementation of the pipeline has some mechanisms specific to Python. This is due to the fact that both synchronous and asynchronous implementations of the pipeline must be supported indepedently.

When constructing an SDK, a developer may consume the pipeline like so:

```python
from azure.core import Configuration, Pipeline
from azure.core.transport import RequestsTransport
from azure.core.pipeline.policies import (
    UserAgentPolicy,
    HeadersPolicy,
    RetryPolicy,
    RedirectPolicy,
    ContentDecodePolicy
)

class FooServiceClient():

    @staticmethod
    def create_foo_config(**kwargs):
        # Here the SDK developer would define the default
        # config to interact with the service
        config = Configuration(**kwargs)
        config.user_agent = UserAgentPolicy("ServiceUserAgentValue", **kwargs)
        config.headers = HeadersPolicy({"CustomHeader": "Value"})
        config.retry = RetryPolicy(**kwargs)
        config.redirect = RedirectPolicy(**kwargs)

    def __init__(self, credentials, config=None, transport=None):
        config = config or FooServiceClient.create_foo_config()
        transport = RequestsTransport(config)
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
        new_request = TransportRequest("GET", "/")
        response = self._pipeline.run(new_request, **kwargs)
        # deserialize response data
```

An end user consuming this SDK may write code like so:
```python
from azure.core.credentials import FooCredentials
from azure.foo import FooServiceClient

creds = FooCredentials("api-key")

# Scenario using entirely default configuration
client = FooServiceClient(creds)
response = client.get_request()

# Scenario where user wishes to tweak a couple of settings
foo_config = 
```

### Transport 

Various combinations of sync/async HTTP libraries as well as alternative event loop implementations are available. Therefore to support the widest range of customer scenarios, we must allow a customer to easily swap out the HTTP transport layer to one of those supported.







