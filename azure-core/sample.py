
from azure.core import Pipeline, RequestsHttpSender


## What role do we want "configuration" to play?
## - Curently it owns, pipeline, credentials, as well as policy objects
## - Unclear where we draw the line between ServiceClient/Configuration

class HTTPSender

configuration.transport = something
pipeline = get_pipeline(credentials, configuration)
pipeline = get_pipeline(credentialsconfiguration, transport=MyTransport)



pipeline = AsyncPipeline(transport=None)

with Pipeline() as my_pipeline:
    my_pipeline.send(something)

async with AsyncPipeline()


from azure.service.aio import FooServiceClient


my_client = FooServiceClient(creds, config=configuration, retries=10})

class FooServiceClient(object):

    def __init__(self, creds):
        creds_policy = as_policy(creds)
        self.pipeline = get_pipeline(creds_policy, configuration)

class AsyncFooServiceClient(object):

    def __init__(self):
        self.pipeline = get_async_pipeline(configuration)


# Default pipeline
# client = ServiceClient(credentials, url)
# client.pipeline  #access default pipeline

# # Tweaked pipeline
# configuration = {'max_redirects': 10, 'max_retries':3, 'proxies':'blah'}
# client = ServiceClient(credentials, url, config=configuration sender=AlternativeRequestsHttpSender)

# # Custom pipeline
# HTTPSenderConfiguration()
# pipeline = Pipeline(policies=[])

# ServiceClient(credentials, url, pipeline=pipeline)


# Request -> [p, p, p] -> sender
sender -> [p, p, p] -> response, deserialize to models