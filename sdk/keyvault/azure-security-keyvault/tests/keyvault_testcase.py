from azure_devtools.scenario_tests import GeneralNameReplacer
from devtools_testutils import AzureMgmtTestCase
# from azure.security.keyvault.keys import KeyClient


class KeyvaultTestCase(AzureMgmtTestCase):
    def setUp(self):
        self.list_test_size = 7
        super(KeyvaultTestCase, self).setUp()

    def tearDown(self):
        super(KeyvaultTestCase, self).tearDown()