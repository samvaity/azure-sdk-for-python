from keyvault_testcase import KeyvaultTestCase
from azure.keyvault.keys import KeyClient
from devtools_testutils import AzureMgmtTestCase, ResourceGroupPreparer


class KeyClientTests(KeyvaultTestCase):
    def test_get_key(self, **kwargs):
        url = ""
        credentials = self.settings.get_credentials()
        client = KeyClient(vault_url=url, credentials=credentials)

        # get all the vault's keys
        keys_at_start = list(client.get_all_keys())
        key_ids_at_start = {key.kid for key in keys_at_start}

        # create a key
        key_name = "testkey"
        new_key = client.create_key(key_name, "RSA")
        assert new_key.name == key_name

        # get the key by name
        key = client.get_key(key_name)

        # get all the vault's keys again
        all_keys = list(client.get_all_keys())
        # assert the vault has exactly one more key now
        assert len(all_keys) - len(keys_at_start) == 1

        # delete the new key
        deleted = client.delete_key(key_name)
        assert deleted.key.kid == key.id

        # verify the created key was deleted
        keys_at_end = client.get_all_keys()
        key_ids_at_end = {key.kid for key in keys_at_end}
        assert len(key_ids_at_end.symmetric_difference(key_ids_at_start)) == 0

        return
