import datetime
import asyncio
from azure.security.keyvault.aio import SecretClient
from azure.identity import AsyncDefaultAzureCredential
from azure.core.exceptions import HttpResponseError

# ----------------------------------------------------------------------------------------------------------
# Prerequistes -
#
# 1. An Azure Key Vault-
#    https://docs.microsoft.com/en-us/azure/key-vault/quick-create-cli
#
# 2. Microsoft Azure Key Vault PyPi package -
#    https://pypi.python.org/pypi/azure-security-keyvault/
#
# 3. Microsoft Azure Identity package -
#    https://pypi.python.org/pypi/azure-identity/
#
# 4. Set Environment variables AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET
#
# 5. In the code, replace YOUR_VAULT_URL with your vault url.
# ----------------------------------------------------------------------------------------------------------
# Sample - demonstrates the basic list operations on a vault(secret) resource for Azure Key Vault
#
# 1. Create secret (set_secret)
#
# 2. List secrets from the Key Vault (list_secrets)
#
# 3. List secret versions from the Key Vault (list_secret_versions)
#
# 4. List deleted secrets from the Key Vault (list_deleted_secrets)
#
# ----------------------------------------------------------------------------------------------------------
async def run_sample():
    # Instantiate a secret client that will be used to call the service.
    # Notice that the client is using default Azure credentials.
    # To make default credentials work, ensure that environment variables 'AZURE_CLIENT_ID',
    # 'AZURE_CLIENT_SECRET' and 'AZURE_TENANT_ID' are set with the service principal credentials.
    credential = AsyncDefaultAzureCredential()
    client = SecretClient(vault_url=YOUR_VAULT_URL, credential=credential)
    try:
        # Let's create secrets holding storage and bank accounts credentials. If the secret
        # already exists in the Key Vault, then a new version of the secret is created.
        print("\n1. Create Secret")
        bank_secret = await client.set_secret("bankSecretName", "secretValue1")
        storage_secret = await client.set_secret("storageSecretName", "secretValue2")
        print("Secret with name '{0}' was created.".format(bank_secret.name))
        print("Secret with name '{0}' was created.".format(storage_secret.name))

        # You need to check if any of the secrets are sharing same values.
        # Let's list the secrets and print their values.
        # List operations don 't return the secrets with value information.
        # So, for each returned secret we call get_secret to get the secret with its value information.
        print("\n2. List secrets from the Key Vault")
        secrets = client.list_secrets()
        async for secret in secrets:
            print("Secret with name '{0}' was found.".format(secret.id))

        # The bank account password got updated, so you want to update the secret in Key Vault to ensure it reflects the new password.
        # Calling set_secret on an existing secret creates a new version of the secret in the Key Vault with the new value.
        updated_secret = await client.set_secret("bankSecretName", "newSecretValue")
        print("Secret with name '{0}' was updated with new value {1}".format(updated_secret.name, updated_secret.value))

        # You need to check all the different values your bank account password secret had previously. Lets print all the versions of this secret.
        print("\n3. List versions of the secret using its id")
        secret_versions = client.list_secret_versions("bankSecretName")
        async for secret_version in secret_versions:
            print("Bank Secret version: '{0}'".format(secret_version.version))

        # The bank acoount and storage accounts got closed. Let's delete bank and storage accounts secrets.
        await client.delete_secret("bankSecretName")
        await client.delete_secret("storageSecretName")

        # To ensure secret is deleted on the server side.
        print("\nDeleting secrets...")
        await asyncio.sleep(30)

        # You can list all the deleted and non-purged secrets, assuming Key Vault is soft-delete enabled.
        print("\n3. List deleted secrets from the Key Vault")
        deleted_secrets = client.list_deleted_secrets()
        async for deleted_secret in deleted_secrets:
            print("Secret with name '{0}' has recovery id {1}".format(deleted_secret.name, deleted_secret.recovery_id))

    except HttpResponseError as e:
        print("\nrun_sample has caught an error. {0}".format(e.message))

    finally:
        print("\nrun_sample done")


if __name__ == "__main__":
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(run_sample())
        loop.close()

    except Exception as e:
        print("Top level Error: {0}".format(str(e)))
