# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE.txt in the project root for
# license information.
# --------------------------------------------------------------------------
import time
import codecs
from dateutil import parser as date_parse
from preparer import VaultClientPreparer
from test_case import KeyVaultTestCase
from azure.security.keyvault._key_vault_id import KeyVaultId
from devtools_testutils import ResourceGroupPreparer
from azure.security.keyvault._generated.v7_0.models import (
    SecretProperties,
    KeyProperties,
    CertificatePolicy,
    IssuerParameters,
    X509CertificateProperties,
    SubjectAlternativeNames,
    IssuerCredentials,
    OrganizationDetails,
    AdministratorDetails,
    Contact,
)


class CertificateClientTests(KeyVaultTestCase):
    def _validate_certificate_operation(self, pending_cert, vault, cert_name, cert_policy):
        prefix = "/".join(s.strip("/") for s in [vault, "certificates", cert_name])
        cert_id = pending_cert.id
        self.assertIsNotNone(pending_cert)
        self.assertIsNotNone(pending_cert.csr)
        self.assertEqual(cert_policy.issuer_parameters.name, pending_cert.issuer_name)
        self.assertTrue(
            cert_id.index(prefix) == 0, "Cert Id should start with '{}', but value is '{}'".format(prefix, cert_id)
        )
        self.assertEqual(pending_cert.name, cert_name)
    
    def _validate_certificate_key_properties(self, expected, key_properties):
        self.assertEqual(expected.exportable, key_properties.exportable)
        self.assertEqual(expected.key_type, key_properties.key_type)
        self.assertEqual(expected.key_size, key_properties.key_size)
        self.assertEqual(expected.reuse_key, key_properties.reuse_key)
        self.assertEqual(expected.curve, key_properties.curve)

    def _validate_certificate(self, cert, vault, cert_name, cert_policy):
        cert_id = KeyVaultId.parse_certificate_id(cert.id)
        self.assertEqual(cert_id.vault.strip("/"), vault.strip("/"))
        self.assertEqual(cert_id.name, cert_name)
        self.assertIsNotNone(cert)
        self.assertIsNotNone(cert.thumbprint)
        self.assertIsNotNone(cert.cer)
        self.assertIsNotNone(cert.policy)
        self.assertIsNotNone(cert.policy.id)
        self.assertIsNotNone(cert.policy.issuer_name)
        self.assertIsNotNone(cert.policy.lifetime_actions)
        self.assertEqual(cert_policy.secret_properties.content_type, cert.policy.content_type)
        self.assertEqual(cert_policy.issuer_parameters.certificate_type, cert.policy.certificate_type)
        self.assertEqual(cert_policy.issuer_parameters.certificate_transparency, cert.policy.certificate_transparency)
        if cert_policy.x509_certificate_properties:
            self.assertEqual(cert.policy.validity_in_months, cert.policy.validity_in_months)
            self.assertEqual(cert_policy.x509_certificate_properties.subject, cert.policy.subject_name)
            self.assertEqual(
                cert_policy.x509_certificate_properties.subject_alternative_names.dns_names,
                cert.policy.subject_alternative_dns_names,
            )
        if cert_policy.lifetime_actions:
            self.assertEqual(cert_policy.lifetime_action.trigger.lifetime_percentage, cert.policy.lifetime_action[0].lifetime_percentage)
            self.assertEqual(cert_policy.lifetime_action.action.action_type, cert.policy.lifetime_action[0].action_type)
        
        self._validate_certificate_key_properties(cert_policy.key_properties, cert.policy.key_properties)
        if cert_policy.x509_certificate_properties.ekus:
            self.assertEqual(cert_policy.x509_certificate_properties.ekus, cert.policy.key_properties.ekus)
        if cert_policy.x509_certificate_properties.key_usage:
            self.assertEqual(cert_policy.x509_certificate_properties.key_usage, cert.policy.key_properties.key_usage)
        self.assertIsNotNone(KeyVaultId.parse_secret_id(cert.sid))
        self.assertIsNotNone(KeyVaultId.parse_key_id(cert.kid))

    def _validate_certificate_list(self, certificates, expected):
        for cert in certificates:
            if cert.id in expected.keys():
                del expected[cert.id]
            else:
                self.assertTrue(False)
        self.assertEqual(len(expected), 0)

    def _validate_issuer_bundle(self, bundle, vault, name, provider, account_id, org_details, expires):
        self.assertIsNotNone(bundle)
        self.assertIsNotNone(bundle.expires, expires)
        self.assertIsNotNone(bundle.organization_id)
        self.assertEqual(bundle.provider, provider)

        issuer_id = KeyVaultId.parse_certificate_issuer_id(bundle.id)
        self.assertEqual(issuer_id.vault.strip("/"), vault.strip("/"))
        self.assertEqual(bundle.name, name)

        if account_id:
            self.assertEqual(bundle.account_id, account_id)
        if organization_id:
            self.assertEqual(bundle.organization_id, organization_id)

    def _update_certificate(self, client, cert):
        expires = date_parse.parse("2050-01-02T08:00:00.000Z")
        tags = {"foo": "updated tag"}
        cert_bundle = client.update_certificate(cert.name, cert.version, expires=expires, tags=tags)
        self.assertEqual(tags, cert_bundle.tags)
        self.assertEqual(cert.id, cert_bundle.id)
        self.assertNotEqual(cert.updated, cert_bundle.updated)
        return cert_bundle

    def _import_common_certificate(self, client, cert_name):
        cert_content = "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"
        cert_password = "123"
        return client.import_certificate(cert_name, base64_encoded_certificate=cert_content, password=cert_password)

    @ResourceGroupPreparer()
    @VaultClientPreparer()
    def test_certificate_crud_operations(self, vault_client, **kwargs):
        self.assertIsNotNone(vault_client)
        client = vault_client.certificates
        cert_name = self.get_resource_name("cert")
        cert_policy = CertificatePolicy(
            key_properties=KeyProperties(exportable=True, key_type="RSA", key_size=2048, reuse_key=False),
            secret_properties=SecretProperties(content_type="application/x-pkcs12"),
            issuer_parameters=IssuerParameters(name="Self"),
            x509_certificate_properties=X509CertificateProperties(
                subject="CN=*.microsoft.com",
                subject_alternative_names=SubjectAlternativeNames(
                    dns_names=["onedrive.microsoft.com", "xbox.microsoft.com"]
                ),
                validity_in_months=24,
            ),
            lifetime_actions=LifetimeActions(
                trigger=Trigger(
                    lifetime_percentage=20
                ),
                action=Action(
                    action_type="AutoRenew"
                )
            )
        )
        # create certificate
        cert_operation = client.create_certificate(cert_name, policy=cert_policy)
        while True:
            pending_cert = client.get_certificate_operation(cert_name)
            self._validate_certificate_operation(pending_cert, client.vault_url, cert_name, cert_policy=cert_policy)
            if pending_cert.status.lower() == "completed":
                cert_id = KeyVaultId.parse_certificate_operation_id(pending_cert.target)
                break
            elif pending_cert.status.lower() != "inprogress":
                raise Exception("Unknown status code for pending certificate: {}".format(pending_cert))
            time.sleep(5)

        # get certificate without version
        cert = client.get_certificate(cert_id.name)
        self._validate_certificate(cert, client.vault_url, cert_name, cert_policy)

        # get certificate as secret
        secret_id = KeyVaultId.parse_secret_id(cert.sid)
        secrets_client = vault_client.secrets
        secret_bundle = secrets_client.get_secret(secret_id.name)

        # update cetificate with version
        if self.is_live:
            # wait to ensure the cert's update time won't equal its creation time
            time.sleep(1)
        self._update_certificate(client, cert)

        # delete certificate
        cert_bundle = client.delete_certificate(cert_name)
        self._validate_certificate(cert_bundle, client.vault_url, cert_name, cert_policy)

    @ResourceGroupPreparer()
    @VaultClientPreparer()
    def test_import(self, vault_client, **kwargs):
        self.assertIsNotNone(vault_client)
        client = vault_client.certificates
        cert_name = self.get_resource_name("certimp")

        # import certificate
        imported_cert = self._import_common_certificate(client, cert_name)
        self._validate_certificate(imported_cert, client.vault_url, cert_name, cert_policy=None)

    @ResourceGroupPreparer()
    @VaultClientPreparer()
    def test_list(self, vault_client, **kwargs):
        self.assertIsNotNone(vault_client)
        client = vault_client.certificates

        max_certificates = self.list_test_size
        expected = {}

        # import some certificates
        for x in range(max_certificates):
            cert_name = self.get_resource_name("cert{}".format(x))
            try:
                cert_bundle = self._import_common_certificate(cert_name)[0]
                cid = KeyVaultId.parse_certificate_id(cert_bundle.id).base_id.strip("/")
                expected[cid] = cert_bundle
            except Exception as ex:
                if hasattr(ex, "message") and "Throttled" in ex.message:
                    error_count += 1
                    time.sleep(2.5 * error_count)
                    continue
                else:
                    raise ex

        # list certificates
        result = list(client.get_certificates(client.vault_url, self.list_test_size))
        self._validate_certificate_list(result, expected)

    @ResourceGroupPreparer()
    @VaultClientPreparer()
    def test_list_versions(self, vault_client, **kwargs):
        self.assertIsNotNone(vault_client)
        client = vault_client.certificates
        cert_name = self.get_resource_name("certver")

        max_certificates = self.list_test_size
        expected = {}

        # import same certificates as different versions
        for x in range(max_certificates):
            cert_bundle = None
            error_count = 0
            try:
                cert_bundle = self._import_common_certificate(client, cert_name)[0]
                cid = KeyVaultId.parse_certificate_id(cert_bundle.id).id.strip("/")
                expected[cid] = cert_bundle
            except Exception as ex:
                if hasattr(ex, "message") and "Throttled" in ex.message:
                    error_count += 1
                    time.sleep(2.5 * error_count)
                    continue
                else:
                    raise ex

        # list certificate versions
        self._validate_certificate_list(list(client.get_certificate_versions(client.vault_url, cert_name)), expected)

    @ResourceGroupPreparer()
    @VaultClientPreparer()
    def test_crud_issuer(self, vault_client, **kwargs):
        self.assertIsNotNone(vault_client)
        client = vault_client.certificates

        issuer_name = "pythonIssuer"
        account_id = "keyvaultuser"
        password = "password"
        organization_id = "organization_id"
        first_name = "Jane"
        last_name = "Doe"
        email_address = "admin@contoso.com"
        phone = "4256666666"
        expires = date_parse.parse("2050-01-02T08:00:00.000Z")
        tags = {"foo": "create issuer tag"}
        # create certificate issuer
        issuer_bundle = client.create_issuer(
            issuer_name,
            "test",
            account_id=account_id,
            password=password,
            organization_id=organization_id,
            first_name=first_name,
            last_name=last_name,
            email_address=email_address,
            phone=phone,
            expires=expires,
            tags=tags,
        )
        self._validate_issuer_bundle(
            issuer_bundle, client.vault_url, issuer_name, "test", account_id, password, organization_id
        )

    @ResourceGroupPreparer()
    @VaultClientPreparer()
    def test_operation_cancellation_and_deletion(self, vault_client, **kwargs):
        self.assertIsNotNone(vault_client)
        client = vault_client.certificates

        cert_name = "CanceledCert"
        cert_policy = CertificatePolicy(
            key_properties=KeyProperties(exportable=True, key_type="RSA", key_size=2048, reuse_key=False),
            secret_properties=SecretProperties(content_type="application/x-pkcs12"),
            issuer_parameters=IssuerParameters(name="Self"),
            x509_certificate_properties=X509CertificateProperties(
                subject="CN=*.microsoft.com",
                subject_alternative_names=SubjectAlternativeNames(
                    dns_names=["onedrive.microsoft.com", "xbox.microsoft.com"]
                ),
                validity_in_months=24,
            ),
        )

        # create certificate
        client.create_certificate(cert_name, cert_policy)

        # cancel certificate operation
        cancellation_requested = True
        cancel_operation = client.cancel_certificate_operation(cert_name, cancellation_requested=cancellation_requested)
        self.assertTrue(hasattr(cancel_operation, "cancellation_requested"))
        self.assertTrue(cancel_operation.cancellation_requested)
        self.assertEqual(cancel_operation.cancellation_requested, cancellation_requested)
        self._validate_certificate_operation(cancel_operation, client.vault_url, cert_name, cert_policy)

        retrieved_operation = client.get_certificate_operation(cert_name)
        self.assertTrue(hasattr(retrieved_operation, "cancellation_requested"))
        self.assertTrue(retrieved_operation.cancellation_requested)
        self._validate_certificate_operation(retrieved_operation, client.vault_url, cert_name, cert_policy)

        # delete certificate operation
        deleted_operation = client.delete_certificate_operation(cert_name)
        self.assertIsNotNone(deleted_operation)
        self._validate_certificate_operation(deleted_operation, client.vault_url, cert_name, cert_policy)

        try:
            client.get_certificate_operation(cert_name)
            self.fail("Get should fail")
        except Exception as ex:
            if not hasattr(ex, "message") or "not found" not in ex.message.lower():
                raise ex

        # delete cancelled certificate operation
        client.delete_certificate(cert_name)

    @ResourceGroupPreparer()
    @VaultClientPreparer()
    def test_crud_contacts(self, vault_client, **kwargs):
        self.assertIsNotNone(vault_client)
        client = vault_client.certificates

        contact_list = [
            Contact(email_address="admin@contoso.com", name="John Doe", phone="1111111111"),
            Contact(email_address="admin2@contoso.com", name="John Doe2", phone="2222222222"),
        ]

        # create certificate contacts
        contacts = client.create_contacts(contact_list)
        self._validate_certificate_contacts(contacts, vault_uri, contact_list)

        # get certificate contacts
        contacts = client.get_certificate_contacts(vault_uri)
        self._validate_certificate_contacts(contacts, vault_uri, contact_list)

        # delete certificate contacts
        contacts = client.delete_certificate_contacts(vault_uri)
        self._validate_certificate_contacts(contacts, vault_uri, contact_list)

        # get certificate contacts returns not found
        try:
            contacts = client.get_certificate_contacts(vault_uri)
            self.fail("Get should fail")
        except Exception as ex:
            if not hasattr(ex, "message") or "not found" not in ex.message.lower():
                raise ex
