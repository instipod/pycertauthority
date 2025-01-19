#!python3
import datetime
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes
from pycertauthority.CertificateAuthority import CertificateAuthorityFactory
from pycertauthority.CertificateUtils import CertificateUtils
from pycertauthority.CertificateExtensions import CertificateExtensions, CertificatePolicyItem

# Emulates a PKI setup similar to the Federal PKI system in the U.S.
# Some extensions are not yet supported that the FPKI system uses:
# Subject Information Access, Policy Constraints, Inhibit Any Policy


# Create the root CA
fed_root_expires = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365*20, minutes=-1)
fed_root_ca_subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "Federal Common Policy CA G2"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "FPKI"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Atlantis Government"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "AT")
])
fed_root_ca = CertificateAuthorityFactory.create_self_signed_ca(fed_root_ca_subject, private_key_size=4096,
                                                                not_valid_after=fed_root_expires,
                                                                hash_algo=hashes.SHA384())
CertificateUtils.write_certificate_to_file("../fed_root.crt", fed_root_ca.get_ca_certificate())

fed_root_ca.add_standard_extension(
    CertificateExtensions.create_aia_extension([], [
        "http://fedpki.gov.at.example.com/rootg2.crt"
    ]), False)
fed_root_ca.add_standard_extension(
    CertificateExtensions.create_crl_points_extension([
        "http://fedpki.gov.at.example.com/rootg2.crl"
    ]), False)

# Create the vendor intermediate CA
int1_expires = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365*8, minutes=-1)
int1_subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "SuperCertCo Federal Intermediate CA G1"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SuperCertCo, Inc."),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "AT")
])
int1_policies = CertificateExtensions.create_certificate_policies_extension([
    CertificatePolicyItem("2.16.840.1.101.3.2.1.3.6"),
    CertificatePolicyItem("2.16.840.1.101.3.2.1.3.16")
])
int1_ca = fed_root_ca.create_intermediate_ca(int1_subject, private_key_size=2048, not_valid_after=int1_expires,
                                             hash_algo=hashes.SHA384(), extensions=[int1_policies])
CertificateUtils.write_certificate_to_file("../int1.crt", int1_ca.get_ca_certificate())

int1_ca.add_standard_extension(
    CertificateExtensions.create_aia_extension([], [
        "http://fedpki.gov.at.example.com/int1.crt"
    ]), False)
int1_ca.add_standard_extension(
    CertificateExtensions.create_crl_points_extension([
        "http://fedpki.gov.at.example.com/int1.crl"
    ]), False)

# Create the agency intermediate CA
int2_expires = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365*8, minutes=-1)
int2_subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "AT Department of Interior Agency CA 1"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Atlantis Department of Interior"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Atlantis Government"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "AT")
])
int2_policies = CertificateExtensions.create_certificate_policies_extension([
    CertificatePolicyItem("2.16.840.1.101.3.2.1.3.6"),
    CertificatePolicyItem("2.16.840.1.101.3.2.1.3.16")
])
int2_constraints = x509.BasicConstraints(ca=True, path_length=0)
int2_ca = int1_ca.create_intermediate_ca(int2_subject, private_key_size=2048, not_valid_after=int2_expires,
                                             basic_constraints=int2_constraints, extensions=[int2_policies])
CertificateUtils.write_certificate_to_file("../int2.crt", int2_ca.get_ca_certificate())

int2_ca.add_standard_extension(
    CertificateExtensions.create_aia_extension([
        "http://fedpki.gov.at.example.com/ocsp2"
    ], [
        "http://fedpki.gov.at.example.com/int2.crt"
    ]), False)
int2_ca.add_standard_extension(
    CertificateExtensions.create_crl_points_extension([
        "http://fedpki.gov.at.example.com/int2.crl"
    ]), False)

# Create a leaf certificate
leaf_expires = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365, minutes=-1)
leaf_subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "housing.gov.at.example.com"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Atlantis Department of Interior"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Atlantis Government"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "AT")
])
leaf_policies = CertificateExtensions.create_certificate_policies_extension([
    CertificatePolicyItem("2.16.840.1.101.3.2.1.3.6"),
    CertificatePolicyItem("2.16.840.1.101.3.2.1.3.16")
])
leaf_private_key = CertificateUtils.generate_rsa_private_key(2048)
leaf_request = CertificateUtils.generate_certificate_request(leaf_private_key, leaf_subject)
leaf_cert = int2_ca.sign_request(leaf_request, leaf_subject, not_valid_after=leaf_expires)
CertificateUtils.write_certificate_to_file("../leaf.crt", leaf_cert)
