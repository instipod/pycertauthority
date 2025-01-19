#!python3
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from CertificateAuthority import CertificateAuthorityFactory
from CertificateUtils import CertificateUtils
from CertificateExtensions import CertificateExtensions, CertificatePolicyItem

# Create a root CA
subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")
])
root_ca = CertificateAuthorityFactory.create_self_signed_ca(subject)
CertificateUtils.write_certificate_to_file("../root.crt", root_ca.get_ca_certificate())

# Create an intermediate CA
subject2 = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA")
])
basic_constraints = x509.BasicConstraints(ca=True, path_length=0)
intermediate_ca = root_ca.create_intermediate_ca(subject2, basic_constraints=basic_constraints)
CertificateUtils.write_certificate_to_file("../intermediate.crt", intermediate_ca.get_ca_certificate())

# Add some standard extensions to the intermediate
crl_points = CertificateExtensions.create_crl_points_extension(["http://ca.example.com/crl.crl"])
intermediate_ca.add_standard_extension(crl_points, False)
aia = CertificateExtensions.create_aia_extension(["http://ocsp.example.com"], ["http://ca.example.com/issuer.crt"])
intermediate_ca.add_standard_extension(aia, False)

# Create a leaf certificate
subject3 = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "www.example.com")
])
policies = CertificateExtensions.create_certificate_policies_extension([
    CertificatePolicyItem("1.1.1", "https://www.example.com", "Hello world")
])
private_key = CertificateUtils.generate_rsa_private_key()
request = CertificateUtils.generate_certificate_request(private_key, subject3)
certificate = intermediate_ca.sign_request(request, extensions=[policies])
CertificateUtils.write_certificate_to_file("../cert.crt", certificate)
