import pytz
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.x509.oid import NameOID
import datetime
from .CertificateUtils import CertificateUtils


# Custom exceptions
class PrivateKeyUnavailableError(Exception):
    def __init__(self):
        super().__init__("The private key is protected or not loaded!")


class CertificateUnknownError(Exception):
    def __init__(self):
        super().__init__("The referenced certificate is not loaded or is otherwise unknown.")


class CertificateAuthority():
    def __init__(self, ca_certificate: x509.Certificate, issuer_certificate=None, ca_private_key=None,
                 key_exportable: bool = True):
        """
        Create a new instance of a Certificate Authority.
        :param ca_certificate: Certificate Authority Certificate
        :param issuer_certificate: Issuer Certificate or Issuer CertificateAuthority
        :param ca_private_key: PrivateKey of the CA, optional
        :param key_exportable: Permit exporting of the CA private key, default True
        """
        self.ca_certificate = ca_certificate
        if issuer_certificate is not None and type(issuer_certificate) is CertificateAuthority:
            self.issuer_ca = issuer_certificate
        else:
            if issuer_certificate is None:
                self.issuer_ca = None
            else:
                self.issuer_ca = CertificateAuthority(issuer_certificate)
        self.ca_private_key = ca_private_key
        self.key_exportable = key_exportable
        self.standard_nc_extensions = []
        self.standard_c_extensions = []

    def load_private_key(self, private_key, key_exportable: bool = True):
        """
        Loads a CA private key after the CertificateAuthority has already been loaded.
        :param private_key: Private key of the CA
        :param key_exportable: Permit exporting of the CA private key, default True
        """
        self.ca_private_key = private_key
        self.key_exportable = key_exportable

    def get_ca_certificate(self) -> x509.Certificate:
        """
        Returns the CA certificate.
        :return: Certificate
        """
        return self.ca_certificate

    def get_ca_subject(self) -> x509.Name:
        """
        Returns the CA certificate subject name.
        :return: Name
        """
        return self.get_ca_certificate().subject

    def get_common_name(self) -> str:
        """
        Returns the first common name (CN) in the subject of the CA certificate.
        :return: CN string
        """
        return self.get_ca_subject().get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    def get_not_valid_before(self) -> datetime.datetime:
        """
        Returns the Not Valid Before timestamp in UTC timezone.
        :return: datetime
        """
        return self.get_ca_certificate().not_valid_before_utc

    def get_not_valid_after(self) -> datetime.datetime:
        """
        Returns the Not Valid After timestamp in UTC timezone.
        :return: datetime
        """
        return self.get_ca_certificate().not_valid_after_utc

    def has_private_key(self) -> bool:
        """
        Determines if the CertificateAuthority object has the CA private key available to use.
        :return: bool
        """
        if self.ca_private_key is None:
            return False
        return True

    def __repr__(self):
        common_name = self.get_common_name()
        try:
            issuer_common_name = self.get_issuer_ca().get_common_name()
        except:
            issuer_common_name = "unknown"
        return f"<CertificateAuthority(CN={common_name}, issuer={issuer_common_name}, has_key={self.has_private_key()})>"

    def get_issuer_ca(self):
        """
        Returns the issuer CertificateAuthority object if available.  Raises CertificateUnknownError if unavailable.
        :return: CertificateAuthority
        """
        if self.get_ca_certificate().subject == self.get_ca_certificate().issuer:
            return self
        if self.issuer_ca is None:
            raise CertificateUnknownError()
        return self.issuer_ca

    def get_issuer_certificate(self) -> x509.Certificate:
        """
        Returns the issuer Certificate if available.  Raises CertificateUnknownError if unavailable.
        :return: Certificate
        """
        return self.get_issuer_ca().get_ca_certificate()

    def get_ca_private_key(self):
        """
        Returns the CA private key if available.  Raises PrivateKeyUnavailableError if unavailable.
        :return: PrivateKey
        """
        if self.ca_private_key is None:
            raise PrivateKeyUnavailableError()
        if not self.key_exportable:
            raise PrivateKeyUnavailableError()

        return self.ca_private_key

    def get_standard_extensions(self) -> list:
        """
        Returns a list of all extensions that will be added to requests to this CA.
        :return: list of extensions
        """
        return self.standard_nc_extensions + self.standard_c_extensions

    def get_standard_noncritical_extensions(self) -> list:
        """
        Returns a list of all non-critical extensions that will be added to requests to this CA.
        :return: list of extensions
        """
        return self.standard_nc_extensions

    def get_standard_critical_extensions(self) -> list:
        """
        Returns a list of all critical extensions that will be added to requests to this CA.
        :return: list of extensions
        """
        return self.standard_c_extensions

    def add_standard_extension(self, extension, critical: bool = False):
        """
        Adds a standard extension to the list.  Standard extensions will be added to all leaf certificates by default.
        :param extension: Extension to add
        :param critical: If the extension should be listed as critical
        """
        if critical:
            self.standard_c_extensions.append(extension)
        else:
            self.standard_nc_extensions.append(extension)

    def remove_standard_extension(self, extension):
        """
        Remove a standard extension from the list.
        :param extension: Extension to remove
        """
        self.standard_c_extensions.pop(extension)
        self.standard_nc_extensions.pop(extension)

    def create_intermediate_ca(self, subject: x509.Name, private_key=None, private_key_size: int = 2048,
                               serial_number: int = None, basic_constraints: x509.BasicConstraints = None,
                               not_valid_before: datetime.datetime = None, not_valid_after: datetime.datetime = None,
                               key_exportable: bool = True, hash_algo: HashAlgorithm = hashes.SHA256(),
                               extensions: list = []):
        """
        Creates a new intermediate certificate authority under this authority.
        :param subject: Subject of the new CA
        :param private_key: Private key to use, default None will generate a new keypair
        :param private_key_size: Key size to generate if private_key is not provided
        :param serial_number: Serial number of new CA certificate
        :param basic_constraints: Basic constraints of the new CA, default CA:True
        :param not_valid_before: Not Valid Before time of the new CA, default -1 minute
        :param not_valid_after: Not Valid After time of the new CA, default not_before + 720d
        :param key_exportable: Permit exporting of the CA private key, default True
        :param hash_algo: Hashing algorithm to use on this CA certificate, default SHA256
        :param extensions: List of additional extensions to add to this CA certificate only
        :return: CertificateAuthority
        """
        if private_key is None:
            private_key = CertificateUtils.generate_rsa_private_key(private_key_size)
        request = CertificateUtils.generate_certificate_request(private_key, subject)
        ca = self.create_intermediate_ca_with_request(request, subject, serial_number, basic_constraints,
                                                        not_valid_before, not_valid_after, hash_algo, extensions)
        ca.load_private_key(private_key, key_exportable)
        return ca

    def create_intermediate_ca_with_request(self, request: x509.CertificateSigningRequest, subject: x509.Name,
                               serial_number: int = None, basic_constraints: x509.BasicConstraints = None,
                               not_valid_before: datetime.datetime = None, not_valid_after: datetime.datetime = None,
                               hash_algo: HashAlgorithm = hashes.SHA256(), extensions: list = []):
        """
        Creates a new intermediate certificate authority under this authority.
        :param request: CertificateSigningRequest for the new CA certificate
        :param subject: Subject of the new CA
        :param serial_number: Serial number of new CA certificate
        :param basic_constraints: Basic constraints of the new CA, default CA:True
        :param not_valid_before: Not Valid Before time of the new CA, default -1 minute
        :param not_valid_after: Not Valid After time of the new CA, default not_before + 720d
        :param hash_algo: Hashing algorithm to use on this CA certificate, default SHA256
        :param extensions: List of additional extensions to add to this CA certificate only
        :return: CertificateAuthority
        """
        if self.ca_private_key is None:
            raise PrivateKeyUnavailableError()

        if basic_constraints is None:
            # If no constraints specified, assume certificate authority with unlimited length
            basic_constraints = x509.BasicConstraints(ca=True, path_length=None)

        if serial_number is None:
            # If no serial number specified, use random
            serial_number = x509.random_serial_number()

        if not_valid_before is None:
            not_valid_before = datetime.datetime.utcnow() + datetime.timedelta(minutes=-1)

        if not_valid_after is None:
            not_valid_after = datetime.datetime.utcnow() + datetime.timedelta(days=730, minutes=-1)

        key_usage = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )
        ext_key_usage = x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE
        ])
        certificate = self.sign_request(request, subject, subject_alternative_names=[], key_usage=key_usage,
                                        serial_number=serial_number, basic_constraints=basic_constraints,
                                        ext_key_usage=ext_key_usage, not_valid_before=not_valid_before,
                                        not_valid_after=not_valid_after, hash_algo=hash_algo, extensions=extensions)
        return CertificateAuthority(certificate, issuer_certificate=self, key_exportable=False)

    def sign_request(self, certificate_request: x509.CertificateSigningRequest, subject: x509.Name = None,
                     subject_alternative_names: list = None, key_usage: x509.KeyUsage = None,
                     serial_number: int = None, basic_constraints: x509.BasicConstraints = None,
                     ext_key_usage: x509.ExtendedKeyUsage = None, not_valid_before: datetime.datetime = None,
                     not_valid_after: datetime.datetime = None, hash_algo: HashAlgorithm = hashes.SHA256(),
                     extensions: list = []) -> x509.Certificate:
        """
        Signs a provided certificate request.  Used to create a new leaf certificate.
        Optionally, override the subject, subject alternative names, and key_usage.
        :param certificate_request: Certificate Request to sign
        :param subject: Subject name to add to the certificate, default use CSR subject
        :param subject_alternative_names: Subject alternative names to add, default use common name
        :param key_usage: Key usage permitted, default Digital signature only
        :param serial_number: Serial number of the certificate, default random
        :param basic_constraints: Basic constraints of the certificate, default CA:False
        :param ext_key_usage: Extended key usage of the certificate, default SERVER_AUTH and CLIENT_AUTH
        :param not_valid_before: Not Valid Before time of the new certificate, default -1 minute
        :param not_valid_after: Not Valid After time of the new certificate, default not_before + 365d
        :param hash_algo: Hashing algorithm to use on the certificate, default SHA256
        :param extensions: List of extensions to add to this certificate only
        :return: Certificate
        """
        if self.ca_private_key is None:
            raise PrivateKeyUnavailableError()

        if subject is None:
            # If subject is not specified, use subject from request
            subject = certificate_request.subject

        if basic_constraints is None:
            # If no constraints specified, assume leaf certificate
            basic_constraints = x509.BasicConstraints(ca=False, path_length=None)

        if serial_number is None:
            # If no serial number specified, use random
            serial_number = x509.random_serial_number()

        if not_valid_before is None:
            not_valid_before = datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=-1)

        if not_valid_after is None:
            not_valid_after = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365, minutes=-1)

        if not_valid_before.tzinfo is None:
            not_valid_before = pytz.UTC.localize(not_valid_before)
        if not_valid_after.tzinfo is None:
            not_valid_after = pytz.UTC.localize(not_valid_after)

        # If the CA expiration is before the end of this cert, limit it to the CA -1 min
        if not_valid_after > self.get_not_valid_after():
            not_valid_after = self.get_not_valid_after() + datetime.timedelta(minutes=-1)

        if subject_alternative_names is None:
            try:
                common_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

                subject_alternative_names = [x509.DNSName(common_name)]
                if common_name[0:4] == "www.":
                    subject_alternative_names.append(x509.DNSName(common_name[4:])) # strip the www
            except:
                subject_alternative_names = []

        if key_usage is None:
            key_usage = x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        if ext_key_usage is None:
            ext_key_usage = x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
            ])

        # Create the certificate builder
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(self.ca_certificate.subject)
        builder = builder.public_key(certificate_request.public_key())
        builder = builder.serial_number(serial_number)
        builder = builder.not_valid_before(not_valid_before)
        builder = builder.not_valid_after(not_valid_after)

        # Add extensions
        builder = builder.add_extension(basic_constraints, critical=True)
        builder = builder.add_extension(ext_key_usage, critical=False)
        builder = builder.add_extension(key_usage, critical=True)

        if len(subject_alternative_names) > 0:
            builder = builder.add_extension(x509.SubjectAlternativeName(subject_alternative_names), critical=False)

        # Key identifiers
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(self.get_ca_certificate().public_key())
        builder = builder.add_extension(aki, critical=False)
        ski = x509.SubjectKeyIdentifier.from_public_key(certificate_request.public_key())
        builder = builder.add_extension(ski, critical=False)

        # Add any other standard extensions
        for extension in self.get_standard_noncritical_extensions():
            builder = builder.add_extension(extension, critical=False)
        for extension in self.get_standard_critical_extensions():
            builder = builder.add_extension(extension, critical=True)

        # Add specific additional extensions
        for extension in extensions:
            builder = builder.add_extension(extension, critical=False)

        # Sign the certificate
        certificate = builder.sign(
            private_key=self.ca_private_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        return certificate


class CertificateAuthorityFactory():
    @staticmethod
    def create_self_signed_ca(subject: x509.Name, private_key=None, private_key_size: int = 2048,
                              serial_number: int = None, not_valid_before: datetime.datetime = None,
                              not_valid_after: datetime.datetime = None,
                              hash_algo: HashAlgorithm = hashes.SHA256(),
                              key_exportable: bool = True) -> CertificateAuthority:
        """
        Creates a new self-signed certificate authority.
        :param subject: Subject name for the new certificate
        :param private_key: Existing private key to use, default None
        :param private_key_size: Size of RSA key to generate if private_key is not provided, default 2048
        :param serial_number: Serial number for the new certificate, default generates random
        :param not_valid_before: Not Valid Before date for new certificate, default now - 1 minute
        :param not_valid_after: Not Valid After date for the new certificate, default not_before + 3650 days
        :param hash_algo: Hashing algorithm to use in the certificate, default SHA256
        :param key_exportable: If the key export methods should be available, default True
        :return: CertificateAuthority
        """
        if private_key is None:
            private_key = CertificateUtils.generate_rsa_private_key(private_key_size)

        if serial_number is None:
            serial_number = x509.random_serial_number()

        if not_valid_before is None:
            not_valid_before = datetime.datetime.utcnow() + datetime.timedelta(minutes=-1)

        if not_valid_after is None:
            not_valid_after = datetime.datetime.utcnow() + datetime.timedelta(days=3650, minutes=-1)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(subject)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(serial_number)
        builder = builder.not_valid_before(not_valid_before)
        builder = builder.not_valid_after(not_valid_after)

        key_usage = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )

        basic_constraints = x509.BasicConstraints(ca=True, path_length=None)
        builder = builder.add_extension(basic_constraints, critical=True)
        ext_key_usage = x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE
        ])
        builder = builder.add_extension(ext_key_usage, critical=False)
        builder = builder.add_extension(key_usage, critical=True)
        ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        builder = builder.add_extension(ski, critical=False)

        certificate = builder.sign(
            private_key=private_key, algorithm=hash_algo, backend=default_backend()
        )
        return CertificateAuthority(certificate, ca_private_key=private_key, key_exportable=key_exportable)
