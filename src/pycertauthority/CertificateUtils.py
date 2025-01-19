from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class CertificateUtils():
    @staticmethod
    def generate_rsa_private_key(key_size: int = 2048) -> rsa:
        """
        Generates a new RSA private key with the specified size.
        :param key_size: Key size, default 2048
        :return: RSA private key
        """
        return rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )

    @staticmethod
    def generate_certificate_request(private_key, subject: x509.Name) -> x509.CertificateSigningRequest:
        """
        Generates a new certificate request with the specified key and subject name.
        :param private_key: Private key to sign the request with
        :param subject: Subject name to include in the request
        :return: CertificateSigningRequest
        """
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject)
        return builder.sign(private_key, hashes.SHA256(), default_backend())

    @staticmethod
    def read_certificate_from_file(path: str) -> x509.Certificate:
        """
        Loads a PEM formatted certificate from file.
        :param path: File path to the certificate.
        :return: Certificate
        """
        with open(path, "rb") as f:
            certificate = x509.load_pem_x509_certificate(f.read(), default_backend())
        return certificate

    @staticmethod
    def read_private_key_from_file(path: str, password: str = None):
        """
        Loads a PEM formatted private key from file.
        :param path: File path to the private key.
        :param password: Password to decrypt the key with, optional, default None
        :return: PrivateKey
        """
        with open(path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=password, backend=default_backend()
            )
        return private_key

    @staticmethod
    def read_certificate_request_from_file(path: str) -> x509.CertificateSigningRequest:
        """
        Loads a PEM certificate signing request from file.
        :param path: File path to the certificate request.
        :return: CertificateSigningRequest
        """
        with open(path, "rb") as f:
            request = x509.load_pem_x509_csr(f.read(), default_backend())
        return request

    @staticmethod
    def write_certificate_request_to_file(path: str, certificate_request: x509.CertificateSigningRequest):
        """
        Writes a certificate signing request to a PEM-formatted file.
        :param path: File path to the certificate request.
        :param certificate_request: Certificate Signing Request to Write
        """
        with open(path, "wb") as f:
            f.write(certificate_request.public_bytes(serialization.Encoding.PEM))
            f.flush()

    @staticmethod
    def write_certificate_to_file(path: str, certificate: x509.Certificate):
        """
        Writes a certificate object to a PEM-formatted file.
        :param path: File path to the certificate file.
        :param certificate: Certificate to Write
        """
        with open(path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
            f.flush()

    @staticmethod
    def write_private_key_to_file(path, private_key, password=None):
        """
        Writes a private key object to a PEM-formatted file.
        :param path: File path to the private key file.
        :param private_key: Private Key to Write
        :param password: Optional password to encrypt the private key
        """
        if password is None:
            algo = serialization.NoEncryption()
        else:
            algo = serialization.BestAvailableEncryption(password)

        with open(path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=algo
                )
            )
            f.flush()