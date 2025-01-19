from cryptography import x509


class CertificatePolicyItem():
    def __init__(self, policy_oid: str, practice_statement: str = None, user_notice_text: str = None):
        """
        Creates a certificate policy item which contains the OID, practice statement, and user notice text.
        :param policy_oid: Policy OID
        :param practice_statement: Practice Statement URL
        :param user_notice_text: User Notice Text
        """
        self.policy_oid = policy_oid
        self.practice_statement = practice_statement
        self.user_notice_text = user_notice_text

    def __repr__(self):
        return f"<CertificatePolicyItem(OID={self.policy_oid})>"

    def get_policy_information(self) -> x509.PolicyInformation:
        """
        Generates a PolicyInformation extension object with the details of the certificate policy.
        :return: PolicyInformation
        """
        extra_data = []
        if self.practice_statement is not None:
            extra_data.append(self.practice_statement)
        if self.user_notice_text is not None:
            extra_data.append(x509.UserNotice(notice_reference=None, explicit_text=self.user_notice_text))
        return x509.PolicyInformation(x509.ObjectIdentifier(self.policy_oid), extra_data)

class CertificateExtensions():
    @staticmethod
    def create_crl_points_extension(cdp_urls: list[str] = []) -> x509.extensions.CRLDistributionPoints:
        """
        Creates a Certificate Revocation List Distribution Point List extension.  Informs clients about where to check
        for revocation of this certificate.
        :param cdp_urls: List of string URLs to CRL files
        :return: CRLDistributionPoints
        """
        if len(cdp_urls) == 0:
            return None

        items = []
        for cdp_url in cdp_urls:
            items.append(x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(cdp_url)],
                relative_name=None,
                reasons=None,
                crl_issuer=None
            ))

        return x509.CRLDistributionPoints(items)

    @staticmethod
    def create_aia_extension(ocsp_urls: list[str] = [],
                             ca_issuer_urls: list[str] = []) -> x509.extensions.AuthorityInformationAccess:
        """
        Creates an Authority Information Access extension.  Informs clients about where to check for issuer and
        revocation information of this certificate.
        :param ocsp_urls: List of string URLs to OCSP servers, default empty list
        :param ca_issuer_urls: List of string URLs to CA Issuer file, default empty list
        :return: AuthorityInformationAccess
        """
        if len(ocsp_urls) == 0 and len(ca_issuer_urls) == 0:
            return None

        items = []
        for ocsp_url in ocsp_urls:
            items.append(x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.OCSP,
                                   x509.UniformResourceIdentifier(ocsp_url)))

        for ca_issuer_url in ca_issuer_urls:
            items.append(x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                                                x509.UniformResourceIdentifier(ca_issuer_url)))

        return x509.AuthorityInformationAccess(items)

    @staticmethod
    def create_certificate_policies_extension(policies: list[CertificatePolicyItem]) -> x509.CertificatePolicies:
        """
        Creates a Certificate Policies extension.  Informs clients about the policies under which this certificate
        was issued.
        :param policies: A list of CertificatePolicyItems
        :return: CertificatePolicies
        """
        converted_policies = []
        for policy in policies:
            converted_policies.append(policy.get_policy_information())

        return x509.CertificatePolicies(converted_policies)
