from cryptography import x509


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
    def create_aia_extension(ocsp_urls: list[str] = [], ca_issuer_urls: list[str] = []) -> x509.extensions.AuthorityInformationAccess:
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