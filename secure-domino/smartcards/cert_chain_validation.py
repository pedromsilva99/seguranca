import sys
import OpenSSL.crypto as osc
import cryptography.x509 as x509
from datetime import datetime
from asn1crypto import pem
import requests


def load_from_url(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.content

    return None


def validate_ocsp(cert):
    raise NotImplementedError

def add_crl(root, cert, base=False, delta=False):
    c = x509.load_der_x509_certificate(osc.dump_certificate(osc.FILETYPE_ASN1, cert))
    if base:
        cdp = c.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
    elif delta:
        cdp = c.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.FRESHEST_CRL
        )
    else:
        return

    for dpoint in cdp.value:
        for url in dpoint.full_name:
            crl = osc.load_crl(
                osc.FILETYPE_ASN1, load_from_url(url.value)
            )
            root.add_crl(crl)


def main():
    if len(sys.argv) < 6:
        print("Usage: %s certificate year month dat chain_certificate [chain certificate]\n"
              % sys.argv[0], file=sys.stderr)
        sys.exit(1)

    # Create validation context (a X509Store object)
    root = osc.X509Store()

    # Set validation flags
    root.set_flags(
        osc.X509StoreFlags.X509_STRICT
    )

    # Set validation date
    d = datetime(
        year=int(sys.argv[2]), month=int(sys.argv[3]), day=int(sys.argv[4])
    )
    root.set_time(d)

    # Load certificates into validation context

    for i in range(5, len(sys.argv)):
        with open(sys.argv[i], 'rb') as cf:
            cf_bytes = cf.read()

            if pem.detect(cf_bytes):
                for _, _, der_bytes in pem.unarmor(cf_bytes, multiple=True):
                    cert = osc.load_certificate(osc.FILETYPE_ASN1, der_bytes)
                    if cert.get_subject() == cert.get_issuer():
                        root.add_cert(cert)
                    else:
                        intermediate.append(cert)
            else:
                cert = osc.load_certificate(osc.FILETYPE_ASN1, der_bytes)
                if cert.subject == cert.issuer:
                    root.add_cert(cert)
                else:
                    intermediate.append(cert)

    # Load certificate to validate
    with open(sys.argv[1], 'rb') as cf:
        cf_bytes = cf.read()

        if pem.detect(cf_bytes):
            cert = osc.load_certificate(osc.FILETYPE_PEM, cf_bytes)
        else:
            cert = osc.load_certificate(osc.FILETYPE_ASN1, cf_bytes)

    validator = osc.X509StoreContext(root, cert, intermediate)

    try:
        validator.verify_certificate()

        # Chain was build, let's do OCSP/CRL some checking

        print("chain:")
        chain = validator.get_verified_chain()

        # See what we hae in the chain certificates

        for cert in chain:
            # print CN field of certificate's subject

            for component in cert.get_subject().get_components():
                if component[0] == b"CN":
                    print("CN: %s"
                          % (str(component[1], 'utf8')))

            # Look in extension for OCSP/CRL information

            for i in range(cert.get_extension_count()):
                if cert.get_extension(i).get_short_name() == b"authorityInfoAccess":
                    validate_ocsp(cert)
                elif cert.get_extension(i).get_short_name() == b"crlDistributionPoints":
                    add_crl(root, cert, base=True)
                elif cert.get_extension(i).get_short_name() == b"freshestCRL":
                    add_crl(root, cert, delta=True)

        # Set validation flags to include CRL validations
        root.set_flags(osc.X509StoreFlags.CRL_CHECK_ALL)

        validator.verify_certificate()
        print("YES")

    except Exception as e:
        print("NO: %s" % e)


if __name__ == '__main__':
    main()
