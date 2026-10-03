"""Generates the two demo PKIs (once, into .runtime/certs):

1. Interception CA -> cert for localhost. L1 presents it to the agent. The agent must trust this CA
   (that is what makes the proxy a man-in-the-middle the agent *agreed* to).
2. Mock public CA -> cert for api.anthropic.com. Only used by the mock upstream; L3 verifies it the same
   way it verifies the real api.anthropic.com chain in live mode.
"""
import datetime as dt
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from common import CERTS

INTERCEPT_CA = CERTS / "interception-ca.pem"
INTERCEPT_CERT, INTERCEPT_KEY = CERTS / "l1-localhost.pem", CERTS / "l1-localhost.key"
MOCK_CA = CERTS / "mock-public-ca.pem"
MOCK_CERT, MOCK_KEY = CERTS / "mock-api.anthropic.com.pem", CERTS / "mock-api.anthropic.com.key"


def _name(cn, org):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, org)])


def _ca(cn, org):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(_name(cn, org)).issuer_name(_name(cn, org))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def _leaf(ca_key, ca_cert, cn, org, dns, ips=()):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    san = [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (x509.CertificateBuilder()
            .subject_name(_name(cn, org)).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


def _write(path_cert, cert, path_key=None, key=None):
    path_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    if key is not None:
        path_key.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        path_key.chmod(0o600)


def ensure_certs():
    if all(p.exists() for p in (INTERCEPT_CA, INTERCEPT_CERT, INTERCEPT_KEY, MOCK_CA, MOCK_CERT, MOCK_KEY)):
        return False
    CERTS.mkdir(parents=True, exist_ok=True)
    ca_key, ca = _ca("Mandate Demo Interception CA", "HackYeah26 Mandate (demo)")
    key, cert = _leaf(ca_key, ca, "localhost", "Mandate L1 intercept", ["localhost"], ["127.0.0.1"])
    _write(INTERCEPT_CA, ca)
    _write(INTERCEPT_CERT, cert, INTERCEPT_KEY, key)
    ca_key, ca = _ca("Mock Public Root CA (demo)", "Mock Internet PKI")
    key, cert = _leaf(ca_key, ca, "api.anthropic.com", "Mock upstream", ["api.anthropic.com", "localhost"], ["127.0.0.1"])
    _write(MOCK_CA, ca)
    _write(MOCK_CERT, cert, MOCK_KEY, key)
    return True


if __name__ == "__main__":
    print("generated" if ensure_certs() else "already present", "->", CERTS)
