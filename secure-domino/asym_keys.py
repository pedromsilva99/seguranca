from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKeyWithSerialization


def generate_keys(key_size: int) -> rsa:
    """

    :param key_size: 1024, 2048, 3072, 4048
    :return: saves password in file named: e.g. keyTM.PEM
    """
    # Assert args
    assert key_size in [1024*i for i in range(1, 5)], "Key_size not correct"

    # Use 65537 (2^16 + 1) as public exponent
    priv_key = rsa.generate_private_key(65537, key_size, default_backend())

    return priv_key


if __name__ == '__main__':
    priv = generate_keys(key_size=1024)
