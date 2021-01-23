import PyKCS11 as pk
import PyKCS11.LowLevel as pkll
from Vale import utils
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa, utils
)


if __name__ == '__main__':

    pkcs11 = utils.load_pkcs11()

    slots = pkcs11.getSlotList()

    classes = {
        pkll.CKO_PRIVATE_KEY: 'private key',
        pkll.CKO_PUBLIC_KEY: 'public key',
        pkll.CKO_CERTIFICATE: 'certificate'
    }

    # for making signatures with the cc
    for slot in slots:
        if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
            session = pkcs11.openSession(slot)
            objects = session.findObjects()
            for obj in objects:
                label = session.getAttributeValue(obj, [pkll.CKA_LABEL])[0]
                clas = session.getAttributeValue(obj, [pkll.CKA_CLASS])[0]
                print(f"Object with label {label}, of class {classes[clas]}")

    # Creating a digital signature
    for slot in slots:
        if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
            data = bytes('data to be signed', 'utf-8')

            session.pykcs11.openSession(slot)

            privKey = session.findObjects(
                [
                    (pkll.CKA_CLASS, pkll.CKO_PRIVATE_KEY),
                    (pkll.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
                ]
            )[0]
            signature = bytes(session.sign(privKey, data, pk.Mechanism(pkll.CKM_SHA1_RSA_PKCS)))

            session.closeSession()

            # cryptography.hazmat code
            ...

