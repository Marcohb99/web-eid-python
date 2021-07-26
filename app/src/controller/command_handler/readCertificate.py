import src.controller.inputOutput as inputOutput
import src.controller.logger as logger
import src.controller.command_handler.signauthutils as utils
import cryptography.hazmat.primitives.serialization.pkcs12 as pkcs12
import cryptography.hazmat.primitives.serialization as serialization
from base64 import b64encode, b64decode
import sys
import os
import pathlib
import fnmatch
from dotenv import load_dotenv

""" ----- Certs and pws ------
MadDogOY.p12 : test                         --> sha1WithRSAEncryption not suported by pyjwt 
Ciudadano_autenticación_activo.pfx : 369258 --> expired
user_one.p12 : user_one                     --> only for signing
PruebaEmpleado4Activo.p12 : Giss2016        --> works fine
signout.p12 : test                          --> expired
"""

test_cert_dict = {
    "MadDogOY.p12": "test",
    "Ciudadano_autenticación_activo.pfx": "369258",
    "user_one.p12": "user_one",
    "PruebaEmpleado4Activo.p12": "Giss2016",
    "signout.p12": "test"
}

cert_file_name = "PruebaEmpleado4Activo.p12"
cert_pw = "Giss2016"


def run(cert_encoding):
    try:
        load_dotenv()
        logger.log_debug(os.getenv("USE_PERSONAL_CERT"))
        if os.getenv("USE_PERSONAL_CERT") == "True":
            ruta = os.getenv("PERSONAL_CERT_PATH")
            pw = os.getenv("PERSONAL_CERT_PW")
        else:
            ruta = read_testing_certificate()
            pw = test_cert_dict[os.getenv("TEST_CERT_NAME")]
        logger.log_debug(ruta)
        priv_key, cert, rest = pkcs12.load_key_and_certificates(
            (open(ruta, 'rb').read()), bytes(pw, "utf-8"))

        pub_key = cert.public_key()  # PUBLIC KEY
        pub_key_pem = pub_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

        sig_algo = utils.signature_algo_to_string(cert.signature_algorithm_oid)
        cert_bytes = cert.public_bytes(cert_encoding)
        cert64 = b64encode(cert_bytes).decode("utf-8")
        return cert64, cert, sig_algo, priv_key, pub_key_pem
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def read_testing_certificate():
    dir_path = pathlib.Path(__file__).parent.absolute()   # command_handler
    ctrl_path = pathlib.Path(dir_path).parent.absolute()  # controller
    src_path = pathlib.Path(ctrl_path).parent.absolute()  # src
    app_path = pathlib.Path(src_path).parent.absolute()   # app
    certs_path = ""

    for path, dirs, files in os.walk(app_path):
        certs_path = os.path.join(
            path, fnmatch.filter(dirs, 'certs')[0])  # other
        break

    ruta = ""
    for path, dirs, files in os.walk(certs_path):
        for f in fnmatch.filter(files, os.getenv("TEST_CERT_NAME")):
            ruta = os.path.abspath(os.path.join(path, f))
    return ruta
