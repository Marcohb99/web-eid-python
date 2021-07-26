import src.controller.inputOutput as inputOutput
import src.controller.command_handler.readCertificate as readCertificate
import src.controller.command_handler.signauthutils as utils
import src.controller.logger as logger
import cryptography.hazmat.primitives.serialization as serialization
import cryptography.x509.oid as oid
import sys
import json


def run(arguments):
    try:
        if len(arguments) != 2:
            logger.log_error(
                __name__ + "argument must be {type: auth/sign, origin: <origin URL>}")
            sys.exit(0)
        if arguments["type"] != "auth" and arguments["type"] != "sign":
            logger.log_error(
                __name__ + " argument type must be either 'auth' or 'sign'")
            sys.exit(0)

        cert64, cert, sig_algo, priv_key, pub_key_pem = readCertificate.run(
            serialization.Encoding.PEM)

        #MIRAR signautils.cpp :: signatureAlgoToVariantMap() DE APP NATIVA ORIGINAL
        algos = utils.signature_algo_to_dict(cert.signature_algorithm_oid)
        subject = cert.subject.get_attributes_for_oid(
            oid.NameOID.COMMON_NAME)[0].value
        origin = json.dumps(arguments['origin'])
        send_certificate(cert64, [algos])
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def send_certificate(cert, algos):
    try:
        full_encoded_message = inputOutput.encode_native(
            {"certificate": cert, "supported-signature-algos": algos})
        inputOutput.send_message(full_encoded_message)
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)
