from datetime import datetime
import src.controller.inputOutput as inputOutput
import src.controller.logger as logger
import src.controller.command_handler.readCertificate as readCertificate
import src.controller.command_handler.signauthutils as utils
import src.controller.command_handler.postRecord as postRecord
import cryptography.hazmat.primitives.serialization as serialization
import sys
import json
import cryptography.x509 as x509
from src.controller.commands import Command


def send_token(token):
    try:
        full_encoded_message = inputOutput.encode_native({'auth-token': token})
        inputOutput.send_message(full_encoded_message)
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def Authenticate(arguments):
    try:
        logger.log_info(
            __name__ + " authentication process started with arguments: " + json.dumps(arguments))
        if(len(arguments) != 3):
            logger.log_error("authenticate.Authenticate: Too few arguments")
            exit(0)

        nonce = json.dumps(arguments["nonce"])
        nonce = nonce[1:-1]
        if (len(nonce) < 32):
            logger.log_error("authenticate.Authenticate: nonce is too short")
            exit(0)

        if (len(nonce) > 128):
            logger.log_error("authenticate.Authenticate: nonce is too long")
            exit(0)

        origin = utils.validate_and_store_origin(arguments)
        origin_cert_obj, origin_cert_str = validate_and_store_certificate(
            arguments)
        logger.log_debug(__name__ + " Retrieving certificate")
        certificate, certificate_der, signature_algorithm, priv_key, pub_key_pem = readCertificate.run(
            serialization.Encoding.DER)

        logger.log_debug(__name__ + " Creating authentication token")
        token_header, token_payload = utils.create_authentication_token(
            certificate, certificate_der, signature_algorithm, nonce, origin, origin_cert_obj, origin_cert_str)

        logger.log_debug(__name__ + " Singing authentication token")
        token = utils.sign_token(token_header, token_payload,
                                 signature_algorithm, priv_key)

        subject_mail = utils.get_mail_from_cert(certificate_der)
        cert_fingerprint = utils.calculate_cert_fingerprint(
            certificate_der.public_bytes(serialization.Encoding.DER)).upper()

        #Build record data
        logger.log_info(__name__ + " Building record data")
        record_data = postRecord.build_record_data(
            token_payload, Command.AUTHENTICATE, subject_mail, cert_fingerprint, None)

        #save record locally
        logger.log_info(
            __name__ + " Saving record locally to eID record server")
        certificate_data = utils.cert_to_dict(
            certificate_der, subject_mail, cert_fingerprint)
        postRecord.save_record_local(record_data, certificate_data, None, None)

        # post to eID record server
        logger.log_info(__name__ + " Posting to eID record server")
        postRecord.run(token, record_data, "")

        logger.log_info(__name__ + " Sending token to eID record server")
        if(isinstance(token, bytes)):
            token = token.decode("utf-8")
        send_token(token)    
        logger.log_info(__name__ + " Token sent successfully.")
        sys.exit(0)
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def validate_and_store_certificate(arguments):
    origin_certificate = arguments["origin-cert"]
    if(origin_certificate == None):
        logger.log_error(__name__ + " : cant find a certificate")
        sys.exit(0)

    cert_str = "-----BEGIN CERTIFICATE-----\n"
    cert_str += origin_certificate
    cert_str += "\n"
    cert_str += "-----END CERTIFICATE-----"
    origin_cert_bytes = bytes(cert_str, "utf-8")
    # inputOutput.write_to_file([cert_str])
    cert_obj = x509.load_pem_x509_certificate(origin_cert_bytes)

    origin_cert_bytes = bytes(origin_certificate, "utf-8")

    now = datetime.now()
    if(cert_obj.not_valid_after < now):
        logger.log_error(__name__ + " : expiration date not valid ")
        sys.exit(0)

    return cert_obj, origin_certificate
