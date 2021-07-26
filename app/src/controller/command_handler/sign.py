from base64 import b64encode, b64decode
import src.controller.inputOutput as inputOutput
import src.controller.logger as logger
import src.controller.command_handler.readCertificate as readCertificate
import src.controller.command_handler.signauthutils as utils
import cryptography.hazmat.primitives.serialization as serialization
import cryptography.hazmat.primitives.hashes as hashes
from cryptography.hazmat.primitives.asymmetric import padding
import cryptography.hazmat.primitives.asymmetric.utils as asymUtils
import cryptography.x509.oid as oid
import sys
import src.controller.command_handler.postRecord as postRecord
from src.controller.commands import Command


def sign(arguments):
    try:
        if (len(arguments) != 4):
            logger.log_error(__name__ +
                             "argument must be {doc-hash: <hash>, hash-algo: <hash_algo>, origin: <origin>, user-eid-cert: <Base64-encoded user eID certificate previously retrieved with get-cert>}")
            sys.exit(0)

        hash_algo_input, doc_bytes = validate_and_store_hash_algo(arguments)
        user_eid_certificate_from_args = utils.parse_and_validate_certificate(
            "user-eid-cert", arguments, False)
        subject = user_eid_certificate_from_args.subject.get_attributes_for_oid(
            oid.NameOID.COMMON_NAME)[0]
        subject = subject.value

        origin = utils.validate_and_store_origin(arguments)
        run(user_eid_certificate_from_args, doc_bytes, hash_algo_input, origin)
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + str(exc_tb.tb_lineno) +
                         " other error sign.sign: " + str(e))
        sys.exit(0)


def run(user_eid_certificate_from_args, doc_bytes, hash_algo, origin):
    try:
        #Assure that the certificate read from the eID card matches the certificate provided as
        #argument.
        certificate, certificate_pem, sig_algo, priv_key, pub_key_pem = readCertificate.run(
            serialization.Encoding.PEM)
        cert_digest = hashes.Hash(hashes.SHA1())
        user_eid_certificate_from_args_digest = hashes.Hash(hashes.SHA1())

        user_eid_certificate_from_args_digest.update(
            user_eid_certificate_from_args.public_bytes(serialization.Encoding.PEM))
        cert_digest.update(certificate_pem.public_bytes(
            serialization.Encoding.PEM))

        if cert_digest.finalize() != user_eid_certificate_from_args_digest.finalize():
            logger.log_error(__name__ + ": certificates don't match (web, card(\n" + cert_digest.finalize(
            ).decode("utf-8") + "\n" + user_eid_certificate_from_args_digest.finalize().decode("utf-8"))
            sys.exit(0)

        signature, doc_hash, algo = sign_hash(
            priv_key, doc_bytes, certificate_pem.signature_hash_algorithm, certificate_pem.signature_algorithm_oid)

        try:
            pub_key = certificate_pem.public_key()
            pub_key.verify(signature, doc_bytes,
                           padding.PKCS1v15(), hashes.SHA256())
            logger.log_info(__name__ + " Valid signature")
        except Exception as e:
            logger.log_error(__name__ + ": invalid signature " + str(e))
            sys.exit(0)

        subject = certificate_pem.subject.get_attributes_for_oid(
            oid.NameOID.COMMON_NAME)[0].value

        token_header, token_payload = utils.create_authentication_token(
            certificate, certificate_pem, sig_algo, b64encode(doc_hash).decode("utf-8"), origin, None, None)

        logger.log_debug(__name__ + " Singing token")

        token = utils.sign_token(
            token_header, token_payload, sig_algo, priv_key)

        subject_mail = utils.get_mail_from_cert(certificate_pem)
        cert_fingerprint = utils.calculate_cert_fingerprint(
            certificate_pem.public_bytes(serialization.Encoding.DER)).upper()

        #build record data
        logger.log_info(__name__ + " Building record data")
        certificate_data = utils.cert_to_dict(
            certificate_pem, subject_mail, cert_fingerprint)
        record_data = postRecord.build_record_data(
            token_payload, Command.SIGN, subject_mail, cert_fingerprint, b64encode(doc_bytes).decode("utf-8"))

        #save record locally
        logger.log_info(__name__ + " Saving record locally")
        postRecord.save_record_local(record_data, certificate_data,
                                     b64encode(signature).decode("utf-8"), b64encode(doc_hash).decode("utf-8"))
        postRecord.save_signed_file(record_data, doc_bytes)

        logger.log_info(__name__ + " Posting sign to eID record server")
        # post to eID record server
        postRecord.run(token, record_data, b64encode(
            signature).decode("utf-8"))

        logger.log_info(__name__ + " Sending token and signature")
        send_signature(b64encode(signature), sig_algo, token)
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def sign_hash(private_key, doc_bytes, hash_algo, sig_algo):
    try:
        algo = utils.signature_algo_to_dict(sig_algo)
        padding_algo = padding.PKCS1v15()
        prehashed = asymUtils.Prehashed(hash_algo)
        signature = private_key.sign(doc_bytes, padding_algo, hash_algo)
        digest = hashes.Hash(hash_algo)
        digest.update(doc_bytes)
        doc_hash = digest.finalize()
        return signature, doc_hash, algo
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def send_signature(signature, sig_algo, token):
    try:
        if isinstance(token, bytes):
            token = token.decode("utf-8")

        full_encoded_message = inputOutput.encode_native(
            {
                "signature": signature.decode("utf-8"),
                "token": token,
                "signature-algo": sig_algo
            })

        inputOutput.send_message(full_encoded_message)
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def validate_and_store_hash_algo(args):
    try:
        hash_arg = utils.validate_and_get_argument(
            "doc-hash", args, False)[1:-1]
        doc_hash = b64decode(bytearray(hash_arg, "utf-8"))
        hash_algo_input = utils.validate_and_get_argument(
            "hash-algo", args, False)[1:-1]
        if (len(hash_algo_input) > 8):  # originally greater than 8
            logger.log_error(__name__ + "hash-algo value is invalid " +
                             hash_algo_input + str(len(hash_algo_input)))
            sys.exit(0)
        return hash_algo_input, doc_hash
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)
