import src.controller.logger as logger
from base64 import b64decode, b64encode
import cryptography.x509 as x509
import sys
import json
import validators
import re
import datetime
import cryptography.x509.oid as oid
from Crypto.Hash import SHA256
import cryptography.hazmat.primitives.serialization as serialization
import jwt


def validate_and_get_argument(arg_name, args, allow_null):
    try:
        if (arg_name not in args.keys()):
            logger.log_error(__name__ + ": argument '" +
                             arg_name + "' is missing")
            sys.exit(0)

        if (allow_null and args[arg_name] == None):
            return args[arg_name]

        arg_value = json.dumps(args[arg_name])
        if not arg_value:
            logger.log_error(__name__ + ": argument '" +
                             arg_name + "' is empty")
            sys.exit(0)

        return arg_value
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def parse_and_validate_certificate(cert_arg_name, args, allow_null):
    try:
        cert_str = validate_and_get_argument(cert_arg_name, args, allow_null)
        if (allow_null and cert_str == None):
            return None

        cert_bytes = b64decode(cert_str)
        cert = x509.load_pem_x509_certificate(cert_bytes)
        if cert == None:
            logger.log_error(
                __name__ + ": invalid certificate passed as argument\n " + cert_str)
            sys.exit(0)
        return cert
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def signature_algo_to_dict(signature_algo):
    try:
        signature_algo_name = signature_algo._name.upper()
        hash_algo = ""
        if("SHA224" in signature_algo_name):
            hash_algo = "SHA-224"
        elif("SHA256" in signature_algo_name):
            hash_algo = "SHA-256"
        elif("SHA384" in signature_algo_name):
            hash_algo = "SHA-384"
        elif("SHA512" in signature_algo_name):
            hash_algo = "SHA-512"
        elif("SHA1" in signature_algo_name):
            hash_algo = "SHA-1"
        else:
            logger.log_error(
                __name__ + ": invalid hash algo " + signature_algo_name)
            sys.exit(0)

        if("PS" in signature_algo_name):
            return {"crypto-algo": "RSA", "hash-algo": hash_algo, "padding-algo": "PSS"}
        elif("RS" in signature_algo_name):
            return {"crypto-algo": "RSA", "hash-algo": hash_algo, "padding-algo": "PKCS1.5"}
        elif("ES" in signature_algo_name):
            return {"crypto-algo": "ECC", "hash-algo": hash_algo, "padding-algo": "NONE"}
        else:
            logger.log_error(
                __name__ + ": invalid sign algo " + signature_algo_name)
            sys.exit(0)
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def signature_algo_to_string(signature_algo):
    try:
        signature_algo_name = signature_algo._name.upper()
        dotted_string = signature_algo.dotted_string
        hash_algo = ""
        if(dotted_string == x509.SignatureAlgorithmOID.RSA_WITH_MD5.dotted_string):
            return "RSMD5"
        elif(dotted_string == x509.SignatureAlgorithmOID.RSA_WITH_SHA1.dotted_string):
            return "RS1"
        elif(dotted_string == x509.SignatureAlgorithmOID.RSA_WITH_SHA224.dotted_string):
            return "RS224"
        elif(dotted_string == x509.SignatureAlgorithmOID.RSA_WITH_SHA256.dotted_string):
            return "RS256"
        elif(dotted_string == x509.SignatureAlgorithmOID.RSA_WITH_SHA384.dotted_string):
            return "RS384"
        elif(dotted_string == x509.SignatureAlgorithmOID.RSA_WITH_SHA512.dotted_string):
            return "RS512"
        elif(dotted_string == x509.SignatureAlgorithmOID.RSASSA_PSS.dotted_string):
            return "PS256"
        elif(dotted_string == x509.SignatureAlgorithmOID.DSA_WITH_SHA1.dotted_string):
            return "DS1"
        elif(dotted_string == x509.SignatureAlgorithmOID.DSA_WITH_SHA224.dotted_string):
            return "DS224"
        elif(dotted_string == x509.SignatureAlgorithmOID.DSA_WITH_SHA256.dotted_string):
            return "DS256"
        else:
            logger.log_error(
                __name__ + ": invalid signature algo " + signature_algo_name)
            sys.exit(0)
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def convert_to_fingerprint_format(fingerprint):
    try:
        size = int(len(fingerprint)/2)
        tuple_f = []
        res = ""
        for i in range(size):
            tuple_f.append(fingerprint[(2 * i): (2 * i + 2)].upper())

        result = ":".join(tuple_f)
        return result
    except Exception as e:
        logger.log_error(__name__ + ": " + str(e))
        sys.exit(0)


def validate_and_store_origin(arguments):
    origin = json.dumps(arguments["origin"])
    origin = origin[1:-1]  # lol
    if(len(origin) > 255):
        logger.log_error(__name__ + " : origin is too long")
        sys.exit(0)

    valid = validators.url(origin)
    if(not valid):
        logger.log_error(__name__ + " : origin is not valid: " +
                         origin + ", " + str(valid))
        sys.exit(0)

    https = bool(re.match(r"https", origin))
    if(not https):
        logger.log_error(__name__ + ": origin is not https")
        sys.exit(0)

    return origin


def create_authentication_token(certificate, certificate_der, signature_algorithm, nonce, origin, origin_certificate, origin_cert_str):
    try:
        date_time = datetime.datetime.now()
        now = int(date_time.timestamp())
        exp = date_time.second + 60 * 5
        subject = certificate_der.subject.get_attributes_for_oid(
            oid.NameOID.COMMON_NAME)[0]
        subject = subject.value

        token_header = {
            "typ": "JWT",
            "alg": signature_algorithm,
            "x5c": [certificate],
        }

        token_payload = {
            "iat": now,
            "exp": now + exp,
            "sub": subject,
            "nonce": nonce,
            "iss": "web-eid app v0.9.0-1-ge6e89fa",
        }

        aud = [origin]
        if(origin_certificate != None):
            h = SHA256.new()
            h.update(b64decode(origin_cert_str))
            origin_cert_fingerprint = h.hexdigest()
            aud.append("urn:cert:sha-256:" + origin_cert_fingerprint)

        aud.append(origin)
        token_payload.update({"aud": aud})

        return token_header, token_payload
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def get_mail_from_cert(certificate):
    try:
        subject_alt_name_extension = certificate.extensions.get_extension_for_oid(
            oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        subject_alt_name_value = subject_alt_name_extension.value
        rfc_name = subject_alt_name_value.get_values_for_type(x509.RFC822Name)
        mail = rfc_name[0]
        return mail
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_info(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        return None


def calculate_cert_fingerprint(certificate):
    h = SHA256.new()
    h.update(certificate)
    origin_cert_fingerprint = h.hexdigest()
    return origin_cert_fingerprint


def cert_to_dict(certificate, subject_mail, origin_cert_fingerprint):
    try:
        data = {
            "certificate": b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode("utf-8"),
            "subjectDN": get_full_dn(certificate, certificate.subject),
            "issuerDN": get_full_dn(certificate, certificate.issuer),
            "subjectEmail": subject_mail,
            "fingerprint": origin_cert_fingerprint
        }
        return data
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit()


def get_full_dn(cert, field):
    try:
        dn = ""
        for attr in field.get_attributes_for_oid(oid.NameOID.GIVEN_NAME):
            dn += "GIVENNAME="+attr.value+" , "
        for attr in field.get_attributes_for_oid(oid.NameOID.SERIAL_NUMBER):
            dn += "SERIALNUMBER="+attr.value+" , "
        for attr in field.get_attributes_for_oid(oid.NameOID.COMMON_NAME):
            dn += "CN="+attr.value+" , "
        for attr in field.get_attributes_for_oid(oid.NameOID.ORGANIZATIONAL_UNIT_NAME):
            dn += "OU="+attr.value+" , "
        for attr in field.get_attributes_for_oid(oid.NameOID.ORGANIZATION_NAME):
            dn += "O="+attr.value+" , "
        for attr in field.get_attributes_for_oid(oid.NameOID.COUNTRY_NAME):
            dn += "C="+attr.value
        return dn
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit()


def sign_token(token_header, token_payload, signature_algorithm, priv_key):
    try:
        jwt_token = jwt.encode(token_payload, priv_key,
                               signature_algorithm, token_header)
        return jwt_token
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)
