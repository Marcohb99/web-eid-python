from urllib import request, parse
import requests
import src.controller.inputOutput as inputOutput
import src.controller.logger as logger
from src.controller.commands import Command
import sys
import json
import platform
import os
import binascii
import pathlib
import fnmatch
import os
from datetime import datetime


post_url = "https://eidrecordserver.herokuapp.com/api/eidrecords"  # remote
# post_url = "https://b4bc1fabd1e0.ngrok.io/api/eidrecords"  # local

date_time = datetime.now().strftime("%m_%d_%Y__%H_%M_%S")


def run(encoded_token, data, signature):
    try:
        parsed_data = parse.urlencode(data).encode()

        headers = {
            'auth-token': encoded_token,
            "signature": signature
        }

        resp = requests.request(
            method='POST', url=post_url, json=data, headers=headers)
        if resp.status_code > 300:
            logger.log_error(__name__ + ": request falied (" +
                             str(resp.status_code) + ") " + resp.content.decode("utf-8"))
            sys.exit()
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def build_record_data(token_payload, command, subject_mail, cert_fingerprint, doc_bytes):
    machine_platform = platform.platform()
    public_ip = format(requests.get('https://api.ipify.org').text)
    file_id = None
    if command == Command.SIGN:
        file_id = generate_file_id()

    data = {
        "platform": machine_platform,
        "publicIp": public_ip,
        "action": command,
        "origin": token_payload['aud'][0],
        "tokenNonce": token_payload['nonce'],
        "subjectEmail": subject_mail,
        "certFingerprint": cert_fingerprint,
        "status": "Python native app success",
        "fileId": file_id,
        "base64Doc": doc_bytes
    }
    return data


def generate_file_id():
    return binascii.b2a_hex(os.urandom(15)).decode("utf-8")


def save_record_local(record_data, certificate_data, signature, docHash):
    try:
        data = {
            "record_data": record_data,
            "certificate_data": certificate_data
        }
        if signature != None:
            data.update({"signature": signature})
        if docHash != None:
            data.update({"docHash": docHash})

        data.update({"date": date_time})
        if (os.name != "posix"):
            name = "\\record_" + date_time + ".json"
        else:
            name = "/record_" + date_time + ".json"
        registry_path = get_registry_path()
        output_name = registry_path + name
        logger.log_info("Saving record into file " + output_name)
        text_file = open(output_name, "w+t")
        text_file.write(json.dumps(data, indent=4, sort_keys=True))
        text_file.close()

        logger.log_info("Record saved successfully")
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def get_output_file_name():
    name = "\output" + date_time + ".txt"
    dir_path = pathlib.Path(__file__).parent.absolute()  # controller
    src_path = pathlib.Path(dir_path).parent.absolute()  # src
    app_path = pathlib.Path(src_path).parent.absolute()  # app
    tmp_path = ""
    for path, dirs, files in os.walk(app_path):
        tmp_path = os.path.join(
            path, fnmatch.filter(dirs, 'tmp')[0])        # tmp
        break
    output_name = tmp_path + name
    return output_name


def get_registry_path():
    dir_path = pathlib.Path(__file__).parent.absolute()  # command_handler
    controller_path = pathlib.Path(dir_path).parent.absolute()  # controller
    src_path = pathlib.Path(controller_path).parent.absolute()  # src
    app_path = pathlib.Path(src_path).parent.absolute()  # app
    registry_path = ""
    for path, dirs, files in os.walk(app_path):
        registry_path = os.path.join(
            path, fnmatch.filter(dirs, 'registry')[0])   # registry
        break

    return registry_path


def save_signed_file(record_data, file_data):
    try:
        registry_path = get_registry_path()
        if (os.name != "posix"):
            name = "\\" + record_data['fileId'] + "_container_metadata.bin"
        else:
            name = "/" + record_data['fileId'] + "_container_metadata.bin"
        registry_path = get_registry_path()
        output_name = registry_path + name
        logger.log_info("Saving signed file " + output_name)
        output_file = open(output_name, "wb")
        output_file.write(file_data)
        output_file.close()

        logger.log_info("File saved successfully")
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)
