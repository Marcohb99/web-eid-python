#!/usr/bin/env python

import sys
import json
import struct
from base64 import b64encode
from datetime import datetime
import src.controller.logger as logger
import src.controller.command_handler.postRecord as postRecord


# Python 3.x version
# Send an encoded message to stdout

date_time = datetime.now().strftime("%m%d%Y_%H_%M_%S")


def send_message(encoded_message):
    try:
        sys.stdout.buffer.write(encoded_message['length'])
        sys.stdout.buffer.write(encoded_message['content'])
        sys.stdout.buffer.flush()
    except Exception as e:  # work on python 3.x
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def encode_native(message):
    try:
        message = bytearray(json.dumps(message), 'utf-8')
        message_length = len(message)
        message_length = struct.pack('=I', message_length)
        return {'length': message_length, 'content': message}
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def json_doc_to_base_64(doc):
    json_doc = bytearray(json.dumps(doc), 'utf-8')
    return b64encode(json_doc)


def read_native():
    try:
        response_length = struct.unpack('=I', sys.stdin.buffer.read(4))[0]
        # read message
        response = sys.stdin.buffer.read(response_length)
        jsonRes = json.loads(response)

        return jsonRes["command"], jsonRes["arguments"]
    except Exception as e:  # work on python 3.x
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def write_to_file(content):
    global date_time
    try:
        content.append(date_time)
        text_file = open(postRecord.get_output_file_name(), "w+t")
        for elem in content:
            text_file.write(elem + "\n")
        text_file.close()
    except Exception as e:  # work on python 3.x
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)
