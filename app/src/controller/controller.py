import src.controller.logger as logger
import src.controller.inputOutput as inputOutput
from src.controller.commands import Command
from src.controller.command_handler import authenticate, getCertificate, sign
import sys
import json


def run(version):
    try:
        encoded_message = inputOutput.encode_native(version)
        inputOutput.send_message(encoded_message)
        command, arguments = inputOutput.read_native()
        logger.log_debug(__name__ + " version sent")
        start_command_execution(command, arguments)
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)


def start_command_execution(command, arguments):
    try:
        logger.log_debug(__name__ + " Command received: " + command)
        if(command == Command.AUTHENTICATE):
            authenticate.Authenticate(arguments)
        elif (command == Command.GET_CERTIFICATE):
            getCertificate.run(arguments)
        elif (command == Command.SIGN):
            sign.sign(arguments)
        else:
            message = "failure: unknown command" + json.dumps(command)
            inputOutput.write_to_file([message])
        sys.exit(0)
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
        sys.exit(0)
