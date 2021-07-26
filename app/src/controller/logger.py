import logging
import os
import pathlib
import fnmatch
import src.controller.inputOutput as inputOutput
import sys

formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
error_logger = None
info_logger = None
record_logger = None


def setup_logger(name, log_file, level=logging.INFO):
    """To setup as many loggers as you want"""

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


def get_logging_file(level):
    name = ""
    if level == logging.INFO or level == logging.DEBUG:
        name = "logs.log"
    elif level == logging.ERROR:
        name = "error.log"

    dir_path = pathlib.Path(__file__).parent.absolute()  # controller
    src_path = pathlib.Path(dir_path).parent.absolute()  # src
    app_path = pathlib.Path(src_path).parent.absolute()  # app
    logs_path = ""
    for path, dirs, files in os.walk(app_path):
        logs_path = os.path.join(
            path, fnmatch.filter(dirs, 'logs')[0])       # logs
        break
    log_file_name = ""
    for path, dirs, files in os.walk(logs_path):
        for f in fnmatch.filter(files, name):
            log_file_name = os.path.abspath(os.path.join(path, f))

    return log_file_name


def log_error(error):
    global error_logger
    try:
        if error_logger == None:
            error_logger = setup_logger(
                "error_logger", get_logging_file(logging.ERROR), logging.ERROR)

        error_logger.error(str(error))
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        inputOutput.write_to_file([str(e), str(exc_tb.tb_lineno)])
        sys.exit()


def log_info(info):
    global info_logger
    try:
        if info_logger == None:
            info_logger = setup_logger(
                "info_logger", get_logging_file(logging.INFO), logging.INFO)

        info_logger.setLevel(logging.INFO)
        info_logger.info(str(info))
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        inputOutput.write_to_file([str(e), str(exc_tb.tb_lineno)])
        sys.exit()


def log_debug(info):
    global info_logger
    try:
        if info_logger == None:
            info_logger = setup_logger(
                "info_logger", get_logging_file(logging.DEBUG), logging.DEBUG)

        info_logger.setLevel(logging.DEBUG)
        info_logger.debug(str(info))
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        inputOutput.write_to_file([str(e), str(exc_tb.tb_lineno)])
        sys.exit()
