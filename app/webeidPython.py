#!/usr/bin/env python

import sys
import src.controller.logger as logger
import src.controller.controller as controller

'''

Main code 

'''
version = {'version': '1.0.0'}
try:
    logger.log_info("Native app started with version " + version["version"])
    controller.run(version)
except Exception as e:  # work on python 3.x
    exc_type, exc_obj, exc_tb = sys.exc_info()
    logger.log_error(__name__ + " " + str(exc_tb.tb_lineno) + " " + str(e))
    sys.exit(0)
