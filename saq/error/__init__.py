# vim: sw=4:ts=4:et
# utility functions to report errors

import logging
import os
import os.path
import shutil
import smtplib
import sys
import traceback

from datetime import datetime
from email.mime.text import MIMEText
from subprocess import Popen, PIPE

import saq

def report_exception():
    import saq.engine

    exc_type, reported_exception, tb = sys.exc_info()

    # spit it out to stdout first
    if saq.DUMP_TRACEBACKS:
        traceback.print_exc()

    try:
        output_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['global']['error_reporting_dir'])
        #if not os.path.exists(output_dir):
            #try:
                #os.makedirs(output_dir)
            #except Exception as e:
                #logging.error("unable to create directory {}: {}".format(output_dir, str(e)))
                #return

        error_report_path = os.path.join(output_dir, datetime.now().strftime('%Y-%m-%d:%H:%M:%S.%f'))
        with open(error_report_path, 'w') as fp:
            if saq.engine.CURRENT_ENGINE:
                fp.write("CURRENT ENGINE: {}\n".format(saq.engine.CURRENT_ENGINE))
                fp.write("CURRENT ANALYSIS TARGET: {}\n".format(saq.engine.CURRENT_ENGINE.root))
                if saq.engine.CURRENT_ENGINE.root:
                    fp.write("CURRENT ANALYSIS MODE: {}\n".format(saq.engine.CURRENT_ENGINE.root.analysis_mode))

            fp.write("EXCEPTION\n")
            fp.write(str(reported_exception))
            fp.write("\n\nSTACK TRACE\n")

            from saq.error.formatter import ExceptionFormatter
            formatter = ExceptionFormatter()
            stack_trace, final_source = formatter.format_traceback(tb)

            fp.write(stack_trace)
            fp.write("\n\nEXCEPTION SOURCE\n")
            fp.write(final_source)
            fp.write("\n")

        if saq.CONFIG['service_engine'].getboolean('copy_analysis_on_error'):
            if saq.engine.CURRENT_ENGINE and saq.engine.CURRENT_ENGINE.root:
                if os.path.isdir(saq.engine.CURRENT_ENGINE.root.storage_dir):
                    analysis_dir = '{}.ace'.format(error_report_path)
                    try:
                        shutil.copytree(saq.engine.CURRENT_ENGINE.root.storage_dir, analysis_dir)
                        logging.warning("copied analysis from {} to {} for review".format(saq.engine.CURRENT_ENGINE.root.storage_dir, analysis_dir))
                    except Exception as e:
                        logging.error("unable to copy from {} to {}: {}".format(saq.engine.CURRENT_ENGINE.root.storage_dir, analysis_dir, e))

        return error_report_path

    except Exception as e:
        logging.error("uncaught exception we reporting an exception: {}".format(e))
        return None
