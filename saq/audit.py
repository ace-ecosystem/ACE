from datetime import datetime
import logging
import os
import saq

logger = None
def log(message):
    # create logger if it does not exist
    global logger
    if logger is None:
        audit_dir = os.path.join(saq.DATA_DIR, 'audit')
        if not os.path.exists(audit_dir):
            os.makedirs(audit_dir)
        audit_log_path = os.path.join(audit_dir, f'audit_{datetime.now().strftime("%Y-%m")}.log')
        handler = logging.FileHandler(audit_log_path)
        handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] - %(message)s'))
        logger = logging.getLogger('audit')
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)

    # log the message
    logger.info(message)
