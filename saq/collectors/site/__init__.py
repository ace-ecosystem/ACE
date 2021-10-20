import logging


def write_email_to_temp_file(parser, path):
    logging.debug(f"writing email to {path}")
    try:
        with open(path, 'wb') as f:
            f.write(parser.email.mime_content)
    except Exception as e:
        logging.debug(f"unable to write {path} as bytes because {e}, attempting as string")
        with open(path, 'w') as f:
            f.write(parser.email.mime_content)
