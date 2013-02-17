import logging

# ------------------------------------------------------------------------
# If you plan to change these ever, you should probably config it.
LOG_LEVEL_CONSOLE    = logging.INFO
LOG_LEVEL_FILEHANDLE = logging.DEBUG
LOG_APPNAME          = "rsbakthat"
LOG_FILE             = "rsbakthat.log"

class LogClass():
    def __init__(self):
        # Logger.
        self.logger = logging.getLogger(LOG_APPNAME)
        self.logger.setLevel(logging.DEBUG)
        # File handle.
        fh = logging.FileHandler(LOG_FILE)
        fh.setLevel(LOG_LEVEL_FILEHANDLE) # Eveeryyyyything.
        # Console handle.
        ch = logging.StreamHandler()
        ch.setLevel(LOG_LEVEL_CONSOLE) # Errors only.
        # Apply logformat.
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(filename)s:%(lineno)d - %(levelname)s - %(message)s - PID: %(process)d  ' )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        # Add handdler to logger instance.
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

instance = LogClass()

if __name__ == '__main__':
    """ Pretty much how to use this from a module """
    logclass = LogClass('test')
    print("You found the secret cow level.")
    logclass.logger.debug('DEBUG.TEST.MESSAGE')
    logclass.logger.info('INFO.TEST.MESSAGE')
    logclass.logger.warn('WARN.TEST.MESSAGE')
    logclass.logger.error('ERROR.TEST.MESSAGE')
    logclass.logger.critical('CRITICAL.TEST.MESSAGE')

