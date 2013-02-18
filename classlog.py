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

if not __name__ == '__main__':
    instance = LogClass()

if __name__ == '__main__':
    """ Pretty much how to use this from a module """
    logclass = LogClass()
    print("You found the secret cow level.")
    logclass.logger.debug('FOR SOME VERBOSITY')
    logclass.logger.info( 'FOR THE LONG WINDED')
    logclass.logger.warn( 'FOR THE ATTENTION SEEKERS')
    logclass.logger.error('FOR THOSE WHO LIKE TO BE A BUZZKILL.')
    logclass.logger.critical('FOR THOSE WHO LIKE TO THROW TANTRUMS')

