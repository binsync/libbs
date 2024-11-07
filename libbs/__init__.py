__version__ = "2.4.0"


import logging
logging.getLogger("libbs").addHandler(logging.NullHandler())
from libbs.logger import Loggers
loggers = Loggers()
del Loggers
del logging
