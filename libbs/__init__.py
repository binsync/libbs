__version__ = "1.10.0"


import logging
logging.getLogger("libbs").addHandler(logging.NullHandler())
from libbs.logger import Loggers
loggers = Loggers()
del Loggers
del logging
