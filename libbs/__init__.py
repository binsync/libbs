__version__ = "0.23.0"

import logging
logging.getLogger("libbs").addHandler(logging.NullHandler())
from libbs.logger import Loggers
loggers = Loggers()
del Loggers
del logging
