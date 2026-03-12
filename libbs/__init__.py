from importlib.metadata import version as _get_version, PackageNotFoundError as _PackageNotFoundError
try:
    __version__ = _get_version("libbs")
except _PackageNotFoundError:
    __version__ = "unknown"


import logging
logging.getLogger("libbs").addHandler(logging.NullHandler())
from libbs.logger import Loggers
loggers = Loggers()
del Loggers
del logging
