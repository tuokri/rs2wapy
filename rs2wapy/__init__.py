from ._version import __version__
from .adapters import adapters
from .epicgamesstore import epicgamesstore
from .models import models
from .parsing import parsing
from .rs2wapy import RS2WebAdmin

__version__ = __version__

__all__ = [
    "adapters",
    "models",
    "parsing",
    "RS2WebAdmin",
    "epicgamesstore",
]
