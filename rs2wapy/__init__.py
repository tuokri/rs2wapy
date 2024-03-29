from ._version import get_versions
from .adapters import adapters
from .epicgamesstore import epicgamesstore
from .models import models
from .parsing import parsing
from .rs2wapy import RS2WebAdmin

__version__ = get_versions()["version"]
del get_versions

__all__ = [
    "adapters",
    "models",
    "parsing",
    "RS2WebAdmin",
    "epicgamesstore",
]
