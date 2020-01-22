from .rs2wapy import RS2WebAdmin

__all__ = [
    "RS2WebAdmin",
]

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
